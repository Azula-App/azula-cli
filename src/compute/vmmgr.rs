//! The real VM manager (macOS): bundles under `~/.azula/vm`, image download
//! and verification, `vm create/list/delete`, and the [`VmBackend`] that
//! spawns one `azula-vm run` per running VM (`vm/BROKER.md` §8,
//! `vm/README.md` §3–§4).

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use data_encoding::HEXLOWER;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha512};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::watch;
use tracing::{info, warn};

use super::grants::{unix_now, write_private_atomic};
use super::seed::{render_meta_data, render_user_data};
use super::vm::{VmBackend, VmError, VmInfo, VmState};
use super::{guest, valid_vm_name};

/// The worker's vsock port (`vm/README.md` §2).
pub const GUEST_PORT: u32 = 1024;
/// How long `start` waits for the worker to answer a ping.
pub const START_DEADLINE: Duration = Duration::from_secs(180);
/// Grace period asked of the guest on stop.
pub const STOP_GRACE_S: u64 = 30;

// --- images ----------------------------------------------------------------

/// A downloadable base image.
pub struct ImageSpec {
    /// What `--image` accepts.
    pub id: &'static str,
    /// Directory under `images/` (the layout is `images/<dir>/disk.raw`; the
    /// first image kept the name its archive extracts under).
    pub dir: &'static str,
    pub base_url: &'static str,
    pub archive: &'static str,
}

pub const IMAGES: &[ImageSpec] = &[ImageSpec {
    id: "debian-13",
    dir: "debian-13-generic-arm64",
    base_url: "https://cloud.debian.org/images/cloud/trixie/latest",
    archive: "debian-13-generic-arm64.tar.xz",
}];

pub fn image_spec(id: &str) -> Result<&'static ImageSpec> {
    IMAGES.iter().find(|i| i.id == id).ok_or_else(|| {
        anyhow!("unknown image `{id}` (known: {})", IMAGES.iter().map(|i| i.id).collect::<Vec<_>>().join(", "))
    })
}

// --- paths -----------------------------------------------------------------

/// Layout of the VM directory (`vm/README.md` §4).
#[derive(Debug, Clone)]
pub struct Paths {
    pub root: PathBuf,
}

impl Paths {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn image_disk(&self, spec: &ImageSpec) -> PathBuf {
        self.root.join("images").join(spec.dir).join("disk.raw")
    }

    pub fn share(&self) -> PathBuf {
        self.root.join("share")
    }

    pub fn vms(&self) -> PathBuf {
        self.root.join("vms")
    }

    pub fn vm(&self, name: &str) -> PathBuf {
        self.vms().join(name)
    }

    pub fn vm_json(&self, name: &str) -> PathBuf {
        self.vm(name).join("vm.json")
    }

    pub fn vsock(&self, name: &str) -> PathBuf {
        self.vm(name).join("vsock.sock")
    }
}

/// `vm.json`: the helper's config (README §3) plus our own metadata (the
/// helper ignores unknown fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmConfig {
    pub cpus: u32,
    pub memory_mb: u64,
    pub machine_id: String,
    pub mac: String,
    pub efi_vars: PathBuf,
    pub disks: Vec<Disk>,
    pub shares: Vec<Share>,
    pub console_log: PathBuf,
    pub vsock: VsockCfg,
    pub image: String,
    pub disk_gb: u64,
    pub created_at: u64,
    /// `nat` (default) or `none`; the helper reads it too.
    #[serde(default = "default_network")]
    pub network: String,
}

fn default_network() -> String {
    "nat".to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Disk {
    pub path: PathBuf,
    pub read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    pub tag: String,
    pub path: PathBuf,
    pub read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VsockCfg {
    pub socket: PathBuf,
    pub port: u32,
}

// --- binaries --------------------------------------------------------------

fn exe_dir() -> Option<PathBuf> {
    std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf))
}

/// `$AZULA_VM_HELPER`, else `azula-vm` next to this executable, else on `PATH`.
pub fn find_helper() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("AZULA_VM_HELPER").filter(|p| !p.is_empty()) {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Ok(p);
        }
        bail!("AZULA_VM_HELPER={} is not a file", p.display());
    }
    if let Some(p) = exe_dir().map(|d| d.join("azula-vm")).filter(|p| p.is_file()) {
        return Ok(p);
    }
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let p = dir.join("azula-vm");
            if p.is_file() {
                return Ok(p);
            }
        }
    }
    bail!("the azula-vm helper was not found: set AZULA_VM_HELPER, or put azula-vm next to the azula binary or on PATH")
}

/// `$AZULA_GUEST_BIN`, else `azula-guest.linux-aarch64` next to this executable.
pub fn find_guest_bin() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("AZULA_GUEST_BIN").filter(|p| !p.is_empty()) {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Ok(p);
        }
        bail!("AZULA_GUEST_BIN={} is not a file", p.display());
    }
    if let Some(p) = exe_dir().map(|d| d.join("azula-guest.linux-aarch64")).filter(|p| p.is_file()) {
        return Ok(p);
    }
    bail!("the guest worker binary was not found: set AZULA_GUEST_BIN, or put azula-guest.linux-aarch64 next to the azula binary")
}

/// Copy the guest binary to `share/azula-guest` atomically (0755).
pub fn install_guest_bin(paths: &Paths, src: &Path) -> Result<PathBuf> {
    let share = paths.share();
    std::fs::create_dir_all(&share).with_context(|| format!("creating {}", share.display()))?;
    let dst = share.join("azula-guest");
    let tmp = share.join(".azula-guest.tmp");
    std::fs::copy(src, &tmp).with_context(|| format!("copying {}", src.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    }
    std::fs::rename(&tmp, &dst)?;
    Ok(dst)
}

// --- image download --------------------------------------------------------

async fn run_checked(cmd: &mut Command, what: &str) -> Result<std::process::Output> {
    let out = cmd.output().await.with_context(|| format!("running {what}"))?;
    if !out.status.success() {
        bail!("{what} failed ({}): {}", out.status, String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(out)
}

/// The expected SHA-512 of `file` from a `SHA512SUMS` listing.
pub fn expected_sha512(sums: &str, file: &str) -> Option<String> {
    sums.lines().find_map(|l| {
        let (hash, name) = l.split_once(char::is_whitespace)?;
        (name.trim().trim_start_matches('*') == file).then(|| hash.to_ascii_lowercase())
    })
}

fn sha512_file(path: &Path) -> Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha512::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(HEXLOWER.encode(h.finalize().as_slice()))
}

/// Make sure `images/<dir>/disk.raw` exists, downloading, verifying
/// (`SHA512SUMS` over HTTPS) and extracting it if not. The image is never
/// booted or modified afterwards.
pub async fn ensure_image(paths: &Paths, spec: &ImageSpec) -> Result<PathBuf> {
    let disk = paths.image_disk(spec);
    if disk.is_file() {
        return Ok(disk);
    }
    let dir = disk.parent().expect("image dir").to_path_buf();
    let work = paths.root.join("images").join(format!("{}.partial", spec.dir));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work)?;

    eprintln!("Downloading {} …", spec.archive);
    let sums = run_checked(
        Command::new("curl").args(["-fsSL", "--proto", "=https", &format!("{}/SHA512SUMS", spec.base_url)]),
        "curl SHA512SUMS",
    )
    .await?;
    let sums = String::from_utf8_lossy(&sums.stdout).into_owned();
    let want = expected_sha512(&sums, spec.archive).ok_or_else(|| anyhow!("SHA512SUMS has no entry for {}", spec.archive))?;
    let archive = work.join(spec.archive);
    run_checked(
        Command::new("curl").args(["-fSL", "--proto", "=https", "-o"]).arg(&archive).arg(format!("{}/{}", spec.base_url, spec.archive)),
        "curl image",
    )
    .await?;
    let got = tokio::task::spawn_blocking({
        let archive = archive.clone();
        move || sha512_file(&archive)
    })
    .await??;
    if got != want {
        bail!("checksum mismatch for {}: expected {want}, got {got}", spec.archive);
    }
    eprintln!("Checksum verified; extracting …");
    run_checked(Command::new("tar").arg("-xJf").arg(&archive).arg("-C").arg(&work), "tar -xJf").await?;
    let raw = work.join("disk.raw");
    if !raw.is_file() {
        bail!("the archive did not contain disk.raw");
    }
    std::fs::create_dir_all(&dir)?;
    std::fs::rename(&raw, &disk)?;
    let _ = std::fs::remove_dir_all(&work);
    Ok(disk)
}

// --- create / list / delete --------------------------------------------------

/// `vm create` options.
#[derive(Debug, Clone)]
pub struct CreateOptions {
    pub image: String,
    pub cpus: u32,
    pub memory_mb: u64,
    pub disk_gb: u64,
    /// `nat` or `none`.
    pub network: String,
}

/// Memory the host keeps for itself when budgeting VM memory.
pub const HOST_RESERVE_MB: u64 = 4096;
/// Free space `vm create` wants on top of the image size.
pub const CREATE_HEADROOM_BYTES: u64 = 10 << 30;

/// May a VM of `new_mb` start when `running_mb` is already committed on a host
/// with `host_mb` of RAM? The running VMs plus the new one must fit in RAM
/// minus [`HOST_RESERVE_MB`].
pub fn check_memory_budget(running_mb: u64, new_mb: u64, host_mb: u64) -> Result<(), String> {
    let budget = host_mb.saturating_sub(HOST_RESERVE_MB);
    if running_mb + new_mb > budget {
        return Err(format!(
            "starting this VM ({new_mb} MiB) with {running_mb} MiB already running would exceed the host's VM memory budget of {budget} MiB (RAM {host_mb} MiB minus {HOST_RESERVE_MB} MiB); stop another VM first"
        ));
    }
    Ok(())
}

/// May `vm create` proceed with `free` bytes available and an image of `image_len`?
pub fn check_free_space(free: u64, image_len: u64) -> Result<(), String> {
    let need = image_len + CREATE_HEADROOM_BYTES;
    if free < need {
        return Err(format!(
            "not enough free disk space: {} MiB available, need {} MiB (image {} MiB plus 10 GiB of headroom)",
            free >> 20,
            need >> 20,
            image_len >> 20
        ));
    }
    Ok(())
}

/// The host's physical memory in MiB (`sysctl hw.memsize`).
pub fn host_memory_mb() -> Option<u64> {
    let name = std::ffi::CString::new("hw.memsize").ok()?;
    let mut value: u64 = 0;
    let mut len = size_of::<u64>();
    // SAFETY: `value` and `len` describe a valid u64 out-buffer for this sysctl.
    let rc = unsafe { libc::sysctlbyname(name.as_ptr(), &mut value as *mut u64 as *mut libc::c_void, &mut len, std::ptr::null_mut(), 0) };
    (rc == 0).then_some(value >> 20)
}

/// Bytes available to unprivileged writers on the volume holding `path`.
pub fn free_bytes(path: &Path) -> Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: statvfs is plain old data; zeroed is a valid initial value.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a valid path and `st` a valid out-struct.
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("statvfs {}", path.display()));
    }
    Ok(st.f_bavail as u64 * st.f_frsize as u64)
}

fn clone_file(src: &Path, dst: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c = |p: &Path| std::ffi::CString::new(p.as_os_str().as_bytes()).map_err(|_| anyhow!("path contains NUL"));
    let (s, d) = (c(src)?, c(dst)?);
    // SAFETY: both are valid NUL-terminated paths for the duration of the call.
    if unsafe { libc::clonefile(s.as_ptr(), d.as_ptr(), 0) } == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    warn!("clonefile failed ({err}); falling back to a plain copy");
    std::fs::copy(src, dst).with_context(|| format!("copying {}", src.display()))?;
    Ok(())
}

/// Create VM `name`: APFS clone of the image grown sparse, its own EFI vars /
/// machine id / MAC from the helper, a seed ISO with a fresh instance id, and
/// `vm.json`. Built in `<name>.partial` and renamed into place.
pub async fn create_vm(paths: &Paths, name: &str, opts: &CreateOptions) -> Result<PathBuf> {
    if !valid_vm_name(name) {
        bail!("invalid VM name `{name}`: use lowercase letters, digits and `-` (at most 63 characters)");
    }
    let spec = image_spec(&opts.image)?;
    let final_dir = paths.vm(name);
    if final_dir.exists() {
        bail!("VM `{name}` already exists");
    }
    let helper = find_helper()?;
    let image = ensure_image(paths, spec).await?;
    let image_len = std::fs::metadata(&image)?.len();
    let disk_bytes = opts.disk_gb.checked_mul(1 << 30).ok_or_else(|| anyhow!("--disk-gb is too large"))?;
    if disk_bytes < image_len {
        bail!("--disk-gb {} is smaller than the image ({} bytes)", opts.disk_gb, image_len);
    }
    if opts.network != "nat" && opts.network != "none" {
        bail!("--network must be `nat` or `none`");
    }

    std::fs::create_dir_all(paths.vms())?;
    check_free_space(free_bytes(&paths.vms())?, image_len).map_err(|e| anyhow!(e))?;
    let work = paths.vms().join(format!("{name}.partial"));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work)?;
    let result = async {
        let disk = work.join("disk.img");
        clone_file(&image, &disk)?;
        std::fs::OpenOptions::new().write(true).open(&disk)?.set_len(disk_bytes)?;

        let efi = work.join("efi.vars");
        let out = run_checked(Command::new(&helper).arg("init").arg("--efi-vars").arg(&efi), "azula-vm init").await?;
        let ids: Value = serde_json::from_slice(&out.stdout).context("parsing azula-vm init output")?;
        let machine_id = ids["machine_id"].as_str().ok_or_else(|| anyhow!("azula-vm init gave no machine_id"))?.to_owned();
        let mac = ids["mac"].as_str().ok_or_else(|| anyhow!("azula-vm init gave no mac"))?.to_owned();

        // Seed ISO.
        let seed_src = work.join("seed-src");
        std::fs::create_dir_all(&seed_src)?;
        let instance_id = uuid::Uuid::new_v4().to_string();
        std::fs::write(seed_src.join("meta-data"), render_meta_data(&instance_id, name))?;
        std::fs::write(seed_src.join("user-data"), render_user_data(name))?;
        run_checked(
            Command::new("hdiutil")
                .args(["makehybrid", "-iso", "-joliet", "-default-volume-name", "cidata", "-o"])
                .arg(work.join("seed.iso"))
                .arg(&seed_src),
            "hdiutil makehybrid",
        )
        .await?;
        std::fs::remove_dir_all(&seed_src)?;

        let cfg = VmConfig {
            cpus: opts.cpus,
            memory_mb: opts.memory_mb,
            machine_id,
            mac,
            efi_vars: final_dir.join("efi.vars"),
            disks: vec![
                Disk { path: final_dir.join("disk.img"), read_only: false },
                Disk { path: final_dir.join("seed.iso"), read_only: true },
            ],
            shares: vec![Share { tag: "azula".into(), path: paths.share(), read_only: true }],
            console_log: final_dir.join("console.log"),
            vsock: VsockCfg { socket: final_dir.join("vsock.sock"), port: GUEST_PORT },
            image: opts.image.clone(),
            disk_gb: opts.disk_gb,
            created_at: unix_now(),
            network: opts.network.clone(),
        };
        write_private_atomic(&work.join("vm.json"), &serde_json::to_vec_pretty(&cfg)?)?;
        std::fs::rename(&work, &final_dir)?;
        Ok::<_, anyhow::Error>(final_dir.clone())
    }
    .await;
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&work);
    }
    result
}

pub fn load_config(paths: &Paths, name: &str) -> Result<VmConfig, VmError> {
    if !valid_vm_name(name) {
        return Err(VmError::unknown(name));
    }
    let bytes = std::fs::read(paths.vm_json(name)).map_err(|_| VmError::unknown(name))?;
    serde_json::from_slice(&bytes).map_err(|e| VmError::new("internal", format!("vm.json for `{name}` is unreadable: {e}")))
}

/// Names of every VM bundle, sorted.
pub fn list_names(paths: &Paths) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(paths.vms())
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().join("vm.json").is_file())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    names.sort();
    names
}

/// Is something accepting connections on the VM's `vsock.sock`?
pub fn socket_is_live(sock: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(sock).is_ok()
}

/// Remove a VM's bundle. Refuses while its `vsock.sock` is live.
pub fn delete_vm(paths: &Paths, name: &str) -> Result<()> {
    load_config(paths, name).map_err(|e| anyhow!("{}", e.msg))?;
    if socket_is_live(&paths.vsock(name)) {
        bail!("VM `{name}` is running; stop it first (`azula vm stop {name}`)");
    }
    std::fs::remove_dir_all(paths.vm(name)).with_context(|| format!("removing {}", paths.vm(name).display()))
}

/// Offline status of every VM for `vm list` (no broker: running = socket live).
pub fn list_offline(paths: &Paths) -> Vec<VmInfo> {
    list_names(paths)
        .into_iter()
        .filter_map(|n| {
            let cfg = load_config(paths, &n).ok()?;
            let running = socket_is_live(&paths.vsock(&n));
            Some(VmInfo {
                name: n,
                state: if running { "running" } else { "stopped" }.into(),
                worker: "unknown".into(),
                image: cfg.image,
                cpus: cfg.cpus,
                memory_mb: cfg.memory_mb,
                disk_gb: cfg.disk_gb,
                network: cfg.network,
                jobs_running: None,
                disk_free_mb: None,
                worker_info: None,
                error: None,
            })
        })
        .collect()
}

// --- the backend -----------------------------------------------------------

#[derive(Default)]
struct Slot {
    /// Serializes start/stop of one VM.
    gate: tokio::sync::Mutex<()>,
    run: Mutex<Option<Run>>,
}

/// One live `azula-vm run` process.
struct Run {
    state: watch::Sender<VmState>,
    stdin: Arc<tokio::sync::Mutex<Option<ChildStdin>>>,
    pid: Option<u32>,
    /// Last stderr lines and the `stopped` event's detail, for diagnostics.
    diag: Arc<Mutex<Vec<String>>>,
}

/// The real [`VmBackend`].
pub struct RealBackend {
    pub paths: Paths,
    helper: PathBuf,
    slots: Mutex<HashMap<String, Arc<Slot>>>,
    /// The last start failure per VM, cleared by a successful start.
    errors: Mutex<HashMap<String, String>>,
    allow_sleep: bool,
    sleep_guard: Mutex<Option<std::process::Child>>,
}

impl RealBackend {
    pub fn new(paths: Paths, helper: PathBuf) -> Self {
        Self { paths, helper, slots: Mutex::new(HashMap::new()), errors: Mutex::new(HashMap::new()), allow_sleep: false, sleep_guard: Mutex::new(None) }
    }

    /// With `true`, never hold an idle-sleep assertion (`serve --allow-sleep`).
    pub fn allow_sleep(mut self, allow: bool) -> Self {
        self.allow_sleep = allow;
        self
    }

    /// VMs that are starting, running or stopping.
    fn active_vms(&self) -> Vec<String> {
        let names: Vec<String> = self.slots.lock().unwrap().keys().cloned().collect();
        names.into_iter().filter(|n| self.current_state(n) != VmState::Stopped).collect()
    }

    /// Hold `caffeinate -i -w <our pid>` while at least one VM is active.
    fn refresh_sleep_guard(&self) {
        if self.allow_sleep {
            return;
        }
        let want = !self.active_vms().is_empty();
        let mut g = self.sleep_guard.lock().unwrap();
        if let Some(child) = g.as_mut() {
            if matches!(child.try_wait(), Ok(Some(_))) {
                *g = None;
            }
        }
        if want && g.is_none() {
            match std::process::Command::new("caffeinate")
                .args(["-i", "-w"])
                .arg(std::process::id().to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                Ok(c) => *g = Some(c),
                Err(e) => warn!("could not hold an idle-sleep assertion: {e}"),
            }
        } else if !want {
            if let Some(mut c) = g.take() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }

    /// Re-check the sleep assertion every few seconds (catches VMs that stopped by themselves).
    pub fn spawn_sleep_guard(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                me.refresh_sleep_guard();
            }
        })
    }

    fn record_error(&self, name: &str, err: &VmError) {
        self.errors.lock().unwrap().insert(name.to_owned(), err.msg.clone());
    }

    fn memory_check(&self, name: &str, new_mb: u64) -> Result<(), VmError> {
        let running: u64 = self.active_vms().iter().filter(|n| n.as_str() != name).filter_map(|n| load_config(&self.paths, n).ok()).map(|c| c.memory_mb).sum();
        let Some(host_mb) = host_memory_mb() else { return Ok(()) };
        check_memory_budget(running, new_mb, host_mb).map_err(|m| VmError::new("host_busy", m))
    }

    fn slot(&self, name: &str) -> Arc<Slot> {
        self.slots.lock().unwrap().entry(name.to_owned()).or_default().clone()
    }

    fn current_state(&self, name: &str) -> VmState {
        let slot = self.slot(name);
        let run = slot.run.lock().unwrap();
        run.as_ref().map(|r| *r.state.borrow()).unwrap_or(VmState::Stopped)
    }

    fn console_tail(&self, name: &str) -> String {
        let text = std::fs::read_to_string(self.paths.vm(name).join("console.log")).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(40)..].join("\n")
    }

    fn failure(&self, name: &str, why: &str, diag: &[String]) -> VmError {
        let mut msg = format!("VM `{name}` failed to start: {why}");
        if !diag.is_empty() {
            msg.push_str(&format!("\nhelper output:\n{}", diag.join("\n")));
        }
        let tail = self.console_tail(name);
        if !tail.is_empty() {
            msg.push_str(&format!("\nconsole (last 40 lines):\n{tail}"));
        }
        VmError::new("vm_start_failed", msg)
    }

    async fn send_op(run_stdin: &Arc<tokio::sync::Mutex<Option<ChildStdin>>>, op: Value) {
        if let Some(stdin) = run_stdin.lock().await.as_mut() {
            let mut line = op.to_string();
            line.push('\n');
            let _ = stdin.write_all(line.as_bytes()).await;
            let _ = stdin.flush().await;
        }
    }

    fn spawn_helper(&self, name: &str) -> Result<Run, VmError> {
        let mut child: Child = Command::new(&self.helper)
            .arg("run")
            .arg("--config")
            .arg(self.paths.vm_json(name))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(false)
            .spawn()
            .map_err(|e| VmError::new("vm_start_failed", format!("could not run {}: {e}", self.helper.display())))?;
        let pid = child.id();
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        let (state_tx, _rx) = watch::channel(VmState::Starting);
        let diag = Arc::new(Mutex::new(Vec::<String>::new()));

        // stderr tail
        let d = diag.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(l)) = lines.next_line().await {
                let mut d = d.lock().unwrap();
                d.push(l);
                let extra = d.len().saturating_sub(40);
                d.drain(..extra);
            }
        });
        // stdout events + process supervision
        let tx = state_tx.clone();
        let d = diag.clone();
        let who = name.to_owned();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(l)) = lines.next_line().await {
                match serde_json::from_str::<Value>(&l) {
                    Ok(v) => match v["event"].as_str() {
                        Some("started") => info!("vm {who}: helper reports started"),
                        Some("stopped") => {
                            let reason = v["reason"].as_str().unwrap_or("?").to_owned();
                            let err = v["error"].as_str().unwrap_or("");
                            info!("vm {who}: stopped ({reason}) {err}");
                            if !err.is_empty() {
                                d.lock().unwrap().push(format!("stopped: {reason}: {err}"));
                            }
                        }
                        _ => {}
                    },
                    Err(_) => d.lock().unwrap().push(l),
                }
            }
            let status = child.wait().await;
            info!("vm {who}: helper exited ({status:?})");
            tx.send_replace(VmState::Stopped);
        });
        Ok(Run { state: state_tx, stdin: Arc::new(tokio::sync::Mutex::new(Some(stdin))), pid, diag })
    }
}

impl VmBackend for RealBackend {
    fn names(&self) -> Result<Vec<String>, VmError> {
        Ok(list_names(&self.paths))
    }

    fn state(&self, name: &str) -> Result<VmState, VmError> {
        load_config(&self.paths, name)?;
        Ok(self.current_state(name))
    }

    async fn info(&self, name: &str) -> Result<VmInfo, VmError> {
        let cfg = load_config(&self.paths, name)?;
        let state = self.current_state(name);
        let (worker, worker_info) = if state == VmState::Running {
            match guest::ping(&self.paths.vsock(name), Duration::from_secs(5)).await {
                Ok(p) => ("ready", Some(p)),
                Err(_) => ("unreachable", None),
            }
        } else {
            ("unknown", None)
        };
        let error = self.errors.lock().unwrap().get(name).cloned();
        let shown = if state == VmState::Stopped && error.is_some() { "failed" } else { state.as_str() };
        Ok(VmInfo {
            name: name.to_owned(),
            state: shown.into(),
            worker: worker.into(),
            image: cfg.image,
            cpus: cfg.cpus,
            memory_mb: cfg.memory_mb,
            disk_gb: cfg.disk_gb,
            network: cfg.network,
            jobs_running: None,
            disk_free_mb: None,
            worker_info: None,
            error,
        }
        .with_pong(worker_info))
    }

    async fn start(&self, name: &str) -> Result<(), VmError> {
        load_config(&self.paths, name)?;
        let slot = self.slot(name);
        let _gate = slot.gate.lock().await;
        if self.current_state(name) == VmState::Running {
            return Ok(());
        }
        let sock = self.paths.vsock(name);
        if socket_is_live(&sock) {
            return Err(VmError::new("vm_start_failed", format!("VM `{name}` is already running under another process (its socket is live)")));
        }
        let cfg = load_config(&self.paths, name)?;
        self.memory_check(name, cfg.memory_mb)?;
        let run = match self.spawn_helper(name) {
            Ok(r) => r,
            Err(e) => {
                self.record_error(name, &e);
                return Err(e);
            }
        };
        self.refresh_sleep_guard();
        let mut state_rx = run.state.subscribe();
        let diag = run.diag.clone();
        let state_tx = run.state.clone();
        *slot.run.lock().unwrap() = Some(run);

        // Race worker readiness against the helper exiting.
        let ready = guest::wait_ready(&sock, START_DEADLINE);
        tokio::pin!(ready);
        let exited = async {
            loop {
                if *state_rx.borrow_and_update() == VmState::Stopped {
                    return;
                }
                if state_rx.changed().await.is_err() {
                    return;
                }
            }
        };
        tokio::select! {
            r = &mut ready => match r {
                Ok(_) => {
                    state_tx.send_replace(VmState::Running);
                    self.errors.lock().unwrap().remove(name);
                    Ok(())
                }
                Err(e) => {
                    let diag = diag.lock().unwrap().clone();
                    let err = self.failure(name, &format!("worker did not answer within {}s ({e})", START_DEADLINE.as_secs()), &diag);
                    self.record_error(name, &err);
                    drop(_gate);
                    let _ = self.stop(name).await;
                    Err(err)
                }
            },
            _ = exited => {
                let diag = diag.lock().unwrap().clone();
                let err = self.failure(name, "the helper exited before the worker came up", &diag);
                self.record_error(name, &err);
                self.refresh_sleep_guard();
                Err(err)
            }
        }
    }

    async fn stop(&self, name: &str) -> Result<(), VmError> {
        load_config(&self.paths, name)?;
        let slot = self.slot(name);
        let _gate = slot.gate.lock().await;
        let parts = {
            let run = slot.run.lock().unwrap();
            run.as_ref().map(|r| (r.state.clone(), r.stdin.clone(), r.pid))
        };
        let Some((state, stdin, pid)) = parts else { return Ok(()) };
        if *state.borrow() == VmState::Stopped {
            *slot.run.lock().unwrap() = None;
            return Ok(());
        }
        state.send_replace(VmState::Stopping);
        let mut rx = state.subscribe();
        Self::send_op(&stdin, json!({"op": "stop", "grace_s": STOP_GRACE_S})).await;
        if !wait_stopped(&mut rx, Duration::from_secs(STOP_GRACE_S + 10)).await {
            warn!("vm {name}: did not stop within the grace period; killing");
            Self::send_op(&stdin, json!({"op": "kill"})).await;
            if !wait_stopped(&mut rx, Duration::from_secs(10)).await {
                if let Some(pid) = pid {
                    // SAFETY: signalling a child process we spawned.
                    unsafe { libc::kill(pid as i32, libc::SIGKILL) };
                }
                let _ = wait_stopped(&mut rx, Duration::from_secs(5)).await;
            }
        }
        // Dropping stdin lets the helper exit if it is somehow still around.
        stdin.lock().await.take();
        *slot.run.lock().unwrap() = None;
        let _ = std::fs::remove_file(self.paths.vsock(name));
        self.refresh_sleep_guard();
        Ok(())
    }

    fn vsock_path(&self, name: &str) -> PathBuf {
        self.paths.vsock(name)
    }

    async fn shutdown(&self) {
        let names: Vec<String> = self.slots.lock().unwrap().keys().cloned().collect();
        let stops = names.iter().map(|n| async move {
            if self.current_state(n) != VmState::Stopped {
                info!("stopping VM {n}");
                let _ = self.stop(n).await;
            }
        });
        futures_join_all(stops).await;
        self.refresh_sleep_guard();
    }
}

/// Wait until the helper has stopped (`true`) or `d` passes (`false`).
async fn wait_stopped(rx: &mut watch::Receiver<VmState>, d: Duration) -> bool {
    let fut = async {
        while *rx.borrow_and_update() != VmState::Stopped {
            if rx.changed().await.is_err() {
                break;
            }
        }
    };
    tokio::time::timeout(d, fut).await.is_ok()
}

/// Run futures concurrently without a `futures` dependency.
async fn futures_join_all<F: std::future::Future<Output = ()>>(futs: impl IntoIterator<Item = F>) {
    let mut pinned: Vec<Option<std::pin::Pin<Box<F>>>> = futs.into_iter().map(|f| Some(Box::pin(f))).collect();
    std::future::poll_fn(|cx| {
        let mut pending = false;
        for slot in pinned.iter_mut() {
            if let Some(f) = slot {
                if f.as_mut().poll(cx).is_ready() {
                    *slot = None;
                } else {
                    pending = true;
                }
            }
        }
        if pending {
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(())
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha512sums_lookup() {
        let sums = "AAA  other.tar.xz\nabcdef  debian-13-generic-arm64.tar.xz\n";
        assert_eq!(expected_sha512(sums, "debian-13-generic-arm64.tar.xz").as_deref(), Some("abcdef"));
        assert_eq!(expected_sha512(sums, "missing"), None);
    }

    #[test]
    fn memory_budget_is_ram_minus_four_gib() {
        // 16 GiB host: 12 GiB budget.
        assert!(check_memory_budget(0, 12 * 1024, 16 * 1024).is_ok());
        assert!(check_memory_budget(8 * 1024, 4 * 1024, 16 * 1024).is_ok());
        assert!(check_memory_budget(8 * 1024, 4 * 1024 + 1, 16 * 1024).is_err());
        assert!(check_memory_budget(0, 1, 2048).is_err(), "tiny host never underflows");
    }

    #[test]
    fn free_space_needs_image_plus_ten_gib() {
        let img = 3u64 << 30;
        assert!(check_free_space(13 << 30, img).is_ok());
        assert!(check_free_space((13 << 30) - 1, img).is_err());
        assert!(free_bytes(&std::env::temp_dir()).unwrap() > 0);
        assert!(host_memory_mb().unwrap() > 1024);
    }

    #[test]
    fn image_dir_mapping() {
        let p = Paths::new("/v");
        let spec = image_spec("debian-13").unwrap();
        assert_eq!(p.image_disk(spec), PathBuf::from("/v/images/debian-13-generic-arm64/disk.raw"));
        assert!(image_spec("nope").is_err());
    }
}
