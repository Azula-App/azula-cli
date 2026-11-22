//! The local backend (Linux): the machine the broker runs on *is* the
//! sandbox, so "starting the VM" means spawning `azula-guest --unix <sock>` as
//! a child and "the VM's vsock" is that worker's Unix socket (`vm/BROKER.md`
//! §9). Only appropriate where the machine is already an isolated VM, such as
//! Android's Linux Terminal.
//!
//! The module also compiles under `cfg(test)` on other Unixes so the pure
//! parts (paths, command line, flag validation) are unit-tested everywhere.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::VecDeque;
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tracing::{info, warn};

use super::vm::{VmBackend, VmError, VmInfo, VmState};
use super::{guest, valid_vm_name, vm_dir};

/// Default VM name (the `--vm` default for a `vms:["*"]` grant).
pub const DEFAULT_NAME: &str = "default";
/// Default user the worker runs jobs as.
pub const DEFAULT_RUN_AS: &str = "azula";
/// How long `start` waits for the worker to answer a ping.
pub const START_DEADLINE: Duration = Duration::from_secs(30);
/// How long `stop` waits after SIGTERM before SIGKILL.
pub const STOP_GRACE: Duration = Duration::from_secs(10);
/// Lines of worker stderr kept for start-failure messages.
const STDERR_KEEP: usize = 20;

/// How long attach-mode `start` waits for an already-provisioned worker (the
/// VM may still be booting).
pub const ATTACH_DEADLINE: Duration = Duration::from_secs(180);
/// Attach-mode `start` poll interval.
pub const ATTACH_POLL: Duration = Duration::from_secs(1);

/// Attach mode (`--worker-socket`): the worker already exists (e.g. inside an
/// AVF VM on Android) and is reachable on this Unix socket; the broker never
/// spawns or stops it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachOpts {
    pub socket: PathBuf,
    pub cpus: u32,
    pub memory_mb: u64,
}

/// Validate the Linux `compute serve` flags (pure, so it is testable anywhere).
/// With `worker_socket` the run-as user is ignored (not even looked up).
pub fn validate_serve_flags(
    local: bool,
    vm_name: &str,
    run_as: &str,
    worker_socket: Option<&Path>,
    vm_cpus: Option<u32>,
    vm_memory_mb: Option<u64>,
) -> Result<(), String> {
    if !local {
        return Err("on Linux `azula compute serve` runs jobs on this machine itself, with no VM in between. \
             That is only appropriate when this machine is already an isolated VM (for example Android's \
             Linux Terminal). Pass --local to confirm."
            .to_owned());
    }
    if !valid_vm_name(vm_name) {
        return Err(format!("--vm-name: invalid name `{vm_name}` (lowercase letters, digits and `-`, 1..=63 chars)"));
    }
    if let Some(sock) = worker_socket {
        if !sock.is_absolute() {
            return Err(format!("--worker-socket: `{}` must be an absolute path", sock.display()));
        }
        return Ok(());
    }
    if vm_cpus.is_some() || vm_memory_mb.is_some() {
        return Err("--vm-cpus and --vm-memory-mb only apply together with --worker-socket".to_owned());
    }
    if run_as.is_empty() || run_as.starts_with('-') || run_as.chars().any(|c| c.is_whitespace() || c == '/') {
        return Err(format!("--run-as: invalid user name `{run_as}`"));
    }
    Ok(())
}

/// Layout of the per-VM directory: `<vm_dir>/local/<name>/{run,state}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalPaths {
    pub dir: PathBuf,
}

impl LocalPaths {
    pub fn new(name: &str) -> Self {
        Self::under(&vm_dir(), name)
    }

    pub fn under(vm_dir: &Path, name: &str) -> Self {
        Self { dir: vm_dir.join("local").join(name) }
    }

    /// 0700, owned by the broker user: the access control for the socket.
    pub fn run_dir(&self) -> PathBuf {
        self.dir.join("run")
    }

    pub fn socket(&self) -> PathBuf {
        self.run_dir().join("worker.sock")
    }

    pub fn state_dir(&self) -> PathBuf {
        self.dir.join("state")
    }
}

/// The program and arguments that start the worker: directly when the broker
/// is root, else through `sudo -n` with `umask 0` so the root-created socket
/// is connectable (the 0700 parent directory is what restricts access).
pub fn worker_command(is_root: bool, guest_bin: &Path, sock: &Path, run_as: &str, state_dir: &Path) -> (String, Vec<String>) {
    let s = |p: &Path| p.to_string_lossy().into_owned();
    let worker_args = ["--unix".to_owned(), s(sock), "--run-as".to_owned(), run_as.to_owned(), "--state-dir".to_owned(), s(state_dir)];
    if is_root {
        (s(guest_bin), worker_args.to_vec())
    } else {
        let mut args = vec!["-n".to_owned(), "sh".to_owned(), "-c".to_owned(), "umask 0; exec \"$0\" \"$@\"".to_owned(), s(guest_bin)];
        args.extend(worker_args);
        ("sudo".to_owned(), args)
    }
}

/// `$AZULA_GUEST_BIN`, else `azula-guest` or `azula-guest.linux-aarch64` next
/// to this executable, else `azula-guest` on `PATH`.
pub fn find_guest_bin() -> Result<PathBuf, String> {
    if let Some(p) = std::env::var_os("AZULA_GUEST_BIN").filter(|p| !p.is_empty()) {
        let p = PathBuf::from(p);
        return if p.is_file() { Ok(p) } else { Err(format!("AZULA_GUEST_BIN={} is not a file", p.display())) };
    }
    let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf));
    if let Some(d) = exe_dir {
        for n in ["azula-guest", "azula-guest.linux-aarch64"] {
            let p = d.join(n);
            if p.is_file() {
                return Ok(p);
            }
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let p = dir.join("azula-guest");
            if p.is_file() {
                return Ok(p);
            }
        }
    }
    Err("the guest worker binary was not found: set AZULA_GUEST_BIN, or put azula-guest next to the azula binary or on PATH".to_owned())
}

/// `MemTotal` of `/proc/meminfo` text, in MiB.
pub fn parse_mem_total_mb(meminfo: &str) -> Option<u64> {
    let line = meminfo.lines().find(|l| l.starts_with("MemTotal:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kb / 1024)
}

fn user_exists(name: &str) -> bool {
    let Ok(c) = CString::new(name) else { return false };
    // SAFETY: `c` is a valid NUL-terminated string; the result is only tested for null.
    !unsafe { libc::getpwnam(c.as_ptr()) }.is_null()
}

fn online_cpus() -> u32 {
    // SAFETY: sysconf has no preconditions.
    let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    n.max(1) as u32
}

/// Total size of the filesystem holding `path`, in GiB.
// statvfs field widths differ between libc targets, so the casts are needed somewhere.
#[allow(clippy::unnecessary_cast)]
fn fs_total_gb(path: &Path) -> Option<u64> {
    let c = CString::new(path.to_str()?).ok()?;
    let mut st = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
    // SAFETY: `c` is NUL-terminated and `st` is valid for writes of a statvfs.
    if unsafe { libc::statvfs(c.as_ptr(), st.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: statvfs succeeded, so the struct is initialised.
    let st = unsafe { st.assume_init() };
    Some((st.f_blocks as u64).saturating_mul(st.f_frsize as u64) >> 30)
}

#[derive(Default)]
struct Inner {
    child: Option<Child>,
    starting: bool,
    stopping: bool,
    error: Option<String>,
}

/// A blocking one-shot `ping` (cheap, for the synchronous `state`): true iff
/// the worker answers a `pong` within `timeout`.
fn ping_blocking(sock: &Path, timeout: Duration) -> bool {
    use std::io::{Read, Write};
    let Ok(mut s) = std::os::unix::net::UnixStream::connect(sock) else { return false };
    let _ = s.set_read_timeout(Some(timeout));
    let _ = s.set_write_timeout(Some(timeout));
    let Ok(buf) = super::frame::Frame::of_type("ping").encode() else { return false };
    if s.write_all(&buf).is_err() {
        return false;
    }
    let mut len = [0u8; 8];
    if s.read_exact(&mut len).is_err() {
        return false;
    }
    let hlen = u32::from_be_bytes([len[0], len[1], len[2], len[3]]) as usize;
    if hlen == 0 || hlen > super::frame::MAX_HEADER {
        return false;
    }
    let mut h = vec![0u8; hlen];
    if s.read_exact(&mut h).is_err() {
        return false;
    }
    serde_json::from_slice::<serde_json::Value>(&h).ok().and_then(|v| v.get("t").and_then(|t| t.as_str()).map(|t| t == "pong")).unwrap_or(false)
}

/// One "VM": the worker running on this machine.
pub struct LocalBackend {
    attach: Option<AttachOpts>,
    name: String,
    run_as: String,
    paths: LocalPaths,
    inner: Mutex<Inner>,
    /// Serialises `start` and `stop`.
    gate: tokio::sync::Mutex<()>,
    stderr: Arc<Mutex<VecDeque<String>>>,
}

impl LocalBackend {
    pub fn new(name: impl Into<String>, run_as: impl Into<String>) -> Self {
        let name = name.into();
        let paths = LocalPaths::new(&name);
        Self { attach: None, name, run_as: run_as.into(), paths, inner: Mutex::new(Inner::default()), gate: tokio::sync::Mutex::new(()), stderr: Arc::default() }
    }

    /// Attach mode: the worker is already listening on `opts.socket`; nothing is spawned.
    pub fn attach(name: impl Into<String>, opts: AttachOpts) -> Self {
        let mut b = Self::new(name, "");
        b.attach = Some(opts);
        b
    }

    pub fn is_attach(&self) -> bool {
        self.attach.is_some()
    }

    pub fn run_as(&self) -> &str {
        &self.run_as
    }

    pub fn paths(&self) -> &LocalPaths {
        &self.paths
    }

    fn check(&self, name: &str) -> Result<(), VmError> {
        if name == self.name {
            Ok(())
        } else {
            Err(VmError::unknown(name))
        }
    }

    fn current_state(&self) -> VmState {
        if let Some(a) = &self.attach {
            let g = self.inner.lock().unwrap();
            if g.starting {
                return VmState::Starting;
            }
            drop(g);
            return if ping_blocking(&a.socket, Duration::from_secs(1)) { VmState::Running } else { VmState::Stopped };
        }
        let mut g = self.inner.lock().unwrap();
        if g.stopping {
            return VmState::Stopping;
        }
        if g.starting {
            return VmState::Starting;
        }
        match g.child.as_mut().map(Child::try_wait) {
            Some(Ok(None)) => VmState::Running,
            Some(_) => {
                g.child = None;
                VmState::Stopped
            }
            None => VmState::Stopped,
        }
    }

    fn stderr_tail(&self) -> String {
        self.stderr.lock().unwrap().iter().cloned().collect::<Vec<_>>().join("\n")
    }

    fn fail(&self, why: &str) -> VmError {
        let mut msg = format!("local worker `{}` failed to start: {why}", self.name);
        let tail = self.stderr_tail();
        if !tail.is_empty() {
            msg.push_str(&format!("\nworker output:\n{tail}"));
        }
        let err = VmError::new("vm_start_failed", msg);
        self.inner.lock().unwrap().error = Some(err.msg.clone());
        err
    }

    fn prepare_dirs(&self) -> Result<(), VmError> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let io = |what: &str, e: std::io::Error| VmError::new("vm_start_failed", format!("{what}: {e}"));
        let run = self.paths.run_dir();
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&run).map_err(|e| io(&format!("creating {}", run.display()), e))?;
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).map_err(|e| io(&format!("securing {}", run.display()), e))?;
        let state = self.paths.state_dir();
        std::fs::create_dir_all(&state).map_err(|e| io(&format!("creating {}", state.display()), e))?;
        let sock = self.paths.socket();
        if sock.exists() {
            if std::os::unix::net::UnixStream::connect(&sock).is_ok() {
                return Err(VmError::new("vm_start_failed", format!("a worker is already listening on {} under another process", sock.display())));
            }
            let _ = std::fs::remove_file(&sock);
        }
        Ok(())
    }

    fn spawn_worker(&self) -> Result<Child, VmError> {
        let bin = find_guest_bin().map_err(|m| VmError::new("vm_start_failed", m))?;
        if !user_exists(&self.run_as) {
            return Err(VmError::new(
                "vm_start_failed",
                format!("the run-as user `{0}` does not exist; create it with `sudo useradd -m -s /bin/bash {0}`", self.run_as),
            ));
        }
        self.prepare_dirs()?;
        // SAFETY: geteuid has no preconditions.
        let is_root = unsafe { libc::geteuid() } == 0;
        let (prog, args) = worker_command(is_root, &bin, &self.paths.socket(), &self.run_as, &self.paths.state_dir());
        info!("starting local worker: {prog} {}", args.join(" "));
        self.stderr.lock().unwrap().clear();
        let mut child = Command::new(prog)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| VmError::new("vm_start_failed", format!("spawning the worker: {e}")))?;
        if let Some(err) = child.stderr.take() {
            let keep = self.stderr.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(err).lines();
                while let Ok(Some(l)) = lines.next_line().await {
                    let mut q = keep.lock().unwrap();
                    if q.len() == STDERR_KEEP {
                        q.pop_front();
                    }
                    q.push_back(l);
                }
            });
        }
        Ok(child)
    }

    /// Ask the worker to exit, escalating to SIGKILL; never holds `inner` across an await.
    async fn terminate(&self, mut child: Child) {
        if let Some(pid) = child.id() {
            // SAFETY: signalling a child process we spawned (sudo relays SIGTERM).
            unsafe { libc::kill(pid as i32, libc::SIGTERM) };
        }
        if tokio::time::timeout(STOP_GRACE, child.wait()).await.is_err() {
            warn!("local worker did not stop within {}s; killing", STOP_GRACE.as_secs());
            let _ = child.start_kill();
            // sudo cannot relay SIGKILL, so a non-root broker also kills the worker via sudo.
            if unsafe { libc::geteuid() } != 0 {
                let _ = Command::new("sudo").args(["-n", "pkill", "-KILL", "-f"]).arg(self.paths.socket()).status().await;
            }
            let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
        }
        let _ = std::fs::remove_file(self.paths.socket());
    }
}

impl VmBackend for LocalBackend {
    fn names(&self) -> Result<Vec<String>, VmError> {
        Ok(vec![self.name.clone()])
    }

    fn state(&self, name: &str) -> Result<VmState, VmError> {
        self.check(name)?;
        Ok(self.current_state())
    }

    async fn info(&self, name: &str) -> Result<VmInfo, VmError> {
        self.check(name)?;
        let state = self.current_state();
        if let Some(a) = &self.attach {
            let (worker, pong) = if state == VmState::Running {
                match guest::ping(&a.socket, Duration::from_secs(5)).await {
                    Ok(p) => ("ready", Some(p)),
                    Err(_) => ("unreachable", None),
                }
            } else {
                ("unknown", None)
            };
            let error = self.inner.lock().unwrap().error.clone();
            let shown = if state == VmState::Stopped && error.is_some() { "failed" } else { state.as_str() };
            return Ok(VmInfo {
                name: self.name.clone(),
                state: shown.into(),
                worker: worker.into(),
                image: "avf".into(),
                cpus: a.cpus,
                memory_mb: a.memory_mb,
                disk_gb: 0,
                network: "proxy".into(),
                jobs_running: None,
                disk_free_mb: None,
                worker_info: None,
                error,
            }
            .with_pong(pong));
        }
        let (worker, pong) = if state == VmState::Running {
            match guest::ping(&self.paths.socket(), Duration::from_secs(5)).await {
                Ok(p) => ("ready", Some(p)),
                Err(_) => ("unreachable", None),
            }
        } else {
            ("unknown", None)
        };
        let error = self.inner.lock().unwrap().error.clone();
        let shown = if state == VmState::Stopped && error.is_some() { "failed" } else { state.as_str() };
        Ok(VmInfo {
            name: self.name.clone(),
            state: shown.into(),
            worker: worker.into(),
            image: "local".into(),
            cpus: online_cpus(),
            memory_mb: std::fs::read_to_string("/proc/meminfo").ok().and_then(|t| parse_mem_total_mb(&t)).unwrap_or(0),
            disk_gb: fs_total_gb(&self.paths.state_dir()).unwrap_or(0),
            network: "host".into(),
            jobs_running: None,
            disk_free_mb: None,
            worker_info: None,
            error,
        }
        .with_pong(pong))
    }

    async fn start(&self, name: &str) -> Result<(), VmError> {
        self.check(name)?;
        let _gate = self.gate.lock().await;
        if self.current_state() == VmState::Running {
            return Ok(());
        }
        self.inner.lock().unwrap().starting = true;
        let result = match &self.attach {
            Some(a) => self.attach_wait(&a.socket, ATTACH_DEADLINE).await,
            None => self.start_locked().await,
        };
        self.inner.lock().unwrap().starting = false;
        match result {
            Ok(()) => {
                self.inner.lock().unwrap().error = None;
                Ok(())
            }
            Err(e) => {
                self.inner.lock().unwrap().error = Some(e.msg.clone());
                Err(e)
            }
        }
    }

    async fn stop(&self, name: &str) -> Result<(), VmError> {
        self.check(name)?;
        if self.attach.is_some() {
            return Err(VmError::new("unsupported", "this broker is attached to an externally managed worker (--worker-socket); stop the VM from the host app instead"));
        }
        let _gate = self.gate.lock().await;
        let child = {
            let mut g = self.inner.lock().unwrap();
            let c = g.child.take();
            g.stopping = c.is_some();
            c
        };
        if let Some(child) = child {
            self.terminate(child).await;
            self.inner.lock().unwrap().stopping = false;
        }
        Ok(())
    }

    fn vsock_path(&self, _name: &str) -> PathBuf {
        match &self.attach {
            Some(a) => a.socket.clone(),
            None => self.paths.socket(),
        }
    }

    async fn shutdown(&self) {
        if self.attach.is_some() {
            return;
        }
        info!("stopping local worker {}", self.name);
        let _ = self.stop(&self.name.clone()).await;
    }
}

impl LocalBackend {
    /// Attach mode: poll `ping` every [`ATTACH_POLL`] until the worker answers
    /// or `deadline` passes. Caller holds the gate.
    async fn attach_wait(&self, sock: &Path, deadline: Duration) -> Result<(), VmError> {
        let end = tokio::time::Instant::now() + deadline;
        loop {
            let err = match guest::ping(sock, Duration::from_secs(2)).await {
                Ok(_) => return Ok(()),
                Err(e) => e,
            };
            if tokio::time::Instant::now() + ATTACH_POLL >= end {
                let msg = format!("the attached worker at {} did not answer within {}s ({err})", sock.display(), deadline.as_secs());
                return Err(VmError::new("vm_start_failed", msg));
            }
            tokio::time::sleep(ATTACH_POLL).await;
        }
    }

    /// Spawn the worker and wait for its first `pong`. Caller holds the gate.
    async fn start_locked(&self) -> Result<(), VmError> {
        let child = self.spawn_worker()?;
        self.inner.lock().unwrap().child = Some(child);
        let sock = self.paths.socket();
        let end = tokio::time::Instant::now() + START_DEADLINE;
        let last = loop {
            let exited = {
                let mut g = self.inner.lock().unwrap();
                match g.child.as_mut().map(Child::try_wait) {
                    Some(Ok(Some(status))) => Some(status.to_string()),
                    Some(Err(e)) => Some(e.to_string()),
                    _ => None,
                }
            };
            if let Some(status) = exited {
                self.inner.lock().unwrap().child = None;
                // Give the stderr reader a moment to drain the dead child's pipe.
                tokio::time::sleep(Duration::from_millis(100)).await;
                // SAFETY: geteuid has no preconditions.
                let hint = if unsafe { libc::geteuid() } != 0 { " (the worker is started with `sudo -n`; is passwordless sudo available?)" } else { "" };
                return Err(self.fail(&format!("the worker exited before answering ({status}){hint}")));
            }
            let err = match guest::ping(&sock, Duration::from_secs(2)).await {
                Ok(_) => return Ok(()),
                Err(e) => e,
            };
            if tokio::time::Instant::now() + Duration::from_millis(500) >= end {
                break err;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        };
        let child = self.inner.lock().unwrap().child.take();
        if let Some(child) = child {
            self.terminate(child).await;
        }
        Err(self.fail(&format!("the worker did not answer within {}s ({last})", START_DEADLINE.as_secs())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serve_requires_local_flag() {
        assert!(validate_serve_flags(false, "default", "azula", None, None, None).unwrap_err().contains("--local"));
        assert!(validate_serve_flags(true, "default", "azula", None, None, None).is_ok());
    }

    #[test]
    fn serve_flag_names_are_validated() {
        assert!(validate_serve_flags(true, "Bad Name", "azula", None, None, None).is_err());
        assert!(validate_serve_flags(true, "", "azula", None, None, None).is_err());
        assert!(validate_serve_flags(true, "pixel-1", "azula", None, None, None).is_ok());
        assert!(validate_serve_flags(true, "default", "", None, None, None).is_err());
        assert!(validate_serve_flags(true, "default", "-x", None, None, None).is_err());
        assert!(validate_serve_flags(true, "default", "a b", None, None, None).is_err());
    }

    #[test]
    fn path_layout() {
        let p = LocalPaths::under(Path::new("/v"), "default");
        assert_eq!(p.dir, Path::new("/v/local/default"));
        assert_eq!(p.socket(), Path::new("/v/local/default/run/worker.sock"));
        assert_eq!(p.state_dir(), Path::new("/v/local/default/state"));
    }

    #[test]
    fn worker_command_direct_as_root() {
        let (prog, args) = worker_command(true, Path::new("/bin/azula-guest"), Path::new("/r/w.sock"), "azula", Path::new("/s"));
        assert_eq!(prog, "/bin/azula-guest");
        assert_eq!(args, ["--unix", "/r/w.sock", "--run-as", "azula", "--state-dir", "/s"]);
    }

    #[test]
    fn worker_command_uses_sudo_with_umask_otherwise() {
        let (prog, args) = worker_command(false, Path::new("/bin/azula-guest"), Path::new("/r/w.sock"), "azula", Path::new("/s"));
        assert_eq!(prog, "sudo");
        assert_eq!(&args[..5], ["-n", "sh", "-c", "umask 0; exec \"$0\" \"$@\"", "/bin/azula-guest"]);
        assert_eq!(&args[5..], ["--unix", "/r/w.sock", "--run-as", "azula", "--state-dir", "/s"]);
    }

    #[test]
    fn meminfo_parsing() {
        assert_eq!(parse_mem_total_mb("MemTotal:        8165304 kB\nMemFree: 1 kB\n"), Some(7973));
        assert_eq!(parse_mem_total_mb("MemFree: 1 kB\n"), None);
    }

    #[test]
    fn single_vm_name() {
        let b = LocalBackend::new("default", "azula");
        assert_eq!(b.names().unwrap(), ["default"]);
        assert_eq!(b.state("default").unwrap(), VmState::Stopped);
        assert_eq!(b.state("other").unwrap_err().code, "unknown_vm");
    }

    // --- attach mode ---------------------------------------------------------

    /// A fake worker: answers every connection's first frame with a `pong`.
    fn fake_worker(sock: &Path) -> tokio::task::JoinHandle<()> {
        use super::super::frame::{read_frame, write_frame, Frame};
        let l = tokio::net::UnixListener::bind(sock).unwrap();
        tokio::spawn(async move {
            while let Ok((mut c, _)) = l.accept().await {
                tokio::spawn(async move {
                    if let Ok(Some(f)) = read_frame(&mut c).await {
                        if f.t() == "ping" {
                            let _ = write_frame(&mut c, &Frame::new(serde_json::json!({"t": "pong", "jobs_running": 2, "disk_free_mb": 99}))).await;
                        }
                    }
                });
            }
        })
    }

    fn attach_backend(sock: &Path) -> LocalBackend {
        LocalBackend::attach("pixel", AttachOpts { socket: sock.to_path_buf(), cpus: 4, memory_mb: 2048 })
    }

    fn tmp_sock(tag: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("azula-attach-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        (dir.join("w.sock"), dir)
    }

    #[test]
    fn attach_flag_validation() {
        let sock = Path::new("/data/w.sock");
        // run-as is ignored (even invalid) in attach mode
        assert!(validate_serve_flags(true, "default", "", Some(sock), Some(4), Some(2048)).is_ok());
        assert!(validate_serve_flags(true, "default", "a b", Some(sock), None, None).is_ok());
        assert!(validate_serve_flags(false, "default", "azula", Some(sock), None, None).unwrap_err().contains("--local"));
        assert!(validate_serve_flags(true, "Bad", "azula", Some(sock), None, None).is_err());
        assert!(validate_serve_flags(true, "default", "azula", Some(Path::new("rel.sock")), None, None).unwrap_err().contains("absolute"));
        assert!(validate_serve_flags(true, "default", "azula", None, Some(4), None).unwrap_err().contains("--worker-socket"));
        assert!(validate_serve_flags(true, "default", "azula", None, None, Some(1)).is_err());
    }

    // multi-thread: `state` pings with a blocking socket call
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn attach_start_state_info_and_stop() {
        let (sock, dir) = tmp_sock("ok");
        let b = attach_backend(&sock);
        assert!(b.is_attach());
        assert_eq!(b.vsock_path("pixel"), sock);
        assert_eq!(b.state("pixel").unwrap(), VmState::Stopped);
        let worker = fake_worker(&sock);
        assert_eq!(b.state("pixel").unwrap(), VmState::Running);
        b.start("pixel").await.unwrap();
        let info = b.info("pixel").await.unwrap();
        assert_eq!((info.image.as_str(), info.network.as_str(), info.cpus, info.memory_mb), ("avf", "proxy", 4, 2048));
        assert_eq!((info.state.as_str(), info.worker.as_str(), info.jobs_running, info.disk_free_mb), ("running", "ready", Some(2), Some(99)));
        let e = b.stop("pixel").await.unwrap_err();
        assert_eq!(e.code, "unsupported");
        b.shutdown().await;
        assert_eq!(b.state("pixel").unwrap(), VmState::Running, "shutdown must be a no-op");
        assert_eq!(b.state("other").unwrap_err().code, "unknown_vm");
        worker.abort();
        let _ = std::fs::remove_dir_all(dir);
    }

    // multi-thread: `state` pings with a blocking socket call
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn attach_start_waits_for_a_late_worker() {
        let (sock, dir) = tmp_sock("late");
        let b = attach_backend(&sock);
        let s2 = sock.clone();
        let late = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1500)).await;
            let _worker = fake_worker(&s2);
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        b.start("pixel").await.unwrap();
        assert_eq!(b.state("pixel").unwrap(), VmState::Running);
        late.abort();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test(start_paused = true)]
    async fn attach_start_times_out_as_vm_start_failed() {
        let (sock, dir) = tmp_sock("none");
        let b = attach_backend(&sock);
        let e = b.start("pixel").await.unwrap_err();
        assert_eq!(e.code, "vm_start_failed");
        assert!(e.msg.contains("180s"), "{}", e.msg);
        assert_eq!(b.info("pixel").await.unwrap().state, "failed");
        let _ = std::fs::remove_dir_all(dir);
    }
}
