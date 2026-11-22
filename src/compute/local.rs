//! The local backend (Linux): the machine the broker runs on *is* the
//! sandbox. The broker never spawns or stops the worker; it only connects to
//! an `azula-guest` that something else keeps listening on a Unix socket
//! (`vm/BROKER.md` §9):
//!
//! * **Terminal mode** (`serve --local`): systemd socket activation. The
//!   socket is `/run/azula/worker.sock`, openable only by the broker's user,
//!   and the worker behind it runs as the unprivileged job user
//!   (`azula compute local-setup` installs the units). Before binding, the
//!   broker refuses a job user that could escape its confinement
//!   ([`check_job_user`]).
//! * **Attach mode** (`--worker-socket`): the worker lives elsewhere (inside
//!   an AVF VM bridged by the azula Android app). No user checks: there is no
//!   `/etc/passwd` here and the worker is in another VM.
//!
//! The module also compiles under `cfg(test)` on other Unixes so the pure
//! parts (flag validation, user checks) are unit-tested everywhere.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::ffi::{CStr, CString};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use super::vm::{VmBackend, VmError, VmInfo, VmState};
use super::{guest, valid_vm_name};

/// Default VM name (the `--vm` default for a `vms:["*"]` grant).
pub const DEFAULT_NAME: &str = "default";
/// Default user the worker runs jobs as.
pub const DEFAULT_RUN_AS: &str = "azula";
/// The socket `azula-guest.socket` listens on in Terminal mode.
pub const DEFAULT_WORKER_SOCKET: &str = "/run/azula/worker.sock";

/// How long Terminal-mode `start` waits for the activated worker to answer.
pub const START_DEADLINE: Duration = Duration::from_secs(30);
/// How long attach-mode `start` waits for an already-provisioned worker (the
/// VM may still be booting).
pub const ATTACH_DEADLINE: Duration = Duration::from_secs(180);
/// `start` poll interval.
pub const START_POLL: Duration = Duration::from_secs(1);

/// Attach mode (`--worker-socket`): the worker already exists (e.g. inside an
/// AVF VM on Android) and is reachable on this Unix socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachOpts {
    pub socket: PathBuf,
    pub cpus: u32,
    pub memory_mb: u64,
}

/// Why `compute serve` needs `--local` on Linux.
pub const NEEDS_LOCAL_MSG: &str = "on Linux `azula compute serve` has no VM to boot: with --local it runs jobs on this machine itself, \
     as an unprivileged job user behind a systemd-activated socket. That is only appropriate when this machine is already an isolated \
     VM (for example Android's Linux Terminal). Run `sudo azula compute local-setup` once to prepare it, then pass --local \
     (`azula-compute.service` does).";

/// Validate the Linux `compute serve` flags (pure, so it is testable anywhere).
/// With `worker_socket` (attach mode) the run-as user is ignored (not even looked up).
pub fn validate_serve_flags(
    local: bool,
    vm_name: &str,
    run_as: &str,
    worker_socket: Option<&Path>,
    vm_cpus: Option<u32>,
    vm_memory_mb: Option<u64>,
) -> Result<(), String> {
    if !local {
        return Err(NEEDS_LOCAL_MSG.to_owned());
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

// --- job-user checks (Terminal mode) -----------------------------------------

/// A passwd entry, as far as the job-user checks care.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserEntry {
    pub uid: u32,
    pub gid: u32,
}

/// Account lookups, injectable so the checks are unit-tested without real users.
pub trait UserDb {
    fn user(&self, name: &str) -> Option<UserEntry>;
    /// `(gid, members)` of the group, or `None` if it doesn't exist.
    fn group(&self, name: &str) -> Option<(u32, Vec<String>)>;
}

/// The system's passwd and group databases (libc, so NSS is honoured).
pub struct SystemDb;

impl UserDb for SystemDb {
    fn user(&self, name: &str) -> Option<UserEntry> {
        let c = CString::new(name).ok()?;
        // SAFETY: `c` is NUL-terminated; the returned static passwd is read immediately.
        let pw = unsafe { libc::getpwnam(c.as_ptr()) };
        if pw.is_null() {
            return None;
        }
        // SAFETY: non-null result of getpwnam.
        let pw = unsafe { &*pw };
        Some(UserEntry { uid: pw.pw_uid, gid: pw.pw_gid })
    }

    fn group(&self, name: &str) -> Option<(u32, Vec<String>)> {
        let c = CString::new(name).ok()?;
        // SAFETY: as above; gr_mem is a NULL-terminated array of C strings.
        unsafe {
            let gr = libc::getgrnam(c.as_ptr());
            if gr.is_null() {
                return None;
            }
            let gr = &*gr;
            let mut members = Vec::new();
            let mut p = gr.gr_mem;
            while !p.is_null() && !(*p).is_null() {
                members.push(CStr::from_ptr(*p).to_string_lossy().into_owned());
                p = p.add(1);
            }
            Some((gr.gr_gid, members))
        }
    }
}

/// Groups whose members can gain root.
pub const ROOT_GROUPS: [&str; 2] = ["sudo", "wheel"];

/// Refuse a job user that is missing, root, the broker's own user, or can
/// gain root through `sudo`/`wheel`. The error names the violation.
pub fn check_job_user(db: &dyn UserDb, run_as: &str, broker_uid: u32) -> Result<(), String> {
    let Some(u) = db.user(run_as) else {
        return Err(format!("the job user `{0}` does not exist; run `sudo azula compute local-setup` (or `sudo useradd -m -s /bin/bash {0}`)", run_as));
    };
    if u.uid == 0 {
        return Err(format!("the job user `{run_as}` is root (uid 0); jobs must run as an unprivileged user"));
    }
    if u.uid == broker_uid {
        return Err(format!(
            "the job user `{run_as}` is the broker's own user (uid {broker_uid}); jobs must not run as the broker's user, or they could read its host key and grants"
        ));
    }
    for g in ROOT_GROUPS {
        if let Some((gid, members)) = db.group(g) {
            if gid == u.gid || members.iter().any(|m| m == run_as) {
                return Err(format!("the job user `{run_as}` is in the `{g}` group, which can gain root; jobs must not run as a user with sudo"));
            }
        }
    }
    Ok(())
}

/// `$AZULA_GUEST_BIN`, else `azula-guest` or `azula-guest.linux-aarch64` next
/// to this executable, else `azula-guest` on `PATH`. (Used by `local-setup`.)
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
    starting: bool,
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

/// One "VM": the worker reachable on a Unix socket. Connect-only: the broker
/// never starts or stops the worker.
pub struct LocalBackend {
    name: String,
    socket: PathBuf,
    /// `Some` in attach mode, `None` in Terminal mode.
    attach: Option<AttachOpts>,
    inner: Mutex<Inner>,
    /// Serialises `start`.
    gate: tokio::sync::Mutex<()>,
}

impl LocalBackend {
    /// Terminal mode: the systemd-activated socket (`socket`, normally
    /// [`DEFAULT_WORKER_SOCKET`]).
    pub fn terminal(name: impl Into<String>, socket: impl Into<PathBuf>) -> Self {
        Self { name: name.into(), socket: socket.into(), attach: None, inner: Mutex::default(), gate: tokio::sync::Mutex::new(()) }
    }

    /// Attach mode: the worker is already listening on `opts.socket`.
    pub fn attach(name: impl Into<String>, opts: AttachOpts) -> Self {
        Self { name: name.into(), socket: opts.socket.clone(), attach: Some(opts), inner: Mutex::default(), gate: tokio::sync::Mutex::new(()) }
    }

    pub fn is_attach(&self) -> bool {
        self.attach.is_some()
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    fn deadline(&self) -> Duration {
        if self.attach.is_some() {
            ATTACH_DEADLINE
        } else {
            START_DEADLINE
        }
    }

    fn check(&self, name: &str) -> Result<(), VmError> {
        if name == self.name {
            Ok(())
        } else {
            Err(VmError::unknown(name))
        }
    }

    fn current_state(&self) -> VmState {
        if self.inner.lock().unwrap().starting {
            return VmState::Starting;
        }
        if ping_blocking(&self.socket, Duration::from_secs(1)) {
            VmState::Running
        } else {
            VmState::Stopped
        }
    }

    /// Poll `ping` every [`START_POLL`] until the worker answers or `deadline`
    /// passes. (In Terminal mode the first connection makes systemd start it.)
    async fn wait_for_worker(&self, deadline: Duration) -> Result<(), VmError> {
        let end = tokio::time::Instant::now() + deadline;
        loop {
            let err = match guest::ping(&self.socket, Duration::from_secs(2)).await {
                Ok(_) => return Ok(()),
                Err(e) => e,
            };
            if tokio::time::Instant::now() + START_POLL >= end {
                let what = if self.attach.is_some() {
                    "the attached worker"
                } else {
                    "the local worker (is `azula-guest.socket` enabled? run `sudo azula compute local-setup`)"
                };
                let msg = format!("{what} at {} did not answer within {}s ({err})", self.socket.display(), deadline.as_secs());
                return Err(VmError::new("vm_start_failed", msg));
            }
            tokio::time::sleep(START_POLL).await;
        }
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
        let (worker, pong) = if state == VmState::Running {
            match guest::ping(&self.socket, Duration::from_secs(5)).await {
                Ok(p) => ("ready", Some(p)),
                Err(_) => ("unreachable", None),
            }
        } else {
            ("unknown", None)
        };
        let error = self.inner.lock().unwrap().error.clone();
        let shown = if state == VmState::Stopped && error.is_some() { "failed" } else { state.as_str() };
        let (image, network, cpus, memory_mb, disk_gb) = match &self.attach {
            Some(a) => ("avf", "proxy", a.cpus, a.memory_mb, 0),
            None => (
                "local",
                "host",
                online_cpus(),
                std::fs::read_to_string("/proc/meminfo").ok().and_then(|t| parse_mem_total_mb(&t)).unwrap_or(0),
                fs_total_gb(Path::new("/")).unwrap_or(0),
            ),
        };
        Ok(VmInfo {
            name: self.name.clone(),
            state: shown.into(),
            worker: worker.into(),
            image: image.into(),
            cpus,
            memory_mb,
            disk_gb,
            network: network.into(),
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
        let result = self.wait_for_worker(self.deadline()).await;
        let mut g = self.inner.lock().unwrap();
        g.starting = false;
        g.error = result.as_ref().err().map(|e| e.msg.clone());
        result
    }

    async fn stop(&self, name: &str) -> Result<(), VmError> {
        self.check(name)?;
        let why = if self.attach.is_some() {
            "this broker is attached to an externally managed worker (--worker-socket); stop the VM from the host app instead"
        } else {
            "the local host cannot be stopped from a client: that would end the machine's own session. Stop it on the machine itself \
             (`systemctl stop azula-guest.service`)"
        };
        Err(VmError::new("unsupported", why))
    }

    fn vsock_path(&self, _name: &str) -> PathBuf {
        self.socket.clone()
    }

    async fn shutdown(&self) {
        // The worker belongs to systemd (or the host app); jobs keep running.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn serve_requires_local_flag() {
        let e = validate_serve_flags(false, "default", "azula", None, None, None).unwrap_err();
        assert!(e.contains("--local") && e.contains("local-setup"), "{e}");
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
    fn meminfo_parsing() {
        assert_eq!(parse_mem_total_mb("MemTotal:        8165304 kB\nMemFree: 1 kB\n"), Some(7973));
        assert_eq!(parse_mem_total_mb("MemFree: 1 kB\n"), None);
    }

    // --- job-user checks ---------------------------------------------------------

    #[derive(Default)]
    struct FakeDb {
        users: HashMap<String, UserEntry>,
        groups: HashMap<String, (u32, Vec<String>)>,
    }

    impl UserDb for FakeDb {
        fn user(&self, name: &str) -> Option<UserEntry> {
            self.users.get(name).cloned()
        }
        fn group(&self, name: &str) -> Option<(u32, Vec<String>)> {
            self.groups.get(name).cloned()
        }
    }

    fn db() -> FakeDb {
        let mut d = FakeDb::default();
        d.users.insert("root".into(), UserEntry { uid: 0, gid: 0 });
        d.users.insert("droid".into(), UserEntry { uid: 1000, gid: 1000 });
        d.users.insert("azula".into(), UserEntry { uid: 1001, gid: 1001 });
        d.groups.insert("sudo".into(), (27, vec!["droid".into()]));
        d
    }

    #[test]
    fn job_user_ok() {
        assert_eq!(check_job_user(&db(), "azula", 1000), Ok(()));
    }

    #[test]
    fn job_user_must_exist() {
        let e = check_job_user(&db(), "nobody-here", 1000).unwrap_err();
        assert!(e.contains("does not exist") && e.contains("nobody-here"), "{e}");
    }

    #[test]
    fn job_user_must_not_be_root() {
        let e = check_job_user(&db(), "root", 1000).unwrap_err();
        assert!(e.contains("is root"), "{e}");
    }

    #[test]
    fn job_user_must_not_be_the_broker() {
        let e = check_job_user(&db(), "azula", 1001).unwrap_err();
        assert!(e.contains("broker's own user"), "{e}");
    }

    #[test]
    fn job_user_must_not_have_sudo() {
        // listed member of `sudo`
        let e = check_job_user(&db(), "droid", 1001).unwrap_err();
        assert!(e.contains("`sudo`"), "{e}");
        // member of `wheel` through the group list
        let mut d = db();
        d.groups.insert("wheel".into(), (10, vec!["azula".into()]));
        let e = check_job_user(&d, "azula", 1000).unwrap_err();
        assert!(e.contains("`wheel`"), "{e}");
        // primary group is `wheel`
        let mut d = db();
        d.groups.insert("wheel".into(), (1001, vec![]));
        assert!(check_job_user(&d, "azula", 1000).unwrap_err().contains("`wheel`"));
    }

    #[test]
    fn system_db_knows_root() {
        let u = SystemDb.user("root").unwrap();
        assert_eq!(u.uid, 0);
        assert!(SystemDb.user("no-such-user-azula-test").is_none());
    }

    // --- connect-only backend ------------------------------------------------------

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
        let dir = std::env::temp_dir().join(format!("azula-local-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        (dir.join("w.sock"), dir)
    }

    #[test]
    fn single_vm_name() {
        let b = LocalBackend::terminal("default", "/nonexistent/w.sock");
        assert!(!b.is_attach());
        assert_eq!(b.names().unwrap(), ["default"]);
        assert_eq!(b.state("default").unwrap(), VmState::Stopped);
        assert_eq!(b.state("other").unwrap_err().code, "unknown_vm");
        assert_eq!(b.vsock_path("default"), Path::new("/nonexistent/w.sock"));
    }

    #[test]
    fn default_socket_is_absolute() {
        assert!(Path::new(DEFAULT_WORKER_SOCKET).is_absolute());
    }

    // multi-thread: `state` pings with a blocking socket call
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn terminal_start_state_info_and_stop() {
        let (sock, dir) = tmp_sock("term");
        let b = LocalBackend::terminal("default", &sock);
        assert_eq!(b.state("default").unwrap(), VmState::Stopped);
        let worker = fake_worker(&sock);
        assert_eq!(b.state("default").unwrap(), VmState::Running);
        b.start("default").await.unwrap();
        let info = b.info("default").await.unwrap();
        assert_eq!((info.image.as_str(), info.network.as_str()), ("local", "host"));
        assert!(info.cpus >= 1);
        assert_eq!((info.state.as_str(), info.worker.as_str(), info.jobs_running, info.disk_free_mb), ("running", "ready", Some(2), Some(99)));
        let e = b.stop("default").await.unwrap_err();
        assert_eq!(e.code, "unsupported");
        b.shutdown().await;
        assert_eq!(b.state("default").unwrap(), VmState::Running, "shutdown must leave the worker alone");
        worker.abort();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test(start_paused = true)]
    async fn terminal_start_failure_hints_at_local_setup() {
        let (sock, dir) = tmp_sock("termfail");
        let b = LocalBackend::terminal("default", &sock);
        let e = b.start("default").await.unwrap_err();
        assert_eq!(e.code, "vm_start_failed");
        assert!(e.msg.contains("30s") && e.msg.contains("local-setup"), "{}", e.msg);
        let _ = std::fs::remove_dir_all(dir);
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
