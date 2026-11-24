//! Listeners, per-connection dispatch and shared worker state
//! (vm/README.md section 2).

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};

use crate::frame::{read_frame, write_frame};
use crate::identity::resolve;
use crate::jobs::{self, Job};
use crate::util::{lock, now_s, random_hex};
use crate::{files, VERSION};

pub const DEFAULT_STATE_DIR: &str = "/var/lib/azula";

#[derive(Debug, Clone)]
pub struct Config {
    pub run_as: String,
    pub state_dir: PathBuf,
    /// Bytes per output segment file (8 MiB).
    pub segment_size: u64,
    /// Segments kept per stream (32).
    pub keep_segments: usize,
    /// `cancel_on_disconnect` grace (60 s).
    pub orphan_after: Duration,
    pub max_per_owner: usize,
    pub max_per_vm: usize,
    pub max_finished: usize,
    pub max_age: Duration,
    pub max_bytes: u64,
    /// Test only: pretend the disk is full after this many output bytes.
    pub disk_limit: Option<u64>,
    /// Extra environment for every job, applied after the clean base and
    /// before the request's own `env` (`--job-env-file`). Hosts without a
    /// NIC use it to point jobs at a proxy.
    pub job_env: Vec<(String, String)>,
}

impl Config {
    pub fn new(run_as: impl Into<String>, state_dir: impl Into<PathBuf>) -> Config {
        Config {
            run_as: run_as.into(),
            state_dir: state_dir.into(),
            segment_size: 8 << 20,
            keep_segments: 32,
            orphan_after: Duration::from_secs(60),
            max_per_owner: 16,
            max_per_vm: 64,
            max_finished: 200,
            max_age: Duration::from_secs(24 * 3600),
            max_bytes: 2 << 30,
            disk_limit: None,
            job_env: Vec::new(),
        }
    }
}

/// Shared worker state: config, the job table, the on-disk store.
pub struct Server {
    pub cfg: Config,
    pub jobs: Mutex<HashMap<String, Arc<Job>>>,
    pub salt: String,
    pub written: AtomicU64,
}

impl Server {
    /// Open (or create) the state dir, mark leftover running jobs
    /// `interrupted`, drop stale part files, apply retention.
    pub fn open(cfg: Config) -> io::Result<Arc<Server>> {
        fs::create_dir_all(cfg.state_dir.join("jobs"))?;
        fs::create_dir_all(cfg.state_dir.join("uploads"))?;
        // Jobs' records and output, and the salt: the worker's own. (With the
        // root worker of a VM that is not a boundary while the job user has sudo.)
        if let Err(e) = fs::set_permissions(&cfg.state_dir, fs::Permissions::from_mode(0o700)) {
            eprintln!("azula-guest: {}: {e}", cfg.state_dir.display());
        }
        let salt_path = cfg.state_dir.join("salt");
        let salt = match fs::read_to_string(&salt_path) {
            Ok(s) if !s.trim().is_empty() => s.trim().to_string(),
            _ => {
                let s = random_hex(16);
                crate::util::write_atomic(&salt_path, s.as_bytes())?;
                s
            }
        };
        let srv = Arc::new(Server {
            cfg,
            jobs: Mutex::new(HashMap::new()),
            salt,
            written: AtomicU64::new(0),
        });
        jobs::load_all(&srv);
        files::prune_stale_parts(&srv);
        srv.prune();
        let weak: Weak<Server> = Arc::downgrade(&srv);
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(60));
            match weak.upgrade() {
                Some(s) => {
                    s.prune();
                    files::prune_stale_parts(&s);
                }
                None => return,
            }
        });
        Ok(srv)
    }

    pub fn jobs_dir(&self) -> PathBuf {
        self.cfg.state_dir.join("jobs")
    }

    pub fn uploads_dir(&self) -> PathBuf {
        self.cfg.state_dir.join("uploads")
    }

    pub fn running_count(&self) -> usize {
        lock(&self.jobs).values().filter(|j| j.is_running()).count()
    }

    /// Retention: age, count and total size of finished jobs; oldest first.
    pub fn prune(&self) {
        let now = now_s();
        let mut victims = Vec::new();
        {
            let mut map = lock(&self.jobs);
            let mut fin: Vec<Arc<Job>> = map
                .values()
                .filter(|j| lock(&j.inner).state != "running")
                .cloned()
                .collect();
            fin.sort_by_key(|j| (lock(&j.inner).ended.unwrap_or(0), j.created_ms));
            let size = |j: &Arc<Job>| {
                let g = lock(&j.inner);
                g.s.iter().map(|s| s.len - s.earliest).sum::<u64>()
            };
            let mut total: u64 = fin.iter().map(size).sum();
            let mut count = fin.len();
            for j in fin {
                let ended = lock(&j.inner).ended.unwrap_or(0);
                let too_old = ended + self.cfg.max_age.as_secs() <= now;
                let over = too_old || count > self.cfg.max_finished || total > self.cfg.max_bytes;
                // Never pull a job out from under a client still reading it.
                if over && lock(&j.inner).attached == 0 {
                    total -= size(&j);
                    count -= 1;
                    map.remove(&j.id);
                    victims.push(j);
                }
            }
        }
        for v in victims {
            let _ = fs::remove_dir_all(&v.dir);
        }
    }

    pub fn find(&self, owner: &str, id: &str) -> Option<Arc<Job>> {
        let j = lock(&self.jobs).get(id).cloned()?;
        (owner == "*" || j.owner == owner).then_some(j)
    }
}

/// A bidirectional byte stream that can be duplicated and shut down.
pub trait Conn: Read + Write + Send + Sync + Sized + 'static {
    fn dup(&self) -> io::Result<Self>;
    fn shutdown(&self);
}

impl Conn for TcpStream {
    fn dup(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn shutdown(&self) {
        let _ = TcpStream::shutdown(self, Shutdown::Both);
    }
}

impl Conn for UnixStream {
    fn dup(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn shutdown(&self) {
        let _ = UnixStream::shutdown(self, Shutdown::Both);
    }
}

pub fn serve_tcp(listener: TcpListener, srv: Arc<Server>) -> io::Result<()> {
    for s in listener.incoming() {
        match s {
            Ok(s) => {
                let _ = s.set_nodelay(true);
                let srv = Arc::clone(&srv);
                thread::spawn(move || handle(s, &srv));
            }
            Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

pub fn serve_unix(listener: UnixListener, srv: Arc<Server>) -> io::Result<()> {
    for s in listener.incoming() {
        match s {
            Ok(s) => {
                let srv = Arc::clone(&srv);
                thread::spawn(move || handle(s, &srv));
            }
            Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

pub fn send<C: Write>(conn: &mut C, header: Value, payload: &[u8]) -> io::Result<()> {
    write_frame(conn, &header, payload)
}

pub fn send_error<C: Write>(conn: &mut C, code: &str, msg: &str) {
    let _ = send(conn, json!({"t":"error","code":code,"msg":msg}), &[]);
}

/// Serve one connection to completion.
pub fn handle<C: Conn>(mut conn: C, srv: &Arc<Server>) {
    let Ok(mut reader) = conn.dup() else { return };
    match read_frame(&mut reader) {
        Ok(Some(f)) => match f.t.as_str() {
            "ping" => {
                let _ = send(&mut conn, pong(srv), &[]);
            }
            "exec" => jobs::exec(srv, &f, &mut conn, reader),
            "attach" => jobs::attach(srv, &f, &mut conn, reader),
            "jobs" => jobs::list(srv, &f, &mut conn),
            "cancel_job" => jobs::cancel_job(srv, &f, &mut conn),
            "put" => files::put(srv, &f, &mut conn, &mut reader),
            "get" => files::get(srv, &f, &mut conn),
            other => send_error(
                &mut conn,
                "bad_request",
                &format!("unknown request type {other:?}"),
            ),
        },
        Ok(None) => {}
        Err(e) => send_error(&mut conn, "bad_request", &e.to_string()),
    }
    conn.shutdown();
}

fn hostname() -> String {
    let mut buf = [0 as libc::c_char; 256];
    unsafe {
        if libc::gethostname(buf.as_mut_ptr(), buf.len() - 1) != 0 {
            return String::new();
        }
        CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned()
    }
}

fn kernel() -> String {
    unsafe {
        let mut u: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut u) != 0 {
            return String::new();
        }
        CStr::from_ptr(u.release.as_ptr())
            .to_string_lossy()
            .into_owned()
    }
}

pub fn disk_free_mb(path: &Path) -> u64 {
    let Ok(c) = CString::new(path.as_os_str().as_encoded_bytes().to_vec()) else {
        return 0;
    };
    unsafe {
        let mut st: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c.as_ptr(), &mut st) != 0 {
            return 0;
        }
        (st.f_bavail as u64).saturating_mul(st.f_frsize as u64) >> 20
    }
}

fn pong(srv: &Server) -> Value {
    let id = resolve(&srv.cfg.run_as);
    json!({
        "t": "pong",
        "worker": format!("azula-guest/{VERSION}"),
        "proto": 1,
        "hostname": hostname(),
        "kernel": kernel(),
        "arch": std::env::consts::ARCH,
        "user": id.name,
        "jobs_running": srv.running_count(),
        "disk_free_mb": disk_free_mb(&srv.cfg.state_dir),
    })
}
