//! Connection handling: ping and exec (vm/README.md section 2).

use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::frame::{read_frame, write_frame, Frame};
use crate::identity::{resolve, Identity};

const CHUNK: usize = 64 * 1024;
const DEFAULT_TIMEOUT_S: u64 = 900;
const KILL_GRACE: Duration = Duration::from_secs(5);
/// After SIGKILL, how long to wait for output pipes held open by escapees.
const DRAIN_GRACE: Duration = Duration::from_secs(2);
const BASE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

#[derive(Debug, Clone)]
pub struct Config {
    pub run_as: String,
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

pub fn serve_tcp(listener: TcpListener, cfg: Config) -> io::Result<()> {
    let cfg = Arc::new(cfg);
    for s in listener.incoming() {
        match s {
            Ok(s) => {
                let _ = s.set_nodelay(true);
                let cfg = Arc::clone(&cfg);
                thread::spawn(move || handle(s, &cfg));
            }
            Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

pub fn serve_unix(listener: UnixListener, cfg: Config) -> io::Result<()> {
    let cfg = Arc::new(cfg);
    for s in listener.incoming() {
        match s {
            Ok(s) => {
                let cfg = Arc::clone(&cfg);
                thread::spawn(move || handle(s, &cfg));
            }
            Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Serializes outgoing frames; once closed, further sends fail.
struct Out<C: Conn> {
    inner: Mutex<(C, bool)>,
    shut: C,
}

impl<C: Conn> Out<C> {
    fn new(conn: C) -> io::Result<Self> {
        let shut = conn.dup()?;
        Ok(Out {
            inner: Mutex::new((conn, false)),
            shut,
        })
    }

    fn send(&self, header: Value, payload: &[u8]) -> io::Result<()> {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if g.1 {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        write_frame(&mut g.0, &header, payload)
    }

    fn error(&self, code: &str, msg: &str) {
        let _ = self.send(json!({"t":"error","code":code,"msg":msg}), &[]);
    }

    fn close(&self) {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).1 = true;
        self.shut.shutdown();
    }
}

/// Serve one connection to completion.
pub fn handle<C: Conn>(conn: C, cfg: &Config) {
    let Ok(mut reader) = conn.dup() else { return };
    let Ok(out) = Out::new(conn) else { return };
    let out = Arc::new(out);
    match read_frame(&mut reader) {
        Ok(Some(f)) => match f.t.as_str() {
            "ping" => {
                let _ = out.send(pong(cfg), &[]);
            }
            "exec" => exec(f, reader, &out, cfg),
            other => out.error("bad_request", &format!("unknown request type {other:?}")),
        },
        Ok(None) => {}
        Err(e) => out.error("bad_request", &e.to_string()),
    }
    out.close();
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

fn pong(cfg: &Config) -> Value {
    let id = resolve(&cfg.run_as);
    json!({
        "t": "pong",
        "worker": format!("azula-guest/{}", crate::VERSION),
        "proto": 1,
        "hostname": hostname(),
        "kernel": kernel(),
        "arch": std::env::consts::ARCH,
        "user": id.name,
    })
}

#[derive(Deserialize)]
struct ExecReq {
    argv: Vec<String>,
    cwd: Option<String>,
    env: Option<BTreeMap<String, String>>,
    stdin: Option<bool>,
    timeout_s: Option<u64>,
}

fn parse_exec(f: &Frame) -> Result<ExecReq, String> {
    let req: ExecReq = serde_json::from_value(Value::Object(f.header.clone()))
        .map_err(|e| format!("invalid exec request: {e}"))?;
    if req.argv.is_empty() || req.argv[0].is_empty() {
        return Err("argv must be non-empty with a non-empty program".into());
    }
    let nul = |s: &String| s.contains('\0');
    if req.argv.iter().any(nul)
        || req.cwd.iter().any(nul)
        || req
            .env
            .iter()
            .flatten()
            .any(|(k, v)| k.is_empty() || k.contains('=') || k.contains('\0') || v.contains('\0'))
    {
        return Err("argv/cwd/env must not contain NUL, and env names must be valid".into());
    }
    Ok(req)
}

enum Ev {
    Cancel,
    Exited(io::Result<ExitStatus>),
    Eof,
}

fn killpg(pid: u32, sig: libc::c_int) {
    unsafe { libc::kill(-(pid as libc::pid_t), sig) };
}

fn pump<C: Conn>(mut src: impl Read, kind: &'static str, out: Arc<Out<C>>) {
    let mut buf = vec![0u8; CHUNK];
    loop {
        match src.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => {
                if out.send(json!({ "t": kind }), &buf[..n]).is_err() {
                    return;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

fn spawn_pump<C: Conn, R: Read + Send + 'static>(
    pipe: Option<R>,
    kind: &'static str,
    out: &Arc<Out<C>>,
    tx: &mpsc::Sender<Ev>,
) {
    let (out, tx) = (Arc::clone(out), tx.clone());
    thread::spawn(move || {
        if let Some(p) = pipe {
            pump(p, kind, out);
        }
        let _ = tx.send(Ev::Eof);
    });
}

fn build_command(req: &ExecReq, id: &Identity, cwd: &str) -> Command {
    let mut cmd = Command::new(&req.argv[0]);
    cmd.args(&req.argv[1..]);
    cmd.env_clear();
    cmd.env("PATH", BASE_PATH)
        .env("HOME", &id.home)
        .env("USER", &id.name)
        .env("LOGNAME", &id.name)
        .env("SHELL", &id.shell)
        .env("LANG", "C.UTF-8");
    if let Some(env) = &req.env {
        cmd.envs(env);
    }
    cmd.current_dir(cwd);
    cmd.stdin(if req.stdin.unwrap_or(false) {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.process_group(0);
    if id.switch {
        if let Ok(name) = CString::new(id.name.clone()) {
            let (uid, gid) = (id.uid, id.gid);
            // std applies uid/gid before pre_exec closures, so do the whole
            // initgroups + setgid + setuid sequence here, in that order.
            unsafe {
                cmd.pre_exec(move || {
                    if libc::initgroups(name.as_ptr(), gid as _) != 0
                        || libc::setgid(gid) != 0
                        || libc::setuid(uid) != 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
    }
    cmd
}

fn exec<C: Conn>(req_frame: Frame, mut reader: C, out: &Arc<Out<C>>, cfg: &Config) {
    let req = match parse_exec(&req_frame) {
        Ok(r) => r,
        Err(m) => return out.error("bad_request", &m),
    };
    let id = resolve(&cfg.run_as);
    let cwd = req.cwd.clone().unwrap_or_else(|| id.home.clone());
    if !Path::new(&cwd).is_dir() {
        return out.error("cwd_missing", &format!("no such directory: {cwd}"));
    }
    let timeout = Duration::from_secs(req.timeout_s.unwrap_or(DEFAULT_TIMEOUT_S).clamp(1, 86_400));
    let mut child = match build_command(&req, &id, &cwd).spawn() {
        Ok(c) => c,
        Err(e) => return out.error("spawn_failed", &e.to_string()),
    };
    let pid = child.id();
    let started = Instant::now();
    let _ = out.send(json!({"t":"started","pid":pid}), &[]);

    let (tx, rx) = mpsc::channel::<Ev>();

    // Output pumps.
    spawn_pump(child.stdout.take(), "stdout", out, &tx);
    spawn_pump(child.stderr.take(), "stderr", out, &tx);

    // Child stdin feeder.
    let stdin_tx = child.stdin.take().map(|mut stdin| {
        let (stx, srx) = mpsc::channel::<Option<Vec<u8>>>();
        thread::spawn(move || {
            while let Ok(Some(chunk)) = srx.recv() {
                if stdin.write_all(&chunk).is_err() {
                    break;
                }
            }
            // dropping `stdin` closes it
        });
        stx
    });

    // Client frame reader: stdin / stdin_eof / cancel; EOF or error = cancel.
    {
        let tx = tx.clone();
        thread::spawn(move || {
            while let Ok(Some(f)) = read_frame(&mut reader) {
                match f.t.as_str() {
                    "stdin" => {
                        if let Some(s) = &stdin_tx {
                            let _ = s.send(Some(f.payload));
                        }
                    }
                    "stdin_eof" => {
                        if let Some(s) = &stdin_tx {
                            let _ = s.send(None);
                        }
                    }
                    "cancel" => {
                        let _ = tx.send(Ev::Cancel);
                    }
                    _ => {}
                }
            }
            let _ = tx.send(Ev::Cancel);
        });
    }

    // Reaper.
    {
        let tx = tx.clone();
        thread::spawn(move || {
            let _ = tx.send(Ev::Exited(child.wait()));
        });
    }

    let timeout_at = started + timeout;
    let mut exited: Option<io::Result<ExitStatus>> = None;
    let mut eofs = 0;
    let mut reason = "exited";
    let mut term_at: Option<Instant> = None;
    let mut kill_sent = false;
    let mut giveup_at = timeout_at;

    while !(exited.is_some() && eofs >= 2) {
        let deadline = match term_at {
            None => timeout_at,
            Some(t) if !kill_sent => t + KILL_GRACE,
            Some(_) => giveup_at,
        };
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(Ev::Exited(s)) => exited = Some(s),
            Ok(Ev::Eof) => eofs += 1,
            Ok(Ev::Cancel) => {
                if term_at.is_none() {
                    reason = "cancelled";
                    term_at = Some(Instant::now());
                    killpg(pid, libc::SIGTERM);
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                let now = Instant::now();
                if term_at.is_none() {
                    reason = "timeout";
                    term_at = Some(now);
                    killpg(pid, libc::SIGTERM);
                } else if !kill_sent {
                    killpg(pid, libc::SIGKILL);
                    kill_sent = true;
                    giveup_at = now + DRAIN_GRACE;
                } else if exited.is_some() {
                    break; // something escaped the group and holds the pipes
                } else {
                    giveup_at = now + DRAIN_GRACE;
                }
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    let (code, signal) = match &exited {
        Some(Ok(st)) => (st.code(), st.signal()),
        _ => (None, None),
    };
    let _ = out.send(
        json!({"t":"exit","code":code,"signal":signal,"reason":reason}),
        &[],
    );
    out.close();
}
