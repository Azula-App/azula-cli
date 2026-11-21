#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use azula_guest::frame::{read_frame, write_frame, Frame};
use azula_guest::server::{serve_tcp, Config, Server};
use serde_json::{json, Value};

static N: AtomicU64 = AtomicU64::new(0);

pub fn uniq() -> String {
    format!(
        "{}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed),
        azula_guest::util::random_hex(4)
    )
}

pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new() -> TempDir {
        let p = std::env::temp_dir().join(format!("azula-guest-test-{}", uniq()));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub struct Env {
    pub port: u16,
    pub srv: Arc<Server>,
    pub dir: TempDir,
}

impl Env {
    pub fn state_dir(&self) -> PathBuf {
        self.dir.0.join("state")
    }
    pub fn files(&self) -> PathBuf {
        let p = self.dir.0.join("files");
        std::fs::create_dir_all(&p).unwrap();
        p
    }
    pub fn client(&self) -> Client<TcpStream> {
        Client::connect(self.port)
    }
}

pub fn start() -> Env {
    start_with(|_| {})
}

pub fn start_with(f: impl FnOnce(&mut Config)) -> Env {
    let dir = TempDir::new();
    let mut cfg = Config::new("azula", dir.0.join("state"));
    f(&mut cfg);
    let srv = Server::open(cfg).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let s2 = Arc::clone(&srv);
    thread::spawn(move || {
        let _ = serve_tcp(l, s2);
    });
    Env { port, srv, dir }
}

pub struct Client<S: Read + Write>(pub S);

#[derive(Default, Debug)]
pub struct Run {
    pub started: Option<Frame>,
    pub attached: Option<Frame>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Next expected offset per stream (absolute).
    pub next: [u64; 2],
    pub gaps: Vec<(String, u64, u64)>,
    pub last: Option<Frame>,
    pub max_chunk: usize,
}

impl Run {
    pub fn last(&self) -> &Frame {
        self.last.as_ref().expect("no terminal frame")
    }
    pub fn h(&self, k: &str) -> Value {
        self.last().header[k].clone()
    }
}

impl Client<TcpStream> {
    pub fn connect(port: u16) -> Self {
        let c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
        Client(c)
    }
}

impl<S: Read + Write> Client<S> {
    pub fn send(&mut self, h: Value, payload: &[u8]) {
        write_frame(&mut self.0, &h, payload).unwrap();
    }
    pub fn recv(&mut self) -> Frame {
        read_frame(&mut self.0).unwrap().expect("unexpected EOF")
    }
    pub fn expect_closed(&mut self) {
        assert!(read_frame(&mut self.0).unwrap_or(None).is_none());
    }
    /// Collect until exit/error/end; checks offsets are contiguous.
    pub fn collect(&mut self) -> Run {
        self.collect_from([0, 0])
    }
    pub fn collect_from(&mut self, start: [u64; 2]) -> Run {
        let mut r = Run {
            next: start,
            ..Default::default()
        };
        loop {
            let f = self.recv();
            match f.t.as_str() {
                "started" => r.started = Some(f),
                "attached" => r.attached = Some(f),
                "gap" => {
                    let i = if f.header["stream"] == "stdout" { 0 } else { 1 };
                    let (from, to) = (
                        f.header["from"].as_u64().unwrap(),
                        f.header["to"].as_u64().unwrap(),
                    );
                    assert_eq!(from, r.next[i], "gap must start at the requested offset");
                    r.next[i] = to;
                    r.gaps
                        .push((f.header["stream"].as_str().unwrap().into(), from, to));
                }
                "stdout" | "stderr" => {
                    let i = if f.t == "stdout" { 0 } else { 1 };
                    assert_eq!(
                        f.header["off"].as_u64().unwrap(),
                        r.next[i],
                        "{} offset",
                        f.t
                    );
                    r.next[i] += f.payload.len() as u64;
                    r.max_chunk = r.max_chunk.max(f.payload.len());
                    if i == 0 {
                        r.stdout.extend_from_slice(&f.payload)
                    } else {
                        r.stderr.extend_from_slice(&f.payload)
                    }
                }
                "exit" | "error" | "end" => {
                    r.last = Some(f);
                    self.expect_closed();
                    return r;
                }
                other => panic!("unexpected frame {other}"),
            }
        }
    }
}

pub fn exec_req(owner: &str, argv: &[&str]) -> Value {
    json!({"t":"exec","owner":owner,"idem":uniq(),"argv":argv})
}

pub fn merge(mut base: Value, extra: Value) -> Value {
    for (k, v) in extra.as_object().unwrap() {
        base[k] = v.clone();
    }
    base
}

pub fn run(env: &Env, req: Value) -> Run {
    let mut c = env.client();
    c.send(req, &[]);
    c.collect()
}

/// Start a detached job; returns (job id, pid).
pub fn detach(env: &Env, req: Value) -> (String, u64) {
    let mut c = env.client();
    c.send(merge(req, json!({"attach":false})), &[]);
    let f = c.recv();
    assert_eq!(f.t, "started", "{f:?}");
    c.expect_closed();
    (
        f.header["job"].as_str().unwrap().into(),
        f.header["pid"].as_u64().unwrap_or(0),
    )
}

pub fn jobs(env: &Env, owner: &str) -> Vec<Value> {
    let mut c = env.client();
    c.send(json!({"t":"jobs","owner":owner}), &[]);
    let f = c.recv();
    assert_eq!(f.t, "job_list", "{f:?}");
    f.header["jobs"].as_array().unwrap().clone()
}

pub fn job_info(env: &Env, owner: &str, id: &str) -> Value {
    jobs(env, owner)
        .into_iter()
        .find(|j| j["job"] == id)
        .unwrap_or(Value::Null)
}

pub fn wait_state(env: &Env, owner: &str, id: &str, state: &str) -> Value {
    let end = Instant::now() + Duration::from_secs(20);
    loop {
        let j = job_info(env, owner, id);
        if j["state"] == state {
            return j;
        }
        assert!(Instant::now() < end, "job {id} never reached {state}: {j}");
        thread::sleep(Duration::from_millis(50));
    }
}

pub fn cancel_job(env: &Env, owner: &str, id: &str) -> Frame {
    let mut c = env.client();
    c.send(json!({"t":"cancel_job","owner":owner,"job":id}), &[]);
    let f = c.recv();
    c.expect_closed();
    f
}

pub fn pgrep(pattern: &str) -> bool {
    Command::new("pgrep")
        .args(["-f", pattern])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn wait_for(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end {
        if f() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out waiting for {what}");
}

pub fn path_str(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}
