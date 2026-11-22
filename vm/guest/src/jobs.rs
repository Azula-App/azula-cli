//! Durable jobs: exec, attach, jobs, cancel_job (vm/README.md 2.1, 2.3-2.6).
//!
//! A job's output goes to disk (segment files named by start offset) and
//! nowhere else. Attached connections tail those files, so no client can
//! block a job.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::FileExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::frame::{read_frame, Frame};
use crate::identity::{resolve, Identity};
use crate::server::{send, send_error, Conn, Server};
use crate::sha256::Sha256;
use crate::util::{lock, now_s, random_hex, write_atomic};

const CHUNK: usize = 64 * 1024;
const DEFAULT_TIMEOUT_S: u64 = 900;
const KILL_GRACE: Duration = Duration::from_secs(5);
/// After SIGKILL, how long to wait for output pipes held open by escapees.
const DRAIN_GRACE: Duration = Duration::from_secs(2);
const BASE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const STREAMS: [&str; 2] = ["stdout", "stderr"];

pub enum Ev {
    Cancel(&'static str),
    Exited(io::Result<ExitStatus>),
    Eof,
    Poke,
}

#[derive(Default, Clone)]
pub struct StreamState {
    pub len: u64,
    pub earliest: u64,
    /// Start offsets of the retained segment files, ascending.
    pub segs: Vec<u64>,
}

pub struct Inner {
    /// `running`, `exited` or `interrupted`.
    pub state: &'static str,
    pub reason: Option<String>,
    pub code: Option<i32>,
    pub signal: Option<i32>,
    pub ended: Option<u64>,
    pub pid: Option<u32>,
    pub s: [StreamState; 2],
    pub truncated: bool,
    pub attached: usize,
}

pub struct Job {
    pub id: String,
    pub owner: String,
    pub label: Option<String>,
    pub idem: String,
    pub spec_hash: String,
    pub argv: Vec<String>,
    pub stdin: bool,
    pub cancel_on_disconnect: bool,
    pub created: u64,
    /// Millisecond creation time: stable ordering within one second.
    pub created_ms: u64,
    pub dir: PathBuf,
    pub inner: Mutex<Inner>,
    pub cv: Condvar,
    ctl: Mutex<Option<Sender<Ev>>>,
}

#[derive(Serialize, Deserialize)]
struct Record {
    job: String,
    owner: String,
    label: Option<String>,
    idem: String,
    spec_hash: String,
    argv: Vec<String>,
    cwd: String,
    /// Names only; values are never written to disk.
    env_keys: Vec<String>,
    stdin: bool,
    timeout_s: u64,
    cancel_on_disconnect: bool,
    created: u64,
    #[serde(default)]
    created_ms: u64,
    started: u64,
}

#[derive(Serialize, Deserialize)]
struct ExitRecord {
    state: String,
    reason: String,
    code: Option<i32>,
    signal: Option<i32>,
    ended: u64,
    stdout_len: u64,
    stderr_len: u64,
    #[serde(default)]
    output_truncated: bool,
}

impl Job {
    pub fn is_running(&self) -> bool {
        lock(&self.inner).state == "running"
    }

    /// Ask the supervisor to cancel; false if the job already ended.
    pub fn cancel(&self, reason: &'static str) -> bool {
        if !self.is_running() {
            return false;
        }
        match lock(&self.ctl).as_ref() {
            Some(tx) => tx.send(Ev::Cancel(reason)).is_ok(),
            None => false,
        }
    }

    fn poke(&self) {
        if let Some(tx) = lock(&self.ctl).as_ref() {
            let _ = tx.send(Ev::Poke);
        }
    }

    fn wake(&self) {
        let _g = lock(&self.inner);
        self.cv.notify_all();
    }

    fn summary(&self) -> Value {
        let g = lock(&self.inner);
        json!({
            "job": self.id,
            "label": self.label,
            "argv": self.argv,
            "state": g.state,
            "reason": g.reason,
            "created": self.created,
            "ended": g.ended,
            "code": g.code,
            "signal": g.signal,
            "stdout_len": g.s[0].len,
            "stderr_len": g.s[1].len,
            "stdout_earliest": g.s[0].earliest,
            "stderr_earliest": g.s[1].earliest,
            "output_truncated": g.truncated,
        })
    }
}

struct AttachGuard<'a>(&'a Job);

impl<'a> AttachGuard<'a> {
    fn new(job: &'a Job) -> Self {
        lock(&job.inner).attached += 1;
        job.poke();
        AttachGuard(job)
    }
}

impl Drop for AttachGuard<'_> {
    fn drop(&mut self) {
        lock(&self.0.inner).attached -= 1;
        self.0.poke();
    }
}

// ---------------------------------------------------------------- loading

fn scan_stream(dir: &Path) -> StreamState {
    let mut segs: Vec<u64> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u64>().ok())
        .collect();
    segs.sort_unstable();
    let len = segs
        .last()
        .map(|&s| s + fs::metadata(dir.join(s.to_string())).map_or(0, |m| m.len()))
        .unwrap_or(0);
    StreamState {
        len,
        earliest: segs.first().copied().unwrap_or(0),
        segs,
    }
}

/// Load every record under `jobs/`; mark those with no `exit.json` interrupted.
pub fn load_all(srv: &Server) {
    let Ok(rd) = fs::read_dir(srv.jobs_dir()) else {
        return;
    };
    for e in rd.flatten() {
        let dir = e.path();
        let Ok(rec) = fs::read(dir.join("job.json"))
            .map_err(|e| e.to_string())
            .and_then(|b| serde_json::from_slice::<Record>(&b).map_err(|e| e.to_string()))
        else {
            continue;
        };
        let s = [
            scan_stream(&dir.join("stdout")),
            scan_stream(&dir.join("stderr")),
        ];
        let exit = fs::read(dir.join("exit.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<ExitRecord>(&b).ok());
        let exit = exit.unwrap_or_else(|| {
            let x = ExitRecord {
                state: "interrupted".into(),
                reason: "interrupted".into(),
                code: None,
                signal: None,
                ended: now_s(),
                stdout_len: s[0].len,
                stderr_len: s[1].len,
                output_truncated: false,
            };
            if let Ok(b) = serde_json::to_vec(&x) {
                let _ = write_atomic(&dir.join("exit.json"), &b);
            }
            x
        });
        let job = Job {
            id: rec.job.clone(),
            owner: rec.owner,
            label: rec.label,
            idem: rec.idem,
            spec_hash: rec.spec_hash,
            argv: rec.argv,
            stdin: rec.stdin,
            cancel_on_disconnect: rec.cancel_on_disconnect,
            created: rec.created,
            created_ms: if rec.created_ms > 0 {
                rec.created_ms
            } else {
                rec.created * 1000
            },
            dir,
            inner: Mutex::new(Inner {
                state: if exit.state == "interrupted" {
                    "interrupted"
                } else {
                    "exited"
                },
                reason: Some(exit.reason),
                code: exit.code,
                signal: exit.signal,
                ended: Some(exit.ended),
                pid: None,
                s,
                truncated: exit.output_truncated,
                attached: 0,
            }),
            cv: Condvar::new(),
            ctl: Mutex::new(None),
        };
        lock(&srv.jobs).insert(rec.job, Arc::new(job));
    }
}

// ------------------------------------------------------------ exec request

#[derive(Deserialize)]
struct ExecReq {
    owner: String,
    idem: String,
    label: Option<String>,
    argv: Vec<String>,
    cwd: Option<String>,
    env: Option<BTreeMap<String, String>>,
    stdin: Option<bool>,
    timeout_s: Option<u64>,
    attach: Option<bool>,
    cancel_on_disconnect: Option<bool>,
}

fn parse_exec(f: &Frame) -> Result<ExecReq, String> {
    let req: ExecReq = serde_json::from_value(Value::Object(f.header.clone()))
        .map_err(|e| format!("invalid exec request: {e}"))?;
    if req.owner.is_empty() || req.idem.is_empty() || req.idem.len() > 256 {
        return Err("owner and idem are required".into());
    }
    if req.argv.is_empty() || req.argv[0].is_empty() {
        return Err("argv must be non-empty with a non-empty program".into());
    }
    let nul = |s: &String| s.contains('\0');
    if req.argv.iter().any(nul)
        || req.cwd.iter().any(nul)
        || req.label.iter().any(nul)
        || req
            .env
            .iter()
            .flatten()
            .any(|(k, v)| k.is_empty() || k.contains('=') || k.contains('\0') || v.contains('\0'))
    {
        return Err("argv/cwd/env must not contain NUL, and env names must be valid".into());
    }
    if req.stdin.unwrap_or(false) && !req.attach.unwrap_or(true) {
        return Err("stdin requires attach".into());
    }
    Ok(req)
}

fn killpg(pid: u32, sig: libc::c_int) {
    unsafe { libc::kill(-(pid as libc::pid_t), sig) };
}

fn build_command(req: &ExecReq, id: &Identity, cwd: &str, job_env: &[(String, String)]) -> Command {
    let mut cmd = Command::new(&req.argv[0]);
    cmd.args(&req.argv[1..]);
    cmd.env_clear();
    cmd.env("PATH", BASE_PATH)
        .env("HOME", &id.home)
        .env("USER", &id.name)
        .env("LOGNAME", &id.name)
        .env("SHELL", &id.shell)
        .env("LANG", "C.UTF-8");
    cmd.envs(job_env.iter().map(|(k, v)| (k, v)));
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
        if let Ok(name) = std::ffi::CString::new(id.name.clone()) {
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

type StdinTx = Sender<Option<Vec<u8>>>;

struct Started {
    job: Arc<Job>,
    deduped: bool,
    stdin: Option<StdinTx>,
}

fn spec_hash(srv: &Server, req: &ExecReq) -> String {
    let canon = serde_json::to_string(&(&req.argv, &req.cwd, &req.env, req.stdin.unwrap_or(false)))
        .unwrap_or_default();
    let mut h = Sha256::new();
    h.update(srv.salt.as_bytes());
    h.update(canon.as_bytes());
    h.hex()
}

fn start_job(srv: &Arc<Server>, req: &ExecReq) -> Result<Started, (&'static str, String)> {
    let hash = spec_hash(srv, req);
    let id = resolve(&srv.cfg.run_as);
    let cwd = req.cwd.clone().unwrap_or_else(|| id.home.clone());
    let timeout_s = req.timeout_s.unwrap_or(DEFAULT_TIMEOUT_S).clamp(1, 86_400);

    // The table lock is held across check-and-create so the same idem key
    // arriving twice at once starts one job.
    let mut map = lock(&srv.jobs);
    if let Some(j) = map
        .values()
        .find(|j| j.owner == req.owner && j.idem == req.idem)
    {
        if j.spec_hash != hash {
            return Err((
                "idem_conflict",
                "idem key already used with a different request".into(),
            ));
        }
        return Ok(Started {
            job: Arc::clone(j),
            deduped: true,
            stdin: None,
        });
    }
    let (mut mine, mut all) = (0, 0);
    for j in map.values().filter(|j| j.is_running()) {
        all += 1;
        if j.owner == req.owner {
            mine += 1;
        }
    }
    if mine >= srv.cfg.max_per_owner {
        return Err((
            "busy",
            format!(
                "{mine} jobs already running for this owner (max {})",
                srv.cfg.max_per_owner
            ),
        ));
    }
    if all >= srv.cfg.max_per_vm {
        return Err((
            "busy",
            format!(
                "{all} jobs already running in this VM (max {})",
                srv.cfg.max_per_vm
            ),
        ));
    }
    if !Path::new(&cwd).is_dir() {
        return Err(("cwd_missing", format!("no such directory: {cwd}")));
    }

    let job_id = format!("j_{}", random_hex(8));
    let dir = srv.jobs_dir().join(&job_id);
    let now = now_s();
    let now_ms = crate::util::now_ms();
    let io_err = |e: io::Error| ("spawn_failed", format!("job record: {e}"));
    fs::create_dir_all(dir.join("stdout")).map_err(io_err)?;
    fs::create_dir_all(dir.join("stderr")).map_err(io_err)?;
    let rec = Record {
        job: job_id.clone(),
        owner: req.owner.clone(),
        label: req.label.clone(),
        idem: req.idem.clone(),
        spec_hash: hash.clone(),
        argv: req.argv.clone(),
        cwd: cwd.clone(),
        env_keys: req
            .env
            .as_ref()
            .map(|e| e.keys().cloned().collect())
            .unwrap_or_default(),
        stdin: req.stdin.unwrap_or(false),
        timeout_s,
        cancel_on_disconnect: req.cancel_on_disconnect.unwrap_or(false),
        created: now,
        created_ms: now_ms,
        started: now,
    };
    let written = serde_json::to_vec_pretty(&rec)
        .map_err(|e| e.to_string())
        .and_then(|b| write_atomic(&dir.join("job.json"), &b).map_err(|e| e.to_string()));
    if let Err(e) = written {
        let _ = fs::remove_dir_all(&dir);
        return Err(("spawn_failed", format!("job record: {e}")));
    }

    let mut child = match build_command(req, &id, &cwd, &srv.cfg.job_env).spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = fs::remove_dir_all(&dir);
            return Err(("spawn_failed", e.to_string()));
        }
    };
    let (tx, rx) = mpsc::channel::<Ev>();
    let job = Arc::new(Job {
        id: job_id.clone(),
        owner: req.owner.clone(),
        label: req.label.clone(),
        idem: req.idem.clone(),
        spec_hash: hash,
        argv: req.argv.clone(),
        stdin: rec.stdin,
        cancel_on_disconnect: rec.cancel_on_disconnect,
        created: now,
        created_ms: now_ms,
        dir,
        inner: Mutex::new(Inner {
            state: "running",
            reason: None,
            code: None,
            signal: None,
            ended: None,
            pid: Some(child.id()),
            s: [StreamState::default(), StreamState::default()],
            truncated: false,
            attached: 0,
        }),
        cv: Condvar::new(),
        ctl: Mutex::new(Some(tx.clone())),
    });
    map.insert(job_id, Arc::clone(&job));
    drop(map);
    srv.prune();

    let stdin = child.stdin.take().map(|mut pipe| {
        let (stx, srx) = mpsc::channel::<Option<Vec<u8>>>();
        let jb = Arc::clone(&job);
        thread::spawn(move || {
            loop {
                match srx.recv() {
                    Ok(Some(chunk)) => {
                        if pipe.write_all(&chunk).is_err() {
                            return;
                        }
                    }
                    Ok(None) => return, // stdin_eof: drop closes the pipe
                    Err(_) => {
                        // Client vanished without stdin_eof: keep the pipe
                        // open so the stdin_lost cancel lands first.
                        while jb.is_running() {
                            thread::sleep(Duration::from_millis(100));
                        }
                        return;
                    }
                }
            }
        });
        stx
    });

    for (i, pipe) in [
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    ]
    .into_iter()
    .enumerate()
    {
        let (job, srv, tx) = (Arc::clone(&job), Arc::clone(srv), tx.clone());
        thread::spawn(move || {
            if let Some(p) = pipe {
                pump(p, &job, &srv, i);
            }
            let _ = tx.send(Ev::Eof);
        });
    }
    {
        let tx = tx.clone();
        thread::spawn(move || {
            let r = child.wait();
            let _ = tx.send(Ev::Exited(r));
        });
    }
    {
        let (job, srv) = (Arc::clone(&job), Arc::clone(srv));
        thread::spawn(move || supervise(job, srv, rx, timeout_s));
    }
    Ok(Started {
        job,
        deduped: false,
        stdin,
    })
}

// ------------------------------------------------------- output to disk

struct StreamWriter {
    dir: PathBuf,
    cur: Option<File>,
    cur_size: u64,
    next_off: u64,
}

fn pump(mut src: Box<dyn Read + Send>, job: &Job, srv: &Server, i: usize) {
    let mut w = StreamWriter {
        dir: job.dir.join(STREAMS[i]),
        cur: None,
        cur_size: 0,
        next_off: 0,
    };
    let mut buf = vec![0u8; CHUNK];
    loop {
        match src.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => w.append(job, srv, i, &buf[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

impl StreamWriter {
    fn mark_truncated(job: &Job) {
        lock(&job.inner).truncated = true;
    }

    fn rotate(&mut self, job: &Job, srv: &Server, i: usize) -> io::Result<()> {
        let start = self.next_off;
        let f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(self.dir.join(start.to_string()))?;
        self.cur = Some(f);
        self.cur_size = 0;
        let mut drop_start = Vec::new();
        {
            let mut g = lock(&job.inner);
            let s = &mut g.s[i];
            s.segs.push(start);
            while s.segs.len() > srv.cfg.keep_segments {
                drop_start.push(s.segs.remove(0));
            }
            s.earliest = s.segs[0];
            job.cv.notify_all();
        }
        for st in drop_start {
            let _ = fs::remove_file(self.dir.join(st.to_string()));
        }
        Ok(())
    }

    fn append(&mut self, job: &Job, srv: &Server, i: usize, mut data: &[u8]) {
        while !data.is_empty() {
            if self.cur.is_none() || self.cur_size >= srv.cfg.segment_size {
                if let Err(_e) = self.rotate(job, srv, i) {
                    self.cur = None;
                    Self::mark_truncated(job);
                    return;
                }
            }
            let room = (srv.cfg.segment_size - self.cur_size) as usize;
            let take = data.len().min(room);
            if let Some(limit) = srv.cfg.disk_limit {
                if srv.written.load(Ordering::Relaxed) + take as u64 > limit {
                    Self::mark_truncated(job);
                    return;
                }
            }
            let f = self.cur.as_mut().expect("segment open");
            let mut done = 0;
            let mut failed = false;
            while done < take {
                match f.write(&data[done..take]) {
                    Ok(0) => {
                        failed = true;
                        break;
                    }
                    Ok(n) => done += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => {
                        failed = true;
                        break;
                    }
                }
            }
            if done > 0 {
                srv.written.fetch_add(done as u64, Ordering::Relaxed);
                self.cur_size += done as u64;
                self.next_off += done as u64;
                let mut g = lock(&job.inner);
                if g.state == "running" {
                    g.s[i].len = self.next_off;
                }
                job.cv.notify_all();
            }
            if failed {
                // Disk full or I/O error: drop the rest, keep draining.
                Self::mark_truncated(job);
                return;
            }
            data = &data[take..];
        }
    }
}

// ----------------------------------------------------------- supervisor

fn supervise(job: Arc<Job>, srv: Arc<Server>, rx: mpsc::Receiver<Ev>, timeout_s: u64) {
    let started = Instant::now();
    let timeout_at = started + Duration::from_secs(timeout_s);
    let pid = lock(&job.inner).pid.unwrap_or(0);
    let mut exited: Option<io::Result<ExitStatus>> = None;
    let mut eofs = 0;
    let mut reason = "exited";
    let mut term_at: Option<Instant> = None;
    let mut kill_sent = false;
    let mut giveup_at = timeout_at;
    let mut idle_since: Option<Instant> = None;
    let terminate =
        |why: &'static str, reason: &mut &'static str, term_at: &mut Option<Instant>| {
            *reason = why;
            *term_at = Some(Instant::now());
            killpg(pid, libc::SIGTERM);
        };

    while !(exited.is_some() && eofs >= 2) {
        // Orphan clock: running with nobody attached.
        if job.cancel_on_disconnect && term_at.is_none() {
            if lock(&job.inner).attached == 0 {
                idle_since.get_or_insert_with(Instant::now);
            } else {
                idle_since = None;
            }
            if let Some(t) = idle_since {
                if t.elapsed() >= srv.cfg.orphan_after {
                    terminate("orphaned", &mut reason, &mut term_at);
                }
            }
        }
        let mut deadline = match term_at {
            None => timeout_at,
            Some(t) if !kill_sent => t + KILL_GRACE,
            Some(_) => giveup_at,
        };
        if term_at.is_none() {
            if let Some(t) = idle_since {
                deadline = deadline.min(t + srv.cfg.orphan_after);
            }
        }
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(Ev::Exited(s)) => exited = Some(s),
            Ok(Ev::Eof) => eofs += 1,
            Ok(Ev::Poke) => {}
            Ok(Ev::Cancel(why)) => {
                if term_at.is_none() {
                    terminate(why, &mut reason, &mut term_at);
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                let now = Instant::now();
                if term_at.is_none() {
                    if now >= timeout_at {
                        terminate("timeout", &mut reason, &mut term_at);
                    }
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
    let ended = now_s();
    let (l0, l1, trunc) = {
        let g = lock(&job.inner);
        (g.s[0].len, g.s[1].len, g.truncated)
    };
    let rec = ExitRecord {
        state: "exited".into(),
        reason: reason.into(),
        code,
        signal,
        ended,
        stdout_len: l0,
        stderr_len: l1,
        output_truncated: trunc,
    };
    if let Ok(b) = serde_json::to_vec(&rec) {
        if let Err(e) = write_atomic(&job.dir.join("exit.json"), &b) {
            eprintln!("azula-guest: writing exit.json for {}: {e}", job.id);
        }
    }
    {
        let mut g = lock(&job.inner);
        g.state = "exited";
        g.reason = Some(reason.into());
        g.code = code;
        g.signal = signal;
        g.ended = Some(ended);
        job.cv.notify_all();
    }
    *lock(&job.ctl) = None;
    srv.prune();
}

// ------------------------------------------------------ connection side

fn spawn_reader<C: Conn>(
    mut reader: C,
    job: Arc<Job>,
    closed: Arc<AtomicBool>,
    stdin: Option<StdinTx>,
) {
    thread::spawn(move || {
        let mut got_eof = false;
        while let Ok(Some(f)) = read_frame(&mut reader) {
            match f.t.as_str() {
                "stdin" => {
                    if let Some(s) = &stdin {
                        let _ = s.send(Some(f.payload));
                    }
                }
                "stdin_eof" => {
                    got_eof = true;
                    if let Some(s) = &stdin {
                        let _ = s.send(None);
                    }
                }
                "cancel" => {
                    job.cancel("cancelled");
                }
                _ => {}
            }
        }
        if stdin.is_some() && job.stdin && !got_eof {
            job.cancel("stdin_lost");
        }
        closed.store(true, Ordering::Relaxed);
        job.wake();
    });
}

enum Step {
    Gap(usize, u64, u64),
    Data(usize, u64, u64, usize),
    Exit(Value),
    End(Value),
    Closed,
}

fn exit_frame(job: &Job, g: &Inner) -> Value {
    json!({
        "t": "exit",
        "job": job.id,
        "code": g.code,
        "signal": g.signal,
        "reason": g.reason,
        "stdout_len": g.s[0].len,
        "stderr_len": g.s[1].len,
    })
}

#[allow(clippy::needless_range_loop)]
fn decide(
    job: &Job,
    g: &Inner,
    offs: &mut [u64; 2],
    follow: bool,
    closed: &AtomicBool,
) -> Option<Step> {
    if closed.load(Ordering::Relaxed) {
        return Some(Step::Closed);
    }
    for i in 0..2 {
        if offs[i] < g.s[i].earliest {
            let (from, to) = (offs[i], g.s[i].earliest);
            offs[i] = to;
            return Some(Step::Gap(i, from, to));
        }
    }
    for i in 0..2 {
        let s = &g.s[i];
        if offs[i] < s.len {
            let idx = s.segs.partition_point(|&st| st <= offs[i]);
            if idx == 0 {
                continue;
            }
            let start = s.segs[idx - 1];
            let end = s.segs.get(idx).copied().unwrap_or(s.len);
            let n = (end.min(s.len) - offs[i]).min(CHUNK as u64) as usize;
            if n == 0 {
                continue;
            }
            return Some(Step::Data(i, start, offs[i], n));
        }
    }
    if g.state != "running" {
        return Some(Step::Exit(exit_frame(job, g)));
    }
    if !follow {
        return Some(Step::End(json!({
            "t": "end",
            "state": "running",
            "stdout_len": g.s[0].len,
            "stderr_len": g.s[1].len,
        })));
    }
    None
}

/// Replay from disk, then tail live, until exit/end/disconnect.
fn stream_to<C: Write>(
    conn: &mut C,
    job: &Job,
    mut offs: [u64; 2],
    follow: bool,
    closed: &AtomicBool,
) -> io::Result<()> {
    loop {
        let step = {
            let mut g = lock(&job.inner);
            loop {
                if let Some(s) = decide(job, &g, &mut offs, follow, closed) {
                    break s;
                }
                g = job
                    .cv
                    .wait_timeout(g, Duration::from_secs(1))
                    .unwrap_or_else(|p| p.into_inner())
                    .0;
            }
        };
        match step {
            Step::Closed => return Ok(()),
            Step::Gap(i, from, to) => send(
                conn,
                json!({"t":"gap","stream":STREAMS[i],"from":from,"to":to}),
                &[],
            )?,
            Step::Data(i, start, off, n) => {
                let mut buf = vec![0u8; n];
                let path = job.dir.join(STREAMS[i]).join(start.to_string());
                match File::open(&path).and_then(|f| f.read_exact_at(&mut buf, off - start)) {
                    Ok(()) => {
                        send(conn, json!({"t":STREAMS[i],"off":off}), &buf)?;
                        offs[i] = off + n as u64;
                    }
                    // Retention removed the segment under us: re-decide (gap).
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => return Err(e),
                }
            }
            Step::Exit(v) | Step::End(v) => return send(conn, v, &[]),
        }
    }
}

pub fn exec<C: Conn>(srv: &Arc<Server>, f: &Frame, conn: &mut C, reader: C) {
    let req = match parse_exec(f) {
        Ok(r) => r,
        Err(m) => return send_error(conn, "bad_request", &m),
    };
    let st = match start_job(srv, &req) {
        Ok(s) => s,
        Err((code, msg)) => return send_error(conn, code, &msg),
    };
    let job = st.job;
    let pid = lock(&job.inner).pid;
    let closed = Arc::new(AtomicBool::new(false));
    let attach = req.attach.unwrap_or(true);
    let _guard = attach.then(|| AttachGuard::new(&job));
    if attach {
        spawn_reader(reader, Arc::clone(&job), Arc::clone(&closed), st.stdin);
    }
    let started = json!({"t":"started","job":job.id,"pid":pid,"deduped":st.deduped});
    if send(conn, started, &[]).is_err() || !attach {
        return;
    }
    let _ = stream_to(conn, &job, [0, 0], true, &closed);
}

pub fn attach<C: Conn>(srv: &Arc<Server>, f: &Frame, conn: &mut C, reader: C) {
    let (Some(owner), Some(id)) = (
        f.header.get("owner").and_then(Value::as_str),
        f.header.get("job").and_then(Value::as_str),
    ) else {
        return send_error(conn, "bad_request", "owner and job are required");
    };
    let off = |k: &str| f.header.get(k).and_then(Value::as_u64).unwrap_or(0);
    let follow = f
        .header
        .get("follow")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let Some(job) = srv.find(owner, id) else {
        return send_error(conn, "not_found", "no such job");
    };
    let state = lock(&job.inner).state;
    let hello =
        json!({"t":"attached","job":job.id,"state":state,"label":job.label,"argv":job.argv});
    if send(conn, hello, &[]).is_err() {
        return;
    }
    let closed = Arc::new(AtomicBool::new(false));
    spawn_reader(reader, Arc::clone(&job), Arc::clone(&closed), None);
    let _guard = AttachGuard::new(&job);
    let _ = stream_to(
        conn,
        &job,
        [off("stdout_off"), off("stderr_off")],
        follow,
        &closed,
    );
}

pub fn list<C: Write>(srv: &Arc<Server>, f: &Frame, conn: &mut C) {
    let Some(owner) = f.header.get("owner").and_then(Value::as_str) else {
        return send_error(conn, "bad_request", "owner is required");
    };
    let mut jobs: Vec<Arc<Job>> = lock(&srv.jobs)
        .values()
        .filter(|j| owner == "*" || j.owner == owner)
        .cloned()
        .collect();
    jobs.sort_by(|a, b| (b.created_ms, &b.id).cmp(&(a.created_ms, &a.id)));
    let list: Vec<Value> = jobs.iter().map(|j| j.summary()).collect();
    let _ = send(conn, json!({"t":"job_list","jobs":list}), &[]);
}

pub fn cancel_job<C: Write>(srv: &Arc<Server>, f: &Frame, conn: &mut C) {
    let (Some(owner), Some(id)) = (
        f.header.get("owner").and_then(Value::as_str),
        f.header.get("job").and_then(Value::as_str),
    ) else {
        return send_error(conn, "bad_request", "owner and job are required");
    };
    let Some(job) = srv.find(owner, id) else {
        return send_error(conn, "not_found", "no such job");
    };
    job.cancel("cancelled");
    let state = lock(&job.inner).state;
    let _ = send(
        conn,
        json!({"t":"cancel_ok","job":job.id,"state":state}),
        &[],
    );
}
