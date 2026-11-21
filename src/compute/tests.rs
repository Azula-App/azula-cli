//! In-process integration tests: a real broker and client over local iroh
//! endpoints, with a fake VM backend whose `vsock.sock` is served by a task
//! speaking the guest protocol (`vm/README.md` §2: durable jobs with owners,
//! idem keys, offsets, attach, jobs, cancel_job, put and get). No VM, no
//! internet.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use data_encoding::HEXLOWER;
use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::Endpoint;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, Notify};

use super::broker::Broker;
use super::client::{self, AttachRequest, Dialer, Event, ExecRequest, Failure, Fault, JobRef, Outcome, Policy, Start};
use super::frame::{read_frame, write_frame, Frame};
use super::grants::{GrantStore, MintOptions, Token, OP_ADMIN, OP_EXEC, OP_VM};
use super::transfer::{self, PullOptions, PushOptions, TransferError, TransferStore};
use super::vm::{VmBackend, VmError, VmInfo, VmState};
use super::ALPN;

// --- fake guest ----------------------------------------------------------------

type ExitInfo = (Option<i64>, Option<i64>, String);

struct Job {
    id: String,
    owner: String,
    idem: String,
    argv: Vec<String>,
    label: String,
    timeout_s: u64,
    st: Mutex<JobState>,
    cancelled: AtomicBool,
    hard_cancelled: AtomicBool,
}

#[derive(Default)]
struct JobState {
    out: Vec<u8>,
    err: Vec<u8>,
    out_earliest: u64,
    exit: Option<ExitInfo>,
    stdin: Vec<u8>,
    stdin_done: bool,
}

impl Job {
    fn push_out(&self, b: &[u8]) {
        self.st.lock().unwrap().out.extend_from_slice(b);
    }
    fn push_err(&self, b: &[u8]) {
        self.st.lock().unwrap().err.extend_from_slice(b);
    }
    fn finish(&self, code: Option<i64>, signal: Option<i64>, reason: &str) {
        let mut s = self.st.lock().unwrap();
        if s.exit.is_none() {
            s.exit = Some((code, signal, reason.to_owned()));
        }
    }
    fn running(&self) -> bool {
        self.st.lock().unwrap().exit.is_none()
    }
}

#[derive(Default)]
struct Fake {
    dir: PathBuf,
    state: Mutex<HashMap<String, VmState>>,
    requests: Mutex<Vec<Value>>,
    starts: AtomicUsize,
    jobs: Mutex<Vec<Arc<Job>>>,
    next_job: AtomicUsize,
    new_jobs: AtomicUsize,
    cancels: AtomicUsize,
    disconnects: AtomicUsize,
    drop_before_started: AtomicBool,
    files: Mutex<HashMap<String, (Vec<u8>, u64)>>,
    dirs: Mutex<HashSet<String>>,
    uploads: Mutex<HashMap<String, (String, Vec<u8>)>>,
    put_offsets: Mutex<Vec<u64>>,
    changed_replies: AtomicUsize,
    tar_payload: Mutex<Vec<u8>>,
    last_stdin: Mutex<Vec<u8>>,
}

fn sha_hex(b: &[u8]) -> String {
    HEXLOWER.encode(Sha256::digest(b).as_slice())
}

impl Fake {
    fn new(tag: &str) -> Arc<Self> {
        let dir = std::env::temp_dir().join(format!("az{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let f = Fake { dir, ..Default::default() };
        for n in ["a", "b", "ci-1", "other"] {
            f.state.lock().unwrap().insert(n.into(), VmState::Stopped);
        }
        Arc::new(f)
    }

    fn set_running(self: &Arc<Self>, name: &str) {
        let sock = self.dir.join(format!("{name}.sock"));
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).unwrap();
        let me = self.clone();
        tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                tokio::spawn(guest_conn(me.clone(), s));
            }
        });
        self.state.lock().unwrap().insert(name.into(), VmState::Running);
    }

    fn running_jobs(&self) -> usize {
        self.jobs.lock().unwrap().iter().filter(|j| j.running()).count()
    }

    fn job_by_label(&self, label: &str) -> Arc<Job> {
        self.jobs.lock().unwrap().iter().find(|j| j.label == label).cloned().expect("job with label")
    }

    fn interrupt_all(&self) {
        for j in self.jobs.lock().unwrap().iter() {
            j.finish(None, None, "interrupted");
        }
    }
}

struct FakeBackend(Arc<Fake>);

impl VmBackend for FakeBackend {
    fn names(&self) -> Result<Vec<String>, VmError> {
        let mut n: Vec<_> = self.0.state.lock().unwrap().keys().cloned().collect();
        n.sort();
        Ok(n)
    }
    fn state(&self, name: &str) -> Result<VmState, VmError> {
        self.0.state.lock().unwrap().get(name).copied().ok_or_else(|| VmError::unknown(name))
    }
    async fn info(&self, name: &str) -> Result<VmInfo, VmError> {
        let st = self.state(name)?;
        Ok(VmInfo {
            name: name.into(),
            state: st.as_str().into(),
            worker: if st == VmState::Running { "ready" } else { "unknown" }.into(),
            image: "fake".into(),
            cpus: 1,
            memory_mb: 512,
            disk_gb: 4,
            network: "nat".into(),
            jobs_running: None,
            disk_free_mb: None,
            worker_info: None,
            error: None,
        })
    }
    async fn start(&self, name: &str) -> Result<(), VmError> {
        if self.state(name)? != VmState::Running {
            self.0.starts.fetch_add(1, SeqCst);
            self.0.set_running(name);
        }
        Ok(())
    }
    async fn stop(&self, name: &str) -> Result<(), VmError> {
        self.state(name)?;
        self.0.state.lock().unwrap().insert(name.into(), VmState::Stopped);
        Ok(())
    }
    fn vsock_path(&self, name: &str) -> PathBuf {
        self.0.dir.join(format!("{name}.sock"))
    }
    async fn shutdown(&self) {}
}

async fn send(w: &mut OwnedWriteHalf, v: Value) -> bool {
    write_frame(w, &Frame::new(v)).await.is_ok()
}

async fn guest_conn(fake: Arc<Fake>, s: UnixStream) {
    let (mut r, mut w) = s.into_split();
    let Ok(Some(first)) = read_frame(&mut r).await else { return };
    match first.t() {
        "ping" => {
            let n = fake.running_jobs();
            send(&mut w, json!({"t":"pong","worker":"fake/1","proto":1,"hostname":"fake-vm","kernel":"6.x","arch":"aarch64","user":"azula","jobs_running":n,"disk_free_mb":1234})).await;
        }
        "exec" => guest_exec(fake, first, r, w).await,
        "attach" => {
            fake.requests.lock().unwrap().push(first.header_value());
            let owner = first.str_field("owner").unwrap_or("").to_owned();
            let id = first.str_field("job").unwrap_or("").to_owned();
            let job = fake.jobs.lock().unwrap().iter().find(|j| j.id == id && j.owner == owner).cloned();
            let Some(job) = job else {
                send(&mut w, json!({"t":"error","code":"not_found","msg":"no such job"})).await;
                return;
            };
            let off = |k: &str| first.header.get(k).and_then(Value::as_u64).unwrap_or(0);
            let follow = first.header.get("follow").and_then(Value::as_bool).unwrap_or(true);
            send(&mut w, json!({"t":"attached","job":job.id,"state":"running","label":job.label,"argv":job.argv})).await;
            stream(fake, job, r, w, off("stdout_off"), off("stderr_off"), follow, false).await;
        }
        "jobs" => {
            fake.requests.lock().unwrap().push(first.header_value());
            let owner = first.str_field("owner").unwrap_or("").to_owned();
            let list: Vec<Value> = fake
                .jobs
                .lock()
                .unwrap()
                .iter()
                .rev()
                .filter(|j| owner == "*" || j.owner == owner)
                .map(|j| {
                    let s = j.st.lock().unwrap();
                    json!({"job": j.id, "label": j.label, "argv": j.argv, "state": if s.exit.is_some() {"exited"} else {"running"},
                           "reason": s.exit.as_ref().map(|e| e.2.clone()), "code": s.exit.as_ref().and_then(|e| e.0),
                           "stdout_len": s.out.len(), "stderr_len": s.err.len(), "stdout_earliest": s.out_earliest, "stderr_earliest": 0,
                           "created": 1u64, "owner": j.owner})
                })
                .collect();
            send(&mut w, json!({"t":"job_list","jobs":list})).await;
        }
        "cancel_job" => {
            fake.requests.lock().unwrap().push(first.header_value());
            let owner = first.str_field("owner").unwrap_or("").to_owned();
            let id = first.str_field("job").unwrap_or("").to_owned();
            let job = fake.jobs.lock().unwrap().iter().find(|j| j.id == id && (owner == "*" || j.owner == owner)).cloned();
            match job {
                Some(j) => {
                    if j.running() {
                        j.cancelled.store(true, SeqCst);
                        j.hard_cancelled.store(true, SeqCst);
                        fake.cancels.fetch_add(1, SeqCst);
                    }
                    send(&mut w, json!({"t":"cancel_ok","job":j.id,"state": if j.running() {"running"} else {"exited"}})).await;
                }
                None => {
                    send(&mut w, json!({"t":"error","code":"not_found","msg":"no such job"})).await;
                }
            }
        }
        "put" => guest_put(fake, first, r, w).await,
        "get" => guest_get(fake, first, w).await,
        _ => {}
    }
}

async fn guest_exec(fake: Arc<Fake>, first: Frame, r: OwnedReadHalf, mut w: OwnedWriteHalf) {
    fake.requests.lock().unwrap().push(first.header_value());
    let owner = first.str_field("owner").unwrap_or("").to_owned();
    let idem = first.str_field("idem").unwrap_or("").to_owned();
    let argv: Vec<String> = first.header["argv"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_owned()).collect();
    if argv[0] == "nonexistent" {
        send(&mut w, json!({"t":"error","code":"spawn_failed","msg":"no such file"})).await;
        return;
    }
    let existing = fake.jobs.lock().unwrap().iter().find(|j| j.owner == owner && j.idem == idem).cloned();
    let (job, deduped) = match existing {
        Some(j) => {
            if j.argv != argv {
                send(&mut w, json!({"t":"error","code":"idem_conflict","msg":"different command"})).await;
                return;
            }
            (j, true)
        }
        None => {
            let id = format!("j_{:016x}", fake.next_job.fetch_add(1, SeqCst) + 0xabc);
            let job = Arc::new(Job {
                id,
                owner,
                idem,
                argv: argv.clone(),
                label: first.str_field("label").unwrap_or("").to_owned(),
                timeout_s: first.header.get("timeout_s").and_then(Value::as_u64).unwrap_or(900),
                st: Mutex::new(JobState::default()),
                cancelled: AtomicBool::new(false),
                hard_cancelled: AtomicBool::new(false),
            });
            fake.jobs.lock().unwrap().push(job.clone());
            fake.new_jobs.fetch_add(1, SeqCst);
            tokio::spawn(run_job(fake.clone(), job.clone()));
            (job, false)
        }
    };
    if fake.drop_before_started.swap(false, SeqCst) {
        return; // the connection dies before the client learns the job id
    }
    send(&mut w, json!({"t":"started","job":job.id,"pid":42,"deduped":deduped})).await;
    if !first.header.get("attach").and_then(Value::as_bool).unwrap_or(true) {
        return;
    }
    let stdin = first.header.get("stdin").and_then(Value::as_bool).unwrap_or(false);
    stream(fake, job, r, w, 0, 0, true, stdin).await;
}

/// What each fake command does.
async fn run_job(fake: Arc<Fake>, job: Arc<Job>) {
    let nap = |ms| tokio::time::sleep(Duration::from_millis(ms));
    match job.argv[0].as_str() {
        "echo" => {
            job.push_out(format!("{}\n", job.argv[1..].join(" ")).as_bytes());
            job.push_err(b"warn");
            job.finish(Some(0), None, "exited");
        }
        "exit7" => job.finish(Some(7), None, "exited"),
        "chatty" => {
            let n: usize = job.argv.get(1).and_then(|s| s.parse().ok()).unwrap_or(40);
            for i in 0..n {
                job.push_out(&vec![(i % 251) as u8; 1000]);
                job.push_err(format!("e{i};").as_bytes());
                nap(5).await;
            }
            job.finish(Some(0), None, "exited");
        }
        "sleep" | "stubborn" => {
            let stubborn = job.argv[0] == "stubborn";
            let deadline = Instant::now() + Duration::from_secs(job.timeout_s);
            loop {
                if job.hard_cancelled.load(SeqCst) || (!stubborn && job.cancelled.load(SeqCst)) {
                    job.finish(None, Some(15), "cancelled");
                    return;
                }
                if Instant::now() >= deadline {
                    job.finish(None, Some(15), "timeout");
                    return;
                }
                if !job.running() {
                    return;
                }
                nap(10).await;
            }
        }
        "cat" | "sh" => {
            loop {
                if !job.running() {
                    return;
                }
                if job.st.lock().unwrap().stdin_done {
                    break;
                }
                nap(10).await;
            }
            let data = job.st.lock().unwrap().stdin.clone();
            if job.argv[0] == "sh" {
                *fake.last_stdin.lock().unwrap() = data;
            } else {
                job.push_out(&data);
            }
            job.finish(Some(0), None, "exited");
        }
        "tar" => {
            let payload = fake.tar_payload.lock().unwrap().clone();
            job.push_out(&payload);
            job.finish(Some(0), None, "exited");
        }
        _ => job.finish(Some(127), None, "exited"),
    }
}

/// Replay (and follow) a job's output to a connected client, while reading its
/// stdin/cancel frames. Mirrors `vm/README.md` §2.3/§2.4.
#[allow(clippy::too_many_arguments)]
async fn stream(fake: Arc<Fake>, job: Arc<Job>, mut r: OwnedReadHalf, mut w: OwnedWriteHalf, mut out_off: u64, mut err_off: u64, follow: bool, stdin_expected: bool) {
    let (stdin_pending_tx, stdin_pending_rx) = tokio::sync::watch::channel(stdin_expected);
    let reader_job = job.clone();
    let reader_fake = fake.clone();
    tokio::spawn(async move {
        loop {
            match read_frame(&mut r).await {
                Ok(Some(f)) => match f.t() {
                    "stdin" => reader_job.st.lock().unwrap().stdin.extend(f.payload),
                    "stdin_eof" => {
                        reader_job.st.lock().unwrap().stdin_done = true;
                        let _ = stdin_pending_tx.send(false);
                    }
                    "cancel" => reader_job.cancelled.store(true, SeqCst),
                    _ => {}
                },
                _ => {
                    reader_fake.disconnects.fetch_add(1, SeqCst);
                    if *stdin_pending_tx.borrow() && reader_job.running() {
                        reader_job.finish(None, Some(15), "stdin_lost");
                    }
                    return;
                }
            }
        }
    });
    let _keep = stdin_pending_rx;
    let wait = Notify::new();
    loop {
        let (out, err, earliest, exit) = {
            let s = job.st.lock().unwrap();
            (s.out.clone(), s.err.clone(), s.out_earliest, s.exit.clone())
        };
        if out_off < earliest {
            if !send(&mut w, json!({"t":"gap","stream":"stdout","from":out_off,"to":earliest})).await {
                return;
            }
            out_off = earliest;
        }
        for (name, buf, off) in [("stdout", &out, &mut out_off), ("stderr", &err, &mut err_off)] {
            while (*off as usize) < buf.len() {
                let end = (*off as usize + 4096).min(buf.len());
                let f = Frame::with_payload(json!({"t": name, "off": *off}), buf[*off as usize..end].to_vec());
                if write_frame(&mut w, &f).await.is_err() {
                    return;
                }
                *off = end as u64;
            }
        }
        if out_off as usize >= out.len() && err_off as usize >= err.len() {
            if let Some((code, signal, reason)) = exit {
                send(&mut w, json!({"t":"exit","job":job.id,"code":code,"signal":signal,"reason":reason,"stdout_len":out.len(),"stderr_len":err.len()})).await;
                return;
            }
            if !follow {
                send(&mut w, json!({"t":"end","state":"running","stdout_len":out.len(),"stderr_len":err.len()})).await;
                return;
            }
        }
        let _ = tokio::time::timeout(Duration::from_millis(15), wait.notified()).await;
    }
}

async fn guest_put(fake: Arc<Fake>, first: Frame, mut r: OwnedReadHalf, mut w: OwnedWriteHalf) {
    fake.requests.lock().unwrap().push(first.header_value());
    let owner = first.str_field("owner").unwrap_or("");
    let path = first.str_field("path").unwrap_or("").to_owned();
    let key = format!("{owner}|{}", first.str_field("upload").unwrap_or(""));
    let overwrite = first.header.get("overwrite").and_then(Value::as_bool).unwrap_or(true);
    let is_dir = fake.dirs.lock().unwrap().contains(&path);
    if is_dir {
        send(&mut w, json!({"t":"error","code":"is_a_directory","msg":"is a directory"})).await;
        return;
    }
    let exists = fake.files.lock().unwrap().contains_key(&path);
    if !overwrite && exists {
        send(&mut w, json!({"t":"error","code":"exists","msg":"exists"})).await;
        return;
    }
    let offset = {
        let mut up = fake.uploads.lock().unwrap();
        let e = up.entry(key.clone()).or_insert_with(|| (path.clone(), Vec::new()));
        if e.0 != path {
            None
        } else {
            Some(e.1.len() as u64)
        }
    };
    let Some(offset) = offset else {
        send(&mut w, json!({"t":"error","code":"upload_conflict","msg":"id in use"})).await;
        return;
    };
    fake.put_offsets.lock().unwrap().push(offset);
    send(&mut w, json!({"t":"put_ready","offset":offset})).await;
    loop {
        match read_frame(&mut r).await {
            Ok(Some(f)) if f.t() == "data" => fake.uploads.lock().unwrap().get_mut(&key).unwrap().1.extend(f.payload),
            Ok(Some(f)) if f.t() == "eof" => {
                let bytes = fake.uploads.lock().unwrap().get(&key).unwrap().1.clone();
                let size = f.header.get("size").and_then(Value::as_u64).unwrap_or(0);
                if bytes.len() as u64 != size {
                    fake.uploads.lock().unwrap().remove(&key);
                    send(&mut w, json!({"t":"error","code":"size_mismatch","msg":"size"})).await;
                } else if sha_hex(&bytes) != f.str_field("sha256").unwrap_or("") {
                    fake.uploads.lock().unwrap().remove(&key);
                    send(&mut w, json!({"t":"error","code":"digest_mismatch","msg":"digest"})).await;
                } else {
                    {
                        let mut files = fake.files.lock().unwrap();
                        let ver = files.get(&path).map(|f| f.1 + 1).unwrap_or(1);
                        files.insert(path.clone(), (bytes.clone(), ver));
                    }
                    fake.uploads.lock().unwrap().remove(&key);
                    send(&mut w, json!({"t":"put_ok","path":format!("/home/azula/{path}"),"size":size,"sha256":sha_hex(&bytes)})).await;
                }
                return;
            }
            _ => return, // dropped: the part stays for resumption
        }
    }
}

async fn guest_get(fake: Arc<Fake>, first: Frame, mut w: OwnedWriteHalf) {
    fake.requests.lock().unwrap().push(first.header_value());
    let path = first.str_field("path").unwrap_or("").to_owned();
    let offset = first.header.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
    let found = fake.files.lock().unwrap().get(&path).cloned();
    let Some((bytes, ver)) = found else {
        let is_dir = fake.dirs.lock().unwrap().contains(&path);
        let code = if is_dir { "not_a_file" } else { "not_found" };
        send(&mut w, json!({"t":"error","code":code,"msg":"no such file"})).await;
        return;
    };
    let etag = format!("v{ver}-{}", bytes.len());
    if let Some(want) = first.str_field("etag") {
        if want != etag {
            fake.changed_replies.fetch_add(1, SeqCst);
            send(&mut w, json!({"t":"error","code":"changed","msg":"file changed"})).await;
            return;
        }
    }
    send(&mut w, json!({"t":"get_meta","path":path,"size":bytes.len(),"mode":0o640,"etag":etag})).await;
    let mut at = offset;
    while at < bytes.len() {
        let end = (at + 64 * 1024).min(bytes.len());
        if write_frame(&mut w, &Frame::with_payload(json!({"t":"data"}), bytes[at..end].to_vec())).await.is_err() {
            return;
        }
        at = end;
    }
    send(&mut w, json!({"t":"get_end","size":bytes.len(),"sha256":sha_hex(&bytes)})).await;
}

// --- harness ----------------------------------------------------------------------

struct Harness {
    fake: Arc<Fake>,
    store: GrantStore,
    broker_ep: Endpoint,
    client_ep: Endpoint,
    router: Router,
    watcher: tokio::task::JoinHandle<()>,
    dir: PathBuf,
}

fn fast() -> Policy {
    Policy { window: Duration::from_secs(20), initial: Duration::from_millis(20), max: Duration::from_millis(100) }
}

fn no_reconnect() -> Policy {
    Policy::with_window(Duration::ZERO)
}

impl Harness {
    async fn new(tag: &str) -> Self {
        let fake = Fake::new(tag);
        let dir = std::env::temp_dir().join(format!("azg{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = GrantStore::new(&dir);
        let broker_ep = Endpoint::bind(presets::Minimal).await.unwrap();
        let broker = Broker::with_watch_interval(Arc::new(FakeBackend(fake.clone())), store.clone(), "testhost".into(), Duration::from_millis(150));
        let watcher = broker.spawn_watcher();
        let router = Router::builder(broker_ep.clone()).accept(ALPN, broker).spawn();
        let client_ep = Endpoint::bind(presets::Minimal).await.unwrap();
        Harness { fake, store, broker_ep, client_ep, router, watcher, dir }
    }

    fn mint_for(&self, ops: &[&str], vms: &[&str], ttl: u64) -> Token {
        let (g, secret) = self
            .store
            .mint(&MintOptions {
                label: "t".into(),
                ttl: Duration::from_secs(ttl),
                ops: ops.iter().map(|s| s.to_string()).collect(),
                vms: vms.iter().map(|s| s.to_string()).collect(),
            })
            .unwrap();
        Token { host: self.broker_ep.id().to_string(), relay: String::new(), grant: g.id, secret }
    }

    fn mint(&self, ops: &[&str], vms: &[&str]) -> Token {
        self.mint_for(ops, vms, 600)
    }

    fn dialer(&self, t: &Token) -> Dialer {
        Dialer::new(self.client_ep.clone(), self.broker_ep.addr(), t.clone())
    }

    async fn session(&self, t: &Token) -> Result<client::Session, Failure> {
        self.dialer(t).session().await
    }

    async fn run(&self, t: &Token, start: Start, stdin: Option<Vec<u8>>, policy: Policy) -> (Outcome, Vec<Event>) {
        let (_tx, rx) = mpsc::channel(1);
        self.run_with(&self.dialer(t), start, stdin, rx, policy).await
    }

    async fn run_with(&self, d: &Dialer, start: Start, stdin: Option<Vec<u8>>, rx: mpsc::Receiver<()>, policy: Policy) -> (Outcome, Vec<Event>) {
        let mut events = Vec::new();
        let stdin: Option<Box<dyn tokio::io::AsyncRead + Unpin + Send>> = stdin.map(|b| Box::new(std::io::Cursor::new(b)) as _);
        let (out, _job) = client::run_job(d, start, stdin, rx, policy, &mut |e| events.push(e.clone())).await;
        (out, events)
    }

    async fn exec(&self, t: &Token, req: ExecRequest) -> (Outcome, Vec<Event>) {
        self.run(t, Start::Exec(req), None, fast()).await
    }

    async fn shutdown(self) {
        self.watcher.abort();
        let _ = self.router.shutdown().await;
        self.client_ep.close().await;
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn req(argv: &[&str]) -> ExecRequest {
    ExecRequest { argv: argv.iter().map(|s| s.to_string()).collect(), ..Default::default() }
}

fn stdout_of(events: &[Event]) -> Vec<u8> {
    events.iter().flat_map(|e| if let Event::Stdout { data, .. } = e { data.clone() } else { Vec::new() }).collect()
}

fn stderr_of(events: &[Event]) -> Vec<u8> {
    events.iter().flat_map(|e| if let Event::Stderr { data, .. } = e { data.clone() } else { Vec::new() }).collect()
}

fn job_ref_of(events: &[Event]) -> String {
    events.iter().find_map(|e| if let Event::Started { job, .. } = e { Some(job.clone()) } else { None }).expect("started event")
}

async fn eventually(what: &str, mut cond: impl FnMut() -> bool) {
    for _ in 0..400 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for {what}");
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("azt{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

// --- exec: the basics -----------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exec_streams_output_starts_the_vm_and_strips_broker_fields() {
    let h = Harness::new("echo").await;
    let t = h.mint(&[OP_EXEC, OP_VM], &["*"]);
    let mut r = req(&["echo", "hi", "$HOME"]);
    r.vm = Some("a".into());
    let (out, events) = h.exec(&t, r).await;
    assert_eq!(out, Outcome::Exit { code: Some(0), signal: None, reason: "exited".into() });
    assert_eq!(stdout_of(&events), b"hi $HOME\n");
    assert_eq!(stderr_of(&events), b"warn");
    assert!(job_ref_of(&events).starts_with("a/j_"), "ref is <vm>/<id>");
    assert_eq!(h.fake.starts.load(SeqCst), 1, "stopped VM was started on demand");
    let seen = h.fake.requests.lock().unwrap()[0].clone();
    for k in ["vm", "start", "all"] {
        assert!(seen.get(k).is_none(), "broker-only field {k} stripped: {seen}");
    }
    assert_eq!(seen["argv"], json!(["echo", "hi", "$HOME"]));
    assert!(seen["idem"].as_str().is_some_and(|s| !s.is_empty()), "client sent an idem key");
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exit_code_and_spawn_failure_pass_through() {
    let h = Harness::new("exit").await;
    let t = h.mint(&[OP_EXEC, OP_VM], &["a"]);
    let (out, _) = h.exec(&t, req(&["exit7"])).await;
    assert_eq!(out.exit_code(), 7, "default VM is the grant's only VM");
    let (out, _) = h.exec(&t, req(&["nonexistent"])).await;
    assert_eq!(out.exit_code(), 127);
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stdin_round_trips_binary_across_many_frames() {
    let h = Harness::new("stdin").await;
    let t = h.mint(&[OP_EXEC, OP_VM], &["a"]);
    let data: Vec<u8> = (0..300_000u32).map(|i| (i * 31 % 256) as u8).collect();
    let mut r = req(&["cat"]);
    r.stdin = true;
    let (out, events) = h.run(&t, Start::Exec(r), Some(data.clone()), fast()).await;
    assert_eq!(out.exit_code(), 0);
    assert_eq!(stdout_of(&events), data);
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_revoked_and_expired_grants_are_indistinguishable() {
    let h = Harness::new("auth").await;
    let good = h.mint(&[OP_EXEC], &["*"]);
    let mut unknown = h.mint(&[OP_EXEC], &["*"]);
    unknown.grant = "g_000000000000".into();
    let mut wrong_secret = good.clone();
    wrong_secret.secret = "A".repeat(43);
    let revoked = h.mint(&[OP_EXEC], &["*"]);
    h.store.revoke(&revoked.grant, false).unwrap();
    let expired = h.mint(&[OP_EXEC], &["*"]);
    {
        let path = h.store.path();
        let mut v: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        for g in v["grants"].as_array_mut().unwrap() {
            if g["id"] == expired.grant.as_str() {
                g["expires"] = json!(1);
            }
        }
        std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
    }
    let mut msgs = Vec::new();
    for t in [&unknown, &wrong_secret, &revoked, &expired] {
        match h.session(t).await {
            Err(Failure::Broker { code, msg }) => {
                assert_eq!(code, "unauthorized");
                msgs.push(msg);
            }
            other => panic!("expected unauthorized, got {:?}", other.map(|_| ())),
        }
    }
    assert!(msgs.windows(2).all(|w| w[0] == w[1]), "identical replies: {msgs:?}");
    assert!(h.session(&good).await.is_ok(), "the live grant still works");
    assert_eq!(h.fake.new_jobs.load(SeqCst), 0);
    let grants = h.store.list().unwrap();
    assert!(grants.iter().find(|g| g.id == good.grant).unwrap().last_used.is_some());
    assert!(grants.iter().find(|g| g.id == revoked.grant).unwrap().last_used.is_none());
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forbidden_vm_and_operation_and_globs() {
    let h = Harness::new("forbidden").await;
    let one_vm = h.mint(&[OP_EXEC, OP_VM], &["a"]);
    let mut r = req(&["echo", "x"]);
    r.vm = Some("b".into());
    let (out, _) = h.exec(&one_vm, r).await;
    assert!(matches!(&out, Outcome::Error { code, .. } if code == "forbidden"), "{out:?}");
    assert_eq!(out.exit_code(), 125);
    assert_eq!(h.fake.new_jobs.load(SeqCst), 0);
    assert_eq!(h.fake.starts.load(SeqCst), 0, "nothing started for a forbidden request");

    let vm_only = h.mint(&[OP_VM], &["*"]);
    let (out, _) = h.exec(&vm_only, req(&["echo", "x"])).await;
    assert!(matches!(&out, Outcome::Error { code, .. } if code == "forbidden"), "{out:?}");

    let exec_only = h.mint(&[OP_EXEC], &["*"]);
    let s = h.session(&exec_only).await.unwrap();
    let err = client::vm_op(s, "start", Some("a"), false).await.unwrap_err();
    assert!(matches!(err, Failure::Broker { ref code, .. } if code == "forbidden"), "{err:?}");

    // `ci-*` covers ci-1 but not `other`.
    let globbed = h.mint(&[OP_EXEC, OP_VM], &["ci-*"]);
    let mut r = req(&["echo", "g"]);
    r.vm = Some("ci-1".into());
    let (out, _) = h.exec(&globbed, r).await;
    assert_eq!(out.exit_code(), 0, "{out:?}");
    let mut r = req(&["echo", "g"]);
    r.vm = Some("other".into());
    let (out, _) = h.exec(&globbed, r).await;
    assert!(matches!(&out, Outcome::Error { code, .. } if code == "forbidden"), "{out:?}");
    let list = client::vm_op(h.session(&globbed).await.unwrap(), "list", None, false).await.unwrap();
    assert_eq!(list.iter().map(|v| v["name"].as_str().unwrap()).collect::<Vec<_>>(), ["ci-1"]);
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_not_running_when_start_is_declined_or_not_granted() {
    let h = Harness::new("notrunning").await;
    let t = h.mint(&[OP_EXEC, OP_VM], &["a"]);
    let mut r = req(&["echo", "x"]);
    r.no_start = true;
    let (out, _) = h.exec(&t, r).await;
    assert!(matches!(&out, Outcome::Error { code, .. } if code == "vm_not_running"), "{out:?}");
    assert_eq!(h.fake.starts.load(SeqCst), 0);

    let exec_only = h.mint(&[OP_EXEC], &["a"]);
    let (out, _) = h.exec(&exec_only, req(&["echo", "x"])).await;
    assert!(matches!(&out, Outcome::Error { code, .. } if code == "vm_not_running"), "{out:?}");
    assert_eq!(h.fake.starts.load(SeqCst), 0);

    let mut r = req(&["echo", "x"]);
    r.vm = Some("ghost".into());
    let any = h.mint(&[OP_EXEC, OP_VM], &["*"]);
    let (out, _) = h.exec(&any, r).await;
    assert!(matches!(&out, Outcome::Error { code, .. } if code == "unknown_vm"), "{out:?}");
    h.shutdown().await;
}

// --- durable jobs: cancel, disconnect, reconnect ------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_interrupt_cancels_and_second_detaches_leaving_the_job_running() {
    let h = Harness::new("cancel").await;
    h.fake.set_running("a");
    let t = h.mint(&[OP_EXEC], &["a"]);
    let (tx, rx) = mpsc::channel(4);
    let fake = h.fake.clone();
    tokio::spawn(async move {
        eventually("job start", || fake.new_jobs.load(SeqCst) == 1).await;
        tx.send(()).await.unwrap();
    });
    let (out, _) = h.run_with(&h.dialer(&t), Start::Exec(req(&["sleep", "600"])), None, rx, fast()).await;
    assert_eq!(out.exit_code(), 130, "{out:?}");
    assert!(matches!(&out, Outcome::Exit { reason, .. } if reason == "cancelled"), "{out:?}");

    // Second interrupt: the job ignores `cancel`, so the client detaches; the job keeps running.
    let (tx, rx) = mpsc::channel(4);
    let fake = h.fake.clone();
    tokio::spawn(async move {
        eventually("second job start", || fake.new_jobs.load(SeqCst) == 2).await;
        tx.send(()).await.unwrap();
        tx.send(()).await.unwrap();
    });
    let (out, events) = h.run_with(&h.dialer(&t), Start::Exec(req(&["stubborn"])), None, rx, fast()).await;
    assert!(matches!(&out, Outcome::Detached { by_interrupt: true, .. }), "{out:?}");
    assert_eq!(out.exit_code(), 130);
    assert!(out.message(None).unwrap().contains(&job_ref_of(&events)), "names the job to reattach to");
    eventually("guest to see the disconnect", || h.fake.disconnects.load(SeqCst) >= 2).await;
    assert_eq!(h.fake.running_jobs(), 1, "a disconnect does not cancel the job");
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detach_returns_at_started_and_attach_replays_from_zero() {
    let h = Harness::new("detach").await;
    let t = h.mint(&[OP_EXEC, OP_VM], &["a"]);
    let mut r = req(&["chatty", "10"]);
    r.detach = true;
    r.label = Some("nightly".into());
    let (out, events) = h.exec(&t, r).await;
    let Outcome::Detached { job, by_interrupt: false } = out.clone() else { panic!("{out:?}") };
    assert_eq!(out.exit_code(), 0);
    assert_eq!(job, job_ref_of(&events));
    let r = JobRef::parse(&job).unwrap();
    // Attach later: the whole output from offset 0, then the exit.
    let start = Start::Attach(AttachRequest { vm: r.vm.clone(), job: r.id.clone(), stdout_off: 0, stderr_off: 0, follow: true });
    let (out, events) = h.run(&t, start, None, fast()).await;
    assert_eq!(out.exit_code(), 0, "{out:?}");
    assert_eq!(stdout_of(&events).len(), 10_000);
    // jobs lists it with its label.
    let (vm, jobs) = client::list_jobs(h.session(&t).await.unwrap(), None, false).await.unwrap();
    assert_eq!(vm, "a");
    assert_eq!(jobs[0]["label"], "nightly");
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconnect_after_a_forced_drop_yields_byte_identical_output() {
    let h = Harness::new("reconnect").await;
    let t = h.mint(&[OP_EXEC, OP_VM], &["a"]);
    // Drop the connection once, after 9 000 bytes of the 40 x 1000 byte stream.
    let d = h.dialer(&t).with_fault(Some(Fault::drop_after(9_000)));
    let (_tx, rx) = mpsc::channel(1);
    let (out, events) = h.run_with(&d, Start::Exec(req(&["chatty", "40"])), None, rx, fast()).await;
    assert_eq!(out.exit_code(), 0, "{out:?}");
    let expected: Vec<u8> = (0..40usize).flat_map(|i| vec![(i % 251) as u8; 1000]).collect();
    assert_eq!(stdout_of(&events), expected, "no repeated or missing stdout bytes");
    let expected_err: Vec<u8> = (0..40).flat_map(|i| format!("e{i};").into_bytes()).collect();
    assert_eq!(stderr_of(&events), expected_err, "no repeated or missing stderr bytes");
    let reconnects = events.iter().filter(|e| matches!(e, Event::Reconnecting { .. })).count();
    assert_eq!(reconnects, 1, "one outage, one notice");
    assert_eq!(h.fake.new_jobs.load(SeqCst), 1, "the job ran once");
    let reqs = h.fake.requests.lock().unwrap().clone();
    let attach = reqs.iter().find(|r| r["t"] == "attach").expect("reattached");
    assert!(attach["stdout_off"].as_u64().unwrap() >= 9_000, "attached with the offsets already written: {attach}");
    // Offsets in the JSON events are contiguous.
    let mut next = 0u64;
    for e in &events {
        if let Event::Stdout { off, data } = e {
            assert_eq!(*off, next);
            next += data.len() as u64;
        }
    }
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resending_before_started_dedupes_by_idem() {
    let h = Harness::new("idem").await;
    h.fake.set_running("a");
    h.fake.drop_before_started.store(true, SeqCst);
    let t = h.mint(&[OP_EXEC], &["a"]);
    let (out, events) = h.exec(&t, req(&["echo", "once"])).await;
    assert_eq!(out.exit_code(), 0, "{out:?}");
    assert_eq!(stdout_of(&events), b"once\n");
    assert_eq!(h.fake.new_jobs.load(SeqCst), 1, "never runs twice");
    let execs: Vec<Value> = h.fake.requests.lock().unwrap().iter().filter(|r| r["t"] == "exec").cloned().collect();
    assert_eq!(execs.len(), 2, "the exec was resent");
    assert_eq!(execs[0]["idem"], execs[1]["idem"], "with the same idem key");
    assert!(events.iter().any(|e| matches!(e, Event::Started { deduped: true, .. })), "the guest answered with the existing job");
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zero_reconnect_window_makes_the_first_drop_a_transport_failure() {
    let h = Harness::new("giveup").await;
    h.fake.set_running("a");
    let t = h.mint(&[OP_EXEC], &["a"]);
    let d = h.dialer(&t).with_fault(Some(Fault::drop_after(1)));
    // Reconnect disabled: the first drop is a transport failure.
    let (_tx, rx) = mpsc::channel(1);
    let (out, _) = h.run_with(&d, Start::Exec(req(&["chatty", "40"])), None, rx, no_reconnect()).await;
    assert!(matches!(out, Outcome::Transport(_)), "{out:?}");
    assert_eq!(out.exit_code(), 255);
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interrupted_and_stdin_lost_jobs_exit_255_with_an_explanation() {
    let h = Harness::new("lost").await;
    h.fake.set_running("a");
    let t = h.mint(&[OP_EXEC], &["a"]);
    // The worker restarted under a running job.
    let fake = h.fake.clone();
    tokio::spawn(async move {
        eventually("job start", || fake.new_jobs.load(SeqCst) == 1).await;
        fake.interrupt_all();
    });
    let (out, _) = h.exec(&t, req(&["sleep", "600"])).await;
    assert_eq!(out.exit_code(), 255, "{out:?}");
    assert!(out.message(None).unwrap().contains("interrupted"));

    // stdin never reaches EOF and the client leaves: the job is cancelled as stdin_lost.
    let (tx, rx) = mpsc::channel(4);
    let (_keep_open, reader) = tokio::io::duplex(64);
    let mut r = req(&["cat"]);
    r.stdin = true;
    let d = h.dialer(&t);
    let fake = h.fake.clone();
    tokio::spawn(async move {
        eventually("cat start", || fake.new_jobs.load(SeqCst) == 2).await;
        tx.send(()).await.unwrap();
        tx.send(()).await.unwrap();
    });
    let mut events = Vec::new();
    let (out, _) = client::run_job(&d, Start::Exec(r), Some(Box::new(reader)), rx, fast(), &mut |e| events.push(e.clone())).await;
    assert!(matches!(out, Outcome::Detached { by_interrupt: true, .. }), "{out:?}");
    let job = JobRef::parse(&job_ref_of(&events)).unwrap();
    let start = Start::Attach(AttachRequest { vm: job.vm, job: job.id, stdout_off: 0, stderr_off: 0, follow: true });
    let (out, _) = h.run(&t, start, None, fast()).await;
    assert!(matches!(&out, Outcome::Exit { reason, .. } if reason == "stdin_lost"), "{out:?}");
    assert_eq!(out.exit_code(), 255);
    assert!(out.message(None).unwrap().contains("stdin"));
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attach_reports_a_retention_gap() {
    let h = Harness::new("gap").await;
    h.fake.set_running("a");
    let t = h.mint(&[OP_EXEC], &["a"]);
    let (out, events) = h.exec(&t, req(&["chatty", "3"])).await;
    assert_eq!(out.exit_code(), 0);
    let job = JobRef::parse(&job_ref_of(&events)).unwrap();
    h.fake.jobs.lock().unwrap()[0].st.lock().unwrap().out_earliest = 1500;
    let start = Start::Attach(AttachRequest { vm: job.vm, job: job.id, stdout_off: 0, stderr_off: 0, follow: false });
    let (out, events) = h.run(&t, start, None, fast()).await;
    assert_eq!(out.exit_code(), 0, "{out:?}");
    assert!(events.contains(&Event::Gap { stream: "stdout".into(), from: 0, to: 1500 }), "{events:?}");
    assert_eq!(stdout_of(&events).len(), 1500, "data resumes from the retained offset");
    h.shutdown().await;
}

// --- grants as principals --------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owner_is_stamped_by_the_broker_and_isolates_grants() {
    let h = Harness::new("owner").await;
    h.fake.set_running("a");
    let g1 = h.mint(&[OP_EXEC], &["a"]);
    let g2 = h.mint(&[OP_EXEC], &["a"]);
    // A client claiming another owner is overwritten with the authenticated grant id.
    let mut s = h.session(&g1).await.unwrap();
    let evil = Frame::new(json!({"t":"exec","vm":"a","owner":g2.grant,"idem":"x1","argv":["echo","mine"],"attach":true}));
    write_frame(&mut s.send, &evil).await.unwrap();
    while let Ok(Some(f)) = read_frame(&mut s.recv).await {
        if f.t() == "exit" {
            break;
        }
    }
    let first = h.fake.requests.lock().unwrap()[0].clone();
    assert_eq!(first["owner"], g1.grant.as_str(), "owner is the grant id, whatever the client said");
    let mut detached = ExecRequest { label: Some("g1-job".into()), ..req(&["sleep", "600"]) };
    detached.detach = true;
    let (_, events) = h.exec(&g1, detached).await;
    let g1_ref = JobRef::parse(&job_ref_of(&events)).unwrap();

    // g2 sees nothing of g1's: list, attach and cancel are all not_found / empty.
    let (_, jobs) = client::list_jobs(h.session(&g2).await.unwrap(), None, false).await.unwrap();
    assert!(jobs.is_empty(), "{jobs:?}");
    let start = Start::Attach(AttachRequest { vm: g1_ref.vm.clone(), job: g1_ref.id.clone(), stdout_off: 0, stderr_off: 0, follow: true });
    let (out, _) = h.run(&g2, start, None, fast()).await;
    assert!(matches!(&out, Outcome::Error { code, .. } if code == "not_found"), "{out:?}");
    let err = client::cancel_job(h.session(&g2).await.unwrap(), &g1_ref, false).await.unwrap_err();
    assert!(matches!(err, Failure::Broker { ref code, .. } if code == "not_found"), "{err:?}");
    assert!(h.fake.job_by_label("g1-job").running(), "g2 could not cancel it");

    // A non-admin cannot ask for everything.
    let err = client::list_jobs(h.session(&g2).await.unwrap(), None, true).await.unwrap_err();
    assert!(matches!(err, Failure::Broker { ref code, .. } if code == "forbidden"), "{err:?}");

    // An admin grant sees and cancels any owner's jobs (owner "*").
    let admin = h.mint(&[OP_EXEC, OP_ADMIN], &["*"]);
    let (_, jobs) = client::list_jobs(h.session(&admin).await.unwrap(), Some("a"), true).await.unwrap();
    assert!(jobs.iter().any(|j| j["label"] == "g1-job"), "{jobs:?}");
    let reqs = h.fake.requests.lock().unwrap().clone();
    assert!(reqs.iter().any(|r| r["t"] == "jobs" && r["owner"] == "*"), "owner * only for the admin");
    assert!(reqs.iter().filter(|r| r["t"] == "jobs").filter(|r| r["owner"] == g2.grant.as_str() || r["owner"] == "*").count() >= 2);
    client::cancel_job(h.session(&admin).await.unwrap(), &g1_ref, true).await.unwrap();
    eventually("admin cancel", || !h.fake.job_by_label("g1-job").running()).await;
    // Without `all`, an admin is an ordinary owner too.
    let (_, mine) = client::list_jobs(h.session(&admin).await.unwrap(), Some("a"), false).await.unwrap();
    assert!(mine.is_empty());
    h.shutdown().await;
}

// --- grant lifetime ------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exec_timeout_is_clamped_to_the_grant_and_a_nearly_expired_grant_is_refused() {
    let h = Harness::new("clamp").await;
    h.fake.set_running("a");
    let t = h.mint_for(&[OP_EXEC], &["a"], 120);
    let mut r = req(&["echo", "x"]);
    r.timeout_s = Some(3600);
    let (out, _) = h.exec(&t, r).await;
    assert_eq!(out.exit_code(), 0);
    let seen = h.fake.requests.lock().unwrap()[0]["timeout_s"].as_u64().unwrap();
    assert!((115..=120).contains(&seen), "timeout lowered to the grant's remaining life: {seen}");
    // A shorter request is left alone.
    let mut r = req(&["echo", "y"]);
    r.timeout_s = Some(30);
    h.exec(&t, r).await;
    assert_eq!(h.fake.requests.lock().unwrap()[1]["timeout_s"], 30);

    let soon = h.mint_for(&[OP_EXEC], &["a"], 30);
    let (out, _) = h.exec(&soon, req(&["echo", "z"])).await;
    assert!(matches!(&out, Outcome::Error { code, .. } if code == "grant_expiring"), "{out:?}");
    assert_eq!(out.exit_code(), 125);
    assert_eq!(h.fake.new_jobs.load(SeqCst), 2, "no job for the expiring grant");
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revocation_closes_a_live_stream_within_five_seconds_and_can_cancel_jobs() {
    let h = Harness::new("revoke").await;
    h.fake.set_running("a");
    let t = h.mint(&[OP_EXEC], &["a"]);
    let started = Instant::now();
    let (tx, rx) = mpsc::channel::<()>(1);
    let store = h.store.clone();
    let grant = t.grant.clone();
    let fake = h.fake.clone();
    tokio::spawn(async move {
        eventually("job start", || fake.new_jobs.load(SeqCst) == 1).await;
        store.revoke(&grant, false).unwrap();
        let _keep = tx;
        tokio::time::sleep(Duration::from_secs(30)).await;
    });
    let (out, _) = h.run_with(&h.dialer(&t), Start::Exec(req(&["sleep", "600"])), None, rx, no_reconnect()).await;
    assert!(matches!(out, Outcome::Transport(_)), "the stream was cut: {out:?}");
    assert!(started.elapsed() < Duration::from_secs(5), "closed in {:?}", started.elapsed());
    assert!(h.fake.jobs.lock().unwrap()[0].running(), "the job keeps running after a plain revoke");
    let err = h.session(&t).await.err().expect("revoked");
    assert!(matches!(err, Failure::Broker { ref code, .. } if code == "unauthorized"));

    // --cancel-jobs: the broker cancels the grant's running jobs on running VMs.
    let t2 = h.mint(&[OP_EXEC], &["a"]);
    let mut r = req(&["sleep", "600"]);
    r.detach = true;
    let (out, _) = h.exec(&t2, r).await;
    assert!(matches!(out, Outcome::Detached { .. }), "{out:?}");
    let sleeper = h.fake.jobs.lock().unwrap().iter().find(|j| j.owner == t2.grant).cloned().unwrap();
    assert!(sleeper.running());
    h.store.revoke(&t2.grant, true).unwrap();
    eventually("jobs cancelled by the revocation", || !sleeper.running()).await;
    assert_eq!(h.fake.cancels.load(SeqCst), 1);
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expiry_closes_live_connections() {
    let h = Harness::new("expiry").await;
    h.fake.set_running("a");
    let t = h.mint(&[OP_EXEC], &["a"]);
    // Attach to a long job, then let the grant run out.
    let (_, events) = {
        let mut r = req(&["sleep", "600"]);
        r.detach = true;
        h.exec(&t, r).await
    };
    let job = JobRef::parse(&job_ref_of(&events)).unwrap();
    let store = h.store.clone();
    let grant = t.grant.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let path = store.path();
        let mut v: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        for g in v["grants"].as_array_mut().unwrap() {
            if g["id"] == grant.as_str() {
                g["expires"] = json!(crate::compute::grants::unix_now() + 1);
            }
        }
        std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
    });
    let started = Instant::now();
    let start = Start::Attach(AttachRequest { vm: job.vm, job: job.id, stdout_off: 0, stderr_off: 0, follow: true });
    let (out, _) = h.run(&t, start, None, no_reconnect()).await;
    assert!(matches!(out, Outcome::Transport(_)), "{out:?}");
    assert!(started.elapsed() < Duration::from_secs(6), "{:?}", started.elapsed());
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stopping_a_busy_vm_needs_force() {
    let h = Harness::new("busy").await;
    h.fake.set_running("a");
    let owner = h.mint(&[OP_EXEC], &["a"]);
    let other = h.mint(&[OP_EXEC, OP_VM], &["a"]);
    let mut r = req(&["sleep", "600"]);
    r.detach = true;
    h.exec(&owner, r).await;
    assert_eq!(h.fake.running_jobs(), 1);
    // Another grant's job counts: vm_busy with the number.
    let err = client::vm_op(h.session(&other).await.unwrap(), "stop", Some("a"), false).await.unwrap_err();
    match &err {
        Failure::Broker { code, msg } => {
            assert_eq!(code, "vm_busy");
            assert!(msg.contains("1 job"), "{msg}");
        }
        e => panic!("{e:?}"),
    }
    assert_eq!(err.exit_code(), 125);
    assert_eq!(h.fake.state.lock().unwrap()["a"], VmState::Running);
    let st = client::vm_op(h.session(&other).await.unwrap(), "stop", Some("a"), true).await.unwrap();
    assert_eq!(st[0]["state"], "stopped");
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_verbs_list_status_start_stop_and_guest_ping() {
    let h = Harness::new("vmverbs").await;
    let scoped = h.mint(&[OP_EXEC, OP_VM], &["a"]);
    let all = h.mint(&[OP_EXEC, OP_VM], &["*"]);

    let list = client::vm_op(h.session(&scoped).await.unwrap(), "list", None, false).await.unwrap();
    assert_eq!(list.len(), 1, "list is filtered to the grant's scope");
    let list = client::vm_op(h.session(&all).await.unwrap(), "list", None, false).await.unwrap();
    assert_eq!(list.len(), 4);

    let st = client::vm_op(h.session(&scoped).await.unwrap(), "start", None, false).await.unwrap();
    assert_eq!(st[0]["name"], "a");
    assert_eq!(st[0]["state"], "running");
    assert_eq!(st[0]["worker"], "ready");

    let pong = client::request_reply(h.session(&scoped).await.unwrap(), &Frame::new(json!({"t":"guest_ping","vm":"a"})), Duration::from_secs(10)).await.unwrap();
    assert_eq!(pong.t(), "pong");
    assert_eq!(pong.str_field("hostname"), Some("fake-vm"));
    assert_eq!(pong.header["jobs_running"], 0);

    let st = client::vm_op(h.session(&scoped).await.unwrap(), "stop", Some("a"), false).await.unwrap();
    assert_eq!(st[0]["state"], "stopped");
    let err = client::request_reply(h.session(&scoped).await.unwrap(), &Frame::new(json!({"t":"guest_ping","vm":"a"})), Duration::from_secs(10)).await.unwrap_err();
    assert!(matches!(err, Failure::Broker { ref code, .. } if code == "vm_not_running"), "{err:?}");

    let ping = client::request_reply(h.session(&all).await.unwrap(), &Frame::of_type("ping"), Duration::from_secs(10)).await.unwrap();
    assert_eq!(ping.str_field("host"), Some("testhost"));
    h.shutdown().await;
}

// --- file transfer ---------------------------------------------------------------------------

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i.wrapping_mul(131) % 251) as u8).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_and_pull_round_trip_with_verification() {
    let h = Harness::new("xfer").await;
    h.fake.set_running("a");
    let t = h.mint(&[OP_EXEC], &["a"]);
    let dir = tmpdir("xfer");
    let store = TransferStore::new(dir.join("transfers.json"));
    let src = dir.join("app.bin");
    let data = pattern(1_300_000);
    std::fs::write(&src, &data).unwrap();
    let d = h.dialer(&t);
    let opts = PushOptions { policy: fast(), ..Default::default() };
    let res = transfer::push(&d, &store, src.to_str().unwrap(), "out/app.bin", &opts, &mut |_, _| {}).await.unwrap();
    assert_eq!(res.size, data.len() as u64);
    assert_eq!(res.sha256, sha_hex(&data));
    assert_eq!(res.resumed_from, 0);
    assert_eq!(h.fake.files.lock().unwrap()["out/app.bin"].0, data);
    assert!(store.is_empty(), "a finished transfer leaves no record");
    // --no-clobber on an existing target: exists, file error, exit 1.
    let no_clobber = PushOptions { no_clobber: true, policy: fast(), ..Default::default() };
    let err = transfer::push(&d, &store, src.to_str().unwrap(), "out/app.bin", &no_clobber, &mut |_, _| {}).await.unwrap_err();
    assert!(matches!(&err, TransferError::File { code, .. } if code == "exists"), "{err:?}");
    assert_eq!(err.exit_code(), 1);
    // A directory target gets the source's basename.
    h.fake.dirs.lock().unwrap().insert("out".into());
    let res = transfer::push(&d, &store, src.to_str().unwrap(), "out", &opts, &mut |_, _| {}).await.unwrap();
    assert!(res.path.ends_with("out/app.bin"), "{}", res.path);
    // Pull it back, atomically, into a directory.
    let out = dir.join("pulled");
    std::fs::create_dir_all(&out).unwrap();
    let res = transfer::pull(&d, &store, "out/app.bin", out.to_str().unwrap(), &PullOptions { policy: fast(), ..Default::default() }, &mut |_, _| {}).await.unwrap();
    assert_eq!(std::fs::read(out.join("app.bin")).unwrap(), data);
    assert_eq!(res.sha256, sha_hex(&data));
    assert!(std::fs::read_dir(&out).unwrap().all(|e| !e.unwrap().file_name().to_string_lossy().ends_with(".part")), "no part file left");
    // Errors: missing file is not_found (1), a directory is not_a_file (1).
    let err = transfer::pull(&d, &store, "nope", out.to_str().unwrap(), &PullOptions::default(), &mut |_, _| {}).await.unwrap_err();
    assert!(matches!(&err, TransferError::File { code, .. } if code == "not_found"), "{err:?}");
    let err = transfer::pull(&d, &store, "out", out.to_str().unwrap(), &PullOptions::default(), &mut |_, _| {}).await.unwrap_err();
    assert!(matches!(&err, TransferError::File { code, .. } if code == "not_a_file"), "{err:?}");
    // The broker errors map to 125.
    let vm_only = h.mint(&[OP_VM], &["a"]);
    let err = transfer::push(&h.dialer(&vm_only), &store, src.to_str().unwrap(), "x", &opts, &mut |_, _| {}).await.unwrap_err();
    assert_eq!(err.exit_code(), 125, "{err:?}");
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_resumes_within_an_invocation_and_across_invocations() {
    let h = Harness::new("pushresume").await;
    h.fake.set_running("a");
    let t = h.mint(&[OP_EXEC], &["a"]);
    let dir = tmpdir("pushresume");
    let store = TransferStore::new(dir.join("transfers.json"));
    let src = dir.join("big.bin");
    let data = pattern(2_000_000);
    std::fs::write(&src, &data).unwrap();

    // Invocation 1: drop after the first chunk and do not reconnect -> transport failure, record kept.
    let d1 = h.dialer(&t).with_fault(Some(Fault::drop_after(100_000)));
    let opts = PushOptions { policy: no_reconnect(), ..Default::default() };
    let err = transfer::push(&d1, &store, src.to_str().unwrap(), "big.bin", &opts, &mut |_, _| {}).await.unwrap_err();
    assert!(matches!(err, TransferError::Transport(_)), "{err:?}");
    assert_eq!(err.exit_code(), 255);
    assert_eq!(store.len(), 1, "transfers.json remembers the upload");
    let partial = h.fake.uploads.lock().unwrap().values().next().unwrap().1.len();
    assert!(partial > 0 && partial < data.len(), "the guest holds a part: {partial}");

    // Invocation 2 (fresh process, same store): continues from the guest's offset.
    let d2 = h.dialer(&t);
    let res = transfer::push(&d2, &store, src.to_str().unwrap(), "big.bin", &PushOptions { policy: fast(), ..Default::default() }, &mut |_, _| {}).await.unwrap();
    assert_eq!(res.resumed_from as usize, partial, "resumed from the part file's length");
    assert_eq!(h.fake.files.lock().unwrap()["big.bin"].0, data, "digest-verified whole file");
    assert!(store.is_empty());

    // Within one invocation: a drop is ridden out by reconnecting.
    let d3 = h.dialer(&t).with_fault(Some(Fault::drop_after(100_000)));
    let before = h.fake.put_offsets.lock().unwrap().len();
    let res = transfer::push(&d3, &store, src.to_str().unwrap(), "again.bin", &PushOptions { policy: fast(), ..Default::default() }, &mut |_, _| {}).await.unwrap();
    assert_eq!(res.size, data.len() as u64);
    let offs = h.fake.put_offsets.lock().unwrap()[before..].to_vec();
    assert_eq!(offs.len(), 2, "two connections: {offs:?}");
    assert!(offs[1] > 0, "the second connection resumed mid-file: {offs:?}");
    assert_eq!(h.fake.files.lock().unwrap()["again.bin"].0, data);

    // A local file that changed between invocations restarts from zero.
    let src2 = dir.join("changing.bin");
    std::fs::write(&src2, pattern(1_500_000)).unwrap();
    let d4 = h.dialer(&t).with_fault(Some(Fault::drop_after(100_000)));
    let _ = transfer::push(&d4, &store, src2.to_str().unwrap(), "c.bin", &PushOptions { policy: no_reconnect(), ..Default::default() }, &mut |_, _| {}).await.unwrap_err();
    std::fs::write(&src2, pattern(1_400_000)).unwrap();
    let res = transfer::push(&h.dialer(&t), &store, src2.to_str().unwrap(), "c.bin", &PushOptions { policy: fast(), ..Default::default() }, &mut |_, _| {}).await.unwrap();
    assert_eq!(res.resumed_from, 0, "different size: a fresh upload id");
    assert_eq!(h.fake.files.lock().unwrap()["c.bin"].0, pattern(1_400_000));
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pull_resumes_and_restarts_when_the_remote_file_changed() {
    let h = Harness::new("pullresume").await;
    h.fake.set_running("a");
    let t = h.mint(&[OP_EXEC], &["a"]);
    let dir = tmpdir("pullresume");
    let store = TransferStore::new(dir.join("transfers.json"));
    let v1 = pattern(1_000_000);
    h.fake.files.lock().unwrap().insert("art.bin".into(), (v1.clone(), 1));
    let dest = dir.join("art.bin");

    // Interrupted pull leaves a part file and a record.
    let d1 = h.dialer(&t).with_fault(Some(Fault::drop_after(200_000)));
    let err = transfer::pull(&d1, &store, "art.bin", dest.to_str().unwrap(), &PullOptions { policy: no_reconnect(), ..Default::default() }, &mut |_, _| {}).await.unwrap_err();
    assert!(matches!(err, TransferError::Transport(_)), "{err:?}");
    assert!(!dest.exists(), "nothing at the destination until the digest matches");
    let parts: Vec<_> = std::fs::read_dir(&dir).unwrap().filter_map(|e| e.ok()).filter(|e| e.file_name().to_string_lossy().ends_with(".part")).collect();
    assert_eq!(parts.len(), 1, "a part file next to the destination");
    assert_eq!(store.len(), 1);

    // Unchanged remote: the next invocation resumes from the part's length.
    let part_len = parts[0].metadata().unwrap().len();
    let res = transfer::pull(&h.dialer(&t), &store, "art.bin", dest.to_str().unwrap(), &PullOptions { policy: fast(), ..Default::default() }, &mut |_, _| {}).await.unwrap();
    assert_eq!(res.resumed_from, part_len);
    assert_eq!(std::fs::read(&dest).unwrap(), v1);
    assert_eq!(h.fake.changed_replies.load(SeqCst), 0);
    std::fs::remove_file(&dest).unwrap();

    // Interrupt again, then the remote file changes: resume is refused with `changed` and restarts from 0.
    let d2 = h.dialer(&t).with_fault(Some(Fault::drop_after(200_000)));
    let _ = transfer::pull(&d2, &store, "art.bin", dest.to_str().unwrap(), &PullOptions { policy: no_reconnect(), ..Default::default() }, &mut |_, _| {}).await.unwrap_err();
    let v2: Vec<u8> = pattern(900_000).iter().map(|b| b ^ 0x5a).collect();
    h.fake.files.lock().unwrap().insert("art.bin".into(), (v2.clone(), 2));
    let res = transfer::pull(&h.dialer(&t), &store, "art.bin", dest.to_str().unwrap(), &PullOptions { policy: fast(), ..Default::default() }, &mut |_, _| {}).await.unwrap();
    assert_eq!(h.fake.changed_replies.load(SeqCst), 1, "the guest refused the stale etag");
    assert_eq!(std::fs::read(&dest).unwrap(), v2, "no splice of two versions");
    assert_eq!(res.sha256, sha_hex(&v2));
    assert!(store.is_empty());
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn directory_trees_travel_as_tar_and_pull_extracts_defensively() {
    let h = Harness::new("tree").await;
    h.fake.set_running("a");
    let t = h.mint(&[OP_EXEC], &["a"]);
    let dir = tmpdir("tree");
    let src = dir.join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("a.txt"), b"alpha").unwrap();
    std::fs::write(src.join("sub/b.txt"), b"beta").unwrap();

    // push -r: the guest's `tar -x` receives a real archive on stdin.
    let res = transfer::push_tree(&h.dialer(&t), &src, "/work/src", None, fast()).await.unwrap();
    assert!(res.entries >= 3);
    let received = h.fake.last_stdin.lock().unwrap().clone();
    let out = dir.join("roundtrip");
    super::tarx::extract_safe(&received[..], &out).unwrap();
    assert_eq!(std::fs::read(out.join("sub/b.txt")).unwrap(), b"beta");
    let exec = h.fake.requests.lock().unwrap().iter().find(|r| r["t"] == "exec").cloned().unwrap();
    assert_eq!(exec["argv"][0], "sh");
    assert_eq!(exec["argv"][4], "/work/src", "the remote dir is an argument, never interpolated into the script");

    // pull -r of that same tree.
    let tarball = dir.join("t.tar");
    super::tarx::build_tar(&src, &tarball).unwrap();
    *h.fake.tar_payload.lock().unwrap() = std::fs::read(&tarball).unwrap();
    let dest = dir.join("pulled");
    transfer::pull_tree(&h.dialer(&t), "/work/src", &dest, None, fast()).await.unwrap();
    assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"alpha");

    // A hostile guest: `../` and an absolute path. Rejected, exit 1, nothing outside the destination.
    let evil = {
        let mut b = Vec::new();
        for (name, body) in [("fine.txt", &b"ok"[..]), ("../escaped.txt", &b"pwn"[..])] {
            let mut hd = tar::Header::new_old();
            hd.set_size(body.len() as u64);
            hd.set_mode(0o644);
            hd.set_entry_type(tar::EntryType::Regular);
            hd.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
            hd.set_cksum();
            b.extend_from_slice(hd.as_bytes());
            b.extend_from_slice(body);
            b.resize(b.len().div_ceil(512) * 512, 0);
        }
        b.extend(vec![0u8; 1024]);
        b
    };
    *h.fake.tar_payload.lock().unwrap() = evil;
    let dest2 = dir.join("victim").join("dest");
    let err = transfer::pull_tree(&h.dialer(&t), "/work/src", &dest2, None, fast()).await.unwrap_err();
    assert_eq!(err.exit_code(), 1, "{err:?}");
    assert!(err.message().contains("unsafe"), "{err:?}");
    assert!(!dir.join("victim").join("escaped.txt").exists(), "nothing written outside LOCAL");
    h.shutdown().await;
}
