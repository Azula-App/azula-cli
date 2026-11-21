//! In-process integration tests: a real broker and client over local iroh
//! endpoints, with a fake VM backend whose `vsock.sock` is served by a task
//! speaking the guest protocol. No VM, no internet.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::Endpoint;
use serde_json::{json, Value};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

use super::broker::Broker;
use super::client::{self, Event, ExecRequest, Failure, Outcome};
use super::frame::{read_frame, write_frame, Frame};
use super::grants::{GrantStore, MintOptions, Token, OP_EXEC, OP_VM};
use super::vm::{VmBackend, VmError, VmInfo, VmState};
use super::ALPN;

// --- fake backend + guest ---------------------------------------------------

#[derive(Default)]
struct Fake {
    dir: PathBuf,
    state: Mutex<HashMap<String, VmState>>,
    execs: Mutex<Vec<Value>>,
    starts: AtomicUsize,
    cancels: AtomicUsize,
    disconnects: AtomicUsize,
    jobs_started: AtomicUsize,
}

impl Fake {
    fn new(tag: &str) -> Arc<Self> {
        let dir = std::env::temp_dir().join(format!("az{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let f = Fake { dir, ..Default::default() };
        for n in ["a", "b"] {
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
            worker_info: None,
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

async fn guest_conn(fake: Arc<Fake>, mut s: UnixStream) {
    let Ok(Some(first)) = read_frame(&mut s).await else { return };
    match first.t() {
        "ping" => {
            let pong = json!({"t":"pong","worker":"fake/1","proto":1,"hostname":"fake-vm","kernel":"6.x","arch":"aarch64","user":"azula"});
            let _ = write_frame(&mut s, &Frame::new(pong)).await;
        }
        "exec" => {
            fake.execs.lock().unwrap().push(first.header_value());
            let argv: Vec<String> = first.header["argv"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_owned()).collect();
            fake.jobs_started.fetch_add(1, SeqCst);
            let _ = write_frame(&mut s, &Frame::new(json!({"t":"started","pid":42}))).await;
            match argv[0].as_str() {
                "echo" => {
                    let out = format!("{}\n", argv[1..].join(" "));
                    let _ = write_frame(&mut s, &Frame::with_payload(json!({"t":"stdout"}), out.into_bytes())).await;
                    let _ = write_frame(&mut s, &Frame::with_payload(json!({"t":"stderr"}), b"warn".to_vec())).await;
                    let _ = write_frame(&mut s, &Frame::new(json!({"t":"exit","code":0,"signal":null,"reason":"exited"}))).await;
                }
                "exit7" => {
                    let _ = write_frame(&mut s, &Frame::new(json!({"t":"exit","code":7,"signal":null,"reason":"exited"}))).await;
                }
                "cat" => {
                    let mut buf = Vec::new();
                    loop {
                        match read_frame(&mut s).await {
                            Ok(Some(f)) if f.t() == "stdin" => buf.extend(f.payload),
                            Ok(Some(f)) if f.t() == "stdin_eof" => break,
                            _ => {
                                fake.disconnects.fetch_add(1, SeqCst);
                                return;
                            }
                        }
                    }
                    for chunk in buf.chunks(64 * 1024) {
                        let _ = write_frame(&mut s, &Frame::with_payload(json!({"t":"stdout"}), chunk.to_vec())).await;
                    }
                    let _ = write_frame(&mut s, &Frame::new(json!({"t":"exit","code":0,"signal":null,"reason":"exited"}))).await;
                }
                "sleep" => match read_frame(&mut s).await {
                    Ok(Some(f)) if f.t() == "cancel" => {
                        fake.cancels.fetch_add(1, SeqCst);
                        let _ = write_frame(&mut s, &Frame::new(json!({"t":"exit","code":null,"signal":15,"reason":"cancelled"}))).await;
                    }
                    _ => {
                        fake.disconnects.fetch_add(1, SeqCst);
                    }
                },
                "stubborn" => loop {
                    // Ignores cancel; only a disconnect ends it.
                    if !matches!(read_frame(&mut s).await, Ok(Some(_))) {
                        fake.disconnects.fetch_add(1, SeqCst);
                        return;
                    }
                },
                _ => {
                    let _ = write_frame(&mut s, &Frame::new(json!({"t":"error","code":"spawn_failed","msg":"no such file"}))).await;
                }
            }
        }
        _ => {}
    }
}

// --- harness ----------------------------------------------------------------

struct Harness {
    fake: Arc<Fake>,
    store: GrantStore,
    broker_ep: Endpoint,
    client_ep: Endpoint,
    router: Router,
}

impl Harness {
    async fn new(tag: &str) -> Self {
        let fake = Fake::new(tag);
        let gdir = std::env::temp_dir().join(format!("azg{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&gdir);
        let store = GrantStore::new(&gdir);
        let broker_ep = Endpoint::bind(presets::Minimal).await.unwrap();
        let broker = Broker::new(Arc::new(FakeBackend(fake.clone())), store.clone(), "testhost".into());
        let router = Router::builder(broker_ep.clone()).accept(ALPN, broker).spawn();
        let client_ep = Endpoint::bind(presets::Minimal).await.unwrap();
        Harness { fake, store, broker_ep, client_ep, router }
    }

    fn mint(&self, ops: &[&str], vms: &[&str]) -> Token {
        let (g, secret) = self
            .store
            .mint(&MintOptions {
                label: "t".into(),
                ttl: Duration::from_secs(600),
                ops: ops.iter().map(|s| s.to_string()).collect(),
                vms: vms.iter().map(|s| s.to_string()).collect(),
            })
            .unwrap();
        Token { host: self.broker_ep.id().to_string(), relay: String::new(), grant: g.id, secret }
    }

    async fn session(&self, t: &Token) -> Result<client::Session, Failure> {
        client::connect(&self.client_ep, self.broker_ep.addr(), t).await
    }

    async fn exec(&self, t: &Token, req: ExecRequest, stdin: Option<Vec<u8>>) -> (Outcome, Vec<Event>) {
        let (_tx, rx) = mpsc::channel(1);
        self.exec_with(t, req, stdin, rx).await
    }

    async fn exec_with(&self, t: &Token, req: ExecRequest, stdin: Option<Vec<u8>>, rx: mpsc::Receiver<()>) -> (Outcome, Vec<Event>) {
        let session = self.session(t).await.expect("session");
        let mut events = Vec::new();
        let stdin: Option<Box<dyn tokio::io::AsyncRead + Unpin + Send>> = stdin.map(|b| Box::new(std::io::Cursor::new(b)) as _);
        let out = client::exec(session, &req, stdin, rx, |e| events.push(e.clone())).await;
        (out, events)
    }

    async fn shutdown(self) {
        let _ = self.router.shutdown().await;
        self.client_ep.close().await;
    }
}

fn req(argv: &[&str]) -> ExecRequest {
    ExecRequest { argv: argv.iter().map(|s| s.to_string()).collect(), ..Default::default() }
}

fn stdout_of(events: &[Event]) -> Vec<u8> {
    events.iter().flat_map(|e| if let Event::Stdout(d) = e { d.clone() } else { Vec::new() }).collect()
}

async fn eventually(what: &str, mut cond: impl FnMut() -> bool) {
    for _ in 0..200 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for {what}");
}

// --- tests ------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exec_streams_output_starts_the_vm_and_strips_broker_fields() {
    let h = Harness::new("echo").await;
    let t = h.mint(&[OP_EXEC, OP_VM], &["*"]);
    let mut r = req(&["echo", "hi", "$HOME"]);
    r.vm = Some("a".into());
    let (out, events) = h.exec(&t, r, None).await;
    assert_eq!(out, Outcome::Exit { code: Some(0), signal: None, reason: "exited".into() });
    assert_eq!(out.exit_code(), 0);
    assert_eq!(stdout_of(&events), b"hi $HOME\n");
    assert!(events.contains(&Event::Stderr(b"warn".to_vec())));
    assert!(events.contains(&Event::Started { pid: Some(42) }));
    assert_eq!(h.fake.starts.load(SeqCst), 1, "stopped VM was started on demand");
    let seen = h.fake.execs.lock().unwrap()[0].clone();
    assert!(seen.get("vm").is_none() && seen.get("start").is_none(), "broker-only fields stripped: {seen}");
    assert_eq!(seen["argv"], json!(["echo", "hi", "$HOME"]));
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exit_code_and_spawn_failure_pass_through() {
    let h = Harness::new("exit").await;
    let t = h.mint(&[OP_EXEC, OP_VM], &["a"]);
    let (out, _) = h.exec(&t, req(&["exit7"]), None).await;
    assert_eq!(out.exit_code(), 7, "default VM is the grant's only VM");
    let (out, _) = h.exec(&t, req(&["nonexistent"]), None).await;
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
    let (out, events) = h.exec(&t, r, Some(data.clone())).await;
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
    h.store.revoke(&revoked.grant).unwrap();
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
    assert_eq!(h.fake.jobs_started.load(SeqCst), 0);
    // last_used / last_peer recorded for the good grant only.
    let grants = h.store.list().unwrap();
    assert!(grants.iter().find(|g| g.id == good.grant).unwrap().last_used.is_some());
    assert!(grants.iter().find(|g| g.id == revoked.grant).unwrap().last_used.is_none());
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forbidden_vm_and_operation() {
    let h = Harness::new("forbidden").await;
    let one_vm = h.mint(&[OP_EXEC, OP_VM], &["a"]);
    let mut r = req(&["echo", "x"]);
    r.vm = Some("b".into());
    let (out, _) = h.exec(&one_vm, r, None).await;
    assert!(matches!(&out, Outcome::Error { code, .. } if code == "forbidden"), "{out:?}");
    assert_eq!(out.exit_code(), 125);
    assert_eq!(h.fake.jobs_started.load(SeqCst), 0);
    assert_eq!(h.fake.starts.load(SeqCst), 0, "nothing started for a forbidden request");

    let vm_only = h.mint(&[OP_VM], &["*"]);
    let (out, _) = h.exec(&vm_only, req(&["echo", "x"]), None).await;
    assert!(matches!(&out, Outcome::Error { code, .. } if code == "forbidden"), "{out:?}");

    let exec_only = h.mint(&[OP_EXEC], &["*"]);
    let s = h.session(&exec_only).await.unwrap();
    let err = client::vm_op(s, "start", Some("a")).await.unwrap_err();
    assert!(matches!(err, Failure::Broker { ref code, .. } if code == "forbidden"), "{err:?}");
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_not_running_when_start_is_declined_or_not_granted() {
    let h = Harness::new("notrunning").await;
    let t = h.mint(&[OP_EXEC, OP_VM], &["a"]);
    let mut r = req(&["echo", "x"]);
    r.no_start = true;
    let (out, _) = h.exec(&t, r, None).await;
    assert!(matches!(&out, Outcome::Error { code, .. } if code == "vm_not_running"), "{out:?}");
    assert_eq!(h.fake.starts.load(SeqCst), 0);

    // start:true without op `vm` in the grant is declined too.
    let exec_only = h.mint(&[OP_EXEC], &["a"]);
    let (out, _) = h.exec(&exec_only, req(&["echo", "x"]), None).await;
    assert!(matches!(&out, Outcome::Error { code, .. } if code == "vm_not_running"), "{out:?}");
    assert_eq!(h.fake.starts.load(SeqCst), 0);

    // Unknown VM.
    let mut r = req(&["echo", "x"]);
    r.vm = Some("ghost".into());
    let any = h.mint(&[OP_EXEC, OP_VM], &["*"]);
    let (out, _) = h.exec(&any, r, None).await;
    assert!(matches!(&out, Outcome::Error { code, .. } if code == "unknown_vm"), "{out:?}");
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_interrupt_cancels_the_job_and_second_disconnects() {
    let h = Harness::new("cancel").await;
    h.fake.set_running("a");
    let t = h.mint(&[OP_EXEC], &["a"]);
    let (tx, rx) = mpsc::channel(4);
    let fake = h.fake.clone();
    tokio::spawn(async move {
        eventually("job start", || fake.jobs_started.load(SeqCst) == 1).await;
        tx.send(()).await.unwrap();
    });
    let (out, _) = h.exec_with(&t, req(&["sleep", "600"]), None, rx).await;
    assert_eq!(out.exit_code(), 130, "{out:?}");
    assert_eq!(h.fake.cancels.load(SeqCst), 1, "the guest received a cancel frame");

    // Second interrupt: the job ignores cancel, so the client disconnects.
    let (tx, rx) = mpsc::channel(4);
    let fake = h.fake.clone();
    tokio::spawn(async move {
        eventually("second job start", || fake.jobs_started.load(SeqCst) == 2).await;
        tx.send(()).await.unwrap();
        tx.send(()).await.unwrap();
    });
    let (out, _) = h.exec_with(&t, req(&["stubborn"]), None, rx).await;
    assert_eq!(out, Outcome::Interrupted);
    eventually("guest to see the disconnect", || h.fake.disconnects.load(SeqCst) == 1).await;
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_disconnect_closes_the_guest_side() {
    let h = Harness::new("disconnect").await;
    h.fake.set_running("a");
    let t = h.mint(&[OP_EXEC], &["a"]);
    let mut s = h.session(&t).await.unwrap();
    let exec = Frame::new(json!({"t":"exec","vm":"a","start":false,"argv":["sleep","600"]}));
    write_frame(&mut s.send, &exec).await.unwrap();
    let started = read_frame(&mut s.recv).await.unwrap().unwrap();
    assert_eq!(started.t(), "started");
    assert_eq!(h.fake.disconnects.load(SeqCst), 0);
    // The client goes away without a cancel frame.
    s.conn.close(0u32.into(), b"bye");
    drop(s);
    eventually("guest to see the disconnect", || h.fake.disconnects.load(SeqCst) == 1).await;
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_verbs_list_status_start_stop_and_guest_ping() {
    let h = Harness::new("vmverbs").await;
    let scoped = h.mint(&[OP_EXEC, OP_VM], &["a"]);
    let all = h.mint(&[OP_EXEC, OP_VM], &["*"]);

    let list = client::vm_op(h.session(&scoped).await.unwrap(), "list", None).await.unwrap();
    assert_eq!(list.len(), 1, "list is filtered to the grant's scope");
    assert_eq!(list[0]["name"], "a");
    let list = client::vm_op(h.session(&all).await.unwrap(), "list", None).await.unwrap();
    assert_eq!(list.len(), 2);

    // Default VM rule: the scoped grant's only VM.
    let st = client::vm_op(h.session(&scoped).await.unwrap(), "start", None).await.unwrap();
    assert_eq!(st[0]["name"], "a");
    assert_eq!(st[0]["state"], "running");
    assert_eq!(st[0]["worker"], "ready");

    let pong = client::request_reply(h.session(&scoped).await.unwrap(), &Frame::new(json!({"t":"guest_ping","vm":"a"})), Duration::from_secs(10)).await.unwrap();
    assert_eq!(pong.t(), "pong");
    assert_eq!(pong.str_field("hostname"), Some("fake-vm"));

    let st = client::vm_op(h.session(&scoped).await.unwrap(), "stop", Some("a")).await.unwrap();
    assert_eq!(st[0]["state"], "stopped");
    let err = client::request_reply(h.session(&scoped).await.unwrap(), &Frame::new(json!({"t":"guest_ping","vm":"a"})), Duration::from_secs(10)).await.unwrap_err();
    assert!(matches!(err, Failure::Broker { ref code, .. } if code == "vm_not_running"), "{err:?}");

    let ping = client::request_reply(h.session(&all).await.unwrap(), &Frame::of_type("ping"), Duration::from_secs(10)).await.unwrap();
    assert_eq!(ping.str_field("host"), Some("testhost"));
    h.shutdown().await;
}
