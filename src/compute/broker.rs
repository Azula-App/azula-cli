//! The compute broker (`vm/BROKER.md` §5): accepts iroh connections on
//! [`super::ALPN`], authenticates the grant, authorizes one request and either
//! answers it or splices bytes between the client and the VM's worker.
//!
//! The broker executes nothing on the host. For job and file requests it
//! stamps the grant id as `owner`, opens the VM's `vsock.sock`, forwards the
//! request, and copies bytes both ways without parsing job output or file
//! data. A background watcher closes the live connections of revoked or
//! expired grants.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWriteExt};
use tokio::net::UnixStream;
use tracing::{debug, info, warn};

use super::frame::{read_frame, write_frame, Frame};
use super::grants::{unix_now, Grant, GrantStore, OP_ADMIN, OP_EXEC, OP_VM};
use super::vm::{VmBackend, VmError, VmInfo, VmState};
use super::{agent, guest, short_id, PROTO_VERSION};

/// How long a client gets to send `hello` and then its request.
const FRAME_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the broker waits for a freshly started VM's worker before forwarding.
const WORKER_WAIT: Duration = Duration::from_secs(30);
/// A job whose grant has less than this left is refused.
const MIN_GRANT_LEFT_S: u64 = 60;
/// Default job timeout when the client names none (matches the worker's).
const DEFAULT_TIMEOUT_S: u64 = 900;
/// How often the watcher looks at the grant store and expiry times.
pub const WATCH_INTERVAL: Duration = Duration::from_secs(2);
/// Request types that are forwarded to the guest worker.
const FORWARDED: &[&str] = &["exec", "attach", "jobs", "cancel_job", "put", "get"];

/// QUIC close codes the watcher uses (the reason text is `revoked`/`expired`).
const CLOSE_REVOKED: u32 = 2;
const CLOSE_EXPIRED: u32 = 3;

/// The broker: a grant store, a VM backend and the host's name.
pub struct Broker<B: VmBackend> {
    inner: Arc<Inner<B>>,
}

struct Inner<B> {
    backend: Arc<B>,
    grants: GrantStore,
    host: String,
    watch_interval: Duration,
    live: Mutex<HashMap<String, Vec<(u64, Connection)>>>,
    next_key: AtomicU64,
    cancel_handled: Mutex<HashSet<String>>,
}

impl<B: VmBackend> Clone for Broker<B> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

impl<B: VmBackend> std::fmt::Debug for Broker<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Broker").field("host", &self.inner.host).finish()
    }
}

impl<B: VmBackend> ProtocolHandler for Broker<B> {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        self.handle_connection(connection).await;
        Ok(())
    }
}

/// Removes a connection from the live index when the request ends.
struct LiveGuard<B: VmBackend> {
    inner: Arc<Inner<B>>,
    grant: String,
    key: u64,
}

impl<B: VmBackend> Drop for LiveGuard<B> {
    fn drop(&mut self) {
        let mut live = self.inner.live.lock().unwrap();
        if let Some(v) = live.get_mut(&self.grant) {
            v.retain(|(k, _)| *k != self.key);
            if v.is_empty() {
                live.remove(&self.grant);
            }
        }
    }
}

/// What one request logged: filled in as the request progresses.
struct ReqLog {
    grant: String,
    req: String,
    vm: String,
    job: String,
}

fn err_frame(code: &str, msg: impl Into<String>) -> Frame {
    Frame::new(json!({"t": "error", "code": code, "msg": msg.into()}))
}

impl<B: VmBackend> Broker<B> {
    pub fn new(backend: Arc<B>, grants: GrantStore, host: String) -> Self {
        Self::with_watch_interval(backend, grants, host, WATCH_INTERVAL)
    }

    pub fn with_watch_interval(backend: Arc<B>, grants: GrantStore, host: String, watch_interval: Duration) -> Self {
        Self {
            inner: Arc::new(Inner {
                backend,
                grants,
                host,
                watch_interval,
                live: Mutex::new(HashMap::new()),
                next_key: AtomicU64::new(1),
                cancel_handled: Mutex::new(HashSet::new()),
            }),
        }
    }

    /// Serve one connection to completion and log one line for it.
    pub async fn handle_connection(&self, conn: Connection) {
        let peer = short_id(&conn.remote_id().to_string());
        let mut log = ReqLog { grant: "-".into(), req: "?".into(), vm: "-".into(), job: "-".into() };
        let outcome = self.serve(&conn, &peer, &mut log).await;
        // Never the secret: only the (non-secret) grant id.
        info!(target: "azula::compute", "grant={} peer={peer} req={} vm={} job={} outcome={outcome}", log.grant, log.req, log.vm, log.job);
        conn.close(0u32.into(), b"done");
    }

    // --- live revocation / expiry --------------------------------------------

    /// Start the watcher: re-reads the grant store when its mtime changes and
    /// checks expiry times every `watch_interval`, closing the live
    /// connections of revoked or expired grants.
    pub fn spawn_watcher(&self) -> tokio::task::JoinHandle<()> {
        let me = self.clone();
        tokio::spawn(async move {
            let mut last_mtime = None;
            let mut grants: Vec<Grant> = Vec::new();
            loop {
                tokio::time::sleep(me.inner.watch_interval).await;
                let m = me.inner.grants.mtime();
                if m != last_mtime || grants.is_empty() {
                    let store = me.inner.grants.clone();
                    if let Ok(Ok(list)) = tokio::task::spawn_blocking(move || store.list()).await {
                        grants = list;
                        last_mtime = m;
                    }
                }
                me.enforce(&grants, unix_now());
            }
        })
    }

    /// Close connections of grants that are revoked, expired or gone, and fire
    /// `--cancel-jobs` once per such revocation.
    fn enforce(&self, grants: &[Grant], now: u64) {
        let live_ids: Vec<String> = self.inner.live.lock().unwrap().keys().cloned().collect();
        for id in live_ids {
            let reason = match grants.iter().find(|g| g.id == id) {
                None => Some((CLOSE_REVOKED, "revoked")),
                Some(g) if g.revoked.is_some() => Some((CLOSE_REVOKED, "revoked")),
                Some(g) if now >= g.expires => Some((CLOSE_EXPIRED, "expired")),
                Some(_) => None,
            };
            if let Some((code, why)) = reason {
                let conns: Vec<Connection> = self.inner.live.lock().unwrap().get(&id).map(|v| v.iter().map(|(_, c)| c.clone()).collect()).unwrap_or_default();
                for c in conns {
                    c.close(code.into(), why.as_bytes());
                }
                info!(target: "azula::compute", "grant={id} closed live connections: {why}");
            }
        }
        for g in grants.iter().filter(|g| g.revoked.is_some() && g.revoke_cancel_jobs) {
            if self.inner.cancel_handled.lock().unwrap().insert(g.id.clone()) {
                let me = self.clone();
                let id = g.id.clone();
                tokio::spawn(async move { me.cancel_jobs_of(&id).await });
            }
        }
    }

    /// `revoke --cancel-jobs`: cancel this grant's running jobs on every running VM.
    async fn cancel_jobs_of(&self, grant: &str) {
        let backend = &*self.inner.backend;
        let Ok(names) = backend.names() else { return };
        for name in names {
            if !matches!(backend.probe(&name).await, Ok((VmState::Running, _))) {
                continue;
            }
            let sock = backend.vsock_path(&name);
            let Ok(jobs) = guest::list_jobs(&sock, grant).await else { continue };
            for j in jobs.iter().filter(|j| j.get("state").and_then(Value::as_str) == Some("running")) {
                if let Some(id) = j.get("job").and_then(Value::as_str) {
                    let r = guest::cancel_job(&sock, grant, id).await;
                    info!(target: "azula::compute", "grant={grant} revoked: cancel_job {name}/{id}: {}", r.map(|_| "ok".to_owned()).unwrap_or_else(|e| e));
                }
            }
        }
    }

    fn register(&self, grant: &str, conn: &Connection) -> LiveGuard<B> {
        let key = self.inner.next_key.fetch_add(1, Ordering::Relaxed);
        self.inner.live.lock().unwrap().entry(grant.to_owned()).or_default().push((key, conn.clone()));
        LiveGuard { inner: self.inner.clone(), grant: grant.to_owned(), key }
    }

    // --- one connection ------------------------------------------------------

    async fn serve(&self, conn: &Connection, peer: &str, log: &mut ReqLog) -> String {
        let (mut send, mut recv) = match tokio::time::timeout(FRAME_TIMEOUT, conn.accept_bi()).await {
            Ok(Ok(s)) => s,
            _ => return "no_stream".into(),
        };

        // 1. hello
        let hello = match read_timed(&mut recv).await {
            Ok(Some(f)) if f.t() == "hello" => f,
            Ok(Some(_)) | Ok(None) => return reply_err(send, "bad_request", "expected hello").await,
            Err(e) => return reply_err(send, "bad_request", &e).await,
        };
        let version = hello.header.get("v").and_then(Value::as_u64).unwrap_or(0);
        if version != PROTO_VERSION as u64 {
            let msg = format!(
                "unsupported protocol version {version}: this broker ({}) speaks {PROTO_VERSION}; the client is {}",
                agent(),
                hello.str_field("client").unwrap_or("unknown")
            );
            return reply_err(send, "unsupported_version", msg).await;
        }
        let grant_id = hello.str_field("grant").unwrap_or("").to_owned();
        let secret = hello.str_field("secret").unwrap_or("").to_owned();
        log.grant = grant_id.chars().take(24).collect();

        let store = self.inner.grants.clone();
        let peer_owned = peer.to_owned();
        let auth = tokio::task::spawn_blocking(move || store.authenticate(&grant_id, &secret, &peer_owned, unix_now())).await;
        let grant: Grant = match auth {
            Ok(Ok(Ok(g))) => g,
            Ok(Ok(Err(_))) => return reply_err(send, "unauthorized", "unauthorized").await,
            Ok(Err(e)) => {
                warn!("grant store error: {e:#}");
                return reply_err(send, "internal", "grant store unavailable").await;
            }
            Err(_) => return reply_err(send, "internal", "grant check failed").await,
        };
        let _live = self.register(&grant.id, conn);

        // 2. welcome
        let welcome = Frame::new(json!({
            "t": "welcome", "v": PROTO_VERSION, "host": self.inner.host, "broker": agent(),
            "grant": grant.id, "expires": grant.expires, "ops": grant.ops, "vms": grant.vms,
            "features": ["jobs", "files"],
        }));
        if write_frame(&mut send, &welcome).await.is_err() {
            return "welcome_failed".into();
        }

        // 3. one request
        let req = match read_timed(&mut recv).await {
            Ok(Some(f)) => f,
            Ok(None) => return "no_request".into(),
            Err(e) => return reply_err(send, "bad_request", &e).await,
        };
        log.req = req.t().to_owned();
        if let Some(vm) = req.str_field("vm") {
            log.vm = vm.to_owned();
        }
        if let Some(job) = req.str_field("job") {
            log.job = job.to_owned();
        }
        match req.t() {
            "ping" => {
                let pong = Frame::new(json!({"t": "pong", "broker": agent(), "host": self.inner.host}));
                reply(send, pong, "ok").await
            }
            "vm" => self.vm_request(send, &grant, &req).await,
            "guest_ping" => self.guest_ping(send, &grant, &req).await,
            t if FORWARDED.contains(&t) => self.forward(conn, send, recv, &grant, req).await,
            other => reply_err(send, "bad_request", format!("unknown request `{other}`")).await,
        }
    }

    // --- vm list/status/start/stop ------------------------------------------

    async fn vm_request(&self, send: SendStream, grant: &Grant, req: &Frame) -> String {
        let op = req.str_field("op").unwrap_or("");
        let force = req.header.get("force").and_then(Value::as_bool).unwrap_or(false);
        let backend = &*self.inner.backend;
        let result: Result<Vec<VmInfo>, VmError> = async {
            match op {
                "list" => {
                    let mut out = Vec::new();
                    for name in backend.names()? {
                        if grant.allows_vm(&name) {
                            out.push(backend.info(&name).await?);
                        }
                    }
                    Ok(out)
                }
                "status" | "start" | "stop" => {
                    let name = req.str_field("vm").ok_or_else(|| VmError::new("bad_request", "missing `vm`"))?;
                    if !grant.allows_vm(name) {
                        return Err(VmError::new("forbidden", format!("this grant does not cover VM `{name}`")));
                    }
                    if op != "status" && !grant.allows_op(OP_VM) {
                        return Err(VmError::new("forbidden", format!("this grant does not allow `vm {op}`")));
                    }
                    let (state, _) = backend.probe(name).await?;
                    match op {
                        "start" => backend.start(name).await?,
                        "stop" => {
                            if state == VmState::Running {
                                if let Ok(jobs) = guest::list_jobs(&backend.vsock_path(name), "*").await {
                                    let n = guest::count_running(&jobs);
                                    if n > 0 && !force {
                                        return Err(VmError::new(
                                            "vm_busy",
                                            format!("{n} job(s) are running in VM `{name}`; stopping it would interrupt them (pass --force to stop anyway)"),
                                        ));
                                    }
                                }
                            }
                            backend.stop(name).await?
                        }
                        _ => {}
                    }
                    Ok(vec![backend.info(name).await?])
                }
                other => Err(VmError::new("bad_request", format!("unknown vm op `{other}`"))),
            }
        }
        .await;
        match result {
            Ok(vms) => reply(send, Frame::new(json!({"t": "vm_status", "vms": vms})), "ok").await,
            Err(e) => reply_err(send, e.code, e.msg).await,
        }
    }

    async fn guest_ping(&self, send: SendStream, grant: &Grant, req: &Frame) -> String {
        let Some(name) = req.str_field("vm") else {
            return reply_err(send, "bad_request", "missing `vm`").await;
        };
        if !grant.allows_vm(name) {
            return reply_err(send, "forbidden", format!("this grant does not cover VM `{name}`")).await;
        }
        let backend = &*self.inner.backend;
        match backend.probe(name).await {
            Err(e) => return reply_err(send, e.code, e.msg).await,
            // The probe just pinged the worker, so its answer is the answer.
            Ok((VmState::Running, Some(pong))) => return reply(send, Frame::with_payload(pong, Vec::new()), "ok").await,
            Ok((VmState::Running, None)) => {}
            Ok((s, _)) => return reply_err(send, "vm_not_running", format!("VM `{name}` is {}", s.as_str())).await,
        }
        match guest::ping(&backend.vsock_path(name), Duration::from_secs(10)).await {
            Ok(pong) => reply(send, Frame::with_payload(pong, Vec::new()), "ok").await,
            Err(e) => reply_err(send, "worker_unreachable", e).await,
        }
    }

    // --- job and file requests -----------------------------------------------

    async fn forward(&self, conn: &Connection, mut send: SendStream, mut recv: RecvStream, grant: &Grant, req: Frame) -> String {
        let kind = req.t().to_owned();
        let Some(name) = req.str_field("vm").map(str::to_owned) else {
            return reply_err(send, "bad_request", "missing `vm`").await;
        };
        if !grant.allows_op(OP_EXEC) {
            return reply_err(send, "forbidden", format!("this grant does not allow {kind}")).await;
        }
        if !grant.allows_vm(&name) {
            return reply_err(send, "forbidden", format!("this grant does not cover VM `{name}`")).await;
        }
        let missing = match kind.as_str() {
            "exec" => !req.header.get("argv").is_some_and(|a| a.as_array().is_some_and(|a| !a.is_empty())),
            "attach" | "cancel_job" => req.str_field("job").is_none(),
            "put" | "get" => req.str_field("path").is_none(),
            _ => false,
        };
        if missing {
            return reply_err(send, "bad_request", format!("malformed {kind} request")).await;
        }
        // Ownership is the authenticated grant, whatever the client sent; only an
        // admin grant may ask for every owner's jobs.
        let all = req.header.get("all").and_then(Value::as_bool).unwrap_or(false);
        let owner = if all && matches!(kind.as_str(), "jobs" | "cancel_job" | "attach") {
            if !grant.allows_op(OP_ADMIN) {
                return reply_err(send, "forbidden", "`all` needs a grant with op admin").await;
            }
            "*".to_owned()
        } else {
            grant.id.clone()
        };

        let mut fwd = req;
        if kind == "exec" {
            let remaining = grant.expires.saturating_sub(unix_now());
            if remaining < MIN_GRANT_LEFT_S {
                return reply_err(send, "grant_expiring", format!("this grant expires in {remaining}s; mint a new one")).await;
            }
            let asked = fwd.header.get("timeout_s").and_then(Value::as_u64).unwrap_or(DEFAULT_TIMEOUT_S);
            fwd.header.insert("timeout_s".into(), json!(asked.min(remaining)));
        }
        let start = fwd.header.get("start").and_then(Value::as_bool).unwrap_or(false);
        for k in ["vm", "start", "all"] {
            fwd.header.remove(k);
        }
        fwd.header.insert("owner".into(), json!(owner));

        let backend = &*self.inner.backend;
        let (state, pong) = match backend.probe(&name).await {
            Ok(p) => p,
            Err(e) => return reply_err(send, e.code, e.msg).await,
        };
        if state != VmState::Running {
            if !(start && grant.allows_op(OP_VM)) {
                return reply_err(send, "vm_not_running", format!("VM `{name}` is {}; start it with `azula vm start {name}`", state.as_str())).await;
            }
            if let Err(e) = backend.start(&name).await {
                return reply_err(send, e.code, e.msg).await;
            }
        }

        // The helper closes the socket at once while the worker is not up, so
        // wait for a ping rather than retrying the request itself (which could
        // otherwise run a job twice).
        // A warm worker already answered the state probe, so its request
        // connection is the only other one this needs.
        let sock = backend.vsock_path(&name);
        let warm = state == VmState::Running && pong.is_some();
        let mut connected = None;
        if warm {
            // It can still die between the probe and here. Nothing has been sent
            // yet, so fall through to waiting for it, as before.
            match UnixStream::connect(&sock).await {
                Ok(s) => connected = Some(s),
                Err(e) => debug!(target: "azula::compute", "vm={name} warm connect failed ({e}); waiting for the worker"),
            }
        }
        let mut unix = match connected {
            Some(s) => s,
            None => {
                if let Err(e) = guest::wait_ready(&sock, WORKER_WAIT).await {
                    return reply_err(send, "worker_unreachable", format!("worker in `{name}` not answering: {e}")).await;
                }
                match UnixStream::connect(&sock).await {
                    Ok(s) => s,
                    Err(e) => return reply_err(send, "worker_unreachable", format!("connect {}: {e}", sock.display())).await,
                }
            }
        };
        if write_frame(&mut unix, &fwd).await.is_err() {
            return reply_err(send, "worker_unreachable", "worker closed the connection").await;
        }

        let (mut ur, mut uw) = unix.into_split();
        // client -> guest; on client EOF half-close the guest side.
        let c2g = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut recv, &mut uw).await;
            let _ = uw.shutdown().await;
            std::future::pending::<()>().await;
        });
        // guest -> client
        let g2c = async {
            let _ = tokio::io::copy(&mut ur, &mut send).await;
            let _ = send.finish();
            // Let the client read everything; do not wait forever for a stuck peer.
            let _ = tokio::time::timeout(Duration::from_secs(10), send.stopped()).await;
        };
        let outcome = tokio::select! {
            _ = g2c => "done",
            _ = conn.closed() => "client_gone",
        };
        c2g.abort();
        drop(ur);
        outcome.into()
    }
}

async fn read_timed<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Frame>, String> {
    match tokio::time::timeout(FRAME_TIMEOUT, read_frame(r)).await {
        Ok(Ok(f)) => Ok(f),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("timed out waiting for a frame".to_owned()),
    }
}

/// Send `frame`, finish the stream, wait for the client to have it.
async fn reply(mut send: SendStream, frame: Frame, outcome: &str) -> String {
    if write_frame(&mut send, &frame).await.is_ok() {
        let _ = send.finish();
        let _ = tokio::time::timeout(Duration::from_secs(10), send.stopped()).await;
    }
    outcome.to_owned()
}

/// Reply with an error frame; the outcome is the error code.
async fn reply_err(send: SendStream, code: &str, msg: impl Into<String>) -> String {
    reply(send, err_frame(code, msg), code).await
}
