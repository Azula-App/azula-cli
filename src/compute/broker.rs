//! The compute broker (`vm/BROKER.md` §5): accepts iroh connections on
//! [`super::ALPN`], authenticates the grant, authorizes one request and either
//! answers it or splices bytes between the client and the VM's worker.
//!
//! The broker executes nothing on the host. For `exec` it opens the VM's
//! `vsock.sock`, forwards the request, and copies bytes both ways without
//! parsing job output; a client disconnect closes the guest side, which the
//! worker treats as cancel.

use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{Connection, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWriteExt};
use tokio::net::UnixStream;
use tracing::{info, warn};

use super::frame::{read_frame, write_frame, Frame};
use super::grants::{unix_now, Grant, GrantStore, OP_EXEC, OP_VM};
use super::vm::{VmBackend, VmError, VmInfo, VmState};
use super::{agent, guest, short_id, PROTO_VERSION};

/// How long a client gets to send `hello` and then its request.
const FRAME_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the broker waits for a freshly started VM's worker before exec.
const WORKER_WAIT: Duration = Duration::from_secs(30);

/// The broker: a grant store, a VM backend and the host's name.
pub struct Broker<B: VmBackend> {
    inner: Arc<Inner<B>>,
}

struct Inner<B> {
    backend: Arc<B>,
    grants: GrantStore,
    host: String,
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

/// What one request logged: filled in as the request progresses.
struct ReqLog {
    grant: String,
    req: String,
    vm: String,
}

fn err_frame(code: &str, msg: impl Into<String>) -> Frame {
    Frame::new(json!({"t": "error", "code": code, "msg": msg.into()}))
}

impl<B: VmBackend> Broker<B> {
    pub fn new(backend: Arc<B>, grants: GrantStore, host: String) -> Self {
        Self { inner: Arc::new(Inner { backend, grants, host }) }
    }

    /// Serve one connection to completion and log one line for it.
    pub async fn handle_connection(&self, conn: Connection) {
        let peer = short_id(&conn.remote_id().to_string());
        let mut log = ReqLog { grant: "-".into(), req: "?".into(), vm: "-".into() };
        let outcome = self.serve(&conn, &peer, &mut log).await;
        // Never the secret: only the (non-secret) grant id.
        info!(target: "azula::compute", "grant={} peer={peer} req={} vm={} outcome={outcome}", log.grant, log.req, log.vm);
        conn.close(0u32.into(), b"done");
    }

    async fn serve(&self, conn: &Connection, peer: &str, log: &mut ReqLog) -> String {
        let (mut send, mut recv) = match tokio::time::timeout(FRAME_TIMEOUT, conn.accept_bi()).await {
            Ok(Ok(s)) => s,
            _ => return "no_stream".into(),
        };

        // 1. hello
        let hello = match read_timed(&mut recv).await {
            Ok(Some(f)) if f.t() == "hello" => f,
            Ok(Some(_)) | Ok(None) => return reply_err(conn, send, "bad_request", "expected hello").await,
            Err(e) => return reply_err(conn, send, "bad_request", &e).await,
        };
        let version = hello.header.get("v").and_then(Value::as_u64).unwrap_or(0);
        if version != PROTO_VERSION as u64 {
            return reply_err(conn, send, "unsupported_version", format!("broker speaks protocol {PROTO_VERSION}")).await;
        }
        let grant_id = hello.str_field("grant").unwrap_or("").to_owned();
        let secret = hello.str_field("secret").unwrap_or("").to_owned();
        log.grant = grant_id.chars().take(24).collect();

        let store = self.inner.grants.clone();
        let peer_owned = peer.to_owned();
        let auth = tokio::task::spawn_blocking(move || store.authenticate(&grant_id, &secret, &peer_owned, unix_now())).await;
        let grant: Grant = match auth {
            Ok(Ok(Ok(g))) => g,
            Ok(Ok(Err(_))) => return reply_err(conn, send, "unauthorized", "unauthorized").await,
            Ok(Err(e)) => {
                warn!("grant store error: {e:#}");
                return reply_err(conn, send, "internal", "grant store unavailable").await;
            }
            Err(_) => return reply_err(conn, send, "internal", "grant check failed").await,
        };

        // 2. welcome
        let welcome = Frame::new(json!({
            "t": "welcome", "v": PROTO_VERSION, "host": self.inner.host, "broker": agent(),
            "grant": grant.id, "expires": grant.expires, "ops": grant.ops, "vms": grant.vms,
        }));
        if write_frame(&mut send, &welcome).await.is_err() {
            return "welcome_failed".into();
        }

        // 3. one request
        let req = match read_timed(&mut recv).await {
            Ok(Some(f)) => f,
            Ok(None) => return "no_request".into(),
            Err(e) => return reply_err(conn, send, "bad_request", &e).await,
        };
        log.req = req.t().to_owned();
        if let Some(vm) = req.str_field("vm") {
            log.vm = vm.to_owned();
        }
        match req.t() {
            "ping" => {
                let pong = Frame::new(json!({"t": "pong", "broker": agent(), "host": self.inner.host}));
                reply(conn, send, pong, "ok").await
            }
            "vm" => self.vm_request(conn, send, &grant, &req).await,
            "guest_ping" => self.guest_ping(conn, send, &grant, &req).await,
            "exec" => self.exec(conn, send, recv, &grant, req).await,
            other => reply_err(conn, send, "bad_request", format!("unknown request `{other}`")).await,
        }
    }

    // --- vm list/status/start/stop ---------------------------------------

    async fn vm_request(&self, conn: &Connection, send: SendStream, grant: &Grant, req: &Frame) -> String {
        let op = req.str_field("op").unwrap_or("");
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
                    backend.state(name)?;
                    match op {
                        "start" => backend.start(name).await?,
                        "stop" => backend.stop(name).await?,
                        _ => {}
                    }
                    Ok(vec![backend.info(name).await?])
                }
                other => Err(VmError::new("bad_request", format!("unknown vm op `{other}`"))),
            }
        }
        .await;
        match result {
            Ok(vms) => reply(conn, send, Frame::new(json!({"t": "vm_status", "vms": vms})), "ok").await,
            Err(e) => reply_err(conn, send, e.code, e.msg).await,
        }
    }

    async fn guest_ping(&self, conn: &Connection, send: SendStream, grant: &Grant, req: &Frame) -> String {
        let Some(name) = req.str_field("vm") else {
            return reply_err(conn, send, "bad_request", "missing `vm`").await;
        };
        if !grant.allows_vm(name) {
            return reply_err(conn, send, "forbidden", format!("this grant does not cover VM `{name}`")).await;
        }
        let backend = &*self.inner.backend;
        match backend.state(name) {
            Err(e) => return reply_err(conn, send, e.code, e.msg).await,
            Ok(VmState::Running) => {}
            Ok(s) => return reply_err(conn, send, "vm_not_running", format!("VM `{name}` is {}", s.as_str())).await,
        }
        match guest::ping(&backend.vsock_path(name), Duration::from_secs(10)).await {
            Ok(pong) => reply(conn, send, Frame::with_payload(pong, Vec::new()), "ok").await,
            Err(e) => reply_err(conn, send, "worker_unreachable", e).await,
        }
    }

    // --- exec ------------------------------------------------------------

    async fn exec(&self, conn: &Connection, mut send: SendStream, mut recv: iroh::endpoint::RecvStream, grant: &Grant, req: Frame) -> String {
        let Some(name) = req.str_field("vm").map(str::to_owned) else {
            return reply_err(conn, send, "bad_request", "missing `vm`").await;
        };
        if !grant.allows_op(OP_EXEC) {
            return reply_err(conn, send, "forbidden", "this grant does not allow exec").await;
        }
        if !grant.allows_vm(&name) {
            return reply_err(conn, send, "forbidden", format!("this grant does not cover VM `{name}`")).await;
        }
        if !req.header.get("argv").is_some_and(|a| a.as_array().is_some_and(|a| !a.is_empty())) {
            return reply_err(conn, send, "bad_request", "`argv` must be a non-empty array").await;
        }
        let backend = &*self.inner.backend;
        let state = match backend.state(&name) {
            Ok(s) => s,
            Err(e) => return reply_err(conn, send, e.code, e.msg).await,
        };
        if state != VmState::Running {
            let may_start = req.header.get("start").and_then(Value::as_bool).unwrap_or(false) && grant.allows_op(OP_VM);
            if !may_start {
                return reply_err(conn, send, "vm_not_running", format!("VM `{name}` is {}; start it with `azula vm start {name}` or pass start", state.as_str())).await;
            }
            if let Err(e) = backend.start(&name).await {
                return reply_err(conn, send, e.code, e.msg).await;
            }
        }

        // The helper closes the socket at once while the worker is not up, so
        // wait for a ping rather than retrying the exec itself (which could
        // otherwise run a job twice).
        let sock = backend.vsock_path(&name);
        if let Err(e) = guest::wait_ready(&sock, WORKER_WAIT).await {
            return reply_err(conn, send, "worker_unreachable", format!("worker in `{name}` not answering: {e}")).await;
        }
        let mut unix = match UnixStream::connect(&sock).await {
            Ok(s) => s,
            Err(e) => return reply_err(conn, send, "worker_unreachable", format!("connect {}: {e}", sock.display())).await,
        };

        // Forward the exec frame minus the broker-only fields.
        let mut fwd = req;
        fwd.header.remove("vm");
        fwd.header.remove("start");
        if write_frame(&mut unix, &fwd).await.is_err() {
            return reply_err(conn, send, "worker_unreachable", "worker closed the connection").await;
        }

        let (mut ur, mut uw) = unix.into_split();
        // client -> guest; on client EOF half-close the guest side. Spawned so
        // it keeps running while we wait on the other direction.
        let c2g = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut recv, &mut uw).await;
            let _ = uw.shutdown().await;
            // Keep `uw` open-but-shut until the task is aborted/dropped.
            std::future::pending::<()>().await;
        });
        // guest -> client
        let g2c = async {
            let _ = tokio::io::copy(&mut ur, &mut send).await;
            let _ = send.finish();
            // Let the client read everything (it closes the connection after
            // `exit`); do not wait forever for a stuck peer.
            let _ = tokio::time::timeout(Duration::from_secs(10), send.stopped()).await;
        };
        let outcome = tokio::select! {
            _ = g2c => "done",
            _ = conn.closed() => "client_gone",
        };
        c2g.abort();
        // Dropping `ur` (and the aborted task's `uw`) closes the guest socket.
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
async fn reply(conn: &Connection, mut send: SendStream, frame: Frame, outcome: &str) -> String {
    if write_frame(&mut send, &frame).await.is_ok() {
        let _ = send.finish();
        let _ = tokio::time::timeout(Duration::from_secs(10), send.stopped()).await;
    }
    let _ = conn;
    outcome.to_owned()
}

/// Reply with an error frame; the outcome is the error code.
async fn reply_err(conn: &Connection, send: SendStream, code: &str, msg: impl Into<String>) -> String {
    reply(conn, send, err_frame(code, msg), code).await
}
