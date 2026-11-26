//! The cross-platform client of the compute broker (`vm/BROKER.md` §5 and
//! §7): connecting, durable job streaming with reconnect (`exec`, `attach`,
//! `logs`), `jobs`, `cancel`, `vm` operations and `doctor`. File transfer is in
//! [`super::transfer`].
//!
//! Everything takes an already-bound iroh [`Endpoint`] and an
//! [`EndpointAddr`] (bundled in a [`Dialer`]), so tests can dial a broker over
//! local addresses; the CLI layer builds both from a token.

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, SecretKey};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::mpsc;

use super::frame::{read_frame, write_frame, Frame};
use super::grants::{parse_duration, Token};
use super::{agent, ALPN, PROTO_VERSION, QUIC_TIMEOUTS};
use crate::endpoint::{bind_with_options, redact_credentials, relay_unreachable, EndpointOptions};

pub const DIAL_TIMEOUT: Duration = Duration::from_secs(20);
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
pub const RELAY_TIMEOUT: Duration = Duration::from_secs(20);
pub const GUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// A start can take up to 180 s on the broker.
pub const VM_OP_TIMEOUT: Duration = Duration::from_secs(200);

/// Exit codes (`vm/BROKER.md` §7).
pub mod exit {
    pub const TIMEOUT: i32 = 124;
    pub const BROKER_ERROR: i32 = 125;
    pub const CWD_MISSING: i32 = 126;
    pub const SPAWN_FAILED: i32 = 127;
    pub const CANCELLED: i32 = 130;
    pub const TRANSPORT: i32 = 255;
}

// --- outcomes and events -------------------------------------------------------

/// How a job stream ended, from the client's point of view.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// The job finished (the worker's `exit` frame).
    Exit { code: Option<i64>, signal: Option<i64>, reason: String },
    /// An `error` frame from the broker or the worker.
    Error { code: String, msg: String },
    /// The connection failed and reconnecting is disabled.
    Transport(String),
    /// Interrupted twice before the job started: nothing to detach from.
    Interrupted,
    /// The client left the job running: `--detach`, or a second Ctrl-C.
    Detached { job: String, by_interrupt: bool },
    /// The reconnect window ran out.
    GaveUp { job: Option<String> },
    /// A non-following replay reached the end of what is retained while the
    /// job is still running.
    End,
}

impl Outcome {
    /// The process exit code for this outcome.
    pub fn exit_code(&self) -> i32 {
        match self {
            Outcome::Exit { reason, .. } if reason == "timeout" => exit::TIMEOUT,
            Outcome::Exit { reason, .. } if reason == "cancelled" => exit::CANCELLED,
            Outcome::Exit { reason, .. } if matches!(reason.as_str(), "interrupted" | "stdin_lost" | "orphaned") => exit::TRANSPORT,
            Outcome::Exit { code: Some(c), .. } => (*c).clamp(0, 255) as i32,
            Outcome::Exit { code: None, signal: Some(s), .. } => 128 + (*s).clamp(0, 127) as i32,
            Outcome::Exit { .. } => exit::TRANSPORT,
            Outcome::Error { code, .. } => match code.as_str() {
                "spawn_failed" => exit::SPAWN_FAILED,
                "cwd_missing" => exit::CWD_MISSING,
                _ => exit::BROKER_ERROR,
            },
            Outcome::Transport(_) | Outcome::GaveUp { .. } => exit::TRANSPORT,
            Outcome::Interrupted => exit::CANCELLED,
            Outcome::Detached { by_interrupt: false, .. } | Outcome::End => 0,
            Outcome::Detached { by_interrupt: true, .. } => exit::CANCELLED,
        }
    }

    /// The `azula: …` message for outcomes that deserve one (without the prefix).
    pub fn message(&self, timeout_s: Option<u64>) -> Option<String> {
        match self {
            Outcome::Exit { reason, .. } => match reason.as_str() {
                "timeout" => Some(format!("job timed out{}", timeout_s.map(|t| format!(" after {t}s")).unwrap_or_default())),
                "cancelled" => Some("job cancelled".into()),
                "interrupted" => Some("job was interrupted: the VM or its worker stopped while it ran".into()),
                "stdin_lost" => Some("job was cancelled: the connection dropped before all of its stdin was delivered".into()),
                "orphaned" => Some("job was cancelled: no client was attached to it for 60 s".into()),
                _ => None,
            },
            Outcome::Error { code, msg } => Some(format!("{code}: {msg}")),
            Outcome::Transport(m) => Some(m.clone()),
            Outcome::Interrupted => Some("interrupted".into()),
            Outcome::Detached { job, by_interrupt: true } => Some(format!("detached; {job} is still running — reattach with: azula compute attach {job}")),
            Outcome::GaveUp { job: Some(job) } => {
                Some(format!("lost the connection; {job} is still running on the host — reattach with: azula compute attach {job}"))
            }
            Outcome::GaveUp { job: None } => Some("lost the connection before the job started, and could not reconnect".into()),
            _ => None,
        }
    }
}

/// A streamed job event, in the shape of the `--json` JSONL output.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// `job` is the full ref (`vm/j_…`).
    Started { job: String, pid: Option<u64>, deduped: bool },
    Stdout { off: u64, data: Vec<u8> },
    Stderr { off: u64, data: Vec<u8> },
    /// Output before `to` was dropped by the host's retention limit.
    Gap { stream: String, from: u64, to: u64 },
    /// The connection dropped; `attempt` counts tries in this outage.
    Reconnecting { attempt: u32, job: Option<String> },
    Exit { code: Option<i64>, signal: Option<i64>, reason: String },
    Error { code: String, msg: String },
}

impl Event {
    pub fn to_json(&self) -> Value {
        match self {
            Event::Started { job, pid, deduped } => json!({"type": "started", "job": job, "pid": pid, "deduped": deduped}),
            Event::Stdout { off, data } => json!({"type": "stdout", "off": off, "data_b64": STANDARD.encode(data)}),
            Event::Stderr { off, data } => json!({"type": "stderr", "off": off, "data_b64": STANDARD.encode(data)}),
            Event::Gap { stream, from, to } => json!({"type": "gap", "stream": stream, "from": from, "to": to}),
            Event::Reconnecting { attempt, .. } => json!({"type": "reconnecting", "attempt": attempt}),
            Event::Exit { code, signal, reason } => json!({"type": "exit", "code": code, "signal": signal, "reason": reason}),
            Event::Error { code, msg } => json!({"type": "error", "code": code, "msg": msg}),
        }
    }
}

/// Why a connection could not be made or a request failed outright.
#[derive(Debug, Clone, PartialEq)]
pub enum Failure {
    /// An `error` frame from the broker (`unauthorized`, `forbidden`, …).
    Broker { code: String, msg: String },
    /// Dial, TLS, stream or framing failure.
    Transport(String),
}

impl Failure {
    pub fn exit_code(&self) -> i32 {
        match self {
            Failure::Broker { .. } => exit::BROKER_ERROR,
            Failure::Transport(_) => exit::TRANSPORT,
        }
    }

    pub fn message(&self) -> String {
        match self {
            Failure::Broker { code, msg } => format!("{code}: {msg}"),
            Failure::Transport(m) => m.clone(),
        }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for Failure {}

pub(crate) fn transport(e: impl std::fmt::Display) -> Failure {
    Failure::Transport(redact_credentials(&e.to_string()))
}

fn error_failure(f: &Frame) -> Failure {
    Failure::Broker { code: f.str_field("code").unwrap_or("internal").to_owned(), msg: f.str_field("msg").unwrap_or("").to_owned() }
}

// --- connecting ------------------------------------------------------------------

/// An authenticated connection: `hello` answered by `welcome`, ready for one request.
pub struct Session {
    pub conn: Connection,
    pub send: SendStream,
    pub recv: RecvStream,
    pub welcome: Frame,
}

impl Session {
    /// The grant's VM scope from `welcome`.
    pub fn grant_vms(&self) -> Vec<String> {
        self.welcome.header.get("vms").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect()).unwrap_or_default()
    }

    pub fn host(&self) -> String {
        self.welcome.str_field("host").unwrap_or("").to_owned()
    }

    /// The VM to use: `explicit`, else the grant's single plain VM, else `default`.
    pub fn resolve_vm(&self, explicit: Option<&str>) -> String {
        match explicit.filter(|v| !v.is_empty()) {
            Some(v) => v.to_owned(),
            None => super::vm::default_vm_for(&self.grant_vms()),
        }
    }
}

/// Client-side fault injection (`AZULA_COMPUTE_FAULT=drop-after:N`): abruptly
/// drop the connection once, after N bytes of job output or transfer payload,
/// then follow the normal reconnect path. Used to prove reconnect for real.
#[derive(Debug)]
pub struct Fault {
    drop_after: u64,
    fired: AtomicBool,
    progress: AtomicU64,
}

impl Fault {
    pub fn drop_after(n: u64) -> Arc<Self> {
        Arc::new(Fault { drop_after: n, fired: AtomicBool::new(false), progress: AtomicU64::new(0) })
    }

    /// Parse `drop-after:<N>`.
    pub fn parse(spec: &str) -> Option<Arc<Self>> {
        spec.trim().strip_prefix("drop-after:")?.trim().parse::<u64>().ok().map(Self::drop_after)
    }

    /// From `AZULA_COMPUTE_FAULT`.
    pub fn from_env() -> Option<Arc<Self>> {
        std::env::var("AZULA_COMPUTE_FAULT").ok().and_then(|v| Self::parse(&v))
    }

    /// Account for `n` more payload bytes; true exactly once, when the threshold is crossed.
    pub fn bytes(&self, n: u64) -> bool {
        let total = self.progress.fetch_add(n, Ordering::SeqCst) + n;
        total >= self.drop_after && !self.fired.swap(true, Ordering::SeqCst)
    }
}

/// Reconnect timing (`--reconnect`, backoff 1 s doubling to 15 s).
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    pub window: Duration,
    pub initial: Duration,
    pub max: Duration,
}

impl Default for Policy {
    fn default() -> Self {
        Policy { window: Duration::from_secs(300), initial: Duration::from_secs(1), max: Duration::from_secs(15) }
    }
}

impl Policy {
    pub fn with_window(window: Duration) -> Self {
        Policy { window, ..Policy::default() }
    }

    fn backoff(&self, attempt: u32) -> Duration {
        self.initial.saturating_mul(1u32 << attempt.saturating_sub(1).min(10)).min(self.max)
    }
}

/// Everything needed to open sessions to one host.
#[derive(Clone)]
pub struct Dialer {
    pub ep: Endpoint,
    pub addr: EndpointAddr,
    pub token: Token,
    pub fault: Option<Arc<Fault>>,
    /// Set by [`Dialer::with_unwaited_relay`]: the relay, until a session has been opened.
    unwaited: Option<(iroh::RelayUrl, Arc<AtomicBool>)>,
}

impl Dialer {
    pub fn new(ep: Endpoint, addr: EndpointAddr, token: Token) -> Self {
        Dialer { ep, addr, token, fault: None, unwaited: None }
    }

    /// For an endpoint from [`bind_client_unwaited`]: sessions dial while it
    /// registers with `relay`, and say so if it can't.
    pub fn with_unwaited_relay(mut self, relay: iroh::RelayUrl) -> Self {
        self.unwaited = Some((relay, Arc::new(AtomicBool::new(true))));
        self
    }

    pub fn with_fault(mut self, fault: Option<Arc<Fault>>) -> Self {
        self.fault = fault;
        self
    }

    pub async fn session(&self) -> Result<Session, Failure> {
        let Some((relay, waiting)) = self.unwaited.as_ref().filter(|(_, w)| w.load(Ordering::Relaxed)) else {
            return connect(&self.ep, self.addr.clone(), &self.token).await;
        };
        let conn = dial_unwaited(&self.ep, self.addr.clone(), relay, RELAY_TIMEOUT, DIAL_TIMEOUT).await?;
        waiting.store(false, Ordering::Relaxed);
        authenticate(conn, &self.token, AUTH_TIMEOUT).await
    }
}

/// Bind the client's own (ephemeral-identity) endpoint with a relay deadline.
/// `relay` homes it on that relay only (the token's, so both directions of a
/// connection meet on the host's relay); `None` keeps n0's default map.
pub async fn bind_client(online_timeout: Duration, relay: Option<iroh::RelayUrl>) -> anyhow::Result<Endpoint> {
    let mut opts = EndpointOptions::new(SecretKey::generate());
    opts.online_timeout = Some(online_timeout);
    opts.relay_url = relay;
    opts.quic_timeouts = Some(QUIC_TIMEOUTS);
    bind_with_options(opts).await
}

/// [`bind_client`] homed on `relay` without waiting for it: the first dial can
/// use the time the registration takes (about a second over n0's relays).
/// Use the endpoint with [`Dialer::with_unwaited_relay`].
pub async fn bind_client_unwaited(relay: iroh::RelayUrl) -> anyhow::Result<Endpoint> {
    let mut opts = EndpointOptions::new(SecretKey::generate());
    opts.wait_online = false;
    opts.relay_url = Some(relay);
    opts.quic_timeouts = Some(QUIC_TIMEOUTS);
    bind_with_options(opts).await
}

/// The relay named by a token, if it parses.
pub fn token_relay(token: &Token) -> Option<iroh::RelayUrl> {
    token.relay.parse().ok().filter(|_| !token.relay.is_empty())
}

/// Dial `addr` on [`ALPN`] within `dial` (a stage deadline of its own).
pub async fn dial(ep: &Endpoint, addr: EndpointAddr, dial: Duration) -> Result<Connection, Failure> {
    match tokio::time::timeout(dial, ep.connect(addr, ALPN)).await {
        Ok(Ok(c)) => Ok(c),
        Ok(Err(e)) => Err(transport(format!("could not connect to the host: {e:#}"))),
        Err(_) => Err(transport(format!("timed out after {}s connecting to the host", dial.as_secs()))),
    }
}

/// Dial `addr` while the endpoint is still reaching `relay`. Whoever is first
/// decides: a direct path needs no relay at all, and once the relay is there the
/// dial gets `dial_wait` of its own. No relay within `relay_wait` is the error a
/// waiting bind gives, and so is a dial that failed without one.
pub(super) async fn dial_unwaited(ep: &Endpoint, addr: EndpointAddr, relay: &iroh::RelayUrl, relay_wait: Duration, dial_wait: Duration) -> Result<Connection, Failure> {
    let opts = || {
        let mut o = EndpointOptions::new(SecretKey::generate());
        o.relay_url = Some(relay.clone());
        o
    };
    let failed = |e: String| transport(format!("could not connect to the host: {e}"));
    let dialing = ep.connect(addr, ALPN);
    tokio::pin!(dialing);
    tokio::select! {
        biased;
        r = &mut dialing => match r {
            Ok(c) => return Ok(c),
            Err(e) => {
                // Too soon to blame the host unless the relay is there.
                return match tokio::time::timeout(RELAY_GRACE, ep.online()).await {
                    Ok(()) => Err(failed(format!("{e:#}"))),
                    Err(_) => Err(transport(format!("{} (dial: {e:#})", relay_unreachable(ep, &opts(), relay_wait)))),
                };
            }
        },
        online = tokio::time::timeout(relay_wait, ep.online()) => {
            if online.is_err() {
                return Err(transport(relay_unreachable(ep, &opts(), relay_wait)));
            }
        }
    }
    match tokio::time::timeout(dial_wait, dialing).await {
        Ok(Ok(c)) => Ok(c),
        Ok(Err(e)) => Err(failed(format!("{e:#}"))),
        Err(_) => Err(transport(format!("timed out after {}s connecting to the host", dial_wait.as_secs()))),
    }
}

/// How long a failed dial waits to learn whether the relay was the problem.
const RELAY_GRACE: Duration = Duration::from_millis(500);

/// Send `hello` on a fresh bi-stream of `conn` and wait for `welcome`.
pub async fn authenticate(conn: Connection, token: &Token, auth: Duration) -> Result<Session, Failure> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(transport)?;
    let hello = Frame::new(json!({
        "t": "hello", "v": PROTO_VERSION, "grant": token.grant, "secret": token.secret, "client": agent(),
    }));
    write_frame(&mut send, &hello).await.map_err(transport)?;
    let welcome = match tokio::time::timeout(auth, read_frame(&mut recv)).await {
        Err(_) => return Err(transport(format!("no answer from the broker within {}s", auth.as_secs()))),
        Ok(Err(e)) => return Err(transport(e)),
        Ok(Ok(None)) => return Err(transport("the broker closed the connection")),
        Ok(Ok(Some(f))) => f,
    };
    match welcome.t() {
        "welcome" => Ok(Session { conn, send, recv, welcome }),
        "error" => Err(error_failure(&welcome)),
        other => Err(transport(format!("unexpected `{other}` frame from the broker"))),
    }
}

/// `dial` + `authenticate`.
pub async fn connect(ep: &Endpoint, addr: EndpointAddr, token: &Token) -> Result<Session, Failure> {
    let conn = dial(ep, addr, DIAL_TIMEOUT).await?;
    authenticate(conn, token, AUTH_TIMEOUT).await
}

/// Send one request and read exactly one reply frame (`error` → `Failure`).
pub async fn request_reply(mut s: Session, req: &Frame, wait: Duration) -> Result<Frame, Failure> {
    write_frame(&mut s.send, req).await.map_err(transport)?;
    let reply = match tokio::time::timeout(wait, read_frame(&mut s.recv)).await {
        Err(_) => return Err(transport(format!("no answer from the broker within {}s", wait.as_secs()))),
        Ok(Err(e)) => return Err(transport(e)),
        Ok(Ok(None)) => return Err(transport("the broker closed the connection")),
        Ok(Ok(Some(f))) => f,
    };
    s.conn.close(0u32.into(), b"done");
    if reply.t() == "error" {
        return Err(error_failure(&reply));
    }
    Ok(reply)
}

/// `vm list|status|start|stop` through the broker. `name` of `None` uses the
/// default-VM rule for `status`/`start`/`stop`.
pub async fn vm_op(session: Session, op: &str, name: Option<&str>, force: bool) -> Result<Vec<Value>, Failure> {
    let mut req = json!({"t": "vm", "op": op, "force": force});
    if op != "list" {
        req["vm"] = json!(session.resolve_vm(name));
    }
    let reply = request_reply(session, &Frame::new(req), VM_OP_TIMEOUT).await?;
    Ok(reply.header.get("vms").and_then(Value::as_array).cloned().unwrap_or_default())
}

// --- job refs ---------------------------------------------------------------------

/// A job named `<vm>/<id>`, or a bare id (the VM then comes from `--vm`).
#[derive(Debug, Clone, PartialEq)]
pub struct JobRef {
    pub vm: Option<String>,
    pub id: String,
}

impl JobRef {
    pub fn parse(text: &str) -> Result<JobRef, String> {
        let t = text.trim();
        let (vm, id) = match t.split_once('/') {
            Some((vm, id)) => (Some(vm.to_owned()), id),
            None => (None, t),
        };
        if !id.starts_with("j_") || id.len() < 3 || !id[2..].bytes().all(|b| b.is_ascii_hexdigit()) || vm.as_deref() == Some("") {
            return Err(format!("`{text}` is not a job: expected `<vm>/j_<hex>` or a bare `j_<hex>` with --vm"));
        }
        Ok(JobRef { vm, id: id.to_owned() })
    }

    pub fn display(vm: &str, id: &str) -> String {
        format!("{vm}/{id}")
    }
}

// --- jobs / cancel ----------------------------------------------------------------

/// `jobs`: this grant's jobs on `vm` (`all`: every owner, admin grants only).
pub async fn list_jobs(session: Session, vm: Option<&str>, all: bool) -> Result<(String, Vec<Value>), Failure> {
    let vm = session.resolve_vm(vm);
    let req = Frame::new(json!({"t": "jobs", "vm": vm, "start": false, "all": all}));
    let reply = request_reply(session, &req, GUEST_TIMEOUT).await?;
    Ok((vm, reply.header.get("jobs").and_then(Value::as_array).cloned().unwrap_or_default()))
}

/// How a `job_list` entry reads in `jobs`: the state word (`running`,
/// `exited`, or the reason when it differs: `timeout`, `cancelled`,
/// `interrupted`, …) and the exit code the client would exit with (`-` while
/// running or when there is none).
pub fn job_status(j: &Value) -> (String, String) {
    let state = j["state"].as_str().unwrap_or("?");
    let reason = j["reason"].as_str().unwrap_or("");
    if state == "running" {
        return ("running".into(), "-".into());
    }
    let word = if reason.is_empty() || reason == "exited" || reason == state { state.to_owned() } else { reason.to_owned() };
    let (code, signal) = (j["code"].as_i64(), j["signal"].as_i64());
    let eff_reason = if reason.is_empty() { state } else { reason };
    let code_text = match (code, signal, eff_reason) {
        (None, None, "exited") => "-".to_owned(),
        _ => Outcome::Exit { code, signal, reason: eff_reason.to_owned() }.exit_code().to_string(),
    };
    (word, code_text)
}

/// `cancel`: ask the worker to cancel a job. Returns the job's state afterwards.
pub async fn cancel_job(session: Session, r: &JobRef, all: bool) -> Result<String, Failure> {
    let vm = session.resolve_vm(r.vm.as_deref());
    let req = Frame::new(json!({"t": "cancel_job", "vm": vm, "start": false, "job": r.id, "all": all}));
    let reply = request_reply(session, &req, GUEST_TIMEOUT).await?;
    Ok(reply.str_field("state").unwrap_or("?").to_owned())
}

// --- exec / attach engine -----------------------------------------------------------

/// What to run.
#[derive(Debug, Clone, Default)]
pub struct ExecRequest {
    /// `None` applies the default-VM rule against the grant's scope.
    pub vm: Option<String>,
    pub no_start: bool,
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    pub env: Vec<(String, String)>,
    pub stdin: bool,
    pub timeout_s: Option<u64>,
    pub label: Option<String>,
    /// Leave the job running and return as soon as it has started.
    pub detach: bool,
    pub cancel_on_disconnect: bool,
    /// Idempotency key; generated when `None`.
    pub idem: Option<String>,
}

/// Replay (and maybe follow) an existing job's output.
#[derive(Debug, Clone, Default)]
pub struct AttachRequest {
    pub vm: Option<String>,
    pub job: String,
    pub stdout_off: u64,
    pub stderr_off: u64,
    pub follow: bool,
}

/// What a job stream starts with.
#[derive(Debug, Clone)]
pub enum Start {
    Exec(ExecRequest),
    Attach(AttachRequest),
}

/// Parse `K=V` (first `=` splits; the key must be non-empty).
pub fn parse_env(kv: &str) -> Result<(String, String), String> {
    match kv.split_once('=') {
        Some((k, v)) if !k.is_empty() => Ok((k.to_owned(), v.to_owned())),
        _ => Err(format!("invalid --env `{kv}`: expected KEY=VALUE")),
    }
}

/// Parse `--timeout` (`90s`, `15m`, `2h`): 1 second to 24 hours.
pub fn parse_timeout(text: &str) -> Result<u64, String> {
    let d = parse_duration(text).map_err(|e| e.to_string())?;
    if d > Duration::from_secs(86_400) {
        return Err("--timeout may be at most 24h".to_owned());
    }
    Ok(d.as_secs())
}

/// Parse `--reconnect` (`5m`, `30s`, or `0` to disable).
pub fn parse_reconnect(text: &str) -> Result<Duration, String> {
    if text.trim() == "0" {
        return Ok(Duration::ZERO);
    }
    parse_duration(text).map_err(|e| e.to_string())
}

impl ExecRequest {
    fn to_frame(&self, vm: &str, idem: &str) -> Frame {
        let mut h = json!({
            "t": "exec", "vm": vm, "start": !self.no_start, "idem": idem, "argv": self.argv,
            "stdin": self.stdin, "attach": !self.detach, "cancel_on_disconnect": self.cancel_on_disconnect,
        });
        if let Some(c) = &self.cwd {
            h["cwd"] = json!(c);
        }
        if let Some(l) = &self.label {
            h["label"] = json!(l);
        }
        if !self.env.is_empty() {
            h["env"] = Value::Object(self.env.iter().map(|(k, v)| (k.clone(), json!(v))).collect());
        }
        if let Some(t) = self.timeout_s {
            h["timeout_s"] = json!(t);
        }
        Frame::new(h)
    }
}

/// Per-run state that survives reconnects.
struct Progress {
    vm: Option<String>,
    job: Option<String>,
    out_off: u64,
    err_off: u64,
    cancel_pending: bool,
    idem: String,
}

impl Progress {
    fn job_ref(&self) -> Option<String> {
        Some(JobRef::display(self.vm.as_deref()?, self.job.as_deref()?))
    }
}

enum ConnEnd {
    Done(Outcome),
    /// The stream broke; `progressed` is true if this connection delivered anything.
    Dropped { why: String, progressed: bool },
}

/// Run a job stream with reconnect: `exec` (resending with the same idem key
/// until `started`, then attaching with the offsets already written) or
/// `attach`. Returns the outcome and the job ref once known.
///
/// * `stdin` is forwarded (then `stdin_eof`) when the request has `stdin`.
/// * Each message on `interrupts` is a local SIGINT: the first sends `cancel`
///   (the job still reports its `exit`), the second detaches.
pub async fn run_job(
    dialer: &Dialer,
    start: Start,
    mut stdin: Option<Box<dyn AsyncRead + Unpin + Send>>,
    mut interrupts: mpsc::Receiver<()>,
    policy: Policy,
    on_event: &mut dyn FnMut(&Event),
) -> (Outcome, Option<String>) {
    let mut st = Progress { vm: None, job: None, out_off: 0, err_off: 0, cancel_pending: false, idem: uuid::Uuid::new_v4().to_string() };
    let mut follow = true;
    let (want_stdin, explicit_vm, exec_req) = match &start {
        Start::Exec(r) => {
            if let Some(i) = &r.idem {
                st.idem = i.clone();
            }
            (r.stdin, r.vm.clone(), Some(r.clone()))
        }
        Start::Attach(a) => {
            st.job = Some(a.job.clone());
            st.out_off = a.stdout_off;
            st.err_off = a.stderr_off;
            follow = a.follow;
            (false, a.vm.clone(), None)
        }
    };
    let mut outage_since: Option<Instant> = None;
    let mut attempt = 0u32;

    loop {
        let session = match dialer.session().await {
            Ok(s) => s,
            Err(Failure::Broker { code, msg }) => {
                on_event(&Event::Error { code: code.clone(), msg: msg.clone() });
                return (Outcome::Error { code, msg }, st.job_ref());
            }
            Err(Failure::Transport(m)) => match retry_gate(&policy, &mut outage_since, &mut attempt, &st, on_event, &mut interrupts, &m).await {
                Some(done) => return (done, st.job_ref()),
                None => continue,
            },
        };
        if st.vm.is_none() {
            st.vm = Some(session.resolve_vm(explicit_vm.as_deref()));
        }
        let end = run_connection(dialer, session, &mut st, exec_req.as_ref(), follow, &mut stdin, &mut interrupts, on_event).await;
        match end {
            ConnEnd::Done(o) => return (o, st.job_ref()),
            ConnEnd::Dropped { why, progressed } => {
                if progressed {
                    outage_since = None;
                    attempt = 0;
                }
                // Stdin that was being streamed cannot be resent, and the worker
                // cancels such a job (`stdin_lost`): report that, don't resend.
                if st.job.is_none() && want_stdin {
                    return (Outcome::Transport(format!("connection lost while sending stdin ({why}); the command was not run to completion")), None);
                }
                if let Some(done) = retry_gate(&policy, &mut outage_since, &mut attempt, &st, on_event, &mut interrupts, &why).await {
                    return (done, st.job_ref());
                }
            }
        }
    }
}

/// Decide whether to retry after a failure: sleeps the backoff and returns
/// `None` to retry, or `Some(outcome)` to stop.
#[allow(clippy::too_many_arguments)]
async fn retry_gate(
    policy: &Policy,
    outage_since: &mut Option<Instant>,
    attempt: &mut u32,
    st: &Progress,
    on_event: &mut dyn FnMut(&Event),
    interrupts: &mut mpsc::Receiver<()>,
    why: &str,
) -> Option<Outcome> {
    if policy.window.is_zero() {
        return Some(Outcome::Transport(format!("connection to the host failed: {why}")));
    }
    let since = *outage_since.get_or_insert_with(Instant::now);
    let elapsed = since.elapsed();
    if elapsed >= policy.window {
        return Some(Outcome::GaveUp { job: st.job_ref() });
    }
    *attempt += 1;
    on_event(&Event::Reconnecting { attempt: *attempt, job: st.job_ref() });
    let wait = policy.backoff(*attempt).min(policy.window - elapsed);
    tokio::select! {
        _ = tokio::time::sleep(wait) => None,
        Some(()) = interrupts.recv() => {
            // Ctrl-C while offline: nothing to cancel remotely; detach or stop.
            Some(match st.job_ref() {
                Some(job) => Outcome::Detached { job, by_interrupt: true },
                None => Outcome::Interrupted,
            })
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_connection(
    dialer: &Dialer,
    session: Session,
    st: &mut Progress,
    exec: Option<&ExecRequest>,
    follow: bool,
    stdin: &mut Option<Box<dyn AsyncRead + Unpin + Send>>,
    interrupts: &mut mpsc::Receiver<()>,
    on_event: &mut dyn FnMut(&Event),
) -> ConnEnd {
    let vm = st.vm.clone().unwrap_or_default();
    let Session { conn, mut send, mut recv, .. } = session;
    let first = match (&st.job, exec) {
        (None, Some(req)) => req.to_frame(&vm, &st.idem),
        (Some(job), _) => Frame::new(json!({
            "t": "attach", "vm": vm, "start": false, "job": job,
            "stdout_off": st.out_off, "stderr_off": st.err_off, "follow": follow,
        })),
        (None, None) => return ConnEnd::Done(Outcome::Error { code: "bad_request".into(), msg: "nothing to run".into() }),
    };
    let sending_stdin = st.job.is_none() && exec.is_some_and(|r| r.stdin);
    if let Err(e) = write_frame(&mut send, &first).await {
        return ConnEnd::Dropped { why: e.to_string(), progressed: false };
    }

    // One task owns the send side so stdin, cancel and the request never interleave.
    let (tx, mut wrx) = mpsc::channel::<Frame>(8);
    let writer = tokio::spawn(async move {
        while let Some(f) = wrx.recv().await {
            if write_frame(&mut send, &f).await.is_err() {
                break;
            }
        }
        send
    });
    if st.cancel_pending {
        let _ = tx.send(Frame::of_type("cancel")).await;
    }
    let stdin_task = match (sending_stdin, stdin.take()) {
        (true, Some(mut input)) => {
            let tx = tx.clone();
            Some(tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match input.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if tx.send(Frame::with_payload(json!({"t": "stdin"}), buf[..n].to_vec())).await.is_err() {
                                return;
                            }
                        }
                    }
                }
                let _ = tx.send(Frame::of_type("stdin_eof")).await;
            }))
        }
        _ => None,
    };

    // A reader task, so select! below never cancels a half-read frame.
    let (ftx, mut frx) = mpsc::channel::<Result<Option<Frame>, String>>(16);
    let reader = tokio::spawn(async move {
        loop {
            match read_frame(&mut recv).await {
                Ok(Some(f)) => {
                    if ftx.send(Ok(Some(f))).await.is_err() {
                        return;
                    }
                }
                Ok(None) => {
                    let _ = ftx.send(Ok(None)).await;
                    return;
                }
                Err(e) => {
                    let _ = ftx.send(Err(e.to_string())).await;
                    return;
                }
            }
        }
    });

    let mut progressed = false;
    let mut cancels = 0u32;
    let end = loop {
        tokio::select! {
            got = frx.recv() => match got {
                None | Some(Ok(None)) => break ConnEnd::Dropped { why: "the connection closed".into(), progressed },
                Some(Err(e)) => break ConnEnd::Dropped { why: e, progressed },
                Some(Ok(Some(f))) => {
                    progressed = true;
                    match f.t() {
                        "started" => {
                            let id = f.str_field("job").unwrap_or("").to_owned();
                            st.job = Some(id.clone());
                            let r = st.job_ref().unwrap_or_default();
                            on_event(&Event::Started { job: r.clone(), pid: f.header.get("pid").and_then(Value::as_u64), deduped: f.header.get("deduped").and_then(Value::as_bool).unwrap_or(false) });
                            if exec.is_some_and(|e| e.detach) {
                                break ConnEnd::Done(Outcome::Detached { job: r, by_interrupt: false });
                            }
                        }
                        "attached" => {}
                        "gap" => {
                            let to = f.header.get("to").and_then(Value::as_u64).unwrap_or(0);
                            let from = f.header.get("from").and_then(Value::as_u64).unwrap_or(0);
                            let stream = f.str_field("stream").unwrap_or("stdout").to_owned();
                            if stream == "stderr" { st.err_off = st.err_off.max(to) } else { st.out_off = st.out_off.max(to) }
                            on_event(&Event::Gap { stream, from, to });
                        }
                        t @ ("stdout" | "stderr") => {
                            let is_out = t == "stdout";
                            let cur = if is_out { st.out_off } else { st.err_off };
                            let off = f.header.get("off").and_then(Value::as_u64).unwrap_or(cur);
                            let mut data = f.payload;
                            let mut off = off;
                            if off < cur {
                                // Replay overlap: drop what we already wrote.
                                let skip = ((cur - off) as usize).min(data.len());
                                data.drain(..skip);
                                off = cur;
                            }
                            if data.is_empty() {
                                continue;
                            }
                            let n = data.len() as u64;
                            if is_out {
                                st.out_off = off + n;
                                on_event(&Event::Stdout { off, data });
                            } else {
                                st.err_off = off + n;
                                on_event(&Event::Stderr { off, data });
                            }
                            if dialer.fault.as_ref().is_some_and(|fl| fl.bytes(n)) {
                                conn.close(0u32.into(), b"fault injection");
                                break ConnEnd::Dropped { why: "fault injected".into(), progressed: true };
                            }
                        }
                        "exit" => {
                            let code = f.header.get("code").and_then(Value::as_i64);
                            let signal = f.header.get("signal").and_then(Value::as_i64);
                            let reason = f.str_field("reason").unwrap_or("exited").to_owned();
                            let want_out = f.header.get("stdout_len").and_then(Value::as_u64).unwrap_or(0);
                            let want_err = f.header.get("stderr_len").and_then(Value::as_u64).unwrap_or(0);
                            if want_out > st.out_off || want_err > st.err_off {
                                break ConnEnd::Dropped { why: "the stream ended before all output arrived".into(), progressed };
                            }
                            on_event(&Event::Exit { code, signal, reason: reason.clone() });
                            break ConnEnd::Done(Outcome::Exit { code, signal, reason });
                        }
                        "end" => break ConnEnd::Done(Outcome::End),
                        "error" => {
                            let code = f.str_field("code").unwrap_or("internal").to_owned();
                            let msg = f.str_field("msg").unwrap_or("").to_owned();
                            on_event(&Event::Error { code: code.clone(), msg: msg.clone() });
                            break ConnEnd::Done(Outcome::Error { code, msg });
                        }
                        _ => {} // unknown events are ignored
                    }
                }
            },
            Some(()) = interrupts.recv() => {
                cancels += 1;
                if cancels == 1 {
                    st.cancel_pending = true;
                    let _ = tx.send(Frame::of_type("cancel")).await;
                } else {
                    break ConnEnd::Done(match st.job_ref() {
                        Some(job) => Outcome::Detached { job, by_interrupt: true },
                        None => Outcome::Interrupted,
                    });
                }
            }
        }
    };

    reader.abort();
    if let Some(t) = stdin_task {
        t.abort();
    }
    drop(tx);
    // Let a pending cancel/stdin frame flush, then say goodbye.
    let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
    conn.close(0u32.into(), b"done");
    end
}

// --- doctor ------------------------------------------------------------------------

/// One doctor stage result.
#[derive(Debug, Clone, PartialEq)]
pub struct Stage {
    pub stage: &'static str,
    pub ok: bool,
    pub ms: u64,
    pub detail: String,
    pub hint: Option<String>,
}

fn hint_for(stage: &str) -> &'static str {
    match stage {
        "token" => "Check that AZULA_COMPUTE_TOKEN holds the full `azc1.` string from `azula compute grant`.",
        "bind" | "relay" => {
            "Allowlist the relay host (and dns.iroh.link) on port 443 in the sandbox's network policy, check HTTPS_PROXY, \
             make sure the proxy's CA is in the system trust store, or try AZULA_RELAY_ONLY=1."
        }
        "dial" => {
            "Is `azula compute serve` running on the Mac, and is the Mac awake and online? Does the token's host id match \
             `azula compute grants` output on the Mac? Check the relay allowlist and try AZULA_RELAY_ONLY=1."
        }
        "auth" => "Is the grant revoked or expired? Mint a new one with `azula compute grant`.",
        "broker" => "The broker answered hello but not ping; is the host running a compatible azula version?",
        "guest" => "Start the VM with `azula vm start NAME`; check that `azula vm status NAME` on the host shows its worker ready.",
        _ => "",
    }
}

struct Doctor {
    stages: Vec<Stage>,
}

impl Doctor {
    fn pass(&mut self, stage: &'static str, t: Instant, detail: impl Into<String>) {
        self.stages.push(Stage { stage, ok: true, ms: t.elapsed().as_millis() as u64, detail: detail.into(), hint: None });
    }

    fn fail(&mut self, stage: &'static str, t: Instant, detail: impl Into<String>) {
        self.stages.push(Stage {
            stage,
            ok: false,
            ms: t.elapsed().as_millis() as u64,
            detail: redact_credentials(&detail.into()),
            hint: Some(hint_for(stage).to_owned()),
        });
    }
}

/// Run the staged connectivity check. `token_text` is parsed as the `token`
/// stage. `emit` is called with each stage as it finishes. Stops at the first
/// failing stage.
pub async fn doctor(token_text: Option<&str>, vm: Option<&str>, mut emit: impl FnMut(&Stage)) -> Vec<Stage> {
    let mut d = Doctor { stages: Vec::new() };
    let mut seen = 0usize;
    macro_rules! flush {
        () => {
            while seen < d.stages.len() {
                emit(&d.stages[seen]);
                seen += 1;
            }
        };
    }

    // token
    let t = Instant::now();
    let token = match token_text.map(Token::decode) {
        None => {
            d.fail("token", t, "no token: pass --token or set AZULA_COMPUTE_TOKEN");
            flush!();
            return d.stages;
        }
        Some(Err(e)) => {
            d.fail("token", t, e.to_string());
            flush!();
            return d.stages;
        }
        Some(Ok(tok)) => tok,
    };
    let addr = match token.addr() {
        Ok(a) => a,
        Err(e) => {
            d.fail("token", t, e.to_string());
            flush!();
            return d.stages;
        }
    };
    d.pass("token", t, format!("grant {}, host {}", token.grant, super::short_id(&token.host)));
    flush!();

    // bind + relay: one bind with a relay deadline (see `bind_with_options`).
    let t = Instant::now();
    let ep = match bind_client(RELAY_TIMEOUT, token_relay(&token)).await {
        Ok(ep) => ep,
        Err(e) => {
            let msg = redact_credentials(&format!("{e:#}"));
            if msg.contains("relay") {
                d.pass("bind", t, "local endpoint bound");
                d.fail("relay", t, format!("{msg} (host relay: {})", token.relay));
            } else {
                d.fail("bind", t, msg);
            }
            flush!();
            return d.stages;
        }
    };
    d.pass("bind", t, "local endpoint bound");
    let home = ep.addr().relay_urls().next().map(|u| u.to_string()).unwrap_or_else(|| "?".into());
    let homed = if token_relay(&token).is_some() { "homed on the token's relay" } else { "default relay map" };
    d.pass("relay", t, format!("online via {home} ({homed}; host's relay: {})", token.relay));
    flush!();

    // dial + auth + broker ping
    let t = Instant::now();
    let conn = match dial(&ep, addr.clone(), DIAL_TIMEOUT).await {
        Ok(c) => c,
        Err(e) => {
            d.fail("dial", t, format!("{e} (relay {})", token.relay));
            flush!();
            ep.close().await;
            return d.stages;
        }
    };
    d.pass("dial", t, "connected to the host");
    flush!();
    let t = Instant::now();
    let session = match authenticate(conn, &token, AUTH_TIMEOUT).await {
        Ok(s) => s,
        Err(e) => {
            d.fail("auth", t, e.message());
            flush!();
            ep.close().await;
            return d.stages;
        }
    };
    let host = session.host();
    d.pass("auth", t, format!("grant accepted by {host}"));
    flush!();
    let t = Instant::now();
    match request_reply(session, &Frame::of_type("ping"), AUTH_TIMEOUT).await {
        Ok(p) => d.pass("broker", t, format!("{} on {}", p.str_field("broker").unwrap_or("?"), p.str_field("host").unwrap_or("?"))),
        Err(e) => d.fail("broker", t, e.message()),
    }
    flush!();

    if let Some(vm) = vm.filter(|_| d.stages.last().is_some_and(|s| s.ok)) {
        let t = Instant::now();
        let result = async {
            let session = connect(&ep, addr, &token).await?;
            let name = session.resolve_vm(Some(vm));
            let r = request_reply(session, &Frame::new(json!({"t": "guest_ping", "vm": name})), GUEST_TIMEOUT).await?;
            Ok::<_, Failure>((name, r))
        }
        .await;
        match result {
            Ok((name, r)) => d.pass(
                "guest",
                t,
                format!(
                    "VM {name}: {} on {}, {} job(s) running, {} MiB disk free",
                    r.str_field("worker").unwrap_or("?"),
                    r.str_field("hostname").unwrap_or("?"),
                    r.header.get("jobs_running").and_then(Value::as_u64).map(|n| n.to_string()).unwrap_or_else(|| "?".into()),
                    r.header.get("disk_free_mb").and_then(Value::as_u64).map(|n| n.to_string()).unwrap_or_else(|| "?".into()),
                ),
            ),
            Err(e) => d.fail("guest", t, e.message()),
        }
        flush!();
    }
    ep.close().await;
    d.stages
}

/// Await `fut`, mapping a deadline miss to a transport failure.
pub async fn within<T>(d: Duration, what: &str, fut: impl Future<Output = T>) -> Result<T, Failure> {
    tokio::time::timeout(d, fut).await.map_err(|_| transport(format!("timed out after {}s: {what}", d.as_secs())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exit(code: Option<i64>, signal: Option<i64>, reason: &str) -> Outcome {
        Outcome::Exit { code, signal, reason: reason.into() }
    }

    #[test]
    fn exit_code_mapping() {
        assert_eq!(exit(Some(0), None, "exited").exit_code(), 0);
        assert_eq!(exit(Some(7), None, "exited").exit_code(), 7);
        assert_eq!(exit(None, Some(9), "exited").exit_code(), 137);
        assert_eq!(exit(None, Some(15), "cancelled").exit_code(), 130);
        assert_eq!(exit(None, Some(15), "timeout").exit_code(), 124);
        for r in ["interrupted", "stdin_lost", "orphaned"] {
            assert_eq!(exit(None, None, r).exit_code(), 255, "{r}");
            assert!(exit(None, None, r).message(None).unwrap().contains("job was"), "{r}");
        }
        assert_eq!(Outcome::Error { code: "spawn_failed".into(), msg: String::new() }.exit_code(), 127);
        assert_eq!(Outcome::Error { code: "cwd_missing".into(), msg: String::new() }.exit_code(), 126);
        for c in ["unauthorized", "forbidden", "vm_not_running", "bad_request", "worker_unreachable", "busy", "host_busy", "vm_busy", "grant_expiring"] {
            assert_eq!(Outcome::Error { code: c.into(), msg: String::new() }.exit_code(), 125, "{c}");
        }
        assert_eq!(Outcome::Transport("x".into()).exit_code(), 255);
        assert_eq!(Outcome::GaveUp { job: None }.exit_code(), 255);
        assert_eq!(Outcome::Interrupted.exit_code(), 130);
        assert_eq!(Outcome::Detached { job: "a/j_1".into(), by_interrupt: true }.exit_code(), 130);
        assert_eq!(Outcome::Detached { job: "a/j_1".into(), by_interrupt: false }.exit_code(), 0);
        assert_eq!(Failure::Transport("x".into()).exit_code(), 255);
        assert_eq!(Failure::Broker { code: "unauthorized".into(), msg: String::new() }.exit_code(), 125);
    }

    #[test]
    fn jobs_show_the_state_once_and_the_exit_code_the_client_would_use() {
        let j = |v: Value| job_status(&v);
        assert_eq!(j(json!({"state": "running"})), ("running".into(), "-".into()));
        assert_eq!(j(json!({"state": "exited", "reason": "exited", "code": 0})), ("exited".into(), "0".into()));
        assert_eq!(j(json!({"state": "exited", "reason": "exited", "code": 7})), ("exited".into(), "7".into()));
        assert_eq!(j(json!({"state": "exited", "reason": "exited", "code": null, "signal": 9})), ("exited".into(), "137".into()));
        assert_eq!(j(json!({"state": "exited", "reason": "timeout", "code": null})), ("timeout".into(), "124".into()));
        assert_eq!(j(json!({"state": "exited", "reason": "cancelled", "code": null, "signal": 15})), ("cancelled".into(), "130".into()));
        assert_eq!(j(json!({"state": "interrupted"})), ("interrupted".into(), "255".into()));
        assert_eq!(j(json!({"state": "exited", "reason": "interrupted"})), ("interrupted".into(), "255".into()));
        assert_eq!(j(json!({"state": "exited", "reason": "stdin_lost"})), ("stdin_lost".into(), "255".into()));
        assert_eq!(j(json!({"state": "exited", "reason": "orphaned"})), ("orphaned".into(), "255".into()));
    }

    #[test]
    fn give_up_message_names_the_attach_command() {
        let m = Outcome::GaveUp { job: Some("build/j_3f9a1c2b7d4e8a60".into()) }.message(None).unwrap();
        assert!(m.contains("azula compute attach build/j_3f9a1c2b7d4e8a60"), "{m}");
        assert!(m.contains("still running"), "{m}");
    }

    #[test]
    fn clients_home_on_the_tokens_relay() {
        let mk = |relay: &str| Token { host: "h".into(), relay: relay.into(), grant: "g".into(), secret: String::new() };
        assert_eq!(token_relay(&mk("https://usw1-1.relay.n0.iroh.link./")).unwrap().to_string(), "https://usw1-1.relay.n0.iroh.link./");
        assert!(token_relay(&mk("")).is_none(), "no relay in the token: keep the default map");
        assert!(token_relay(&mk("not a url")).is_none());
    }

    #[test]
    fn job_refs() {
        assert_eq!(JobRef::parse("build/j_3f9a").unwrap(), JobRef { vm: Some("build".into()), id: "j_3f9a".into() });
        assert_eq!(JobRef::parse("j_ab12").unwrap(), JobRef { vm: None, id: "j_ab12".into() });
        for bad in ["", "build/", "/j_1", "build/x_1", "j_", "j_zz", "build/j_1/x"] {
            assert!(JobRef::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn env_timeout_and_reconnect_parsing() {
        assert_eq!(parse_env("A=b=c").unwrap(), ("A".into(), "b=c".into()));
        assert_eq!(parse_env("A=").unwrap(), ("A".into(), String::new()));
        assert!(parse_env("=x").is_err() && parse_env("novalue").is_err());
        assert_eq!(parse_timeout("15m").unwrap(), 900);
        assert_eq!(parse_timeout("24h").unwrap(), 86_400);
        assert!(parse_timeout("25h").is_err() && parse_timeout("0s").is_err() && parse_timeout("soon").is_err());
        assert_eq!(parse_reconnect("0").unwrap(), Duration::ZERO);
        assert_eq!(parse_reconnect("5m").unwrap(), Duration::from_secs(300));
        assert!(parse_reconnect("x").is_err());
    }

    #[test]
    fn backoff_doubles_to_the_cap() {
        let p = Policy::default();
        let secs: Vec<u64> = (1..=7).map(|a| p.backoff(a).as_secs()).collect();
        assert_eq!(secs, [1, 2, 4, 8, 15, 15, 15]);
    }

    #[test]
    fn fault_fires_once_after_n_bytes() {
        let f = Fault::parse("drop-after:10").unwrap();
        assert!(!f.bytes(4));
        assert!(f.bytes(6), "crossing the threshold fires");
        assert!(!f.bytes(100), "only the first drop");
        assert!(Fault::parse("drop-after:x").is_none() && Fault::parse("nope").is_none());
    }

    #[test]
    fn events_render_as_jsonl() {
        assert_eq!(Event::Stdout { off: 5, data: b"hi".to_vec() }.to_json(), json!({"type": "stdout", "off": 5, "data_b64": "aGk="}));
        assert_eq!(
            Event::Started { job: "a/j_1".into(), pid: Some(3), deduped: false }.to_json(),
            json!({"type": "started", "job": "a/j_1", "pid": 3, "deduped": false})
        );
        assert_eq!(Event::Gap { stream: "stdout".into(), from: 0, to: 9 }.to_json(), json!({"type": "gap", "stream": "stdout", "from": 0, "to": 9}));
        assert_eq!(Event::Reconnecting { attempt: 2, job: None }.to_json(), json!({"type": "reconnecting", "attempt": 2}));
        assert_eq!(
            Event::Exit { code: Some(7), signal: None, reason: "exited".into() }.to_json(),
            json!({"type": "exit", "code": 7, "signal": null, "reason": "exited"})
        );
    }

    #[test]
    fn exec_frame_shape() {
        let r = ExecRequest {
            argv: vec!["echo".into(), "$HOME".into()],
            env: vec![("A".into(), "1".into())],
            cwd: Some("/w".into()),
            timeout_s: Some(60),
            label: Some("x".into()),
            ..Default::default()
        };
        let f = r.to_frame("build", "idem-1");
        assert_eq!(f.str_field("vm"), Some("build"));
        assert_eq!(f.str_field("idem"), Some("idem-1"));
        assert_eq!(f.header["start"], json!(true));
        assert_eq!(f.header["attach"], json!(true));
        assert_eq!(f.header["stdin"], json!(false));
        assert_eq!(f.header["env"], json!({"A": "1"}));
        assert_eq!(f.header["timeout_s"], json!(60));
        assert_eq!(f.header["label"], json!("x"));
        let no_start = ExecRequest { no_start: true, detach: true, argv: vec!["x".into()], ..Default::default() };
        let f = no_start.to_frame("v", "i");
        assert_eq!(f.header["start"], json!(false));
        assert_eq!(f.header["attach"], json!(false));
    }

    #[tokio::test]
    async fn reconnecting_gives_up_after_the_window_naming_the_job() {
        let st = Progress { vm: Some("b".into()), job: Some("j_ab12".into()), out_off: 0, err_off: 0, cancel_pending: false, idem: String::new() };
        let (_tx, mut rx) = mpsc::channel(1);
        let policy = Policy { window: Duration::from_millis(80), initial: Duration::from_millis(10), max: Duration::from_millis(20) };
        let (mut since, mut attempt, mut events) = (None, 0u32, Vec::new());
        let outcome = loop {
            if let Some(o) = retry_gate(&policy, &mut since, &mut attempt, &st, &mut |e| events.push(e.clone()), &mut rx, "boom").await {
                break o;
            }
        };
        assert_eq!(outcome, Outcome::GaveUp { job: Some("b/j_ab12".into()) });
        assert_eq!(outcome.exit_code(), 255);
        assert!(events.len() >= 2 && matches!(events[0], Event::Reconnecting { attempt: 1, .. }), "{events:?}");
        // With reconnecting disabled the very first failure is final.
        let mut none = None;
        let mut a0 = 0;
        let o = retry_gate(&Policy::with_window(Duration::ZERO), &mut none, &mut a0, &st, &mut |_| {}, &mut rx, "boom").await;
        assert!(matches!(o, Some(Outcome::Transport(_))));
    }

    #[tokio::test]
    async fn doctor_fails_at_token_stage_without_network() {
        let none = doctor(None, None, |_| {}).await;
        assert_eq!(none.len(), 1);
        assert!(!none[0].ok && none[0].stage == "token");
        let bad = doctor(Some("azc1.garbage"), None, |_| {}).await;
        assert!(!bad[0].ok && bad[0].hint.is_some());
    }
}
