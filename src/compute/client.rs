//! The cross-platform client of the compute broker: `exec`, `doctor` and the
//! `vm start|stop|status` verbs (`vm/BROKER.md` §5 and §7). Everything here
//! takes an already-bound iroh [`Endpoint`] and an [`EndpointAddr`], so tests
//! can dial a broker over local addresses; the CLI layer builds both from a
//! token.

use std::future::Future;
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
use super::{agent, ALPN, PROTO_VERSION};
use crate::endpoint::{bind_with_options, redact_credentials, EndpointOptions};

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

/// How a request ended, from the client's point of view.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// The job finished (the guest's `exit` frame).
    Exit { code: Option<i64>, signal: Option<i64>, reason: String },
    /// An `error` frame from the broker or the worker.
    Error { code: String, msg: String },
    /// The connection failed or dropped before an `exit`.
    Transport(String),
    /// The user interrupted twice and we disconnected.
    Interrupted,
}

impl Outcome {
    /// The process exit code for this outcome.
    pub fn exit_code(&self) -> i32 {
        match self {
            Outcome::Exit { reason, .. } if reason == "timeout" => exit::TIMEOUT,
            Outcome::Exit { reason, .. } if reason == "cancelled" => exit::CANCELLED,
            Outcome::Exit { code: Some(c), .. } => (*c).clamp(0, 255) as i32,
            Outcome::Exit { code: None, signal: Some(s), .. } => 128 + (*s).clamp(0, 127) as i32,
            Outcome::Exit { .. } => exit::TRANSPORT,
            Outcome::Error { code, .. } => match code.as_str() {
                "spawn_failed" => exit::SPAWN_FAILED,
                "cwd_missing" => exit::CWD_MISSING,
                _ => exit::BROKER_ERROR,
            },
            Outcome::Transport(_) => exit::TRANSPORT,
            Outcome::Interrupted => exit::CANCELLED,
        }
    }
}

/// A streamed job event, in the shape of the `--json` JSONL output.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    Started { pid: Option<u64> },
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit { code: Option<i64>, signal: Option<i64>, reason: String },
    Error { code: String, msg: String },
}

impl Event {
    /// `{"type":"started","pid"}`, `{"type":"stdout"|"stderr","data_b64"}`, …
    pub fn to_json(&self) -> Value {
        match self {
            Event::Started { pid } => json!({"type": "started", "pid": pid}),
            Event::Stdout(d) => json!({"type": "stdout", "data_b64": STANDARD.encode(d)}),
            Event::Stderr(d) => json!({"type": "stderr", "data_b64": STANDARD.encode(d)}),
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

fn transport(e: impl std::fmt::Display) -> Failure {
    Failure::Transport(redact_credentials(&e.to_string()))
}

fn error_failure(f: &Frame) -> Failure {
    Failure::Broker { code: f.str_field("code").unwrap_or("internal").to_owned(), msg: f.str_field("msg").unwrap_or("").to_owned() }
}

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
}

/// Bind the client's own (ephemeral-identity) endpoint with a relay deadline.
pub async fn bind_client(online_timeout: Duration) -> anyhow::Result<Endpoint> {
    let mut opts = EndpointOptions::new(SecretKey::generate());
    opts.online_timeout = Some(online_timeout);
    bind_with_options(opts).await
}

/// Dial `addr` on [`ALPN`] within `dial` (a stage deadline of its own).
pub async fn dial(ep: &Endpoint, addr: EndpointAddr, dial: Duration) -> Result<Connection, Failure> {
    match tokio::time::timeout(dial, ep.connect(addr, ALPN)).await {
        Ok(Ok(c)) => Ok(c),
        Ok(Err(e)) => Err(transport(format!("could not connect to the host: {e:#}"))),
        Err(_) => Err(transport(format!("timed out after {}s connecting to the host", dial.as_secs()))),
    }
}

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
pub async fn vm_op(session: Session, op: &str, name: Option<&str>) -> Result<Vec<Value>, Failure> {
    let mut req = json!({"t": "vm", "op": op});
    if op != "list" {
        let vm = match name {
            Some(n) => n.to_owned(),
            None => super::vm::default_vm_for(&session.grant_vms()),
        };
        req["vm"] = json!(vm);
    }
    let reply = request_reply(session, &Frame::new(req), VM_OP_TIMEOUT).await?;
    Ok(reply.header.get("vms").and_then(Value::as_array).cloned().unwrap_or_default())
}

// --- exec ------------------------------------------------------------------

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

impl ExecRequest {
    fn to_frame(&self, vm: &str) -> Frame {
        let mut h = json!({"t": "exec", "vm": vm, "start": !self.no_start, "argv": self.argv, "stdin": self.stdin});
        if let Some(c) = &self.cwd {
            h["cwd"] = json!(c);
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

/// Run `req` over `session`, streaming events to `on_event`.
///
/// * `stdin` is forwarded (then `stdin_eof`) when `req.stdin` is set.
/// * Each message on `interrupts` is a local SIGINT: the first sends `cancel`
///   (the job still reports its `exit`), the second disconnects.
pub async fn exec(
    session: Session,
    req: &ExecRequest,
    stdin: Option<Box<dyn AsyncRead + Unpin + Send>>,
    mut interrupts: mpsc::Receiver<()>,
    mut on_event: impl FnMut(&Event),
) -> Outcome {
    let vm = req.vm.clone().unwrap_or_else(|| super::vm::default_vm_for(&session.grant_vms()));
    let Session { conn, mut send, mut recv, .. } = session;
    if let Err(e) = write_frame(&mut send, &req.to_frame(&vm)).await {
        return Outcome::Transport(redact_credentials(&e.to_string()));
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
    let stdin_task = match (req.stdin, stdin) {
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

    let mut cancels = 0u32;
    let outcome = loop {
        tokio::select! {
            got = frx.recv() => match got {
                None | Some(Ok(None)) => break Outcome::Transport("connection to the host dropped before the job reported an exit status".into()),
                Some(Err(e)) => break Outcome::Transport(redact_credentials(&format!("connection to the host failed: {e}"))),
                Some(Ok(Some(f))) => match f.t() {
                    "started" => on_event(&Event::Started { pid: f.header.get("pid").and_then(Value::as_u64) }),
                    "stdout" => on_event(&Event::Stdout(f.payload)),
                    "stderr" => on_event(&Event::Stderr(f.payload)),
                    "exit" => {
                        let code = f.header.get("code").and_then(Value::as_i64);
                        let signal = f.header.get("signal").and_then(Value::as_i64);
                        let reason = f.str_field("reason").unwrap_or("exited").to_owned();
                        on_event(&Event::Exit { code, signal, reason: reason.clone() });
                        break Outcome::Exit { code, signal, reason };
                    }
                    "error" => {
                        let code = f.str_field("code").unwrap_or("internal").to_owned();
                        let msg = f.str_field("msg").unwrap_or("").to_owned();
                        on_event(&Event::Error { code: code.clone(), msg: msg.clone() });
                        break Outcome::Error { code, msg };
                    }
                    _ => {} // unknown events are ignored
                },
            },
            Some(()) = interrupts.recv() => {
                cancels += 1;
                if cancels == 1 {
                    let _ = tx.send(Frame::of_type("cancel")).await;
                } else {
                    break Outcome::Interrupted;
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
    outcome
}

// --- doctor ----------------------------------------------------------------

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
            "Allowlist the relay host on port 443 in the sandbox's network policy, check HTTPS_PROXY, \
             make sure the proxy's CA is in the system trust store, or try AZULA_RELAY_ONLY=1."
        }
        "dial" => "Is `azula compute serve` running on the host, and is the host online? Check the relay allowlist and try AZULA_RELAY_ONLY=1.",
        "auth" => "Is the grant revoked or expired? Mint a new one with `azula compute grant`.",
        "broker" => "The broker answered hello but not ping; is the host running a compatible azula version?",
        "guest" => "Start the VM with `azula vm start NAME`; check that `azula vm list` on the host shows its worker ready.",
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
    let ep = match bind_client(RELAY_TIMEOUT).await {
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
    d.pass("relay", t, format!("online via {home} (host's relay: {})", token.relay));
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
            let name = if vm.is_empty() { super::vm::default_vm_for(&session.grant_vms()) } else { vm.to_owned() };
            let r = request_reply(session, &Frame::new(json!({"t": "guest_ping", "vm": name})), GUEST_TIMEOUT).await?;
            Ok::<_, Failure>((name, r))
        }
        .await;
        match result {
            Ok((name, r)) => d.pass("guest", t, format!("VM {name}: {} on {}", r.str_field("worker").unwrap_or("?"), r.str_field("hostname").unwrap_or("?"))),
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
        assert_eq!(Outcome::Error { code: "spawn_failed".into(), msg: String::new() }.exit_code(), 127);
        assert_eq!(Outcome::Error { code: "cwd_missing".into(), msg: String::new() }.exit_code(), 126);
        for c in ["unauthorized", "forbidden", "vm_not_running", "bad_request", "worker_unreachable"] {
            assert_eq!(Outcome::Error { code: c.into(), msg: String::new() }.exit_code(), 125, "{c}");
        }
        assert_eq!(Outcome::Transport("x".into()).exit_code(), 255);
        assert_eq!(Outcome::Interrupted.exit_code(), 130);
        assert_eq!(Failure::Transport("x".into()).exit_code(), 255);
        assert_eq!(Failure::Broker { code: "unauthorized".into(), msg: String::new() }.exit_code(), 125);
    }

    #[test]
    fn env_and_timeout_parsing() {
        assert_eq!(parse_env("A=b=c").unwrap(), ("A".into(), "b=c".into()));
        assert_eq!(parse_env("A=").unwrap(), ("A".into(), String::new()));
        assert!(parse_env("=x").is_err() && parse_env("novalue").is_err());
        assert_eq!(parse_timeout("15m").unwrap(), 900);
        assert_eq!(parse_timeout("24h").unwrap(), 86_400);
        assert!(parse_timeout("25h").is_err() && parse_timeout("0s").is_err() && parse_timeout("soon").is_err());
    }

    #[test]
    fn events_render_as_jsonl() {
        assert_eq!(Event::Stdout(b"hi".to_vec()).to_json(), json!({"type": "stdout", "data_b64": "aGk="}));
        assert_eq!(Event::Started { pid: Some(3) }.to_json(), json!({"type": "started", "pid": 3}));
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
            ..Default::default()
        };
        let f = r.to_frame("build");
        assert_eq!(f.str_field("vm"), Some("build"));
        assert_eq!(f.header["start"], json!(true));
        assert_eq!(f.header["stdin"], json!(false));
        assert_eq!(f.header["env"], json!({"A": "1"}));
        assert_eq!(f.header["timeout_s"], json!(60));
        let no_start = ExecRequest { no_start: true, argv: vec!["x".into()], ..Default::default() };
        assert_eq!(no_start.to_frame("v").header["start"], json!(false));
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
