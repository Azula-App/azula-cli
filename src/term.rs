//! Remote-shell ("SSH"-like) protocol handler.
//!
//! Serves the `azula/term/0` ALPN. On each connection the server accepts the
//! client-opened bi stream and either bridges it to a brand-new, throwaway
//! PTY shell (the legacy behavior — see `legacy_bridge`) or, when the client
//! opts in with a `Frame::TermAttach` first frame, attaches it to a
//! `Session` that outlives any single bi-stream (see `persistent_session`
//! and friends below).
//!
//! * PTY output is read on a blocking thread and forwarded to the client as
//!   [`Frame::Term`] chunks.
//! * Incoming [`Frame::Input`] frames are written verbatim to the PTY stdin.
//!
//! portable-pty's reader/writer are blocking, so the bridge uses
//! `spawn_blocking` threads plus a tokio mpsc channel to move bytes between the
//! blocking PTY side and the async iroh side.
//!
//! ## Persistent sessions (opt-in)
//!
//! A client that never sends `Frame::TermAttach` gets exactly today's
//! behavior: a fresh PTY per bi-stream that dies the instant the stream ends,
//! with no trace left behind. This is the compatibility anchor — the
//! preexisting end-to-end tests in this file exercise exactly that path and
//! are unmodified by the persistent-session work.
//!
//! A client that sends `Frame::TermAttach { session }` as its first frame
//! (either literally first, or replayed by [`accept_gate::gate_stranger`] —
//! see the TRAP note below) instead gets a `Session` registered in the
//! process-wide [`SESSIONS`] map: the PTY is spawned once and kept alive by a
//! long-running [`session_core`] task independent of any one bi-stream. Each
//! bi-stream that attaches to it (the very first one, or a later reattach)
//! runs [`bind_attachment`], which registers itself as the session's *current*
//! attachment, replays a snapshot of the session's [`SessionRing`] scrollback
//! (for a resume), and then bridges client input to the PTY and PTY output to
//! the client until the stream ends — at which point the PTY is left running
//! (detached) rather than killed, subject to `--session-ttl`.
//!
//! TRAP: `accept_gate::gate_stranger` may consume and replay the client's
//! first frame (a legacy client's `Input`/`Resize` sent with no preceding
//! `Hello`) — that replay path MUST also recognize `Frame::TermAttach`, since
//! a *new* client presenting an invite as a stranger still opts into
//! persistence on its very first stream. See the `leading_frame` resolution
//! in `term_session` below.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::EndpointId;
use portable_pty::{ChildKiller, CommandBuilder, MasterPty, NativePtySystem, PtySize, PtySystem};
use tokio::io::BufReader;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use crate::accept_gate::{gate_stranger, GateOutcome};
use crate::proto::{read_frame, write_frame, Frame};
use crate::registry;

/// ALPN identifier for the remote-shell protocol.
pub const TERM_ALPN: &[u8] = b"azula/term/0";

/// Cap on how long we wait for a stream's first application frame (whether
/// replayed by the accept gate or read fresh) before falling back to the
/// legacy path with nothing to replay. Bounded so a slow/silent client can't
/// stall session setup indefinitely, but generous enough that it's never hit
/// in practice — real clients send their first frame immediately.
const FIRST_FRAME_TIMEOUT: Duration = Duration::from_millis(500);

/// Cap on each `SessionRing` — 256 KiB of the most recent shell output,
/// evicted from the front on newline boundaries so a replay never starts
/// mid-line.
const SESSION_RING_CAP: usize = 256 * 1024;

/// Replay chunk size: a resumed session's scrollback is sent as `Frame::Term`
/// chunks no larger than this, so a full ring doesn't show up as one giant
/// line.
const REPLAY_CHUNK: usize = 64 * 1024;

/// How often the TTL reaper sweeps [`SESSIONS`] for detached sessions past
/// their `--session-ttl`.
const TTL_REAP_INTERVAL: Duration = Duration::from_secs(30);

/// Protocol handler for the remote-shell ALPN.
///
/// Unlike `bridge/device.rs`'s `LLM_ALPN` handler (which tracks a live
/// multi-device map), `serve`'s term ALPN has no device-session concept — it
/// just needs to know whether an inbound connection is from a device already
/// in the registry, and gate strangers on a valid invite per
/// `azula-docs/openspec/specs/invitations/design.md` (see `accept_gate::gate_stranger`, shared
/// with `mcp.rs`'s `LlmHandler`).
#[derive(Debug, Clone)]
pub struct TermHandler {
    /// Our own node id — the invite-verification audience and signature key.
    my_node_id: EndpointId,
    /// Admit invite-less strangers as unverified instead of closing the
    /// connection (`--allow-legacy`, default on for one release).
    allow_legacy: bool,
    /// `--name` override for the terminal's announced `Frame::Profile.name`;
    /// falls back to this machine's hostname when unset.
    name_override: Option<String>,
    /// `--description` override for the terminal's announced
    /// `Frame::Profile.description`; falls back to the shell's launch
    /// working directory when unset.
    description_override: Option<String>,
    /// How long a detached persistent session survives before the TTL reaper
    /// kills it. `None` (`--session-ttl 0`) disables persistence entirely: a
    /// `TermAttach` handshake is still honored, but the PTY never outlives
    /// its bi-stream (same as the legacy path, just with the new frames).
    session_ttl: Option<Duration>,
}

impl TermHandler {
    pub fn new(
        my_node_id: EndpointId,
        allow_legacy: bool,
        name_override: Option<String>,
        description_override: Option<String>,
        session_ttl: Option<Duration>,
    ) -> Self {
        TermHandler {
            my_node_id,
            allow_legacy,
            name_override,
            description_override,
            session_ttl,
        }
    }
}

impl ProtocolHandler for TermHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        handle(
            connection,
            self.my_node_id,
            self.allow_legacy,
            self.name_override.clone(),
            self.description_override.clone(),
            self.session_ttl,
        )
        .await
        .map_err(|e| AcceptError::from_boxed(e.into()))
    }
}

async fn handle(
    connection: Connection,
    my_node_id: EndpointId,
    allow_legacy: bool,
    name_override: Option<String>,
    description_override: Option<String>,
    session_ttl: Option<Duration>,
) -> Result<()> {
    let remote_id = connection.remote_id();
    let remote = remote_id.to_string();
    info!(%remote, "term: client connected");

    // Known devices connect exactly as before — no gate. This is checked once
    // per connection (not per stream): a stranger who verifies on the first
    // stream is registered and every later stream on the same connection is
    // then implicitly from a "known" peer for the rest of its lifetime.
    let mut known = registry::find_by_node_id(&remote_id).is_some();
    let mut first_stream = true;
    // The app keys a terminal conversation by peer id, so every stream on this
    // connection rewires the *same* conversation (see `ConnectService.wireStream`
    // / `wireConv` in the app) — one `Profile` per connection is enough; a
    // second one on a later stream would just redundantly re-announce the same
    // name/description. Sent for the connection's first stream regardless of
    // whether that stream belonged to an already-known device or a
    // just-admitted stranger.
    let mut profile_sent = false;

    // Each bi stream the client opens is an independent terminal session, so a
    // single connection can drive many terminals. Loop accepting new streams.
    loop {
        let (send, recv) = match connection.accept_bi().await {
            Ok(pair) => pair,
            Err(e) => {
                debug!(%remote, error = %e, "term: connection closed");
                return Ok(());
            }
        };

        let mut reader = BufReader::new(recv);
        let mut first_frame: Option<Frame> = None;

        if first_stream && !known {
            let device_name = format!("term-{}", &remote[..8.min(remote.len())]);
            match gate_stranger(&mut reader, my_node_id, allow_legacy, &remote, &device_name, "term").await {
                GateOutcome::Admit { replay } => {
                    known = true; // don't re-gate later streams on this connection
                    first_frame = replay.map(|b| *b);
                }
                GateOutcome::Close => return Ok(()),
            }
        }
        first_stream = false;

        let profile = ProfileAnnounce {
            send: !profile_sent,
            name_override: name_override.clone(),
            description_override: description_override.clone(),
        };
        profile_sent = true;

        let remote = remote.clone();
        tokio::spawn(async move {
            if let Err(e) = term_session(send, reader, first_frame, remote.clone(), remote_id, profile, session_ttl).await {
                warn!(%remote, error = %e, "term: session error");
            }
        });
    }
}

/// Strip a trailing macOS mDNS `.local` suffix from a hostname so it reads
/// cleanly as a display name (e.g. `"Sals-MacBook-Pro.local"` ->
/// `"Sals-MacBook-Pro"`). A no-op for hostnames that don't end in `.local`.
fn strip_local_suffix(hostname: &str) -> &str {
    hostname.strip_suffix(".local").unwrap_or(hostname)
}

/// This machine's host name, used as the terminal conversation's default
/// display name. Falls back to `"azula"` if the OS reports an empty hostname.
fn default_hostname() -> String {
    let raw = gethostname::gethostname().to_string_lossy().into_owned();
    let stripped = strip_local_suffix(&raw);
    if stripped.is_empty() {
        "azula".to_string()
    } else {
        stripped.to_string()
    }
}

/// Resolve the terminal's `Frame::Profile.name`: the `--name` override if set
/// (and non-blank), else this machine's hostname.
fn resolve_profile_name(name_override: &Option<String>) -> String {
    match name_override {
        Some(n) if !n.trim().is_empty() => n.clone(),
        _ => default_hostname(),
    }
}

/// Resolve the terminal's `Frame::Profile.description`: the `--description`
/// override if set (and non-blank), else `launch_cwd` (the shell's launch
/// working directory, captured once — this never live-tracks later `cd`s).
fn resolve_profile_description(description_override: &Option<String>, launch_cwd: &str) -> String {
    match description_override {
        Some(d) if !d.trim().is_empty() => d.clone(),
        _ => launch_cwd.to_string(),
    }
}

/// Pull the longest valid-UTF-8 prefix out of `buf`, leaving any incomplete
/// trailing multibyte sequence for the next read (so we never split a char or an
/// escape sequence). Genuinely invalid bytes are replaced with U+FFFD once, so a
/// bad byte can't wedge the stream.
fn drain_valid_utf8(buf: &mut Vec<u8>) -> String {
    let mut out = String::new();
    loop {
        match std::str::from_utf8(buf) {
            Ok(s) => {
                out.push_str(s);
                buf.clear();
                break;
            }
            Err(e) => {
                let valid = e.valid_up_to();
                out.push_str(std::str::from_utf8(&buf[..valid]).unwrap());
                match e.error_len() {
                    Some(len) => {
                        out.push('\u{FFFD}');
                        buf.drain(..valid + len);
                    }
                    None => {
                        buf.drain(..valid);
                        break;
                    }
                }
            }
        }
    }
    out
}

/// Split `s` into chunks of at most `max_len` bytes, never splitting a
/// multibyte UTF-8 char across chunks.
fn chunk_utf8(s: &str, max_len: usize) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    while start < s.len() {
        let mut end = (start + max_len).min(s.len());
        while end > start && !s.is_char_boundary(end) {
            end -= 1;
        }
        if end == start {
            // max_len landed inside a single char that's itself longer than
            // max_len (impossible for UTF-8's <=4-byte chars given any
            // sane max_len, but guard against an infinite loop regardless).
            end = s.len();
        }
        out.push(&s[start..end]);
        start = end;
    }
    out
}

// ---------------------------------------------------------------------------
// Session ring: bounded scrollback kept per persistent session.
// ---------------------------------------------------------------------------

/// A bounded byte ring of a persistent session's recent PTY output, used to
/// replay scrollback to a client that reattaches. Only ever holds valid UTF-8
/// (every `push` is fed a `drain_valid_utf8` result, and eviction only ever
/// trims from the front up to and including a `\n`, which can't split a
/// multibyte char), so the ring's full contents are always valid UTF-8 as a
/// whole even though eviction operates on raw bytes.
struct SessionRing {
    buf: std::collections::VecDeque<u8>,
}

impl SessionRing {
    fn new() -> Self {
        SessionRing { buf: std::collections::VecDeque::new() }
    }

    fn push(&mut self, bytes: &[u8]) {
        self.buf.extend(bytes.iter().copied());
        self.evict();
    }

    /// Trim from the front, at newline boundaries, until back under cap. If
    /// the buffer is over cap with no newline at all (a single pathological
    /// line longer than the whole cap), just drop everything rather than
    /// spin — an unbroken line that long isn't useful scrollback anyway.
    fn evict(&mut self) {
        while self.buf.len() > SESSION_RING_CAP {
            match self.buf.iter().position(|&b| b == b'\n') {
                Some(pos) => {
                    self.buf.drain(..=pos);
                }
                None => {
                    self.buf.clear();
                    break;
                }
            }
        }
    }

    fn snapshot(&self) -> Vec<u8> {
        self.buf.iter().copied().collect()
    }
}

// ---------------------------------------------------------------------------
// Session registry: persistent PTYs that outlive any single bi-stream.
// ---------------------------------------------------------------------------

/// What the session's PTY sends toward whichever bi-stream is currently
/// attached (if any) — plain output, or the terminal event that the shell
/// exited.
enum SessionEvent {
    Output(String),
    Exit(Option<i32>),
}

/// A persistent shell session, keyed by a random id in [`SESSIONS`]. Kept
/// alive by [`session_core`] independent of any one bi-stream; bi-streams
/// come and go via [`bind_attachment`].
struct Session {
    id: String,
    /// Only the peer that created a session may reattach to it; anyone else
    /// asking for this id silently gets a brand new session instead (see
    /// `persistent_session`).
    owner: EndpointId,
    /// PTY stdin, shared by whichever bi-stream is currently attached.
    in_tx: mpsc::Sender<Vec<u8>>,
    master: StdMutex<Box<dyn MasterPty + Send>>,
    ring: StdMutex<SessionRing>,
    /// The current attachment (if any), tagged with a generation number so a
    /// displaced attachment can tell it's been superseded rather than
    /// mistaking a later attachment's registration for its own.
    current_attach: StdMutex<Option<(u64, mpsc::Sender<SessionEvent>)>>,
    /// Fires (value itself unused) whenever `current_attach` changes, so a
    /// live attachment's bridge loop can wake up and check whether it's still
    /// the current one.
    attach_changed: watch::Sender<()>,
    generation: AtomicU64,
    /// Set when the session has no live attachment; cleared on
    /// (re)attachment. The TTL reaper only kills sessions detached longer
    /// than `--session-ttl`.
    detached_at: StdMutex<Option<Instant>>,
    killer: StdMutex<Box<dyn ChildKiller + Send + Sync>>,
}

/// Process-wide persistent-session registry. Module-private and deliberately
/// separate from `registry.rs`, which is the paired-*device* registry (a
/// different concept, persisted to disk); sessions are in-memory only and
/// gone on restart.
static SESSIONS: OnceLock<StdMutex<HashMap<String, Arc<Session>>>> = OnceLock::new();

fn sessions() -> &'static StdMutex<HashMap<String, Arc<Session>>> {
    SESSIONS.get_or_init(|| StdMutex::new(HashMap::new()))
}

fn new_session_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// Look up a session by id, but only if `owner` is the peer that created it.
/// A wrong-owner or missing id both come back `None` — the caller can't tell
/// the difference, which is the point (no probing which ids exist).
fn find_owned_session(id: &str, owner: EndpointId) -> Option<Arc<Session>> {
    let map = sessions().lock().unwrap();
    map.get(id).filter(|s| s.owner == owner).cloned()
}

/// Kill every registered session's shell and empty the registry.
///
/// A live persistent session's PTY-reader thread is a `spawn_blocking` task
/// parked in a real, synchronous read from the shell; it only returns once
/// the shell produces output or exits. Dropping a tokio `Runtime` blocks the
/// dropping thread until every outstanding task — including that one —
/// finishes, so on process shutdown this must run *before* the runtime is
/// dropped (see the call site in `main.rs`'s `serve`), or shutdown hangs
/// forever waiting for a shell that's never going to produce more output on
/// its own. Tests that create persistent sessions call this for the same
/// reason: a `#[tokio::test]`'s own runtime is torn down when the test
/// function returns, and a still-alive shell hangs that teardown exactly
/// like a real shutdown would.
pub fn kill_all_sessions() {
    let map = std::mem::take(&mut *sessions().lock().unwrap());
    for session in map.into_values() {
        let _ = session.killer.lock().unwrap().kill();
    }
}

/// Kill and remove one specific session by id (a no-op if it's already
/// gone). [`SESSIONS`] is one process-wide registry shared by every
/// concurrently running `#[tokio::test]` in this binary, so a test that
/// needs to unblock its *own* session's PTY-reader thread before returning
/// (see `kill_all_sessions`'s doc comment) must not reach for the blunt
/// kill-everything version — that would also kill a session a *different*,
/// concurrently running test still needs.
#[cfg(test)]
fn kill_session(id: &str) {
    if let Some(session) = sessions().lock().unwrap().remove(id) {
        let _ = session.killer.lock().unwrap().kill();
    }
}

/// Spawn the periodic sweep that kills and removes persistent sessions that
/// have been detached longer than `ttl`. Only worth spawning when persistence
/// is actually enabled (`ttl` is `Some`) — call once at server startup.
pub fn spawn_ttl_reaper(ttl: Duration) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(TTL_REAP_INTERVAL);
        // The first tick fires immediately; skip it so we don't sweep the
        // instant the server starts with an empty registry.
        interval.tick().await;
        loop {
            interval.tick().await;
            reap_expired_sessions(ttl);
        }
    });
}

fn reap_expired_sessions(ttl: Duration) {
    let now = Instant::now();
    let expired: Vec<Arc<Session>> = {
        let map = sessions().lock().unwrap();
        map.values()
            .filter(|s| matches!(*s.detached_at.lock().unwrap(), Some(at) if now.duration_since(at) >= ttl))
            .cloned()
            .collect()
    };
    if expired.is_empty() {
        return;
    }
    let mut map = sessions().lock().unwrap();
    for s in expired {
        let _ = s.killer.lock().unwrap().kill();
        map.remove(&s.id);
        info!(session = %s.id, "term: session TTL expired; reaped");
    }
}

// ---------------------------------------------------------------------------
// PTY spawning: shared by the legacy path and persistent sessions.
// ---------------------------------------------------------------------------

/// A freshly spawned PTY shell, not yet wired into either the legacy bridge
/// or a `Session`.
struct SpawnedPty {
    master: Box<dyn MasterPty + Send>,
    in_tx: mpsc::Sender<Vec<u8>>,
    out_rx: mpsc::Receiver<Vec<u8>>,
    killer: Box<dyn ChildKiller + Send + Sync>,
    /// Resolves once the PTY hits EOF (shell exited) *and* the child has been
    /// reaped, yielding its exit code when available. `out_rx` closing and
    /// this handle resolving happen together (the reader thread's own
    /// `out_tx` isn't dropped until after it calls `child.wait()`).
    reader_task: tokio::task::JoinHandle<Option<i32>>,
    writer_task: tokio::task::JoinHandle<()>,
}

/// Open a PTY and spawn the user's shell into it — identical setup for both
/// the legacy ephemeral path and a new persistent session; only what happens
/// to the returned handles afterward differs.
fn spawn_pty_shell() -> Result<SpawnedPty> {
    let pty_system = NativePtySystem::default();
    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .context("opening PTY")?;

    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
    let mut cmd = CommandBuilder::new(&shell);
    // A login shell when using the fallback /bin/sh; harmless otherwise.
    cmd.arg("-l");
    cmd.env("TERM", "xterm-256color");

    let mut child = pair
        .slave
        .spawn_command(cmd)
        .context("spawning shell in PTY")?;
    // Drop the slave; the master keeps the PTY alive. Keep the master itself so we
    // can resize it when the client reports its viewport size.
    drop(pair.slave);
    let master = pair.master;
    let killer = child.clone_killer();

    // Blocking reader + writer handles for the PTY master.
    let mut pty_reader = master
        .try_clone_reader()
        .context("cloning PTY reader")?;
    let mut pty_writer = master
        .take_writer()
        .context("taking PTY writer")?;

    // PTY output -> async channel, fed by a blocking thread.
    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(64);
    let reader_task = tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 4096];
        loop {
            match pty_reader.read(&mut buf) {
                Ok(0) => break, // EOF: shell exited.
                Ok(n) => {
                    if out_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break; // Receiver dropped.
                    }
                }
                Err(_) => break,
            }
        }
        // Reap the child so it doesn't linger as a zombie, and hand back its
        // exit code for persistent sessions' `Frame::TermExit` (the legacy
        // path ignores this — it kills the child from the outside, at which
        // point this same wait() call reaps it just the same).
        child.wait().ok().map(|s| s.exit_code() as i32)
    });

    // PTY input <- async channel, drained by a blocking thread.
    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(64);
    let writer_task = tokio::task::spawn_blocking(move || {
        let mut in_rx = in_rx;
        while let Some(bytes) = in_rx.blocking_recv() {
            if pty_writer.write_all(&bytes).is_err() {
                break;
            }
            let _ = pty_writer.flush();
        }
    });

    Ok(SpawnedPty { master, in_tx, out_rx, killer, reader_task, writer_task })
}

// ---------------------------------------------------------------------------
// Per-stream entry point: decide legacy vs. persistent, then dispatch.
// ---------------------------------------------------------------------------

/// Whether (and with what overrides) to send a `Frame::Profile` for this
/// stream. Bundled into one param — see the `profile_sent` comment in
/// `handle` for why `send` is `true` only once per connection.
struct ProfileAnnounce {
    send: bool,
    name_override: Option<String>,
    description_override: Option<String>,
}

/// One bounded (`FIRST_FRAME_TIMEOUT`) read of a single frame off `reader`,
/// for resolving a stream's leading frame outside the accept gate. `Ok(None)`
/// covers both a clean stream end and the timeout elapsing with nothing
/// sent — both mean "proceed as if idle". `Err(())` means a real I/O error,
/// which the caller should treat as fatal for the stream (log already
/// emitted here so callers don't need to).
async fn read_bounded_frame(
    reader: &mut BufReader<RecvStream>,
    remote: &str,
    what: &str,
) -> Result<Option<Frame>, ()> {
    match tokio::time::timeout(FIRST_FRAME_TIMEOUT, read_frame(reader)).await {
        Ok(Ok(f)) => Ok(f),
        Ok(Err(e)) => {
            warn!(%remote, error = %e, what, "term: read error waiting for a leading frame");
            Err(())
        }
        Err(_elapsed) => Ok(None), // Nothing sent yet; proceed as if idle.
    }
}

/// Bridge one bi stream. `reader` may already have consumed a first frame
/// while gating the connection (see `gate_stranger`); that frame — or,
/// absent one, a frame read fresh here with a bounded timeout — decides
/// whether this stream opts into a persistent session (`Frame::TermAttach`)
/// or gets the legacy ephemeral behavior (anything else, including nothing
/// within the timeout).
async fn term_session(
    send: SendStream,
    mut reader: BufReader<RecvStream>,
    first_frame: Option<Frame>,
    remote: String,
    remote_id: EndpointId,
    profile: ProfileAnnounce,
    session_ttl: Option<Duration>,
) -> Result<()> {
    let mut send = send;

    // Capture the server process's launch directory now, one-shot (this does
    // NOT track later `cd`s in the shell) — the default terminal description
    // unless `--description` overrides it.
    let launch_cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    // Announce this terminal's identity before any shell output, so the app
    // names the conversation from the very first frame it sees. Reused for
    // both known devices and invite-verified/allow-legacy strangers — see the
    // `profile_sent` comment in `handle` for why this is once per connection.
    if profile.send {
        let profile_frame = Frame::Profile {
            name: resolve_profile_name(&profile.name_override),
            description: Some(resolve_profile_description(&profile.description_override, &launch_cwd)),
            avatar: None,
            mime: None,
        };
        if write_frame(&mut send, &profile_frame).await.is_err() {
            debug!(%remote, "term: failed to send profile frame; continuing");
        }
    }

    // Resolve the stream's leading frame: the accept gate's replay if it ran,
    // else a fresh bounded read. Both are treated identically from here on —
    // this is the TRAP called out in the module docs: a gate replay MUST be
    // checked for `TermAttach` too.
    let leading_frame: Option<Frame> = match first_frame {
        Some(f) => Some(f),
        None => match read_bounded_frame(&mut reader, &remote, "the first frame").await {
            Ok(f) => f,
            Err(()) => {
                let _ = send.finish();
                return Ok(());
            }
        },
    };

    // The azula app's `ConnectService.ping()` sends `Frame::Hello` as the
    // literal first frame on every dialed stream, on every ALPN, including
    // this one — then `wireConv` follows up with `Frame::TermAttach`. The
    // accept gate above consumes a leading `Hello` only while verifying a
    // *stranger's* invite; once a peer is known, `first_stream && !known` is
    // false, the gate never runs, and the fresh read just above is the one
    // that captures the Hello. Without skipping it here, that Hello would be
    // treated as the stream's leading frame, the real `TermAttach` right
    // behind it would never be inspected, and every reconnect from a known
    // peer would silently fall through to `legacy_bridge` (fresh shell, no
    // resume) instead of the persistent-session path. Bounded to skipping at
    // most one `Hello` — it's sent exactly once per stream, so this never
    // loops. A `Hello` is never terminal input or a session command, so
    // skipping it changes nothing for the legacy path either: it was never
    // valid to replay as PTY input in the first place.
    let leading_frame: Option<Frame> = match leading_frame {
        Some(Frame::Hello { .. }) => match read_bounded_frame(&mut reader, &remote, "the frame after Hello").await {
            Ok(f) => f,
            Err(()) => {
                let _ = send.finish();
                return Ok(());
            }
        },
        other => other,
    };

    if let Some(Frame::TermAttach { session }) = leading_frame {
        return persistent_session(send, reader, session, remote, remote_id, session_ttl).await;
    }

    let pty = spawn_pty_shell().context("spawning shell")?;
    legacy_bridge(send, reader, leading_frame, remote, pty).await
}

/// The pre-existing ephemeral behavior, byte-for-byte: replay whatever
/// leading frame we have (if any) as input, then bridge PTY output to the
/// client and client frames to the PTY until either side closes — at which
/// point the shell is killed. No trace of this session survives the stream.
async fn legacy_bridge(
    send: SendStream,
    mut reader: BufReader<RecvStream>,
    leading_frame: Option<Frame>,
    remote: String,
    mut pty: SpawnedPty,
) -> Result<()> {
    let mut send = send;

    // Replay a frame the accept-gate (or our own leading-frame read) already
    // consumed off the stream, so gating doesn't silently drop the client's
    // first keystrokes.
    match leading_frame {
        Some(Frame::Input { text }) => {
            let _ = pty.in_tx.send(text.into_bytes()).await;
        }
        Some(Frame::Resize { cols, rows }) => {
            let _ = pty.master.resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 });
        }
        Some(other) => {
            debug!(%remote, ?other, "term: ignoring replayed non-input frame");
        }
        None => {}
    }

    // Carry buffer for PTY output: a 4096-byte read can split a multibyte UTF-8
    // char (or an escape sequence) at the boundary, so hold the incomplete tail
    // and decode only the valid prefix each time — no U+FFFD artifacts.
    let mut pending: Vec<u8> = Vec::new();

    // Main bridge loop: forward PTY output to the client and client input to
    // the PTY until either side closes.
    loop {
        tokio::select! {
            // PTY produced output.
            chunk = pty.out_rx.recv() => {
                match chunk {
                    Some(bytes) => {
                        pending.extend_from_slice(&bytes);
                        let text = drain_valid_utf8(&mut pending);
                        if !text.is_empty()
                            && write_frame(&mut send, &Frame::term(text)).await.is_err()
                        {
                            debug!(%remote, "term: client send failed; closing");
                            break;
                        }
                    }
                    None => {
                        debug!(%remote, "term: shell exited");
                        break;
                    }
                }
            }

            // Client sent a frame.
            frame = read_frame(&mut reader) => {
                match frame {
                    Ok(Some(Frame::Input { text })) => {
                        // Write the keystrokes/command verbatim; no extra newline.
                        if pty.in_tx.send(text.into_bytes()).await.is_err() {
                            break;
                        }
                    }
                    Ok(Some(Frame::Resize { cols, rows })) => {
                        let _ = pty.master.resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 });
                    }
                    Ok(Some(other)) => {
                        debug!(%remote, ?other, "term: ignoring non-input frame");
                    }
                    Ok(None) => {
                        debug!(%remote, "term: client closed stream");
                        break;
                    }
                    Err(e) => {
                        warn!(%remote, error = %e, "term: read error");
                        break;
                    }
                }
            }
        }
    }

    // Tear down: drop the input channel so the writer thread exits, kill the
    // child shell, and stop the reader thread.
    drop(pty.in_tx);
    let _ = pty.killer.kill();
    pty.reader_task.abort();
    pty.writer_task.abort();
    let _ = send.finish();
    info!(%remote, "term: session ended");
    Ok(())
}

// ---------------------------------------------------------------------------
// Persistent-session path.
// ---------------------------------------------------------------------------

/// Resolve a `TermAttach { session }`: reattach if `session` names an
/// existing session owned by `remote_id`, else create a brand new one
/// (`resumed: false`) — this covers both "no id given" (a fresh session was
/// requested) and "id given but not found / owned by someone else" (silently
/// falls back rather than leaking which ids exist).
async fn persistent_session(
    send: SendStream,
    reader: BufReader<RecvStream>,
    requested: Option<String>,
    remote: String,
    remote_id: EndpointId,
    session_ttl: Option<Duration>,
) -> Result<()> {
    if let Some(id) = requested.as_deref() {
        if let Some(session) = find_owned_session(id, remote_id) {
            return attach_to_session(send, reader, session, remote, session_ttl).await;
        }
    }
    create_persistent_session(send, reader, remote, remote_id, session_ttl).await
}

/// Spawn a brand new PTY, register it as a new `Session`, and attach this
/// stream to it as the first (and so far only) attachment.
async fn create_persistent_session(
    send: SendStream,
    reader: BufReader<RecvStream>,
    remote: String,
    remote_id: EndpointId,
    session_ttl: Option<Duration>,
) -> Result<()> {
    let mut send = send;

    let pty = match spawn_pty_shell() {
        Ok(p) => p,
        Err(e) => {
            warn!(%remote, error = %e, "term: failed to spawn PTY for persistent session");
            let _ = send.finish();
            return Ok(());
        }
    };

    let id = new_session_id();
    let session = Arc::new(Session {
        id: id.clone(),
        owner: remote_id,
        in_tx: pty.in_tx,
        master: StdMutex::new(pty.master),
        ring: StdMutex::new(SessionRing::new()),
        current_attach: StdMutex::new(None),
        attach_changed: watch::channel(()).0,
        generation: AtomicU64::new(0),
        detached_at: StdMutex::new(None),
        killer: StdMutex::new(pty.killer),
    });

    sessions().lock().unwrap().insert(id.clone(), session.clone());
    tokio::spawn(session_core(session.clone(), pty.out_rx, pty.reader_task));

    if write_frame(&mut send, &Frame::TermSession { session: id.clone(), resumed: false }).await.is_err() {
        debug!(%remote, session = %id, "term: failed to send term_session frame");
        // Fall through into bind_attachment anyway: it will immediately hit
        // the same broken stream on its own read/write and detach cleanly,
        // leaving the session registered exactly like any other detach.
    }

    bind_attachment(send, reader, session, remote, session_ttl).await
}

/// Reattach to an existing, owned session: acknowledge with
/// `resumed: true`, replay its scrollback ring, then bind this stream as the
/// current attachment.
async fn attach_to_session(
    send: SendStream,
    reader: BufReader<RecvStream>,
    session: Arc<Session>,
    remote: String,
    session_ttl: Option<Duration>,
) -> Result<()> {
    let mut send = send;

    if write_frame(&mut send, &Frame::TermSession { session: session.id.clone(), resumed: true })
        .await
        .is_err()
    {
        debug!(%remote, session = %session.id, "term: failed to send term_session (resumed) frame; closing");
        return Ok(());
    }

    // Replay BEFORE registering the live attachment channel, so scrollback
    // and live output never interleave out of order.
    let snapshot = session.ring.lock().unwrap().snapshot();
    let text = String::from_utf8_lossy(&snapshot).into_owned();
    for chunk in chunk_utf8(&text, REPLAY_CHUNK) {
        if write_frame(&mut send, &Frame::term(chunk)).await.is_err() {
            debug!(%remote, session = %session.id, "term: failed sending replay chunk; closing");
            return Ok(());
        }
    }

    bind_attachment(send, reader, session, remote, session_ttl).await
}

/// Register this stream as `session`'s current attachment (displacing any
/// previous one), then bridge client <-> session until the stream ends or
/// the PTY exits. On stream end: detach (keep the PTY alive) when
/// persistence is enabled, or kill the session outright when
/// `--session-ttl 0` has it disabled.
async fn bind_attachment(
    send: SendStream,
    mut reader: BufReader<RecvStream>,
    session: Arc<Session>,
    remote: String,
    session_ttl: Option<Duration>,
) -> Result<()> {
    let mut send = send;

    let my_gen = session.generation.fetch_add(1, Ordering::SeqCst) + 1;
    let (event_tx, mut event_rx) = mpsc::channel::<SessionEvent>(256);
    *session.current_attach.lock().unwrap() = Some((my_gen, event_tx));
    *session.detached_at.lock().unwrap() = None;
    let _ = session.attach_changed.send(());
    let mut changed_rx = session.attach_changed.subscribe();

    // SIGWINCH-nudge bookkeeping: the very first Resize we see after
    // (re)attaching, if it reports the same size the PTY already has (which
    // is the common case — the app resizes to whatever its viewport already
    // is on reconnect), gets a synthetic one-row wobble so alt-screen TUIs
    // (vim, htop, claude's own TUI) notice the "resize" and repaint instead
    // of leaving stale content on screen until the user interacts.
    let mut nudge_pending = true;

    loop {
        tokio::select! {
            changed = changed_rx.changed() => {
                if changed.is_err() {
                    break; // Sender dropped — shouldn't happen while we hold an Arc.
                }
                let superseded = match &*session.current_attach.lock().unwrap() {
                    Some((gen, _)) => *gen != my_gen,
                    None => true,
                };
                if superseded {
                    debug!(%remote, session = %session.id, "term: attachment superseded by a newer stream; closing");
                    break;
                }
            }

            event = event_rx.recv() => {
                match event {
                    Some(SessionEvent::Output(text)) => {
                        if write_frame(&mut send, &Frame::term(text)).await.is_err() {
                            debug!(%remote, session = %session.id, "term: client send failed; detaching");
                            break;
                        }
                    }
                    Some(SessionEvent::Exit(code)) => {
                        let _ = write_frame(&mut send, &Frame::TermExit { session: session.id.clone(), code }).await;
                        let _ = send.finish();
                        info!(%remote, session = %session.id, "term: session exited");
                        return Ok(());
                    }
                    None => break, // session_core gone without a final Exit — shouldn't happen.
                }
            }

            frame = read_frame(&mut reader) => {
                match frame {
                    Ok(Some(Frame::Input { text })) => {
                        if session.in_tx.send(text.into_bytes()).await.is_err() {
                            break;
                        }
                    }
                    Ok(Some(Frame::Resize { cols, rows })) => {
                        let size = PtySize { rows, cols, pixel_width: 0, pixel_height: 0 };
                        if nudge_pending {
                            nudge_pending = false;
                            nudge_resize_if_unchanged(&session, size);
                        } else {
                            let _ = session.master.lock().unwrap().resize(size);
                        }
                    }
                    Ok(Some(Frame::TermAttach { .. })) => {
                        debug!(%remote, session = %session.id, "term: ignoring a second term_attach on an already-attached stream");
                    }
                    Ok(Some(other)) => {
                        debug!(%remote, ?other, "term: ignoring non-input frame");
                    }
                    Ok(None) => {
                        debug!(%remote, session = %session.id, "term: client detached");
                        break;
                    }
                    Err(e) => {
                        warn!(%remote, error = %e, "term: read error");
                        break;
                    }
                }
            }
        }
    }

    // Detach: clear our own attachment registration (only if a newer one
    // hasn't already replaced it) and either leave the PTY running or kill it
    // outright, per --session-ttl.
    {
        let mut cur = session.current_attach.lock().unwrap();
        if matches!(&*cur, Some((gen, _)) if *gen == my_gen) {
            *cur = None;
        }
    }
    let _ = session.attach_changed.send(());

    match session_ttl {
        Some(_) => {
            *session.detached_at.lock().unwrap() = Some(Instant::now());
            debug!(%remote, session = %session.id, "term: detached; PTY kept alive");
        }
        None => {
            // Persistence administratively disabled: behave like the legacy
            // path on stream end — kill the shell instead of leaving it
            // around with no TTL reaper to ever clean it up.
            let _ = session.killer.lock().unwrap().kill();
            sessions().lock().unwrap().remove(&session.id);
            debug!(%remote, session = %session.id, "term: --session-ttl 0; killed on detach");
        }
    }

    let _ = send.finish();
    Ok(())
}

/// If `size` matches what the PTY already thinks its size is, wobble it by
/// one row and back so the child gets two resize events instead of a no-op
/// one — see the nudge comment on `bind_attachment`'s `nudge_pending`.
fn nudge_resize_if_unchanged(session: &Session, size: PtySize) {
    let master = session.master.lock().unwrap();
    let unchanged = master.get_size().map(|current| current == size).unwrap_or(false);
    if unchanged {
        let nudged = PtySize { rows: size.rows.saturating_sub(1).max(1), ..size };
        let _ = master.resize(nudged);
        let _ = master.resize(size);
    } else {
        let _ = master.resize(size);
    }
}

/// Drains a persistent session's PTY output for as long as the PTY lives,
/// independent of any single bi-stream: pushes every chunk into the ring and
/// forwards it to whichever attachment is currently registered (if any). On
/// PTY EOF, notifies the current attachment (if any) with the exit code and
/// removes the session from [`SESSIONS`] — no bi-stream needs to be attached
/// for this to happen; a session left detached past exit is simply gone.
async fn session_core(
    session: Arc<Session>,
    mut out_rx: mpsc::Receiver<Vec<u8>>,
    reader_task: tokio::task::JoinHandle<Option<i32>>,
) {
    let mut pending: Vec<u8> = Vec::new();
    while let Some(bytes) = out_rx.recv().await {
        pending.extend_from_slice(&bytes);
        let text = drain_valid_utf8(&mut pending);
        if text.is_empty() {
            continue;
        }
        session.ring.lock().unwrap().push(text.as_bytes());
        let current = session.current_attach.lock().unwrap().clone();
        if let Some((_, tx)) = current {
            let _ = tx.send(SessionEvent::Output(text)).await;
        }
    }

    let exit_code = reader_task.await.unwrap_or(None);
    let current = session.current_attach.lock().unwrap().clone();
    if let Some((_, tx)) = current {
        let _ = tx.send(SessionEvent::Exit(exit_code)).await;
    }
    sessions().lock().unwrap().remove(&session.id);
    debug!(session = %session.id, "term: persistent session's PTY exited; removed from registry");
}

// ---------------------------------------------------------------------------
// Unit tests: name/description resolution, chunking, SessionRing.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod resolve_tests {
    use super::{resolve_profile_description, resolve_profile_name, strip_local_suffix};

    #[test]
    fn strip_local_suffix_strips_mdns_suffix() {
        assert_eq!(strip_local_suffix("Sals-MacBook-Pro.local"), "Sals-MacBook-Pro");
    }

    #[test]
    fn strip_local_suffix_leaves_other_hostnames_alone() {
        assert_eq!(strip_local_suffix("my-server"), "my-server");
    }

    #[test]
    fn resolve_profile_name_prefers_override() {
        assert_eq!(resolve_profile_name(&Some("Foo".to_string())), "Foo");
    }

    #[test]
    fn resolve_profile_name_ignores_blank_override() {
        // A blank --name is treated as "not set" rather than announcing an
        // empty display name.
        let name = resolve_profile_name(&Some("   ".to_string()));
        assert!(!name.is_empty());
    }

    #[test]
    fn resolve_profile_name_falls_back_to_hostname_when_absent() {
        let name = resolve_profile_name(&None);
        assert!(!name.is_empty());
    }

    #[test]
    fn resolve_profile_description_prefers_override() {
        assert_eq!(resolve_profile_description(&Some("/bar".to_string()), "/home/x"), "/bar");
    }

    #[test]
    fn resolve_profile_description_falls_back_to_cwd_when_absent() {
        assert_eq!(resolve_profile_description(&None, "/home/x"), "/home/x");
    }
}

#[cfg(test)]
mod chunk_tests {
    use super::chunk_utf8;

    #[test]
    fn chunk_utf8_splits_on_max_len_boundaries() {
        let s = "a".repeat(10);
        let chunks = chunk_utf8(&s, 4);
        assert_eq!(chunks, vec!["aaaa", "aaaa", "aa"]);
    }

    #[test]
    fn chunk_utf8_never_splits_a_multibyte_char() {
        // Each "é" is 2 bytes; a max_len that would land mid-char must back
        // off to the previous char boundary.
        let s = "éééé"; // 8 bytes total
        let chunks = chunk_utf8(s, 3);
        for c in &chunks {
            assert!(std::str::from_utf8(c.as_bytes()).is_ok());
        }
        assert_eq!(chunks.concat(), s);
    }

    #[test]
    fn chunk_utf8_short_input_is_one_chunk() {
        assert_eq!(chunk_utf8("hi", 64 * 1024), vec!["hi"]);
    }

    #[test]
    fn chunk_utf8_empty_input_yields_no_chunks() {
        assert!(chunk_utf8("", 64).is_empty());
    }
}

#[cfg(test)]
mod ring_tests {
    use super::{SessionRing, SESSION_RING_CAP};

    #[test]
    fn push_and_snapshot_roundtrip_under_cap() {
        let mut ring = SessionRing::new();
        ring.push(b"hello\n");
        ring.push(b"world\n");
        assert_eq!(ring.snapshot(), b"hello\nworld\n");
    }

    #[test]
    fn eviction_trims_from_the_front_on_a_newline_boundary() {
        let mut ring = SessionRing::new();
        // Fill well past the cap with distinct newline-terminated lines, then
        // check the tail survives and the front got dropped at a `\n`.
        for i in 0..(SESSION_RING_CAP / 8 + 100) {
            ring.push(format!("line-{i:04}\n").as_bytes());
        }
        let snap = ring.snapshot();
        assert!(snap.len() <= SESSION_RING_CAP);
        // Never starts mid-line: either empty, or the byte right after the
        // start is the beginning of a "line-" entry (i.e. no partial prefix
        // of a line at the very front).
        assert!(snap.starts_with(b"line-") || snap.is_empty());
        // The most recent line must still be present.
        let last_line = format!("line-{:04}\n", SESSION_RING_CAP / 8 + 99);
        assert!(
            String::from_utf8_lossy(&snap).ends_with(&last_line),
            "expected snapshot to end with the most recent line"
        );
    }

    #[test]
    fn snapshot_is_empty_for_a_fresh_ring() {
        let ring = SessionRing::new();
        assert!(ring.snapshot().is_empty());
    }

    #[test]
    fn a_single_push_over_cap_with_no_newline_clears_rather_than_spins() {
        let mut ring = SessionRing::new();
        let huge = vec![b'x'; SESSION_RING_CAP + 10];
        ring.push(&huge);
        assert!(ring.snapshot().is_empty());
    }
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use iroh::endpoint::presets;
    use iroh::protocol::Router;
    use iroh::Endpoint;
    use tokio::io::BufReader;
    use tokio::time::timeout;

    use super::{TermHandler, TERM_ALPN};
    use crate::proto::{read_frame, write_frame, Frame};

    /// End-to-end test for the remote-shell-over-iroh path.
    ///
    /// Two real iroh endpoints are created in-process:
    ///   - a **server** that accepts connections with `TermHandler` on `TERM_ALPN`
    ///   - a **client** that connects to the server's direct address, opens a
    ///     bi-directional stream, and sends a shell command
    ///
    /// The test asserts that the unique marker string appears in the PTY output
    /// that comes back as `Frame::Term` frames, proving the full
    /// PTY-spawn → bridge → iroh-stream → frame path.
    #[tokio::test]
    async fn term_handler_end_to_end() {
        // A unique marker that every POSIX shell can echo and that is very
        // unlikely to appear in shell startup noise.
        const MARKER: &str = "AZULA_LIVE_OK_7F3A";

        // ── Server ─────────────────────────────────────────────────────────
        // Use `presets::Minimal` (no public relays / STUN needed) for a
        // purely local, loopback test.
        let server_ep = Endpoint::bind(presets::Minimal)
            .await
            .expect("server endpoint bind");

        let server_addr = server_ep.addr();
        let server_id = server_ep.id();

        let router = Router::builder(server_ep)
            .accept(TERM_ALPN, TermHandler::new(server_id, true, None, None, Some(Duration::from_secs(60 * 60))))
            .spawn();

        // ── Client ─────────────────────────────────────────────────────────
        let client_ep = Endpoint::bind(presets::Minimal)
            .await
            .expect("client endpoint bind");

        // Connect directly to the server's local address — no relay/ticket needed.
        let conn = client_ep
            .connect(server_addr, TERM_ALPN)
            .await
            .expect("client connect");

        // The protocol requires the dialer to write first (server does
        // `accept_bi`, which blocks until the client sends data).
        let (mut send, recv) = conn.open_bi().await.expect("open_bi");

        // Write the echo command.  The PTY will echo the typed text and then
        // print the command's output, both as `Frame::Term` chunks.
        write_frame(
            &mut send,
            &Frame::Input {
                text: format!("echo {MARKER}\n"),
            },
        )
        .await
        .expect("write frame");

        // ── Read frames until the marker appears (or timeout) ───────────────
        let mut reader = BufReader::new(recv);
        let mut accumulated = String::new();

        let read_result = timeout(Duration::from_secs(20), async {
            loop {
                match read_frame(&mut reader).await {
                    Ok(Some(Frame::Term { line })) => {
                        accumulated.push_str(&line);
                        if accumulated.contains(MARKER) {
                            return Ok::<(), anyhow::Error>(());
                        }
                    }
                    Ok(Some(_)) => {} // ignore other frame types
                    Ok(None) => {
                        // Stream closed before we saw the marker.
                        anyhow::bail!("stream closed before marker appeared; got: {accumulated:?}");
                    }
                    Err(e) => {
                        anyhow::bail!("read_frame error: {e}; got so far: {accumulated:?}");
                    }
                }
            }
        })
        .await;

        // ── Cleanup ─────────────────────────────────────────────────────────
        let _ = send.finish();
        conn.close(0u32.into(), b"done");
        let _ = router.shutdown().await;
        client_ep.close().await;

        // ── Assert ───────────────────────────────────────────────────────────
        match read_result {
            Err(_elapsed) => panic!(
                "timed out waiting for marker '{MARKER}'; output so far: {accumulated:?}"
            ),
            Ok(Err(e)) => panic!("{e}"),
            Ok(Ok(())) => {
                // Success: the marker was found in the PTY output.
                println!("Captured PTY output (first 512 chars): {:?}",
                    &accumulated[..accumulated.len().min(512)]);
            }
        }
    }

    /// Two bi streams over ONE connection each get their own PTY — proving the
    /// remote shell multiplexes many terminals over a single connection.
    #[tokio::test]
    async fn term_two_sessions_over_one_connection() {
        let server_ep = Endpoint::bind(presets::Minimal).await.expect("server bind");
        let server_addr = server_ep.addr();
        let server_id = server_ep.id();
        let router = Router::builder(server_ep)
            .accept(TERM_ALPN, TermHandler::new(server_id, true, None, None, Some(Duration::from_secs(60 * 60))))
            .spawn();

        let client_ep = Endpoint::bind(presets::Minimal).await.expect("client bind");
        let conn = client_ep.connect(server_addr, TERM_ALPN).await.expect("connect");

        async fn run_echo(conn: &iroh::endpoint::Connection, marker: &str) -> bool {
            let (mut send, recv) = conn.open_bi().await.expect("open_bi");
            write_frame(&mut send, &Frame::Input { text: format!("echo {marker}\n") })
                .await
                .expect("write");
            let mut reader = BufReader::new(recv);
            let got = timeout(Duration::from_secs(20), async {
                let mut acc = String::new();
                loop {
                    match read_frame(&mut reader).await {
                        Ok(Some(Frame::Term { line })) => {
                            acc.push_str(&line);
                            if acc.contains(marker) {
                                return true;
                            }
                        }
                        Ok(Some(_)) => {}
                        Ok(None) | Err(_) => return false,
                    }
                }
            })
            .await
            .unwrap_or(false);
            let _ = send.finish();
            got
        }

        // Two independent sessions multiplexed on the SAME connection.
        let a = run_echo(&conn, "AZULA_SESS_A_11AA").await;
        let b = run_echo(&conn, "AZULA_SESS_B_22BB").await;

        conn.close(0u32.into(), b"done");
        let _ = router.shutdown().await;
        client_ep.close().await;

        assert!(a, "session A did not receive its marker over its own stream");
        assert!(b, "session B (2nd stream on the same connection) did not receive its marker");
    }

    /// A terminal connection announces its identity as a `Frame::Profile`
    /// before any `Frame::Term` shell output, and `--name`/`--description`
    /// overrides passed to `TermHandler::new` end up in that frame verbatim.
    #[tokio::test]
    async fn term_session_sends_profile_before_term_output() {
        let server_ep = Endpoint::bind(presets::Minimal).await.expect("server bind");
        let server_addr = server_ep.addr();
        let server_id = server_ep.id();
        let router = Router::builder(server_ep)
            .accept(
                TERM_ALPN,
                TermHandler::new(server_id, true, Some("Foo".to_string()), Some("/bar".to_string()), Some(Duration::from_secs(60 * 60))),
            )
            .spawn();

        let client_ep = Endpoint::bind(presets::Minimal).await.expect("client bind");
        let conn = client_ep.connect(server_addr, TERM_ALPN).await.expect("connect");
        let (mut send, recv) = conn.open_bi().await.expect("open_bi");
        write_frame(&mut send, &Frame::Input { text: "echo hi\n".to_string() })
            .await
            .expect("write");

        let mut reader = BufReader::new(recv);
        let first = timeout(Duration::from_secs(20), read_frame(&mut reader))
            .await
            .expect("timed out waiting for the first frame")
            .expect("read_frame errored")
            .expect("stream closed before any frame arrived");

        let _ = send.finish();
        conn.close(0u32.into(), b"done");
        let _ = router.shutdown().await;
        client_ep.close().await;

        match first {
            Frame::Profile { name, description, avatar, mime } => {
                assert_eq!(name, "Foo", "name override was not applied");
                assert_eq!(description.as_deref(), Some("/bar"), "description override was not applied");
                assert_eq!(avatar, None);
                assert_eq!(mime, None);
            }
            other => panic!("expected the first frame to be a Profile, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Persistent-session tests (Feature 5).
    // -----------------------------------------------------------------------

    /// Spins up a server + client endpoint pair. Returns the router (drop /
    /// shutdown when done) and a connected `Connection`.
    async fn start_server_and_connect(
        ttl: Option<Duration>,
    ) -> (Router, iroh::endpoint::Connection, Endpoint) {
        let server_ep = Endpoint::bind(presets::Minimal).await.expect("server bind");
        let server_addr = server_ep.addr();
        let server_id = server_ep.id();
        let router = Router::builder(server_ep)
            .accept(TERM_ALPN, TermHandler::new(server_id, true, None, None, ttl))
            .spawn();

        let client_ep = Endpoint::bind(presets::Minimal).await.expect("client bind");
        let conn = client_ep.connect(server_addr, TERM_ALPN).await.expect("connect");
        (router, conn, client_ep)
    }

    /// Reads frames off `reader` until `f` returns `Some`, or `MARKER`-style
    /// timeout elapses.
    async fn read_until<T>(
        reader: &mut BufReader<iroh::endpoint::RecvStream>,
        mut f: impl FnMut(&Frame) -> Option<T>,
    ) -> Option<T> {
        timeout(Duration::from_secs(20), async {
            loop {
                match read_frame(reader).await {
                    Ok(Some(frame)) => {
                        if let Some(v) = f(&frame) {
                            return Some(v);
                        }
                    }
                    Ok(None) | Err(_) => return None,
                }
            }
        })
        .await
        .unwrap_or(None)
    }

    /// A brand new `TermAttach { session: None }` creates a persistent
    /// session: the server replies `term_session { resumed: false }` with a
    /// fresh id, and the shell works normally.
    #[tokio::test]
    async fn attach_new_creates_a_persistent_session() {
        let (router, conn, client_ep) = start_server_and_connect(Some(Duration::from_secs(3600))).await;

        let (mut send, recv) = conn.open_bi().await.expect("open_bi");
        write_frame(&mut send, &Frame::TermAttach { session: None }).await.expect("write");

        let mut reader = BufReader::new(recv);
        // First frame is the Profile (send_profile is per-connection first stream).
        let sess = read_until(&mut reader, |f| match f {
            Frame::TermSession { session, resumed } => Some((session.clone(), *resumed)),
            _ => None,
        })
        .await
        .expect("expected a term_session frame");
        assert!(!sess.1, "a brand new session must not be marked resumed");
        assert!(!sess.0.is_empty());

        write_frame(&mut send, &Frame::Input { text: "echo AZULA_ATTACH_NEW_1\n".to_string() })
            .await
            .expect("write");
        let saw_marker = read_until(&mut reader, |f| match f {
            Frame::Term { line } if line.contains("AZULA_ATTACH_NEW_1") => Some(()),
            _ => None,
        })
        .await;
        assert!(saw_marker.is_some(), "expected the echoed marker in Term output");

        let _ = send.finish();
        conn.close(0u32.into(), b"done");
        // The session is still alive (ttl enabled, never detached-and-reaped
        // in this test) — kill it before shutdown or the runtime's teardown
        // blocks forever waiting for its PTY-reader thread to join. See
        // `kill_session`'s doc comment for why this is per-id, not the
        // blunt `kill_all_sessions`.
        super::kill_session(&sess.0);
        let _ = router.shutdown().await;
        client_ep.close().await;
    }

    /// Detach (end the stream) then reattach with the returned session id on
    /// a NEW stream (same connection): the marker from a command run BEFORE
    /// detaching shows up in the replay, without re-running anything.
    #[tokio::test]
    async fn detach_reattach_replays_scrollback_without_rerunning() {
        let (router, conn, client_ep) = start_server_and_connect(Some(Duration::from_secs(3600))).await;

        let session_id = {
            let (mut send, recv) = conn.open_bi().await.expect("open_bi");
            write_frame(&mut send, &Frame::TermAttach { session: None }).await.expect("write");
            let mut reader = BufReader::new(recv);
            let (id, _resumed) = read_until(&mut reader, |f| match f {
                Frame::TermSession { session, resumed } => Some((session.clone(), *resumed)),
                _ => None,
            })
            .await
            .expect("expected term_session");

            write_frame(&mut send, &Frame::Input { text: "echo AZULA_REPLAY_MARKER_9\n".to_string() })
                .await
                .expect("write");
            let saw = read_until(&mut reader, |f| match f {
                Frame::Term { line } if line.contains("AZULA_REPLAY_MARKER_9") => Some(()),
                _ => None,
            })
            .await;
            assert!(saw.is_some(), "expected the marker before detaching");

            let _ = send.finish(); // detach: end the stream without killing the PTY
            id
        };

        // Give the server a moment to process the stream-end and mark the
        // session detached before we reattach.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let (mut send2, recv2) = conn.open_bi().await.expect("open_bi (reattach)");
        write_frame(&mut send2, &Frame::TermAttach { session: Some(session_id.clone()) })
            .await
            .expect("write attach");
        let mut reader2 = BufReader::new(recv2);
        let (id2, resumed2) = read_until(&mut reader2, |f| match f {
            Frame::TermSession { session, resumed } => Some((session.clone(), *resumed)),
            _ => None,
        })
        .await
        .expect("expected term_session on reattach");
        assert_eq!(id2, session_id, "reattach must resume the SAME session id");
        assert!(resumed2, "reattach must be marked resumed");

        // The marker must show up from the REPLAY — i.e. without sending any
        // new Input at all.
        let replayed = read_until(&mut reader2, |f| match f {
            Frame::Term { line } if line.contains("AZULA_REPLAY_MARKER_9") => Some(()),
            _ => None,
        })
        .await;
        assert!(replayed.is_some(), "expected the marker to be replayed on reattach");

        let _ = send2.finish();
        conn.close(0u32.into(), b"done");
        super::kill_session(&session_id); // still alive — see kill_session's doc comment.
        let _ = router.shutdown().await;
        client_ep.close().await;
    }

    /// Reattaching from a FRESH connection (new `Endpoint`, same node key)
    /// still resumes the same session — persistence survives a full
    /// reconnect, not just a new stream on the same connection.
    #[tokio::test]
    async fn reattach_across_connections_with_same_owner_key() {
        let server_ep = Endpoint::bind(presets::Minimal).await.expect("server bind");
        let server_addr = server_ep.addr();
        let server_id = server_ep.id();
        let router = Router::builder(server_ep)
            .accept(TERM_ALPN, TermHandler::new(server_id, true, None, None, Some(Duration::from_secs(3600))))
            .spawn();

        // First connection: create the session.
        let client_secret = iroh::SecretKey::generate();
        let client_ep1 = Endpoint::builder(presets::Minimal)
            .secret_key(client_secret.clone())
            .bind()
            .await
            .expect("client1 bind");
        let conn1 = client_ep1.connect(server_addr.clone(), TERM_ALPN).await.expect("connect1");

        let session_id = {
            let (mut send, recv) = conn1.open_bi().await.expect("open_bi");
            write_frame(&mut send, &Frame::TermAttach { session: None }).await.expect("write");
            let mut reader = BufReader::new(recv);
            let (id, _r) = read_until(&mut reader, |f| match f {
                Frame::TermSession { session, resumed } => Some((session.clone(), *resumed)),
                _ => None,
            })
            .await
            .expect("expected term_session");
            let _ = send.finish();
            id
        };
        conn1.close(0u32.into(), b"done");
        client_ep1.close().await;

        // Second, brand new Endpoint using the SAME secret key (same
        // EndpointId) reattaches.
        let client_ep2 = Endpoint::builder(presets::Minimal)
            .secret_key(client_secret)
            .bind()
            .await
            .expect("client2 bind");
        let conn2 = client_ep2.connect(server_addr, TERM_ALPN).await.expect("connect2");
        let (mut send2, recv2) = conn2.open_bi().await.expect("open_bi 2");
        write_frame(&mut send2, &Frame::TermAttach { session: Some(session_id.clone()) })
            .await
            .expect("write attach");
        let mut reader2 = BufReader::new(recv2);
        let (id2, resumed2) = read_until(&mut reader2, |f| match f {
            Frame::TermSession { session, resumed } => Some((session.clone(), *resumed)),
            _ => None,
        })
        .await
        .expect("expected term_session on cross-connection reattach");

        assert_eq!(id2, session_id);
        assert!(resumed2, "a fresh connection with the same key must still resume");

        let _ = send2.finish();
        conn2.close(0u32.into(), b"done");
        super::kill_session(&session_id); // still alive — see kill_session's doc comment.
        let _ = router.shutdown().await;
        client_ep2.close().await;
    }

    /// A client that never sends `TermAttach` gets the exact legacy
    /// behavior: no `term_session`/`term_exit` frames ever appear, just plain
    /// `Frame::Term` output (covered fully by `term_handler_end_to_end`
    /// above, which is unmodified). This test additionally confirms the
    /// session registry stays empty for a legacy connection.
    #[tokio::test]
    async fn legacy_client_never_creates_a_registry_entry() {
        let (router, conn, client_ep) = start_server_and_connect(Some(Duration::from_secs(3600))).await;

        let (mut send, recv) = conn.open_bi().await.expect("open_bi");
        write_frame(&mut send, &Frame::Input { text: "echo AZULA_LEGACY_NO_REGISTRY\n".to_string() })
            .await
            .expect("write");
        let mut reader = BufReader::new(recv);
        let saw = read_until(&mut reader, |f| match f {
            Frame::Term { line } if line.contains("AZULA_LEGACY_NO_REGISTRY") => Some(()),
            _ => None,
        })
        .await;
        assert!(saw.is_some());

        // No term_session frame should ever have been sent for this stream —
        // best-effort check: read a tiny bit more with a short timeout and
        // confirm nothing but Term frames arrive.
        let unexpected = timeout(Duration::from_millis(300), read_frame(&mut reader)).await;
        if let Ok(Ok(Some(frame))) = unexpected {
            assert!(
                matches!(frame, Frame::Term { .. }),
                "legacy stream must never see a term_session/term_exit frame, got {frame:?}"
            );
        }

        let _ = send.finish();
        conn.close(0u32.into(), b"done");
        let _ = router.shutdown().await;
        client_ep.close().await;
    }

    /// `--session-ttl 0` (`ttl: None`) still honors the `TermAttach`
    /// handshake, but a detach kills the PTY immediately instead of leaving
    /// it around — a reattach afterward gets a brand new session
    /// (`resumed: false`), not a replay of the old one.
    #[tokio::test]
    async fn session_ttl_zero_kills_on_detach_instead_of_persisting() {
        let (router, conn, client_ep) = start_server_and_connect(None).await;

        let session_id = {
            let (mut send, recv) = conn.open_bi().await.expect("open_bi");
            write_frame(&mut send, &Frame::TermAttach { session: None }).await.expect("write");
            let mut reader = BufReader::new(recv);
            let (id, resumed) = read_until(&mut reader, |f| match f {
                Frame::TermSession { session, resumed } => Some((session.clone(), *resumed)),
                _ => None,
            })
            .await
            .expect("expected term_session even with ttl disabled");
            assert!(!resumed);
            let _ = send.finish();
            id
        };

        tokio::time::sleep(Duration::from_millis(200)).await;

        let (mut send2, recv2) = conn.open_bi().await.expect("open_bi 2");
        write_frame(&mut send2, &Frame::TermAttach { session: Some(session_id.clone()) })
            .await
            .expect("write attach");
        let mut reader2 = BufReader::new(recv2);
        let (id2, resumed2) = read_until(&mut reader2, |f| match f {
            Frame::TermSession { session, resumed } => Some((session.clone(), *resumed)),
            _ => None,
        })
        .await
        .expect("expected term_session on the second attempt");

        assert_ne!(id2, session_id, "the old session must be gone, not resumed");
        assert!(!resumed2, "--session-ttl 0 must never resume across a detach");

        let _ = send2.finish();
        conn.close(0u32.into(), b"done");
        let _ = router.shutdown().await;
        client_ep.close().await;
    }

    /// When the shell process exits, the currently attached stream gets a
    /// `Frame::TermExit`, and the session disappears from the registry (a
    /// later attach with the same id creates a fresh session).
    #[tokio::test]
    async fn shell_exit_sends_term_exit_and_removes_session() {
        let (router, conn, client_ep) = start_server_and_connect(Some(Duration::from_secs(3600))).await;

        let (mut send, recv) = conn.open_bi().await.expect("open_bi");
        write_frame(&mut send, &Frame::TermAttach { session: None }).await.expect("write");
        let mut reader = BufReader::new(recv);
        let (session_id, _resumed) = read_until(&mut reader, |f| match f {
            Frame::TermSession { session, resumed } => Some((session.clone(), *resumed)),
            _ => None,
        })
        .await
        .expect("expected term_session");

        // Ask the shell to exit outright.
        write_frame(&mut send, &Frame::Input { text: "exit\n".to_string() }).await.expect("write exit");

        let exit_frame = read_until(&mut reader, |f| match f {
            Frame::TermExit { session, .. } if *session == session_id => Some(()),
            _ => None,
        })
        .await;
        assert!(exit_frame.is_some(), "expected a term_exit frame after the shell exited");

        let _ = send.finish();
        conn.close(0u32.into(), b"done");
        let _ = router.shutdown().await;
        client_ep.close().await;
    }

    /// A different peer (different node key) presenting the same session id
    /// never resumes another owner's session — it silently gets a fresh one.
    #[tokio::test]
    async fn owner_check_prevents_cross_peer_attach() {
        let server_ep = Endpoint::bind(presets::Minimal).await.expect("server bind");
        let server_addr = server_ep.addr();
        let server_id = server_ep.id();
        let router = Router::builder(server_ep)
            .accept(TERM_ALPN, TermHandler::new(server_id, true, None, None, Some(Duration::from_secs(3600))))
            .spawn();

        let owner_ep = Endpoint::bind(presets::Minimal).await.expect("owner bind");
        let owner_conn = owner_ep.connect(server_addr.clone(), TERM_ALPN).await.expect("owner connect");
        let session_id = {
            let (mut send, recv) = owner_conn.open_bi().await.expect("open_bi");
            write_frame(&mut send, &Frame::TermAttach { session: None }).await.expect("write");
            let mut reader = BufReader::new(recv);
            let (id, _r) = read_until(&mut reader, |f| match f {
                Frame::TermSession { session, resumed } => Some((session.clone(), *resumed)),
                _ => None,
            })
            .await
            .expect("expected term_session");
            let _ = send.finish();
            id
        };

        let stranger_ep = Endpoint::bind(presets::Minimal).await.expect("stranger bind");
        let stranger_conn = stranger_ep.connect(server_addr, TERM_ALPN).await.expect("stranger connect");
        let (mut send2, recv2) = stranger_conn.open_bi().await.expect("open_bi stranger");
        write_frame(&mut send2, &Frame::TermAttach { session: Some(session_id.clone()) })
            .await
            .expect("write attach");
        let mut reader2 = BufReader::new(recv2);
        let (id2, resumed2) = read_until(&mut reader2, |f| match f {
            Frame::TermSession { session, resumed } => Some((session.clone(), *resumed)),
            _ => None,
        })
        .await
        .expect("expected term_session for the stranger too");

        assert_ne!(id2, session_id, "a different owner must never resume someone else's session");
        assert!(!resumed2);

        let _ = send2.finish();
        owner_conn.close(0u32.into(), b"done");
        stranger_conn.close(0u32.into(), b"done");
        // Both sessions still alive — see kill_session's doc comment for why
        // this is per-id rather than the blunt kill_all_sessions.
        super::kill_session(&session_id);
        super::kill_session(&id2);
        let _ = router.shutdown().await;
        owner_ep.close().await;
        stranger_ep.close().await;
    }

    /// Reproduces the azula app's real wire shape for a KNOWN peer: every
    /// dialed stream starts with `Frame::Hello` (`ConnectService.ping()`)
    /// before the actual `Frame::TermAttach` (`wireConv`). Pre-registering the
    /// client's node id makes the server treat it as known from its very
    /// first stream, so the accept gate never runs and `term_session`'s own
    /// leading-frame read is what has to see past the Hello — this is
    /// exactly the bug: a known peer's reconnect used to fall through to
    /// `legacy_bridge` (fresh shell, no resume) because the Hello masked the
    /// TermAttach behind it.
    #[tokio::test]
    async fn known_peer_hello_then_term_attach_still_resumes() {
        use crate::registry::{self, Device};

        // Holds ENV_TEST_LOCK for the whole body — see its doc comment: this
        // mutates the process-global AZULA_REGISTRY_DIR, which other tests
        // (accept_gate.rs, bridge/tests.rs) also mutate under the same lock.
        let _guard = registry::ENV_TEST_LOCK.lock().await;
        let registry_dir = std::env::temp_dir()
            .join(format!("azula-term-test-{}", std::process::id()))
            .join("known_peer_hello");
        let _ = std::fs::remove_dir_all(&registry_dir);
        std::env::set_var("AZULA_REGISTRY_DIR", &registry_dir);

        let server_ep = Endpoint::bind(presets::Minimal).await.expect("server bind");
        let server_addr = server_ep.addr();
        let server_id = server_ep.id();

        let client_ep = Endpoint::bind(presets::Minimal).await.expect("client bind");
        let client_id = client_ep.id();

        // Register the client as a known device BEFORE it ever connects, so
        // `known` is true on its very first stream (see `handle`'s
        // `registry::find_by_node_id` check) — no invite, no gate, exactly
        // like a device that paired in a previous session.
        registry::add(
            Device { name: "known-term-peer".to_string(), ticket: client_id.to_string(), added_at: None, invite: None },
            false,
        )
        .expect("register known device");

        let router = Router::builder(server_ep)
            .accept(TERM_ALPN, TermHandler::new(server_id, true, None, None, Some(Duration::from_secs(3600))))
            .spawn();

        let conn = client_ep.connect(server_addr, TERM_ALPN).await.expect("connect");

        // ── First stream: Hello, then TermAttach{None} ──────────────────────
        let (mut send, recv) = conn.open_bi().await.expect("open_bi");
        write_frame(&mut send, &Frame::Hello { name: "client".to_string(), invite: None, cert: None })
            .await
            .expect("write hello");
        write_frame(&mut send, &Frame::TermAttach { session: None }).await.expect("write attach");

        let mut reader = BufReader::new(recv);
        let sess = read_until(&mut reader, |f| match f {
            Frame::TermSession { session, resumed } => Some((session.clone(), *resumed)),
            _ => None,
        })
        .await
        .expect("expected a term_session frame even with a known peer's leading Hello");
        assert!(!sess.1, "a brand new session must not be marked resumed");

        write_frame(&mut send, &Frame::Input { text: "echo AZULA_KNOWN_HELLO_MARKER\n".to_string() })
            .await
            .expect("write");
        let saw_marker = read_until(&mut reader, |f| match f {
            Frame::Term { line } if line.contains("AZULA_KNOWN_HELLO_MARKER") => Some(()),
            _ => None,
        })
        .await;
        assert!(saw_marker.is_some(), "expected the echoed marker in Term output — session must be a real working shell, not the legacy path");

        let _ = send.finish(); // detach: end the stream without killing the PTY
        tokio::time::sleep(Duration::from_millis(200)).await;

        // ── Second stream (same connection, still "known"): Hello, then
        // TermAttach{Some(id)} ───────────────────────────────────────────────
        let (mut send2, recv2) = conn.open_bi().await.expect("open_bi reattach");
        write_frame(&mut send2, &Frame::Hello { name: "client".to_string(), invite: None, cert: None })
            .await
            .expect("write hello 2");
        write_frame(&mut send2, &Frame::TermAttach { session: Some(sess.0.clone()) })
            .await
            .expect("write attach 2");

        let mut reader2 = BufReader::new(recv2);
        let (id2, resumed2) = read_until(&mut reader2, |f| match f {
            Frame::TermSession { session, resumed } => Some((session.clone(), *resumed)),
            _ => None,
        })
        .await
        .expect("expected term_session on reattach");
        assert_eq!(id2, sess.0, "a known peer's Hello-then-TermAttach reattach must resume the SAME session");
        assert!(resumed2, "reattach must be marked resumed");

        // The marker must show up from the REPLAY — i.e. without sending any
        // new Input at all — proving scrollback survived the detach.
        let replayed = read_until(&mut reader2, |f| match f {
            Frame::Term { line } if line.contains("AZULA_KNOWN_HELLO_MARKER") => Some(()),
            _ => None,
        })
        .await;
        assert!(replayed.is_some(), "expected the marker to be replayed on reattach, without re-running it");

        let _ = send2.finish();
        conn.close(0u32.into(), b"done");
        super::kill_session(&sess.0); // still alive — see kill_session's doc comment.
        let _ = router.shutdown().await;
        client_ep.close().await;

        std::env::remove_var("AZULA_REGISTRY_DIR");
    }
}
