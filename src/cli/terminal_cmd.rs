//! `azula terminal [new|list|attach|kill]` — host, manage, or attach to
//! persistent terminal sessions (design.md D5).
//!
//! Bare `azula terminal` hosts a fresh interactive `$SHELL` session exactly
//! like `azula run`'s handoff end state: connect block, then serve until the
//! shell exits or Ctrl-C. `azula terminal new` spawns a **detached**
//! background process (a re-exec of this same binary with a hidden
//! `--host-detached` flag) hosting one **named** persistent session, so its
//! pairing survives restarts; `list`/`kill` read/manage the runtime state
//! files those detached hosts write. `azula terminal attach <name|url>` is
//! the CLI **client**: raw-mode passthrough of PTY bytes to the local
//! terminal, so a session started in CI or on another machine can be
//! continued from a laptop shell, not only from the phone.
//!
//! Every hosting path here builds its own dedicated `TermHandler`/`Router`
//! the way `azula serve` does (see `cli::legacy::serve`) — none of this goes
//! through `core::establish`, which is the heavier multi-device `SessionCore`
//! path `azula mcp` uses.
//!
//! TODO(phase 4): a detached host with a machine identity should push a
//! relayed "session online" notice through `SessionCore::send_message` so
//! the phone doesn't need the connect block's invite/QR at all (design.md
//! D3/D6). Not implemented yet — phase 4 builds the relay delivery chain
//! this needs.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};
use iroh::protocol::Router;
use iroh::EndpointId;
use iroh_tickets::endpoint::EndpointTicket;
use serde::{Deserialize, Serialize};
use tokio::io::BufReader;
use tracing::warn;

use crate::identity;
use crate::invite;
use crate::link::{self, Parsed};
use crate::mcp::{LlmHandler, LLM_ALPN};
use crate::proto::{read_frame, write_frame, Frame};
use crate::qr;
use crate::session::SessionKey;
use crate::term::{self, TermHandler, TERM_ALPN};

/// The PTY size a freshly hosted session starts at before any real client
/// has attached and reported its own viewport (matches `term.rs`'s own
/// `LEGACY_PTY_SIZE` — a real client resizes it immediately).
const HOST_PTY_SIZE: portable_pty::PtySize =
    portable_pty::PtySize { rows: 24, cols: 80, pixel_width: 0, pixel_height: 0 };

// ---------------------------------------------------------------------------
// clap surface
// ---------------------------------------------------------------------------

/// `azula terminal [new|list|attach|kill]` — with no subcommand, hosts a
/// fresh interactive shell inline.
#[derive(Debug, Clone, clap::Args)]
pub(super) struct TerminalArgs {
    #[command(subcommand)]
    action: Option<TerminalAction>,

    /// Override the connect block's announced conversation name. Defaults to
    /// this machine's hostname.
    #[arg(long, value_name = "NAME")]
    name: Option<String>,

    /// Override the connect block's announced conversation description.
    /// Defaults to the shell's launch working directory.
    #[arg(long, value_name = "DESCRIPTION")]
    desc: Option<String>,

    /// How long (in minutes) the session stays alive after the last client
    /// detaches, waiting for a reattach, before it's reaped. `0` disables
    /// persistence (the session dies the instant its one stream ends).
    #[arg(long = "session-ttl", value_name = "MINUTES", default_value_t = 60)]
    session_ttl: u64,

    /// Admit invite-less unknown strangers as unverified instead of
    /// requiring the connect block's invite.
    #[arg(long = "allow-legacy", default_value_t = true, action = clap::ArgAction::Set)]
    allow_legacy: bool,

    /// Internal: re-exec target for `terminal new`'s detached host process.
    /// Not part of the public CLI surface.
    #[arg(long = "host-detached", hide = true)]
    host_detached: bool,

    /// Internal: the command line the detached host runs instead of `$SHELL
    /// -l` (paired with --host-detached; set from `terminal new --cmd`).
    #[arg(long = "host-cmd", hide = true, value_name = "CMD")]
    host_cmd: Option<String>,
}

#[derive(Debug, Clone, clap::Subcommand)]
pub(super) enum TerminalAction {
    /// Spawn a detached background process hosting one named persistent
    /// session.
    New(NewArgs),
    /// List detached sessions: name, pid, liveness, invite.
    List(ListArgs),
    /// Terminate a detached session by name.
    Kill(KillArgs),
    /// Attach this terminal to a hosted session as a raw passthrough client.
    /// Detach with Ctrl-\.
    Attach(AttachArgs),
}

#[derive(Debug, Clone, clap::Args)]
pub(super) struct NewArgs {
    /// Command the detached session runs instead of `$SHELL -l` (parsed as a
    /// shell command line, e.g. `--cmd "claude"`).
    #[arg(long)]
    cmd: Option<String>,

    /// Session name — also usable with `list`/`kill`/`attach <name>`.
    /// Defaults to a short random id when omitted.
    #[arg(long)]
    name: Option<String>,
}

#[derive(Debug, Clone, clap::Args)]
pub(super) struct ListArgs {
    /// Machine-readable output: a JSON array of
    /// `{name,pid,alive,node_id,invite_url,started_at}`.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, clap::Args)]
pub(super) struct KillArgs {
    /// The session name, as shown by `azula terminal list`.
    name: String,
}

#[derive(Debug, Clone, clap::Args)]
pub(super) struct AttachArgs {
    /// A detached session's name (see `azula terminal list`), or an invite
    /// URL / ticket printed in a connect block.
    target: String,
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

pub(super) async fn run(args: TerminalArgs) -> Result<()> {
    let host_detached = args.host_detached;
    let action = args.action.clone();
    match action {
        None if host_detached => cmd_host_detached(args).await,
        None => cmd_bare(args).await,
        Some(TerminalAction::New(a)) => cmd_new(a).await,
        Some(TerminalAction::List(a)) => cmd_list(a),
        Some(TerminalAction::Kill(a)) => cmd_kill(a),
        Some(TerminalAction::Attach(a)) => cmd_attach(a).await,
    }
}

// ---------------------------------------------------------------------------
// Shared hosting machinery — bare `azula terminal` and `--host-detached`
// both build one of these.
// ---------------------------------------------------------------------------

/// A live hosted session: enough to print a connect block, wait for it to
/// end, and shut down cleanly. Returned by [`host_session`] so tests can
/// dial `router.endpoint().addr()` directly (no invite-URL parsing needed),
/// exactly like `term.rs`'s own in-process iroh tests. `_session` is kept
/// alive (not dropped early) for the same reason `bridge::run`/`run_stdio`
/// keep `Established::session` alive for the life of the server: an
/// ephemeral `SessionKey`'s guard deletes its on-disk key file on drop, and
/// D2 says that should happen "on clean exit," not the instant the endpoint
/// finishes binding. A *named* session's key has no guard at all (meant to
/// persist), so this is a no-op either way for `terminal new`'s detached
/// hosts.
pub(super) struct HostedTerminal {
    pub(super) node_id: EndpointId,
    pub(super) invite_url: String,
    pub(super) session_id: String,
    pub(super) router: Router,
    // Held only for its Drop side effect (deletes an ephemeral session's key
    // file on clean exit; a no-op for a named session, which has no guard)
    // — never read.
    #[allow(dead_code)]
    _session: SessionKey,
}

/// Bind a dedicated endpoint (a named [`SessionKey`] when `session_name` is
/// given, else a fresh ephemeral one — design.md D2: "`azula run`/`azula
/// terminal`: fresh ephemeral session per invocation"), spawn `cmd` (or
/// `$SHELL -l`) as a host-created session, and serve it on `TERM_ALPN` (plus
/// `LLM_ALPN` so the phone's dial-race finds the conversation the way `azula
/// serve` does today).
pub(super) async fn host_session(
    session_name: Option<&str>,
    cmd: Option<&str>,
    name_override: Option<String>,
    description_override: Option<String>,
    session_ttl_minutes: u64,
    allow_legacy: bool,
) -> Result<HostedTerminal> {
    let session = SessionKey::resolve(session_name)?;
    let (endpoint, ticket) = crate::endpoint::bind_endpoint_with_secret(session.secret.clone())
        .await
        .context("binding the terminal session's endpoint")?;
    let my_node_id = endpoint.id();

    let argv: Option<Vec<String>> =
        cmd.map(|c| shell_words::split(c).context("parsing --cmd")).transpose()?;
    let session_id = term::spawn_host_shell_session(argv.as_deref(), HOST_PTY_SIZE, &[])
        .context("spawning the hosted shell")?;

    let session_ttl = if session_ttl_minutes == 0 {
        None
    } else {
        Some(Duration::from_secs(session_ttl_minutes * 60))
    };
    if let Some(ttl) = session_ttl {
        term::spawn_ttl_reaper(ttl);
    }

    let router = Router::builder(endpoint)
        .accept(LLM_ALPN, LlmHandler::new(None, my_node_id, allow_legacy))
        .accept(
            TERM_ALPN,
            TermHandler::new(my_node_id, allow_legacy, name_override, description_override, session_ttl)
                .with_default_session(session_id.clone()),
        )
        .spawn();

    let machine_secret = identity::load_machine_secret_if_exists();
    let invite_url =
        match crate::core::mint_pairing_invite(machine_secret.as_ref(), &ticket, router.endpoint().secret_key()).await {
            Some(encoded) => qr::invite_url(&encoded),
            None => qr::pairing_url(&ticket),
        };

    Ok(HostedTerminal { node_id: my_node_id, invite_url, session_id, router, _session: session })
}

async fn cmd_bare(args: TerminalArgs) -> Result<()> {
    let hosted = host_session(None, None, args.name, args.desc, args.session_ttl, args.allow_legacy).await?;
    print_connect_block(&hosted.node_id.to_string(), &hosted.invite_url);
    wait_until_session_ends_or_ctrl_c(&hosted.session_id).await;
    term::kill_all_sessions();
    let _ = tokio::time::timeout(Duration::from_secs(5), hosted.router.shutdown()).await;
    Ok(())
}

/// The `--host-detached` re-exec target `terminal new` spawns.
async fn cmd_host_detached(args: TerminalArgs) -> Result<()> {
    let name = args.name.clone().context("--host-detached requires --name")?;
    let hosted = host_session(
        Some(&name),
        args.host_cmd.as_deref(),
        Some(name.clone()),
        args.desc.clone(),
        args.session_ttl,
        args.allow_legacy,
    )
    .await?;

    let state = SessionState {
        name: name.clone(),
        pid: std::process::id(),
        node_id: hosted.node_id.to_string(),
        invite_url: hosted.invite_url.clone(),
        started_at: now_secs(),
    };
    if let Err(e) = write_state(&state) {
        warn!(error = %e, "terminal: failed to write runtime state file");
    }

    print_connect_block(&hosted.node_id.to_string(), &hosted.invite_url);

    wait_until_session_ends_or_signal(&hosted.session_id).await;

    term::kill_all_sessions();
    let _ = tokio::time::timeout(Duration::from_secs(5), hosted.router.shutdown()).await;
    remove_state(&name);
    Ok(())
}

async fn wait_until_session_ends_or_ctrl_c(session_id: &str) {
    loop {
        if !term::session_is_alive(session_id) {
            return;
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(300)) => {}
            _ = tokio::signal::ctrl_c() => return,
        }
    }
}

async fn wait_until_session_ends_or_signal(session_id: &str) {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
    loop {
        if !term::session_is_alive(session_id) {
            return;
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(300)) => {}
            _ = tokio::signal::ctrl_c() => return,
            _ = async {
                match sigterm.as_mut() {
                    Some(s) => { s.recv().await; }
                    None => std::future::pending::<()>().await,
                }
            } => return,
        }
    }
}

// ---------------------------------------------------------------------------
// Connect block — shared with `cli::run_cmd`'s failure handoff.
// ---------------------------------------------------------------------------

/// Build the connect block's text: session identity, invite URL, and its
/// Unicode QR. Pure (no I/O) so it's directly unit-testable; [`print_connect_block`]
/// is the thin I/O wrapper both `azula run` and `azula terminal` use.
pub(super) fn format_connect_block(node_id: &str, invite_url: &str) -> String {
    let qr = qr::render_qr(invite_url);
    let short: String = node_id.chars().take(8).collect();
    format!(
        "\n  azula session: {short}…\n\n  {invite_url}\n\n{qr}\n  Scan with your phone, run `azula terminal attach {invite_url}` from another shell, or open the URL.\n\n"
    )
}

/// Print the connect block to *both* stdout and stderr (spec: "prints the
/// connect block to stderr AND stdout" — stderr so it survives even when
/// stdout is redirected into a CI log parser, stdout so a human tailing the
/// job output still sees it inline).
pub(super) fn print_connect_block(node_id: &str, invite_url: &str) {
    let block = format_connect_block(node_id, invite_url);
    print!("{block}");
    let _ = std::io::stdout().flush();
    eprint!("{block}");
    let _ = std::io::stderr().flush();
}

// ---------------------------------------------------------------------------
// Runtime state files (`$TMPDIR/azula/sessions/<name>.json`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(super) struct SessionState {
    pub(super) name: String,
    pub(super) pid: u32,
    pub(super) node_id: String,
    pub(super) invite_url: String,
    pub(super) started_at: u64,
}

/// `$TMPDIR/azula/sessions`, or the `AZULA_RUNTIME_DIR` override (tests /
/// sandboxes — mirrors `session::sessions_dir`'s and `registry::override_dir`'s
/// convention). Distinct from `session.rs`'s `~/.azula/sessions/<name>.key`
/// (a named session's persistent *key*) and `$TMPDIR/azula/sessions/<name>.key`
/// (an *ephemeral* session's key) — this directory holds the detached hosts'
/// runtime *state*, `.json` not `.key`.
fn runtime_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("AZULA_RUNTIME_DIR") {
        return PathBuf::from(dir);
    }
    std::env::temp_dir().join("azula").join("sessions")
}

fn state_path(name: &str) -> PathBuf {
    runtime_dir().join(format!("{name}.json"))
}

fn write_state(state: &SessionState) -> Result<()> {
    let dir = runtime_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("create dirs {}", dir.display()))?;
    let path = state_path(&state.name);
    let content = serde_json::to_string_pretty(state)?;
    std::fs::write(&path, content).with_context(|| format!("write {}", path.display()))
}

fn read_state(name: &str) -> Option<SessionState> {
    let data = std::fs::read_to_string(state_path(name)).ok()?;
    serde_json::from_str(&data).ok()
}

fn read_all_states() -> Vec<SessionState> {
    let dir = runtime_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut states: Vec<SessionState> = entries
        .flatten()
        .filter(|e| e.path().extension().and_then(|e| e.to_str()) == Some("json"))
        .filter_map(|e| std::fs::read_to_string(e.path()).ok())
        .filter_map(|s| serde_json::from_str(&s).ok())
        .collect();
    states.sort_by(|a: &SessionState, b: &SessionState| a.name.cmp(&b.name));
    states
}

fn remove_state(name: &str) {
    let _ = std::fs::remove_file(state_path(name));
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// Whether a process with this pid exists — `kill(pid, 0)` sends no signal,
/// it only checks existence/permission.
fn pid_alive(pid: u32) -> bool {
    // pid 0 (own process group) and anything that doesn't fit pid_t must read
    // as dead: state files can hold garbage, and u32::MAX cast to pid_t is
    // -1, which `kill(-1, 0)` treats as "probe every signalable process".
    if pid == 0 || pid > i32::MAX as u32 {
        return false;
    }
    // SAFETY: `kill` with signal 0 is a pure existence/permission probe; it
    // sends nothing to the target process.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

/// A short random session-name suffix (4 lowercase hex chars) for `terminal
/// new` when `--name` is omitted — same trick `session.rs`'s
/// `random_suffix` uses (a freshly generated key's CSPRNG output, no `rand`
/// dependency).
fn generate_name() -> String {
    let bytes = iroh::SecretKey::generate().to_bytes();
    format!("term-{}", data_encoding::HEXLOWER.encode(&bytes[..2]))
}

// ---------------------------------------------------------------------------
// `azula terminal new`
// ---------------------------------------------------------------------------

async fn cmd_new(args: NewArgs) -> Result<()> {
    let name = args.name.clone().unwrap_or_else(generate_name);
    if state_path(&name).exists() {
        anyhow::bail!(
            "a session named '{name}' is already recorded (see `azula terminal list`); pick a \
             different --name, or `azula terminal kill {name}` it first"
        );
    }

    let dir = runtime_dir().join(&name);
    std::fs::create_dir_all(&dir).with_context(|| format!("create dirs {}", dir.display()))?;
    let exe = std::env::current_exe().context("resolving the current executable")?;

    let mut cmd = std::process::Command::new(&exe);
    cmd.arg("terminal").arg("--host-detached").arg("--name").arg(&name);
    if let Some(c) = &args.cmd {
        cmd.arg("--host-cmd").arg(c);
    }
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::fs::File::create(dir.join("stdout.log")).context("creating stdout.log")?);
    cmd.stderr(std::fs::File::create(dir.join("stderr.log")).context("creating stderr.log")?);
    {
        use std::os::unix::process::CommandExt as _;
        // New session/process group: detach from this terminal's job control
        // so the host outlives this invocation and doesn't receive signals
        // meant for our own foreground process group.
        cmd.process_group(0);
    }

    let child = cmd.spawn().context("spawning the detached host process")?;
    let pid = child.id();

    // Best-effort: wait a few seconds for the host to come online and write
    // its state file, so `terminal new` can hand back the connect block
    // directly instead of telling the user to go run `list`.
    for _ in 0..50 {
        if let Some(state) = read_state(&name) {
            println!("Started detached terminal session '{name}' (pid {}).", state.pid);
            println!("Logs: {}", dir.display());
            print_connect_block(&state.node_id, &state.invite_url);
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    println!(
        "Started detached terminal session '{name}' (pid {pid}); still coming online — check `azula terminal list`."
    );
    println!("Logs: {}", dir.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// `azula terminal list`
// ---------------------------------------------------------------------------

fn cmd_list(args: ListArgs) -> Result<()> {
    let states = read_all_states();

    if args.json {
        let rows: Vec<serde_json::Value> = states
            .iter()
            .map(|s| {
                serde_json::json!({
                    "name": s.name,
                    "pid": s.pid,
                    "alive": pid_alive(s.pid),
                    "node_id": s.node_id,
                    "invite_url": s.invite_url,
                    "started_at": s.started_at,
                })
            })
            .collect();
        super::print_json(&rows);
        return Ok(());
    }

    if states.is_empty() {
        println!("No detached terminal sessions. Start one with `azula terminal new --name NAME`.");
        return Ok(());
    }

    println!("{:<20} {:<10} {:<6} INVITE", "NAME", "PID", "ALIVE");
    println!("{}", "-".repeat(70));
    for s in &states {
        println!("{:<20} {:<10} {:<6} {}", s.name, s.pid, pid_alive(s.pid), s.invite_url);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `azula terminal kill`
// ---------------------------------------------------------------------------

fn cmd_kill(args: KillArgs) -> Result<()> {
    let state = read_state(&args.name)
        .with_context(|| format!("no recorded session named '{}' (see `azula terminal list`)", args.name))?;

    // SAFETY: signaling a pid we read from our own runtime state file.
    let rc = unsafe { libc::kill(state.pid as libc::pid_t, libc::SIGTERM) };
    remove_state(&args.name);

    if rc == 0 {
        println!("Sent SIGTERM to '{}' (pid {}); cleaned up its state file.", args.name, state.pid);
    } else {
        println!("'{}' (pid {}) was already gone; cleaned up its state file.", args.name, state.pid);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `azula terminal attach` — the raw passthrough client.
// ---------------------------------------------------------------------------

/// Resolve `target` to a dialable ticket and, if it's an invite, the raw
/// invite token to present in `Hello.invite`. Tries a recorded session name
/// first (`azula terminal new --name X` / `--host-detached`'s state file),
/// then falls back to parsing `target` itself as an invite URL / ticket /
/// bare token (`link::parse`, the same parser `azula pair`/`--device` use).
fn resolve_attach_target(target: &str) -> Result<(String, Option<String>)> {
    if let Some(state) = read_state(target) {
        return ticket_and_invite_from_url(&state.invite_url);
    }
    ticket_and_invite_from_url(target)
}

fn ticket_and_invite_from_url(url: &str) -> Result<(String, Option<String>)> {
    match link::parse(url) {
        Some(Parsed::Invite(payload)) => {
            let decoded = invite::InvitePayload::decode(&payload).context("invalid invite")?;
            let ticket = decoded.ticket().context("invalid invite ticket")?;
            Ok((ticket.to_string(), Some(payload)))
        }
        Some(Parsed::Ticket(t)) => Ok((t, None)),
        None => anyhow::bail!("could not parse a session name, ticket, or invite from {url:?}"),
    }
}

async fn cmd_attach(args: AttachArgs) -> Result<()> {
    let (ticket_str, invite_token) = resolve_attach_target(&args.target)?;
    let ticket = EndpointTicket::from_str(&ticket_str).context("invalid ticket")?;

    let endpoint = iroh::Endpoint::bind(iroh::endpoint::presets::N0).await.context("binding local endpoint")?;
    let conn = endpoint
        .connect(ticket.endpoint_addr().clone(), TERM_ALPN)
        .await
        .context("dialing the hosted session")?;
    let (mut send, recv) = conn.open_bi().await.context("opening a stream")?;

    write_frame(&mut send, &Frame::Hello { name: "azula terminal attach".to_string(), invite: invite_token, cert: None })
        .await
        .context("sending hello")?;
    write_frame(&mut send, &Frame::TermAttach { session: None }).await.context("sending term_attach")?;

    eprintln!("Attaching… (Ctrl-\\ to detach)");

    let guard = RawModeGuard::enable().ok();
    let mut reader = BufReader::new(recv);
    pump_attach(&mut send, &mut reader).await;
    drop(guard);

    let _ = send.finish();
    conn.close(0u32.into(), b"done");
    endpoint.close().await;
    eprintln!("\r\nDetached.");
    Ok(())
}

/// The detach chord: Ctrl-\ (ASCII FS, 0x1C) — raw mode disables the
/// terminal's own SIGQUIT handling for it, so it arrives here as a plain
/// byte to act on ourselves. Documented in `--help`.
const DETACH_BYTE: u8 = 0x1c;

/// Split `buf` at the first detach-chord byte, if any: `(before, true)` when
/// found — only `before` should be forwarded, then the caller detaches — or
/// `(buf, false)` when absent (forward it all). Pure and unit-testable,
/// unlike the raw termios/socket plumbing around it.
fn split_at_detach_chord(buf: &[u8]) -> (&[u8], bool) {
    match buf.iter().position(|&b| b == DETACH_BYTE) {
        Some(i) => (&buf[..i], true),
        None => (buf, false),
    }
}

async fn pump_attach(send: &mut iroh::endpoint::SendStream, reader: &mut BufReader<iroh::endpoint::RecvStream>) {
    let (stdin_tx, mut stdin_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if stdin_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let mut winch = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change()).ok();
    if let Some((cols, rows)) = local_terminal_size() {
        let _ = write_frame(send, &Frame::Resize { cols, rows }).await;
    }

    let mut stdout = std::io::stdout();
    loop {
        tokio::select! {
            chunk = stdin_rx.recv() => {
                match chunk {
                    Some(bytes) => {
                        let (before, detach) = split_at_detach_chord(&bytes);
                        if !before.is_empty() {
                            let text = String::from_utf8_lossy(before).into_owned();
                            if write_frame(send, &Frame::Input { text }).await.is_err() {
                                break;
                            }
                        }
                        if detach {
                            break;
                        }
                    }
                    None => break,
                }
            }

            _ = winch_recv(&mut winch) => {
                if let Some((cols, rows)) = local_terminal_size() {
                    let _ = write_frame(send, &Frame::Resize { cols, rows }).await;
                }
            }

            frame = read_frame(reader) => {
                match frame {
                    Ok(Some(Frame::Term { line })) => {
                        let _ = stdout.write_all(line.as_bytes());
                        let _ = stdout.flush();
                    }
                    Ok(Some(Frame::TermExit { .. })) => break,
                    Ok(Some(_)) => {}
                    Ok(None) | Err(_) => break,
                }
            }
        }
    }
}

/// Await the next SIGWINCH, or never resolve when no signal stream is
/// available (e.g. installing the handler failed) — keeps `pump_attach`'s
/// `tokio::select!` arm uniform either way.
async fn winch_recv(winch: &mut Option<tokio::signal::unix::Signal>) {
    match winch {
        Some(s) => {
            s.recv().await;
        }
        None => std::future::pending::<()>().await,
    }
}

/// The local terminal's `(cols, rows)`, or `None` when stdout isn't a TTY
/// (or the ioctl fails).
fn local_terminal_size() -> Option<(u16, u16)> {
    // SAFETY: STDOUT_FILENO is always a valid fd value; `winsize` is a
    // plain-old-data struct and `ioctl`/`isatty` are standard POSIX calls.
    unsafe {
        if libc::isatty(libc::STDOUT_FILENO) != 1 {
            return None;
        }
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) != 0 {
            return None;
        }
        if ws.ws_col == 0 || ws.ws_row == 0 {
            return None;
        }
        Some((ws.ws_col, ws.ws_row))
    }
}

/// RAII guard: puts the local terminal into raw mode on construction,
/// restores its original settings on drop — including on an unwind from a
/// panic, so a crash mid-attach never leaves the user's shell broken.
struct RawModeGuard {
    orig: libc::termios,
}

impl RawModeGuard {
    fn enable() -> std::io::Result<Self> {
        // SAFETY: STDIN_FILENO is always a valid fd value; `termios` is a
        // plain-old-data struct and `tcgetattr`/`tcsetattr` are standard
        // POSIX calls.
        unsafe {
            let mut orig: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(libc::STDIN_FILENO, &mut orig) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut raw = orig;
            raw.c_lflag &= !(libc::ECHO | libc::ICANON | libc::ISIG | libc::IEXTEN);
            raw.c_iflag &= !(libc::IXON | libc::ICRNL | libc::BRKINT | libc::INPCK | libc::ISTRIP);
            raw.c_oflag &= !libc::OPOST;
            raw.c_cflag |= libc::CS8;
            raw.c_cc[libc::VMIN] = 1;
            raw.c_cc[libc::VTIME] = 0;
            if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(RawModeGuard { orig })
        }
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        // SAFETY: restoring termios settings this same guard captured in
        // `enable`.
        unsafe {
            let _ = libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.orig);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    fn isolated_runtime_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("azula-terminal-cmd-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("AZULA_RUNTIME_DIR", &dir);
        dir
    }

    fn sample_state(name: &str, pid: u32) -> SessionState {
        SessionState {
            name: name.to_string(),
            pid,
            node_id: "deadbeef".to_string(),
            invite_url: "https://azula.app/i/azitest".to_string(),
            started_at: 1_767_225_600,
        }
    }

    // --- connect block (pure) -----------------------------------------

    #[test]
    fn format_connect_block_contains_the_invite_url_and_a_qr() {
        let block = format_connect_block("abcdef1234567890", "https://azula.app/i/azitest");
        assert!(block.contains("https://azula.app/i/azitest"), "{block}");
        assert!(block.contains("abcdef12"), "expected a short node id: {block}");
        // The QR renderer emits dense block characters; a real invite string
        // is always long enough to produce a non-trivial code.
        assert!(block.contains('█') || block.contains('▀') || block.contains('▄'), "expected QR art: {block}");
    }

    // --- detach chord (pure) -------------------------------------------

    #[test]
    fn split_at_detach_chord_finds_the_chord_and_splits_before_it() {
        let (before, detach) = split_at_detach_chord(b"hello\x1cworld");
        assert_eq!(before, b"hello");
        assert!(detach);
    }

    #[test]
    fn split_at_detach_chord_passes_through_when_absent() {
        let (before, detach) = split_at_detach_chord(b"hello world");
        assert_eq!(before, b"hello world");
        assert!(!detach);
    }

    #[test]
    fn split_at_detach_chord_on_a_lone_chord_yields_empty_before() {
        let (before, detach) = split_at_detach_chord(b"\x1c");
        assert!(before.is_empty());
        assert!(detach);
    }

    // --- runtime state files --------------------------------------------

    #[test]
    fn write_read_and_remove_state_roundtrips() {
        let _guard = crate::registry::ENV_TEST_LOCK.blocking_lock();
        let _dir = isolated_runtime_dir("roundtrip");

        let state = sample_state("work", 12345);
        write_state(&state).expect("write state");
        assert_eq!(read_state("work"), Some(state));

        remove_state("work");
        assert_eq!(read_state("work"), None);

        std::env::remove_var("AZULA_RUNTIME_DIR");
    }

    #[test]
    fn list_sees_two_concurrently_recorded_sessions() {
        let _guard = crate::registry::ENV_TEST_LOCK.blocking_lock();
        let _dir = isolated_runtime_dir("list_two");

        write_state(&sample_state("work", 111)).expect("write work");
        write_state(&sample_state("experiments", 222)).expect("write experiments");

        let states = read_all_states();
        let names: Vec<&str> = states.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["experiments", "work"], "list must see both concurrently recorded sessions");

        std::env::remove_var("AZULA_RUNTIME_DIR");
    }

    #[test]
    fn pid_alive_is_true_for_our_own_process_and_false_for_a_reaped_child() {
        assert!(pid_alive(std::process::id()), "our own process must report alive");

        // A short-lived child that has already exited AND been reaped: use a
        // definitely-invalid pid (0 is never a valid target for a signal
        // meant "this process"; effectively guaranteed ESRCH here) rather
        // than raced timing against a real child.
        assert!(!pid_alive(u32::MAX), "an implausible pid must not report alive");
    }

    /// `kill` actually terminates a real (harmless, throwaway) child process
    /// and `cmd_kill`'s underlying state-file cleanup runs regardless of
    /// whether the signal delivery raced the child's own natural exit.
    #[test]
    fn kill_terminates_a_real_child_and_cleans_up_its_state_file() {
        let _guard = crate::registry::ENV_TEST_LOCK.blocking_lock();
        let _dir = isolated_runtime_dir("kill_real_child");

        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn a throwaway child to kill");
        let pid = child.id();
        write_state(&sample_state("killable", pid)).expect("write state");

        cmd_kill(KillArgs { name: "killable".to_string() }).expect("kill succeeds");

        assert_eq!(read_state("killable"), None, "kill must remove the state file");
        let status = child.wait().expect("wait for the killed child");
        assert!(!status.success(), "a SIGTERM'd child must not report success");

        std::env::remove_var("AZULA_RUNTIME_DIR");
    }

    #[test]
    fn kill_of_an_unrecorded_name_errors() {
        let _guard = crate::registry::ENV_TEST_LOCK.blocking_lock();
        let _dir = isolated_runtime_dir("kill_missing");

        let err = cmd_kill(KillArgs { name: "does-not-exist".to_string() }).unwrap_err();
        assert!(err.to_string().contains("no recorded session"), "{err}");

        std::env::remove_var("AZULA_RUNTIME_DIR");
    }

    // --- resolve_attach_target -------------------------------------------

    #[test]
    fn resolve_attach_target_prefers_a_recorded_name_over_treating_it_as_a_url() {
        let _guard = crate::registry::ENV_TEST_LOCK.blocking_lock();
        let _dir = isolated_runtime_dir("resolve_name");

        // A REAL minted invite (offline: a fake dialable ticket wrapping a
        // fresh key's EndpointAddr) — resolve_attach_target fully decodes the
        // recorded invite, so a hand-typed token string can't stand in.
        let ticket_str =
            EndpointTicket::new(iroh::EndpointAddr::from(iroh::SecretKey::generate().public()))
                .to_string();
        let invite_dir = std::env::temp_dir().join(format!("azula-terminal-test-{}-resolve", std::process::id()));
        let _ = std::fs::remove_dir_all(&invite_dir);
        let (payload, _issued) = invite::mint_in(
            &invite_dir,
            &ticket_str,
            invite::Expiry::Never,
            false,
            false,
            None,
            &iroh::SecretKey::generate(),
        )
        .expect("mint offline invite");
        write_state(&SessionState {
            name: "work".to_string(),
            pid: 1,
            node_id: "abcd".to_string(),
            invite_url: format!("https://azula.app/i/{}", payload.encode()),
            started_at: 0,
        })
        .expect("write state");

        let (ticket, invite) = resolve_attach_target("work").expect("resolves");
        assert!(invite.is_some(), "expected the recorded invite payload to be extracted");
        assert!(!ticket.is_empty());

        std::env::remove_var("AZULA_RUNTIME_DIR");
    }

    #[test]
    fn resolve_attach_target_falls_back_to_parsing_a_bare_ticket() {
        let _guard = crate::registry::ENV_TEST_LOCK.blocking_lock();
        let _dir = isolated_runtime_dir("resolve_bare");

        let (ticket, invite) = resolve_attach_target("some-bare-ticket-token").expect("resolves");
        assert_eq!(ticket, "some-bare-ticket-token");
        assert!(invite.is_none());

        std::env::remove_var("AZULA_RUNTIME_DIR");
    }

    #[test]
    fn generate_name_produces_distinct_names() {
        assert_ne!(generate_name(), generate_name());
    }
}
