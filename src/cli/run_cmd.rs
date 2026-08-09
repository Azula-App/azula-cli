//! `azula run [--handoff on-error|always|never] [--hold MINUTES] [--name N]
//! [--desc D] -- CMD ARGS…` — wrap a command in a PTY, mirroring its output
//! unmodified to the real stdout (so CI logs are unchanged) while feeding the
//! same 256 KiB session ring buffer `term.rs`'s persistent sessions use. On
//! the handoff trigger (nonzero exit for `on-error`, the default;
//! unconditional for `always`; never for `never`) the captured output
//! becomes a held `term.rs` session's scrollback, a login shell takes over
//! in the same process's cwd/env, and a connect block (invite URL + QR) is
//! printed so a phone or `azula terminal attach` can pick up where the
//! failure left off — design.md D5. The process stays alive until the
//! handoff session ends or `--hold` (default 60 minutes) expires, then exits
//! with the *original* wrapped command's exit code, so CI still reports the
//! failure.
//!
//! TODO(phase 4): when a machine identity exists, additionally push a
//! "build failed — attach here" agent message through the relay via
//! `SessionCore::send_message`, so the phone gets a notification without
//! anyone watching the log (design.md D3/D6: "no scan needed [...] `azula
//! run` can additionally send a [...] agent message through the relay").
//! Not implemented yet — phase 4 builds the relay delivery chain this needs;
//! this phase always falls back to printing the connect block.

use std::time::Duration;

use anyhow::{Context, Result};
use portable_pty::PtySize;
use tracing::warn;

use crate::cli::terminal_cmd::print_connect_block;
use crate::mcp::{LlmHandler, LLM_ALPN};
use crate::qr;
use crate::session::SessionKey;
use crate::term::{self, TermHandler, TERM_ALPN};

/// Coarse memory bound for the wrapped command's captured output while it's
/// still running. The *precise* 256 KiB/newline-boundary trim happens for
/// real once the bytes seed the handoff session's ring buffer
/// (`term::spawn_host_shell_session` -> `SessionRing::push`); this is just a
/// safety valve against a very long-running, chatty command growing this
/// buffer unbounded in the meantime.
const CAPTURE_SOFT_CAP: usize = 4 * 1024 * 1024;

/// A sane fixed PTY size for the wrapped command when stdout isn't a real
/// TTY (the common CI case).
const FALLBACK_PTY_SIZE: PtySize = PtySize { rows: 50, cols: 200, pixel_width: 0, pixel_height: 0 };

/// Default session TTL passed to the handoff's `TermHandler` — unrelated to
/// `--hold` (which bounds how long *this process* waits); this just needs to
/// outlive any individual detach/reattach cycle within that window. No TTL
/// reaper is spawned for `azula run` (its own `--hold` wait loop and final
/// `term::kill_all_sessions()` already bound the session's lifetime to the
/// process's own).
const HANDOFF_SESSION_TTL: Duration = Duration::from_secs(60 * 60);

// ---------------------------------------------------------------------------
// clap surface
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, clap::Args)]
pub(super) struct RunArgs {
    /// When to hand off to an interactive shell in the same session: on the
    /// wrapped command's nonzero exit (the default), always (once the
    /// command finishes, regardless of its exit code), or never (plain PTY
    /// passthrough — exits with the command's own code, no handoff).
    #[arg(long, value_enum, default_value = "on-error")]
    pub(super) handoff: HandoffMode,

    /// Minutes to hold a triggered handoff session open before giving up and
    /// exiting with the wrapped command's original exit code.
    #[arg(long, default_value_t = 60)]
    pub(super) hold: u64,

    /// Override the handoff connect block's announced conversation name.
    #[arg(long)]
    pub(super) name: Option<String>,

    /// Override the handoff connect block's announced conversation
    /// description.
    #[arg(long)]
    pub(super) desc: Option<String>,

    /// Test-only: hold in seconds instead of minutes (overrides --hold).
    /// Hidden — not part of the public CLI surface.
    #[arg(long = "hold-secs", hide = true)]
    pub(super) hold_secs: Option<u64>,

    /// The command to run, and its arguments.
    #[arg(required = true, trailing_var_arg = true, num_args = 1..)]
    pub(super) command: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(super) enum HandoffMode {
    OnError,
    Always,
    Never,
}

/// Whether `mode` triggers a handoff for a wrapped command that exited with
/// `exit_code`. Pure and unit-testable.
fn should_handoff(mode: HandoffMode, exit_code: i32) -> bool {
    match mode {
        HandoffMode::Never => false,
        HandoffMode::OnError => exit_code != 0,
        HandoffMode::Always => true,
    }
}

// ---------------------------------------------------------------------------
// Entry point — returns the process exit code rather than calling
// `std::process::exit` itself, so tests can drive the real logic in-process.
// ---------------------------------------------------------------------------

pub(super) async fn run(args: RunArgs) -> i32 {
    match run_inner(args).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: azula run: {e}");
            1
        }
    }
}

async fn run_inner(args: RunArgs) -> Result<i32> {
    let wrapped = run_wrapped(&args.command).await?;
    if wrapped.interrupted {
        // The user asked to stop (Ctrl-C) while the wrapped command was
        // still running — honor that outright, no handoff.
        return Ok(wrapped.exit_code);
    }

    if !should_handoff(args.handoff, wrapped.exit_code) {
        return Ok(wrapped.exit_code);
    }

    let hold = args
        .hold_secs
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(args.hold * 60));

    if let Err(e) = handoff(wrapped.captured, args.name, args.desc, hold).await {
        warn!(error = %e, "run: handoff failed; exiting with the wrapped command's own exit code");
    }

    Ok(wrapped.exit_code)
}

// ---------------------------------------------------------------------------
// Running the wrapped command
// ---------------------------------------------------------------------------

struct WrappedResult {
    exit_code: i32,
    captured: Vec<u8>,
    /// The user hit Ctrl-C while the command was running — its child was
    /// killed, and no handoff should be attempted regardless of `--handoff`.
    interrupted: bool,
}

/// Run `command` in a PTY, mirroring every output chunk unmodified to the
/// real stdout while capturing a bounded copy for a possible handoff
/// preamble. Propagates the invoking terminal's size (and forwards SIGWINCH)
/// when stdout is a TTY; falls back to a fixed size in CI. Local stdin is
/// *not* forwarded to the wrapped command — `azula run`'s primary use case
/// is a CI/script wrapper, and a wedged read on unforwarded stdin would just
/// see immediate EOF (the PTY master's write half closes once nothing holds
/// its sender), same as running under `< /dev/null`.
async fn run_wrapped(command: &[String]) -> Result<WrappedResult> {
    let size = local_pty_size();
    let mut pty = term::spawn_pty_process(Some(command), size).context("spawning the wrapped command")?;
    drop(pty.in_tx); // no stdin forwarding — see the doc comment above.

    let mut captured: Vec<u8> = Vec::new();
    let mut stdout = std::io::stdout();
    let mut winch = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change()).ok();

    loop {
        tokio::select! {
            chunk = pty.out_rx.recv() => {
                match chunk {
                    Some(bytes) => {
                        use std::io::Write as _;
                        let _ = stdout.write_all(&bytes);
                        let _ = stdout.flush();
                        append_capped(&mut captured, &bytes);
                    }
                    None => {
                        pty.writer_task.abort();
                        let exit_code = pty.reader_task.await.unwrap_or(None).unwrap_or(1);
                        return Ok(WrappedResult { exit_code, captured, interrupted: false });
                    }
                }
            }

            _ = winch_recv(&mut winch) => {
                if let Some((cols, rows)) = terminal_size() {
                    let _ = pty.master.resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 });
                }
            }

            _ = tokio::signal::ctrl_c() => {
                let _ = pty.killer.kill();
                pty.reader_task.abort();
                pty.writer_task.abort();
                return Ok(WrappedResult { exit_code: 130, captured, interrupted: true });
            }
        }
    }
}

async fn winch_recv(winch: &mut Option<tokio::signal::unix::Signal>) {
    match winch {
        Some(s) => {
            s.recv().await;
        }
        None => std::future::pending::<()>().await,
    }
}

fn append_capped(buf: &mut Vec<u8>, chunk: &[u8]) {
    buf.extend_from_slice(chunk);
    if buf.len() > CAPTURE_SOFT_CAP {
        let excess = buf.len() - CAPTURE_SOFT_CAP;
        buf.drain(..excess);
    }
}

/// `(cols, rows)` for the wrapped command's PTY: the invoking terminal's
/// real size when stdout is a TTY, else [`FALLBACK_PTY_SIZE`].
fn local_pty_size() -> PtySize {
    match terminal_size() {
        Some((cols, rows)) => PtySize { rows, cols, pixel_width: 0, pixel_height: 0 },
        None => FALLBACK_PTY_SIZE,
    }
}

fn terminal_size() -> Option<(u16, u16)> {
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

// ---------------------------------------------------------------------------
// Handoff
// ---------------------------------------------------------------------------

/// The live handoff session, before the connect block is printed or the
/// hold-timeout wait begins — split out from [`handoff`] so tests can dial
/// `router.endpoint().addr()` directly (no invite-URL parsing needed),
/// exactly like `term.rs`'s own in-process iroh tests. `_session` is kept
/// alive (not dropped early) for the same reason `bridge::run`/`run_stdio`
/// keep `Established::session` alive for the life of the server: an
/// ephemeral `SessionKey`'s guard deletes its on-disk key file on drop, and
/// D2 says that should happen "on clean exit," not the instant the endpoint
/// finishes binding.
struct Handoff {
    endpoint_id: iroh::EndpointId,
    invite_url: String,
    session_id: String,
    router: iroh::protocol::Router,
    // Held only for its Drop side effect (deletes the ephemeral key file on
    // clean exit) — never read.
    #[allow(dead_code)]
    _session: SessionKey,
}

/// Bind a fresh ephemeral session (design.md D2: "`azula run`/`azula
/// terminal`: fresh ephemeral session per invocation" —
/// `session::SessionKey::resolve(None)`), spawn `$SHELL -l` as a host-created
/// session seeded with `captured`'s output, and serve it on `TERM_ALPN`
/// (plus `LLM_ALPN` so the phone's dial-race finds the terminal conversation
/// the way `azula serve` does today — mirrors how `serve` wires
/// `TermHandler`).
async fn start_handoff(
    captured: &[u8],
    name: Option<String>,
    desc: Option<String>,
    shell_argv: Option<&[String]>,
) -> Result<Handoff> {
    let session = SessionKey::resolve(None).context("resolving the handoff session's ephemeral identity")?;
    let (endpoint, ticket) = crate::endpoint::bind_endpoint_with_secret(session.secret.clone())
        .await
        .context("binding the handoff session's endpoint")?;
    let my_endpoint_id = endpoint.id();

    let session_id = term::spawn_host_shell_session(shell_argv, local_pty_size(), captured)
        .context("spawning the handoff shell")?;

    let router = iroh::protocol::Router::builder(endpoint)
        .accept(LLM_ALPN, LlmHandler::new(None, my_endpoint_id))
        .accept(
            TERM_ALPN,
            TermHandler::new(my_endpoint_id, name, desc, Some(HANDOFF_SESSION_TTL))
                .with_default_session(session_id.clone()),
        )
        .spawn();

    let invite_url =
        match crate::core::mint_pairing_invite(&ticket, router.endpoint().secret_key()) {
            Some(encoded) => qr::invite_url(&encoded),
            None => qr::pairing_url(&ticket),
        };

    Ok(Handoff { endpoint_id: my_endpoint_id, invite_url, session_id, router, _session: session })
}

async fn handoff(
    captured: Vec<u8>,
    name: Option<String>,
    desc: Option<String>,
    hold: Duration,
) -> Result<()> {
    let h = start_handoff(&captured, name, desc, None).await?;
    print_connect_block(&h.endpoint_id.to_string(), &h.invite_url);
    wait_for_session_end_or_hold(&h.session_id, hold).await;
    // Kill sessions BEFORE router shutdown: a live session's PTY-reader
    // thread is parked in a blocking read from a shell that may still be
    // running (the hold timeout expired before it exited on its own), and a
    // signal-immune login shell can keep the whole teardown pinned. The
    // shutdown itself is bounded as a second line of defense.
    term::kill_all_sessions();
    let _ = tokio::time::timeout(Duration::from_secs(5), h.router.shutdown()).await;
    Ok(())
}

async fn wait_for_session_end_or_hold(session_id: &str, hold: Duration) {
    let deadline = tokio::time::Instant::now() + hold;
    loop {
        if !term::session_is_alive(session_id) {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            return;
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(300)) => {}
            _ = tokio::signal::ctrl_c() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::terminal_cmd::format_connect_block;

    // --- should_handoff (pure) -------------------------------------------

    #[test]
    fn on_error_triggers_only_on_nonzero_exit() {
        assert!(!should_handoff(HandoffMode::OnError, 0));
        assert!(should_handoff(HandoffMode::OnError, 7));
        assert!(should_handoff(HandoffMode::OnError, 1));
    }

    #[test]
    fn always_triggers_regardless_of_exit_code() {
        assert!(should_handoff(HandoffMode::Always, 0));
        assert!(should_handoff(HandoffMode::Always, 7));
    }

    #[test]
    fn never_never_triggers() {
        assert!(!should_handoff(HandoffMode::Never, 0));
        assert!(!should_handoff(HandoffMode::Never, 7));
    }

    // --- append_capped (pure) --------------------------------------------

    #[test]
    fn append_capped_stays_under_cap_for_a_huge_single_chunk() {
        let mut buf = Vec::new();
        append_capped(&mut buf, &vec![b'x'; CAPTURE_SOFT_CAP * 2]);
        assert!(buf.len() <= CAPTURE_SOFT_CAP);
    }

    #[test]
    fn append_capped_keeps_the_most_recent_bytes() {
        let mut buf = Vec::new();
        append_capped(&mut buf, b"AAAA");
        append_capped(&mut buf, &vec![b'x'; CAPTURE_SOFT_CAP]);
        append_capped(&mut buf, b"ZZZZ_MARKER");
        assert!(buf.ends_with(b"ZZZZ_MARKER"));
    }

    // --- run-wrapper exit-code preservation (integration) -----------------

    /// `azula run --handoff never -- sh -c 'exit 7'` must exit 7: no
    /// endpoint, no session, no connect block — a pure PTY passthrough.
    #[tokio::test]
    async fn handoff_never_preserves_the_wrapped_commands_exit_code() {
        let args = RunArgs {
            handoff: HandoffMode::Never,
            hold: 60,
            name: None,
            desc: None,
            hold_secs: None,
            command: vec!["sh".to_string(), "-c".to_string(), "exit 7".to_string()],
        };
        let code = run(args).await;
        assert_eq!(code, 7);
    }

    /// A clean (exit 0) command under the default `on-error` handoff mode
    /// exits 0 immediately, with no handoff attempted.
    #[tokio::test]
    async fn handoff_on_error_passes_through_a_clean_exit() {
        let args = RunArgs {
            handoff: HandoffMode::OnError,
            hold: 60,
            name: None,
            desc: None,
            hold_secs: None,
            command: vec!["sh".to_string(), "-c".to_string(), "exit 0".to_string()],
        };
        let code = run(args).await;
        assert_eq!(code, 0);
    }

    // --- connect block content (pure) -------------------------------------

    #[test]
    fn connect_block_text_names_the_invite() {
        let block = format_connect_block("aabbccdd11223344", "https://azula.app/i/azitest");
        assert!(block.contains("https://azula.app/i/azitest"));
    }

    // --- clap parsing: flags + the trailing wrapped command ---------------

    #[test]
    fn run_command_line_parses_flags_and_the_trailing_wrapped_command() {
        use clap::FromArgMatches as _;

        let matches = crate::cli::build_command()
            .try_get_matches_from(["azula", "run", "--handoff", "always", "--hold", "5", "--", "sh", "-c", "exit 7"])
            .expect("parses");
        let cli = crate::cli::Cli::from_arg_matches(&matches).expect("builds Cli");
        match cli.command {
            Some(crate::cli::Command::Run(args)) => {
                assert_eq!(args.handoff, HandoffMode::Always);
                assert_eq!(args.hold, 5);
                assert_eq!(args.command, vec!["sh".to_string(), "-c".to_string(), "exit 7".to_string()]);
            }
            other => panic!("expected Command::Run, got {other:?}"),
        }
    }

    #[test]
    fn run_handoff_defaults_to_on_error() {
        use clap::FromArgMatches as _;

        let matches = crate::cli::build_command()
            .try_get_matches_from(["azula", "run", "--", "sh", "-c", "exit 0"])
            .expect("parses");
        let cli = crate::cli::Cli::from_arg_matches(&matches).expect("builds Cli");
        match cli.command {
            Some(crate::cli::Command::Run(args)) => assert_eq!(args.handoff, HandoffMode::OnError),
            other => panic!("expected Command::Run, got {other:?}"),
        }
    }

    // --- full handoff: preamble replay, cwd inheritance, exit-code
    // preservation (in-process iroh pair, mirroring term.rs's own tests) ---

    /// `sh -c 'exit 7'` under `--handoff on-error` triggers a handoff whose
    /// held session (a) carries the failed command's captured output as
    /// scrollback and (b) runs the login shell in the *same* cwd as the
    /// `azula run` process — proving both "keeps the ring buffer" and
    /// "same cwd" from the terminal spec's "Run Wrapper With Failure
    /// Handoff" requirement — while the overall wrapper still preserves the
    /// original exit code once the session ends.
    #[tokio::test]
    async fn failing_command_hands_off_with_scrollback_and_inherited_cwd_then_preserves_exit_code() {
        let wrapped = run_wrapped(&["sh".to_string(), "-c".to_string(), "echo AZULA_RUN_FAILURE_MARKER; exit 7".to_string()])
            .await
            .expect("run the wrapped command");
        assert_eq!(wrapped.exit_code, 7);
        assert!(!wrapped.interrupted);
        assert!(
            String::from_utf8_lossy(&wrapped.captured).contains("AZULA_RUN_FAILURE_MARKER"),
            "expected the wrapped command's own output to be captured"
        );

        // /bin/sh, not $SHELL: the user's login shell reads arbitrary dotfiles
        // and (on macOS zsh setups) can survive the polite kill signal — the
        // test must be hermetic and prompt-fast.
        let sh = vec!["/bin/sh".to_string()];
        let h = start_handoff(&wrapped.captured, None, None, Some(&sh)).await.expect("start handoff");
        let addr = h.router.endpoint().addr();

        let client_ep = iroh::Endpoint::bind(iroh::endpoint::presets::Minimal).await.expect("client bind");
        let conn = client_ep.connect(addr, TERM_ALPN).await.expect("client connect");
        let (mut send, recv) = conn.open_bi().await.expect("open_bi");
        // Redeem the handoff's own minted invite first: the handoff session is
        // host-created and therefore invite-gated (`find_owned_session`), so a
        // raw attach would silently get a FRESH session instead of the held
        // one. This is the spec's "Invite redemption grants the held session"
        // scenario, exercised end to end.
        let invite_token = h
            .invite_url
            .rsplit('/')
            .next()
            .expect("invite token in the connect-block URL")
            .to_string();
        crate::proto::write_frame(
            &mut send,
            &crate::proto::Frame::Hello {
                name: client_ep.id().to_string(),
                invite: Some(invite_token),
                cert: None,
            },
        )
        .await
        .expect("write hello redeeming the handoff invite");
        crate::proto::write_frame(&mut send, &crate::proto::Frame::TermAttach { session: None })
            .await
            .expect("write term_attach");

        let mut reader = tokio::io::BufReader::new(recv);
        let (resumed_id, resumed) = read_until(&mut reader, |f| match f {
            crate::proto::Frame::TermSession { session, resumed } => Some((session.clone(), *resumed)),
            _ => None,
        })
        .await
        .expect("expected a term_session frame");
        assert_eq!(resumed_id, h.session_id);
        assert!(resumed, "attaching to the pre-created handoff session must be marked resumed");

        let replayed_marker = read_until(&mut reader, |f| match f {
            crate::proto::Frame::Term { line } if line.contains("AZULA_RUN_FAILURE_MARKER") => Some(()),
            _ => None,
        })
        .await;
        assert!(replayed_marker.is_some(), "expected the failed command's output to be replayed as scrollback");

        // The handoff shell must be running in this same process's cwd.
        crate::proto::write_frame(&mut send, &crate::proto::Frame::Input { text: "pwd\n".to_string() })
            .await
            .expect("write pwd");
        let expected_cwd = std::env::current_dir().expect("current dir").to_string_lossy().into_owned();
        let saw_cwd = read_until(&mut reader, |f| match f {
            crate::proto::Frame::Term { line } if line.contains(&expected_cwd) => Some(()),
            _ => None,
        })
        .await;
        assert!(saw_cwd.is_some(), "expected the handoff shell's pwd to match azula run's own cwd ({expected_cwd})");

        let _ = send.finish();
        conn.close(0u32.into(), b"done");
        client_ep.close().await;

        term::kill_session(&h.session_id);
        let _ = tokio::time::timeout(Duration::from_secs(5), h.router.shutdown()).await;
    }

    /// Reads frames off `reader` until `f` returns `Some`, bounded so a stuck
    /// test fails fast instead of hanging CI — mirrors `term.rs`'s own
    /// `read_until` test helper (private to its module, so duplicated here
    /// rather than exposed across the crate just for tests).
    async fn read_until<T>(
        reader: &mut tokio::io::BufReader<iroh::endpoint::RecvStream>,
        mut f: impl FnMut(&crate::proto::Frame) -> Option<T>,
    ) -> Option<T> {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                match crate::proto::read_frame(reader).await {
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
}
