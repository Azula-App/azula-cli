//! Remote-shell ("SSH"-like) protocol handler.
//!
//! Serves the `azula/term/0` ALPN. On each connection the server accepts the
//! client-opened bi stream, spawns the user's shell in a PTY (via
//! `portable-pty`), and bridges it to the iroh stream:
//!
//! * PTY output is read on a blocking thread and forwarded to the client as
//!   [`Frame::Term`] chunks.
//! * Incoming [`Frame::Input`] frames are written verbatim to the PTY stdin.
//!
//! portable-pty's reader/writer are blocking, so the bridge uses
//! `spawn_blocking` threads plus a tokio mpsc channel to move bytes between the
//! blocking PTY side and the async iroh side.

use std::io::{Read, Write};
use std::time::Duration;

use anyhow::{Context, Result};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::EndpointId;
use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};
use tokio::io::BufReader;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::invite;
use crate::proto::{read_frame, write_frame, Frame};
use crate::registry::{self, Device};

/// ALPN identifier for the remote-shell protocol.
pub const TERM_ALPN: &[u8] = b"azula/term/0";

/// 15 s cap on waiting for a stranger's first frame — mirrors the same gate
/// in `bridge/device.rs`'s `accept_incoming`.
const STRANGER_HELLO_TIMEOUT: Duration = Duration::from_secs(15);

/// Protocol handler for the remote-shell ALPN.
///
/// Unlike `bridge/device.rs`'s `LLM_ALPN` handler (which tracks a live
/// multi-device map), `serve`'s term ALPN has no device-session concept — it
/// just needs to know whether an inbound connection is from a device already
/// in the registry, and gate strangers on a valid invite per
/// `azula-docs/docs/invitations.md`.
#[derive(Debug, Clone)]
pub struct TermHandler {
    /// Our own node id — the invite-verification audience and signature key.
    my_node_id: EndpointId,
    /// Admit invite-less strangers as unverified instead of closing the
    /// connection (`--allow-legacy`, default on for one release).
    allow_legacy: bool,
}

impl TermHandler {
    pub fn new(my_node_id: EndpointId, allow_legacy: bool) -> Self {
        TermHandler { my_node_id, allow_legacy }
    }
}

impl ProtocolHandler for TermHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        handle(connection, self.my_node_id, self.allow_legacy)
            .await
            .map_err(|e| AcceptError::from_boxed(e.into()))
    }
}

async fn handle(connection: Connection, my_node_id: EndpointId, allow_legacy: bool) -> Result<()> {
    let remote_id = connection.remote_id();
    let remote = remote_id.to_string();
    info!(%remote, "term: client connected");

    // Known devices connect exactly as before — no gate. This is checked once
    // per connection (not per stream): a stranger who verifies on the first
    // stream is registered and every later stream on the same connection is
    // then implicitly from a "known" peer for the rest of its lifetime.
    let mut known = registry::find_by_node_id(&remote_id).is_some();
    let mut first_stream = true;

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
            match gate_stranger(&mut reader, my_node_id, allow_legacy, &remote).await {
                GateOutcome::Admit { replay } => {
                    known = true; // don't re-gate later streams on this connection
                    first_frame = replay.map(|b| *b);
                }
                GateOutcome::Close => return Ok(()),
            }
        }
        first_stream = false;

        let remote = remote.clone();
        tokio::spawn(async move {
            if let Err(e) = term_session(send, reader, first_frame, remote.clone()).await {
                warn!(%remote, error = %e, "term: session error");
            }
        });
    }
}

enum GateOutcome {
    /// Admit the connection; `replay` is a frame already consumed off the
    /// stream while gating that the session must still process (e.g. a
    /// legacy client's `Input` sent with no preceding `Hello`). Boxed so this
    /// variant doesn't force `Close` to pay for `Frame`'s size too.
    Admit { replay: Option<Box<Frame>> },
    Close,
}

/// Require the first frame of a stranger's first stream to be a `Hello`
/// carrying a valid invite (verified against `my_node_id`'s issued-invite
/// store). Registers the device (as `azula pair` would) and marks single-use
/// invites consumed on success. Falls back to admitting unverified when
/// `allow_legacy` is set (transition escape hatch); otherwise closes.
async fn gate_stranger(
    reader: &mut BufReader<RecvStream>,
    my_node_id: EndpointId,
    allow_legacy: bool,
    remote: &str,
) -> GateOutcome {
    let first = match tokio::time::timeout(STRANGER_HELLO_TIMEOUT, read_frame(reader)).await {
        Ok(result) => result,
        Err(_elapsed) => {
            info!(%remote, "term: stranger's first frame timed out; closing");
            return GateOutcome::Close;
        }
    };

    let invite_token = match &first {
        Ok(Some(Frame::Hello { invite: Some(tok), .. })) => Some(tok.clone()),
        _ => None,
    };

    let verified = match invite_token {
        Some(tok) => match invite::verify_inbound(&tok, my_node_id, &my_node_id) {
            Ok(v) => {
                info!(%remote, invite_id = %v.invite_id, "term: stranger presented a valid invite");
                Some(v)
            }
            Err(e) if allow_legacy => {
                warn!(%remote, error = %e, "term: invite verification failed; admitting as unverified (--allow-legacy)");
                None
            }
            Err(e) => {
                warn!(%remote, error = %e, "term: invite verification failed; closing (pass --allow-legacy to admit anyway)");
                return GateOutcome::Close;
            }
        },
        None if allow_legacy => {
            info!(%remote, "term: stranger connected without an invite; admitting as unverified (--allow-legacy)");
            None
        }
        None => {
            warn!(%remote, "term: stranger connected without a valid invite; closing (pass --allow-legacy to admit anyway)");
            return GateOutcome::Close;
        }
    };

    if let Some(v) = verified {
        let device = Device {
            name: format!("term-{}", &remote[..8.min(remote.len())]),
            ticket: remote.to_string(),
            added_at: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            ),
            invite: None,
        };
        if let Err(e) = registry::add(device, false) {
            warn!(%remote, error = %e, "term: failed to register invite-verified device");
        }
        if v.single_use {
            if let Err(e) = invite::mark_consumed(&v.invite_id) {
                warn!(%remote, error = %e, "term: failed to mark invite consumed");
            }
        }
    }

    // A non-Hello first frame (legacy client that sends Input immediately) must
    // be replayed into the session so it isn't lost; a Hello frame is fully
    // consumed by the gate and has nothing to replay.
    let replay = match first {
        Ok(Some(frame @ Frame::Hello { .. })) => {
            let _ = frame; // consumed by the gate; nothing to replay
            None
        }
        Ok(Some(other)) => Some(Box::new(other)),
        Ok(None) | Err(_) => None,
    };
    GateOutcome::Admit { replay }
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

/// Bridge one bi stream to its own dedicated PTY shell. `reader` may already
/// have consumed a first frame while gating the connection (see
/// `gate_stranger`); `first_frame`, if present, is replayed into the session
/// before the normal read loop starts so nothing sent before the gate ran is lost.
async fn term_session(
    send: SendStream,
    mut reader: BufReader<RecvStream>,
    first_frame: Option<Frame>,
    remote: String,
) -> Result<()> {
    let mut send = send;

    // Spin up a PTY running the user's shell.
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

    // Blocking reader + writer handles for the PTY master.
    let mut pty_reader = master
        .try_clone_reader()
        .context("cloning PTY reader")?;
    let mut pty_writer = master
        .take_writer()
        .context("taking PTY writer")?;

    // No injected banner — the terminal shows only the shell's own output (its
    // PS1 prompt appears as soon as the login shell starts), so we honor whatever
    // prompt the environment defines instead of branding it "azula".

    // PTY output -> async channel, fed by a blocking thread.
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(64);
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

    // Replay a frame the accept-gate already consumed off the stream (a
    // legacy client's `Input`/`Resize` sent before any `Hello`), so gating
    // doesn't silently drop the client's first keystrokes.
    match first_frame {
        Some(Frame::Input { text }) => {
            let _ = in_tx.send(text.into_bytes()).await;
        }
        Some(Frame::Resize { cols, rows }) => {
            let _ = master.resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 });
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
            chunk = out_rx.recv() => {
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
                        if in_tx.send(text.into_bytes()).await.is_err() {
                            break;
                        }
                    }
                    Ok(Some(Frame::Resize { cols, rows })) => {
                        let _ = master.resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 });
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
    drop(in_tx);
    let _ = child.kill();
    reader_task.abort();
    writer_task.abort();
    let _ = send.finish();
    info!(%remote, "term: session ended");
    Ok(())
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
            .accept(TERM_ALPN, TermHandler::new(server_id, true))
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
        let router = Router::builder(server_ep).accept(TERM_ALPN, TermHandler::new(server_id, true)).spawn();

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
}
