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

use anyhow::{Context, Result};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler};
use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};
use tokio::io::BufReader;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::proto::{read_frame, write_frame, Frame};

/// ALPN identifier for the remote-shell protocol.
pub const TERM_ALPN: &[u8] = b"azula/term/0";

/// Protocol handler for the remote-shell ALPN.
#[derive(Debug, Clone, Default)]
pub struct TermHandler;

impl TermHandler {
    pub fn new() -> Self {
        TermHandler
    }
}

impl ProtocolHandler for TermHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        handle(connection)
            .await
            .map_err(|e| AcceptError::from_boxed(e.into()))
    }
}

async fn handle(connection: Connection) -> Result<()> {
    let remote = connection.remote_id().to_string();
    info!(%remote, "term: client connected");

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
        let remote = remote.clone();
        tokio::spawn(async move {
            if let Err(e) = term_session(send, recv, remote.clone()).await {
                warn!(%remote, error = %e, "term: session error");
            }
        });
    }
}

/// Bridge one bi stream to its own dedicated PTY shell.
async fn term_session(send: SendStream, recv: RecvStream, remote: String) -> Result<()> {
    let mut send = send;
    let mut reader = BufReader::new(recv);

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
    // Drop the slave; the master keeps the PTY alive.
    drop(pair.slave);

    // Blocking reader + writer handles for the PTY master.
    let mut pty_reader = pair
        .master
        .try_clone_reader()
        .context("cloning PTY reader")?;
    let mut pty_writer = pair
        .master
        .take_writer()
        .context("taking PTY writer")?;

    // Initial banner so the client sees something on connect.
    write_frame(
        &mut send,
        &Frame::term(format!("azula shell ({shell}) — connected\r\n")),
    )
    .await?;

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

    // Main bridge loop: forward PTY output to the client and client input to
    // the PTY until either side closes.
    loop {
        tokio::select! {
            // PTY produced output.
            chunk = out_rx.recv() => {
                match chunk {
                    Some(bytes) => {
                        let line = String::from_utf8_lossy(&bytes).into_owned();
                        if write_frame(&mut send, &Frame::term(line)).await.is_err() {
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

        let router = Router::builder(server_ep)
            .accept(TERM_ALPN, TermHandler::new())
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
        let router = Router::builder(server_ep).accept(TERM_ALPN, TermHandler::new()).spawn();

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
