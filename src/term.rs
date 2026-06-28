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
use iroh::endpoint::Connection;
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

    // The client opens the bi stream and writes first.
    let (send, recv) = connection.accept_bi().await?;
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
