//! Talking to a VM's worker over the helper's Unix socket (`vsock.sock`).

use std::path::Path;
use std::time::Duration;

use serde_json::Value;
use tokio::net::UnixStream;

use super::frame::{read_frame, write_frame, Frame};

/// One `ping`: returns the worker's `pong` header. Fails if the socket is
/// absent, the helper closes it at once (worker not listening yet), or the
/// answer is not a `pong` within `timeout`.
pub async fn ping(sock: &Path, timeout: Duration) -> Result<Value, String> {
    let fut = async {
        let mut s = UnixStream::connect(sock).await.map_err(|e| format!("connect {}: {e}", sock.display()))?;
        write_frame(&mut s, &Frame::of_type("ping")).await.map_err(|e| e.to_string())?;
        match read_frame(&mut s).await {
            Ok(Some(f)) if f.t() == "pong" => Ok(f.header_value()),
            Ok(Some(f)) => Err(format!("unexpected `{}` frame from worker", f.t())),
            Ok(None) => Err("worker closed the connection".to_owned()),
            Err(e) => Err(e.to_string()),
        }
    };
    tokio::time::timeout(timeout, fut).await.unwrap_or_else(|_| Err("worker did not answer in time".to_owned()))
}

/// Ping every second until the worker answers or `deadline` passes.
pub async fn wait_ready(sock: &Path, deadline: Duration) -> Result<Value, String> {
    let end = tokio::time::Instant::now() + deadline;
    loop {
        let last = match ping(sock, Duration::from_secs(5)).await {
            Ok(v) => return Ok(v),
            Err(e) => e,
        };
        if tokio::time::Instant::now() + Duration::from_millis(500) >= end {
            return Err(last);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

impl Frame {
    pub(crate) fn header_value(&self) -> Value {
        Value::Object(self.header.clone())
    }
}
