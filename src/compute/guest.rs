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

/// Send one request frame to the worker and collect the single reply frame
/// (`job_list`, `cancel_ok`, …). An `error` frame becomes `Err("code: msg")`.
pub async fn request_one(sock: &Path, req: Frame, timeout: Duration) -> Result<Frame, String> {
    let fut = async {
        let mut s = UnixStream::connect(sock).await.map_err(|e| format!("connect {}: {e}", sock.display()))?;
        write_frame(&mut s, &req).await.map_err(|e| e.to_string())?;
        match read_frame(&mut s).await {
            Ok(Some(f)) if f.t() == "error" => Err(format!("{}: {}", f.str_field("code").unwrap_or("error"), f.str_field("msg").unwrap_or(""))),
            Ok(Some(f)) => Ok(f),
            Ok(None) => Err("worker closed the connection".to_owned()),
            Err(e) => Err(e.to_string()),
        }
    };
    tokio::time::timeout(timeout, fut).await.unwrap_or_else(|_| Err("worker did not answer in time".to_owned()))
}

/// The jobs the worker lists for `owner` (`"*"` for every owner).
pub async fn list_jobs(sock: &Path, owner: &str) -> Result<Vec<Value>, String> {
    let req = Frame::new(serde_json::json!({"t": "jobs", "owner": owner}));
    let reply = request_one(sock, req, Duration::from_secs(10)).await?;
    Ok(reply.header.get("jobs").and_then(Value::as_array).cloned().unwrap_or_default())
}

/// Ask the worker to cancel `job` on behalf of `owner`.
pub async fn cancel_job(sock: &Path, owner: &str, job: &str) -> Result<(), String> {
    let req = Frame::new(serde_json::json!({"t": "cancel_job", "owner": owner, "job": job}));
    request_one(sock, req, Duration::from_secs(10)).await.map(|_| ())
}

/// How many of `jobs` (a `job_list`) are still running.
pub fn count_running(jobs: &[Value]) -> usize {
    jobs.iter().filter(|j| j.get("state").and_then(Value::as_str) == Some("running")).count()
}
