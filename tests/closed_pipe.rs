//! A closed stdout must end the client verbs quietly with 141, never a panic,
//! and the process must not die from SIGPIPE (Rust ignores it, so EPIPE is
//! returned to us), which is what lets the relay connection reconnect.

#![cfg(unix)]

use std::os::fd::FromRawFd;
use std::process::{Command, Stdio};

/// A pipe whose read end is already closed: every write gets EPIPE.
fn closed_pipe_stdout() -> Stdio {
    let mut fds = [0i32; 2];
    // SAFETY: plain pipe(2)/close(2) on descriptors we just created.
    unsafe {
        assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
        libc::close(fds[0]);
        Stdio::from_raw_fd(fds[1])
    }
}

#[test]
fn printing_to_a_closed_pipe_exits_141_without_a_panic() {
    // `compute doctor` with no token prints its first stage line without any network.
    let out = Command::new(env!("CARGO_BIN_EXE_azula"))
        .args(["compute", "doctor"])
        .env_remove("AZULA_COMPUTE_TOKEN")
        .stdout(closed_pipe_stdout())
        .stderr(Stdio::piped())
        .output()
        .expect("run azula");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(141), "stderr: {stderr}");
    assert!(!stderr.contains("panicked"), "no panic: {stderr}");
    assert!(!stderr.contains("Broken pipe"), "no message: {stderr}");
}
