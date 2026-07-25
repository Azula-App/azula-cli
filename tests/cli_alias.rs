//! Integration test: a deprecated CLI alias (`azula serve-mcp`) prints a
//! one-line stderr deprecation notice, then otherwise behaves normally
//! (delegates to the replacement's behavior) — cli-surface spec, "Legacy
//! alias still works": "it behaves as the corresponding new command and
//! prints a deprecation notice to stderr".
//!
//! Spawns the actual built binary (`CARGO_BIN_EXE_azula`, only set for
//! integration tests under `tests/`) rather than calling into the library,
//! since the behavior under test — what a real invocation of the `azula`
//! binary prints — is specifically about the compiled CLI entry point.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn serve_mcp_alias_prints_deprecation_notice_then_behaves_normally() {
    let bin = env!("CARGO_BIN_EXE_azula");

    // Isolate every stateful path this invocation could touch so the test
    // never reads/writes a developer's real ~/.azula.
    let tmp = std::env::temp_dir().join(format!("azula-cli-alias-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("create isolated test dir");

    let mut child = Command::new(bin)
        // --bind 127.0.0.1:0 (an ephemeral local port) + --legacy-ticket
        // (skip invite minting) keep this from needing real network access;
        // the deprecation notice prints before any of that regardless.
        .args(["serve-mcp", "--bind", "127.0.0.1:0", "--legacy-ticket"])
        .env("AZULA_KEY_DIR", tmp.join("keys"))
        .env("AZULA_SESSIONS_DIR", tmp.join("sessions"))
        .env("AZULA_REGISTRY_DIR", tmp.join("registry"))
        .env("AZULA_STATE_DIR", tmp.join("state"))
        .env("AZULA_MAILBOX_DIR", tmp.join("mailbox"))
        .env("RUST_LOG", "error")
        .stdin(Stdio::null())
        // Drained on a background thread below — `serve-mcp` prints a
        // sizeable startup banner + QR block to stdout, easily enough to
        // fill an unread OS pipe buffer and wedge the child mid-write.
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn `azula serve-mcp`");

    let mut stdout_pipe = child.stdout.take().expect("stdout was piped");
    let stdout_drain = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf);
    });

    let mut stderr_pipe = child.stderr.take().expect("stderr was piped");
    let stderr_reader = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = stderr_pipe.read_to_string(&mut buf);
        buf
    });

    // `serve-mcp` runs forever (it's a long-lived server) — the deprecation
    // notice is the very first thing it does, synchronously, before binding
    // anything. Poll briefly so a real early failure (e.g. it exits instead
    // of serving) surfaces as a clear panic instead of a confusing empty-
    // stderr assertion failure below.
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            panic!("`azula serve-mcp` exited early with {status:?} instead of running as a server");
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let _ = child.kill();
    let _ = child.wait();
    let stderr = stderr_reader.join().unwrap_or_default();
    let _ = stdout_drain.join();

    assert!(
        stderr.contains("`azula serve-mcp` is deprecated"),
        "expected a deprecation notice naming `azula serve-mcp`, got stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("azula mcp --http"),
        "expected the notice to point at the replacement command, got stderr:\n{stderr}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
