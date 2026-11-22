//! `--systemd-socket`: the worker adopts a listening socket passed as fd 3
//! (`LISTEN_PID`/`LISTEN_FDS`), runs jobs as its own non-root user, and
//! serves file operations without needing to chown.

mod common;

use std::fs;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use common::*;
use serde_json::json;

fn whoami() -> String {
    let o = Command::new("id").arg("-un").output().unwrap();
    String::from_utf8(o.stdout).unwrap().trim().to_string()
}

/// Spawn `azula-guest --systemd-socket` with `listener` as fd 3 and
/// `LISTEN_PID` set to the worker's own pid (the shell's `$$`, kept by `exec`).
fn spawn_activated(listener: &UnixListener, state: &Path, run_as: &str, listen_fds: &str) -> Child {
    let fd = listener.as_raw_fd();
    let script = format!("LISTEN_PID=$$ LISTEN_FDS={listen_fds} exec \"$0\" \"$@\"");
    let mut cmd = Command::new("sh");
    cmd.args(["-c", &script, env!("CARGO_BIN_EXE_azula-guest"), "--systemd-socket", "--run-as", run_as, "--state-dir", &path_str(state)])
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // SAFETY: only async-signal-safe calls (dup2, fcntl) between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            if fd == 3 {
                // dup2 onto itself is a no-op and would leave CLOEXEC set.
                if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            } else if libc::dup2(fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.spawn().unwrap()
}

fn stop(mut child: Child) -> String {
    let _ = child.kill();
    let mut err = String::new();
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_string(&mut err);
    }
    let _ = child.wait();
    err
}

fn unix(sock: &Path) -> Client<UnixStream> {
    let s = UnixStream::connect(sock).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    Client(s)
}

#[test]
fn serves_on_the_activated_socket_as_the_workers_own_user() {
    let dir = TempDir::new();
    let sock = dir.0.join("worker.sock");
    // Bound before the worker exists, like systemd does: a client that
    // connects early just queues until the worker accepts.
    let listener = UnixListener::bind(&sock).unwrap();
    let me = whoami();
    let child = spawn_activated(&listener, &dir.0.join("state"), &me, "1");

    // ping
    let mut c = unix(&sock);
    c.send(json!({"t":"ping"}), &[]);
    let pong = c.recv();
    assert_eq!(pong.t, "pong", "{pong:?}");
    assert_eq!(pong.header["user"], me);

    // job runs as the worker's own uid, and the activation fd is not leaked
    let mut c = unix(&sock);
    c.send(exec_req("g_a", &["sh", "-c", "id -un; echo ${LISTEN_FDS:-unset}; [ -e /dev/fd/3 ] && echo leaked || echo clean"]), &[]);
    let r = c.collect();
    assert_eq!(r.h("code"), 0, "{:?}", r.last());
    assert_eq!(String::from_utf8_lossy(&r.stdout), format!("{me}\nunset\nclean\n"));

    // non-root file put/get (no chown to another user is possible or needed)
    let target = dir.0.join("files/up.bin");
    let data = b"activated hello".to_vec();
    let mut c = unix(&sock);
    c.send(json!({"t":"put","owner":"g_a","path":path_str(&target),"upload":"u-act","mode":0o640}), &[]);
    assert_eq!(c.recv().t, "put_ready");
    c.send(json!({"t":"data"}), &data);
    let mut h = azula_guest::sha256::Sha256::new();
    h.update(&data);
    c.send(json!({"t":"eof","size":data.len(),"sha256":h.hex()}), &[]);
    let ok = c.recv();
    assert_eq!(ok.t, "put_ok", "{ok:?}");
    assert_eq!(fs::read(&target).unwrap(), data);

    let mut c = unix(&sock);
    c.send(json!({"t":"get","owner":"g_a","path":path_str(&target)}), &[]);
    let meta = c.recv();
    assert_eq!(meta.t, "get_meta", "{meta:?}");
    let f = c.recv();
    assert_eq!((f.t.as_str(), f.payload.as_slice()), ("data", data.as_slice()));

    let err = stop(child);
    assert!(!err.contains("not running as root"), "spurious run-as warning: {err}");
    assert!(err.contains("systemd-activated"), "{err}");
}

#[test]
fn missing_activation_environment_is_a_clear_error() {
    let dir = TempDir::new();
    let o = Command::new(env!("CARGO_BIN_EXE_azula-guest"))
        .args(["--systemd-socket", "--state-dir", &path_str(&dir.0.join("state"))])
        .env_remove("LISTEN_PID")
        .env_remove("LISTEN_FDS")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("LISTEN_PID/LISTEN_FDS are not set"), "{err}");
}

#[test]
fn activation_fd_that_is_not_open_is_a_clear_error() {
    let dir = TempDir::new();
    let listener = UnixListener::bind(dir.0.join("s")).unwrap();
    // LISTEN_FDS=1 but we never install the socket on fd 3.
    drop(listener);
    let script = "LISTEN_PID=$$ LISTEN_FDS=1 exec \"$0\" \"$@\"";
    let o = Command::new("sh")
        .args(["-c", script, env!("CARGO_BIN_EXE_azula-guest"), "--systemd-socket", "--state-dir", &path_str(&dir.0.join("state"))])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("fd 3"), "{err}");
}
