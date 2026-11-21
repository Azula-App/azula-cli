//! Restart reconciliation, using the real binary so the worker can be killed.

mod common;

use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use common::*;
use serde_json::json;

struct Worker {
    child: Child,
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_worker(state: &Path, sock: &Path) -> Worker {
    let child = Command::new(env!("CARGO_BIN_EXE_azula-guest"))
        .args(["--unix", &path_str(sock), "--state-dir", &path_str(state)])
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_for("socket", 10, || UnixStream::connect(sock).is_ok());
    Worker { child }
}

fn unix(sock: &Path) -> Client<UnixStream> {
    let s = UnixStream::connect(sock).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    Client(s)
}

#[test]
fn worker_restart_marks_running_jobs_interrupted() {
    let dir = TempDir::new();
    let state = dir.0.join("state");
    let sock = dir.0.join("w.sock");

    let w1 = spawn_worker(&state, &sock);
    // A finished job with output, and a long-running one.
    let mut c = unix(&sock);
    c.send(
        exec_req("g_a", &["sh", "-c", "echo before; echo err >&2"]),
        &[],
    );
    let done = c.collect();
    let done_id = done.started.unwrap().header["job"]
        .as_str()
        .unwrap()
        .to_string();
    let mut c = unix(&sock);
    c.send(
        merge(
            exec_req("g_a", &["sh", "-c", "echo partial; exec sleep 7790"]),
            json!({"attach":false}),
        ),
        &[],
    );
    let st = c.recv();
    let (run_id, pid) = (
        st.header["job"].as_str().unwrap().to_string(),
        st.header["pid"].as_i64().unwrap() as i32,
    );
    wait_for("partial output", 5, || {
        std::fs::read(dir.0.join("state/jobs").join(&run_id).join("stdout/0"))
            .is_ok_and(|b| b == b"partial\n")
    });

    // Kill the worker hard: no exit.json for the running job.
    drop(w1);
    assert!(!dir
        .0
        .join("state/jobs")
        .join(&run_id)
        .join("exit.json")
        .exists());

    let _w2 = spawn_worker(&state, &sock);
    let mut c = unix(&sock);
    c.send(json!({"t":"jobs","owner":"g_a"}), &[]);
    let list = c.recv().header["jobs"].as_array().unwrap().clone();
    let get = |id: &str| list.iter().find(|j| j["job"] == id).unwrap().clone();
    let r = get(&run_id);
    assert_eq!(r["state"], "interrupted");
    assert_eq!(r["reason"], "interrupted");
    assert!(r["code"].is_null());
    assert_eq!(r["stdout_len"], 8);
    assert_eq!(get(&done_id)["state"], "exited");
    assert_eq!(get(&done_id)["code"], 0);

    // attach to the interrupted job replays its output, then exits with that reason.
    let mut c = unix(&sock);
    c.send(
        json!({"t":"attach","owner":"g_a","job":run_id,"follow":true}),
        &[],
    );
    let r = c.collect();
    assert_eq!(r.attached.as_ref().unwrap().header["state"], "interrupted");
    assert_eq!(r.stdout, b"partial\n");
    assert_eq!(r.last().t, "exit");
    assert_eq!(r.h("reason"), "interrupted");
    assert!(r.h("code").is_null());

    // The finished job's output survived too.
    let mut c = unix(&sock);
    c.send(
        json!({"t":"attach","owner":"g_a","job":done_id,"follow":false}),
        &[],
    );
    let r = c.collect();
    assert_eq!(
        (r.stdout.as_slice(), r.stderr.as_slice()),
        (&b"before\n"[..], &b"err\n"[..])
    );

    // Idem keys survive a restart as well.
    let mut c = unix(&sock);
    let again = json!({"t":"exec","owner":"g_a","idem":"same","argv":["echo","x"]});
    c.send(again.clone(), &[]);
    let first = c.collect();
    drop(first);
    let _w3 = {
        drop(_w2);
        spawn_worker(&state, &sock)
    };
    let mut c = unix(&sock);
    c.send(again, &[]);
    let r = c.collect();
    assert_eq!(r.started.as_ref().unwrap().header["deduped"], true);
    assert_eq!(r.stdout, b"x\n");

    // The orphaned process outlived the worker (no cgroup on macOS); clean up.
    unsafe { libc::kill(-pid, libc::SIGKILL) };
}
