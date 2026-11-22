mod common;

use std::io::Write;
use std::thread;
use std::time::{Duration, Instant};

use common::*;
use serde_json::json;

#[test]
fn ping_pong() {
    let env = start();
    let (job, _) = detach(&env, exec_req("g_a", &["sleep", "7701"]));
    let mut c = env.client();
    c.send(json!({"t":"ping"}), &[]);
    let f = c.recv();
    assert_eq!(f.t, "pong");
    assert_eq!(
        f.header["worker"],
        format!("azula-guest/{}", env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(f.header["proto"], 1);
    assert!(f.header["hostname"].is_string());
    assert!(!f.header["kernel"].as_str().unwrap().is_empty());
    assert_eq!(f.header["arch"], std::env::consts::ARCH);
    assert!(!f.header["user"].as_str().unwrap().is_empty());
    assert_eq!(f.header["jobs_running"], 1);
    assert!(f.header["disk_free_mb"].as_u64().unwrap() > 0);
    c.expect_closed();
    cancel_job(&env, "g_a", &job);
}

#[test]
fn echo_hi() {
    let env = start();
    let r = run(&env, exec_req("g_a", &["echo", "hi"]));
    let st = r.started.as_ref().unwrap();
    assert!(st.header["job"].as_str().unwrap().starts_with("j_"));
    assert_eq!(st.header["job"].as_str().unwrap().len(), 18);
    assert!(st.header["pid"].as_u64().unwrap() > 0);
    assert_eq!(st.header["deduped"], false);
    assert_eq!(r.stdout, b"hi\n");
    assert!(r.stderr.is_empty());
    assert_eq!(r.last().t, "exit");
    assert_eq!(r.h("job"), st.header["job"]);
    assert_eq!(r.h("code"), 0);
    assert!(r.h("signal").is_null());
    assert_eq!(r.h("reason"), "exited");
    assert_eq!(r.h("stdout_len"), 3);
    assert_eq!(r.h("stderr_len"), 0);
}

#[test]
fn stderr_routing() {
    let env = start();
    let r = run(&env, exec_req("g_a", &["sh", "-c", "echo e >&2"]));
    assert!(r.stdout.is_empty());
    assert_eq!(r.stderr, b"e\n");
    assert_eq!(r.h("stderr_len"), 2);
}

#[test]
fn nonzero_exit() {
    let env = start();
    let r = run(&env, exec_req("g_a", &["sh", "-c", "exit 7"]));
    assert_eq!(r.h("code"), 7);
    assert_eq!(r.h("reason"), "exited");
}

#[test]
fn killed_by_signal_has_null_code() {
    let env = start();
    let r = run(&env, exec_req("g_a", &["sh", "-c", "kill -9 $$"]));
    assert!(r.h("code").is_null());
    assert_eq!(r.h("signal"), 9);
}

#[test]
fn env_overrides_and_clean_base() {
    let env = start();
    let r = run(
        &env,
        merge(
            exec_req(
                "g_a",
                &["sh", "-c", "echo $FOO $LANG; env | grep -c ^HOME="],
            ),
            json!({"env":{"FOO":"bar"}}),
        ),
    );
    assert_eq!(r.stdout, b"bar C.UTF-8\n1\n");
}

#[test]
fn job_env_applies_under_request_env() {
    let env = start_with(|c| {
        c.job_env = vec![
            ("HTTPS_PROXY".into(), "http://127.0.0.1:3128".into()),
            ("FOO".into(), "from-job-env".into()),
        ]
    });
    let r = run(
        &env,
        merge(
            exec_req("g_a", &["sh", "-c", "echo $HTTPS_PROXY $FOO"]),
            json!({"env":{"FOO":"from-request"}}),
        ),
    );
    assert_eq!(r.stdout, b"http://127.0.0.1:3128 from-request\n");
}

#[test]
fn cwd_is_honored() {
    let env = start();
    let r = run(
        &env,
        merge(exec_req("g_a", &["pwd", "-P"]), json!({"cwd":"/"})),
    );
    assert_eq!(r.stdout, b"/\n");
}

#[test]
fn stdin_round_trip() {
    let env = start();
    let mut c = env.client();
    c.send(merge(exec_req("g_a", &["cat"]), json!({"stdin":true})), &[]);
    c.send(json!({"t":"stdin"}), b"hello ");
    c.send(json!({"t":"stdin"}), b"world\n");
    c.send(json!({"t":"stdin_eof"}), &[]);
    let r = c.collect();
    assert_eq!(r.stdout, b"hello world\n");
    assert_eq!(r.h("code"), 0);
    assert_eq!(r.h("reason"), "exited");
}

#[test]
fn stdin_defaults_to_dev_null() {
    let env = start();
    let r = run(&env, exec_req("g_a", &["cat"]));
    assert!(r.stdout.is_empty());
    assert_eq!(r.h("code"), 0);
}

#[test]
fn large_output_complete_and_ordered() {
    let env = start();
    const N: usize = 5 * 1024 * 1024;
    let r = run(
        &env,
        exec_req(
            "g_a",
            &["sh", "-c", "yes 0123456789abcdef | head -c 5242880"],
        ),
    );
    assert_eq!(r.stdout.len(), N);
    assert!(r.max_chunk <= 64 * 1024);
    let line = b"0123456789abcdef\n";
    for (i, b) in r.stdout.iter().enumerate() {
        assert_eq!(*b, line[i % line.len()], "mismatch at {i}");
    }
    assert_eq!(r.h("stdout_len"), N as u64);
}

#[test]
fn cancel_sleep() {
    let env = start();
    let mut c = env.client();
    c.send(exec_req("g_a", &["sleep", "100"]), &[]);
    assert_eq!(c.recv().t, "started");
    let t = Instant::now();
    c.send(json!({"t":"cancel"}), &[]);
    let r = c.collect();
    assert!(t.elapsed() < Duration::from_secs(3));
    assert_eq!(r.h("reason"), "cancelled");
    assert!(r.h("code").is_null());
    assert_eq!(r.h("signal"), libc::SIGTERM);
}

#[test]
fn cancel_kills_process_group() {
    let env = start();
    let mut c = env.client();
    c.send(
        exec_req("g_a", &["sh", "-c", "sleep 7771 & sleep 7771"]),
        &[],
    );
    assert_eq!(c.recv().t, "started");
    wait_for("sleeps to start", 5, || pgrep("sleep 7771"));
    c.send(json!({"t":"cancel"}), &[]);
    let r = c.collect();
    assert_eq!(r.h("reason"), "cancelled");
    wait_for("sleeps to die", 5, || !pgrep("sleep 7771"));
}

#[test]
fn timeout() {
    let env = start();
    let t = Instant::now();
    let r = run(
        &env,
        merge(exec_req("g_a", &["sleep", "100"]), json!({"timeout_s":1})),
    );
    assert_eq!(r.h("reason"), "timeout");
    assert!(t.elapsed() < Duration::from_secs(5));
}

#[test]
fn sigterm_ignoring_job_is_sigkilled() {
    let env = start();
    let mut c = env.client();
    c.send(
        exec_req(
            "g_a",
            &[
                "sh",
                "-c",
                "trap '' TERM; echo ready; while :; do sleep 1; done",
            ],
        ),
        &[],
    );
    loop {
        if c.recv().t == "stdout" {
            break;
        }
    }
    let t = Instant::now();
    c.send(json!({"t":"cancel"}), &[]);
    let r = c.collect_from([6, 0]);
    assert_eq!(r.h("reason"), "cancelled");
    assert_eq!(r.h("signal"), libc::SIGKILL);
    assert!(t.elapsed() >= Duration::from_secs(4));
}

#[test]
fn spawn_failed() {
    let env = start();
    let r = run(&env, exec_req("g_a", &["/nonexistent/azula-prog"]));
    assert_eq!(r.last().t, "error");
    assert_eq!(r.h("code"), "spawn_failed");
    assert!(r.started.is_none());
    // The failed job leaves no record behind.
    assert!(jobs(&env, "g_a").is_empty());
}

#[test]
fn cwd_missing() {
    let env = start();
    let r = run(
        &env,
        merge(
            exec_req("g_a", &["true"]),
            json!({"cwd":"/nonexistent-azula-dir"}),
        ),
    );
    assert_eq!(r.h("code"), "cwd_missing");
}

#[test]
fn bad_requests() {
    let env = start();
    for req in [
        json!({"t":"exec","owner":"g_a","idem":"x"}),
        json!({"t":"exec","owner":"g_a","idem":"x","argv":[]}),
        json!({"t":"exec","owner":"g_a","idem":"x","argv":[1]}),
        json!({"t":"exec","owner":"g_a","idem":"x","argv":["true"],"env":{"A":1}}),
        json!({"t":"exec","owner":"g_a","argv":["true"]}),
        json!({"t":"exec","idem":"x","argv":["true"]}),
        json!({"t":"exec","owner":"g_a","idem":"x","argv":["cat"],"stdin":true,"attach":false}),
        json!({"t":"nope"}),
    ] {
        let r = run(&env, req.clone());
        assert_eq!(r.last().t, "error", "{req}");
        assert_eq!(r.h("code"), "bad_request", "{req}");
    }
}

#[test]
fn protocol_error_closes_connection() {
    let env = start();
    let mut c = env.client();
    c.0.write_all(&[0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
    let r = c.collect();
    assert_eq!(r.h("code"), "bad_request");
}

#[test]
fn concurrent_jobs() {
    let env = start();
    let port = env.port;
    let hs: Vec<_> = (0..8)
        .map(|i| {
            thread::spawn(move || {
                let mut c = Client::connect(port);
                c.send(
                    exec_req("g_a", &["sh", "-c", &format!("sleep 0.3; echo {i}")]),
                    &[],
                );
                let r = c.collect();
                assert_eq!(r.stdout, format!("{i}\n").into_bytes());
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
}
