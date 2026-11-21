use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use azula_guest::frame::{read_frame, write_frame, Frame};
use azula_guest::server::{serve_tcp, Config};
use serde_json::{json, Value};

fn start() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    thread::spawn(move || {
        let _ = serve_tcp(
            l,
            Config {
                run_as: "azula".into(),
            },
        );
    });
    port
}

struct Client(TcpStream);

struct Result {
    started: Option<Frame>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    last: Frame,
    max_chunk: usize,
}

impl Client {
    fn connect() -> Client {
        let c = TcpStream::connect(("127.0.0.1", start())).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
        Client(c)
    }
    fn send(&mut self, h: Value, payload: &[u8]) {
        write_frame(&mut self.0, &h, payload).unwrap();
    }
    fn recv(&mut self) -> Frame {
        read_frame(&mut self.0).unwrap().expect("unexpected EOF")
    }
    /// Collect frames until exit or error.
    fn collect(&mut self) -> Result {
        let mut r = Result {
            started: None,
            stdout: vec![],
            stderr: vec![],
            last: Frame {
                t: String::new(),
                header: Default::default(),
                payload: vec![],
            },
            max_chunk: 0,
        };
        loop {
            let f = self.recv();
            match f.t.as_str() {
                "started" => r.started = Some(f),
                "stdout" => {
                    r.max_chunk = r.max_chunk.max(f.payload.len());
                    r.stdout.extend_from_slice(&f.payload)
                }
                "stderr" => {
                    r.max_chunk = r.max_chunk.max(f.payload.len());
                    r.stderr.extend_from_slice(&f.payload)
                }
                "exit" | "error" => {
                    r.last = f;
                    // Connection must be closed after the final frame.
                    assert!(read_frame(&mut self.0).unwrap().is_none());
                    return r;
                }
                other => panic!("unexpected frame {other}"),
            }
        }
    }
}

fn exec(argv: &[&str]) -> Value {
    json!({"t":"exec","argv":argv})
}

fn run(req: Value) -> Result {
    let mut c = Client::connect();
    c.send(req, &[]);
    c.collect()
}

fn pgrep(pattern: &str) -> bool {
    Command::new("pgrep")
        .args(["-f", pattern])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn wait_for(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end {
        if f() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out waiting for {what}");
}

#[test]
fn ping_pong() {
    let mut c = Client::connect();
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
    assert!(read_frame(&mut c.0).unwrap().is_none());
}

#[test]
fn echo_hi() {
    let r = run(exec(&["echo", "hi"]));
    assert!(r.started.unwrap().header["pid"].as_u64().unwrap() > 0);
    assert_eq!(r.stdout, b"hi\n");
    assert!(r.stderr.is_empty());
    assert_eq!(r.last.t, "exit");
    assert_eq!(r.last.header["code"], 0);
    assert!(r.last.header["signal"].is_null());
    assert_eq!(r.last.header["reason"], "exited");
}

#[test]
fn stderr_routing() {
    let r = run(exec(&["sh", "-c", "echo e >&2"]));
    assert!(r.stdout.is_empty());
    assert_eq!(r.stderr, b"e\n");
    assert_eq!(r.last.header["code"], 0);
}

#[test]
fn nonzero_exit() {
    let r = run(exec(&["sh", "-c", "exit 7"]));
    assert_eq!(r.last.header["code"], 7);
    assert_eq!(r.last.header["reason"], "exited");
}

#[test]
fn killed_by_signal_has_null_code() {
    let r = run(exec(&["sh", "-c", "kill -9 $$"]));
    assert!(r.last.header["code"].is_null());
    assert_eq!(r.last.header["signal"], 9);
}

#[test]
fn env_overrides_and_clean_base() {
    let r = run(
        json!({"t":"exec","argv":["sh","-c","echo $FOO $LANG; env | grep -c ^HOME="],
        "env":{"FOO":"bar"}}),
    );
    assert_eq!(r.stdout, b"bar C.UTF-8\n1\n");
}

#[test]
fn cwd_is_honored() {
    let r = run(json!({"t":"exec","argv":["pwd","-P"],"cwd":"/"}));
    assert_eq!(r.stdout, b"/\n");
}

#[test]
fn stdin_round_trip() {
    let mut c = Client::connect();
    c.send(json!({"t":"exec","argv":["cat"],"stdin":true}), &[]);
    c.send(json!({"t":"stdin"}), b"hello ");
    c.send(json!({"t":"stdin"}), b"world\n");
    c.send(json!({"t":"stdin_eof"}), &[]);
    let r = c.collect();
    assert_eq!(r.stdout, b"hello world\n");
    assert_eq!(r.last.header["code"], 0);
}

#[test]
fn stdin_defaults_to_dev_null() {
    let r = run(exec(&["cat"]));
    assert!(r.stdout.is_empty());
    assert_eq!(r.last.header["code"], 0);
}

#[test]
fn large_output_complete_and_ordered() {
    const N: usize = 5 * 1024 * 1024;
    let r = run(exec(&[
        "sh",
        "-c",
        "yes 0123456789abcdef | head -c 5242880",
    ]));
    assert_eq!(r.stdout.len(), N);
    assert!(r.max_chunk <= 64 * 1024);
    let line = b"0123456789abcdef\n";
    for (i, b) in r.stdout.iter().enumerate() {
        assert_eq!(*b, line[i % line.len()], "mismatch at {i}");
    }
    assert_eq!(r.last.header["code"], 0);
}

#[test]
fn cancel_sleep() {
    let mut c = Client::connect();
    c.send(exec(&["sleep", "100"]), &[]);
    assert_eq!(c.recv().t, "started");
    let t = Instant::now();
    c.send(json!({"t":"cancel"}), &[]);
    let r = c.collect();
    assert!(t.elapsed() < Duration::from_secs(3));
    assert_eq!(r.last.header["reason"], "cancelled");
    assert!(r.last.header["code"].is_null());
    assert_eq!(r.last.header["signal"], libc::SIGTERM);
}

#[test]
fn cancel_kills_process_group() {
    let mut c = Client::connect();
    c.send(exec(&["sh", "-c", "sleep 7771 & sleep 7771"]), &[]);
    assert_eq!(c.recv().t, "started");
    wait_for("sleeps to start", 5, || pgrep("sleep 7771"));
    c.send(json!({"t":"cancel"}), &[]);
    let r = c.collect();
    assert_eq!(r.last.header["reason"], "cancelled");
    wait_for("sleeps to die", 5, || !pgrep("sleep 7771"));
}

#[test]
fn timeout() {
    let t = Instant::now();
    let r = run(json!({"t":"exec","argv":["sleep","100"],"timeout_s":1}));
    assert_eq!(r.last.header["reason"], "timeout");
    assert!(t.elapsed() < Duration::from_secs(5));
}

#[test]
fn sigterm_ignoring_job_is_sigkilled() {
    let mut c = Client::connect();
    c.send(
        exec(&[
            "sh",
            "-c",
            "trap '' TERM; echo ready; while :; do sleep 1; done",
        ]),
        &[],
    );
    loop {
        let f = c.recv();
        if f.t == "stdout" {
            break;
        }
    }
    let t = Instant::now();
    c.send(json!({"t":"cancel"}), &[]);
    let r = c.collect();
    assert_eq!(r.last.header["reason"], "cancelled");
    assert_eq!(r.last.header["signal"], libc::SIGKILL);
    assert!(t.elapsed() >= Duration::from_secs(4));
}

#[test]
fn spawn_failed() {
    let r = run(exec(&["/nonexistent/azula-prog"]));
    assert_eq!(r.last.t, "error");
    assert_eq!(r.last.header["code"], "spawn_failed");
    assert!(r.started.is_none());
}

#[test]
fn cwd_missing() {
    let r = run(json!({"t":"exec","argv":["true"],"cwd":"/nonexistent-azula-dir"}));
    assert_eq!(r.last.t, "error");
    assert_eq!(r.last.header["code"], "cwd_missing");
}

#[test]
fn bad_requests() {
    for req in [
        json!({"t":"exec"}),
        json!({"t":"exec","argv":[]}),
        json!({"t":"exec","argv":[1]}),
        json!({"t":"exec","argv":["true"],"env":{"A":1}}),
        json!({"t":"nope"}),
    ] {
        let r = run(req.clone());
        assert_eq!(r.last.t, "error", "{req}");
        assert_eq!(r.last.header["code"], "bad_request", "{req}");
    }
}

#[test]
fn protocol_error_closes_connection() {
    let mut c = Client::connect();
    c.0.write_all(&[0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
    let r = c.collect();
    assert_eq!(r.last.header["code"], "bad_request");
}

#[test]
fn closing_connection_kills_job() {
    let mut c = Client::connect();
    c.send(exec(&["sh", "-c", "sleep 7772 & sleep 7772"]), &[]);
    assert_eq!(c.recv().t, "started");
    wait_for("sleeps to start", 5, || pgrep("sleep 7772"));
    drop(c);
    wait_for("sleeps to die", 10, || !pgrep("sleep 7772"));
}

#[test]
fn concurrent_jobs() {
    let port = start();
    let hs: Vec<_> = (0..8)
        .map(|i| {
            thread::spawn(move || {
                let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
                write_frame(
                    &mut c,
                    &exec(&["sh", "-c", &format!("sleep 0.3; echo {i}")]),
                    &[],
                )
                .unwrap();
                let mut out = vec![];
                loop {
                    let f = read_frame(&mut c).unwrap().unwrap();
                    match f.t.as_str() {
                        "stdout" => out.extend(f.payload),
                        "exit" => break,
                        _ => {}
                    }
                }
                assert_eq!(out, format!("{i}\n").into_bytes());
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
}
