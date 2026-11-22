use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::process::exit;

use azula_guest::server::{serve_tcp, serve_unix, Config, Server, DEFAULT_STATE_DIR};

enum Listen {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Vsock(u32),
    Tcp(String),
    Unix(String),
}

const USAGE: &str =
    "usage: azula-guest [--vsock-port N | --tcp ADDR | --unix PATH] [--run-as USER] [--state-dir DIR] [--job-env-file PATH] [--version]";

/// `KEY=VALUE` lines (blank lines and `#` comments ignored) added to every
/// job's environment.
fn read_job_env(path: &str) -> Vec<(String, String)> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| die(&format!("cannot read --job-env-file {path}: {e}")));
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('=').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
        .filter(|(k, _)| !k.is_empty())
        .collect()
}

fn die(msg: &str) -> ! {
    eprintln!("azula-guest: {msg}");
    exit(2);
}

fn num(v: &str) -> u64 {
    v.parse()
        .unwrap_or_else(|_| die(&format!("bad number {v:?}")))
}

fn main() {
    let mut listen: Option<Listen> = None;
    let mut run_as = "azula".to_string();
    let mut cfg = Config::new("azula", DEFAULT_STATE_DIR);
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = |name: &str| {
            args.next()
                .unwrap_or_else(|| die(&format!("{name} needs a value")))
        };
        match a.as_str() {
            "--version" | "-V" => {
                println!("azula-guest {}", azula_guest::VERSION);
                return;
            }
            "--help" | "-h" => {
                println!("{USAGE}");
                return;
            }
            "--vsock-port" => {
                let v = val("--vsock-port");
                let n = v
                    .parse()
                    .unwrap_or_else(|_| die(&format!("bad port {v:?}")));
                listen = Some(Listen::Vsock(n));
            }
            "--tcp" => listen = Some(Listen::Tcp(val("--tcp"))),
            "--unix" => listen = Some(Listen::Unix(val("--unix"))),
            "--run-as" => run_as = val("--run-as"),
            "--state-dir" => cfg.state_dir = val("--state-dir").into(),
            "--job-env-file" => cfg.job_env = read_job_env(&val("--job-env-file")),
            // Test knobs.
            "--segment-size" => cfg.segment_size = num(&val("--segment-size")),
            "--keep-segments" => cfg.keep_segments = num(&val("--keep-segments")) as usize,
            "--orphan-secs" => {
                cfg.orphan_after = std::time::Duration::from_secs(num(&val("--orphan-secs")))
            }
            other => die(&format!("unknown argument {other:?}\n{USAGE}")),
        }
    }
    let listen = listen.unwrap_or(Listen::Vsock(1024));
    cfg.run_as = run_as;
    let srv = match Server::open(cfg) {
        Ok(s) => s,
        Err(e) => die(&format!("cannot open state dir: {e}")),
    };
    let result = match listen {
        Listen::Tcp(addr) => TcpListener::bind(&addr)
            .inspect(|l| {
                if let Ok(a) = l.local_addr() {
                    eprintln!("azula-guest: listening on tcp {a}");
                }
            })
            .and_then(|l| serve_tcp(l, srv)),
        Listen::Unix(path) => {
            let _ = std::fs::remove_file(&path);
            UnixListener::bind(&path)
                .inspect(|_| eprintln!("azula-guest: listening on unix {path}"))
                .and_then(|l| serve_unix(l, srv))
        }
        #[cfg(target_os = "linux")]
        Listen::Vsock(port) => {
            eprintln!("azula-guest: listening on vsock port {port}");
            azula_guest::vsock::serve(port, srv)
        }
        #[cfg(not(target_os = "linux"))]
        Listen::Vsock(_) => die("vsock is only available on Linux; use --tcp or --unix"),
    };
    if let Err(e) = result {
        die(&format!("listener failed: {e}"));
    }
}
