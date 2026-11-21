use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::process::exit;

use azula_guest::server::{serve_tcp, serve_unix, Config};

enum Listen {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Vsock(u32),
    Tcp(String),
    Unix(String),
}

const USAGE: &str =
    "usage: azula-guest [--vsock-port N | --tcp ADDR | --unix PATH] [--run-as USER] [--version]";

fn die(msg: &str) -> ! {
    eprintln!("azula-guest: {msg}");
    exit(2);
}

fn main() {
    let mut listen: Option<Listen> = None;
    let mut run_as = "azula".to_string();
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
            other => die(&format!("unknown argument {other:?}\n{USAGE}")),
        }
    }
    let listen = listen.unwrap_or(Listen::Vsock(1024));
    let cfg = Config { run_as };
    let result = match listen {
        Listen::Tcp(addr) => TcpListener::bind(&addr)
            .inspect(|l| {
                if let Ok(a) = l.local_addr() {
                    eprintln!("azula-guest: listening on tcp {a}");
                }
            })
            .and_then(|l| serve_tcp(l, cfg)),
        Listen::Unix(path) => {
            let _ = std::fs::remove_file(&path);
            UnixListener::bind(&path)
                .inspect(|_| eprintln!("azula-guest: listening on unix {path}"))
                .and_then(|l| serve_unix(l, cfg))
        }
        #[cfg(target_os = "linux")]
        Listen::Vsock(port) => {
            eprintln!("azula-guest: listening on vsock port {port}");
            azula_guest::vsock::serve(port, cfg)
        }
        #[cfg(not(target_os = "linux"))]
        Listen::Vsock(_) => die("vsock is only available on Linux; use --tcp or --unix"),
    };
    if let Err(e) = result {
        die(&format!("listener failed: {e}"));
    }
}
