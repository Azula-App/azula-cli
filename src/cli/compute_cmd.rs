//! `azula compute` — run commands in a VM on a remote Mac over iroh.
//!
//! Host verbs (`serve`, `grant`, `grants`, `revoke`) run on Apple silicon
//! macOS only; client verbs (`exec`, `doctor`) run anywhere. The `vm`
//! noun lives in `vm_cmd`. Contract: `vm/BROKER.md` §5–§7.

use std::io::Write;
use std::time::Duration;

use anyhow::Result;
use clap::{Args, Subcommand};
use tokio::sync::mpsc;

use crate::compute::client::{self, Event, ExecRequest, Failure, Outcome};
use crate::compute::grants::Token;

#[derive(Debug, Args)]
pub(super) struct ComputeArgs {
    #[command(subcommand)]
    action: ComputeAction,
}

#[derive(Debug, Subcommand)]
enum ComputeAction {
    /// Host (Apple silicon macOS): run the compute broker in the foreground.
    /// It accepts authenticated requests from remote `azula compute exec`
    /// clients and runs their commands inside the VMs you created with
    /// `azula vm create`. Ctrl-C stops the broker and every VM it started.
    Serve,
    /// Host (Apple silicon macOS): mint an access token for a remote client.
    /// Prints the token once (the host keeps only a hash) and an `export
    /// AZULA_COMPUTE_TOKEN=…` line to paste into the client's environment.
    Grant(GrantArgs),
    /// Host (Apple silicon macOS): list the grants this host has minted.
    Grants {
        /// Machine-readable output: a JSON array of grants (no secrets).
        #[arg(long)]
        json: bool,
    },
    /// Host (Apple silicon macOS): revoke a grant. Takes effect for the next
    /// request.
    Revoke {
        /// The grant id shown by `azula compute grants` (e.g. `g_3f9a1c2b7d4e`).
        #[arg(value_name = "GRANT_ID")]
        id: String,
    },
    /// Client: run a command inside a VM on the host and stream its output.
    /// The command runs directly (no shell) as an unprivileged user in the
    /// VM; this process exits with the command's exit code. Exit codes:
    /// 124 timeout, 125 broker error (unauthorized, forbidden, vm_not_running,
    /// …), 126 cwd missing, 127 command could not be spawned, 128+N killed by
    /// signal N, 130 cancelled by Ctrl-C, 255 connection failure.
    #[command(after_help = "Examples:\n  azula compute exec -- uname -a\n  azula compute exec --vm build --cwd /home/azula/src -- cargo test\n  tar -c . | azula compute exec --stdin -- tar -x -C /work")]
    Exec(ExecArgs),
    /// Client: check, stage by stage, that this machine can reach the host
    /// and that the token works (token, bind, relay, dial, auth, broker, and
    /// with `--vm` the VM's worker). Reports the first failing stage.
    Doctor(DoctorArgs),
}

#[derive(Debug, Args)]
struct GrantArgs {
    /// How long the grant stays valid: a number and a unit (`30m`, `12h`, `7d`).
    #[arg(long, default_value = "7d", value_name = "DURATION")]
    ttl: String,
    /// Restrict the grant to this VM. Repeat for several. Default: every VM.
    #[arg(long = "vm", value_name = "NAME")]
    vms: Vec<String>,
    /// Operations the grant allows: `exec` (run commands) and/or `vm`
    /// (start and stop VMs).
    #[arg(long, value_delimiter = ',', default_value = "exec,vm", value_name = "OPS")]
    ops: Vec<String>,
    /// A note shown by `azula compute grants`, e.g. `claude-code`.
    #[arg(long, default_value = "", value_name = "TEXT")]
    label: String,
    /// Machine-readable output: `{"grant":{…},"token":"azc1.…"}`.
    #[arg(long)]
    json: bool,
}

/// `--token` / `AZULA_COMPUTE_TOKEN`, shared by every client verb.
#[derive(Debug, Args)]
pub(super) struct TokenArg {
    /// The access token from `azula compute grant`.
    #[arg(long, env = "AZULA_COMPUTE_TOKEN", hide_env_values = true, value_name = "TOKEN")]
    pub(super) token: Option<String>,
}

#[derive(Debug, Args)]
struct ExecArgs {
    #[command(flatten)]
    token: TokenArg,
    /// VM to run in. Default: the grant's only VM when it names exactly one,
    /// otherwise `default`.
    #[arg(long, value_name = "NAME")]
    vm: Option<String>,
    /// Fail with `vm_not_running` instead of starting a stopped VM.
    #[arg(long)]
    no_start: bool,
    /// Working directory inside the VM (default: the job user's home).
    #[arg(long, value_name = "DIR")]
    cwd: Option<String>,
    /// Environment variable for the command, `KEY=VALUE`. Repeatable.
    #[arg(long = "env", value_name = "KEY=VALUE", value_parser = client::parse_env)]
    env: Vec<(String, String)>,
    /// Forward this process's stdin to the command, then end-of-file.
    /// Otherwise the command's stdin is empty.
    #[arg(long)]
    stdin: bool,
    /// Stop the command after this long: `90s`, `15m`, up to `24h`.
    #[arg(long, default_value = "15m", value_name = "DURATION", value_parser = client::parse_timeout)]
    timeout: u64,
    /// Print JSON Lines events on stdout instead of streaming raw output:
    /// `started`, `stdout`/`stderr` (base64 `data_b64`), `exit`, `error`.
    #[arg(long)]
    json: bool,
    /// The command and its arguments, after `--`.
    #[arg(last = true, required = true, value_name = "ARGV")]
    argv: Vec<String>,
}

#[derive(Debug, Args)]
struct DoctorArgs {
    #[command(flatten)]
    token: TokenArg,
    /// Also check that this VM's worker answers (default VM when the flag
    /// is given without a name is chosen by the grant).
    #[arg(long, value_name = "NAME", num_args = 0..=1, default_missing_value = "")]
    vm: Option<String>,
    /// Machine-readable output: `{"ok":bool,"stages":[…]}`.
    #[arg(long)]
    json: bool,
}

pub(super) async fn run(args: ComputeArgs) -> Result<()> {
    match args.action {
        ComputeAction::Serve => host::serve().await,
        ComputeAction::Grant(a) => host::grant(a).await,
        ComputeAction::Grants { json } => host::grants(json),
        ComputeAction::Revoke { id } => host::revoke(&id),
        ComputeAction::Exec(a) => exec(a).await,
        ComputeAction::Doctor(a) => doctor(a).await,
    }
}

/// Print `azula: msg` and exit.
pub(super) fn die(code: i32, msg: &str) -> ! {
    eprintln!("azula: {msg}");
    std::process::exit(code);
}

/// The token from the flag/env, or exit 125 with a hint.
pub(super) fn require_token(arg: &TokenArg) -> Token {
    let Some(text) = arg.token.as_deref().filter(|t| !t.trim().is_empty()) else {
        die(client::exit::BROKER_ERROR, "no token: pass --token or set AZULA_COMPUTE_TOKEN (mint one with `azula compute grant` on the host)");
    };
    match Token::decode(text) {
        Ok(t) => t,
        Err(e) => die(client::exit::BROKER_ERROR, &format!("{e:#}")),
    }
}

/// Bind a client endpoint and authenticate against the token's host.
pub(super) async fn open_session(token: &Token) -> Result<(iroh::Endpoint, client::Session), Failure> {
    let addr = token.addr().map_err(|e| Failure::Broker { code: "bad_request".into(), msg: e.to_string() })?;
    let ep = client::bind_client(client::RELAY_TIMEOUT).await.map_err(|e| Failure::Transport(crate::endpoint::redact_credentials(&format!("{e:#}"))))?;
    match client::connect(&ep, addr, token).await {
        Ok(s) => Ok((ep, s)),
        Err(e) => {
            ep.close().await;
            Err(e)
        }
    }
}

pub(super) async fn close_quietly(ep: iroh::Endpoint) {
    let _ = tokio::time::timeout(Duration::from_secs(3), ep.close()).await;
}

fn emit_json(v: &serde_json::Value) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{v}");
    let _ = out.flush();
}

async fn exec(args: ExecArgs) -> Result<()> {
    let token = require_token(&args.token);
    let (ep, session) = match open_session(&token).await {
        Ok(x) => x,
        Err(f) => {
            if args.json {
                let code = match &f {
                    Failure::Broker { code, .. } => code.clone(),
                    Failure::Transport(_) => "transport".to_owned(),
                };
                emit_json(&Event::Error { code, msg: f.message() }.to_json());
            }
            die(f.exit_code(), &f.message());
        }
    };

    // Ctrl-C: first cancels the job, second disconnects.
    let (itx, irx) = mpsc::channel::<()>(4);
    tokio::spawn(async move {
        while tokio::signal::ctrl_c().await.is_ok() {
            if itx.send(()).await.is_err() {
                break;
            }
        }
    });

    let req = ExecRequest {
        vm: args.vm.clone(),
        no_start: args.no_start,
        argv: args.argv.clone(),
        cwd: args.cwd.clone(),
        env: args.env.clone(),
        stdin: args.stdin,
        timeout_s: Some(args.timeout),
    };
    let stdin: Option<Box<dyn tokio::io::AsyncRead + Unpin + Send>> = if args.stdin { Some(Box::new(tokio::io::stdin())) } else { None };
    let json = args.json;
    let outcome = client::exec(session, &req, stdin, irx, |ev| {
        if json {
            emit_json(&ev.to_json());
            return;
        }
        match ev {
            Event::Stdout(d) => {
                let mut o = std::io::stdout().lock();
                let _ = o.write_all(d);
                let _ = o.flush();
            }
            Event::Stderr(d) => {
                let mut e = std::io::stderr().lock();
                let _ = e.write_all(d);
                let _ = e.flush();
            }
            _ => {}
        }
    })
    .await;
    close_quietly(ep).await;

    match &outcome {
        Outcome::Exit { reason, .. } if reason == "timeout" => eprintln!("azula: job timed out after {}s", args.timeout),
        Outcome::Exit { reason, .. } if reason == "cancelled" => eprintln!("azula: job cancelled"),
        Outcome::Error { code, msg } if !json => eprintln!("azula: {code}: {msg}"),
        Outcome::Transport(m) => {
            if json {
                emit_json(&Event::Error { code: "transport".into(), msg: m.clone() }.to_json());
            }
            eprintln!("azula: {m}");
        }
        Outcome::Interrupted => eprintln!("azula: interrupted; disconnected from the host"),
        _ => {}
    }
    std::process::exit(outcome.exit_code());
}

async fn doctor(args: DoctorArgs) -> Result<()> {
    let json = args.json;
    let stages = client::doctor(args.token.token.as_deref().filter(|t| !t.trim().is_empty()), args.vm.as_deref(), |s| {
        if !json {
            let mark = if s.ok { "\u{2713}" } else { "\u{2717}" };
            println!("{mark} {:<7} {:>6} ms  {}", s.stage, s.ms, s.detail);
            if let Some(h) = &s.hint {
                if !s.ok {
                    println!("    hint: {h}");
                }
            }
        }
    })
    .await;
    let ok = stages.last().is_some_and(|s| s.ok);
    if json {
        let items: Vec<_> = stages
            .iter()
            .map(|s| serde_json::json!({"stage": s.stage, "ok": s.ok, "ms": s.ms, "detail": s.detail, "hint": s.hint}))
            .collect();
        emit_json(&serde_json::json!({"ok": ok, "stages": items}));
    }
    std::process::exit(if ok { 0 } else { 1 });
}

// --- host verbs ------------------------------------------------------------

#[cfg(target_os = "macos")]
mod host {
    use super::*;
    use crate::compute::grants::{parse_duration, MintOptions, OP_EXEC, OP_VM};

    pub(super) async fn serve() -> Result<()> {
        crate::compute::host::serve().await
    }

    pub(super) async fn grant(a: GrantArgs) -> Result<()> {
        let ttl = parse_duration(&a.ttl).map_err(|e| anyhow::anyhow!("--ttl: {e}"))?;
        for op in &a.ops {
            if op != OP_EXEC && op != OP_VM {
                anyhow::bail!("--ops: unknown operation `{op}` (use exec, vm)");
            }
        }
        let vms = if a.vms.is_empty() { vec!["*".to_owned()] } else { a.vms.clone() };
        for v in &vms {
            if v != "*" && !crate::compute::valid_vm_name(v) {
                anyhow::bail!("--vm: invalid VM name `{v}`");
            }
        }
        let (grant, token) = crate::compute::host::grant(&MintOptions { label: a.label.clone(), ttl, ops: a.ops.clone(), vms }).await?;
        if a.json {
            emit_json(&serde_json::json!({"grant": public_grant(&grant), "token": token}));
        } else {
            println!("{token}");
            println!("export AZULA_COMPUTE_TOKEN={token}");
            eprintln!("grant {} expires in {} (ops: {}, vms: {})", grant.id, a.ttl, grant.ops.join(","), grant.vms.join(","));
        }
        Ok(())
    }

    /// A grant without its secret hash, for display.
    fn public_grant(g: &crate::compute::grants::Grant) -> serde_json::Value {
        serde_json::json!({
            "id": g.id, "label": g.label, "created": g.created, "expires": g.expires, "ops": g.ops, "vms": g.vms,
            "revoked": g.revoked, "last_used": g.last_used, "last_peer": g.last_peer,
        })
    }

    pub(super) fn grants(json: bool) -> Result<()> {
        let grants = crate::compute::host::list_grants()?;
        if json {
            emit_json(&serde_json::Value::Array(grants.iter().map(public_grant).collect()));
            return Ok(());
        }
        if grants.is_empty() {
            println!("no grants (mint one with `azula compute grant`)");
            return Ok(());
        }
        let now = crate::compute::grants::unix_now();
        println!("{:<16} {:<8} {:<20} {:<10} {:<10} LABEL", "ID", "STATUS", "VMS", "OPS", "LAST USED");
        for g in grants {
            let status = if g.revoked.is_some() {
                "revoked"
            } else if now >= g.expires {
                "expired"
            } else {
                "active"
            };
            let last = g.last_used.map(|t| format!("{}s ago", now.saturating_sub(t))).unwrap_or_else(|| "never".into());
            println!("{:<16} {:<8} {:<20} {:<10} {:<10} {}", g.id, status, g.vms.join(","), g.ops.join(","), last, g.label);
        }
        Ok(())
    }

    pub(super) fn revoke(id: &str) -> Result<()> {
        if crate::compute::host::revoke(id)? {
            println!("revoked {id}");
            Ok(())
        } else {
            die(2, &format!("no grant `{id}` (see `azula compute grants`)"));
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod host {
    use super::*;

    fn unsupported() -> ! {
        die(2, crate::compute::HOST_ONLY_MSG)
    }

    pub(super) async fn serve() -> Result<()> {
        unsupported()
    }
    pub(super) async fn grant(_: GrantArgs) -> Result<()> {
        unsupported()
    }
    pub(super) fn grants(_: bool) -> Result<()> {
        unsupported()
    }
    pub(super) fn revoke(_: &str) -> Result<()> {
        unsupported()
    }
}
