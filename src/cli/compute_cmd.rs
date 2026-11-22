//! `azula compute` — run commands in a VM on a remote Mac over iroh.
//!
//! Host verbs (`serve`, `grant`, `grants`, `revoke`) run on Apple silicon
//! macOS only; client verbs (`exec`, `attach`, `logs`, `jobs`, `cancel`,
//! `push`, `pull`, `doctor`) run anywhere. The `vm` noun lives in `vm_cmd`.
//! Contract: `vm/BROKER.md` §5–§7.

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use clap::{Args, Subcommand};
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::compute::client::{self, AttachRequest, Dialer, Event, ExecRequest, Failure, JobRef, Outcome, Policy, Start};
use crate::compute::grants::Token;
use crate::compute::transfer::{self, PullOptions, PushOptions, Transfer, TransferError, TransferStore};

#[derive(Debug, Args)]
pub(super) struct ComputeArgs {
    #[command(subcommand)]
    action: ComputeAction,
}

#[derive(Debug, Subcommand)]
enum ComputeAction {
    /// Host (Apple silicon macOS, or Linux with --local): run the compute
    /// broker in the foreground. It accepts authenticated requests from remote
    /// `azula compute` clients and runs their commands inside the VMs you
    /// created with `azula vm create`. While a VM runs it keeps the Mac from
    /// idle-sleeping. Ctrl-C stops the broker and every VM it started (running
    /// jobs end as `interrupted`). On Linux there is no VM: with --local the
    /// jobs run on this machine itself (as --run-as), which is only
    /// appropriate when this machine is already an isolated VM, e.g. Android's
    /// Linux Terminal.
    Serve {
        /// Don't hold an idle-sleep assertion while VMs run.
        #[arg(long)]
        allow_sleep: bool,
        /// Linux only: run jobs on this machine itself (required there).
        #[cfg(target_os = "linux")]
        #[arg(long)]
        local: bool,
        /// Linux only: the name of the one local "VM" (what `--vm` selects).
        #[cfg(target_os = "linux")]
        #[arg(long, value_name = "NAME", default_value = "default")]
        vm_name: String,
        /// Linux only: the user the worker runs jobs as. It must exist.
        #[cfg(target_os = "linux")]
        #[arg(long, value_name = "USER", default_value = "azula")]
        run_as: String,
        /// Linux only, attach mode: connect to an already-running `azula-guest`
        /// listening on this Unix socket instead of spawning one (e.g. an AVF VM
        /// bridged by an Android app). The broker never starts or stops it;
        /// `start` waits up to 180 s for it to answer. --run-as is ignored.
        #[cfg(target_os = "linux")]
        #[arg(long, value_name = "PATH")]
        worker_socket: Option<std::path::PathBuf>,
        /// Linux attach mode: CPU count to report in `vm status` (default 0).
        #[cfg(target_os = "linux")]
        #[arg(long, value_name = "N")]
        vm_cpus: Option<u32>,
        /// Linux attach mode: memory in MiB to report in `vm status` (default 0).
        #[cfg(target_os = "linux")]
        #[arg(long, value_name = "M")]
        vm_memory_mb: Option<u64>,
    },
    /// Host (Apple silicon macOS or Linux): mint an access token for a remote client.
    /// Prints the token once (the host keeps only a hash) and an `export
    /// AZULA_COMPUTE_TOKEN=…` line to paste into the client's environment.
    /// Mint one grant per cloud session or agent: a grant owns the jobs it
    /// starts.
    Grant(GrantArgs),
    /// Host (Apple silicon macOS or Linux): list the grants this host has minted.
    Grants {
        /// Machine-readable output: a JSON array of grants (no secrets).
        #[arg(long)]
        json: bool,
    },
    /// Host (Apple silicon macOS or Linux): revoke a grant. A running `serve` closes
    /// the grant's live connections within a few seconds; its jobs keep
    /// running unless `--cancel-jobs` is given.
    Revoke {
        /// The grant id shown by `azula compute grants` (e.g. `g_3f9a1c2b7d4e`).
        #[arg(value_name = "GRANT_ID")]
        id: String,
        /// Also cancel the grant's running jobs on every running VM.
        #[arg(long)]
        cancel_jobs: bool,
    },
    /// Client: run a command inside a VM on the host and stream its output.
    /// The command runs directly (no shell) as an unprivileged user in the
    /// VM and keeps running if you disconnect; this process exits with its
    /// exit code. If the connection drops it reconnects and resumes the
    /// output without gaps or repeats. Exit codes: 124 timeout, 125 broker
    /// error (unauthorized, forbidden, vm_not_running, busy, …), 126 cwd
    /// missing, 127 command could not be spawned, 128+N killed by signal N,
    /// 130 cancelled by Ctrl-C, 255 connection failure or a job that was
    /// interrupted.
    #[command(after_help = "Examples:\n  azula compute exec -- uname -a\n  azula compute exec --vm build --cwd /home/azula/src -- cargo test\n  azula compute exec --detach --label nightly -- ./run-tests.sh\n  tar -c . | azula compute exec --stdin -- tar -x -C /work")]
    Exec(ExecArgs),
    /// Client: replay a job's output from the start and follow it to the end.
    /// Exits with the job's exit code, like `exec`.
    Attach(AttachArgs),
    /// Client: print a job's retained output.
    Logs(LogsArgs),
    /// Client: list this grant's jobs on a VM, newest first.
    Jobs(JobsArgs),
    /// Client: cancel a running job (SIGTERM, then SIGKILL after 5 s).
    Cancel(CancelArgs),
    /// Client: copy a local file (or a directory with `-r`) into the VM. The
    /// transfer is verified with SHA-256, lands atomically, and resumes after
    /// a dropped connection or when you rerun the same command.
    #[command(after_help = "Examples:\n  azula compute push ./app.tgz /home/azula/app.tgz\n  azula compute push -r ./src /home/azula/src\n  tar -c . | azula compute push - /work/src.tar")]
    Push(PushArgs),
    /// Client: copy a file (or a directory with `-r`) out of the VM.
    #[command(after_help = "Examples:\n  azula compute pull /home/azula/out/app.tgz ./app.tgz\n  azula compute pull -r /home/azula/out ./out")]
    Pull(PullArgs),
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
    /// Restrict the grant to this VM name or `*` glob (`ci-*`). Repeat for
    /// several. Default: every VM.
    #[arg(long = "vm", value_name = "NAME|GLOB")]
    vms: Vec<String>,
    /// Operations the grant allows: `exec` (run jobs, move files), `vm`
    /// (start and stop VMs, auto-start) and/or `admin` (see and cancel every
    /// grant's jobs).
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

/// `--vm` / `AZULA_COMPUTE_VM`.
#[derive(Debug, Args)]
struct VmArg {
    /// VM to use. Default: `AZULA_COMPUTE_VM`, else the grant's VM when its
    /// scope is exactly one plain name, else `default`.
    #[arg(long, env = "AZULA_COMPUTE_VM", value_name = "NAME")]
    vm: Option<String>,
}

#[derive(Debug, Args)]
struct ExecArgs {
    #[command(flatten)]
    token: TokenArg,
    #[command(flatten)]
    vm: VmArg,
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
    /// Otherwise the command's stdin is empty. A job still waiting for stdin
    /// is cancelled if the connection drops.
    #[arg(long)]
    stdin: bool,
    /// Stop the command after this long: `90s`, `15m`, up to `24h` (and never
    /// later than the grant's expiry).
    #[arg(long, default_value = "15m", value_name = "DURATION", value_parser = client::parse_timeout)]
    timeout: u64,
    /// Print the job ref (`vm/j_…`) on stdout and exit 0 as soon as the job
    /// has started; it keeps running. Follow it with `attach` or `logs`.
    #[arg(long, conflicts_with = "stdin")]
    detach: bool,
    /// Cancel the job if no client has been attached to it for 60 s.
    #[arg(long)]
    cancel_on_disconnect: bool,
    /// How long to keep trying to reconnect after the connection drops
    /// (`5m`, `30s`; `0` disables reconnecting).
    #[arg(long, default_value = "5m", value_name = "DURATION", value_parser = client::parse_reconnect)]
    reconnect: Duration,
    /// A note shown by `azula compute jobs`.
    #[arg(long, value_name = "TEXT")]
    label: Option<String>,
    /// Don't print the `job … started` notice on stderr.
    #[arg(long, short)]
    quiet: bool,
    /// Print JSON Lines events on stdout instead of streaming raw output:
    /// `started`, `stdout`/`stderr` (base64 `data_b64`, byte `off`), `gap`,
    /// `reconnecting`, `exit`, `error`.
    #[arg(long)]
    json: bool,
    /// The command and its arguments, after `--`.
    #[arg(last = true, required = true, value_name = "ARGV")]
    argv: Vec<String>,
}

#[derive(Debug, Args)]
struct AttachArgs {
    #[command(flatten)]
    token: TokenArg,
    #[command(flatten)]
    vm: VmArg,
    /// How long to keep trying to reconnect (`5m`, `0` disables).
    #[arg(long, default_value = "5m", value_name = "DURATION", value_parser = client::parse_reconnect)]
    reconnect: Duration,
    /// Print JSON Lines events instead of raw output (see `exec --json`).
    #[arg(long)]
    json: bool,
    /// The job: `<vm>/j_…`, or a bare `j_…` with `--vm`.
    #[arg(value_name = "JOB")]
    job: String,
}

#[derive(Debug, Args)]
struct LogsArgs {
    #[command(flatten)]
    token: TokenArg,
    #[command(flatten)]
    vm: VmArg,
    /// Keep streaming until the job ends, then exit with its exit code.
    /// Without it, print what is retained and exit 0.
    #[arg(long, short)]
    follow: bool,
    /// Only the last N lines of each stream (reads at most the last 256 KiB).
    #[arg(long, value_name = "N")]
    tail: Option<usize>,
    /// Only stdout.
    #[arg(long, conflicts_with = "stderr_only")]
    stdout_only: bool,
    /// Only stderr.
    #[arg(long)]
    stderr_only: bool,
    /// How long to keep trying to reconnect when following (`5m`, `0` disables).
    #[arg(long, default_value = "5m", value_name = "DURATION", value_parser = client::parse_reconnect)]
    reconnect: Duration,
    /// Print JSON Lines events instead of raw output (see `exec --json`).
    #[arg(long)]
    json: bool,
    /// The job: `<vm>/j_…`, or a bare `j_…` with `--vm`.
    #[arg(value_name = "JOB")]
    job: String,
}

#[derive(Debug, Args)]
struct JobsArgs {
    #[command(flatten)]
    token: TokenArg,
    #[command(flatten)]
    vm: VmArg,
    /// List every grant's jobs (needs a grant with op `admin`).
    #[arg(long)]
    all: bool,
    /// Machine-readable output: a JSON array of jobs, each with a `ref`.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct CancelArgs {
    #[command(flatten)]
    token: TokenArg,
    #[command(flatten)]
    vm: VmArg,
    /// Cancel a job of any grant (needs a grant with op `admin`).
    #[arg(long)]
    all: bool,
    /// The job: `<vm>/j_…`, or a bare `j_…` with `--vm`.
    #[arg(value_name = "JOB")]
    job: String,
}

#[derive(Debug, Args)]
struct PushArgs {
    #[command(flatten)]
    token: TokenArg,
    #[command(flatten)]
    vm: VmArg,
    /// Copy a directory tree (streams tar through the VM; not resumable
    /// byte-for-byte, retried from the connection's offset).
    #[arg(long, short)]
    recursive: bool,
    /// Mode for the new file, octal (default: the local file's mode).
    #[arg(long, value_name = "OCTAL", value_parser = parse_mode)]
    mode: Option<u32>,
    /// Fail with `exists` instead of replacing an existing remote file.
    #[arg(long)]
    no_clobber: bool,
    /// How long to keep trying to reconnect (`5m`, `0` disables).
    #[arg(long, default_value = "5m", value_name = "DURATION", value_parser = client::parse_reconnect)]
    reconnect: Duration,
    /// Print `{"path","size","sha256","resumed_from"}` on stdout.
    #[arg(long)]
    json: bool,
    /// Local file, a directory with `-r`, or `-` for stdin.
    #[arg(value_name = "LOCAL")]
    local: String,
    /// Path in the VM: absolute, or relative to the job user's home. Ends in
    /// `/` (or names a directory) to keep the local file's name.
    #[arg(value_name = "REMOTE")]
    remote: String,
}

#[derive(Debug, Args)]
struct PullArgs {
    #[command(flatten)]
    token: TokenArg,
    #[command(flatten)]
    vm: VmArg,
    /// Copy a directory tree (the VM runs `tar -c`; extraction here rejects
    /// absolute paths, `..`, escaping links and device nodes).
    #[arg(long, short)]
    recursive: bool,
    /// How long to keep trying to reconnect (`5m`, `0` disables).
    #[arg(long, default_value = "5m", value_name = "DURATION", value_parser = client::parse_reconnect)]
    reconnect: Duration,
    /// Print `{"path","size","sha256","resumed_from"}` on stdout.
    #[arg(long)]
    json: bool,
    /// Path in the VM: absolute, or relative to the job user's home.
    #[arg(value_name = "REMOTE")]
    remote: String,
    /// Local destination file or directory, or `-` for stdout.
    #[arg(value_name = "LOCAL")]
    local: String,
}

#[derive(Debug, Args)]
struct DoctorArgs {
    #[command(flatten)]
    token: TokenArg,
    /// Also check that this VM's worker answers (the grant's VM when the
    /// flag is given without a name).
    #[arg(long, value_name = "NAME", num_args = 0..=1, default_missing_value = "")]
    vm: Option<String>,
    /// Machine-readable output: `{"ok":bool,"stages":[…]}`.
    #[arg(long)]
    json: bool,
}

fn parse_mode(s: &str) -> Result<u32, String> {
    u32::from_str_radix(s.trim_start_matches("0o"), 8).map(|m| m & 0o777).map_err(|_| format!("invalid mode `{s}`: expected octal like 0644"))
}

pub(super) async fn run(args: ComputeArgs) -> Result<()> {
    match args.action {
        #[cfg(target_os = "linux")]
        ComputeAction::Serve { allow_sleep: _, local, vm_name, run_as, worker_socket, vm_cpus, vm_memory_mb } => {
            host::serve_local(local, &vm_name, &run_as, worker_socket, vm_cpus, vm_memory_mb).await
        }
        #[cfg(not(target_os = "linux"))]
        ComputeAction::Serve { allow_sleep } => host::serve(allow_sleep).await,
        ComputeAction::Grant(a) => host::grant(a).await,
        ComputeAction::Grants { json } => host::grants(json),
        ComputeAction::Revoke { id, cancel_jobs } => host::revoke(&id, cancel_jobs),
        ComputeAction::Exec(a) => exec(a).await,
        ComputeAction::Attach(a) => attach(a).await,
        ComputeAction::Logs(a) => logs(a).await,
        ComputeAction::Jobs(a) => jobs(a).await,
        ComputeAction::Cancel(a) => cancel(a).await,
        ComputeAction::Push(a) => push(a).await,
        ComputeAction::Pull(a) => pull(a).await,
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

/// Bind a client endpoint for `token`'s host.
async fn make_dialer(token: &Token) -> Result<Dialer, Failure> {
    let addr = token.addr().map_err(|e| Failure::Broker { code: "bad_request".into(), msg: e.to_string() })?;
    let ep = client::bind_client(client::RELAY_TIMEOUT, client::token_relay(token)).await.map_err(|e| Failure::Transport(crate::endpoint::redact_credentials(&format!("{e:#}"))))?;
    Ok(Dialer::new(ep, addr, token.clone()).with_fault(client::Fault::from_env()))
}

async fn dialer_or_die(arg: &TokenArg) -> Dialer {
    let token = require_token(arg);
    match make_dialer(&token).await {
        Ok(d) => d,
        Err(f) => die(f.exit_code(), &f.message()),
    }
}

/// Bind a client endpoint and authenticate against the token's host.
pub(super) async fn open_session(token: &Token) -> Result<(iroh::Endpoint, client::Session), Failure> {
    let d = make_dialer(token).await?;
    match d.session().await {
        Ok(s) => Ok((d.ep, s)),
        Err(e) => {
            d.ep.close().await;
            Err(e)
        }
    }
}

pub(super) async fn close_quietly(ep: iroh::Endpoint) {
    let _ = tokio::time::timeout(Duration::from_secs(3), ep.close()).await;
}

fn emit_json(v: &Value) {
    let mut line = v.to_string();
    line.push('\n');
    crate::compute::out::write_bytes(line.as_bytes());
}

use crate::compute::transfer::human_bytes;

/// Ctrl-C as a channel: each SIGINT is one message.
fn interrupts() -> mpsc::Receiver<()> {
    let (tx, rx) = mpsc::channel::<()>(4);
    tokio::spawn(async move {
        while tokio::signal::ctrl_c().await.is_ok() {
            if tx.send(()).await.is_err() {
                break;
            }
        }
    });
    rx
}

/// Printing of a job stream's events, shared by exec/attach/logs.
struct Printer {
    json: bool,
    quiet: bool,
    stdout: bool,
    stderr: bool,
}

impl Printer {
    fn event(&self, ev: &Event) {
        if self.json {
            emit_json(&ev.to_json());
            return;
        }
        match ev {
            Event::Stdout { data, .. } if self.stdout => crate::compute::out::write_bytes(data),
            Event::Stderr { data, .. } if self.stderr => {
                let mut e = std::io::stderr().lock();
                let _ = e.write_all(data);
                let _ = e.flush();
            }
            Event::Started { job, .. } if !self.quiet => eprintln!("azula: job {job} started"),
            Event::Gap { stream, from, to } => eprintln!("azula: {} bytes of {stream} were dropped by the host's retention limit", to.saturating_sub(*from)),
            Event::Reconnecting { attempt: 1, job } => match job {
                Some(j) => eprintln!("azula: connection lost, reattaching to {j}"),
                None => eprintln!("azula: connection lost, reconnecting"),
            },
            _ => {}
        }
    }
}

/// Run a job stream to its end and exit the process with its code.
#[allow(clippy::too_many_arguments)]
async fn stream_job(dialer: Dialer, start: Start, stdin: bool, policy: Policy, printer: Printer, timeout_s: Option<u64>, detach: bool, mirror_exit: bool) -> ! {
    let irx = interrupts();
    let stdin: Option<Box<dyn tokio::io::AsyncRead + Unpin + Send>> = if stdin { Some(Box::new(tokio::io::stdin())) } else { None };
    let mut on_event = |ev: &Event| printer.event(ev);
    let (outcome, _job) = client::run_job(&dialer, start, stdin, irx, policy, &mut on_event).await;
    close_quietly(dialer.ep.clone()).await;
    let json = printer.json;
    match &outcome {
        Outcome::Detached { job, by_interrupt: false } if detach && !json => crate::outln!("{job}"),
        Outcome::Error { .. } if json => {}
        Outcome::Transport(_) | Outcome::GaveUp { .. } if json => {
            if let Some(m) = outcome.message(timeout_s) {
                emit_json(&Event::Error { code: "transport".into(), msg: m }.to_json());
            }
        }
        _ => {}
    }
    if let Some(m) = outcome.message(timeout_s) {
        if !(json && matches!(outcome, Outcome::Error { .. })) {
            eprintln!("azula: {m}");
        }
    }
    let code = if mirror_exit { outcome.exit_code() } else if matches!(outcome, Outcome::End | Outcome::Exit { .. }) { 0 } else { outcome.exit_code() };
    std::process::exit(code);
}

async fn exec(args: ExecArgs) -> Result<()> {
    let dialer = dialer_or_die(&args.token).await;
    let req = ExecRequest {
        vm: args.vm.vm.clone(),
        no_start: args.no_start,
        argv: args.argv.clone(),
        cwd: args.cwd.clone(),
        env: args.env.clone(),
        stdin: args.stdin,
        timeout_s: Some(args.timeout),
        label: args.label.clone(),
        detach: args.detach,
        cancel_on_disconnect: args.cancel_on_disconnect,
        idem: None,
    };
    let printer = Printer { json: args.json, quiet: args.quiet, stdout: true, stderr: true };
    stream_job(dialer, Start::Exec(req), args.stdin, Policy::with_window(args.reconnect), printer, Some(args.timeout), args.detach, true).await
}

fn parse_job_or_die(text: &str, vm: &VmArg) -> JobRef {
    match JobRef::parse(text) {
        Ok(mut r) => {
            if r.vm.is_none() {
                r.vm = vm.vm.clone();
            }
            r
        }
        Err(e) => die(2, &e),
    }
}

async fn attach(args: AttachArgs) -> Result<()> {
    let r = parse_job_or_die(&args.job, &args.vm);
    let dialer = dialer_or_die(&args.token).await;
    let start = Start::Attach(AttachRequest { vm: r.vm, job: r.id, stdout_off: 0, stderr_off: 0, follow: true });
    let printer = Printer { json: args.json, quiet: true, stdout: true, stderr: true };
    stream_job(dialer, start, false, Policy::with_window(args.reconnect), printer, None, false, true).await
}

/// The last `n` lines of `buf` (a trailing partial line counts as a line).
pub(super) fn tail_lines(buf: &[u8], n: usize) -> &[u8] {
    if n == 0 {
        return &[];
    }
    let body = buf.strip_suffix(b"\n").unwrap_or(buf);
    let mut seen = 0;
    for (i, b) in body.iter().enumerate().rev() {
        if *b == b'\n' {
            seen += 1;
            if seen == n {
                return &buf[i + 1..];
            }
        }
    }
    buf
}

async fn logs(args: LogsArgs) -> Result<()> {
    let r = parse_job_or_die(&args.job, &args.vm);
    let dialer = dialer_or_die(&args.token).await;
    let printer = Printer { json: args.json, quiet: true, stdout: !args.stderr_only, stderr: !args.stdout_only };
    let policy = Policy::with_window(args.reconnect);
    let (mut out_off, mut err_off) = (0u64, 0u64);
    if let Some(n) = args.tail {
        // Find where the job's streams end, read the last 256 KiB of each, print the last N lines.
        const WINDOW: u64 = 256 * 1024;
        let session = match dialer.session().await {
            Ok(s) => s,
            Err(f) => die(f.exit_code(), &f.message()),
        };
        let (_, jobs) = match client::list_jobs(session, r.vm.as_deref(), false).await {
            Ok(x) => x,
            Err(f) => die(f.exit_code(), &f.message()),
        };
        let Some(j) = jobs.iter().find(|j| j["job"].as_str() == Some(r.id.as_str())) else {
            die(1, &format!("not_found: no job {}", args.job));
        };
        let field = |k: &str| j[k].as_u64().unwrap_or(0);
        let (olen, elen) = (field("stdout_len"), field("stderr_len"));
        let (o0, e0) = (olen.saturating_sub(WINDOW).max(field("stdout_earliest")), elen.saturating_sub(WINDOW).max(field("stderr_earliest")));
        let (mut ob, mut eb) = (Vec::new(), Vec::new());
        let start = Start::Attach(AttachRequest { vm: r.vm.clone(), job: r.id.clone(), stdout_off: o0, stderr_off: e0, follow: false });
        let (_tx, irx) = mpsc::channel(1);
        let mut collect = |ev: &Event| match ev {
            Event::Stdout { data, .. } => ob.extend_from_slice(data),
            Event::Stderr { data, .. } => eb.extend_from_slice(data),
            _ => {}
        };
        let (outcome, _) = client::run_job(&dialer, start, None, irx, policy, &mut collect).await;
        if let Outcome::Error { code, msg } = &outcome {
            die(if code == "not_found" { 1 } else { outcome.exit_code() }, &format!("{code}: {msg}"));
        }
        if printer.stdout {
            printer.event(&Event::Stdout { off: o0, data: tail_lines(&ob, n).to_vec() });
        }
        if printer.stderr {
            printer.event(&Event::Stderr { off: e0, data: tail_lines(&eb, n).to_vec() });
        }
        out_off = o0 + ob.len() as u64;
        err_off = e0 + eb.len() as u64;
        if !args.follow {
            close_quietly(dialer.ep.clone()).await;
            std::process::exit(0);
        }
    }
    let start = Start::Attach(AttachRequest { vm: r.vm, job: r.id, stdout_off: out_off, stderr_off: err_off, follow: args.follow });
    stream_job(dialer, start, false, policy, printer, None, false, args.follow).await
}

fn fmt_age(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m", secs / 60),
        3600..=86_399 => format!("{}h", secs / 3600),
        _ => format!("{}d", secs / 86_400),
    }
}

async fn jobs(args: JobsArgs) -> Result<()> {
    let token = require_token(&args.token);
    let (ep, session) = match open_session(&token).await {
        Ok(x) => x,
        Err(f) => die(f.exit_code(), &f.message()),
    };
    let res = client::list_jobs(session, args.vm.vm.as_deref(), args.all).await;
    close_quietly(ep).await;
    let (vm, jobs) = match res {
        Ok(x) => x,
        Err(f) => die(f.exit_code(), &f.message()),
    };
    if args.json {
        let items: Vec<Value> = jobs
            .iter()
            .map(|j| {
                let mut j = j.clone();
                j["ref"] = json!(JobRef::display(&vm, j["job"].as_str().unwrap_or("")));
                j["exit_code"] = match client::job_status(&j).1.parse::<i64>() {
                    Ok(c) => json!(c),
                    Err(_) => Value::Null,
                };
                j
            })
            .collect();
        emit_json(&Value::Array(items));
        return Ok(());
    }
    if jobs.is_empty() {
        crate::outln!("no jobs on {vm}");
        return Ok(());
    }
    let now = crate::compute::grants::unix_now();
    crate::outln!("{:<30} {:<18} {:>5} {:>5}  {:<14} COMMAND", "JOB", "STATE", "EXIT", "AGE", "LABEL");
    for j in &jobs {
        let (state, code) = client::job_status(j);
        let age = j["created"].as_f64().map(|c| fmt_age(now.saturating_sub(c as u64))).unwrap_or_else(|| "-".into());
        let argv = j["argv"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(" ")).unwrap_or_default();
        crate::outln!("{:<30} {:<18} {:>5} {:>5}  {:<14} {}", JobRef::display(&vm, j["job"].as_str().unwrap_or("?")), state, code, age, j["label"].as_str().unwrap_or(""), argv);
    }
    Ok(())
}

async fn cancel(args: CancelArgs) -> Result<()> {
    let r = parse_job_or_die(&args.job, &args.vm);
    let token = require_token(&args.token);
    let (ep, session) = match open_session(&token).await {
        Ok(x) => x,
        Err(f) => die(f.exit_code(), &f.message()),
    };
    let res = client::cancel_job(session, &r, args.all).await;
    close_quietly(ep).await;
    match res {
        Ok(state) => {
            crate::outln!("{}: {state}", args.job);
            Ok(())
        }
        Err(Failure::Broker { code, msg }) if code == "not_found" => die(1, &format!("{code}: {msg}")),
        Err(f) => die(f.exit_code(), &f.message()),
    }
}

fn report_transfer(verb: &str, arrow: &str, t: &Transfer, json: bool) {
    if json {
        emit_json(&serde_json::to_value(t).unwrap_or(Value::Null));
    }
    let resumed = if t.resumed_from > 0 { format!(" (resumed from {})", human_bytes(t.resumed_from)) } else { String::new() };
    eprintln!("azula: {verb} {} {arrow} {} sha256 {}{resumed}", human_bytes(t.size), t.path, t.sha256);
}

fn transfer_die(e: &TransferError) -> ! {
    die(e.exit_code(), &e.message())
}

/// A progress callback that prints a line to stderr at most every few seconds.
fn progress_printer(verb: &'static str) -> impl FnMut(u64, u64) {
    let mut last = std::time::Instant::now();
    move |done, total| {
        if last.elapsed() >= Duration::from_secs(3) && done < total {
            last = std::time::Instant::now();
            eprintln!("azula: {verb} {} of {}", human_bytes(done), human_bytes(total));
        }
    }
}

async fn push(args: PushArgs) -> Result<()> {
    let dialer = dialer_or_die(&args.token).await;
    let policy = Policy::with_window(args.reconnect);
    let result = if args.recursive {
        match transfer::push_tree(&dialer, Path::new(&args.local), &args.remote, args.vm.vm.as_deref(), policy).await {
            Ok(t) => {
                eprintln!("azula: pushed {} entries from {} → {}", t.entries, args.local, args.remote);
                if args.json {
                    emit_json(&json!({"path": args.remote, "entries": t.entries}));
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    } else {
        let opts = PushOptions { vm: args.vm.vm.clone(), mode: args.mode, no_clobber: args.no_clobber, policy };
        let store = TransferStore::default_location();
        let mut progress = progress_printer("pushed");
        match transfer::push(&dialer, &store, &args.local, &args.remote, &opts, &mut progress).await {
            Ok(t) => {
                report_transfer("pushed", "→", &t, args.json);
                Ok(())
            }
            Err(e) => Err(e),
        }
    };
    close_quietly(dialer.ep.clone()).await;
    match result {
        Ok(()) => Ok(()),
        Err(e) => transfer_die(&e),
    }
}

async fn pull(args: PullArgs) -> Result<()> {
    let dialer = dialer_or_die(&args.token).await;
    let policy = Policy::with_window(args.reconnect);
    let result = if args.recursive {
        match transfer::pull_tree(&dialer, &args.remote, Path::new(&args.local), args.vm.vm.as_deref(), policy).await {
            Ok(t) => {
                eprintln!("azula: pulled {} entries from {} → {}", t.entries, args.remote, args.local);
                if args.json {
                    emit_json(&json!({"path": args.local, "entries": t.entries}));
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    } else {
        let opts = PullOptions { vm: args.vm.vm.clone(), policy };
        let store = TransferStore::default_location();
        let mut progress = progress_printer("pulled");
        match transfer::pull(&dialer, &store, &args.remote, &args.local, &opts, &mut progress).await {
            Ok(t) => {
                report_transfer("pulled", "→", &t, args.json);
                Ok(())
            }
            Err(e) => Err(e),
        }
    };
    close_quietly(dialer.ep.clone()).await;
    match result {
        Ok(()) => Ok(()),
        Err(e) => transfer_die(&e),
    }
}

async fn doctor(args: DoctorArgs) -> Result<()> {
    let json = args.json;
    let stages = client::doctor(args.token.token.as_deref().filter(|t| !t.trim().is_empty()), args.vm.as_deref(), |s| {
        if !json {
            let mark = if s.ok { "\u{2713}" } else { "\u{2717}" };
            crate::outln!("{mark} {:<7} {:>6} ms  {}", s.stage, s.ms, s.detail);
            if let Some(h) = &s.hint {
                if !s.ok {
                    crate::outln!("    hint: {h}");
                }
            }
        }
    })
    .await;
    let ok = stages.last().is_some_and(|s| s.ok);
    if json {
        let items: Vec<_> = stages.iter().map(|s| json!({"stage": s.stage, "ok": s.ok, "ms": s.ms, "detail": s.detail, "hint": s.hint})).collect();
        emit_json(&json!({"ok": ok, "stages": items}));
    }
    std::process::exit(if ok { 0 } else { 1 });
}

// --- host verbs ------------------------------------------------------------

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod host {
    use super::*;
    use crate::compute::grants::{parse_duration, MintOptions, OP_ADMIN, OP_EXEC, OP_VM};

    #[cfg(target_os = "macos")]
    pub(super) async fn serve(allow_sleep: bool) -> Result<()> {
        crate::compute::host::serve(allow_sleep).await
    }

    #[cfg(target_os = "linux")]
    pub(super) async fn serve_local(
        local: bool,
        vm_name: &str,
        run_as: &str,
        worker_socket: Option<std::path::PathBuf>,
        vm_cpus: Option<u32>,
        vm_memory_mb: Option<u64>,
    ) -> Result<()> {
        if let Err(e) = crate::compute::local::validate_serve_flags(local, vm_name, run_as, worker_socket.as_deref(), vm_cpus, vm_memory_mb) {
            die(2, &e);
        }
        let attach = worker_socket.map(|socket| crate::compute::local::AttachOpts { socket, cpus: vm_cpus.unwrap_or(0), memory_mb: vm_memory_mb.unwrap_or(0) });
        crate::compute::host::serve_local(vm_name, run_as, attach).await
    }

    pub(super) async fn grant(a: GrantArgs) -> Result<()> {
        let ttl = parse_duration(&a.ttl).map_err(|e| anyhow::anyhow!("--ttl: {e}"))?;
        for op in &a.ops {
            if op != OP_EXEC && op != OP_VM && op != OP_ADMIN {
                anyhow::bail!("--ops: unknown operation `{op}` (use exec, vm, admin)");
            }
        }
        let vms = if a.vms.is_empty() { vec!["*".to_owned()] } else { a.vms.clone() };
        for v in &vms {
            let pattern_ok = v.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'*');
            if v.is_empty() || !pattern_ok {
                anyhow::bail!("--vm: invalid VM name or pattern `{v}` (lowercase letters, digits, `-` and `*`)");
            }
        }
        let (grant, token) = crate::compute::host::grant(&MintOptions { label: a.label.clone(), ttl, ops: a.ops.clone(), vms }).await?;
        if a.json {
            emit_json(&json!({"grant": public_grant(&grant), "token": token}));
        } else {
            crate::outln!("{token}");
            crate::outln!("export AZULA_COMPUTE_TOKEN={token}");
            eprintln!("grant {} expires in {} (ops: {}, vms: {})", grant.id, a.ttl, grant.ops.join(","), grant.vms.join(","));
        }
        Ok(())
    }

    /// A grant without its secret hash, for display.
    fn public_grant(g: &crate::compute::grants::Grant) -> Value {
        json!({
            "id": g.id, "label": g.label, "created": g.created, "expires": g.expires, "ops": g.ops, "vms": g.vms,
            "revoked": g.revoked, "last_used": g.last_used, "last_peer": g.last_peer,
        })
    }

    pub(super) fn grants(json: bool) -> Result<()> {
        let grants = crate::compute::host::list_grants()?;
        if json {
            emit_json(&Value::Array(grants.iter().map(public_grant).collect()));
            return Ok(());
        }
        if grants.is_empty() {
            crate::outln!("no grants (mint one with `azula compute grant`)");
            return Ok(());
        }
        let now = crate::compute::grants::unix_now();
        crate::outln!("{:<16} {:<8} {:<20} {:<14} {:<10} LABEL", "ID", "STATUS", "VMS", "OPS", "LAST USED");
        for g in grants {
            let status = if g.revoked.is_some() {
                "revoked"
            } else if now >= g.expires {
                "expired"
            } else {
                "active"
            };
            let last = g.last_used.map(|t| format!("{}s ago", now.saturating_sub(t))).unwrap_or_else(|| "never".into());
            crate::outln!("{:<16} {:<8} {:<20} {:<14} {:<10} {}", g.id, status, g.vms.join(","), g.ops.join(","), last, g.label);
        }
        Ok(())
    }

    pub(super) fn revoke(id: &str, cancel_jobs: bool) -> Result<()> {
        if crate::compute::host::revoke(id, cancel_jobs)? {
            crate::outln!("revoked {id}");
            if cancel_jobs {
                crate::outln!("a running `azula compute serve` will cancel its jobs");
            }
            Ok(())
        } else {
            die(2, &format!("no grant `{id}` (see `azula compute grants`)"));
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod host {
    use super::*;

    fn unsupported() -> ! {
        die(2, crate::compute::HOST_ONLY_MSG)
    }

    pub(super) async fn serve(_: bool) -> Result<()> {
        unsupported()
    }
    pub(super) async fn grant(_: GrantArgs) -> Result<()> {
        unsupported()
    }
    pub(super) fn grants(_: bool) -> Result<()> {
        unsupported()
    }
    pub(super) fn revoke(_: &str, _: bool) -> Result<()> {
        unsupported()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_keeps_the_last_n_lines() {
        let t = |s: &str, n| String::from_utf8(tail_lines(s.as_bytes(), n).to_vec()).unwrap();
        assert_eq!(t("a\nb\nc\n", 2), "b\nc\n");
        assert_eq!(t("a\nb\nc", 2), "b\nc");
        assert_eq!(t("a\nb\n", 5), "a\nb\n");
        assert_eq!(t("a\nb\n", 0), "");
        assert_eq!(t("", 3), "");
        assert_eq!(t("one", 1), "one");
    }

    #[test]
    fn modes_parse_as_octal() {
        assert_eq!(parse_mode("0644").unwrap(), 0o644);
        assert_eq!(parse_mode("755").unwrap(), 0o755);
        assert!(parse_mode("9").is_err());
    }

    #[test]
    fn age_formatting() {
        assert_eq!(fmt_age(5), "5s");
        assert_eq!(fmt_age(120), "2m");
        assert_eq!(fmt_age(7200), "2h");
        assert_eq!(fmt_age(200_000), "2d");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
    }
}
