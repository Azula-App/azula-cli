//! azula — server-side companion for the azula p2p app.
//!
//! Binds an iroh endpoint, prints a shareable ticket, and serves two ALPN
//! protocols to connecting azula app clients:
//!
//! * `azula/llm/0`  — an LLM relay that acts as an MCP (Model Context Protocol)
//!   *client*: it pushes each chat message into a shared upstream MCP session
//!   and streams the tool result back. A canned notice is streamed when no MCP
//!   server is configured.
//! * `azula/term/0` — a remote shell ("SSH"-like) bridge over a PTY

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use iroh::protocol::Router;
use tracing::{info, warn};

use azula::invite::{self, Expiry};
use azula::link::{self, Parsed};
use azula::mcp::{self, LlmHandler, McpConfig, McpTransport, LLM_ALPN};
use azula::term::{TermHandler, TERM_ALPN};
use azula::{bridge, endpoint, qr, registry};

/// Command-line interface.
#[derive(Debug, Parser)]
#[command(name = "azula", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    serve: ServeArgs,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Bind the iroh endpoint, print the ticket, and serve until Ctrl-C.
    Serve(ServeArgs),
    /// Run the MCP↔iroh bridge: an MCP server (Streamable HTTP) that manages
    /// connections to one or more Azula app devices over iroh.
    ServeMcp(ServeMcpArgs),
    /// Run the MCP↔iroh bridge over **stdio** — for `claude mcp add azula -- azula mcp`.
    /// Same tools as `serve-mcp` (pair, send, render A2UI, receive) but spoken over
    /// stdin/stdout so Claude Code launches it directly; no HTTP port.
    Mcp(McpArgs),
    /// Pair a new device: save its ticket to the registry.
    Pair(PairArgs),
    /// List all registered devices and their registry source.
    Devices,
    /// Print a QR code for a ticket, URL, or bare token.
    Qr(QrArgs),
    /// Mint a new invite (or, with `revoke`, delete a previously issued one).
    Invite(InviteCliArgs),
    /// List all invites this node has issued.
    Invites,
}

/// Options for the `serve-mcp` command (the MCP↔iroh bridge).
#[derive(Debug, Clone, clap::Args)]
struct ServeMcpArgs {
    /// Address to serve the MCP-over-HTTP endpoint on (path is /mcp).
    #[arg(long, env = "AZULA_MCP_BIND", default_value = "127.0.0.1:8765")]
    bind: String,

    /// A device ticket URL to connect to (repeatable). Each value is a URL or
    /// bare ticket in any form accepted by `azula pair`.
    #[arg(long = "device", value_name = "URL", action = clap::ArgAction::Append)]
    device: Option<Vec<String>>,

    /// Display name for this bridge (sent as `hello` to peer bridges so they
    /// can identify it by name). Defaults to `bridge-<first 8 chars of node id>`.
    #[arg(long, value_name = "NAME")]
    name: Option<String>,

    /// Hard per-peer turn cap for bridge-to-bridge `say` conversations. Once
    /// either side reaches this many turns the conversation is closed.
    #[arg(long = "max-turns", value_name = "N", default_value_t = 20)]
    max_turns: u64,

    /// Admit invite-less unknown strangers as unverified pending devices
    /// instead of closing the connection. Transition escape hatch — default
    /// on for one release, then off (see azula-docs/docs/invitations.md).
    #[arg(long = "allow-legacy", default_value_t = true, action = clap::ArgAction::Set)]
    allow_legacy: bool,

    /// Print the raw dial ticket in the startup pairing QR instead of minting
    /// a signed 24h invite.
    #[arg(long = "legacy-ticket")]
    legacy_ticket: bool,
}

/// Options for the `mcp` command (the stdio MCP↔iroh bridge).
#[derive(Debug, Clone, clap::Args)]
struct McpArgs {
    /// A device ticket URL to connect to (repeatable). Each value is a URL or bare
    /// ticket in any form accepted by `azula pair`.
    #[arg(long = "device", value_name = "URL", action = clap::ArgAction::Append)]
    device: Option<Vec<String>>,

    /// Display name this bridge announces to the app (shown as the conversation name
    /// and the notification title). Defaults to "Claude".
    #[arg(long, value_name = "NAME", default_value = "Claude")]
    name: String,

    /// Hard per-peer turn cap for bridge-to-bridge `say` conversations.
    #[arg(long = "max-turns", value_name = "N", default_value_t = 20)]
    max_turns: u64,

    /// Admit invite-less unknown strangers as unverified pending devices
    /// instead of closing the connection. Transition escape hatch — default
    /// on for one release, then off (see azula-docs/docs/invitations.md).
    #[arg(long = "allow-legacy", default_value_t = true, action = clap::ArgAction::Set)]
    allow_legacy: bool,

    /// Print the raw dial ticket in the startup pairing output instead of
    /// minting a signed 24h invite.
    #[arg(long = "legacy-ticket")]
    legacy_ticket: bool,
}

/// Options for `azula pair`.
#[derive(Debug, Clone, clap::Args)]
struct PairArgs {
    /// The invite link (https://azula.app/i/<payload>, azula://i?c=<payload>,
    /// bare azi... payload), legacy ticket URL, or bare token.
    url: String,

    /// Display name for this device.
    #[arg(long)]
    name: Option<String>,

    /// Save to the global (~/.azula) registry instead of the project registry.
    #[arg(long)]
    global: bool,
}

/// Options for `azula qr`.
#[derive(Debug, Clone, clap::Args)]
struct QrArgs {
    /// A ticket, `https://azula.app/s/<token>`, or `azula://connect?code=<token>` URL.
    code: String,
}

/// Options for `azula invite`: mints by default, or `revoke <id-prefix>` to delete one.
#[derive(Debug, Clone, clap::Args)]
struct InviteCliArgs {
    #[command(subcommand)]
    action: Option<InviteAction>,

    #[command(flatten)]
    mint: InviteMintArgs,
}

#[derive(Debug, Clone, Subcommand)]
enum InviteAction {
    /// Revoke (delete) an issued invite by id or id-prefix.
    Revoke(InviteRevokeArgs),
}

#[derive(Debug, Clone, clap::Args)]
struct InviteMintArgs {
    /// Validity window: `1h`, `24h`, `7d`, or `never`.
    #[arg(long, default_value = "24h")]
    expires: String,

    /// Sign the invite with this node's key so the redeemer/azula.app can
    /// verify authenticity before dialing.
    #[arg(long)]
    sign: bool,

    /// The invite may only be redeemed once.
    #[arg(long = "single-use")]
    single_use: bool,

    /// A note shown next to this invite in `azula invites` (e.g. a recipient's name).
    #[arg(long)]
    label: Option<String>,

    /// Mint against the bridge identity (the one `azula serve-mcp`/`azula mcp`
    /// use) instead of the default `serve` identity. Use this to hand out a
    /// pairing invite for a running bridge from the CLI — a plain `azula
    /// invite` mints for a different key and won't be accepted by
    /// `serve-mcp`/`mcp` (only that bridge's own startup banner or
    /// `start_pairing` tool output will be).
    #[arg(long)]
    bridge: bool,
}

#[derive(Debug, Clone, clap::Args)]
struct InviteRevokeArgs {
    /// The invite id (or a unique prefix of it) shown by `azula invites`.
    id_prefix: String,
}

/// Options for the `serve` command (also used when run with no subcommand).
#[derive(Debug, Clone, clap::Args)]
struct ServeArgs {
    /// Spawn an MCP server as a child process over stdio. Value is a full
    /// command line, e.g. `npx -y @modelcontextprotocol/server-everything`.
    /// Mutually exclusive with --mcp-url.
    #[arg(long, env = "AZULA_MCP_STDIO", conflicts_with = "mcp_url")]
    mcp_stdio: Option<String>,

    /// Connect to a remote MCP server over Streamable HTTP / SSE, e.g.
    /// `https://example.com/mcp`. Mutually exclusive with --mcp-stdio.
    #[arg(long, env = "AZULA_MCP_URL")]
    mcp_url: Option<String>,

    /// MCP tool to call to push a message. Defaults to the first tool the
    /// server lists.
    #[arg(long, env = "AZULA_MCP_TOOL")]
    mcp_tool: Option<String>,

    /// JSON argument name that carries the message text in the tool call.
    #[arg(long, env = "AZULA_MCP_MESSAGE_ARG", default_value = "message")]
    mcp_message_arg: String,

    /// Serve only the remote-terminal ALPN (no LLM). A client that connects then
    /// opens a terminal session directly instead of an LLM chat — handy for the
    /// Docker shell container.
    #[arg(long, env = "AZULA_TERM_ONLY")]
    term_only: bool,

    /// Admit invite-less unknown strangers into the remote-shell ALPN as
    /// unverified instead of closing the connection. Transition escape hatch
    /// — default on for one release, then off (see
    /// azula-docs/docs/invitations.md). Does not affect the LLM relay ALPN,
    /// which has no device-registry concept.
    #[arg(long = "allow-legacy", default_value_t = true, action = clap::ArgAction::Set)]
    allow_legacy: bool,

    /// Print the raw dial ticket in the startup pairing QR instead of minting
    /// a signed 24h invite.
    #[arg(long = "legacy-ticket")]
    legacy_ticket: bool,

    /// Override the name a connecting terminal announces to the app (sent as
    /// `Frame::Profile.name`, becomes the conversation title). Defaults to
    /// this machine's hostname.
    #[arg(long, value_name = "NAME")]
    name: Option<String>,

    /// Override the description a connecting terminal announces to the app
    /// (sent as `Frame::Profile.description`, becomes the conversation
    /// sub-line). Defaults to the shell's launch working directory.
    #[arg(long, value_name = "DESCRIPTION")]
    description: Option<String>,

    /// How long (in minutes) a detached persistent terminal session's shell
    /// stays alive waiting for a `term_attach` reattach before it's killed.
    /// `0` disables persistence entirely — a `term_attach` handshake is
    /// still honored, but the shell never outlives its stream (same as a
    /// legacy client, just speaking the new frames).
    #[arg(long = "session-ttl", value_name = "MINUTES", default_value_t = 60)]
    session_ttl: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Logs go to stderr, never stdout — the `mcp` subcommand speaks JSON-RPC over
    // stdout, so any stray stdout write would corrupt the protocol stream.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Some(Command::ServeMcp(args)) => {
            bridge::run(
                args.bind,
                args.device.unwrap_or_default(),
                args.name,
                args.max_turns,
                args.allow_legacy,
                args.legacy_ticket,
            )
            .await
        }
        Some(Command::Mcp(args)) => {
            bridge::run_stdio(
                args.device.unwrap_or_default(),
                Some(args.name),
                args.max_turns,
                args.allow_legacy,
                args.legacy_ticket,
            )
            .await
        }
        Some(Command::Serve(args)) => serve(args).await,
        Some(Command::Pair(args)) => cmd_pair(args),
        Some(Command::Devices) => cmd_devices(),
        Some(Command::Qr(args)) => cmd_qr(args),
        Some(Command::Invite(args)) => match args.action {
            Some(InviteAction::Revoke(r)) => cmd_invite_revoke(r),
            None => cmd_invite_mint(args.mint).await,
        },
        Some(Command::Invites) => cmd_invites(),
        None => serve(cli.serve).await,
    }
}

fn cmd_pair(args: PairArgs) -> Result<()> {
    let (token, invite_str) = match link::parse(&args.url) {
        Some(Parsed::Invite(payload)) => {
            let decoded = invite::InvitePayload::decode(&payload)
                .with_context(|| format!("invalid invite: {:?}", args.url))?;
            let ticket = decoded.ticket().context("invalid invite ticket")?;
            (ticket.to_string(), Some(payload))
        }
        Some(Parsed::Ticket(t)) => (t, None),
        None => {
            eprintln!("error: could not extract a token from {:?}", args.url);
            std::process::exit(1);
        }
    };

    let name = args.name.unwrap_or_else(|| {
        token.chars().take(8).collect()
    });

    let device = registry::Device {
        name: name.clone(),
        ticket: token.clone(),
        added_at: Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        ),
        invite: invite_str,
    };

    let path = registry::add(device, args.global)?;

    println!("Paired device '{}' (ticket: {}…)", name, token.chars().take(8).collect::<String>());
    println!("Saved to: {}", path.display());
    Ok(())
}

fn cmd_devices() -> Result<()> {
    let known = registry::load();

    if known.is_empty() {
        println!("No devices registered. Use `azula pair <URL>` to add one.");
        return Ok(());
    }

    // Determine which registry file each device came from for the "source" column.
    let global_devices: Vec<String> = registry::global_path()
        .map(|p| registry::read_file(&p).into_iter().map(|d| d.name).collect())
        .unwrap_or_default();

    let project_devices: Vec<String> = registry::project_path()
        .map(|p| registry::read_file(&p).into_iter().map(|d| d.name).collect())
        .unwrap_or_default();

    println!("{:<20} {:<12} SOURCE", "NAME", "FINGERPRINT");
    println!("{}", "-".repeat(48));
    for d in &known {
        let fingerprint: String = d.ticket.chars().take(8).collect();
        let source = if project_devices.contains(&d.name) {
            "project"
        } else if global_devices.contains(&d.name) {
            "global"
        } else {
            "?"
        };
        println!("{:<20} {:<12} {}", d.name, format!("{fingerprint}…"), source);
    }
    Ok(())
}

fn cmd_qr(args: QrArgs) -> Result<()> {
    let token = match link::parse_ticket(&args.code) {
        Some(t) => t,
        None => {
            eprintln!("error: could not extract a token from {:?}", args.code);
            std::process::exit(1);
        }
    };
    qr::print_pairing("Pairing code:", &token);
    Ok(())
}

/// Parse `--expires` (`1h`, `24h`, `7d`, `never`) into an [`Expiry`].
fn parse_expiry(s: &str) -> Result<Expiry> {
    match s {
        "never" => Ok(Expiry::Never),
        "1h" => Ok(Expiry::In(std::time::Duration::from_secs(60 * 60))),
        "24h" => Ok(Expiry::In(std::time::Duration::from_secs(24 * 60 * 60))),
        "7d" => Ok(Expiry::In(std::time::Duration::from_secs(7 * 24 * 60 * 60))),
        other => anyhow::bail!("invalid --expires {other:?}; expected 1h, 24h, 7d, or never"),
    }
}

async fn cmd_invite_mint(args: InviteMintArgs) -> Result<()> {
    let expiry = parse_expiry(&args.expires)?;

    // `serve` (default) and `serve-mcp`/`mcp` (`--bridge`) persist separate
    // node keys, so which identity this mints against determines which
    // running process can ever accept it — a `serve` invite is dialable
    // against a running (or about-to-run) `azula serve`; a `--bridge` invite
    // against `serve-mcp`/`mcp`. Getting this wrong is the #1 way a minted
    // invite mysteriously fails verification, so the identity is always
    // printed alongside the result.
    let identity_name = if args.bridge { "bridge" } else { "serve" };
    let (endpoint, ticket) = endpoint::bind_server_endpoint(identity_name).await?;
    let node_id = endpoint.id();

    let (payload, record) = invite::mint(
        &ticket,
        expiry,
        args.sign,
        args.single_use,
        args.label.clone(),
        endpoint.secret_key(),
    )?;
    let encoded = payload.encode();
    let url = qr::invite_url(&encoded);

    let node_id_str = node_id.to_string();
    println!(
        "Minted invite {} for the {identity_name} identity (node {}…)",
        record.id,
        &node_id_str[..8.min(node_id_str.len())]
    );
    println!("  expires: {}", describe_expiry(record.expires_at));
    if let Some(label) = &record.label {
        println!("  label: {label}");
    }
    println!("  signed: {}, single-use: {}", record.is_signed(), record.is_single_use());
    if args.bridge {
        println!("  pairs with: azula serve-mcp / azula mcp (this same identity)");
    } else {
        println!("  pairs with: azula serve (this same identity); NOT serve-mcp/mcp — mint with --bridge for that");
    }
    println!();
    qr::print_invite_pairing("Share this invite:", &encoded);
    println!("  {url}");
    Ok(())
}

fn describe_expiry(expires_at: u32) -> String {
    if expires_at == 0 {
        "never".to_string()
    } else {
        format!("unix {expires_at}")
    }
}

fn cmd_invites() -> Result<()> {
    let issued = invite::list();
    if issued.is_empty() {
        println!("No invites issued. Use `azula invite` to mint one.");
        return Ok(());
    }

    println!(
        "{:<18} {:<12} {:<20} {:<10} {:<8} LABEL",
        "ID", "CREATED", "EXPIRES", "CONSUMED", "FLAGS"
    );
    println!("{}", "-".repeat(90));
    for i in &issued {
        let expires = if i.expires_at == 0 { "never".to_string() } else { i.expires_at.to_string() };
        let mut flags = Vec::new();
        if i.is_signed() {
            flags.push("signed");
        }
        if i.is_single_use() {
            flags.push("single-use");
        }
        let flags = if flags.is_empty() { "-".to_string() } else { flags.join(",") };
        println!(
            "{:<18} {:<12} {:<20} {:<10} {:<8} {}",
            i.id,
            i.created_at,
            expires,
            i.consumed,
            flags,
            i.label.as_deref().unwrap_or("-"),
        );
    }
    Ok(())
}

fn cmd_invite_revoke(args: InviteRevokeArgs) -> Result<()> {
    let removed = invite::revoke(&args.id_prefix)?;
    if removed == 0 {
        eprintln!("No invite matching {:?} found.", args.id_prefix);
        std::process::exit(1);
    }
    println!("Revoked {removed} invite(s) matching {:?}.", args.id_prefix);
    Ok(())
}

async fn serve(args: ServeArgs) -> Result<()> {
    // Bind with the n0 defaults (public discovery + relays), reusing a persisted
    // key so the node id (and connect code) stays stable across restarts.
    let (endpoint, ticket) = endpoint::bind_server_endpoint("serve").await?;
    let node_id = endpoint.id();

    // `0` disables persistence outright (no reaper needed — sessions never
    // survive a detach in that mode, see `term::bind_attachment`).
    let session_ttl = if args.session_ttl == 0 {
        None
    } else {
        Some(std::time::Duration::from_secs(args.session_ttl * 60))
    };
    if let Some(ttl) = session_ttl {
        azula::term::spawn_ttl_reaper(ttl);
    }

    // MCP backend config. Exactly one transport flag may be set (clap enforces
    // mutual exclusion); neither set is allowed and yields the canned fallback.
    let transport = match (args.mcp_stdio, args.mcp_url) {
        (Some(cmd), _) => Some(McpTransport::Stdio(cmd)),
        (_, Some(url)) => Some(McpTransport::Url(url)),
        (None, None) => None,
    };
    let mcp_config = McpConfig {
        transport: transport.clone(),
        tool: args.mcp_tool,
        message_arg: args.mcp_message_arg,
    };

    let mcp_target = match &transport {
        Some(McpTransport::Stdio(cmd)) => format!("stdio: {cmd}"),
        Some(McpTransport::Url(url)) => format!("http: {url}"),
        None => "none (canned fallback)".to_string(),
    };
    let mut banner_lines = vec![
        "  Paste this code into the azula app to connect:".to_string(),
        String::new(),
        format!("    {ticket}"),
        String::new(),
        format!("  Short node id: {node_id}"),
        String::new(),
        "  Serving ALPNs:".to_string(),
    ];
    if !args.term_only {
        banner_lines.push(format!("    azula/llm/0   MCP relay  -> {mcp_target}"));
    }
    let session_ttl_desc = match session_ttl {
        Some(ttl) => format!("{} min", ttl.as_secs() / 60),
        None => "disabled (--session-ttl 0)".to_string(),
    };
    banner_lines.push(format!("    azula/term/0  remote shell (session ttl: {session_ttl_desc})"));
    endpoint::print_banner("azula server", &banner_lines);

    // Mint a signed 24h invite for the startup pairing QR instead of printing
    // the raw ticket, unless --legacy-ticket asks for the old behavior (or
    // minting fails, e.g. $HOME unset).
    let startup_invite = if args.legacy_ticket {
        None
    } else {
        let expiry = Expiry::In(std::time::Duration::from_secs(24 * 60 * 60));
        match invite::mint(&ticket, expiry, true, false, None, endpoint.secret_key()) {
            Ok((payload, _)) => Some(payload.encode()),
            Err(e) => {
                warn!(error = %e, "invite: failed to mint startup invite; falling back to raw ticket");
                None
            }
        }
    };
    match &startup_invite {
        Some(encoded) => qr::print_invite_pairing("Pair by scanning:", encoded),
        None => qr::print_pairing("Pair by scanning:", &ticket),
    }

    // Establish the shared upstream MCP session eagerly (when a transport flag
    // is set). A connect failure is non-fatal: log it and fall back to the
    // no-MCP responder so the iroh path stays usable.
    let mcp = match mcp::connect(&mcp_config).await {
        Ok(handle) => handle,
        Err(e) => {
            warn!(error = %e, "mcp: eager connect failed; using canned fallback responder");
            None
        }
    };

    // A Router dispatches incoming connections by ALPN to the handlers. In
    // term-only mode we skip the LLM ALPN so a connecting client lands directly
    // in a terminal (the client keeps the highest-priority ALPN a peer accepts).
    let router = if args.term_only {
        info!("term-only mode: serving the remote shell, no LLM");
        Router::builder(endpoint)
            .accept(
                TERM_ALPN,
                TermHandler::new(node_id, args.allow_legacy, args.name.clone(), args.description.clone(), session_ttl),
            )
            .spawn()
    } else {
        Router::builder(endpoint)
            .accept(LLM_ALPN, LlmHandler::new(mcp, node_id, args.allow_legacy))
            .accept(
                TERM_ALPN,
                TermHandler::new(node_id, args.allow_legacy, args.name.clone(), args.description.clone(), session_ttl),
            )
            .spawn()
    };

    info!("serving — press Ctrl-C to stop");
    tokio::signal::ctrl_c().await?;
    info!("shutting down…");
    router.shutdown().await?;
    // A live persistent session's PTY-reader thread is parked in a blocking
    // read from a shell that's still running; #[tokio::main]'s runtime
    // (dropped when this function returns) would otherwise hang waiting for
    // that thread to join. Kill every session's shell so it unblocks.
    azula::term::kill_all_sessions();
    Ok(())
}
