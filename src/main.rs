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

mod bridge;
mod demo;
mod link;
mod mailbox;
mod mcp;
mod proto;
mod qr;
mod registry;
mod term;

use anyhow::Result;
use clap::{Parser, Subcommand};
use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::Endpoint;
use iroh_tickets::endpoint::EndpointTicket;
use tracing::{info, warn};

use crate::mcp::{LlmHandler, McpConfig, McpTransport, LLM_ALPN};
use crate::term::{TermHandler, TERM_ALPN};

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
    /// Pair a new device: save its ticket to the registry.
    Pair(PairArgs),
    /// List all registered devices and their registry source.
    Devices,
    /// Print a QR code for a ticket, URL, or bare token.
    Qr(QrArgs),
    /// Push a sample A2UI surface to a connected device for manual testing.
    DemoUi(DemoUiArgs),
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
}

/// Options for `azula pair`.
#[derive(Debug, Clone, clap::Args)]
struct PairArgs {
    /// The device ticket URL or bare token.
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

/// Options for `azula demo-ui`.
#[derive(Debug, Clone, clap::Args)]
struct DemoUiArgs {
    /// A registered device name, or a ticket / pairing URL to dial directly.
    device: String,

    /// Render the sample surface and exit without listening for events.
    #[arg(long)]
    once: bool,
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
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Some(Command::ServeMcp(args)) => {
            bridge::run(args.bind, args.device.unwrap_or_default(), args.name, args.max_turns).await
        }
        Some(Command::Serve(args)) => serve(args).await,
        Some(Command::Pair(args)) => cmd_pair(args),
        Some(Command::Devices) => cmd_devices(),
        Some(Command::Qr(args)) => cmd_qr(args),
        Some(Command::DemoUi(args)) => demo::run(args.device, args.once).await,
        None => serve(cli.serve).await,
    }
}

fn cmd_pair(args: PairArgs) -> Result<()> {
    let token = match link::parse_ticket(&args.url) {
        Some(t) => t,
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
    let global_devices = registry::global_path()
        .map(|p| {
            if p.exists() {
                load_names_from_file(&p)
            } else {
                vec![]
            }
        })
        .unwrap_or_default();

    let project_devices = registry::project_path()
        .map(|p| {
            if p.exists() {
                load_names_from_file(&p)
            } else {
                vec![]
            }
        })
        .unwrap_or_default();

    println!("{:<20} {:<12} {}", "NAME", "FINGERPRINT", "SOURCE");
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

fn load_names_from_file(path: &std::path::Path) -> Vec<String> {
    #[derive(serde::Deserialize)]
    struct Reg { devices: Vec<registry::Device> }
    let data = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    match serde_json::from_str::<Reg>(&data) {
        Ok(r) => r.devices.into_iter().map(|d| d.name).collect(),
        Err(_) => vec![],
    }
}

async fn serve(args: ServeArgs) -> Result<()> {
    // Bind with the n0 defaults (public discovery + relays).
    let endpoint = Endpoint::bind(presets::N0).await?;
    info!("waiting for the endpoint to come online…");
    endpoint.online().await;

    let node_id = endpoint.id();
    let ticket = EndpointTicket::new(endpoint.addr());

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
    print_banner(&node_id.to_string(), &ticket.to_string(), &mcp_target);
    qr::print_pairing("Pair by scanning:", &ticket.to_string());

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

    // A Router dispatches incoming connections by ALPN to the handlers.
    let router = Router::builder(endpoint)
        .accept(LLM_ALPN, LlmHandler::new(mcp))
        .accept(TERM_ALPN, TermHandler::new())
        .spawn();

    info!("serving — press Ctrl-C to stop");
    tokio::signal::ctrl_c().await?;
    info!("shutting down…");
    router.shutdown().await?;
    Ok(())
}

fn print_banner(node_id: &str, ticket: &str, mcp_target: &str) {
    println!();
    println!("  ╔══════════════════════════════════════════════════════════╗");
    println!("  ║                     azula server                          ║");
    println!("  ╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Paste this code into the azula app to connect:");
    println!();
    println!("    {ticket}");
    println!();
    println!("  Short node id: {node_id}");
    println!();
    println!("  Serving ALPNs:");
    println!("    azula/llm/0   MCP relay  -> {mcp_target}");
    println!("    azula/term/0  remote shell");
    println!();
}
