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
mod mcp;
mod proto;
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
    /// Run the MCP↔iroh bridge: an MCP server (Streamable HTTP) that dials an
    /// Azula app over iroh, so an LLM can connect to the app's session.
    ServeMcp(ServeMcpArgs),
}

/// Options for the `serve-mcp` command (the MCP↔iroh bridge).
#[derive(Debug, Clone, clap::Args)]
struct ServeMcpArgs {
    /// The Azula app's iroh ticket (its session "code") to bridge to.
    #[arg(long, env = "AZULA_APP_TICKET")]
    app_ticket: String,

    /// Address to serve the MCP-over-HTTP endpoint on (path is /mcp).
    #[arg(long, env = "AZULA_MCP_BIND", default_value = "127.0.0.1:8765")]
    bind: String,
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
        Some(Command::ServeMcp(args)) => bridge::run(args.app_ticket, args.bind).await,
        Some(Command::Serve(args)) => serve(args).await,
        None => serve(cli.serve).await,
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
