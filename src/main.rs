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
//!
//! The command-line surface itself (noun-verb taxonomy, argument parsing,
//! per-verb dispatch) lives in `azula::cli` — this binary is just the
//! process entry point: set up logging (stderr only — `azula mcp`'s stdio
//! transport speaks JSON-RPC over stdout, so any stray stdout write would
//! corrupt the protocol stream), then hand off.

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    azula::cli::run().await
}
