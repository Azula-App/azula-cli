//! Shared startup helpers for the long-lived server commands (`serve`, the
//! `serve-mcp`/`mcp` bridge, and the `blackjack` demo): binding an iroh
//! endpoint with a persisted identity and printing the startup banner.

use anyhow::Result;
use iroh::endpoint::presets;
use iroh::Endpoint;
use iroh_tickets::endpoint::EndpointTicket;
use tracing::info;

use crate::identity;

/// Bind an iroh endpoint reusing the persisted secret key for `identity_name`,
/// wait for it to come online, and return it along with its connect ticket.
/// This is the "load_or_create_secret → bind → online → ticket" sequence every
/// server command needs before standing up its own ALPN handlers.
pub async fn bind_server_endpoint(identity_name: &str) -> Result<(Endpoint, String)> {
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(identity::load_or_create_secret(identity_name))
        .bind()
        .await?;
    info!("bringing endpoint online…");
    endpoint.online().await;
    let ticket = EndpointTicket::new(endpoint.addr()).to_string();
    Ok((endpoint, ticket))
}

/// Print a boxed startup banner: a centered `title`, then each of `body` on
/// its own line. Callers format `body` with whatever's relevant (ticket, node
/// id, ALPNs, HTTP endpoint, …) — this just owns the shared framing.
pub fn print_banner(title: &str, body: &[String]) {
    const INNER_WIDTH: usize = 60;
    let title_len = title.chars().count();
    let left = (INNER_WIDTH.saturating_sub(title_len)) / 2;
    let right = INNER_WIDTH.saturating_sub(title_len).saturating_sub(left);

    println!();
    println!("  ╔{}╗", "═".repeat(INNER_WIDTH));
    println!("  ║{}{}{}║", " ".repeat(left), title, " ".repeat(right));
    println!("  ╚{}╝", "═".repeat(INNER_WIDTH));
    println!();
    for line in body {
        println!("{line}");
    }
    println!();
}
