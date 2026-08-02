//! Shared startup helpers for the long-lived server commands (`serve`, the
//! `serve-mcp`/`mcp` bridge, and the `blackjack` demo): binding an iroh
//! endpoint with a persisted identity and printing the startup banner.

use anyhow::Result;
use iroh::endpoint::presets;
use iroh::{Endpoint, SecretKey};
use iroh_tickets::endpoint::EndpointTicket;
use tracing::info;

use crate::identity;

/// Bind an iroh endpoint with an explicit secret key, wait for it to come
/// online, and return it along with its connect ticket. This is the
/// "bind → online → ticket" sequence every server command needs before
/// standing up its own ALPN handlers; [`bind_server_endpoint`] and
/// [`bind_machine_endpoint`] are thin wrappers that resolve `secret` from a
/// persisted identity first.
pub async fn bind_endpoint_with_secret(secret: SecretKey) -> Result<(Endpoint, String)> {
    let endpoint = Endpoint::builder(presets::N0).secret_key(secret).bind().await?;
    info!("bringing endpoint online…");
    endpoint.online().await;
    let ticket = EndpointTicket::new(endpoint.addr()).to_string();
    Ok((endpoint, ticket))
}

/// Bind an iroh endpoint reusing the persisted secret key for `identity_name`,
/// wait for it to come online, and return it along with its connect ticket.
pub async fn bind_server_endpoint(identity_name: &str) -> Result<(Endpoint, String)> {
    bind_endpoint_with_secret(identity::load_or_create_secret(identity_name)).await
}

/// As [`bind_server_endpoint`], but for the machine identity
/// (`~/.azula/machine.key`, adopting `bridge.key` in place if that's all that
/// exists — see `identity::load_or_create_machine_secret`). Creation is
/// allowed here: callers of this function are explicit pairing-side flows
/// (`azula invite --bridge`, `start_pairing`, the bridge startup banner),
/// never a bare session-establishment path.
pub async fn bind_machine_endpoint() -> Result<(Endpoint, String)> {
    bind_endpoint_with_secret(identity::load_or_create_machine_secret()).await
}

/// Print a boxed startup banner: a centered `title`, then each of `body` on
/// its own line. Callers format `body` with whatever's relevant (ticket, endpoint
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
