//! `serve-mcp` — multi-device MCP↔iroh bridge.
//!
//! Runs an MCP server over Streamable HTTP.  An external LLM client connects
//! and uses these tools to manage azula device sessions and peer-bridge
//! conversations:
//!
//! - `connect`        — pair a new device or peer bridge by ticket/URL
//! - `list_devices`   — show known + live-connection status
//! - `send_message`   — send text to an azula app device (streamed assistant reply)
//! - `send_file`      — send a local file (e.g. an image) to a device as an inline attachment
//! - `get_messages`   — drain the inbox: user chat text + `ui-event:` lines + peer messages + received files
//! - `wait_for_reply` — long-poll until a device has new inbound activity, then drain it
//! - `set_name`       — set the conversation's name/description shown in the app
//! - `say`            — send a peer-to-peer chat message to another bridge
//! - `render_ui`      — render an A2UI declarative surface on a device
//! - `update_ui`      — update a surface's data model (react to a `ui-event`)
//! - `delete_ui`      — remove a surface
//! - `disconnect`     — drop a live connection, optionally forget the device
//! - `start_pairing`  — show the bridge's pairing URL + QR code
//!
//! The app renders an `a2ui` frame's message (A2UI v0.9.1: createSurface /
//! updateComponents / updateDataModel / deleteSurface) as a native surface in
//! its azula conversation, and sends an `a2ui_action` frame back when the user
//! interacts — which the reader surfaces through `get_messages`.
//!
//! Two bridges can talk to each other: when `connect` dials a remote bridge,
//! a `hello` frame is sent first so the peer can name this bridge. Then
//! `say` delivers chat frames peer-to-peer. `get_messages` returns both app
//! chat and peer chat from the same inbox. The bridge enforces a hard
//! per-peer `max_turns` cap; `say done=true` ends the conversation early.
//!
//! On startup the bridge loads the registry and dials every known device in the
//! background (failures are non-fatal).
//!
//! Submodules: [`device`] owns per-device connection state (dial + accept +
//! reconnect matching), [`state`] writes the runtime state file, and [`tools`]
//! is the `AzulaBridge` MCP tool surface. This module wires them together:
//! `setup_bridge` binds the endpoint and starts the accept/dial/redelivery
//! loops, and `run` / `run_stdio` stand up the MCP server on top of that.

mod device;
mod state;
mod tools;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use iroh::protocol::Router;
use iroh::Endpoint;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::StreamableHttpService;
use rmcp::ServiceExt;
use tokio::sync::Mutex as AsyncMutex;
use tracing::info;

use crate::invite;
use crate::link::parse_ticket;
use crate::mailbox;
use crate::mcp::LLM_ALPN;
use crate::qr;
use crate::registry;

use device::{connect_device, BridgeAcceptHandler, DeviceMap};
use state::write_state;
use tools::AzulaBridge;

// ---------------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------------

/// The iroh side of the bridge, shared by the HTTP (`run`) and stdio (`run_stdio`)
/// MCP servers: a bound endpoint, the accept router, the device map, and the
/// background dial + redelivery tasks. `_router` is held so accepts keep working.
struct BridgeCore {
    endpoint: Arc<Endpoint>,
    devices: DeviceMap,
    bridge_ticket: String,
    own_name: String,
    _router: Router,
}

/// Bind the endpoint, stand up the accept router, preload known devices (+ any
/// `--device` flags), and start the background dial + redelivery loops. `label` is
/// a human tag written into the runtime state file (the HTTP bind, or "stdio").
/// `allow_legacy` admits invite-less unknown strangers as unverified instead
/// of closing the connection (see `BridgeAcceptHandler` / the invitations
/// spec's transition policy).
async fn setup_bridge(
    label: &str,
    device_urls: Vec<String>,
    name: Option<String>,
    allow_legacy: bool,
) -> Result<BridgeCore> {
    // Reuse a persisted key so the bridge keeps a stable node id (and connect
    // code) across restarts; the one endpoint serves both accept and dial.
    let (raw_endpoint, bridge_ticket) = crate::endpoint::bind_server_endpoint("bridge").await?;
    let my_node_id = raw_endpoint.id();

    let devices: DeviceMap = Arc::new(AsyncMutex::new(HashMap::new()));

    // Our display name (the conversation title the app shows), announced to apps in
    // both the dial and accept directions. Computed before the accept handler so it
    // can use it. Falls back to bridge-<id> only when no --name was given.
    let endpoint_id_str = my_node_id.to_string();
    let own_name = name.unwrap_or_else(|| {
        let len = endpoint_id_str.len();
        format!("bridge-{}", &endpoint_id_str[..8_usize.min(len)])
    });

    // Accept incoming azula app / peer-bridge connections (devices that scanned
    // the bridge's QR) and register them.
    let accept_handler =
        BridgeAcceptHandler::new(devices.clone(), label.to_string(), own_name.clone(), my_node_id, allow_legacy);
    let iroh_router = Router::builder(raw_endpoint)
        .accept(LLM_ALPN, accept_handler)
        .spawn();

    // One endpoint for both accepting inbound and dialing outbound.
    let endpoint = Arc::new(iroh_router.endpoint().clone());

    info!(own_name=%own_name, "bridge: own name");

    // Load registry and pre-populate the device map.
    let known = registry::load();
    {
        let mut guard = devices.lock().await;
        for d in &known {
            guard.insert(d.name.clone(), device::DeviceConn::new(d.ticket.clone()).with_invite(d.invite.clone()));
        }
    }

    // Also add any --device flags (not persisted).
    for url in &device_urls {
        if let Some(token) = parse_ticket(url) {
            let dev_name: String = token.chars().take(8).collect();
            let mut guard = devices.lock().await;
            guard.entry(dev_name.clone()).or_insert_with(|| device::DeviceConn::new(token.clone()));
        }
    }

    write_state(label, &devices).await;

    // Best-effort dial all known devices in the background.
    {
        let guard = devices.lock().await;
        let entries: Vec<(String, String, Option<String>)> = guard
            .iter()
            .map(|(n, c)| (n.clone(), c.ticket.clone(), c.invite.clone()))
            .collect();
        drop(guard);

        let own_name_clone = own_name.clone();
        let label_owned = label.to_string();
        for (dev_name, ticket, invite) in entries {
            let ep = endpoint.clone();
            let devs = devices.clone();
            let label_str = label_owned.clone();
            let my_name = own_name_clone.clone();
            tokio::spawn(async move {
                connect_device(&ep, &dev_name, &ticket, &devs, &my_name, invite.as_deref()).await;
                write_state(&label_str, &devs).await;
            });
        }
    }

    // Periodic redelivery: every 25 s, try to reconnect any offline device
    // that has queued mail.
    {
        let ep = endpoint.clone();
        let devs = devices.clone();
        let label_owned = label.to_string();
        let my_name = own_name.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(25)).await;
                let pending: Vec<(String, String, Option<String>)> = {
                    let guard = devs.lock().await;
                    guard.iter()
                        .filter(|(name, conn)| !conn.connected && mailbox::has_pending(name))
                        .map(|(name, conn)| (name.clone(), conn.ticket.clone(), conn.invite.clone()))
                        .collect()
                };
                for (dev_name, ticket, invite) in pending {
                    info!(device=%dev_name, "bridge: attempting redelivery of queued mail");
                    connect_device(&ep, &dev_name, &ticket, &devs, &my_name, invite.as_deref()).await;
                    write_state(&label_owned, &devs).await;
                }
            }
        });
    }

    Ok(BridgeCore { endpoint, devices, bridge_ticket, own_name, _router: iroh_router })
}

/// Mint a signed 24h invite wrapping `ticket` (spec: "serve/serve-mcp mint a
/// signed 24h invite for their startup pairing QR instead of printing the raw
/// ticket"). Shared by the startup banner ([`startup_invite`]) and the
/// `start_pairing` MCP tool (`tools.rs`), so both surfaces retire the raw
/// ticket link the same way. A mint failure (e.g. `$HOME` unset) falls back
/// to `None` so callers can fall back to the raw-ticket link.
pub(super) fn mint_bridge_invite(ticket: &str, secret_key: &iroh::SecretKey) -> Option<String> {
    let expiry = invite::Expiry::In(std::time::Duration::from_secs(24 * 60 * 60));
    match invite::mint(ticket, expiry, true, false, None, secret_key) {
        Ok((payload, _)) => Some(payload.encode()),
        Err(e) => {
            tracing::warn!(error = %e, "bridge: failed to mint invite; falling back to raw ticket");
            None
        }
    }
}

/// Mint a signed 24h invite for the bridge's startup pairing QR.
/// `legacy_ticket` skips minting (the `--legacy-ticket` escape hatch).
fn startup_invite(core: &BridgeCore, legacy_ticket: bool) -> Option<String> {
    if legacy_ticket {
        return None;
    }
    mint_bridge_invite(&core.bridge_ticket, core.endpoint.secret_key())
}

pub async fn run(
    bind: String,
    device_urls: Vec<String>,
    name: Option<String>,
    max_turns: u64,
    allow_legacy: bool,
    legacy_ticket: bool,
) -> Result<()> {
    let core = setup_bridge(&bind, device_urls, name, allow_legacy).await?;

    // MCP server over Streamable HTTP, mounted at /mcp.
    let ep_svc = core.endpoint.clone();
    let devs_svc = core.devices.clone();
    let bind_svc = bind.clone();
    let ticket_svc = core.bridge_ticket.clone();
    let own_name_svc = core.own_name.clone();
    let service = StreamableHttpService::new(
        move || Ok(AzulaBridge::new(
            ep_svc.clone(),
            devs_svc.clone(),
            bind_svc.clone(),
            ticket_svc.clone(),
            own_name_svc.clone(),
            max_turns,
            legacy_ticket,
        )),
        Arc::new(LocalSessionManager::default()),
        Default::default(),
    );
    let http_router = axum::Router::new().nest_service("/mcp", service);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    crate::endpoint::print_banner(
        "azula MCP bridge (multi-device)",
        &[
            format!("  MCP endpoint:  http://{bind}/mcp"),
            "  Add this URL to an MCP-capable LLM client.".to_string(),
        ],
    );
    match startup_invite(&core, legacy_ticket) {
        Some(encoded) => qr::print_invite_pairing("Pair a device by scanning:", &encoded),
        None => qr::print_pairing("Pair a device by scanning:", &core.bridge_ticket),
    }
    axum::serve(listener, http_router).await?;
    Ok(())
}

/// Run the bridge as a **stdio** MCP server — for `claude mcp add azula -- azula mcp`.
/// Same `AzulaBridge` + iroh node as [`run`], but JSON-RPC is spoken over stdin/stdout,
/// so all human output goes to **stderr** and never corrupts the protocol stream.
pub async fn run_stdio(
    device_urls: Vec<String>,
    name: Option<String>,
    max_turns: u64,
    allow_legacy: bool,
    legacy_ticket: bool,
) -> Result<()> {
    let core = setup_bridge("stdio", device_urls, name, allow_legacy).await?;

    eprintln!("azula MCP bridge (stdio) online as \"{}\"", core.own_name);
    match startup_invite(&core, legacy_ticket) {
        Some(encoded) => eprintln!("pairing URL: {}", qr::invite_url(&encoded)),
        None => eprintln!("pairing URL: {}", qr::pairing_url(&core.bridge_ticket)),
    }
    eprintln!("(call the start_pairing tool to show a QR and pair a phone)");

    let bridge = AzulaBridge::new(
        core.endpoint.clone(),
        core.devices.clone(),
        "stdio".to_string(),
        core.bridge_ticket.clone(),
        core.own_name.clone(),
        max_turns,
        legacy_ticket,
    );
    // Serve over stdio; core stays alive (holds the accept router) until we stop.
    let running = bridge.serve(rmcp::transport::stdio()).await?;
    running.waiting().await?;
    Ok(())
}
