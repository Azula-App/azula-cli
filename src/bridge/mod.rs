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
use iroh::{Endpoint, SecretKey};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::StreamableHttpService;
use rmcp::ServiceExt;
use tokio::sync::Mutex as AsyncMutex;
use tracing::{info, warn};

use crate::certs;
use crate::identity;
use crate::invite;
use crate::link::parse_ticket;
use crate::mailbox;
use crate::mcp::LLM_ALPN;
use crate::qr;
use crate::registry;
use crate::session::SessionKey;

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
    /// The per-process session identity bound to `endpoint` (design.md D2).
    /// Held so an ephemeral session's on-disk key file isn't deleted (by its
    /// Drop guard) while the bridge is still using it.
    #[allow(dead_code)]
    session: SessionKey,
    /// This session's own `azd…` certificate — chained to the machine root
    /// when one exists, self-certified otherwise (design.md D1/D3) —
    /// re-presented in every `Hello` frame this bridge sends.
    session_cert: String,
    /// The machine identity, read from disk only (never created here) —
    /// `None` in a headless environment. Used solely to mint pairing invites
    /// against the machine identity (`mint_pairing_invite`); see
    /// `identity::load_machine_secret_if_exists`'s docs for why a
    /// session-establishment path like this one must never create one.
    machine_secret: Option<SecretKey>,
}

/// Bind the endpoint, stand up the accept router, preload known devices (+ any
/// `--device` flags), and start the background dial + redelivery loops. `label` is
/// a human tag written into the runtime state file (the HTTP bind, or "stdio").
/// `allow_legacy` admits invite-less unknown strangers as unverified instead
/// of closing the connection (see `BridgeAcceptHandler` / the invitations
/// spec's transition policy). `session_name` is `--session`/`AZULA_SESSION`:
/// `Some` selects a persistent named session key, `None` mints a fresh
/// ephemeral one per process (design.md D2) — this is what binds the
/// endpoint now, never the old shared "bridge" identity, so concurrent
/// `azula mcp` processes never collide on one node id.
async fn setup_bridge(
    label: &str,
    device_urls: Vec<String>,
    name: Option<String>,
    allow_legacy: bool,
    session_name: Option<String>,
) -> Result<BridgeCore> {
    let session = SessionKey::resolve(session_name.as_deref())?;
    let (raw_endpoint, bridge_ticket) = crate::endpoint::bind_endpoint_with_secret(session.secret.clone()).await?;
    let my_node_id = raw_endpoint.id();
    info!(session = %session.display_name, mode = ?session.mode, node_id = %my_node_id, "bridge: session identity");

    // D1: the machine identity, read-only — session establishment must never
    // implicitly create `machine.key` (the headless spec's "no standing
    // credential"). `None` here is the headless case: no machine to chain a
    // session cert to, so the session self-certifies instead (D3).
    let machine_secret = identity::load_machine_secret_if_exists();

    // The session's own `azd…` cert, carried in every Hello frame this
    // process sends: chained to the machine root when one exists, or
    // self-certified (`root_pk == device_pk == session_pk`) in the headless
    // case — same minting path either way (`certs::mint_session_cert`).
    let session_cert = match &machine_secret {
        Some(m) => certs::mint_session_cert(m, my_node_id, certs::DEFAULT_SESSION_EXPIRY),
        None => certs::mint_self_certified_session(&session.secret, certs::DEFAULT_SESSION_EXPIRY),
    }
    .encode();

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
    let accept_handler = BridgeAcceptHandler::new(
        devices.clone(),
        label.to_string(),
        own_name.clone(),
        my_node_id,
        allow_legacy,
        session_cert.clone(),
    );
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
        let cert_owned = session_cert.clone();
        for (dev_name, ticket, invite) in entries {
            let ep = endpoint.clone();
            let devs = devices.clone();
            let label_str = label_owned.clone();
            let my_name = own_name_clone.clone();
            let my_cert = cert_owned.clone();
            tokio::spawn(async move {
                connect_device(&ep, &dev_name, &ticket, &devs, &my_name, invite.as_deref(), Some(&my_cert)).await;
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
        let my_cert = session_cert.clone();
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
                    connect_device(&ep, &dev_name, &ticket, &devs, &my_name, invite.as_deref(), Some(&my_cert)).await;
                    write_state(&label_owned, &devs).await;
                }
            }
        });
    }

    Ok(BridgeCore { endpoint, devices, bridge_ticket, own_name, _router: iroh_router, session, session_cert, machine_secret })
}

/// Mint a signed 24h invite wrapping `ticket`, signed by `secret_key` (spec:
/// "serve/serve-mcp mint a signed 24h invite for their startup pairing QR
/// instead of printing the raw ticket"). Shared by [`mint_pairing_invite`]
/// (which decides *which* identity's ticket/key to pass) and — indirectly, by
/// still being the raw building block — anything else that wants a plain
/// self-signed invite. A mint failure (e.g. `$HOME` unset) falls back to
/// `None` so callers can fall back to the raw-ticket link.
pub(super) fn mint_bridge_invite(ticket: &str, secret_key: &SecretKey) -> Option<String> {
    let expiry = invite::Expiry::In(std::time::Duration::from_secs(24 * 60 * 60));
    match invite::mint(ticket, expiry, true, false, None, secret_key) {
        Ok((payload, _)) => Some(payload.encode()),
        Err(e) => {
            tracing::warn!(error = %e, "bridge: failed to mint invite; falling back to raw ticket");
            None
        }
    }
}

/// Mint the pairing invite shown by the startup banner and the
/// `start_pairing` tool (design.md D1/D3): against the **machine** identity
/// when one already exists on disk (`machine_secret.is_some()` — this
/// function never creates one, matching `identity::load_machine_secret_if_exists`'s
/// contract), or the session's own identity when it doesn't (the headless
/// case, or a machine-identity bind failure).
///
/// Minting against the machine identity needs a dialable ticket for it, so
/// this briefly binds a second endpoint under `machine_secret` purely to
/// obtain one — the same "bind, mint, let it drop" shape `azula invite
/// --bridge` (`cmd_invite_mint` in `main.rs`) already uses; the ticket is a
/// pre-authorization for whenever the machine identity is next brought
/// online with a router, not a promise that it's dialable right now (a
/// dedicated `azula pair` context, design.md's open follow-up, is where that
/// gets tightened up).
pub(super) async fn mint_pairing_invite(
    machine_secret: Option<&SecretKey>,
    session_ticket: &str,
    session_secret: &SecretKey,
) -> Option<String> {
    if let Some(machine_secret) = machine_secret {
        match crate::endpoint::bind_endpoint_with_secret(machine_secret.clone()).await {
            Ok((_ep, machine_ticket)) => {
                if let Some(encoded) = mint_bridge_invite(&machine_ticket, machine_secret) {
                    return Some(encoded);
                }
            }
            Err(e) => {
                warn!(error = %e, "bridge: could not bind the machine identity for a pairing invite; falling back to the session identity");
            }
        }
    }
    mint_bridge_invite(session_ticket, session_secret)
}

/// Mint the bridge's startup pairing QR invite (against the machine identity
/// when available, else the session's own — see [`mint_pairing_invite`]).
/// `legacy_ticket` skips minting entirely (the `--legacy-ticket` escape
/// hatch), returning the session's raw ticket link instead.
async fn startup_invite(core: &BridgeCore, legacy_ticket: bool) -> Option<String> {
    if legacy_ticket {
        return None;
    }
    mint_pairing_invite(core.machine_secret.as_ref(), &core.bridge_ticket, core.endpoint.secret_key()).await
}

pub async fn run(
    bind: String,
    device_urls: Vec<String>,
    name: Option<String>,
    max_turns: u64,
    allow_legacy: bool,
    legacy_ticket: bool,
    session_name: Option<String>,
) -> Result<()> {
    let core = setup_bridge(&bind, device_urls, name, allow_legacy, session_name).await?;

    // MCP server over Streamable HTTP, mounted at /mcp.
    let ep_svc = core.endpoint.clone();
    let devs_svc = core.devices.clone();
    let bind_svc = bind.clone();
    let ticket_svc = core.bridge_ticket.clone();
    let own_name_svc = core.own_name.clone();
    let session_cert_svc = core.session_cert.clone();
    let machine_secret_svc = core.machine_secret.clone();
    let service = StreamableHttpService::new(
        move || Ok(AzulaBridge::new(
            ep_svc.clone(),
            devs_svc.clone(),
            bind_svc.clone(),
            ticket_svc.clone(),
            own_name_svc.clone(),
            max_turns,
            legacy_ticket,
            session_cert_svc.clone(),
            machine_secret_svc.clone(),
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
    match startup_invite(&core, legacy_ticket).await {
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
    session_name: Option<String>,
) -> Result<()> {
    let core = setup_bridge("stdio", device_urls, name, allow_legacy, session_name).await?;

    eprintln!("azula MCP bridge (stdio) online as \"{}\"", core.own_name);
    match startup_invite(&core, legacy_ticket).await {
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
        core.session_cert.clone(),
        core.machine_secret.clone(),
    );
    // Serve over stdio; core stays alive (holds the accept router) until we stop.
    let running = bridge.serve(rmcp::transport::stdio()).await?;
    running.waiting().await?;
    Ok(())
}
