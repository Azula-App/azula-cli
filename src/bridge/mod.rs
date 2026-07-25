//! `azula mcp` (`serve-mcp`/`mcp`) — multi-device MCP↔iroh bridge.
//!
//! Runs an MCP server (stdio by default, or Streamable HTTP with `--http`).
//! An external LLM client connects and uses these tools to manage azula
//! device sessions and peer-bridge conversations:
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
//! `tools` is the `AzulaBridge` MCP tool surface, a thin wrapper over
//! [`crate::core::SessionCore`] (connection/registry/relay/A2UI/inbox logic
//! now lives there, shared with the CLI verbs in [`crate::cli`]). This module
//! wires it together: `run` / `run_stdio` call [`crate::core::establish`] to
//! bind the endpoint and start the accept/dial/redelivery loops, then stand
//! up the MCP server on top of it.

mod tools;

#[cfg(test)]
mod tests;

use anyhow::Result;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::StreamableHttpService;
use rmcp::ServiceExt;

use crate::core::{self, Established};
use crate::qr;

use tools::AzulaBridge;

/// Mint the bridge's startup pairing QR invite (against the machine identity
/// when available, else the session's own — see [`core::mint_pairing_invite`]
/// via [`core::SessionCore::pairing_url`]). `legacy_ticket` skips minting
/// entirely (the `--legacy-ticket` escape hatch), returning the session's raw
/// ticket link instead.
async fn startup_invite(core: &core::SessionCore, legacy_ticket: bool) -> Option<String> {
    if legacy_ticket {
        return None;
    }
    Some(core.pairing_url(false).await)
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
    let Established { core, session: _session, router: _router } =
        core::establish(&bind, device_urls, name, allow_legacy, session_name).await?;

    // MCP server over Streamable HTTP, mounted at /mcp.
    let ep_svc = core.endpoint.clone();
    let devs_svc = core.devices.clone();
    let bind_svc = bind.clone();
    let ticket_svc = core.ticket.clone();
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
        std::sync::Arc::new(LocalSessionManager::default()),
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
        Some(url) => qr::print_pairing_url("Pair a device by scanning:", &url),
        None => qr::print_pairing("Pair a device by scanning:", &core.ticket),
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
    let Established { core, session: _session, router: _router } =
        core::establish("stdio", device_urls, name, allow_legacy, session_name).await?;

    eprintln!("azula MCP bridge (stdio) online as \"{}\"", core.own_name);
    match startup_invite(&core, legacy_ticket).await {
        Some(url) => eprintln!("pairing URL: {url}"),
        None => eprintln!("pairing URL: {}", qr::pairing_url(&core.ticket)),
    }
    eprintln!("(call the start_pairing tool to show a QR and pair a phone)");

    let bridge = AzulaBridge::new(
        core.endpoint.clone(),
        core.devices.clone(),
        "stdio".to_string(),
        core.ticket.clone(),
        core.own_name.clone(),
        max_turns,
        legacy_ticket,
        core.session_cert.clone(),
        core.machine_secret.clone(),
    );
    // Serve over stdio; core/router/session stay alive (holds the accept
    // router, keeps an ephemeral session's key file from being deleted)
    // until we stop.
    let running = bridge.serve(rmcp::transport::stdio()).await?;
    running.waiting().await?;
    Ok(())
}
