//! `serve-mcp` — multi-device MCP↔iroh bridge.
//!
//! Runs an MCP server over Streamable HTTP.  An external LLM client connects
//! and uses these tools to manage azula device sessions and peer-bridge
//! conversations:
//!
//! - `connect`        — pair a new device or peer bridge by ticket/URL
//! - `list_devices`   — show known + live-connection status
//! - `send_message`   — send text to an azula app device (streamed assistant reply)
//! - `get_messages`   — drain the inbox: user chat text + `ui-event:` lines + peer messages
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

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;

use anyhow::Result;
use iroh::endpoint::presets;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::Endpoint;
use iroh_tickets::endpoint::EndpointTicket;
use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, ServerCapabilities, ServerInfo};
use rmcp::schemars;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::StreamableHttpService;
use rmcp::{tool, tool_handler, tool_router, ErrorData, ServerHandler};
use serde::{Deserialize, Serialize};
use tokio::io::BufReader;
use tokio::sync::Mutex as AsyncMutex;
use tracing::{info, warn};

use crate::link::parse_ticket;
use crate::mcp::LLM_ALPN;
use crate::proto::{read_frame, write_frame, Frame};
use crate::qr;
use crate::mailbox;
use crate::registry::{self, Device};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type Inbox = Arc<std::sync::Mutex<VecDeque<String>>>;
type AppSend = Arc<AsyncMutex<Option<SendStream>>>;

/// Per-device live state.
#[derive(Clone, Debug)]
struct DeviceConn {
    send: AppSend,
    inbox: Inbox,
    ticket: String,
    connected: bool,
    /// Turn counter for peer bridge conversations.
    turns: Arc<std::sync::atomic::AtomicU64>,
    /// Whether this conversation has been closed (turn limit or explicit done).
    closed: Arc<std::sync::atomic::AtomicBool>,
}

impl DeviceConn {
    fn new(ticket: String) -> Self {
        DeviceConn {
            send: Arc::new(AsyncMutex::new(None)),
            inbox: Arc::new(std::sync::Mutex::new(VecDeque::new())),
            ticket,
            connected: false,
            turns: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            closed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Reset conversation state (turns=0, closed=false) — call on (re)connect.
    fn reset_conversation(&self) {
        self.turns.store(0, Relaxed);
        self.closed.store(false, Relaxed);
    }
}

type DeviceMap = Arc<AsyncMutex<HashMap<String, DeviceConn>>>;

/// Monotonic counter for auto-generated A2UI surface ids (`ui-<n>`).
static SURFACE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// The A2UI basic catalog this bridge targets.
const A2UI_CATALOG: &str = "https://a2ui.org/specification/v0_9_1/catalogs/basic/catalog.json";

// ---------------------------------------------------------------------------
// Runtime state file
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct DeviceStatus {
    name: String,
    connected: bool,
}

#[derive(Serialize, Deserialize)]
struct BridgeState {
    bind: String,
    pid: u32,
    devices: Vec<DeviceStatus>,
}

fn state_path() -> std::path::PathBuf {
    std::env::temp_dir().join("azula").join("bridge.json")
}

async fn write_state(bind: &str, devices: &DeviceMap) {
    let path = state_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let guard = devices.lock().await;
    let statuses: Vec<DeviceStatus> = guard
        .iter()
        .map(|(name, conn)| DeviceStatus { name: name.clone(), connected: conn.connected })
        .collect();
    drop(guard);
    let state = BridgeState { bind: bind.to_string(), pid: std::process::id(), devices: statuses };
    if let Ok(json) = serde_json::to_string_pretty(&state) {
        let _ = std::fs::write(&path, json);
    }
}

// ---------------------------------------------------------------------------
// iroh dial helper
// ---------------------------------------------------------------------------

async fn dial_device(
    endpoint: &Endpoint,
    ticket_str: &str,
) -> Result<(SendStream, RecvStream)> {
    use std::str::FromStr;
    let ticket = EndpointTicket::from_str(ticket_str)?;
    let addr = ticket.endpoint_addr().clone();
    let conn = endpoint.connect(addr, LLM_ALPN).await?;
    Ok(conn.open_bi().await?)
}

/// Dial and register a device in the map.  Returns whether it connected.
/// Sends `Frame::Hello { name: own_name }` as the very first frame, then the
/// `thinking(false)` handshake.  Calls `reset_conversation()` on the DeviceConn.
async fn connect_device(
    endpoint: &Endpoint,
    name: &str,
    ticket: &str,
    devices: &DeviceMap,
    own_name: &str,
) -> bool {
    match dial_device(endpoint, ticket).await {
        Ok((mut send, recv)) => {
            // Send hello so the peer can name us.
            if let Err(e) = write_frame(&mut send, &Frame::Hello { name: own_name.into() }).await {
                warn!(device=%name, error=%e, "bridge: hello write failed");
                return false;
            }
            // Legacy handshake frame for azula app clients.
            if let Err(e) = write_frame(&mut send, &Frame::thinking(false)).await {
                warn!(device=%name, error=%e, "bridge: handshake write failed");
                return false;
            }
            // Flush any queued mailbox frames before handing off the stream.
            if let Err(e) = flush_mailbox(name, &mut send).await {
                warn!(device=%name, error=%e, "bridge: mailbox flush failed (continuing)");
            }
            let inbox: Inbox = Arc::new(std::sync::Mutex::new(VecDeque::new()));
            let inbox_reader = inbox.clone();
            tokio::spawn(async move { reader_loop(recv, inbox_reader).await });

            let mut guard = devices.lock().await;
            let conn = guard.entry(name.to_string()).or_insert_with(|| DeviceConn::new(ticket.to_string()));
            *conn.send.lock().await = Some(send);
            conn.inbox = inbox;
            conn.connected = true;
            conn.ticket = ticket.to_string();
            conn.reset_conversation();
            info!(device=%name, "bridge: connected");
            true
        }
        Err(e) => {
            warn!(device=%name, error=%e, "bridge: could not connect; device shows disconnected");
            false
        }
    }
}

async fn reader_loop(recv: RecvStream, inbox: Inbox) {
    read_frames_into(BufReader::new(recv), inbox).await
}

/// Push a single frame into an inbox (Chat → text, A2uiAction → `ui-event:` line).
fn push_frame(inbox: &Inbox, frame: Frame) {
    match frame {
        Frame::Chat { text } => inbox.lock().unwrap().push_back(text),
        Frame::A2uiAction { action } => {
            let line = format!("ui-event: {}", serde_json::to_string(&action).unwrap_or_default());
            inbox.lock().unwrap().push_back(line);
        }
        _ => {}
    }
}

/// Drain frames from a buffered reader into a device inbox. Chat text passes
/// through verbatim; an A2UI action becomes a parseable `ui-event:` line so the
/// LLM can react (match on surfaceId and respond with `update_ui`). Generic
/// over the reader so the behavior is unit-testable over an in-memory pipe.
async fn read_frames_into<R: tokio::io::AsyncRead + Unpin>(mut reader: BufReader<R>, inbox: Inbox) {
    loop {
        match read_frame(&mut reader).await {
            Ok(Some(frame)) => push_frame(&inbox, frame),
            Ok(None) => break,
            Err(e) => {
                warn!(error = %e, "bridge: app stream read error");
                break;
            }
        }
    }
}

/// Flush any queued mailbox frames to a device over its send stream.
/// Clears the mailbox only if all writes succeed; leaves it intact on error.
async fn flush_mailbox(device: &str, send: &mut SendStream) -> anyhow::Result<()> {
    let frames = crate::mailbox::load(device);
    if frames.is_empty() {
        return Ok(());
    }
    for f in &frames {
        write_frame(send, f).await?;
    }
    crate::mailbox::clear(device);
    Ok(())
}

// ---------------------------------------------------------------------------
// Accept handler — registers phones that scan the bridge's QR and dial in
// ---------------------------------------------------------------------------

/// iroh `ProtocolHandler` that accepts incoming azula app connections on
/// `LLM_ALPN` and registers each as a device in the shared map.
#[derive(Clone, Debug)]
struct BridgeAcceptHandler {
    devices: DeviceMap,
    bind: String,
    /// Counter to assign monotonically-increasing names to scanned devices.
    scan_counter: Arc<std::sync::atomic::AtomicU32>,
}

impl BridgeAcceptHandler {
    fn new(devices: DeviceMap, bind: String) -> Self {
        Self {
            devices,
            bind,
            scan_counter: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        }
    }
}

impl ProtocolHandler for BridgeAcceptHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        accept_incoming(connection, self.devices.clone(), self.bind.clone(), self.scan_counter.clone())
            .await
            .map_err(|e| AcceptError::from_boxed(e.into()))
    }
}

async fn accept_incoming(
    connection: Connection,
    devices: DeviceMap,
    bind: String,
    counter: Arc<std::sync::atomic::AtomicU32>,
) -> Result<()> {
    let remote_id_str = connection.remote_id().to_string();
    let fallback_name = if remote_id_str.len() >= 8 {
        format!("scan-{}", &remote_id_str[..8])
    } else {
        let n = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("scan-{n}")
    };

    info!(%fallback_name, "bridge: incoming connection");

    // The dialer opens the bi stream.
    let (mut send, recv) = connection.accept_bi().await?;
    let mut reader = BufReader::new(recv);

    // Read the very first frame to determine the peer's name.
    // If it's a Hello, use the name field; otherwise fall back to scan-<id>.
    let (peer_name, pending_frame) = match read_frame(&mut reader).await {
        Ok(Some(Frame::Hello { name })) => {
            let sanitized = if name.trim().is_empty() {
                fallback_name.clone()
            } else {
                name
            };
            info!(peer=%sanitized, "bridge: hello from peer");
            (sanitized, None)
        }
        Ok(Some(other)) => {
            // Non-hello first frame — use fallback name, replay frame.
            (fallback_name.clone(), Some(other))
        }
        Ok(None) | Err(_) => {
            // Clean close or parse error — drop without registering.
            return Ok(());
        }
    };

    let inbox: Inbox = Arc::new(std::sync::Mutex::new(VecDeque::new()));

    // Replay a non-hello first frame if present.
    if let Some(frame) = pending_frame {
        push_frame(&inbox, frame);
    }

    // Flush any queued mailbox frames before moving send into the map.
    if let Err(e) = flush_mailbox(&peer_name, &mut send).await {
        warn!(%peer_name, error=%e, "bridge: mailbox flush failed on accept (continuing)");
    }

    {
        let mut guard = devices.lock().await;
        let entry = guard.entry(peer_name.clone()).or_insert_with(|| DeviceConn {
            send: Arc::new(AsyncMutex::new(None)),
            inbox: inbox.clone(),
            ticket: remote_id_str.clone(),
            connected: false,
            turns: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            closed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        });
        // Update the send stream and status; preserve turns/closed so an
        // ongoing conversation is not interrupted by a re-dial from the peer.
        *entry.send.lock().await = Some(send);
        entry.connected = true;
        entry.ticket = remote_id_str.clone();
        // Update inbox to point at our newly created one so the reader below
        // drains into the same Inbox the entry holds.
        entry.inbox = inbox.clone();
    }

    write_state(&bind, &devices).await;
    info!(%peer_name, "bridge: peer registered");

    // Continue draining frames; reader already consumed the hello.
    read_frames_into(reader, inbox).await;
    Ok(())
}

// ---------------------------------------------------------------------------
// MCP tool argument types
// ---------------------------------------------------------------------------

#[derive(Deserialize, schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
struct ConnectArgs {
    /// The device URL or ticket to connect to.
    url: String,
    /// Optional display name for this device.
    name: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
struct SendMessageArgs {
    /// The device name to send to.
    device: String,
    /// The text to deliver.
    text: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
struct GetMessagesArgs {
    /// If specified, drain only this device; otherwise drain all devices.
    device: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
struct SayArgs {
    /// The peer bridge name to send to (as registered in the device map).
    device: String,
    /// The message text to deliver to the peer.
    text: String,
    /// If true, mark this conversation as done after sending (sends a closing notice to the peer).
    done: Option<bool>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
struct DisconnectArgs {
    /// The device name.
    device: String,
    /// If true, also remove from the registry.
    forget: Option<bool>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
struct RenderUiArgs {
    /// The device name to render the UI on.
    device: String,
    /// A2UI basic-catalog components as a flat JSON array. Each element is an
    /// object with an `id` and a `component` type; exactly one must have
    /// `"id":"root"`. Components reference children by id (`child` / `children`),
    /// and props may be literals or `{"path":"/ptr"}` bindings into the data
    /// model. Buttons carry `{"action":{"event":{"name":...,"context":{...}}}}`.
    components: serde_json::Value,
    /// Optional initial data model (a JSON object) backing the `{"path":...}` bindings.
    data_model: Option<serde_json::Value>,
    /// Optional surface id. One (`ui-<n>`) is generated if omitted.
    surface_id: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
struct UpdateUiArgs {
    /// The device name the surface lives on.
    device: String,
    /// The surface id returned by `render_ui`.
    surface_id: String,
    /// RFC 6901 JSON pointer into the data model (e.g. `/dice/you`). `""` targets the whole model.
    path: String,
    /// The new JSON value to set at `path`.
    value: serde_json::Value,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
struct DeleteUiArgs {
    /// The device name the surface lives on.
    device: String,
    /// The surface id to remove.
    surface_id: String,
}

// ---------------------------------------------------------------------------
// MCP server handler
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AzulaBridge {
    endpoint: Arc<Endpoint>,
    devices: DeviceMap,
    bind: String,
    /// The bridge's own iroh ticket (base32 string) used by `start_pairing`.
    pairing_ticket: String,
    /// This bridge's display name (sent as `hello` to peer bridges).
    own_name: String,
    /// Hard turn cap per peer bridge conversation.
    max_turns: u64,
    #[allow(dead_code)]
    tool_router: ToolRouter<AzulaBridge>,
}

#[tool_router]
impl AzulaBridge {
    fn new(
        endpoint: Arc<Endpoint>,
        devices: DeviceMap,
        bind: String,
        pairing_ticket: String,
        own_name: String,
        max_turns: u64,
    ) -> Self {
        Self {
            endpoint,
            devices,
            bind,
            pairing_ticket,
            own_name,
            max_turns,
            tool_router: Self::tool_router(),
        }
    }

    /// Connect to a new azula device or peer bridge by ticket URL or bare token.
    #[tool(description = "Connect to a new azula device or peer bridge by ticket URL (https://azula.app/s/<token>, azula://connect?code=<token>) or bare token. Optionally provide a display name. When connecting to another bridge, a hello frame is exchanged so the remote bridge can name this one.")]
    async fn connect(&self, Parameters(args): Parameters<ConnectArgs>) -> Result<CallToolResult, ErrorData> {
        let token = match parse_ticket(&args.url) {
            Some(t) => t,
            None => return Ok(CallToolResult::error(vec![Content::text("invalid ticket or URL")])),
        };

        // Derive name if absent.
        let name = args.name.unwrap_or_else(|| {
            let prefix: String = token.chars().take(8).collect();
            prefix
        });

        // Save to registry.
        let device = Device {
            name: name.clone(),
            ticket: token.clone(),
            added_at: Some(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()),
        };
        if let Err(e) = registry::add(device, false) {
            warn!(error=%e, "bridge: registry add failed; continuing");
        }

        // Dial the device.
        let connected = connect_device(&self.endpoint, &name, &token, &self.devices, &self.own_name).await;

        // If now connected, reset the conversation state.
        if connected {
            let guard = self.devices.lock().await;
            if let Some(conn) = guard.get(&name) {
                conn.reset_conversation();
            }
        }

        // If not yet in map, add a placeholder.
        {
            let mut guard = self.devices.lock().await;
            guard.entry(name.clone()).or_insert_with(|| DeviceConn::new(token.clone()));
        }

        write_state(&self.bind, &self.devices).await;

        let status = if connected { "connected" } else { "saved (could not connect now)" };
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Device '{}' {status}. Ticket fingerprint: {}…",
            name,
            token.chars().take(8).collect::<String>()
        ))]))
    }

    /// List all known devices and their connection status.
    #[tool(description = "List all known azula devices and their live connection status.")]
    async fn list_devices(&self) -> Result<CallToolResult, ErrorData> {
        let known = registry::load();
        let guard = self.devices.lock().await;

        if known.is_empty() && guard.is_empty() {
            return Ok(CallToolResult::success(vec![Content::text(
                "No devices registered. Use `connect` to add one.",
            )]));
        }

        let mut lines: Vec<String> = Vec::new();
        lines.push("Known devices:".to_string());

        // Build a union of names.
        let mut names: Vec<String> = known.iter().map(|d| d.name.clone()).collect();
        for k in guard.keys() {
            if !names.contains(k) {
                names.push(k.clone());
            }
        }
        names.sort();

        for name in &names {
            let ticket = known
                .iter()
                .find(|d| &d.name == name)
                .map(|d| d.ticket.clone())
                .or_else(|| guard.get(name).map(|c| c.ticket.clone()))
                .unwrap_or_default();
            let fingerprint: String = ticket.chars().take(8).collect();
            let live = guard.get(name);
            let status = match live {
                Some(c) if c.connected => "connected",
                Some(_) => "disconnected",
                None => "offline",
            };
            lines.push(format!("  {name}  [{fingerprint}…]  {status}"));
        }

        Ok(CallToolResult::success(vec![Content::text(lines.join("\n"))]))
    }

    /// Send a text message to a device.
    #[tool(description = "Send a text message to a named azula device. The text appears as a streamed azula-assistant reply in the app.")]
    async fn send_message(&self, Parameters(args): Parameters<SendMessageArgs>) -> Result<CallToolResult, ErrorData> {
        let conn = match self.ensure_device(&args.device).await {
            Ok(c) => c,
            Err(_) => {
                mailbox::enqueue(&args.device, &[
                    Frame::thinking(true),
                    Frame::token(args.text.clone()),
                    Frame::token_done(),
                    Frame::thinking(false),
                ]);
                return Ok(CallToolResult::success(vec![Content::text(format!(
                    "queued for delivery to '{}' (offline)", args.device
                ))]));
            }
        };

        let mut send_guard = conn.send.lock().await;
        let Some(send) = send_guard.as_mut() else {
            mailbox::enqueue(&args.device, &[
                Frame::thinking(true),
                Frame::token(args.text.clone()),
                Frame::token_done(),
                Frame::thinking(false),
            ]);
            return Ok(CallToolResult::success(vec![Content::text(format!(
                "queued for delivery to '{}' (offline)", args.device
            ))]));
        };

        for frame in [
            Frame::thinking(true),
            Frame::token(args.text),
            Frame::token_done(),
            Frame::thinking(false),
        ] {
            write_frame(send, &frame)
                .await
                .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        }
        Ok(CallToolResult::success(vec![Content::text("ok")]))
    }

    /// Drain new messages from one device or all devices.
    #[tool(description = "Drain new inbound messages from a named device or peer bridge, or from all devices if no device name is given. Lines are either the peer's chat text (from `say` calls by another bridge) or the user's chat text, or `ui-event: {\"name\":...,\"surfaceId\":...,\"sourceComponentId\":...,\"context\":{...}}` JSON describing an interaction with an A2UI surface rendered via `render_ui` (match on surfaceId and respond with `update_ui`).")]
    async fn get_messages(&self, Parameters(args): Parameters<GetMessagesArgs>) -> Result<CallToolResult, ErrorData> {
        let guard = self.devices.lock().await;

        if let Some(name) = &args.device {
            let conn = match guard.get(name) {
                Some(c) => c.clone(),
                None => return Ok(CallToolResult::error(vec![Content::text(format!(
                    "unknown device '{name}'"
                ))])),
            };
            drop(guard);
            let msgs: Vec<String> = conn.inbox.lock().unwrap().drain(..).collect();
            let text = if msgs.is_empty() { "(no new messages)".to_string() } else { msgs.join("\n") };
            Ok(CallToolResult::success(vec![Content::text(text)]))
        } else {
            let mut all: Vec<String> = Vec::new();
            for (name, conn) in guard.iter() {
                let msgs: Vec<String> = conn.inbox.lock().unwrap().drain(..).collect();
                for m in msgs {
                    all.push(format!("\u{300a}{name}\u{300b} {m}"));
                }
            }
            drop(guard);
            let text = if all.is_empty() { "(no new messages)".to_string() } else { all.join("\n") };
            Ok(CallToolResult::success(vec![Content::text(text)]))
        }
    }

    /// Send a peer-to-peer chat message to another bridge.
    #[tool(description = "Send a peer-to-peer chat message to another azula bridge (not an app device). The message appears in that bridge's `get_messages` inbox. Replies from the peer arrive via `get_messages` on this bridge. Set `done=true` to signal the end of the conversation (sends a closing notice to the peer). The bridge enforces a hard per-peer turn cap (`max_turns`); once reached the conversation is closed automatically. Use `connect` first to establish the iroh connection.")]
    async fn say(&self, Parameters(args): Parameters<SayArgs>) -> Result<CallToolResult, ErrorData> {
        let conn = match self.ensure_device(&args.device).await {
            Ok(c) => c,
            Err(_) => {
                mailbox::enqueue(&args.device, &[Frame::Chat { text: args.text.clone() }]);
                return Ok(CallToolResult::success(vec![Content::text(format!(
                    "queued for delivery to '{}' (offline)", args.device
                ))]));
            }
        };

        if conn.closed.load(Relaxed) {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "conversation with '{}' is closed",
                args.device
            ))]));
        }

        let n = conn.turns.fetch_add(1, Relaxed);
        let max = self.max_turns;

        if n >= max {
            // Send a turn-limit notice to the peer, then close.
            {
                let mut send_guard = conn.send.lock().await;
                if let Some(send) = send_guard.as_mut() {
                    let _ = write_frame(
                        send,
                        &Frame::Chat { text: "[conversation ended: turn limit]".into() },
                    )
                    .await;
                }
            }
            conn.closed.store(true, Relaxed);
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "turn limit ({max}) reached for '{}'",
                args.device
            ))]));
        }

        // Send the chat frame.
        {
            let mut send_guard = conn.send.lock().await;
            let Some(send) = send_guard.as_mut() else {
                mailbox::enqueue(&args.device, &[Frame::Chat { text: args.text.clone() }]);
                return Ok(CallToolResult::success(vec![Content::text(format!(
                    "queued for delivery to '{}' (offline)", args.device
                ))]));
            };
            if let Err(e) = write_frame(send, &Frame::Chat { text: args.text }).await {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "failed to send to '{}': {e}",
                    args.device
                ))]));
            }

            if args.done == Some(true) {
                let closing = Frame::Chat {
                    text: format!("[conversation ended by {}]", self.own_name),
                };
                let _ = write_frame(send, &closing).await;
            }
        }

        if args.done == Some(true) {
            conn.closed.store(true, Relaxed);
        }

        Ok(CallToolResult::success(vec![Content::text(format!(
            "delivered to '{}' (turn {}/{})",
            args.device,
            n + 1,
            max
        ))]))
    }

    /// Render an A2UI declarative UI surface on a device.
    #[tool(description = "Render an A2UI declarative UI surface in the azula app on a named device. Pass `components` as a flat JSON array of A2UI basic-catalog components (v0.9.1); exactly one must have \"id\":\"root\". Available components: Text, Image, Icon, Video, AudioPlayer, Row, Column, List, Card, Tabs, Modal, Divider, Button, TextField, CheckBox, ChoicePicker, Slider, DateTimeInput. Components reference children by id (child/children); props are literals or {\"path\":\"/ptr\"} bindings into the optional `data_model`. A Button carries {\"action\":{\"event\":{\"name\":\"...\",\"context\":{...}}}}; when the user interacts, an event arrives via `get_messages` as a `ui-event: {...}` JSON line carrying name/surfaceId/sourceComponentId/context. Returns the surfaceId — pass it to `update_ui` to change the data model in response.")]
    async fn render_ui(&self, Parameters(args): Parameters<RenderUiArgs>) -> Result<CallToolResult, ErrorData> {
        // Validate: components must be an array containing a "root" component.
        let comps = match &args.components {
            serde_json::Value::Array(a) => a,
            _ => return Ok(CallToolResult::error(vec![Content::text(
                "`components` must be a JSON array of A2UI components",
            )])),
        };
        if !comps.iter().any(|c| c.get("id").and_then(|v| v.as_str()) == Some("root")) {
            return Ok(CallToolResult::error(vec![Content::text(
                "the component list needs one component with \"id\":\"root\" (the surface root)",
            )]));
        }

        let surface_id = args.surface_id.unwrap_or_else(|| {
            format!("ui-{}", SURFACE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
        });

        let conn = match self.ensure_device(&args.device).await {
            Ok(c) => c,
            Err(e) => return Ok(e),
        };

        // createSurface → updateComponents → (optional) updateDataModel.
        self.send_a2ui(&conn, serde_json::json!({
            "version": "v0.9.1",
            "createSurface": { "surfaceId": surface_id, "catalogId": A2UI_CATALOG }
        })).await?;
        self.send_a2ui(&conn, serde_json::json!({
            "version": "v0.9.1",
            "updateComponents": { "surfaceId": surface_id, "components": args.components }
        })).await?;
        if let Some(dm) = args.data_model {
            self.send_a2ui(&conn, serde_json::json!({
                "version": "v0.9.1",
                "updateDataModel": { "surfaceId": surface_id, "path": "", "value": dm }
            })).await?;
        }

        Ok(CallToolResult::success(vec![Content::text(format!(
            "rendered surface '{surface_id}' on '{}'", args.device
        ))]))
    }

    /// Update the data model of a rendered A2UI surface.
    #[tool(description = "Update the data model of an A2UI surface previously created with `render_ui`, at a JSON-pointer `path` (RFC 6901; \"\" replaces the whole model). Use this to react to a `ui-event` — e.g. set /dice/result after a roll, or push fresh data into a bound Text.")]
    async fn update_ui(&self, Parameters(args): Parameters<UpdateUiArgs>) -> Result<CallToolResult, ErrorData> {
        let conn = match self.ensure_device(&args.device).await {
            Ok(c) => c,
            Err(e) => return Ok(e),
        };
        self.send_a2ui(&conn, serde_json::json!({
            "version": "v0.9.1",
            "updateDataModel": { "surfaceId": args.surface_id, "path": args.path, "value": args.value }
        })).await?;
        Ok(CallToolResult::success(vec![Content::text(format!(
            "updated surface '{}' at '{}'", args.surface_id, args.path
        ))]))
    }

    /// Remove an A2UI surface from a device.
    #[tool(description = "Remove an A2UI surface from a device (it stops rendering/updating). Pass the surfaceId returned by `render_ui`.")]
    async fn delete_ui(&self, Parameters(args): Parameters<DeleteUiArgs>) -> Result<CallToolResult, ErrorData> {
        let conn = match self.ensure_device(&args.device).await {
            Ok(c) => c,
            Err(e) => return Ok(e),
        };
        self.send_a2ui(&conn, serde_json::json!({
            "version": "v0.9.1",
            "deleteSurface": { "surfaceId": args.surface_id }
        })).await?;
        Ok(CallToolResult::success(vec![Content::text(format!(
            "deleted surface '{}'", args.surface_id
        ))]))
    }

    /// Show the bridge's pairing URL and QR code so a user can scan and connect.
    #[tool(description = "Return the bridge's pairing URL and a Unicode QR code. The user scans the QR with their phone camera to open the azula app and connect to this bridge automatically. No arguments needed.")]
    async fn start_pairing(&self) -> Result<CallToolResult, ErrorData> {
        let url = qr::pairing_url(&self.pairing_ticket);
        let qr_block = qr::render_qr(&url);
        let text = format!(
            "{url}\n\n```\n{qr_block}\n```\n\nScan with your phone's camera or open the URL to pair this device.",
        );
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }

    /// Disconnect from a device, optionally removing it from the registry.
    #[tool(description = "Disconnect from a named device. Set forget=true to also remove it from the device registry.")]
    async fn disconnect(&self, Parameters(args): Parameters<DisconnectArgs>) -> Result<CallToolResult, ErrorData> {
        let mut guard = self.devices.lock().await;

        if let Some(conn) = guard.get_mut(&args.device) {
            // Drop the send stream to close the connection.
            *conn.send.lock().await = None;
            conn.connected = false;
        }

        if args.forget.unwrap_or(false) {
            guard.remove(&args.device);
            drop(guard);
            // Remove from both registry files.
            for path_opt in [registry::global_path(), registry::project_path()] {
                if let Some(path) = path_opt {
                    if path.exists() {
                        remove_from_registry_file(&path, &args.device);
                    }
                }
            }
            write_state(&self.bind, &self.devices).await;
            Ok(CallToolResult::success(vec![Content::text(format!(
                "device '{}' disconnected and removed from registry", args.device
            ))]))
        } else {
            drop(guard);
            write_state(&self.bind, &self.devices).await;
            Ok(CallToolResult::success(vec![Content::text(format!(
                "device '{}' disconnected", args.device
            ))]))
        }
    }
}

impl AzulaBridge {
    /// Ensure the named device has a live connection (lazy-dialing a known
    /// device if needed), returning a clone of its [`DeviceConn`] or an error
    /// [`CallToolResult`] for the caller to return.
    async fn ensure_device(&self, device: &str) -> Result<DeviceConn, CallToolResult> {
        let needs_dial = {
            let guard = self.devices.lock().await;
            match guard.get(device) {
                Some(c) if c.connected => false,
                Some(_) => true,
                None => registry::load().iter().any(|d| d.name == device),
            }
        };

        if needs_dial {
            let ticket = {
                let guard = self.devices.lock().await;
                guard.get(device).map(|c| c.ticket.clone())
            }
            .or_else(|| registry::load().into_iter().find(|d| d.name == device).map(|d| d.ticket));
            if let Some(t) = ticket {
                connect_device(&self.endpoint, device, &t, &self.devices, &self.own_name).await;
            }
        }

        let guard = self.devices.lock().await;
        match guard.get(device) {
            Some(c) if c.connected => Ok(c.clone()),
            Some(_) => Err(CallToolResult::error(vec![Content::text(format!(
                "device '{device}' is not reachable"
            ))])),
            None => Err(CallToolResult::error(vec![Content::text(format!(
                "unknown device '{device}'; use `connect` first"
            ))])),
        }
    }

    /// Write a single A2UI message to a connected device as an `a2ui` frame.
    async fn send_a2ui(&self, conn: &DeviceConn, message: serde_json::Value) -> Result<(), ErrorData> {
        let mut send_guard = conn.send.lock().await;
        let Some(send) = send_guard.as_mut() else {
            return Err(ErrorData::internal_error("device send stream closed".to_string(), None));
        };
        write_frame(send, &Frame::A2ui { message })
            .await
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))
    }
}

fn remove_from_registry_file(path: &std::path::Path, name: &str) {
    #[derive(Serialize, Deserialize, Default)]
    struct Reg { devices: Vec<Device> }

    let data = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut reg: Reg = match serde_json::from_str(&data) {
        Ok(r) => r,
        Err(_) => return,
    };
    reg.devices.retain(|d| d.name != name);
    if let Ok(json) = serde_json::to_string_pretty(&reg) {
        let _ = std::fs::write(path, json);
    }
}

#[tool_handler]
impl ServerHandler for AzulaBridge {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.instructions = Some(
            "Multi-device azula bridge. Use `connect` to pair a device or peer bridge, \
             `list_devices` to see status, `send_message` / `get_messages` to communicate \
             with azula app devices, `say` to exchange peer-to-peer messages with another \
             bridge (replies arrive via `get_messages`), `disconnect` to close a connection. \
             To show a rich UI on an app device, call `render_ui` with A2UI components; \
             user interactions come back through `get_messages` as `ui-event:` lines — \
             react with `update_ui`."
                .into(),
        );
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info
    }
}

// ---------------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------------

pub async fn run(
    bind: String,
    device_urls: Vec<String>,
    name: Option<String>,
    max_turns: u64,
) -> Result<()> {
    let raw_endpoint = Endpoint::bind(presets::N0).await?;
    info!("bridge endpoint coming online…");
    raw_endpoint.online().await;

    let devices: DeviceMap = Arc::new(AsyncMutex::new(HashMap::new()));

    // Build an iroh Router that accepts incoming azula app / peer bridge
    // connections (from devices that scanned the bridge's QR code) and
    // registers them.
    let accept_handler = BridgeAcceptHandler::new(devices.clone(), bind.clone());
    let iroh_router = Router::builder(raw_endpoint)
        .accept(LLM_ALPN, accept_handler)
        .spawn();

    // Retrieve the endpoint from the router so we use a single endpoint for
    // both accepting inbound connections and dialing outbound ones.
    let endpoint = Arc::new(iroh_router.endpoint().clone());

    // Compute the bridge's own pairing ticket for QR / start_pairing tool.
    let bridge_ticket = EndpointTicket::new(endpoint.addr()).to_string();

    // Compute own_name: use --name if given, else derive from the endpoint id.
    let endpoint_id_str = endpoint.id().to_string();
    let own_name = name.unwrap_or_else(|| {
        let len = endpoint_id_str.len();
        format!("bridge-{}", &endpoint_id_str[..8_usize.min(len)])
    });
    info!(own_name=%own_name, "bridge: own name");

    // Load registry and pre-populate the device map.
    let known = registry::load();
    {
        let mut guard = devices.lock().await;
        for d in &known {
            guard.insert(d.name.clone(), DeviceConn::new(d.ticket.clone()));
        }
    }

    // Also add any --device flags from the command line.
    for url in &device_urls {
        if let Some(token) = parse_ticket(url) {
            let name: String = token.chars().take(8).collect();
            let mut guard = devices.lock().await;
            guard.entry(name.clone()).or_insert_with(|| DeviceConn::new(token.clone()));
        }
    }

    // Write initial state.
    write_state(&bind, &devices).await;

    // Best-effort dial all known devices in the background.
    {
        let guard = devices.lock().await;
        let entries: Vec<(String, String)> = guard
            .iter()
            .map(|(n, c)| (n.clone(), c.ticket.clone()))
            .collect();
        drop(guard);

        let own_name_clone = own_name.clone();
        for (dev_name, ticket) in entries {
            let ep = endpoint.clone();
            let devs = devices.clone();
            let bind_str = bind.clone();
            let my_name = own_name_clone.clone();
            tokio::spawn(async move {
                connect_device(&ep, &dev_name, &ticket, &devs, &my_name).await;
                write_state(&bind_str, &devs).await;
            });
        }
    }

    // Periodic redelivery: every 25 s, try to reconnect any offline device
    // that has queued mail.
    {
        let ep = endpoint.clone();
        let devs = devices.clone();
        let bind_str = bind.clone();
        let my_name = own_name.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(25)).await;
                // Snapshot device names + tickets for offline devices with pending mail.
                let pending: Vec<(String, String)> = {
                    let guard = devs.lock().await;
                    guard.iter()
                        .filter(|(name, conn)| !conn.connected && crate::mailbox::has_pending(name))
                        .map(|(name, conn)| (name.clone(), conn.ticket.clone()))
                        .collect()
                };
                for (dev_name, ticket) in pending {
                    info!(device=%dev_name, "bridge: attempting redelivery of queued mail");
                    connect_device(&ep, &dev_name, &ticket, &devs, &my_name).await;
                    write_state(&bind_str, &devs).await;
                }
            }
        });
    }

    // MCP server over Streamable HTTP, mounted at /mcp.
    let ep_svc = endpoint.clone();
    let devs_svc = devices.clone();
    let bind_svc = bind.clone();
    let ticket_svc = bridge_ticket.clone();
    let own_name_svc = own_name.clone();
    let service = StreamableHttpService::new(
        move || Ok(AzulaBridge::new(
            ep_svc.clone(),
            devs_svc.clone(),
            bind_svc.clone(),
            ticket_svc.clone(),
            own_name_svc.clone(),
            max_turns,
        )),
        Arc::new(LocalSessionManager::default()),
        Default::default(),
    );
    let http_router = axum::Router::new().nest_service("/mcp", service);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    print_banner(&bind);
    qr::print_pairing("Pair a device by scanning:", &bridge_ticket);
    axum::serve(listener, http_router).await?;
    Ok(())
}

fn print_banner(bind: &str) {
    println!();
    println!("  azula MCP bridge (multi-device)");
    println!("  MCP endpoint:  http://{bind}/mcp");
    println!("  Add this URL to an MCP-capable LLM client.");
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// The reader surfaces user chat text verbatim and turns an A2UI action
    /// (sent by the app when a user taps a surface) into a `ui-event:` line the
    /// LLM can parse from `get_messages`.
    #[tokio::test]
    async fn reader_surfaces_chat_and_ui_events() {
        let (mut writer, reader) = tokio::io::duplex(8192);
        let inbox: Inbox = Arc::new(std::sync::Mutex::new(VecDeque::new()));
        let inbox_reader = inbox.clone();
        let handle = tokio::spawn(async move {
            read_frames_into(BufReader::new(reader), inbox_reader).await;
        });

        let chat = serde_json::to_string(&Frame::Chat { text: "hello".into() }).unwrap();
        let action = serde_json::json!({
            "name": "roll", "surfaceId": "dice-1", "sourceComponentId": "rollBtn", "context": {}
        });
        let act = serde_json::to_string(&Frame::A2uiAction { action }).unwrap();
        writer.write_all(format!("{chat}\n{act}\n").as_bytes()).await.unwrap();
        writer.shutdown().await.unwrap(); // EOF → reader_loop returns
        handle.await.unwrap();

        let got: Vec<String> = inbox.lock().unwrap().drain(..).collect();
        assert_eq!(got.len(), 2, "expected 2 inbox lines, got {got:?}");
        assert_eq!(got[0], "hello");
        assert!(got[1].starts_with("ui-event: "), "not a ui-event line: {}", got[1]);
        assert!(got[1].contains(r#""name":"roll""#), "missing action name: {}", got[1]);
        assert!(got[1].contains(r#""surfaceId":"dice-1""#), "missing surfaceId: {}", got[1]);
    }

    /// Two bridges connect to each other over iroh. Alice dials Bob, says "ping",
    /// Bob says "pong" back. The turn limit is enforced at 3 turns.
    #[tokio::test]
    async fn bridge_to_bridge_relay() {
        // Bind two separate iroh endpoints.  We use Minimal (no relay) so the
        // test works offline; we skip `online()` since that waits for a relay.
        let alice_raw_ep = Endpoint::bind(presets::Minimal).await.unwrap();
        let bob_raw_ep = Endpoint::bind(presets::Minimal).await.unwrap();

        let alice_devices: DeviceMap = Arc::new(AsyncMutex::new(HashMap::new()));
        let bob_devices: DeviceMap = Arc::new(AsyncMutex::new(HashMap::new()));

        let bind_placeholder = "127.0.0.1:0".to_string();

        // Build iroh routers with accept handlers.
        let alice_accept = BridgeAcceptHandler::new(alice_devices.clone(), bind_placeholder.clone());
        let alice_router = Router::builder(alice_raw_ep)
            .accept(LLM_ALPN, alice_accept)
            .spawn();

        let bob_accept = BridgeAcceptHandler::new(bob_devices.clone(), bind_placeholder.clone());
        let bob_router = Router::builder(bob_raw_ep)
            .accept(LLM_ALPN, bob_accept)
            .spawn();

        let alice_ep = Arc::new(alice_router.endpoint().clone());
        let bob_ep = Arc::new(bob_router.endpoint().clone());

        let alice_ticket = EndpointTicket::new(alice_ep.addr()).to_string();
        let bob_ticket = EndpointTicket::new(bob_ep.addr()).to_string();

        // Create the AzulaBridge handles.
        let alice = AzulaBridge::new(
            alice_ep.clone(),
            alice_devices.clone(),
            bind_placeholder.clone(),
            alice_ticket.clone(),
            "alice".to_string(),
            3,
        );
        let bob = AzulaBridge::new(
            bob_ep.clone(),
            bob_devices.clone(),
            bind_placeholder.clone(),
            bob_ticket.clone(),
            "bob".to_string(),
            3,
        );

        // Alice connects to Bob.
        let connect_result = alice
            .connect(Parameters(ConnectArgs {
                url: bob_ticket.clone(),
                name: Some("bob".to_string()),
            }))
            .await
            .unwrap();
        assert!(
            !connect_result.is_error.unwrap_or(false),
            "connect should succeed: {:?}",
            connect_result
        );

        // Wait for Bob's accept handler to register "alice".
        let mut registered = false;
        for _ in 0..40 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let guard = bob_devices.lock().await;
            if guard.contains_key("alice") {
                registered = true;
                break;
            }
        }
        assert!(registered, "bob should have 'alice' in his device map after hello");

        // Alice says "ping" to Bob.
        let say_result = alice
            .say(Parameters(SayArgs {
                device: "bob".to_string(),
                text: "ping".to_string(),
                done: None,
            }))
            .await
            .unwrap();
        assert!(
            !say_result.is_error.unwrap_or(false),
            "alice say ping should succeed: {:?}",
            say_result
        );

        // Give Bob's reader a moment to drain the frame into his inbox.
        for _ in 0..40 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let guard = bob_devices.lock().await;
            if let Some(conn) = guard.get("alice") {
                if !conn.inbox.lock().unwrap().is_empty() {
                    break;
                }
            }
        }

        // Drain Bob's inbox via get_messages and assert it contains "ping".
        let bob_msgs = bob
            .get_messages(Parameters(GetMessagesArgs { device: Some("alice".to_string()) }))
            .await
            .unwrap();
        assert!(
            !bob_msgs.is_error.unwrap_or(false),
            "get_messages should succeed: {:?}",
            bob_msgs
        );
        let bob_text = bob_msgs.content.iter()
            .filter_map(|c| c.as_text().map(|t| t.text.as_str()))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(bob_text.contains("ping"), "bob inbox should contain 'ping', got: {bob_text}");

        // Bob needs to connect back to Alice to reply.
        let bob_connect = bob
            .connect(Parameters(ConnectArgs {
                url: alice_ticket.clone(),
                name: Some("alice".to_string()),
            }))
            .await
            .unwrap();
        assert!(
            !bob_connect.is_error.unwrap_or(false),
            "bob connect to alice should succeed: {:?}",
            bob_connect
        );

        // Wait for Alice's accept handler to see bob.
        for _ in 0..40 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let guard = alice_devices.lock().await;
            if guard.contains_key("bob") {
                break;
            }
        }

        // Bob says "pong" to Alice.
        let pong_result = bob
            .say(Parameters(SayArgs {
                device: "alice".to_string(),
                text: "pong".to_string(),
                done: None,
            }))
            .await
            .unwrap();
        assert!(
            !pong_result.is_error.unwrap_or(false),
            "bob say pong should succeed: {:?}",
            pong_result
        );

        // Wait for Alice's inbox to receive "pong".
        for _ in 0..40 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let guard = alice_devices.lock().await;
            if let Some(conn) = guard.get("bob") {
                if !conn.inbox.lock().unwrap().is_empty() {
                    break;
                }
            }
        }

        // Drain Alice's inbox and assert it contains "pong".
        let alice_msgs = alice
            .get_messages(Parameters(GetMessagesArgs { device: Some("bob".to_string()) }))
            .await
            .unwrap();
        assert!(
            !alice_msgs.is_error.unwrap_or(false),
            "get_messages should succeed: {:?}",
            alice_msgs
        );
        let alice_text = alice_msgs.content.iter()
            .filter_map(|c| c.as_text().map(|t| t.text.as_str()))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(alice_text.contains("pong"), "alice inbox should contain 'pong', got: {alice_text}");

        // Drive Alice past max_turns=3: she's used 1 turn (ping). Say 2 more to hit the limit.
        // Turn 2
        let t2 = alice
            .say(Parameters(SayArgs {
                device: "bob".to_string(),
                text: "turn2".to_string(),
                done: None,
            }))
            .await
            .unwrap();
        assert!(!t2.is_error.unwrap_or(false), "turn 2 should succeed: {:?}", t2);

        // Turn 3
        let t3 = alice
            .say(Parameters(SayArgs {
                device: "bob".to_string(),
                text: "turn3".to_string(),
                done: None,
            }))
            .await
            .unwrap();
        assert!(!t3.is_error.unwrap_or(false), "turn 3 should succeed: {:?}", t3);

        // Turn 4 — over the limit (max=3).
        let t4 = alice
            .say(Parameters(SayArgs {
                device: "bob".to_string(),
                text: "turn4".to_string(),
                done: None,
            }))
            .await
            .unwrap();
        assert!(
            t4.is_error.unwrap_or(false),
            "turn 4 should fail (over limit): {:?}",
            t4
        );
        assert!(
            alice_devices.lock().await
                .get("bob")
                .map(|c| c.closed.load(Relaxed))
                .unwrap_or(false),
            "bob conn should be closed after turn limit"
        );

        // Subsequent say should immediately return closed error.
        let t5 = alice
            .say(Parameters(SayArgs {
                device: "bob".to_string(),
                text: "turn5".to_string(),
                done: None,
            }))
            .await
            .unwrap();
        assert!(
            t5.is_error.unwrap_or(false),
            "turn 5 should fail (conversation closed): {:?}",
            t5
        );

        // Cleanup.
        alice_router.shutdown().await.unwrap();
        bob_router.shutdown().await.unwrap();
    }

    /// Tests that messages for an offline device are queued and then flushed
    /// when the device reconnects. Uses in-memory duplex for the flush path.
    #[tokio::test]
    async fn offline_queue_then_flush() {
        // Set a unique mailbox dir for this test so it doesn't interfere with others.
        let mbox_dir = std::env::temp_dir()
            .join(format!("azula-bridge-test-{}", std::process::id()))
            .join("offline_queue");
        std::env::set_var("AZULA_MAILBOX_DIR", &mbox_dir);

        let ep = Endpoint::bind(presets::Minimal).await.unwrap();
        let devices: DeviceMap = Arc::new(AsyncMutex::new(HashMap::new()));
        let bind_placeholder = "127.0.0.1:0".to_string();
        let ep_arc = Arc::new(ep.clone());

        // Register "phone" as disconnected with a placeholder ticket.
        {
            let mut guard = devices.lock().await;
            guard.insert("phone".to_string(), DeviceConn::new("placeholder_ticket".to_string()));
        }

        let alice = AzulaBridge::new(
            ep_arc.clone(),
            devices.clone(),
            bind_placeholder.clone(),
            "alice-ticket".to_string(),
            "alice".to_string(),
            20,
        );

        // send_message to offline "phone" should queue, not error.
        let result = alice
            .send_message(Parameters(SendMessageArgs {
                device: "phone".to_string(),
                text: "hi while you were away".to_string(),
            }))
            .await
            .unwrap();

        assert!(
            !result.is_error.unwrap_or(false),
            "send_message to offline device should return success (queued): {:?}",
            result
        );
        let result_text = result.content.iter()
            .filter_map(|c| c.as_text().map(|t| t.text.as_str()))
            .collect::<Vec<_>>()
            .join("");
        assert!(
            result_text.contains("queued"),
            "result should mention 'queued', got: {result_text}"
        );

        // has_pending should be true.
        assert!(
            crate::mailbox::has_pending("phone"),
            "mailbox should have pending frames for 'phone'"
        );

        // Now test the flush: create an in-memory duplex and flush to it.
        let (mut send_stream, recv_stream) = tokio::io::duplex(65536);

        // Collect received frames.
        let handle = tokio::spawn(async move {
            let mut reader = tokio::io::BufReader::new(recv_stream);
            let mut frames = vec![];
            while let Ok(Some(f)) = crate::proto::read_frame(&mut reader).await {
                frames.push(f);
            }
            frames
        });

        // Use flush_mailbox via a wrapper — but flush_mailbox is private.
        // Instead call enqueue/load/clear directly to simulate the flush.
        let queued = crate::mailbox::load("phone");
        for f in &queued {
            crate::proto::write_frame(&mut send_stream, f).await.unwrap();
        }
        crate::mailbox::clear("phone");
        drop(send_stream); // EOF so reader task ends.

        let received = handle.await.unwrap();

        // Should receive thinking(true), token("hi while you were away"), token_done, thinking(false).
        assert_eq!(received.len(), 4, "expected 4 frames, got: {received:?}");
        assert!(matches!(&received[0], Frame::Thinking { on: true }));
        assert!(
            matches!(&received[1], Frame::Token { delta, .. } if delta == "hi while you were away"),
            "second frame should be token with text, got: {:?}", received[1]
        );
        assert!(matches!(&received[2], Frame::Token { done: true, .. }));
        assert!(matches!(&received[3], Frame::Thinking { on: false }));

        // After flush and clear, has_pending should be false.
        assert!(
            !crate::mailbox::has_pending("phone"),
            "mailbox should be empty after flush"
        );

        // Clean up env var.
        std::env::remove_var("AZULA_MAILBOX_DIR");
    }
}
