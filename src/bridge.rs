//! `serve-mcp` — multi-device MCP↔iroh bridge.
//!
//! Runs an MCP server over Streamable HTTP.  An external LLM client connects
//! and uses five tools to manage azula device sessions:
//!
//! - `connect`        — pair a new device by ticket/URL
//! - `list_devices`   — show known + live-connection status
//! - `send_message`   — send text to a device
//! - `get_messages`   — drain the inbox (one device or all)
//! - `disconnect`     — drop a live connection, optionally forget the device
//!
//! On startup the bridge loads the registry and dials every known device in the
//! background (failures are non-fatal).

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Arc;

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
}

impl DeviceConn {
    fn new(ticket: String) -> Self {
        DeviceConn {
            send: Arc::new(AsyncMutex::new(None)),
            inbox: Arc::new(std::sync::Mutex::new(VecDeque::new())),
            ticket,
            connected: false,
        }
    }
}

type DeviceMap = Arc<AsyncMutex<HashMap<String, DeviceConn>>>;

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
async fn connect_device(
    endpoint: &Endpoint,
    name: &str,
    ticket: &str,
    devices: &DeviceMap,
) -> bool {
    match dial_device(endpoint, ticket).await {
        Ok((mut send, recv)) => {
            if let Err(e) = write_frame(&mut send, &Frame::thinking(false)).await {
                warn!(device=%name, error=%e, "bridge: handshake write failed");
                return false;
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
    let mut reader = BufReader::new(recv);
    loop {
        match read_frame(&mut reader).await {
            Ok(Some(Frame::Chat { text })) => inbox.lock().unwrap().push_back(text),
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(e) => {
                warn!(error = %e, "bridge: app stream read error");
                break;
            }
        }
    }
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
    // Derive a stable name from the remote node id (first 8 hex chars) or
    // fall back to scan-<n> if the id string is somehow too short.
    let remote_id_str = connection.remote_id().to_string();
    let name = if remote_id_str.len() >= 8 {
        format!("scan-{}", &remote_id_str[..8])
    } else {
        let n = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("scan-{n}")
    };

    info!(%name, "bridge: incoming connection from scanned device");

    // Accepted connections use accept_bi (the app opens the bi stream).
    let (send, recv) = connection.accept_bi().await?;

    let inbox: Inbox = Arc::new(std::sync::Mutex::new(VecDeque::new()));
    let inbox_reader = inbox.clone();
    tokio::spawn(async move { reader_loop(recv, inbox_reader).await });

    let conn = DeviceConn {
        send: Arc::new(AsyncMutex::new(Some(send))),
        inbox,
        ticket: remote_id_str.clone(),
        connected: true,
    };

    {
        let mut guard = devices.lock().await;
        guard.insert(name.clone(), conn);
    }

    write_state(&bind, &devices).await;
    info!(%name, "bridge: scanned device registered");
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
struct DisconnectArgs {
    /// The device name.
    device: String,
    /// If true, also remove from the registry.
    forget: Option<bool>,
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
    #[allow(dead_code)]
    tool_router: ToolRouter<AzulaBridge>,
}

#[tool_router]
impl AzulaBridge {
    fn new(endpoint: Arc<Endpoint>, devices: DeviceMap, bind: String, pairing_ticket: String) -> Self {
        Self { endpoint, devices, bind, pairing_ticket, tool_router: Self::tool_router() }
    }

    /// Connect to a new azula device by ticket URL or bare token.
    #[tool(description = "Connect to a new azula device by ticket URL (https://azula.app/s/<token>, azula://connect?code=<token>) or bare token. Optionally provide a display name.")]
    async fn connect(&self, Parameters(args): Parameters<ConnectArgs>) -> Result<CallToolResult, ErrorData> {
        let token = match parse_ticket(&args.url) {
            Some(t) => t,
            None => return Ok(CallToolResult::error(vec![Content::text("invalid ticket or URL")])),
        };

        // Derive name if absent.
        let name = args.name.unwrap_or_else(|| {
            let prefix: String = token.chars().take(8).collect();
            // Make sure name is unique.
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
        let connected = connect_device(&self.endpoint, &name, &token, &self.devices).await;

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
        // Lazy-connect if known but not live.
        let needs_dial = {
            let guard = self.devices.lock().await;
            match guard.get(&args.device) {
                Some(c) if c.connected => false,
                Some(_) => true,
                None => {
                    // Check registry.
                    let known = registry::load();
                    known.iter().any(|d| d.name == args.device)
                }
            }
        };

        if needs_dial {
            let ticket = {
                let guard = self.devices.lock().await;
                guard.get(&args.device).map(|c| c.ticket.clone())
            }.or_else(|| {
                registry::load().into_iter().find(|d| d.name == args.device).map(|d| d.ticket)
            });

            if let Some(t) = ticket {
                connect_device(&self.endpoint, &args.device, &t, &self.devices).await;
            }
        }

        let guard = self.devices.lock().await;
        let conn = match guard.get(&args.device) {
            Some(c) if c.connected => c.clone(),
            Some(_) => return Ok(CallToolResult::error(vec![Content::text(format!(
                "device '{}' is not reachable", args.device
            ))])),
            None => return Ok(CallToolResult::error(vec![Content::text(format!(
                "unknown device '{}'; use `connect` first", args.device
            ))])),
        };
        drop(guard);

        let mut send_guard = conn.send.lock().await;
        let Some(send) = send_guard.as_mut() else {
            return Ok(CallToolResult::error(vec![Content::text("device send stream closed")]));
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
    #[tool(description = "Drain new messages from a named device, or from all devices if no device name is given.")]
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
            "Multi-device azula bridge. Use `connect` to pair a device, `list_devices` to see \
             status, `send_message` / `get_messages` to communicate, `disconnect` to close."
                .into(),
        );
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info
    }
}

// ---------------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------------

pub async fn run(bind: String, device_urls: Vec<String>) -> Result<()> {
    let raw_endpoint = Endpoint::bind(presets::N0).await?;
    info!("bridge endpoint coming online…");
    raw_endpoint.online().await;

    let devices: DeviceMap = Arc::new(AsyncMutex::new(HashMap::new()));

    // Build an iroh Router that accepts incoming azula app connections (from
    // devices that scanned the bridge's QR code) and registers them.
    let accept_handler = BridgeAcceptHandler::new(devices.clone(), bind.clone());
    let iroh_router = Router::builder(raw_endpoint)
        .accept(LLM_ALPN, accept_handler)
        .spawn();

    // Retrieve the endpoint from the router so we use a single endpoint for
    // both accepting inbound connections and dialing outbound ones.
    let endpoint = Arc::new(iroh_router.endpoint().clone());

    // Compute the bridge's own pairing ticket for QR / start_pairing tool.
    let bridge_ticket = EndpointTicket::new(endpoint.addr()).to_string();

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

        for (name, ticket) in entries {
            let ep = endpoint.clone();
            let devs = devices.clone();
            let bind_str = bind.clone();
            tokio::spawn(async move {
                connect_device(&ep, &name, &ticket, &devs).await;
                write_state(&bind_str, &devs).await;
            });
        }
    }

    // MCP server over Streamable HTTP, mounted at /mcp.
    let ep_svc = endpoint.clone();
    let devs_svc = devices.clone();
    let bind_svc = bind.clone();
    let ticket_svc = bridge_ticket.clone();
    let service = StreamableHttpService::new(
        move || Ok(AzulaBridge::new(ep_svc.clone(), devs_svc.clone(), bind_svc.clone(), ticket_svc.clone())),
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
