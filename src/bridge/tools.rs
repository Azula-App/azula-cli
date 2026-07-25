//! The `AzulaBridge` MCP tool surface — the 12 `#[tool]` methods an external
//! LLM client calls to manage azula device sessions and peer-bridge
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
//! Plus their argument types and the `ServerHandler` impl. [`super::setup_bridge`]
//! constructs the shared [`super::device::DeviceMap`] this reads and writes.

use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

use anyhow::Result;
use iroh::Endpoint;
use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, ServerCapabilities, ServerInfo};
use rmcp::schemars;
use rmcp::{tool, tool_handler, tool_router, ErrorData, ServerHandler};
use serde::Deserialize;
use tracing::warn;

use crate::filexfer;
use crate::invite;
use crate::link::{self, Parsed};
use crate::mailbox;
use crate::proto::{write_frame, Frame};
use crate::qr;
use crate::registry::{self, Device};

use super::device::{connect_device, DeviceConn, DeviceMap};
use super::state::write_state;

/// Monotonic counter for auto-generated A2UI surface ids (`ui-<time>-<n>`).
static SURFACE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// The A2UI basic catalog this bridge targets.
const A2UI_CATALOG: &str = "https://a2ui.org/specification/v0_9_1/catalogs/basic/catalog.json";

// ---------------------------------------------------------------------------
// MCP tool argument types
// ---------------------------------------------------------------------------

#[derive(Deserialize, schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct ConnectArgs {
    /// The device URL or ticket to connect to.
    pub(super) url: String,
    /// Optional display name for this device.
    pub(super) name: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct SendMessageArgs {
    /// The device name to send to.
    pub(super) device: String,
    /// The text to deliver.
    pub(super) text: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct GetMessagesArgs {
    /// If specified, drain only this device; otherwise drain all devices.
    pub(super) device: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct SendFileArgs {
    /// The device name to send to.
    pub(super) device: String,
    /// Path to the local file to send (a path on the machine running the
    /// bridge, not the phone). Mime type is inferred from the extension.
    pub(super) path: String,
    /// Optional caption shown alongside the attachment in the app.
    pub(super) caption: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct SayArgs {
    /// The peer bridge name to send to (as registered in the device map).
    pub(super) device: String,
    /// The message text to deliver to the peer.
    pub(super) text: String,
    /// If true, mark this conversation as done after sending (sends a closing notice to the peer).
    pub(super) done: Option<bool>,
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
    /// Optional surface id. A unique one (`ui-<time>-<n>`) is generated if omitted;
    /// omit it to add a NEW card, or pass an existing id to replace that card.
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

#[derive(Deserialize, schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
struct WaitForReplyArgs {
    /// The device name to wait on.
    device: String,
    /// How long to wait, in seconds, before giving up. Defaults to 120.
    timeout_s: Option<u64>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
struct SetNameArgs {
    /// The project + session topic, shown as the conversation's description under
    /// the name in the app — e.g. "azula / terminal refactor".
    description: Option<String>,
    /// Override the sender name shown in the app. Defaults to the bridge's name
    /// (usually "Claude"); normally leave this unset.
    name: Option<String>,
    /// The device to update. Omit to update every connected device.
    device: Option<String>,
}

// ---------------------------------------------------------------------------
// MCP server handler
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AzulaBridge {
    endpoint: Arc<Endpoint>,
    devices: DeviceMap,
    bind: String,
    /// The bridge's own iroh ticket (base32 string) — the dial target
    /// `start_pairing` wraps in a freshly minted invite (or, with
    /// `legacy_ticket`, returns directly).
    pairing_ticket: String,
    /// This bridge's display name (sent as `hello` to peer bridges).
    own_name: String,
    /// Hard turn cap per peer bridge conversation.
    max_turns: u64,
    /// `start_pairing` returns the raw ticket link instead of minting an
    /// invite (`--legacy-ticket`, mirrors the startup banner's escape hatch).
    legacy_ticket: bool,
    /// This session's own `azd…` certificate (design.md D1/D3), re-presented
    /// in every `Hello` frame `connect`/`ensure_device` send when dialing out.
    session_cert: String,
    /// The machine identity, if one exists on disk — `None` in a headless
    /// environment. `start_pairing` mints against this when present (see
    /// `super::mint_pairing_invite`); never created here.
    machine_secret: Option<iroh::SecretKey>,
    #[allow(dead_code)]
    tool_router: ToolRouter<AzulaBridge>,
}

#[tool_router]
impl AzulaBridge {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        endpoint: Arc<Endpoint>,
        devices: DeviceMap,
        bind: String,
        pairing_ticket: String,
        own_name: String,
        max_turns: u64,
        legacy_ticket: bool,
        session_cert: String,
        machine_secret: Option<iroh::SecretKey>,
    ) -> Self {
        Self {
            endpoint,
            devices,
            bind,
            pairing_ticket,
            own_name,
            max_turns,
            legacy_ticket,
            session_cert,
            machine_secret,
            tool_router: Self::tool_router(),
        }
    }

    /// Connect to a new azula device or peer bridge by ticket URL, invite link, or bare token.
    #[tool(description = "Connect to a new azula device or peer bridge by invite link (https://azula.app/i/<payload>, azula://i?c=<payload>, bare azi... payload) or legacy ticket URL (https://azula.app/s/<token>, azula://connect?code=<token>) or bare token. Optionally provide a display name. When connecting to another bridge, a hello frame is exchanged so the remote bridge can name this one; an invite is re-presented in that hello so the remote's accept gate can verify it.")]
    pub(super) async fn connect(&self, Parameters(args): Parameters<ConnectArgs>) -> Result<CallToolResult, ErrorData> {
        let (ticket, invite_str) = match link::parse(&args.url) {
            Some(Parsed::Invite(payload)) => {
                let decoded = match invite::InvitePayload::decode(&payload) {
                    Ok(d) => d,
                    Err(e) => return Ok(CallToolResult::error(vec![Content::text(format!("invalid invite: {e}"))])),
                };
                let ticket = match decoded.ticket() {
                    Ok(t) => t.to_string(),
                    Err(e) => return Ok(CallToolResult::error(vec![Content::text(format!("invalid invite ticket: {e}"))])),
                };
                (ticket, Some(payload))
            }
            Some(Parsed::Ticket(t)) => (t, None),
            None => return Ok(CallToolResult::error(vec![Content::text("invalid ticket or URL")])),
        };

        // Derive name if absent.
        let name = args.name.unwrap_or_else(|| {
            let prefix: String = ticket.chars().take(8).collect();
            prefix
        });

        // Save to registry.
        let device = Device {
            name: name.clone(),
            ticket: ticket.clone(),
            added_at: Some(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()),
            invite: invite_str.clone(),
        };
        if let Err(e) = registry::add(device, false) {
            warn!(error=%e, "bridge: registry add failed; continuing");
        }

        // Dial the device, presenting the invite (if any) and our session cert in the hello.
        let connected = connect_device(&self.endpoint, &name, &ticket, &self.devices, &self.own_name, invite_str.as_deref(), Some(&self.session_cert)).await;

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
            guard
                .entry(name.clone())
                .or_insert_with(|| DeviceConn::new(ticket.clone()).with_invite(invite_str.clone()));
        }

        write_state(&self.bind, &self.devices).await;

        let status = if connected { "connected" } else { "saved (could not connect now)" };
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Device '{}' {status}. Ticket fingerprint: {}…",
            name,
            ticket.chars().take(8).collect::<String>()
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
    pub(super) async fn send_message(&self, Parameters(args): Parameters<SendMessageArgs>) -> Result<CallToolResult, ErrorData> {
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

    /// Send a local file (e.g. an image) to a device as an inline attachment.
    #[tool(description = "Send a local file to a named azula device as an inline attachment — this is how to show the user an IMAGE (or share audio/video/PDF/text/any other file). `path` is a path on THIS machine (where the bridge runs), not the phone. Mime type is inferred from the file extension (png/jpg/jpeg/gif/webp/svg -> image/*, mp4/mov, mp3/wav/ogg, pdf, txt/md, else application/octet-stream). Files over 64 MiB are rejected. Optional `caption` is shown alongside the attachment in the app. Requires a live connection (like render_ui) — it is not queued for offline devices, since a large file would blow the mailbox's message cap.")]
    pub(super) async fn send_file(&self, Parameters(args): Parameters<SendFileArgs>) -> Result<CallToolResult, ErrorData> {
        let path = std::path::Path::new(&args.path);
        let bytes = match tokio::fs::read(path).await {
            Ok(b) => b,
            Err(e) => return Ok(CallToolResult::error(vec![Content::text(format!(
                "could not read '{}': {e}", args.path
            ))])),
        };

        if bytes.len() as u64 > filexfer::MAX_FILE_BYTES {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "'{}' is {} bytes, which exceeds the {} byte (64 MiB) limit",
                args.path,
                bytes.len(),
                filexfer::MAX_FILE_BYTES
            ))]));
        }

        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();
        let mime = filexfer::guess_mime(path);
        let size = bytes.len();

        let conn = match self.ensure_device(&args.device).await {
            Ok(c) => c,
            Err(e) => return Ok(e),
        };

        let id = uuid::Uuid::new_v4().to_string();
        let frames = match filexfer::build_file_frames(id, name.clone(), mime.clone(), args.caption.clone(), &bytes) {
            Ok(f) => f,
            Err(e) => return Ok(CallToolResult::error(vec![Content::text(e.to_string())])),
        };

        let mut send_guard = conn.send.lock().await;
        let Some(send) = send_guard.as_mut() else {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "device '{}' send stream closed", args.device
            ))]));
        };
        for frame in &frames {
            write_frame(send, frame)
                .await
                .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        }

        Ok(CallToolResult::success(vec![Content::text(format!(
            "sent '{name}' ({mime}, {size} bytes) to '{}'", args.device
        ))]))
    }

    /// Drain new messages from one device or all devices.
    #[tool(description = "Drain new inbound messages from a named device or peer bridge, or from all devices if no device name is given. Lines are either the peer's chat text (from `say` calls by another bridge) or the user's chat text, `ui-event: {\"name\":...,\"surfaceId\":...,\"sourceComponentId\":...,\"context\":{...}}` JSON describing an interaction with an A2UI surface rendered via `render_ui` (match on surfaceId and respond with `update_ui`), or `[received file: <name> (<mime>, <size> bytes) -> <path>]` when the user attaches a file/image (the path is on this machine, readable directly).")]
    pub(super) async fn get_messages(&self, Parameters(args): Parameters<GetMessagesArgs>) -> Result<CallToolResult, ErrorData> {
        let guard = self.devices.lock().await;

        if let Some(name) = &args.device {
            let conn = match guard.get(name) {
                Some(c) => c.clone(),
                None => return Ok(CallToolResult::error(vec![Content::text(format!(
                    "unknown device '{name}'"
                ))])),
            };
            drop(guard);
            let msgs: Vec<String> = conn.inbox.lock().unwrap_or_else(|e| e.into_inner()).drain(..).collect();
            let text = if msgs.is_empty() { "(no new messages)".to_string() } else { msgs.join("\n") };
            Ok(CallToolResult::success(vec![Content::text(text)]))
        } else {
            let mut all: Vec<String> = Vec::new();
            for (name, conn) in guard.iter() {
                let msgs: Vec<String> = conn.inbox.lock().unwrap_or_else(|e| e.into_inner()).drain(..).collect();
                for m in msgs {
                    all.push(format!("\u{300a}{name}\u{300b} {m}"));
                }
            }
            drop(guard);
            let text = if all.is_empty() { "(no new messages)".to_string() } else { all.join("\n") };
            Ok(CallToolResult::success(vec![Content::text(text)]))
        }
    }

    /// Long-poll: block until the device has new inbound activity, then drain it.
    #[tool(description = "Wait (long-poll) until a named device has new inbound activity — the user's chat reply, an A2UI `ui-event:` interaction with a surface from `render_ui`, or a received file/image (`[received file: ...]`) — then return it and drain the inbox. Blocks up to `timeout_s` seconds (default 120), returning \"(no reply within Ns)\" on timeout. Use this after `send_message` or `render_ui` to pause for the user's response; `get_messages` is the non-blocking drain.")]
    async fn wait_for_reply(&self, Parameters(args): Parameters<WaitForReplyArgs>) -> Result<CallToolResult, ErrorData> {
        let timeout_s = args.timeout_s.unwrap_or(120);
        // The DeviceConn's inbox is an Arc shared with the reader loop, so cloning
        // the conn once and polling its inbox sees frames as they arrive.
        let conn = {
            let guard = self.devices.lock().await;
            match guard.get(&args.device) {
                Some(c) => c.clone(),
                None => return Ok(CallToolResult::error(vec![Content::text(format!(
                    "unknown device '{}'", args.device
                ))])),
            }
        };
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(timeout_s);
        loop {
            let msgs: Vec<String> = conn.inbox.lock().unwrap_or_else(|e| e.into_inner()).drain(..).collect();
            if !msgs.is_empty() {
                return Ok(CallToolResult::success(vec![Content::text(msgs.join("\n"))]));
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(CallToolResult::success(vec![Content::text(format!(
                    "(no reply within {timeout_s}s)"
                ))]));
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        }
    }

    /// Set the conversation's name and/or description in the app.
    #[tool(description = "Set how this conversation is labelled in the azula app. Leave `name` unset so it stays the assistant name (\"Claude\"); put the project + session topic in `description` (e.g. \"azula / terminal refactor\"), which the app shows under the name in the conversation list and the chat header. Keep the same description for a session; set a fresh one for a new session. Applies to the given device, or every connected device if omitted.")]
    async fn set_name(&self, Parameters(args): Parameters<SetNameArgs>) -> Result<CallToolResult, ErrorData> {
        let targets: Vec<DeviceConn> = {
            let guard = self.devices.lock().await;
            match &args.device {
                Some(name) => match guard.get(name) {
                    Some(c) => vec![c.clone()],
                    None => return Ok(CallToolResult::error(vec![Content::text(format!("unknown device '{name}'"))])),
                },
                None => guard.values().cloned().collect(),
            }
        };
        let name = args.name.clone().unwrap_or_else(|| self.own_name.clone());
        let frame = Frame::Profile { name: name.clone(), description: args.description.clone(), avatar: None, mime: None };
        let mut sent = 0;
        for conn in &targets {
            let mut g = conn.send.lock().await;
            if let Some(send) = g.as_mut() {
                if write_frame(send, &frame).await.is_ok() {
                    sent += 1;
                }
            }
        }
        Ok(CallToolResult::success(vec![Content::text(format!(
            "set name=\"{name}\" description={:?} on {sent} device(s)", args.description
        ))]))
    }

    /// Send a peer-to-peer chat message to another bridge.
    #[tool(description = "Send a peer-to-peer chat message to another azula bridge (not an app device). The message appears in that bridge's `get_messages` inbox. Replies from the peer arrive via `get_messages` on this bridge. Set `done=true` to signal the end of the conversation (sends a closing notice to the peer). The bridge enforces a hard per-peer turn cap (`max_turns`); once reached the conversation is closed automatically. Use `connect` first to establish the iroh connection.")]
    pub(super) async fn say(&self, Parameters(args): Parameters<SayArgs>) -> Result<CallToolResult, ErrorData> {
        let conn = match self.ensure_device(&args.device).await {
            Ok(c) => c,
            Err(_) => {
                mailbox::enqueue(&args.device, &[Frame::Chat { text: args.text.clone(), id: None }]);
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
                        &Frame::Chat { text: "[conversation ended: turn limit]".into(), id: None },
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
                mailbox::enqueue(&args.device, &[Frame::Chat { text: args.text.clone(), id: None }]);
                return Ok(CallToolResult::success(vec![Content::text(format!(
                    "queued for delivery to '{}' (offline)", args.device
                ))]));
            };
            if let Err(e) = write_frame(send, &Frame::Chat { text: args.text, id: None }).await {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "failed to send to '{}': {e}",
                    args.device
                ))]));
            }

            if args.done == Some(true) {
                let closing = Frame::Chat {
                    text: format!("[conversation ended by {}]", self.own_name),
                    id: None,
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
    #[tool(description = r##"Render an interactive A2UI surface in the azula app on a device. Returns the surfaceId (pass it to update_ui / delete_ui).

STRUCTURE: `components` is a flat JSON array; each element is {"id":"...","component":"<Type>", ...props}. Exactly one must have "id":"root". Containers reference children by id — `child` (single id) or `children` (array of ids); never nest component objects. Optional `data_model` is a JSON object; any prop value may be a literal OR a binding {"path":"/rfc6901/pointer"} into the data model.

The app renders these in azula's "neon-glass" style (rounded, pink accent). Text is Markdown-rendered.

COMPONENTS (props):
- Text: text (string|binding; Markdown: ### headings, - bullets, **bold**, *italic*, `code`); variant: h1|h2|h3|h4|h5|h6|body(default)|caption(italic, dimmed).
- Row: children[]; justify: start|center|end|spaceBetween|spaceAround|spaceEvenly; align: start|center|end.
- Column: children[]; justify (vertical), align (horizontal).
- List: children[]; direction: vertical(default)|horizontal(scrolls); align.
- Card: child; variant: (default, filled surface) | nested (transparent + outline).
- Divider: axis: horizontal(default)|vertical.
- Tabs: tabs: [{"title":"...","child":"<id>"}] (underline style; local selection).
- Modal: trigger:<id>, content:<id> (tapping the trigger opens content in a glass sheet with a ✕ close).
- Button: child:<id> (its label, usually a Text); variant: default|primary(gradient)|borderless; action:{"event":{"name":"<event>","context":{...}}}.
- TextField: label; value:{"path":"/f"} (two-way — edits write to the data model); variant: shortText(default)|longText|number|obscured.
- CheckBox: label; value:{"path":"/flag"} (boolean, two-way).
- ChoicePicker: label; value:{"path":"/sel"} (array); options:[{"value","label","description"?}]; variant: mutuallyExclusive(default,single)|multipleSelection; displayStyle: chips(default, pills)|checkbox (radio for single, tick for multi).
- Slider: label; value:{"path":"/n"}; min(default 0); max(default 100).
- DateTimeInput: label; value:{"path":"/dt"} (ISO 8601 string).
- Image: url — MUST be a data URI ("data:image/png;base64,...."); http URLs render a themed placeholder. variant (size preset): icon|avatar(round)|smallFeature|mediumFeature(default)|largeFeature|header. fit: contain(default)|cover|stretch.
- Icon: name — vector icons: bolt|terminal|lock|link|chat|controls (others: check|close|add|settings|star|warning|home|search|…); inherits text color.
- Video: url — styled mock player (play button + scrubber; no live playback).
- AudioPlayer: url — a `data:audio/...;base64,...` URI plays for real (play/pause + seekable waveform); a remote http url or no url renders the same static mock player as before (no live playback).

INTERACTION: A Button tap emits a `ui-event: {"name","surfaceId","sourceComponentId","context"}` line you receive via wait_for_reply / get_messages (context bindings are resolved against the current data model). Input components (TextField/CheckBox/ChoicePicker/Slider) write into the data model at their bound path; to READ those values, reference them in a Button's action `context` (e.g. "context":{"note":{"path":"/note"}}) — the tap's ui-event then carries the resolved values. Respond by calling update_ui (change the data model at a JSON-pointer) or render_ui (a new surface).

EXAMPLE (a name form):
components: [
  {"id":"root","component":"Card","child":"col"},
  {"id":"col","component":"Column","children":["t","f","btn"],"align":"center"},
  {"id":"t","component":"Text","text":"What's your name?","variant":"h2"},
  {"id":"f","component":"TextField","label":"name","value":{"path":"/name"}},
  {"id":"lbl","component":"Text","text":"Submit"},
  {"id":"btn","component":"Button","child":"lbl","variant":"primary","action":{"event":{"name":"submit","context":{"name":{"path":"/name"}}}}}
]
data_model: {"name":""}"##)]
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
            // Include a per-process time base so auto-generated ids don't collide
            // with surfaces from an earlier bridge run (which would replace an
            // existing card instead of adding a new one).
            let n = SURFACE_SEQ.fetch_add(1, Relaxed);
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0);
            format!("ui-{t}-{n}")
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
    pub(super) async fn start_pairing(&self) -> Result<CallToolResult, ErrorData> {
        // Mint against the machine identity when one exists (design.md
        // D1/D3), else the session's own — same rationale as the startup
        // banner (`--legacy-ticket` opts back into the raw ticket, or
        // minting can fail — e.g. $HOME unset — in which case fall back the
        // same way).
        let url = if self.legacy_ticket {
            qr::pairing_url(&self.pairing_ticket)
        } else {
            match super::mint_pairing_invite(self.machine_secret.as_ref(), &self.pairing_ticket, self.endpoint.secret_key()).await {
                Some(encoded) => qr::invite_url(&encoded),
                None => qr::pairing_url(&self.pairing_ticket),
            }
        };
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
            let _ = registry::remove(&args.device);
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
            let ticket_and_invite = {
                let guard = self.devices.lock().await;
                guard.get(device).map(|c| (c.ticket.clone(), c.invite.clone()))
            }
            .or_else(|| {
                registry::load()
                    .into_iter()
                    .find(|d| d.name == device)
                    .map(|d| (d.ticket, d.invite))
            });
            if let Some((t, invite)) = ticket_and_invite {
                connect_device(&self.endpoint, device, &t, &self.devices, &self.own_name, invite.as_deref(), Some(&self.session_cert)).await;
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

#[tool_handler]
impl ServerHandler for AzulaBridge {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.instructions = Some(
            "azula bridge — a link to the user's azula phone app over iroh. \
             To pair a phone: call `start_pairing` and show the user the returned URL + QR \
             code (they scan it or paste the code into the app's \"＋ connect a peer\"), OR \
             call `connect` with a share code the user copies from their app. Then use \
             `send_message` to send a chat message, `send_file` to send an image or other \
             file (the only way to show a real image — `render_ui`'s Image component only \
             renders small embedded data URIs), and `render_ui` to show an interactive \
             A2UI card (all three raise a phone notification when the app is backgrounded). \
             To receive the user's reply, a card tap, or a file/image they send, call \
             `wait_for_reply` (blocks until they respond) or `get_messages` (drain now); \
             A2UI taps arrive as `ui-event:` lines — react with `update_ui` — and attachments \
             arrive as `[received file: ...]` lines naming a local path. Once connected, call `set_name` with \
             description=\"<project> / <topic>\" (e.g. \"azula / terminal refactor\") to \
             label the conversation — the name stays \"Claude\"; keep the description for \
             the session, set a fresh one for a new session. `render_ui`'s description \
             documents the full A2UI catalog. `list_devices` shows connection status; \
             `disconnect` closes a connection. (`say` is for bridge-to-bridge chat, not apps.)"
                .into(),
        );
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info
    }
}
