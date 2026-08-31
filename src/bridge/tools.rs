//! The `AzulaBridge` MCP tool surface — the 12 `#[tool]` methods an external
//! LLM client calls to manage azula device sessions and peer-bridge
//! conversations:
//!
//! - `connect`        — pair a new device or peer bridge by ticket/URL
//! - `list_devices`   — show known + live-connection status
//! - `send_message`   — send text to an azula app device (streamed assistant reply)
//! - `send_file`      — send a local file (e.g. an image) to a device as an inline attachment
//! - `get_messages`   — drain the inbox: user chat text + `ui-event:` lines + peer messages + received files
//! - `get_events`     — drain the inbox as structured JSON events (typed, not rendered)
//! - `wait_for_reply` — long-poll until a device has new inbound activity, then drain it
//! - `set_typing`     — show/clear the thinking indicator without sending text
//! - `set_name`       — set the conversation's name/description shown in the app
//! - `say`            — send a peer-to-peer chat message to another bridge
//! - `render_ui`      — render an A2UI declarative surface on a device
//! - `update_ui`      — update a surface's data model (react to a `ui-event`)
//! - `delete_ui`      — remove a surface
//! - `disconnect`     — drop a live connection, optionally forget the device
//! - `start_pairing`  — show the bridge's pairing URL + QR code
//!
//! Every method here is a **thin wrapper**: deserialize the MCP args, call
//! the matching [`crate::core::SessionCore`] operation, format the result (or
//! error) as a [`CallToolResult`] — `azula-docs/openspec/changes/
//! cli-multi-session-relay/specs/cli-surface/spec.md`'s "CLI and MCP Share
//! One Core" requirement. `cli::*` is the sibling thin layer, over the same
//! `SessionCore` methods, for the noun-verb CLI surface.

use std::sync::Arc;

use anyhow::Result;
use iroh::Endpoint;
use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, ServerCapabilities, ServerInfo};
use rmcp::schemars;
use rmcp::{tool, tool_handler, tool_router, ErrorData, ServerHandler};
use serde::Deserialize;

use crate::core::device::DeviceMap;
use crate::core::{self, CoreError, SessionCore};
use crate::qr;

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
pub(super) struct RenderUiArgs {
    /// The device name to render the UI on.
    pub(super) device: String,
    /// A2UI basic-catalog components as a flat JSON array. Each element is an
    /// object with an `id` and a `component` type; exactly one must have
    /// `"id":"root"`. Components reference children by id (`child` / `children`),
    /// and props may be literals or `{"path":"/ptr"}` bindings into the data
    /// model. Buttons carry `{"action":{"event":{"name":...,"context":{...}}}}`.
    pub(super) components: serde_json::Value,
    /// Optional initial data model (a JSON object) backing the `{"path":...}` bindings.
    pub(super) data_model: Option<serde_json::Value>,
    /// Optional surface id. A unique one (`ui-<time>-<n>`) is generated if omitted;
    /// omit it to add a NEW card, or pass an existing id to replace that card.
    pub(super) surface_id: Option<String>,
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
pub(super) struct GetEventsArgs {
    /// If specified, drain only this device; otherwise drain all devices.
    pub(super) device: Option<String>,
    /// Wait up to this many seconds for something to arrive before draining.
    /// Omit to take whatever is pending and return immediately.
    pub(super) timeout_s: Option<u64>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub(super) struct SetTypingArgs {
    /// The device whose conversation should show (or stop showing) activity.
    pub(super) device: String,
    /// `true` to show the thinking indicator, `false` to clear it.
    pub(super) on: bool,
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
// CoreError -> CallToolResult/ErrorData mapping
// ---------------------------------------------------------------------------

/// Map a [`CoreError`] to how the original (pre-extraction) tool bodies
/// distinguished the two MCP failure shapes: `Usage`/`Operational` are a
/// **tool-level** error the model sees in the result (`Ok(CallToolResult::
/// error(...))`, same as e.g. "unknown device" always was); `Transport` is a
/// **protocol-level** error (`Err(ErrorData::internal_error(...))`, matching
/// the original `?`-propagated `write_frame(...).map_err(ErrorData::internal_error)`
/// call sites).
fn core_err_to_tool_result(e: CoreError) -> Result<CallToolResult, ErrorData> {
    match e {
        CoreError::Transport(m) => Err(ErrorData::internal_error(m, None)),
        CoreError::Usage(m) | CoreError::Operational(m) => Ok(CallToolResult::error(vec![Content::text(m)])),
    }
}

// ---------------------------------------------------------------------------
// MCP server handler
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AzulaBridge {
    core: Arc<SessionCore>,
    /// Hard turn cap per peer bridge conversation.
    max_turns: u64,
    /// `start_pairing` returns the raw ticket link instead of minting an
    /// invite (`--legacy-ticket`, mirrors the startup banner's escape hatch).
    legacy_ticket: bool,
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
        let core = Arc::new(SessionCore::from_parts(
            endpoint, devices, bind, pairing_ticket, own_name, session_cert, machine_secret,
        ));

        let mut tool_router = Self::tool_router();
        // The `render_ui` tool's description carries the full A2UI catalog
        // (see `catalog::A2UI_CATALOG`'s docs) — but `#[tool(description =
        // ...)]` only accepts a string literal (rmcp/darling parses it via
        // `FromMeta for String`), and `concat!` doesn't accept a `const`
        // path either (only literal tokens), so it can't be assembled at the
        // attribute site without duplicating the catalog text into the
        // source a second time. Overwrite the generated route's description
        // here instead, at construction time, so the catalog prose lives in
        // exactly one place in the crate.
        if let Some(route) = tool_router.map.get_mut("render_ui") {
            route.attr.description = Some(std::borrow::Cow::Owned(format!(
                "{}\n\n{}",
                crate::catalog::RENDER_UI_INTRO,
                crate::catalog::A2UI_CATALOG
            )));
        }

        Self { core, max_turns, legacy_ticket, tool_router }
    }

    /// Connect to a new azula device or peer bridge by ticket URL, invite link, or bare token.
    #[tool(description = "Connect to a new azula device or peer bridge by invite link (https://azula.app/i/<payload>, azula://i?c=<payload>, bare azi... payload) or legacy ticket URL (https://azula.app/s/<token>, azula://connect?code=<token>) or bare token. Optionally provide a display name. When connecting to another bridge, a hello frame is exchanged so the remote bridge can name this one; an invite is re-presented in that hello so the remote's accept gate can verify it.")]
    pub(super) async fn connect(&self, Parameters(args): Parameters<ConnectArgs>) -> Result<CallToolResult, ErrorData> {
        match self.core.connect(&args.url, args.name).await {
            Ok(outcome) => {
                let status = if outcome.connected { "connected" } else { "saved (could not connect now)" };
                Ok(CallToolResult::success(vec![Content::text(format!(
                    "Device '{}' {status}. Ticket fingerprint: {}…",
                    outcome.name, outcome.ticket_fingerprint
                ))]))
            }
            Err(e) => core_err_to_tool_result(e),
        }
    }

    /// List all known devices and their connection status.
    #[tool(description = "List all known azula devices and their live connection status.")]
    async fn list_devices(&self) -> Result<CallToolResult, ErrorData> {
        let summaries = self.core.list_devices().await;
        if summaries.is_empty() {
            return Ok(CallToolResult::success(vec![Content::text("No devices registered. Use `connect` to add one.")]));
        }
        let mut lines = vec!["Known devices:".to_string()];
        for d in &summaries {
            let status = match d.status {
                core::DeviceLiveStatus::Connected => "connected",
                core::DeviceLiveStatus::Disconnected => "disconnected",
                core::DeviceLiveStatus::Offline => "offline",
            };
            lines.push(format!("  {}  [{}…]  {status}", d.name, d.ticket_fingerprint));
        }
        Ok(CallToolResult::success(vec![Content::text(lines.join("\n"))]))
    }

    /// Send a text message to a device.
    #[tool(description = "Send a text message to a named azula device. The text appears as a streamed azula-assistant reply in the app.")]
    pub(super) async fn send_message(&self, Parameters(args): Parameters<SendMessageArgs>) -> Result<CallToolResult, ErrorData> {
        match self.core.send_message(&args.device, args.text).await {
            Ok(core::SendOutcome::Sent) => Ok(CallToolResult::success(vec![Content::text("ok")])),
            Ok(core::SendOutcome::Queued) => Ok(CallToolResult::success(vec![Content::text(format!(
                "queued for delivery to '{}' (offline)", args.device
            ))])),
            Err(e) => core_err_to_tool_result(e),
        }
    }

    /// Send a local file (e.g. an image) to a device as an inline attachment.
    #[tool(description = "Send a local file to a named azula device as an inline attachment — this is how to show the user an IMAGE (or share audio/video/PDF/text/any other file). `path` is a path on THIS machine (where the bridge runs), not the phone. Mime type is inferred from the file extension (png/jpg/jpeg/gif/webp/svg -> image/*, mp4/mov, mp3/wav/ogg, pdf, txt/md, else application/octet-stream). Files over 64 MiB are rejected. Optional `caption` is shown alongside the attachment in the app. Requires a live connection (like render_ui) — it is not queued for offline devices, since a large file would blow the mailbox's message cap.")]
    pub(super) async fn send_file(&self, Parameters(args): Parameters<SendFileArgs>) -> Result<CallToolResult, ErrorData> {
        let path = std::path::Path::new(&args.path);
        match self.core.send_file(&args.device, path, args.caption).await {
            Ok(sent) => Ok(CallToolResult::success(vec![Content::text(format!(
                "sent '{}' ({}, {} bytes) to '{}'", sent.name, sent.mime, sent.size, args.device
            ))])),
            Err(e) => core_err_to_tool_result(e),
        }
    }

    /// Drain new messages from one device or all devices.
    #[tool(description = "Drain new inbound messages from a named device or peer bridge, or from all devices if no device name is given. Lines are either the peer's chat text (from `say` calls by another bridge) or the user's chat text, `ui-event: {\"name\":...,\"surfaceId\":...,\"sourceComponentId\":...,\"context\":{...}}` JSON describing an interaction with an A2UI surface rendered via `render_ui` (match on surfaceId and respond with `update_ui`), or `[received file: <name> (<mime>, <size> bytes) -> <path>]` when the user attaches a file/image (the path is on this machine, readable directly).")]
    pub(super) async fn get_messages(&self, Parameters(args): Parameters<GetMessagesArgs>) -> Result<CallToolResult, ErrorData> {
        match self.core.get_messages(args.device.as_deref()).await {
            Ok(lines) => {
                let text = if lines.is_empty() {
                    "(no new messages)".to_string()
                } else if args.device.is_some() {
                    lines.into_iter().map(|l| l.text).collect::<Vec<_>>().join("\n")
                } else {
                    lines
                        .into_iter()
                        .map(|l| format!("\u{300a}{}\u{300b} {}", l.device, l.text))
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                Ok(CallToolResult::success(vec![Content::text(text)]))
            }
            Err(e) => core_err_to_tool_result(e),
        }
    }

    /// Structured sibling of `get_messages`, for programmatic consumers.
    #[tool(description = "Drain this session's inbox as structured JSON events instead of rendered text: one object per event with a `type` of `message`, `ui_event`, `file`, `connected` or `disconnected`, plus the source `device`. A `ui_event` carries the A2UI tap payload verbatim and a `file` carries the attachment's facts, neither of which survive `get_messages`' one-line rendering. Set `timeout_s` to wait for the inbox to become non-empty before draining (an elapsed timeout returns an empty list, not an error); omit it to take whatever is pending and return at once. Shares one queue with `get_messages`/`wait_for_reply` — an event drained here is not returned by those. Prefer this when a program, rather than a person, reads the result.")]
    pub(super) async fn get_events(&self, Parameters(args): Parameters<GetEventsArgs>) -> Result<CallToolResult, ErrorData> {
        match self.core.get_events(args.device.as_deref(), args.timeout_s).await {
            Ok(events) => {
                // A JSON array, one object per event — the same vocabulary
                // `azula watch --json` streams, so a consumer can move between
                // the two without re-learning the shape.
                let json = serde_json::to_string(&events).unwrap_or_else(|_| "[]".to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(e) => core_err_to_tool_result(e),
        }
    }

    /// Show or clear the conversation's thinking indicator, with no message.
    #[tool(description = "Turn the azula conversation's thinking indicator on or off without sending any text, so a long agent turn looks alive before it has anything to say. `send_message` already brackets its own text with this state; this exposes it on its own. Requires a live connection and errors immediately if the device is unreachable — it is never queued to the relay or the local mailbox, because an indicator replayed later would claim activity that has already ended. Always clear it (`on: false`) when the turn finishes, including when it fails.")]
    pub(super) async fn set_typing(&self, Parameters(args): Parameters<SetTypingArgs>) -> Result<CallToolResult, ErrorData> {
        match self.core.set_typing(&args.device, args.on).await {
            Ok(()) => {
                let state = if args.on { "on" } else { "off" };
                Ok(CallToolResult::success(vec![Content::text(format!(
                    "typing indicator {state} for '{}'",
                    args.device
                ))]))
            }
            Err(e) => core_err_to_tool_result(e),
        }
    }

    /// Long-poll: block until the device has new inbound activity, then drain it.
    #[tool(description = "Wait (long-poll) until a named device has new inbound activity — the user's chat reply, an A2UI `ui-event:` interaction with a surface from `render_ui`, or a received file/image (`[received file: ...]`) — then return it and drain the inbox. Blocks up to `timeout_s` seconds (default 120), returning \"(no reply within Ns)\" on timeout. Use this after `send_message` or `render_ui` to pause for the user's response; `get_messages` is the non-blocking drain.")]
    async fn wait_for_reply(&self, Parameters(args): Parameters<WaitForReplyArgs>) -> Result<CallToolResult, ErrorData> {
        let timeout_s = args.timeout_s.unwrap_or(120);
        match self.core.wait_for_reply(&args.device, timeout_s).await {
            Ok(core::WaitOutcome::Lines(lines)) => Ok(CallToolResult::success(vec![Content::text(lines.join("\n"))])),
            Ok(core::WaitOutcome::TimedOut) => {
                Ok(CallToolResult::success(vec![Content::text(format!("(no reply within {timeout_s}s)"))]))
            }
            Err(e) => core_err_to_tool_result(e),
        }
    }

    /// Set the conversation's name and/or description in the app.
    #[tool(description = "Set how this conversation is labelled in the azula app. Leave `name` unset so it stays the assistant name (\"Claude\"); put the project + session topic in `description` (e.g. \"azula / terminal refactor\"), which the app shows under the name in the conversation list and the chat header. Keep the same description for a session; set a fresh one for a new session. Applies to the given device, or every connected device if omitted.")]
    async fn set_name(&self, Parameters(args): Parameters<SetNameArgs>) -> Result<CallToolResult, ErrorData> {
        match self.core.set_name(args.device.as_deref(), args.name, args.description).await {
            Ok(outcome) => Ok(CallToolResult::success(vec![Content::text(format!(
                "set name=\"{}\" description={:?} on {} device(s)", outcome.name, outcome.description, outcome.sent
            ))])),
            Err(e) => core_err_to_tool_result(e),
        }
    }

    /// Send a peer-to-peer chat message to another bridge.
    #[tool(description = "Send a peer-to-peer chat message to another azula bridge (not an app device). The message appears in that bridge's `get_messages` inbox. Replies from the peer arrive via `get_messages` on this bridge. Set `done=true` to signal the end of the conversation (sends a closing notice to the peer). The bridge enforces a hard per-peer turn cap (`max_turns`); once reached the conversation is closed automatically. Use `connect` first to establish the iroh connection.")]
    pub(super) async fn say(&self, Parameters(args): Parameters<SayArgs>) -> Result<CallToolResult, ErrorData> {
        match self.core.say(&args.device, args.text, args.done, self.max_turns).await {
            Ok(core::SayOutcome::Delivered { turn, max }) => Ok(CallToolResult::success(vec![Content::text(format!(
                "delivered to '{}' (turn {turn}/{max})", args.device
            ))])),
            Ok(core::SayOutcome::Queued) => Ok(CallToolResult::success(vec![Content::text(format!(
                "queued for delivery to '{}' (offline)", args.device
            ))])),
            Err(e) => core_err_to_tool_result(e),
        }
    }

    /// Render an A2UI declarative UI surface on a device. Description is
    /// overwritten at construction time (`AzulaBridge::new`) with the intro
    /// sentence plus the full `catalog::A2UI_CATALOG` prose — see that
    /// module for why this can't be assembled directly in the attribute.
    #[tool(description = "Render an interactive A2UI surface in the azula app on a device. Returns the surfaceId (pass it to update_ui / delete_ui). If the device is offline but its relay is known, the surface is queued to the relay and replayed to the phone next sync instead of failing. See `azula ui catalog` for the full component catalog.")]
    pub(super) async fn render_ui(&self, Parameters(args): Parameters<RenderUiArgs>) -> Result<CallToolResult, ErrorData> {
        match self.core.render_ui_outcome(&args.device, args.components, args.data_model, args.surface_id).await {
            Ok((surface_id, core::SendOutcome::Sent)) => Ok(CallToolResult::success(vec![Content::text(format!(
                "rendered surface '{surface_id}' on '{}'", args.device
            ))])),
            Ok((surface_id, core::SendOutcome::Queued)) => Ok(CallToolResult::success(vec![Content::text(format!(
                "surface '{surface_id}' queued for replay via relay to '{}' (offline)", args.device
            ))])),
            Err(e) => core_err_to_tool_result(e),
        }
    }

    /// Update the data model of a rendered A2UI surface.
    #[tool(description = "Update the data model of an A2UI surface previously created with `render_ui`, at a JSON-pointer `path` (RFC 6901; \"\" replaces the whole model). Use this to react to a `ui-event` — e.g. set /dice/result after a roll, or push fresh data into a bound Text. If the device is offline but its relay is known and this session rendered the surface, the update is coalesced into a full-surface snapshot queued to the relay instead of failing.")]
    async fn update_ui(&self, Parameters(args): Parameters<UpdateUiArgs>) -> Result<CallToolResult, ErrorData> {
        match self.core.update_ui_outcome(&args.device, &args.surface_id, &args.path, args.value).await {
            Ok(core::SendOutcome::Sent) => Ok(CallToolResult::success(vec![Content::text(format!(
                "updated surface '{}' at '{}'", args.surface_id, args.path
            ))])),
            Ok(core::SendOutcome::Queued) => Ok(CallToolResult::success(vec![Content::text(format!(
                "surface '{}' update queued for replay via relay (offline)", args.surface_id
            ))])),
            Err(e) => core_err_to_tool_result(e),
        }
    }

    /// Remove an A2UI surface from a device.
    #[tool(description = "Remove an A2UI surface from a device (it stops rendering/updating). Pass the surfaceId returned by `render_ui`. If the device is offline but its relay is known, the deletion is queued to the relay (as a tombstone) instead of failing.")]
    async fn delete_ui(&self, Parameters(args): Parameters<DeleteUiArgs>) -> Result<CallToolResult, ErrorData> {
        match self.core.delete_ui_outcome(&args.device, &args.surface_id).await {
            Ok(core::SendOutcome::Sent) => {
                Ok(CallToolResult::success(vec![Content::text(format!("deleted surface '{}'", args.surface_id))]))
            }
            Ok(core::SendOutcome::Queued) => Ok(CallToolResult::success(vec![Content::text(format!(
                "surface '{}' deletion queued for replay via relay (offline)", args.surface_id
            ))])),
            Err(e) => core_err_to_tool_result(e),
        }
    }

    /// Show the bridge's pairing URL and QR code so a user can scan and connect.
    #[tool(description = "Return the bridge's pairing URL and a Unicode QR code. The user scans the QR with their phone camera to open the azula app and connect to this bridge automatically. No arguments needed.")]
    pub(super) async fn start_pairing(&self) -> Result<CallToolResult, ErrorData> {
        let url = self.core.pairing_url(self.legacy_ticket).await;
        let qr_block = qr::render_qr(&url);
        let text = format!(
            "{url}\n\n```\n{qr_block}\n```\n\nScan with your phone's camera or open the URL to pair this device.",
        );
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }

    /// Disconnect from a device, optionally removing it from the registry.
    #[tool(description = "Disconnect from a named device. Set forget=true to also remove it from the device registry.")]
    async fn disconnect(&self, Parameters(args): Parameters<DisconnectArgs>) -> Result<CallToolResult, ErrorData> {
        let forget = args.forget.unwrap_or(false);
        self.core.disconnect(&args.device, forget).await;
        if forget {
            Ok(CallToolResult::success(vec![Content::text(format!(
                "device '{}' disconnected and removed from registry", args.device
            ))]))
        } else {
            Ok(CallToolResult::success(vec![Content::text(format!("device '{}' disconnected", args.device))]))
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::sync::Mutex as AsyncMutex;

    /// `AzulaBridge::new` overwrites the macro-generated `render_ui` route's
    /// description at construction time (the catalog text lives once in
    /// `catalog::A2UI_CATALOG`, not duplicated into the `#[tool(description =
    /// ...)]` literal — see that constructor's comment). Pin down that the
    /// override actually finds and replaces the route — a typo in the tool
    /// name used as the `tool_router.map` key would silently no-op instead
    /// of failing loudly.
    #[tokio::test]
    async fn render_ui_tool_description_carries_the_full_a2ui_catalog() {
        let ep = Endpoint::bind(iroh::endpoint::presets::Minimal).await.unwrap();
        let ep = Arc::new(ep);
        let devices: DeviceMap = Arc::new(AsyncMutex::new(HashMap::new()));

        let bridge = AzulaBridge::new(
            ep,
            devices,
            "test".to_string(),
            "ticket".to_string(),
            "bridge".to_string(),
            20,
            true,
            "azd-test-cert".to_string(),
            None,
        );

        let route = bridge.tool_router.map.get("render_ui").expect("render_ui route is registered");
        let description = route.attr.description.as_deref().unwrap_or_default();
        assert!(
            description.contains(crate::catalog::RENDER_UI_INTRO),
            "expected the intro sentence in the description, got: {description}"
        );
        assert!(
            description.contains("STRUCTURE:") && description.contains(crate::catalog::A2UI_CATALOG),
            "expected the full A2UI_CATALOG prose in the description, got: {description}"
        );
    }
}
