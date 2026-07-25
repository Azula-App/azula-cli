//! `SessionCore` — the shared connection-management layer behind both the
//! MCP tool surface (`bridge::tools::AzulaBridge`) and the CLI noun-verb
//! surface (`cli::*`): endpoint bind (session key + cert, per phase 1),
//! device map + registry load, dial/ensure_device, send_message/say
//! streaming, send_file, A2UI send (render/update/delete + root validation),
//! inbox (get/wait), mailbox queueing, and runtime state file writes.
//!
//! `cli-multi-session-relay` design.md D4: "The MCP tools and CLI verbs call
//! one `SessionCore`... the MCP layer is a thin `#[tool_router]` over it, the
//! CLI a thin clap layer." This module is that core; [`bridge::tools`] and
//! [`crate::cli`] hold the "thin layer" formatting on top of it.
//!
//! [`establish`] is the one-shot-vs-long-running entry point used by both
//! callers: `azula mcp` holds the returned [`Established::router`] /
//! [`Established::session`] for the life of the process; a one-shot CLI verb
//! (`message send`, `ui render`, …) does the same but for one action, then
//! lets both drop (closing the connection and, for an ephemeral session,
//! deleting its key file).

pub mod device;
pub mod state;
pub mod status;
pub mod watch;

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use iroh::protocol::Router;
use iroh::{Endpoint, SecretKey};
use tokio::sync::Mutex as AsyncMutex;
use tracing::info;

use crate::certs;
use crate::filexfer;
use crate::identity;
use crate::invite;
use crate::link::{self, Parsed};
use crate::mailbox;
use crate::mcp::LLM_ALPN;
use crate::proto::{write_frame, Frame};
use crate::qr;
use crate::registry::{self, Device};
use crate::session::SessionKey;

use device::DeviceMap;
use state::write_state;

/// The A2UI basic catalog id this session targets when creating a surface —
/// a URL identifying the *A2UI protocol* catalog, distinct from
/// [`crate::catalog::A2UI_CATALOG`] (this crate's own prose documentation of
/// that catalog's components, embedded in the MCP tool description / `azula
/// ui catalog` / `azula ui render --help`).
const A2UI_CATALOG_URL: &str = "https://a2ui.org/specification/v0_9_1/catalogs/basic/catalog.json";

/// Monotonic counter for auto-generated A2UI surface ids (`ui-<time>-<n>`).
static SURFACE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A `SessionCore` operation failure, classified so callers can decide how to
/// surface it:
///
/// - `Usage` — a bad argument/input, caught before any network activity
///   (invalid ticket, malformed A2UI components, an oversize/unreadable
///   file). CLI verbs exit `2`; the MCP layer returns an ordinary
///   `CallToolResult::error` (a result the model sees and can react to).
/// - `Operational` — a runtime connectivity/lookup failure (device unknown,
///   unreachable, or a business-rule rejection like a closed conversation).
///   CLI verbs exit `1`; the MCP layer also returns `CallToolResult::error`.
/// - `Transport` — a live-stream write failed after a connection was judged
///   healthy. CLI verbs exit `1`; the MCP layer returns a protocol-level
///   `ErrorData` (matching the original tool bodies' `?`-propagated errors).
#[derive(Debug, Clone)]
pub enum CoreError {
    Usage(String),
    Operational(String),
    Transport(String),
}

impl CoreError {
    /// The human-readable message, with no variant-kind prefix — matches the
    /// exact wording the original (pre-extraction) tool bodies returned.
    pub fn message(&self) -> &str {
        match self {
            CoreError::Usage(m) | CoreError::Operational(m) | CoreError::Transport(m) => m,
        }
    }

    /// The process exit code a CLI verb should use for this failure, per the
    /// cli-surface spec: "0 success; 1 operational failure (unreachable,
    /// timeout); 2 usage/validation."
    pub fn exit_code(&self) -> i32 {
        match self {
            CoreError::Usage(_) => 2,
            CoreError::Operational(_) | CoreError::Transport(_) => 1,
        }
    }
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for CoreError {}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

// ---------------------------------------------------------------------------
// SessionCore
// ---------------------------------------------------------------------------

/// The shared connection-management state for one session identity: a bound
/// endpoint, the live device map, and this process's own certificate
/// material. Constructed via [`establish`] (full setup: accept router,
/// registry preload, background dial/redelivery) or [`SessionCore::from_parts`]
/// (tests, and anywhere the caller already holds its own router — see
/// `bridge::tools::AzulaBridge::new`).
pub struct SessionCore {
    pub endpoint: Arc<Endpoint>,
    pub devices: DeviceMap,
    /// A human tag written into the runtime state file (the HTTP bind, or
    /// "stdio", or a CLI verb's own label) — kept as `label` here since
    /// one-shot CLI verbs aren't a "bind" in any HTTP sense.
    pub label: String,
    /// This session's own dial ticket.
    pub ticket: String,
    /// This session's display name (the conversation title the app shows),
    /// announced to apps in both the dial and accept directions.
    pub own_name: String,
    /// This session's own `azd…` certificate (design.md D1/D3), re-presented
    /// in every `Hello` frame this session sends.
    pub session_cert: String,
    /// The machine identity, read from disk only (never created here) —
    /// `None` in a headless environment.
    pub machine_secret: Option<SecretKey>,
}

impl SessionCore {
    /// Build a `SessionCore` directly from its parts, with no accept router
    /// of its own — for callers (tests, or anyone standing up their own
    /// `Router`) that already have a live endpoint/device map and just need
    /// the shared operations. [`establish`] is the usual entry point.
    pub fn from_parts(
        endpoint: Arc<Endpoint>,
        devices: DeviceMap,
        label: String,
        ticket: String,
        own_name: String,
        session_cert: String,
        machine_secret: Option<SecretKey>,
    ) -> Self {
        SessionCore { endpoint, devices, label, ticket, own_name, session_cert, machine_secret }
    }
}

/// The result of [`establish`]: the shared core, plus the two things whose
/// *lifetime* (not API) the caller must manage — the session key (whose
/// on-disk file an ephemeral session deletes on drop) and the accept router
/// (which stops serving inbound connections once dropped/shut down).
pub struct Established {
    pub core: SessionCore,
    pub session: SessionKey,
    pub router: Router,
}

/// Bind the endpoint, stand up the accept router, preload known devices (+
/// any `--device` flags), and start the background dial + redelivery loops.
///
/// `label` is a human tag written into the runtime state file (the HTTP
/// bind, "stdio", or a CLI verb's own label). `allow_legacy` admits
/// invite-less unknown strangers as unverified instead of closing the
/// connection. `session_name` is `--session`/`AZULA_SESSION`: `Some` selects
/// a persistent named session key, `None` mints a fresh ephemeral one per
/// process (design.md D2) — `azula mcp` passes the raw `--session` value
/// (ephemeral by default); one-shot CLI verbs pass `Some("cli")` unless the
/// user overrode it, per D2's "one-shot verbs share the `cli` conversation".
pub async fn establish(
    label: &str,
    device_urls: Vec<String>,
    name: Option<String>,
    allow_legacy: bool,
    session_name: Option<String>,
) -> Result<Established> {
    let session = SessionKey::resolve(session_name.as_deref())?;
    let (raw_endpoint, bridge_ticket) = crate::endpoint::bind_endpoint_with_secret(session.secret.clone()).await?;
    let my_node_id = raw_endpoint.id();
    info!(session = %session.display_name, mode = ?session.mode, node_id = %my_node_id, "core: session identity");

    // D1: the machine identity, read-only — session establishment must never
    // implicitly create `machine.key`. `None` here is the headless case: the
    // session self-certifies instead (D3).
    let machine_secret = identity::load_machine_secret_if_exists();

    let session_cert = match &machine_secret {
        Some(m) => certs::mint_session_cert(m, my_node_id, certs::DEFAULT_SESSION_EXPIRY),
        None => certs::mint_self_certified_session(&session.secret, certs::DEFAULT_SESSION_EXPIRY),
    }
    .encode();

    let devices: DeviceMap = Arc::new(AsyncMutex::new(HashMap::new()));

    let endpoint_id_str = my_node_id.to_string();
    let own_name = name.unwrap_or_else(|| {
        let len = endpoint_id_str.len();
        format!("bridge-{}", &endpoint_id_str[..8_usize.min(len)])
    });

    let accept_handler = device::BridgeAcceptHandler::new(
        devices.clone(),
        label.to_string(),
        own_name.clone(),
        my_node_id,
        allow_legacy,
        session_cert.clone(),
    );
    let iroh_router = Router::builder(raw_endpoint).accept(LLM_ALPN, accept_handler).spawn();
    let endpoint = Arc::new(iroh_router.endpoint().clone());

    info!(own_name=%own_name, "core: own name");

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
        if let Some(token) = link::parse_ticket(url) {
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
                device::connect_device(&ep, &dev_name, &ticket, &devs, &my_name, invite.as_deref(), Some(&my_cert)).await;
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
                    guard
                        .iter()
                        .filter(|(name, conn)| !conn.connected && mailbox::has_pending(name))
                        .map(|(name, conn)| (name.clone(), conn.ticket.clone(), conn.invite.clone()))
                        .collect()
                };
                for (dev_name, ticket, invite) in pending {
                    info!(device=%dev_name, "core: attempting redelivery of queued mail");
                    device::connect_device(&ep, &dev_name, &ticket, &devs, &my_name, invite.as_deref(), Some(&my_cert)).await;
                    write_state(&label_owned, &devs).await;
                }
            }
        });
    }

    Ok(Established {
        core: SessionCore {
            endpoint,
            devices,
            label: label.to_string(),
            ticket: bridge_ticket,
            own_name,
            session_cert,
            machine_secret,
        },
        session,
        router: iroh_router,
    })
}

// ---------------------------------------------------------------------------
// Pairing invites (design.md D1/D3) — used by `start_pairing` (MCP) and
// `SessionCore::pairing_url` (CLI-facing).
// ---------------------------------------------------------------------------

/// Mint a signed 24h invite wrapping `ticket`, signed by `secret_key`. A mint
/// failure (e.g. `$HOME` unset) falls back to `None` so callers can fall back
/// to the raw-ticket link.
pub(crate) fn mint_bridge_invite(ticket: &str, secret_key: &SecretKey) -> Option<String> {
    let expiry = invite::Expiry::In(std::time::Duration::from_secs(24 * 60 * 60));
    match invite::mint(ticket, expiry, true, false, None, secret_key) {
        Ok((payload, _)) => Some(payload.encode()),
        Err(e) => {
            tracing::warn!(error = %e, "core: failed to mint invite; falling back to raw ticket");
            None
        }
    }
}

/// Mint the pairing invite shown by the startup banner / `start_pairing` /
/// `SessionCore::pairing_url` (design.md D1/D3): against the **machine**
/// identity when one already exists on disk, or the session's own when it
/// doesn't (the headless case, or a machine-identity bind failure).
pub(crate) async fn mint_pairing_invite(
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
                tracing::warn!(error = %e, "core: could not bind the machine identity for a pairing invite; falling back to the session identity");
            }
        }
    }
    mint_bridge_invite(session_ticket, session_secret)
}

// ---------------------------------------------------------------------------
// Data types returned by SessionCore operations
// ---------------------------------------------------------------------------

pub struct ConnectOutcome {
    pub name: String,
    pub connected: bool,
    pub ticket_fingerprint: String,
}

pub enum DeviceLiveStatus {
    Connected,
    Disconnected,
    /// Known (registry) but never dialed/accepted this run.
    Offline,
}

pub struct DeviceSummary {
    pub name: String,
    pub ticket_fingerprint: String,
    pub status: DeviceLiveStatus,
}

pub enum SendOutcome {
    Sent,
    Queued,
}

pub struct FileSent {
    pub name: String,
    pub mime: String,
    pub size: usize,
}

pub struct InboxLine {
    pub device: String,
    pub text: String,
}

pub enum WaitOutcome {
    Lines(Vec<String>),
    TimedOut,
}

pub struct SetNameOutcome {
    pub name: String,
    pub description: Option<String>,
    pub sent: usize,
}

pub enum SayOutcome {
    Delivered { turn: u64, max: u64 },
    Queued,
}

// ---------------------------------------------------------------------------
// SessionCore operations
// ---------------------------------------------------------------------------

impl SessionCore {
    /// Connect to a new azula device or peer bridge by ticket URL, invite
    /// link, or bare token; persists it to the registry either way.
    pub async fn connect(&self, url: &str, name: Option<String>) -> Result<ConnectOutcome, CoreError> {
        let (ticket, invite_str) = match link::parse(url) {
            Some(Parsed::Invite(payload)) => {
                let decoded = invite::InvitePayload::decode(&payload)
                    .map_err(|e| CoreError::Usage(format!("invalid invite: {e}")))?;
                let ticket = decoded.ticket().map_err(|e| CoreError::Usage(format!("invalid invite ticket: {e}")))?;
                (ticket.to_string(), Some(payload))
            }
            Some(Parsed::Ticket(t)) => (t, None),
            None => return Err(CoreError::Usage("invalid ticket or URL".to_string())),
        };

        let name = name.unwrap_or_else(|| ticket.chars().take(8).collect());

        let dev = Device {
            name: name.clone(),
            ticket: ticket.clone(),
            added_at: Some(now_secs()),
            invite: invite_str.clone(),
        };
        if let Err(e) = registry::add(dev, false) {
            tracing::warn!(error=%e, "core: registry add failed; continuing");
        }

        let connected = device::connect_device(
            &self.endpoint, &name, &ticket, &self.devices, &self.own_name, invite_str.as_deref(), Some(&self.session_cert),
        )
        .await;

        if connected {
            let guard = self.devices.lock().await;
            if let Some(conn) = guard.get(&name) {
                conn.reset_conversation();
            }
        }

        {
            let mut guard = self.devices.lock().await;
            guard
                .entry(name.clone())
                .or_insert_with(|| device::DeviceConn::new(ticket.clone()).with_invite(invite_str.clone()));
        }

        write_state(&self.label, &self.devices).await;

        Ok(ConnectOutcome { name, connected, ticket_fingerprint: ticket.chars().take(8).collect() })
    }

    /// All known devices (registry ∪ live map) and their live connection status.
    pub async fn list_devices(&self) -> Vec<DeviceSummary> {
        let known = registry::load();
        let guard = self.devices.lock().await;

        let mut names: Vec<String> = known.iter().map(|d| d.name.clone()).collect();
        for k in guard.keys() {
            if !names.contains(k) {
                names.push(k.clone());
            }
        }
        names.sort();

        names
            .into_iter()
            .map(|name| {
                let ticket = known
                    .iter()
                    .find(|d| d.name == name)
                    .map(|d| d.ticket.clone())
                    .or_else(|| guard.get(&name).map(|c| c.ticket.clone()))
                    .unwrap_or_default();
                let ticket_fingerprint: String = ticket.chars().take(8).collect();
                let status = match guard.get(&name) {
                    Some(c) if c.connected => DeviceLiveStatus::Connected,
                    Some(_) => DeviceLiveStatus::Disconnected,
                    None => DeviceLiveStatus::Offline,
                };
                DeviceSummary { name, ticket_fingerprint, status }
            })
            .collect()
    }

    /// Resolve a `--device` argument against known devices: the name itself
    /// if given and known; the sole registered device if omitted and exactly
    /// one exists; a `Usage` error (listing candidates, or explaining none
    /// are registered) otherwise. cli-surface spec: "`--device D` matches a
    /// registry device by name; with exactly one registered device it may be
    /// omitted (defaulting to it); error listing candidates otherwise."
    pub async fn resolve_target_device(&self, requested: Option<&str>) -> Result<String, CoreError> {
        match requested {
            Some(d) => {
                let known_live = self.devices.lock().await.contains_key(d);
                let known_registry = registry::load().iter().any(|dev| dev.name == d);
                if known_live || known_registry {
                    Ok(d.to_string())
                } else {
                    Err(CoreError::Usage(format!("unknown device '{d}'; run `azula devices` to see known devices")))
                }
            }
            None => {
                let mut names: Vec<String> = self.devices.lock().await.keys().cloned().collect();
                for d in registry::load() {
                    if !names.contains(&d.name) {
                        names.push(d.name);
                    }
                }
                names.sort();
                match names.len() {
                    1 => Ok(names.into_iter().next().expect("len checked")),
                    0 => Err(CoreError::Usage(
                        "no devices registered; pair one with `azula pair <URL>` or pass --device".to_string(),
                    )),
                    _ => Err(CoreError::Usage(format!(
                        "multiple devices registered ({}); specify one with --device",
                        names.join(", ")
                    ))),
                }
            }
        }
    }

    /// Ensure the named device has a live connection (lazy-dialing a known
    /// device if needed), returning a clone of its connection state.
    pub async fn ensure_device(&self, device_name: &str) -> Result<device::DeviceConn, CoreError> {
        let needs_dial = {
            let guard = self.devices.lock().await;
            match guard.get(device_name) {
                Some(c) if c.connected => false,
                Some(_) => true,
                None => registry::load().iter().any(|d| d.name == device_name),
            }
        };

        if needs_dial {
            let ticket_and_invite = {
                let guard = self.devices.lock().await;
                guard.get(device_name).map(|c| (c.ticket.clone(), c.invite.clone()))
            }
            .or_else(|| {
                registry::load()
                    .into_iter()
                    .find(|d| d.name == device_name)
                    .map(|d| (d.ticket, d.invite))
            });
            if let Some((t, invite)) = ticket_and_invite {
                device::connect_device(
                    &self.endpoint, device_name, &t, &self.devices, &self.own_name, invite.as_deref(), Some(&self.session_cert),
                )
                .await;
            }
        }

        let guard = self.devices.lock().await;
        match guard.get(device_name) {
            Some(c) if c.connected => Ok(c.clone()),
            Some(_) => Err(CoreError::Operational(format!("device '{device_name}' is not reachable"))),
            None => Err(CoreError::Operational(format!("unknown device '{device_name}'; use `connect` first"))),
        }
    }

    /// A plain map lookup — no dial attempt — for callers (`get_messages`,
    /// `wait_for_reply`, `set_name`) that only ever read/write an already
    /// (or never) connected device's state.
    pub async fn lookup_device(&self, device_name: &str) -> Option<device::DeviceConn> {
        self.devices.lock().await.get(device_name).cloned()
    }

    /// Send a text message to a device — appears as a streamed
    /// azula-assistant reply in the app. Queues via the offline mailbox
    /// (same delivery chain either the MCP tool or a CLI verb uses) when the
    /// device can't be reached right now.
    pub async fn send_message(&self, device_name: &str, text: String) -> Result<SendOutcome, CoreError> {
        let queue = |text: String| mailbox::enqueue(device_name, &[
            Frame::thinking(true),
            Frame::token(text),
            Frame::token_done(),
            Frame::thinking(false),
        ]);

        let conn = match self.ensure_device(device_name).await {
            Ok(c) => c,
            Err(_) => {
                queue(text);
                return Ok(SendOutcome::Queued);
            }
        };

        let mut send_guard = conn.send.lock().await;
        let Some(send) = send_guard.as_mut() else {
            drop(send_guard);
            queue(text);
            return Ok(SendOutcome::Queued);
        };

        for frame in [Frame::thinking(true), Frame::token(text), Frame::token_done(), Frame::thinking(false)] {
            write_frame(send, &frame).await.map_err(|e| CoreError::Transport(e.to_string()))?;
        }
        Ok(SendOutcome::Sent)
    }

    /// Send a local file to a device as an inline attachment. Unlike
    /// `send_message`, this requires a live connection — it is not queued
    /// for offline devices (a large file would blow the mailbox's cap).
    pub async fn send_file(&self, device_name: &str, path: &std::path::Path, caption: Option<String>) -> Result<FileSent, CoreError> {
        let bytes = tokio::fs::read(path)
            .await
            .map_err(|e| CoreError::Usage(format!("could not read '{}': {e}", path.display())))?;

        if bytes.len() as u64 > filexfer::MAX_FILE_BYTES {
            return Err(CoreError::Usage(format!(
                "'{}' is {} bytes, which exceeds the {} byte (64 MiB) limit",
                path.display(),
                bytes.len(),
                filexfer::MAX_FILE_BYTES
            )));
        }

        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file").to_string();
        let mime = filexfer::guess_mime(path);
        let size = bytes.len();

        let conn = self.ensure_device(device_name).await?;

        let id = uuid::Uuid::new_v4().to_string();
        let frames = filexfer::build_file_frames(id, name.clone(), mime.clone(), caption, &bytes)
            .map_err(|e| CoreError::Usage(e.to_string()))?;

        let mut send_guard = conn.send.lock().await;
        let Some(send) = send_guard.as_mut() else {
            return Err(CoreError::Transport(format!("device '{device_name}' send stream closed")));
        };
        for frame in &frames {
            write_frame(send, frame).await.map_err(|e| CoreError::Transport(e.to_string()))?;
        }

        Ok(FileSent { name, mime, size })
    }

    /// Drain new messages from one device, or from every device if `device`
    /// is `None`.
    pub async fn get_messages(&self, device_name: Option<&str>) -> Result<Vec<InboxLine>, CoreError> {
        let guard = self.devices.lock().await;
        if let Some(name) = device_name {
            let conn = match guard.get(name) {
                Some(c) => c.clone(),
                None => return Err(CoreError::Operational(format!("unknown device '{name}'"))),
            };
            drop(guard);
            let msgs: Vec<String> = conn.inbox.lock().unwrap_or_else(|e| e.into_inner()).drain(..).collect();
            Ok(msgs.into_iter().map(|text| InboxLine { device: name.to_string(), text }).collect())
        } else {
            let mut all = Vec::new();
            for (name, conn) in guard.iter() {
                let msgs: Vec<String> = conn.inbox.lock().unwrap_or_else(|e| e.into_inner()).drain(..).collect();
                for text in msgs {
                    all.push(InboxLine { device: name.clone(), text });
                }
            }
            Ok(all)
        }
    }

    /// Long-poll: block until the device has new inbound activity, then
    /// drain it (or report a timeout after `timeout_s` seconds).
    pub async fn wait_for_reply(&self, device_name: &str, timeout_s: u64) -> Result<WaitOutcome, CoreError> {
        let conn = {
            let guard = self.devices.lock().await;
            match guard.get(device_name) {
                Some(c) => c.clone(),
                None => return Err(CoreError::Operational(format!("unknown device '{device_name}'"))),
            }
        };
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(timeout_s);
        loop {
            let msgs: Vec<String> = conn.inbox.lock().unwrap_or_else(|e| e.into_inner()).drain(..).collect();
            if !msgs.is_empty() {
                return Ok(WaitOutcome::Lines(msgs));
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(WaitOutcome::TimedOut);
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        }
    }

    /// Set the conversation's name/description on one device, or every
    /// connected device if `device` is `None`.
    pub async fn set_name(&self, device_name: Option<&str>, name: Option<String>, description: Option<String>) -> Result<SetNameOutcome, CoreError> {
        let targets: Vec<device::DeviceConn> = {
            let guard = self.devices.lock().await;
            match device_name {
                Some(n) => match guard.get(n) {
                    Some(c) => vec![c.clone()],
                    None => return Err(CoreError::Operational(format!("unknown device '{n}'"))),
                },
                None => guard.values().cloned().collect(),
            }
        };
        let name = name.unwrap_or_else(|| self.own_name.clone());
        let frame = Frame::Profile { name: name.clone(), description: description.clone(), avatar: None, mime: None };
        let mut sent = 0;
        for conn in &targets {
            let mut g = conn.send.lock().await;
            if let Some(send) = g.as_mut() {
                if write_frame(send, &frame).await.is_ok() {
                    sent += 1;
                }
            }
        }
        Ok(SetNameOutcome { name, description, sent })
    }

    /// Send a peer-to-peer chat message to another bridge session (not an
    /// app device), enforcing `max_turns`.
    pub async fn say(&self, device_name: &str, text: String, done: Option<bool>, max_turns: u64) -> Result<SayOutcome, CoreError> {
        let conn = match self.ensure_device(device_name).await {
            Ok(c) => c,
            Err(_) => {
                mailbox::enqueue(device_name, &[Frame::Chat { text: text.clone(), id: None }]);
                return Ok(SayOutcome::Queued);
            }
        };

        if conn.closed.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(CoreError::Operational(format!("conversation with '{device_name}' is closed")));
        }

        let n = conn.turns.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if n >= max_turns {
            {
                let mut send_guard = conn.send.lock().await;
                if let Some(send) = send_guard.as_mut() {
                    let _ = write_frame(send, &Frame::Chat { text: "[conversation ended: turn limit]".into(), id: None }).await;
                }
            }
            conn.closed.store(true, std::sync::atomic::Ordering::Relaxed);
            return Err(CoreError::Operational(format!("turn limit ({max_turns}) reached for '{device_name}'")));
        }

        {
            let mut send_guard = conn.send.lock().await;
            let Some(send) = send_guard.as_mut() else {
                mailbox::enqueue(device_name, &[Frame::Chat { text: text.clone(), id: None }]);
                return Ok(SayOutcome::Queued);
            };
            if let Err(e) = write_frame(send, &Frame::Chat { text: text.clone(), id: None }).await {
                return Err(CoreError::Transport(format!("failed to send to '{device_name}': {e}")));
            }
            if done == Some(true) {
                let closing = Frame::Chat { text: format!("[conversation ended by {}]", self.own_name), id: None };
                let _ = write_frame(send, &closing).await;
            }
        }

        if done == Some(true) {
            conn.closed.store(true, std::sync::atomic::Ordering::Relaxed);
        }

        Ok(SayOutcome::Delivered { turn: n + 1, max: max_turns })
    }

    /// Write a single A2UI message to a connected device as an `a2ui` frame.
    async fn send_a2ui_frame(&self, conn: &device::DeviceConn, message: serde_json::Value) -> Result<(), CoreError> {
        let mut send_guard = conn.send.lock().await;
        let Some(send) = send_guard.as_mut() else {
            return Err(CoreError::Transport("device send stream closed".to_string()));
        };
        write_frame(send, &Frame::A2ui { message }).await.map_err(|e| CoreError::Transport(e.to_string()))
    }

    /// Render an A2UI declarative surface on a device: validates the
    /// component tree client-side (cli-surface spec: "Invalid component
    /// trees SHALL be rejected client-side with the same root-component
    /// validation the MCP tool applies" — nothing is sent on failure) before
    /// dialing or writing anything. Returns the surface id used.
    pub async fn render_ui(
        &self,
        device_name: &str,
        components: serde_json::Value,
        data_model: Option<serde_json::Value>,
        surface_id: Option<String>,
    ) -> Result<String, CoreError> {
        validate_a2ui_components(&components)?;

        let surface_id = surface_id.unwrap_or_else(|| {
            // Include a per-process time base so auto-generated ids don't collide
            // with surfaces from an earlier session (which would replace an
            // existing card instead of adding a new one).
            let n = SURFACE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0);
            format!("ui-{t}-{n}")
        });

        let conn = self.ensure_device(device_name).await?;

        self.send_a2ui_frame(&conn, serde_json::json!({
            "version": "v0.9.1",
            "createSurface": { "surfaceId": surface_id, "catalogId": A2UI_CATALOG_URL }
        })).await?;
        self.send_a2ui_frame(&conn, serde_json::json!({
            "version": "v0.9.1",
            "updateComponents": { "surfaceId": surface_id, "components": components }
        })).await?;
        if let Some(dm) = data_model {
            self.send_a2ui_frame(&conn, serde_json::json!({
                "version": "v0.9.1",
                "updateDataModel": { "surfaceId": surface_id, "path": "", "value": dm }
            })).await?;
        }

        Ok(surface_id)
    }

    /// Update the data model of a rendered A2UI surface at an RFC 6901
    /// JSON pointer (`""` replaces the whole model).
    pub async fn update_ui(&self, device_name: &str, surface_id: &str, path: &str, value: serde_json::Value) -> Result<(), CoreError> {
        let conn = self.ensure_device(device_name).await?;
        self.send_a2ui_frame(&conn, serde_json::json!({
            "version": "v0.9.1",
            "updateDataModel": { "surfaceId": surface_id, "path": path, "value": value }
        })).await
    }

    /// Remove an A2UI surface from a device.
    pub async fn delete_ui(&self, device_name: &str, surface_id: &str) -> Result<(), CoreError> {
        let conn = self.ensure_device(device_name).await?;
        self.send_a2ui_frame(&conn, serde_json::json!({
            "version": "v0.9.1",
            "deleteSurface": { "surfaceId": surface_id }
        })).await
    }

    /// Disconnect from a device (drop its live stream), optionally removing
    /// it from the registry too. Never errors — an unknown device is simply
    /// a no-op, matching the original MCP tool's behavior.
    pub async fn disconnect(&self, device_name: &str, forget: bool) {
        {
            let mut guard = self.devices.lock().await;
            if let Some(conn) = guard.get_mut(device_name) {
                *conn.send.lock().await = None;
                conn.connected = false;
            }
        }
        if forget {
            let mut guard = self.devices.lock().await;
            guard.remove(device_name);
            drop(guard);
            let _ = registry::remove(device_name);
        }
        write_state(&self.label, &self.devices).await;
    }

    /// This session's pairing URL: a freshly minted 24h invite (against the
    /// machine identity when one exists, else this session's own — design.md
    /// D1/D3), or the raw dial-ticket link when `legacy_ticket` is set.
    pub async fn pairing_url(&self, legacy_ticket: bool) -> String {
        if legacy_ticket {
            qr::pairing_url(&self.ticket)
        } else {
            match mint_pairing_invite(self.machine_secret.as_ref(), &self.ticket, self.endpoint.secret_key()).await {
                Some(encoded) => qr::invite_url(&encoded),
                None => qr::pairing_url(&self.ticket),
            }
        }
    }
}

/// Validate an A2UI `components` value client-side: it must be a JSON array
/// containing exactly one component with `"id":"root"`. Shared by
/// `SessionCore::render_ui` and `cli::ui`'s stdin validation (the same check,
/// so a script gets an identical rejection whether it goes through the MCP
/// tool or the CLI verb).
pub fn validate_a2ui_components(components: &serde_json::Value) -> Result<(), CoreError> {
    let comps = match components {
        serde_json::Value::Array(a) => a,
        _ => return Err(CoreError::Usage("`components` must be a JSON array of A2UI components".to_string())),
    };
    if !comps.iter().any(|c| c.get("id").and_then(|v| v.as_str()) == Some("root")) {
        return Err(CoreError::Usage(
            "the component list needs one component with \"id\":\"root\" (the surface root)".to_string(),
        ));
    }
    Ok(())
}
