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
pub mod relay_a2ui;
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

/// Per-process monotonic sequence stamped on outgoing `Frame::A2uiSnapshot`s
/// (relay capability) — lets the relay ignore a stale, out-of-order snapshot
/// for a surface. Unrelated to the account-sync log's own `lamport` concept;
/// this one only orders one session's snapshots for one relay.
static A2UI_SNAPSHOT_LAMPORT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

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
    /// This session's description (the conversation sub-line), announced as
    /// `Frame::Profile` on each dial when set. `None` leaves whatever the
    /// device already shows untouched.
    pub own_description: Option<String>,
    /// This session's own `azd…` certificate (design.md D1/D3), re-presented
    /// in every `Hello` frame this session sends.
    pub session_cert: String,
    /// The machine identity, read from disk only (never created here) —
    /// `None` in a headless environment.
    pub machine_secret: Option<SecretKey>,
    /// Cached connections to the identity's relay, keyed by relay ticket —
    /// deliberately a *separate* map from `devices` so dialing the relay
    /// never marks the phone device itself as connected (relay spec /
    /// design.md D6's delivery chain: "The relay connection may be cached
    /// like device connections but MUST NOT mark the phone device as
    /// connected"). See [`Self::ensure_relay`].
    relay_conns: DeviceMap,
    /// Retained full A2UI surface state per `(device_name, surface_id)` —
    /// what this session last rendered or coalesced, kept so an offline
    /// `update_ui` can build a full-surface snapshot for the relay from only
    /// a pointer delta (relay spec: "A session that can't reach the phone
    /// SHALL coalesce its render_ui/update_ui/delete_ui calls into
    /// full-surface snapshots"). See [`Self::render_ui_outcome`].
    surface_state: Arc<AsyncMutex<HashMap<(String, String), SurfaceState>>>,
}

/// A session's retained copy of one A2UI surface — see
/// [`SessionCore::surface_state`]'s doc comment.
#[derive(Clone, Debug)]
struct SurfaceState {
    components: serde_json::Value,
    data_model: serde_json::Value,
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
        SessionCore {
            endpoint,
            devices,
            label,
            ticket,
            own_name,
            own_description: None,
            session_cert,
            machine_secret,
            relay_conns: Arc::new(AsyncMutex::new(HashMap::new())),
            surface_state: Arc::new(AsyncMutex::new(HashMap::new())),
        }
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
/// bind, "stdio", or a CLI verb's own label). `session_name` is `--session`/`AZULA_SESSION`: `Some` selects
/// a persistent named session key, `None` mints a fresh ephemeral one per
/// process (design.md D2) — `azula mcp` passes the raw `--session` value
/// (ephemeral by default); one-shot CLI verbs pass `Some("cli")` unless the
/// user overrode it, per D2's "one-shot verbs share the `cli` conversation".
pub async fn establish(
    label: &str,
    device_urls: Vec<String>,
    name: Option<String>,
    description: Option<String>,
    session_name: Option<String>,
) -> Result<Established> {
    let session = SessionKey::resolve(session_name.as_deref())?;
    let (raw_endpoint, bridge_ticket) = crate::endpoint::bind_endpoint_with_secret(session.secret.clone()).await?;
    let my_endpoint_id = raw_endpoint.id();
    info!(session = %session.display_name, mode = ?session.mode, endpoint_id = %my_endpoint_id, "core: session identity");

    // D1: the machine identity, read-only — session establishment must never
    // implicitly create `machine.key`. `None` here is the headless case: the
    // session self-certifies instead (D3).
    let machine_secret = identity::load_machine_secret_if_exists();

    let session_cert = match &machine_secret {
        Some(m) => certs::mint_session_cert(m, my_endpoint_id, certs::DEFAULT_SESSION_EXPIRY),
        None => certs::mint_self_certified_session(&session.secret, certs::DEFAULT_SESSION_EXPIRY),
    }
    .encode();

    let devices: DeviceMap = Arc::new(AsyncMutex::new(HashMap::new()));

    let endpoint_id_str = my_endpoint_id.to_string();
    let own_name = name.unwrap_or_else(|| {
        let len = endpoint_id_str.len();
        format!("bridge-{}", &endpoint_id_str[..8_usize.min(len)])
    });

    let accept_handler = device::BridgeAcceptHandler::new(
        devices.clone(),
        label.to_string(),
        own_name.clone(),
        my_endpoint_id,
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
            own_description: description,
            session_cert,
            machine_secret,
            relay_conns: Arc::new(AsyncMutex::new(HashMap::new())),
            surface_state: Arc::new(AsyncMutex::new(HashMap::new())),
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
/// `SessionCore::pairing_url`, always against the **session** identity — the
/// endpoint that actually accepts the dial the invite invites.
///
/// This used to mint against the machine identity when `machine.key` existed
/// (design.md D1/D3), binding that endpoint just long enough to read its
/// ticket. The endpoint was dropped at the end of that expression, so the
/// advertised endpoint had no listener: a scanner resolved the peer from the
/// discovery record published during the bind and then hung forever "opening
/// direct path". The gate would have rejected the invite even if the dial had
/// landed — [`invite::verify_inbound`] requires both that the embedded
/// ticket's endpoint id *is* the verifying endpoint's own and that the
/// signature is by that same key, and [`crate::accept_gate`]'s gates verify as
/// the session endpoint.
///
/// The machine identity is still the trust anchor; it just isn't the dial
/// target. The session presents a `Hello.cert` chaining to the machine root,
/// and the app pins *that* root when it accepts (session-identity spec,
/// "Accepting a certified stranger pins the root"), so a machine paired
/// through any one session auto-admits its later sessions.
pub(crate) fn mint_pairing_invite(session_ticket: &str, session_secret: &SecretKey) -> Option<String> {
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

/// Take everything currently queued on a device's inbox.
///
/// One place so `get_messages`, `wait_for_reply` and `get_events` cannot drift
/// apart on the poisoned-mutex recovery, and so it stays obvious that they
/// share a single queue.
fn drain_inbox(conn: &device::DeviceConn) -> Vec<watch::InboxEntry> {
    conn.inbox.lock().unwrap_or_else(|e| e.into_inner()).drain(..).collect()
}

#[derive(Debug)]
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
                let connected = device::connect_device(
                    &self.endpoint, device_name, &t, &self.devices, &self.own_name, invite.as_deref(), Some(&self.session_cert),
                )
                .await;
                // Announce the operator's `--description` on the fresh
                // connection. `Hello` carries only a name, so the sub-line
                // needs its own `Profile` frame; sending it here means every
                // verb that dials gets it, not just the ones that thought to.
                if connected && self.own_description.is_some() {
                    let _ = self
                        .set_name(Some(device_name), None, self.own_description.clone())
                        .await;
                }
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
    /// azula-assistant reply in the app. Delivery chain (relay spec /
    /// design.md D6): direct to the device first; the identity's relay
    /// second, when a relay hint is known (delivered there as a `Chat`
    /// frame, appended by the relay as an `agent_in` log entry); the local
    /// per-device JSONL mailbox last, only when no relay hint is known.
    pub async fn send_message(&self, device_name: &str, text: String) -> Result<SendOutcome, CoreError> {
        let queue_local = |text: String| mailbox::enqueue(device_name, &[
            Frame::thinking(true),
            Frame::token(text),
            Frame::token_done(),
            Frame::thinking(false),
        ]);

        let conn = match self.ensure_device(device_name).await {
            Ok(c) => c,
            Err(_) => {
                if let Some(outcome) = self.try_deliver_via_relay(device_name, &text).await {
                    return outcome;
                }
                queue_local(text);
                return Ok(SendOutcome::Queued);
            }
        };

        let mut send_guard = conn.send.lock().await;
        let Some(send) = send_guard.as_mut() else {
            drop(send_guard);
            if let Some(outcome) = self.try_deliver_via_relay(device_name, &text).await {
                return outcome;
            }
            queue_local(text);
            return Ok(SendOutcome::Queued);
        };

        for frame in [Frame::thinking(true), Frame::token(text), Frame::token_done(), Frame::thinking(false)] {
            write_frame(send, &frame).await.map_err(|e| CoreError::Transport(e.to_string()))?;
        }
        Ok(SendOutcome::Sent)
    }


    /// Turn the conversation's thinking indicator on or off, sending nothing
    /// else.
    ///
    /// `send_message` already brackets its text with `thinking(true)`/
    /// `thinking(false)`, but that is the only thing that emits the frame, so
    /// there is no way to show activity *before* any text exists — which is
    /// exactly what an agent's long turn needs.
    ///
    /// Deliberately live-only: unlike `send_message` this never falls back to
    /// the relay or the local mailbox. A typing indicator replayed from a queue
    /// minutes or hours later is worse than none, because the state it claims
    /// ended when the turn that set it did. This puts it in the same class as
    /// `send_file` under mcp-bridge's "Live-Connection-Only Tools Fail Fast,
    /// Never Queue".
    pub async fn set_typing(&self, device_name: &str, on: bool) -> Result<(), CoreError> {
        let conn = self.ensure_device(device_name).await?;
        let mut send_guard = conn.send.lock().await;
        let Some(send) = send_guard.as_mut() else {
            return Err(CoreError::Operational(format!(
                "device '{device_name}' is not connected; a typing indicator is not queued"
            )));
        };
        write_frame(send, &Frame::thinking(on)).await.map_err(|e| CoreError::Transport(e.to_string()))
    }

    /// Delivery-chain step 2 (relay spec / design.md D6): if `device_name`
    /// has a known relay ticket, dial it (LLM ALPN, this session's own
    /// `Hello{cert}`) and deliver `text` as a `Chat` frame — the relay
    /// appends it as an `agent_in` entry keyed by this session's public key,
    /// so the phone picks it up on its next sync (live-pushed if a sync
    /// connection is already open). Returns `None` when no relay is known,
    /// or the relay itself couldn't be reached/written to either — either
    /// way the caller falls through to the local JSONL mailbox (step 3);
    /// `Some(Ok(SendOutcome::Queued))` on a successful relay hand-off.
    async fn try_deliver_via_relay(&self, device_name: &str, text: &str) -> Option<Result<SendOutcome, CoreError>> {
        let ticket = registry::relay_for(device_name)?;
        let conn = self.ensure_relay(&ticket).await.ok()?;
        let mut send_guard = conn.send.lock().await;
        let send = send_guard.as_mut()?;
        let id = uuid::Uuid::new_v4().simple().to_string();
        match write_frame(send, &Frame::Chat { text: text.to_string(), id: Some(id) }).await {
            Ok(()) => Some(Ok(SendOutcome::Queued)),
            Err(_) => None,
        }
    }

    /// Ensure a cached connection to the identity's relay at `ticket`,
    /// dialing it (LLM ALPN, presenting this session's own `Hello{cert}`) if
    /// not already connected. Cached in [`Self::relay_conns`] — never
    /// [`Self::devices`] — so this never marks the phone device itself as
    /// connected.
    async fn ensure_relay(&self, ticket: &str) -> Result<device::DeviceConn, CoreError> {
        let needs_dial = {
            let guard = self.relay_conns.lock().await;
            !matches!(guard.get(ticket), Some(c) if c.connected)
        };
        if needs_dial {
            device::connect_device(
                &self.endpoint, ticket, ticket, &self.relay_conns, &self.own_name, None, Some(&self.session_cert),
            )
            .await;
        }
        let guard = self.relay_conns.lock().await;
        match guard.get(ticket) {
            Some(c) if c.connected => Ok(c.clone()),
            _ => Err(CoreError::Operational("relay is not reachable".to_string())),
        }
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
            let msgs = drain_inbox(&conn);
            Ok(msgs.into_iter().map(|e| InboxLine { device: name.to_string(), text: e.human_line() }).collect())
        } else {
            let mut all = Vec::new();
            for (name, conn) in guard.iter() {
                for entry in drain_inbox(conn) {
                    all.push(InboxLine { device: name.clone(), text: entry.human_line() });
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
            let msgs = drain_inbox(&conn);
            if !msgs.is_empty() {
                return Ok(WaitOutcome::Lines(msgs.iter().map(|e| e.human_line()).collect()));
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(WaitOutcome::TimedOut);
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        }
    }


    /// Drain one device's inbox as structured events, or every device's when
    /// `device_name` is `None`.
    ///
    /// This is the same queue `get_messages`/`wait_for_reply` drain — an entry
    /// read here is gone for all of them — but it reports what the reader
    /// actually saw rather than a rendered line, so a tap keeps its payload and
    /// a file keeps its facts.
    ///
    /// With `timeout_s` set it waits for the inbox to become non-empty before
    /// draining, returning an empty vec if the timeout elapses first; with
    /// `None` it takes whatever is pending and returns immediately. Both modes
    /// live here rather than being composed from `wait_for_reply`, because that
    /// drains the queue as text and would consume the events before a
    /// structured read could see them.
    pub async fn get_events(
        &self,
        device_name: Option<&str>,
        timeout_s: Option<u64>,
    ) -> Result<Vec<watch::WatchEvent>, CoreError> {
        // Resolve targets once; a device that disappears mid-wait simply stops
        // producing, which is the same behaviour the text drains have.
        let targets: Vec<(String, device::DeviceConn)> = {
            let guard = self.devices.lock().await;
            match device_name {
                Some(name) => match guard.get(name) {
                    Some(c) => vec![(name.to_string(), c.clone())],
                    None => return Err(CoreError::Operational(format!("unknown device '{name}'"))),
                },
                None => guard.iter().map(|(n, c)| (n.clone(), c.clone())).collect(),
            }
        };

        let deadline = timeout_s.map(|s| tokio::time::Instant::now() + tokio::time::Duration::from_secs(s));
        loop {
            let mut out = Vec::new();
            for (name, conn) in &targets {
                for entry in drain_inbox(conn) {
                    out.push(entry.into_event(name));
                }
            }
            if !out.is_empty() {
                return Ok(out);
            }
            match deadline {
                // Immediate mode: whatever was pending (possibly nothing).
                None => return Ok(Vec::new()),
                // Waiting mode: an elapsed timeout is an empty result, not an
                // error — nothing arriving is a normal outcome for a poll.
                Some(d) if tokio::time::Instant::now() >= d => return Ok(Vec::new()),
                Some(_) => tokio::time::sleep(tokio::time::Duration::from_millis(200)).await,
            }
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
    /// app device), enforcing `max_turns`. Same relay-then-local-mailbox
    /// fallback chain as [`Self::send_message`] when the target is
    /// unreachable.
    pub async fn say(&self, device_name: &str, text: String, done: Option<bool>, max_turns: u64) -> Result<SayOutcome, CoreError> {
        let conn = match self.ensure_device(device_name).await {
            Ok(c) => c,
            Err(_) => {
                if let Some(outcome) = self.try_deliver_via_relay(device_name, &text).await {
                    return outcome.map(|_| SayOutcome::Queued);
                }
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
                if let Some(outcome) = self.try_deliver_via_relay(device_name, &text).await {
                    return outcome.map(|_| SayOutcome::Queued);
                }
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
    /// dialing or writing anything. Returns the surface id used. Thin
    /// wrapper over [`Self::render_ui_outcome`], discarding whether it went
    /// out live or was coalesced to the relay — kept with this exact
    /// signature since `cli::ui::render` (outside this phase's file
    /// ownership) calls it and only needs the surface id.
    pub async fn render_ui(
        &self,
        device_name: &str,
        components: serde_json::Value,
        data_model: Option<serde_json::Value>,
        surface_id: Option<String>,
    ) -> Result<String, CoreError> {
        self.render_ui_outcome(device_name, components, data_model, surface_id).await.map(|(id, _)| id)
    }

    /// As [`Self::render_ui`], but also reports whether the surface went out
    /// live (`SendOutcome::Sent`) or was coalesced into a full-surface
    /// snapshot delivered to the relay (`SendOutcome::Queued`) because the
    /// device was unreachable but a relay hint is known (mcp-bridge spec:
    /// "render_ui to an offline device with a relay"). With no relay known,
    /// behaves exactly as before: an immediate error, nothing sent.
    pub async fn render_ui_outcome(
        &self,
        device_name: &str,
        components: serde_json::Value,
        data_model: Option<serde_json::Value>,
        surface_id: Option<String>,
    ) -> Result<(String, SendOutcome), CoreError> {
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

        match self.ensure_device(device_name).await {
            Ok(conn) => {
                self.send_a2ui_frame(&conn, serde_json::json!({
                    "version": "v0.9.1",
                    "createSurface": { "surfaceId": surface_id, "catalogId": A2UI_CATALOG_URL }
                })).await?;
                self.send_a2ui_frame(&conn, serde_json::json!({
                    "version": "v0.9.1",
                    "updateComponents": { "surfaceId": surface_id, "components": components }
                })).await?;
                if let Some(dm) = &data_model {
                    self.send_a2ui_frame(&conn, serde_json::json!({
                        "version": "v0.9.1",
                        "updateDataModel": { "surfaceId": surface_id, "path": "", "value": dm }
                    })).await?;
                }
                self.retain_surface_state(device_name, &surface_id, components, data_model).await;
                Ok((surface_id, SendOutcome::Sent))
            }
            Err(unreachable_err) => {
                let Some(ticket) = registry::relay_for(device_name) else { return Err(unreachable_err) };
                self.retain_surface_state(device_name, &surface_id, components.clone(), data_model.clone()).await;
                self.send_snapshot_to_relay(device_name, &ticket, &surface_id, Some(components), data_model).await?;
                Ok((surface_id, SendOutcome::Queued))
            }
        }
    }

    /// Update the data model of a rendered A2UI surface at an RFC 6901
    /// JSON pointer (`""` replaces the whole model). Thin wrapper over
    /// [`Self::update_ui_outcome`] — see [`Self::render_ui`]'s doc for why.
    pub async fn update_ui(&self, device_name: &str, surface_id: &str, path: &str, value: serde_json::Value) -> Result<(), CoreError> {
        self.update_ui_outcome(device_name, surface_id, path, value).await.map(|_| ())
    }

    /// As [`Self::update_ui`], but also reports live-vs-queued (see
    /// [`Self::render_ui_outcome`]). Offline-with-relay coalescing only
    /// works when this session already holds the surface's full state
    /// (rendered earlier in this session, live or via a prior coalesce) —
    /// relay spec: "`update_ui` against an offline phone therefore works
    /// iff the session holds the full surface". With no retained state, this
    /// surfaces the original unreachable error even if a relay is known,
    /// since a valid full-surface snapshot can't be built from a bare
    /// pointer delta.
    pub async fn update_ui_outcome(
        &self,
        device_name: &str,
        surface_id: &str,
        path: &str,
        value: serde_json::Value,
    ) -> Result<SendOutcome, CoreError> {
        match self.ensure_device(device_name).await {
            Ok(conn) => {
                self.send_a2ui_frame(&conn, serde_json::json!({
                    "version": "v0.9.1",
                    "updateDataModel": { "surfaceId": surface_id, "path": path, "value": value }
                })).await?;
                // Keep the retained cache fresh even on the live path, so a
                // *later* update_ui in the same session can still coalesce
                // if the device goes offline mid-session.
                self.apply_data_model_pointer(device_name, surface_id, path, &value).await;
                Ok(SendOutcome::Sent)
            }
            Err(unreachable_err) => {
                let Some(ticket) = registry::relay_for(device_name) else { return Err(unreachable_err) };
                let Some((components, data_model)) =
                    self.apply_data_model_pointer(device_name, surface_id, path, &value).await
                else {
                    return Err(unreachable_err);
                };
                self.send_snapshot_to_relay(device_name, &ticket, surface_id, Some(components), Some(data_model)).await?;
                Ok(SendOutcome::Queued)
            }
        }
    }

    /// Remove an A2UI surface from a device. Thin wrapper over
    /// [`Self::delete_ui_outcome`] — see [`Self::render_ui`]'s doc for why.
    pub async fn delete_ui(&self, device_name: &str, surface_id: &str) -> Result<(), CoreError> {
        self.delete_ui_outcome(device_name, surface_id).await.map(|_| ())
    }

    /// As [`Self::delete_ui`], but also reports live-vs-queued (see
    /// [`Self::render_ui_outcome`]). Unlike `update_ui`, deleting needs no
    /// retained state — the tombstone carries no components — so it always
    /// coalesces to the relay when a relay hint is known, regardless of
    /// whether this session ever rendered the surface itself.
    pub async fn delete_ui_outcome(&self, device_name: &str, surface_id: &str) -> Result<SendOutcome, CoreError> {
        match self.ensure_device(device_name).await {
            Ok(conn) => {
                self.send_a2ui_frame(&conn, serde_json::json!({
                    "version": "v0.9.1",
                    "deleteSurface": { "surfaceId": surface_id }
                })).await?;
                self.surface_state.lock().await.remove(&(device_name.to_string(), surface_id.to_string()));
                Ok(SendOutcome::Sent)
            }
            Err(unreachable_err) => {
                let Some(ticket) = registry::relay_for(device_name) else { return Err(unreachable_err) };
                self.surface_state.lock().await.remove(&(device_name.to_string(), surface_id.to_string()));
                self.send_snapshot_to_relay(device_name, &ticket, surface_id, None, None).await?;
                Ok(SendOutcome::Queued)
            }
        }
    }

    /// Overwrite this session's retained copy of `(device_name, surface_id)`
    /// with a freshly rendered full state — see [`Self::surface_state`]'s
    /// doc comment. `data_model: None` leaves any previously retained data
    /// model as-is (matches `render_ui`'s "no data model" meaning "nothing
    /// to set", not "clear it").
    async fn retain_surface_state(
        &self,
        device_name: &str,
        surface_id: &str,
        components: serde_json::Value,
        data_model: Option<serde_json::Value>,
    ) {
        let mut guard = self.surface_state.lock().await;
        let entry = guard
            .entry((device_name.to_string(), surface_id.to_string()))
            .or_insert_with(|| SurfaceState { components: serde_json::Value::Null, data_model: serde_json::Value::Null });
        entry.components = components;
        if let Some(dm) = data_model {
            entry.data_model = dm;
        }
    }

    /// Apply an RFC 6901 pointer update to this session's retained copy of a
    /// surface's data model (if this session has one — i.e. it rendered or
    /// previously coalesced this surface), returning the resulting full
    /// `(components, data_model)` pair, or `None` if nothing is retained for
    /// `(device_name, surface_id)`. `path == ""` replaces the whole model
    /// with `value`, matching the live path's own convention.
    async fn apply_data_model_pointer(
        &self,
        device_name: &str,
        surface_id: &str,
        path: &str,
        value: &serde_json::Value,
    ) -> Option<(serde_json::Value, serde_json::Value)> {
        let mut guard = self.surface_state.lock().await;
        let state = guard.get_mut(&(device_name.to_string(), surface_id.to_string()))?;
        if path.is_empty() {
            state.data_model = value.clone();
        } else {
            set_at_json_pointer(&mut state.data_model, path, value.clone());
        }
        Some((state.components.clone(), state.data_model.clone()))
    }

    /// Deliver one coalesced A2UI snapshot to the identity's relay
    /// (`Frame::A2uiSnapshot`) — the relay spec's "session that can't reach
    /// the phone SHALL coalesce ... into full-surface snapshots delivered to
    /// the relay". Enforces the 256 KiB per-surface cap client-side first
    /// (design.md D6/task 4.5: "the session checks the 256 KiB cap BEFORE
    /// sending and errors the tool call locally"), so an oversized snapshot
    /// never reaches the wire at all.
    async fn send_snapshot_to_relay(
        &self,
        device_name: &str,
        ticket: &str,
        surface_id: &str,
        components: Option<serde_json::Value>,
        data_model: Option<serde_json::Value>,
    ) -> Result<(), CoreError> {
        let size = serde_json::to_vec(&components).map(|v| v.len()).unwrap_or(0)
            + serde_json::to_vec(&data_model).map(|v| v.len()).unwrap_or(0);
        if size > relay_a2ui::MAX_SNAPSHOT_BYTES {
            return Err(CoreError::Usage(format!(
                "surface '{surface_id}' snapshot is {size} bytes, exceeds the {} byte (256 KiB) relay cap",
                relay_a2ui::MAX_SNAPSHOT_BYTES
            )));
        }

        let conn = self.ensure_relay(ticket).await.map_err(|_| {
            CoreError::Operational(format!("device '{device_name}' is unreachable and its relay is also unreachable"))
        })?;
        let lamport = A2UI_SNAPSHOT_LAMPORT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut send_guard = conn.send.lock().await;
        let Some(send) = send_guard.as_mut() else {
            return Err(CoreError::Operational(format!(
                "device '{device_name}' is unreachable and its relay is also unreachable"
            )));
        };
        write_frame(
            send,
            &Frame::A2uiSnapshot {
                conversation: self.endpoint.id().to_string(),
                surface: surface_id.to_string(),
                components,
                data_model,
                lamport,
            },
        )
        .await
        .map_err(|e| CoreError::Transport(e.to_string()))
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
            match mint_pairing_invite(&self.ticket, self.endpoint.secret_key()) {
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

/// Set `value` at RFC 6901 pointer `path` (e.g. `/dice/you`) within `root`,
/// creating intermediate JSON objects as needed (JSON-Patch-style "add"
/// semantics) — used by [`SessionCore::apply_data_model_pointer`] to build a
/// full data model offline, where (unlike the live path) nothing on the
/// other end applies the pointer for us. `path` must be non-empty (the
/// caller handles `""` — "replace the whole model" — itself); object keys
/// only (array-index tokens are treated as literal object keys, a reasonable
/// degrade for the object-shaped data models the A2UI catalog's bindings
/// use, rather than a panic).
fn set_at_json_pointer(root: &mut serde_json::Value, path: &str, value: serde_json::Value) {
    let tokens: Vec<String> =
        path.split('/').skip(1).map(|t| t.replace("~1", "/").replace("~0", "~")).collect();
    let Some((last, ancestors)) = tokens.split_last() else {
        *root = value;
        return;
    };

    let mut cursor = root;
    for token in ancestors {
        if !cursor.is_object() {
            *cursor = serde_json::Value::Object(serde_json::Map::new());
        }
        cursor = cursor
            .as_object_mut()
            .expect("just ensured this is an object")
            .entry(token.clone())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    }
    if !cursor.is_object() {
        *cursor = serde_json::Value::Object(serde_json::Map::new());
    }
    cursor.as_object_mut().expect("just ensured this is an object").insert(last.clone(), value);
}

/// A pairing invite is only useful if the endpoint that *accepts* the dial it
/// advertises can also redeem it. Minting against the machine identity broke
/// both halves at once: the machine endpoint was bound just long enough to
/// read its ticket and then dropped, so a scanner resolved the peer from the
/// discovery record and hung forever "opening direct path" — and had the dial
/// landed, the gate would have rejected the invite anyway, since
/// [`invite::verify_inbound`] checks the embedded ticket's endpoint id and the
/// signature against the *verifying* endpoint's own key.
///
/// Asserting through `verify_inbound` — the exact call
/// [`crate::accept_gate`]'s gates make — covers ticket binding, signing key,
/// and store membership in one go. A test that only asserted "an `/i/` link
/// came back" (as `bridge::tests::start_pairing_mints_invite_unless_legacy_ticket`
/// does) passes happily against the broken version.
#[cfg(test)]
mod pairing_invite_tests {
    use super::*;

    use iroh::endpoint::presets;
    use iroh::Endpoint;
    use iroh_tickets::endpoint::EndpointTicket;

    #[tokio::test]
    async fn pairing_invite_is_redeemable_by_the_accepting_endpoint() {
        // Holds ENV_TEST_LOCK: this mutates the process-global
        // AZULA_INVITES_DIR, which concurrent tests also mutate.
        let _guard = crate::registry::ENV_TEST_LOCK.lock().await;
        let invites_dir = std::env::temp_dir()
            .join(format!("azula-core-test-{}", std::process::id()))
            .join("pairing_invite_binds_to_accepting_endpoint");
        let _ = std::fs::remove_dir_all(&invites_dir);
        std::env::set_var("AZULA_INVITES_DIR", &invites_dir);

        let ep = Endpoint::bind(presets::Minimal).await.unwrap();
        let ticket = EndpointTicket::new(ep.addr()).to_string();

        let encoded =
            mint_pairing_invite(&ticket, ep.secret_key()).expect("minting the pairing invite succeeds");

        let my_id = ep.id();
        let verified = invite::verify_inbound(&encoded, my_id, &my_id)
            .expect("the accepting endpoint must be able to redeem its own pairing invite");
        assert!(!verified.invite_id.is_empty(), "a redeemed invite carries its id");

        std::env::remove_var("AZULA_INVITES_DIR");
        ep.close().await;
    }
}

#[cfg(test)]
mod pointer_tests {
    use super::set_at_json_pointer;

    #[test]
    fn sets_a_top_level_key() {
        let mut root = serde_json::json!({});
        set_at_json_pointer(&mut root, "/you", serde_json::json!(6));
        assert_eq!(root, serde_json::json!({"you": 6}));
    }

    #[test]
    fn creates_intermediate_objects() {
        let mut root = serde_json::json!({});
        set_at_json_pointer(&mut root, "/dice/you", serde_json::json!(6));
        assert_eq!(root, serde_json::json!({"dice": {"you": 6}}));
    }

    #[test]
    fn overwrites_an_existing_value_in_place() {
        let mut root = serde_json::json!({"dice": {"you": 3, "them": 5}});
        set_at_json_pointer(&mut root, "/dice/you", serde_json::json!(6));
        assert_eq!(root, serde_json::json!({"dice": {"you": 6, "them": 5}}));
    }

    #[test]
    fn decodes_tilde_escapes() {
        let mut root = serde_json::json!({});
        set_at_json_pointer(&mut root, "/a~1b/c~0d", serde_json::json!(1));
        assert_eq!(root, serde_json::json!({"a/b": {"c~d": 1}}));
    }
}

/// `SessionCore`'s delivery-chain and relay-coalescing behavior (task 4.7).
/// Uses real iroh endpoints on localhost (not duplexes) since `send_message`/
/// `render_ui`'s relay path dials out via `device::connect_device`, the same
/// production code path `establish` uses.
#[cfg(test)]
mod relay_tests {
    use super::*;
    use std::collections::HashMap;

    use iroh::endpoint::presets;
    use iroh::{Endpoint, SecretKey};
    use iroh_tickets::endpoint::EndpointTicket;

    fn seed(start: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = start.wrapping_add(i as u8);
        }
        s
    }

    /// Set the trio of env-var overrides these tests need (registry, mailbox,
    /// relay A2UI store) at a fresh isolated directory, holding
    /// `registry::ENV_TEST_LOCK` for the caller's whole test body (same
    /// convention as every other module's env-var-mutating tests).
    fn isolate(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("azula-core-relay-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("AZULA_REGISTRY_DIR", dir.join("registry"));
        std::env::set_var("AZULA_MAILBOX_DIR", dir.join("mailbox"));
        std::env::set_var("AZULA_RELAY_A2UI_DIR", dir.join("relay-a2ui"));
        dir
    }

    fn unisolate() {
        std::env::remove_var("AZULA_REGISTRY_DIR");
        std::env::remove_var("AZULA_MAILBOX_DIR");
        std::env::remove_var("AZULA_RELAY_A2UI_DIR");
    }

    async fn bare_core(machine_secret: Option<SecretKey>, session_cert: String) -> SessionCore {
        let ep = Endpoint::builder(presets::Minimal).bind().await.expect("bind session endpoint");
        SessionCore::from_parts(
            Arc::new(ep),
            Arc::new(AsyncMutex::new(HashMap::new())),
            "test".to_string(),
            "session-ticket".to_string(),
            "session".to_string(),
            session_cert,
            machine_secret,
        )
    }

    /// A real relay endpoint serving `mailbox_role::RelayLlmHandler`,
    /// admitting sessions whose cert chains to `machine_root`. Returns its
    /// dial ticket, its `LogStore` (to assert what landed as `agent_in`),
    /// and its `RelayA2uiStore` (to assert A2UI snapshots).
    async fn spawn_fake_relay(
        name: &str,
        machine_root: iroh::PublicKey,
    ) -> (String, crate::sync::LogStore, relay_a2ui::RelayA2uiStore, iroh::PublicKey) {
        let relay_ep = Endpoint::builder(presets::Minimal).bind().await.expect("bind relay endpoint");
        let relay_ticket = EndpointTicket::new(relay_ep.addr()).to_string();
        let relay_device_secret = SecretKey::generate();
        let relay_device_pk = relay_device_secret.public();
        let store = crate::sync::LogStore::open(
            std::env::temp_dir().join(format!("azula-core-relay-test-store-{}-{name}", std::process::id())),
            machine_root,
        )
        .expect("open relay log store");
        let a2ui_store = relay_a2ui::RelayA2uiStore::open(
            std::env::temp_dir().join(format!("azula-core-relay-test-a2ui-{}-{name}", std::process::id())),
            machine_root,
        )
        .expect("open relay a2ui store");
        let known_roots = Arc::new(AsyncMutex::new(vec![machine_root]));
        let handler = crate::mailbox_role::RelayLlmHandler::new(
            Arc::new(relay_device_secret),
            store.clone(),
            a2ui_store.clone(),
            known_roots,
        );
        let _router = Router::builder(relay_ep).accept(LLM_ALPN, handler).spawn();
        // Leak the router so it keeps serving for the test's lifetime — a
        // background test process, not something that needs clean shutdown.
        std::mem::forget(_router);
        (relay_ticket, store, a2ui_store, relay_device_pk)
    }

    #[tokio::test]
    async fn send_message_falls_back_to_local_mailbox_when_no_relay_is_known() {
        let _guard = registry::ENV_TEST_LOCK.lock().await;
        isolate("no_relay");

        let core = bare_core(None, "azd-fake-session-cert".to_string()).await;
        let outcome = core.send_message("ghost-device", "hi there".to_string()).await.unwrap();
        assert!(matches!(outcome, SendOutcome::Queued));
        assert!(!mailbox::load("ghost-device").is_empty(), "must have queued locally");

        unisolate();
    }

    #[tokio::test]
    async fn send_message_prefers_relay_over_local_mailbox_when_a_relay_hint_is_known() {
        let _guard = registry::ENV_TEST_LOCK.lock().await;
        isolate("prefers_relay");

        let machine = SecretKey::from_bytes(&seed(0x70));
        let (relay_ticket, relay_store, _a2ui, relay_device_pk) =
            spawn_fake_relay("prefers_relay", machine.public()).await;

        let session_ep = Endpoint::builder(presets::Minimal).bind().await.unwrap();
        let session_cert =
            certs::mint_session_cert(&machine, session_ep.id(), certs::DEFAULT_SESSION_EXPIRY).encode();
        let core = SessionCore::from_parts(
            Arc::new(session_ep.clone()),
            Arc::new(AsyncMutex::new(HashMap::new())),
            "test".to_string(),
            "session-ticket".to_string(),
            "session".to_string(),
            session_cert,
            Some(machine.clone()),
        );

        registry::set_relay("phone", &relay_ticket).unwrap();

        let outcome = core.send_message("phone", "hello from claude".to_string()).await.unwrap();
        assert!(matches!(outcome, SendOutcome::Queued));

        // Wait for the relay to fold the Chat frame into an agent_in entry.
        let entries = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let entries = relay_store.read_from(&relay_device_pk, 0).await.unwrap();
                if !entries.is_empty() {
                    return entries;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("timed out waiting for agent_in to land on the relay");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, crate::eventlog::Kind::AgentIn);
        let body: crate::eventlog::AgentInBody = serde_json::from_str(&entries[0].body).unwrap();
        assert_eq!(body.conversation, session_ep.id().to_string(), "conversation keyed by the session's own pk");
        assert_eq!(body.text, "hello from claude");

        assert!(
            mailbox::load("phone").is_empty(),
            "must NOT have fallen back to the local mailbox once the relay took it"
        );

        unisolate();
    }

    #[tokio::test]
    async fn oversized_a2ui_snapshot_is_rejected_client_side_before_any_relay_dial() {
        let _guard = registry::ENV_TEST_LOCK.lock().await;
        isolate("oversized");

        let core = bare_core(None, "azd-fake-session-cert".to_string()).await;
        // An unresolvable relay ticket -- if the cap check didn't run first,
        // this would hang/fail on a dial attempt instead of erroring fast.
        registry::set_relay("phone", "not-a-real-ticket").unwrap();

        let huge = serde_json::json!({"id": "root", "text": "x".repeat(relay_a2ui::MAX_SNAPSHOT_BYTES + 1)});
        let err = core.render_ui("phone", serde_json::json!([huge]), None, Some("dice-1".to_string())).await.unwrap_err();
        assert!(matches!(err, CoreError::Usage(_)));
        assert!(err.to_string().contains("256 KiB"), "{err}");

        unisolate();
    }
}
