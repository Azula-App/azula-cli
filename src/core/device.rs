//! Per-device connection state: the live device map, dialing (outbound) and
//! the accept-side handler (inbound) that registers azula app / peer-bridge
//! connections, and reconnect-by-endpoint-id matching.
//!
//! Both directions converge on the same [`DeviceMap`]: a [`Dialer`] fills
//! in an entry when a [`super::SessionCore`] dials out, and
//! [`BridgeAcceptHandler`] fills in (or updates) an entry when a device dials
//! in. Each entry's [`Inbox`] is fed by a background reader task for the
//! lifetime of that connection. That reader also reassembles inbound
//! `file_begin`/`file_chunk`/`file_end` sequences (see [`crate::filexfer`]),
//! writing completed files to disk and surfacing a `[received file: ...]`
//! text line into the inbox.
//!
//! A connection's reader task also owns the *end* of that connection: when the
//! stream ends (EOF, error, the connection closing) it marks the device
//! disconnected, drops the dead send handle, and tells the inbox, so the next
//! send or presence tick redials rather than writing into a link that is gone.
//! Every successful dial or accept likewise reports `connected`. Both reach
//! consumers as `connected`/`disconnected` events from `get_events`.
//!
//! Moved here from the old `bridge::device` (cli-multi-session-relay phase 2)
//! so both the MCP tool layer (`bridge::tools`) and the CLI verbs (`cli::*`)
//! share one connection-management implementation via [`super::SessionCore`].

use super::watch::InboxEntry;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::str::FromStr;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use iroh_tickets::endpoint::EndpointTicket;
use tokio::io::BufReader;
use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, info, warn};

use crate::filexfer::{self, FileAssembler};
use crate::invite;
use crate::mailbox;
use crate::mcp::LLM_ALPN;
use crate::proto::{read_frame, write_frame, Frame};
use crate::registry::{self, Device};

use super::state::write_state;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// `Inbox`/`DeviceConn`/`DeviceMap` are `pub` (not `pub(crate)`): they appear
// in `SessionCore`'s own public fields/method signatures (`devices`,
// `ensure_device`, `lookup_device`), so anything that can see `SessionCore`
// must also be able to name these types. The dial/accept machinery below
// stays `pub(crate)` — only used by `core::establish` and same-crate tests.
pub type Inbox = Arc<std::sync::Mutex<VecDeque<InboxEntry>>>;
pub type AppSend = Arc<AsyncMutex<Option<SendStream>>>;

/// Per-device live state.
#[derive(Clone, Debug)]
pub struct DeviceConn {
    pub send: AppSend,
    pub inbox: Inbox,
    pub ticket: String,
    /// The encoded invite string (`"azi…"`) this device was paired with, if
    /// any — re-presented in `Hello` on every (re)dial per the invitations
    /// spec, until the issuer has accepted and this becomes a known peer.
    pub invite: Option<String>,
    pub connected: bool,
    /// Turn counter for peer bridge conversations.
    pub turns: Arc<std::sync::atomic::AtomicU64>,
    /// Whether this conversation has been closed (turn limit or explicit done).
    pub closed: Arc<std::sync::atomic::AtomicBool>,
    /// Which connection currently owns this entry (`0` = none yet). Every
    /// dial/accept takes a fresh one from [`next_generation`]; a connection's
    /// reader compares it when its stream ends, so a *superseded* connection
    /// winding down can never mark its live replacement disconnected.
    pub(crate) generation: u64,
    /// Serialises dials to this device. Lives in the shared map entry (not in
    /// any one `SessionCore`) so the startup dial, `ensure_device`, the
    /// presence loop and `azula mcp`'s separate tool-layer core all queue
    /// behind each other instead of racing out two connections.
    pub(crate) dial_lock: Arc<AsyncMutex<()>>,
    /// Bumped each time a dial to this device finishes, whether it connected or
    /// not. A caller that queued behind someone else's dial sees it changed and
    /// shares that outcome instead of immediately dialing again — otherwise a
    /// one-shot verb whose device is unreachable would sit out the startup
    /// dial's failure and then its own, twice the wait it had when they ran in
    /// parallel.
    pub(crate) dial_seq: u64,
    /// Set by an explicit `disconnect`: the presence loop leaves a held device
    /// alone (the operator asked for it to be down) until something connects it
    /// again — a send's lazy redial, or the device dialing in.
    pub(crate) held: bool,
}

/// Source of connection generations. `0` is reserved for "never connected".
static NEXT_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn next_generation() -> u64 {
    NEXT_GENERATION.fetch_add(1, Relaxed)
}

impl DeviceConn {
    pub fn new(ticket: String) -> Self {
        DeviceConn {
            send: Arc::new(AsyncMutex::new(None)),
            inbox: Arc::new(std::sync::Mutex::new(VecDeque::new())),
            ticket,
            invite: None,
            connected: false,
            turns: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            closed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            generation: 0,
            dial_lock: Arc::new(AsyncMutex::new(())),
            dial_seq: 0,
            held: false,
        }
    }

    /// Make `send` this entry's live stream on a brand-new connection: take a
    /// fresh generation (returned), lift any explicit-disconnect hold, and — if
    /// the device was down — put a `connected` event in the inbox. The inbox
    /// itself is *kept* across reconnects: a consumer long-polling it must see
    /// the reconnect and what follows, and whatever the peer sent just before a
    /// drop must not vanish with a swapped-out queue.
    async fn attach(&mut self, send: SendStream) -> u64 {
        *self.send.lock().await = Some(send);
        let was_connected = std::mem::replace(&mut self.connected, true);
        self.held = false;
        self.generation = next_generation();
        if !was_connected {
            push_entry(&self.inbox, InboxEntry::Connected);
        }
        self.generation
    }

    pub fn with_invite(mut self, invite: Option<String>) -> Self {
        self.invite = invite;
        self
    }

    /// Reset conversation state (turns=0, closed=false) — call on (re)connect.
    pub fn reset_conversation(&self) {
        self.turns.store(0, Relaxed);
        self.closed.store(false, Relaxed);
    }
}

pub type DeviceMap = Arc<AsyncMutex<HashMap<String, DeviceConn>>>;

// ---------------------------------------------------------------------------
// iroh dial helper
// ---------------------------------------------------------------------------

/// Resolve a stored device ticket to an address iroh can dial.
///
/// The registry holds two shapes (see [`registry::endpoint_id_of`]): a full
/// `EndpointTicket` — written by `azula pair` and by an outbound `connect`,
/// carrying whatever addresses were known — and a *bare endpoint id*, which is
/// all accept-side registration has for a phone that scanned this session's QR
/// and dialed in. The second used to fail to parse here, so a phone paired that
/// way could never be dialed back: after any restart of the session it stayed
/// offline until the phone itself dialed in. A bare id is dialed by id alone and
/// left to iroh's address lookup (DNS + relay) to find.
pub(crate) fn dial_target(ticket_str: &str) -> Result<EndpointAddr> {
    match EndpointTicket::from_str(ticket_str) {
        Ok(ticket) => Ok(ticket.endpoint_addr().clone()),
        Err(ticket_err) => match EndpointId::from_str(ticket_str.trim()) {
            Ok(id) => Ok(EndpointAddr::from(id)),
            Err(_) => Err(ticket_err.into()),
        },
    }
}

pub(crate) async fn dial_device(
    endpoint: &Endpoint,
    ticket_str: &str,
) -> Result<(SendStream, RecvStream)> {
    let addr = dial_target(ticket_str)?;
    let conn = endpoint.connect(addr, LLM_ALPN).await?;
    Ok(conn.open_bi().await?)
}

/// How a dial request relates to a connection that may already exist or be in
/// progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DialPolicy {
    /// Dial regardless (an explicit `connect`). Still queues behind an
    /// in-flight dial to the same device rather than racing it.
    Always,
    /// Dial unless the device is connected by the time this caller holds the
    /// dial lock. A caller that arrives mid-dial waits for it and reuses its
    /// result — the lazy-redial paths (`ensure_device`, startup).
    IfDisconnected,
    /// Background maintenance: skip — never wait — if the device is connected,
    /// held, mid-dial, or no longer known. Never creates an entry.
    IfIdle,
}

/// What a [`Dialer`] request came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DialOutcome {
    /// A new connection was established and registered.
    Connected,
    /// Nothing to do: the device was already connected.
    AlreadyConnected,
    /// The dial failed (unreachable, refused, or the handshake write failed).
    Failed,
    /// [`DialPolicy::IfIdle`] declined: a dial is in flight, the device is held,
    /// or it is gone.
    Skipped,
}

impl DialOutcome {
    /// Whether the device is up as a result of this request.
    pub(crate) fn is_up(self) -> bool {
        matches!(self, DialOutcome::Connected | DialOutcome::AlreadyConnected)
    }
}

/// Everything needed to dial peers *as this session*: the endpoint, the device
/// map it fills in, the identity presented in `Hello`, and the runtime-state
/// label refreshed whenever a link comes up or goes down. Cheap to clone; the
/// presence loop holds one.
#[derive(Clone)]
pub(crate) struct Dialer {
    pub(crate) endpoint: Arc<Endpoint>,
    pub(crate) devices: DeviceMap,
    pub(crate) own_name: String,
    /// This session's `azd…` certificate, presented in every `Hello`.
    pub(crate) cert: Option<String>,
    /// The operator's `--description` (the conversation sub-line), announced as
    /// a `Frame::Profile` on every connection this dialer makes. `Hello` carries
    /// only a name, so the sub-line needs its own frame; sending it here means
    /// every path that dials — startup, a verb's lazy redial, the presence
    /// loop — gets it, not just whichever one thought to.
    pub(crate) description: Option<String>,
    /// The runtime-state label (`bridge.json`'s `bind`); `None` skips the
    /// state-file refresh (the relay's connection cache has no state file).
    pub(crate) label: Option<String>,
}

impl Dialer {
    /// Dial `name` at `ticket` and register it, whether or not it is already
    /// connected. Returns whether a connection was established.
    pub(crate) async fn connect(&self, name: &str, ticket: &str, invite: Option<&str>) -> bool {
        self.run(name, Some((ticket, invite)), DialPolicy::Always).await == DialOutcome::Connected
    }

    /// Make sure `name` is connected, dialing it if not. Creates the map entry
    /// from `ticket`/`invite` when the device isn't in the map yet; an existing
    /// entry's own ticket and invite win. Returns whether the device is up.
    pub(crate) async fn ensure(&self, name: &str, ticket: &str, invite: Option<&str>) -> bool {
        self.run(name, Some((ticket, invite)), DialPolicy::IfDisconnected).await.is_up()
    }

    /// One background redial attempt at a device that is already in the map.
    pub(crate) async fn redial_idle(&self, name: &str) -> DialOutcome {
        self.run(name, None, DialPolicy::IfIdle).await
    }

    async fn run(&self, name: &str, seed: Option<(&str, Option<&str>)>, policy: DialPolicy) -> DialOutcome {
        // One entry per device from the first dial on, so concurrent callers
        // share one dial lock.
        let (dial_lock, seq_before) = {
            let mut guard = self.devices.lock().await;
            let conn = match (guard.contains_key(name), seed) {
                (true, _) => guard.get_mut(name).expect("contains_key just checked"),
                (false, Some((ticket, invite))) => guard
                    .entry(name.to_string())
                    .or_insert_with(|| DeviceConn::new(ticket.to_string()).with_invite(invite.map(String::from))),
                (false, None) => return DialOutcome::Skipped,
            };
            if policy != DialPolicy::Always && conn.connected {
                return DialOutcome::AlreadyConnected;
            }
            if policy == DialPolicy::IfIdle && conn.held {
                return DialOutcome::Skipped;
            }
            (conn.dial_lock.clone(), conn.dial_seq)
        };

        let _dialing = if policy == DialPolicy::IfIdle {
            match dial_lock.try_lock_owned() {
                Ok(held) => held,
                Err(_) => return DialOutcome::Skipped,
            }
        } else {
            dial_lock.lock_owned().await
        };

        // Re-check now that we hold the lock: whoever we queued behind may have
        // connected the device, and an explicit `connect` may have changed its
        // ticket. Read what to dial from the entry, not from the caller's
        // (possibly stale) snapshot.
        let (ticket, invite) = {
            let guard = self.devices.lock().await;
            match guard.get(name) {
                None => return DialOutcome::Skipped,
                Some(conn) if policy != DialPolicy::Always => {
                    if conn.connected {
                        return DialOutcome::AlreadyConnected;
                    }
                    if conn.dial_seq != seq_before {
                        // A dial finished while we waited and left the device
                        // down: that is our answer too. (Dialing again here is
                        // what the next presence tick, or the caller's next
                        // attempt, is for.)
                        return DialOutcome::Failed;
                    }
                    if policy == DialPolicy::IfIdle && conn.held {
                        return DialOutcome::Skipped;
                    }
                    (conn.ticket.clone(), conn.invite.clone())
                }
                Some(conn) => match seed {
                    Some((ticket, invite)) => (ticket.to_string(), invite.map(String::from)),
                    None => (conn.ticket.clone(), conn.invite.clone()),
                },
            }
        };

        let connected = self.dial_registered(name, &ticket, invite.as_deref(), policy == DialPolicy::IfIdle).await;
        // Still holding the dial lock, so a waiter sees this before it runs.
        if let Some(conn) = self.devices.lock().await.get_mut(name) {
            conn.dial_seq += 1;
        }
        if connected {
            DialOutcome::Connected
        } else {
            DialOutcome::Failed
        }
    }

    /// The dial itself. Sends `Frame::Hello { name: own_name, invite, cert }`
    /// as the very first frame (presenting `invite` — the encoded invite string,
    /// if this device was paired via one, so an unknown-to-the-peer dial can
    /// pass its accept gate — and `cert` — this session's own `azd…`
    /// certificate, so a peer that already trusts our machine root can
    /// auto-admit us without an invite at all, see `certs.rs`/design.md D1),
    /// then the `thinking(false)` handshake, then flushes the mailbox. On
    /// success it registers the connection (resetting the conversation) and
    /// starts its reader. Every dial path goes through here, so a presence
    /// redial does exactly what the startup dial does.
    ///
    /// `quiet` demotes the failure log from warn to debug: a background retry
    /// of a phone that is asleep fails every minute, and that is not news.
    async fn dial_registered(&self, name: &str, ticket: &str, invite: Option<&str>, quiet: bool) -> bool {
        let (mut send, recv) = match dial_device(&self.endpoint, ticket).await {
            Ok(streams) => streams,
            Err(e) => {
                if quiet {
                    debug!(device=%name, error=%e, "bridge: redial failed; device stays disconnected");
                } else {
                    warn!(device=%name, error=%e, "bridge: could not connect; device shows disconnected");
                }
                return false;
            }
        };
        // Send hello so the peer can name us (and verify our invite/cert, if any).
        let hello = Frame::Hello { name: self.own_name.clone(), invite: invite.map(String::from), cert: self.cert.clone() };
        if let Err(e) = write_frame(&mut send, &hello).await {
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
        if let Some(description) = &self.description {
            let profile = Frame::Profile {
                name: self.own_name.clone(),
                description: Some(description.clone()),
                avatar: None,
                mime: None,
            };
            if let Err(e) = write_frame(&mut send, &profile).await {
                warn!(device=%name, error=%e, "bridge: profile write failed (continuing)");
            }
        }

        let (generation, inbox) = {
            let mut guard = self.devices.lock().await;
            let conn = guard
                .entry(name.to_string())
                .or_insert_with(|| DeviceConn::new(ticket.to_string()).with_invite(invite.map(String::from)));
            let generation = conn.attach(send).await;
            conn.ticket = ticket.to_string();
            conn.invite = invite.map(String::from);
            conn.reset_conversation();
            (generation, conn.inbox.clone())
        };
        tokio::spawn(reader_task(recv, inbox, self.devices.clone(), name.to_string(), generation, self.label.clone()));
        info!(device=%name, "bridge: connected");
        if let Some(label) = &self.label {
            write_state(label, &self.devices).await;
        }
        true
    }
}

/// Drive one connection's inbound half, then record that it ended.
async fn reader_task(
    recv: RecvStream,
    inbox: Inbox,
    devices: DeviceMap,
    device_name: String,
    generation: u64,
    state_label: Option<String>,
) {
    read_frames_into(BufReader::new(recv), inbox, &device_name).await;
    connection_ended(&devices, &device_name, generation, state_label.as_deref()).await;
}

/// A connection's stream has ended (EOF, error, or the connection closing).
///
/// If it is still the device's *current* connection, mark the device
/// disconnected, drop the dead send handle (best effort — a writer mid-flight
/// holds that lock, and its write fails on its own), and queue a `disconnected`
/// event; the next send then redials via `ensure_device`, and the presence loop
/// picks the device up. A connection that was already superseded or explicitly
/// disconnected changes nothing, so it can't take a live replacement down.
pub(crate) async fn connection_ended(devices: &DeviceMap, name: &str, generation: u64, state_label: Option<&str>) {
    let went_down = {
        let mut guard = devices.lock().await;
        match guard.get_mut(name) {
            Some(conn) if conn.connected && conn.generation == generation => {
                conn.connected = false;
                if let Ok(mut send) = conn.send.try_lock() {
                    *send = None;
                }
                push_entry(&conn.inbox, InboxEntry::Disconnected);
                true
            }
            _ => false,
        }
    };
    if went_down {
        info!(device=%name, "bridge: connection ended; device shows disconnected");
        if let Some(label) = state_label {
            write_state(label, devices).await;
        }
    }
}

/// State for one in-flight inbound file transfer, keyed by `FileBegin.id`.
struct PendingFile {
    name: String,
    mime: String,
    caption: Option<String>,
    assembler: FileAssembler,
}

/// In-flight inbound file transfers for one connection, keyed by transfer id.
/// Lives for the lifetime of a single reader loop — no locking needed since
/// only that loop (and the one-shot first-frame replay in `accept_incoming`,
/// which shares the same map) ever touches it.
type Transfers = HashMap<String, PendingFile>;

fn push_entry(inbox: &Inbox, entry: InboxEntry) {
    // A poisoned inbox mutex (a prior holder panicked mid-push) shouldn't cascade
    // into every subsequent frame for this device — recover the inner value.
    inbox.lock().unwrap_or_else(|e| e.into_inner()).push_back(entry);
}

/// Push a single frame into an inbox (Chat → text, A2uiAction → `ui-event:`
/// line), or fold it into an in-flight file transfer (FileBegin/FileChunk/
/// FileEnd) — completed transfers are written to disk and surfaced as a
/// `[received file: ...]` text line.
fn push_frame(inbox: &Inbox, transfers: &mut Transfers, frame: Frame) {
    match frame {
        Frame::Chat { text, .. } => push_entry(inbox, InboxEntry::Message(text)),
        Frame::A2uiAction { action } => {
            // Kept as the payload itself, not a rendered line: this is the
            // difference between a tap and a user typing "ui-event: {...}".
            let payload = serde_json::to_value(&action).unwrap_or(serde_json::Value::Null);
            push_entry(inbox, InboxEntry::UiEvent(payload));
        }
        Frame::FileBegin { id, name, mime, size, encoding, caption } => {
            if encoding != filexfer::ENCODING_BASE64 {
                // The app only ever sends base64 from its File-attach path;
                // skip gracefully rather than erroring the whole stream.
                warn!(id = %id, %encoding, "bridge: incoming file uses unsupported encoding; skipping");
                return;
            }
            if size > filexfer::MAX_FILE_BYTES {
                warn!(id = %id, %name, size, "bridge: incoming file exceeds max size; rejecting");
                push_entry(inbox, InboxEntry::Notice(format!(
                    "[rejected file: {name} ({size} bytes) exceeds the {} byte (64 MiB) limit]",
                    filexfer::MAX_FILE_BYTES
                )));
                return;
            }
            transfers.insert(id, PendingFile { name, mime, caption, assembler: FileAssembler::new() });
        }
        Frame::FileChunk { id, data, .. } => {
            let Some(pending) = transfers.get_mut(&id) else {
                // Stray chunk for an unknown (or rejected/oversize) id — skip.
                return;
            };
            if let Err(e) = pending.assembler.push_chunk(&data) {
                warn!(id = %id, error = %e, "bridge: bad file chunk; dropping transfer");
                transfers.remove(&id);
            }
        }
        Frame::FileEnd { id } => {
            let Some(pending) = transfers.remove(&id) else {
                // Stray end for an unknown (or already-dropped) id — skip.
                return;
            };
            let bytes = pending.assembler.finish();
            let size = bytes.len();
            match filexfer::save_received_file(&filexfer::received_dir(), &pending.name, &bytes) {
                Ok(path) => {
                    push_entry(
                        inbox,
                        InboxEntry::File {
                            name: pending.name,
                            mime: pending.mime,
                            size: size as u64,
                            path: path.display().to_string(),
                            caption: pending.caption,
                        },
                    );
                }
                Err(e) => {
                    warn!(id = %id, name = %pending.name, error = %e, "bridge: failed to save received file");
                    push_entry(
                        inbox,
                        InboxEntry::Notice(format!("[failed to save received file '{}': {e}]", pending.name)),
                    );
                }
            }
        }
        _ => {}
    }
}

/// Drain frames from a buffered reader into a device inbox. Chat text passes
/// through verbatim; an A2UI action becomes a parseable `ui-event:` line so the
/// LLM can react (match on surfaceId and respond with `update_ui`); file
/// transfers are reassembled and surfaced once complete (see [`push_frame`]).
/// A `Frame::RelayHint` (relay spec: the phone shares the identity's relay
/// ticket "at machine pairing time") is parsed and persisted
/// (`registry::set_relay`) rather than surfaced as an inbox line — `device_name`
/// is the registry name this connection is filed under. Generic over the
/// reader so the behavior is unit-testable over an in-memory pipe.
pub(crate) async fn read_frames_into<R: tokio::io::AsyncRead + Unpin>(reader: BufReader<R>, inbox: Inbox, device_name: &str) {
    read_frames_into_with(reader, inbox, Transfers::new(), device_name).await
}

/// As [`read_frames_into`], but seeded with an existing `transfers` map — used
/// by `accept_incoming` so a file transfer started by a replayed first frame
/// isn't lost when handing off to the main read loop.
async fn read_frames_into_with<R: tokio::io::AsyncRead + Unpin>(
    mut reader: BufReader<R>,
    inbox: Inbox,
    mut transfers: Transfers,
    device_name: &str,
) {
    loop {
        match read_frame(&mut reader).await {
            Ok(Some(Frame::RelayHint { ticket })) => match registry::set_relay(device_name, &ticket) {
                Ok(path) => info!(device = %device_name, path = %path.display(), "core: learned relay hint"),
                Err(e) => warn!(device = %device_name, error = %e, "core: failed to persist relay hint"),
            },
            Ok(Some(frame)) => push_frame(&inbox, &mut transfers, frame),
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
async fn flush_mailbox(device: &str, send: &mut SendStream) -> Result<()> {
    let frames = mailbox::load(device);
    if frames.is_empty() {
        return Ok(());
    }
    for f in &frames {
        write_frame(send, f).await?;
    }
    mailbox::clear(device);
    Ok(())
}

// ---------------------------------------------------------------------------
// Endpoint-id matching — reconnect recognition
// ---------------------------------------------------------------------------

/// Given the endpoint id of an inbound connection, look it up against all known
/// devices (from the in-memory map and the registry) and return the existing
/// device name if a ticket matches.
///
/// This is a pure function (no I/O) so it is easily unit-tested.
pub(crate) fn match_known_device(
    remote_endpoint_id: &EndpointId,
    map_devices: &HashMap<String, DeviceConn>,
    registry_devices: &[Device],
) -> Option<String> {
    let remote_str = remote_endpoint_id.to_string();

    // Chain in-memory map entries and registry entries together, preferring
    // in-memory (project wins, same as registry::load()).
    let ticket_iter = {
        // Collect (name, ticket) pairs: in-memory map first, then registry
        // for names not already in the map.
        let mut pairs: Vec<(String, String)> = map_devices
            .iter()
            .map(|(n, c)| (n.clone(), c.ticket.clone()))
            .collect();
        for d in registry_devices {
            if !pairs.iter().any(|(n, _)| n == &d.name) {
                pairs.push((d.name.clone(), d.ticket.clone()));
            }
        }
        pairs
    };

    for (name, ticket) in ticket_iter {
        // Both stored shapes: a dialable `EndpointTicket` and the bare endpoint
        // id accept-side registration writes. Only the first used to match, so a
        // phone paired by dialing in was not recognised when it came back.
        if registry::endpoint_id_of(&ticket).is_some_and(|id| id.to_string() == remote_str) {
            return Some(name);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Accept handler — registers phones that scan the bridge's QR and dial in
// ---------------------------------------------------------------------------

/// iroh `ProtocolHandler` that accepts incoming azula app connections on
/// `LLM_ALPN` and registers each as a device in the shared map.
#[derive(Clone, Debug)]
pub(crate) struct BridgeAcceptHandler {
    devices: DeviceMap,
    bind: String,
    /// The name this bridge announces to apps that connect in (the conversation
    /// title on the phone), e.g. "Claude".
    own_name: String,
    /// Our own endpoint id — the invite-verification audience (rule 2: the
    /// invite's embedded ticket must name *us*) and signature-verification key.
    my_endpoint_id: EndpointId,
    /// This session's own `azd…` certificate (design.md D1/D3), sent back to
    /// an app that dials in so it can recognise our machine root on future
    /// connections without an invite.
    own_cert: String,
    /// Counter to assign monotonically-increasing names to scanned devices.
    scan_counter: Arc<std::sync::atomic::AtomicU32>,
}

impl BridgeAcceptHandler {
    pub(crate) fn new(
        devices: DeviceMap,
        bind: String,
        own_name: String,
        my_endpoint_id: EndpointId,
        own_cert: String,
    ) -> Self {
        Self {
            devices,
            bind,
            own_name,
            my_endpoint_id,
            own_cert,
            scan_counter: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        }
    }
}

impl ProtocolHandler for BridgeAcceptHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        accept_incoming(
            connection,
            self.devices.clone(),
            self.bind.clone(),
            self.own_name.clone(),
            self.scan_counter.clone(),
            self.my_endpoint_id,
            self.own_cert.clone(),
        )
        .await
        .map_err(|e| AcceptError::from_boxed(e.into()))
    }
}

/// 15 s cap on waiting for a stranger's first frame — long enough for a real
/// dial, short enough that a silent connection doesn't tie up an accept slot.
const STRANGER_HELLO_TIMEOUT: Duration = Duration::from_secs(15);

#[allow(clippy::too_many_arguments)]
async fn accept_incoming(
    connection: Connection,
    devices: DeviceMap,
    bind: String,
    own_name: String,
    counter: Arc<std::sync::atomic::AtomicU32>,
    my_endpoint_id: EndpointId,
    own_cert: String,
) -> Result<()> {
    let remote_id = connection.remote_id();
    let remote_id_str = remote_id.to_string();
    let fallback_name = if remote_id_str.len() >= 8 {
        format!("scan-{}", &remote_id_str[..8])
    } else {
        let n = counter.fetch_add(1, Relaxed);
        format!("scan-{n}")
    };

    info!(%fallback_name, "bridge: incoming connection");

    // --- Endpoint-id match: check if this is a known registered device ---
    // Snapshot current map entries and registry to avoid holding the lock
    // across async I/O (the bi-stream accept and frame read below).
    let endpoint_id_match: Option<String> = {
        let guard = devices.lock().await;
        let reg = registry::load();
        match_known_device(&remote_id, &guard, &reg)
    };
    if let Some(ref matched) = endpoint_id_match {
        info!(peer=%matched, "bridge: recognised reconnecting device by endpoint id");
    }
    let known = endpoint_id_match.is_some();

    // The dialer opens the bi stream.
    let (mut send, recv) = connection.accept_bi().await?;
    let mut reader = BufReader::new(recv);

    // Read the very first frame. Known peers connect exactly as before (no
    // gate, no timeout); a stranger gets a 15s cap on top of the accept-gate
    // check below (invitations spec's verification rules).
    let first_frame = if known {
        read_frame(&mut reader).await
    } else {
        match tokio::time::timeout(STRANGER_HELLO_TIMEOUT, read_frame(&mut reader)).await {
            Ok(result) => result,
            Err(_elapsed) => {
                info!(%fallback_name, "bridge: stranger's first frame timed out; closing");
                return Ok(());
            }
        }
    };

    // --- Accept gate for strangers: require a valid invite in Hello.invite. ---
    let mut verified: Option<invite::VerifiedInvite> = None;
    if !known {
        let invite_token = match &first_frame {
            Ok(Some(Frame::Hello { invite: Some(tok), .. })) => Some(tok.clone()),
            _ => None,
        };
        match invite_token {
            Some(tok) => match invite::verify_inbound(&tok, my_endpoint_id, &my_endpoint_id) {
                Ok(v) => {
                    info!(%fallback_name, invite_id = %v.invite_id, "bridge: stranger presented a valid invite");
                    verified = Some(v);
                }
                Err(e) => {
                    warn!(%fallback_name, error = %e, "bridge: invite verification failed; closing");
                    return Ok(());
                }
            },
            None => {
                warn!(%fallback_name, "bridge: stranger connected without a valid invite; closing");
                return Ok(());
            }
        }
    }

    // Read the very first frame to determine the peer's name.
    // Priority: (1) endpoint-id matched known device, (2) Hello frame, (3) scan-<id>.
    let recognised = known;
    let (peer_name, pending_frame, from_app) = match first_frame {
        Ok(Some(Frame::Hello { name, .. })) => {
            // An azula app announces its 64-hex endpoint id as the Hello name; a peer
            // bridge announces a "bridge-…" name. Only app clients get our reply.
            let looks_like_endpoint_id = name.len() == 64 && name.chars().all(|c| c.is_ascii_hexdigit());
            // Endpoint-id match takes priority over hello name (a registered device
            // dialling in IS that device, regardless of what name it advertises).
            let resolved = endpoint_id_match.unwrap_or_else(|| {
                if name.trim().is_empty() { fallback_name.clone() } else { name }
            });
            info!(peer=%resolved, "bridge: hello from peer");
            (resolved, None, recognised || looks_like_endpoint_id)
        }
        Ok(Some(other)) => {
            // Non-hello first frame — use endpoint-id match or fallback name, replay frame.
            let resolved = endpoint_id_match.unwrap_or(fallback_name.clone());
            (resolved, Some(other), recognised)
        }
        Ok(None) | Err(_) => {
            // Clean close or parse error — drop without registering.
            return Ok(());
        }
    };

    // A stranger who verified an invite is admitted: register them like
    // `azula pair` would (headless — verification *is* acceptance), and mark
    // single-use invites consumed.
    if let Some(v) = verified {
        let device = Device {
            name: peer_name.clone(),
            ticket: remote_id_str.clone(),
            added_at: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            ),
            invite: None,
        };
        if let Err(e) = registry::add(device, false) {
            warn!(peer=%peer_name, error=%e, "bridge: failed to register invite-verified device");
        }
        if v.single_use {
            if let Err(e) = invite::mark_consumed(&v.invite_id) {
                warn!(peer=%peer_name, error=%e, "bridge: failed to mark invite consumed");
            }
        }
    }

    // Announce ourselves to an azula app so it titles the conversation with our
    // name (e.g. "Claude"); the app keeps the bridge's peer code as the subtitle.
    // Never to peer bridges. The LLM can refine the title later via `set_name`.
    if from_app {
        let _ = write_frame(&mut send, &Frame::Hello { name: own_name.clone(), invite: None, cert: Some(own_cert.clone()) }).await;
    }

    // Flush any queued mailbox frames before moving send into the map.
    if let Err(e) = flush_mailbox(&peer_name, &mut send).await {
        warn!(%peer_name, error=%e, "bridge: mailbox flush failed on accept (continuing)");
    }

    let (generation, inbox) = {
        let mut guard = devices.lock().await;
        let entry = guard.entry(peer_name.clone()).or_insert_with(|| DeviceConn::new(remote_id_str.clone()));
        // Install the stream and mark the device live; preserve turns/closed so
        // an ongoing conversation is not interrupted by a re-dial from the peer.
        // The entry's inbox is kept (not swapped for a fresh one) so a consumer
        // already waiting on it sees this reconnect and what follows.
        let generation = entry.attach(send).await;
        // Don't downgrade a dialable ticket we already hold for this very
        // endpoint to the bare id — it carries addresses the bare id lacks.
        if registry::endpoint_id_of(&entry.ticket) != Some(remote_id) {
            entry.ticket = remote_id_str.clone();
        }
        (generation, entry.inbox.clone())
    };

    // Replay a non-hello first frame if present.
    let mut transfers = Transfers::new();
    if let Some(frame) = pending_frame {
        push_frame(&inbox, &mut transfers, frame);
    }

    write_state(&bind, &devices).await;
    info!(%peer_name, "bridge: peer registered");

    // Continue draining frames; reader already consumed the hello. When the
    // peer goes away, record it so the device stops reading as connected.
    read_frames_into_with(reader, inbox, transfers, &peer_name).await;
    connection_ended(&devices, &peer_name, generation, Some(&bind)).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::test_support::{core_knowing, eventually, isolate, unisolate, PhoneStub};
    use crate::proto::write_frame;
    use iroh::address_lookup::memory::MemoryLookup;
    use iroh::endpoint::presets;
    use tokio::io::AsyncWriteExt;

    const WITHIN: Duration = Duration::from_secs(10);

    /// The registry holds a dialable ticket *or* a bare endpoint id; both must
    /// resolve to the same peer, and nonsense must still be an error.
    #[tokio::test]
    async fn dial_target_accepts_a_ticket_or_a_bare_endpoint_id() {
        let ep = Endpoint::bind(presets::Minimal).await.unwrap();
        let ticket = EndpointTicket::new(ep.addr()).to_string();

        let from_ticket = dial_target(&ticket).expect("a full ticket resolves");
        assert_eq!(from_ticket.id, ep.id());
        assert!(!from_ticket.addrs.is_empty(), "a ticket's addresses are kept");

        let bare = ep.id().to_string();
        let from_bare = dial_target(&bare).expect("a bare endpoint id resolves");
        assert_eq!(from_bare.id, ep.id());
        assert!(from_bare.addrs.is_empty(), "a bare id carries no addresses; iroh looks them up");
        assert_eq!(dial_target(&format!("  {bare}\n")).unwrap().id, ep.id(), "stray whitespace is tolerated");

        assert!(dial_target("definitely not a ticket").is_err());
        assert!(dial_target("").is_err());
        ep.close().await;
    }

    /// The root cause behind a phone that stayed offline after the session
    /// restarted: a phone paired by dialing in is registered by its bare
    /// endpoint id, which the dial used to reject outright ("could not
    /// connect") so it was never retried. Here the only thing the session knows
    /// is the id; iroh's address lookup supplies the rest.
    #[tokio::test]
    async fn a_phone_registered_by_bare_endpoint_id_can_be_dialed() {
        let _guard = registry::ENV_TEST_LOCK.lock().await;
        isolate("bare_id_dial");

        let mut stub = PhoneStub::listening().await;
        let lookup = MemoryLookup::new();
        lookup.add_endpoint_info(stub.endpoint.addr());
        let session_ep = Endpoint::builder(presets::Minimal).address_lookup(lookup).bind().await.unwrap();

        let devices: DeviceMap = Arc::new(AsyncMutex::new(HashMap::new()));
        let bare_id = stub.endpoint.id().to_string();
        devices.lock().await.insert("phone".into(), DeviceConn::new(bare_id));
        let dialer = Dialer {
            endpoint: Arc::new(session_ep.clone()),
            devices: devices.clone(),
            own_name: "session".into(),
            cert: Some("azd-test-cert".into()),
            description: None,
            label: None,
        };

        assert!(dialer.ensure("phone", "ignored: the entry's own ticket wins", None).await);
        let mut link = stub.next_link(WITHIN).await.expect("the phone should receive the dial");
        assert!(matches!(link.next_frame().await, Some(Frame::Hello { .. })));

        session_ep.close().await;
        stub.shutdown().await;
        unisolate();
    }

    /// `match_known_device` must recognise a returning phone whichever shape its
    /// registry row has — it only understood full tickets, so a phone paired by
    /// dialing in (a bare endpoint id) came back as a stranger.
    #[test]
    fn match_known_device_recognises_a_bare_endpoint_id_row() {
        let phone = iroh::SecretKey::generate().public();
        let other = iroh::SecretKey::generate().public();
        let rows = vec![
            Device { name: "phone".into(), ticket: phone.to_string(), added_at: None, invite: None },
            Device { name: "hand-edited".into(), ticket: "not a ticket".into(), added_at: None, invite: None },
        ];
        assert_eq!(match_known_device(&phone, &HashMap::new(), &rows).as_deref(), Some("phone"));
        assert_eq!(match_known_device(&other, &HashMap::new(), &rows), None);

        // And a live entry whose ticket is the bare id (what accept-side
        // registration stores in the map).
        let mut live = HashMap::new();
        live.insert("scanned".to_string(), DeviceConn::new(other.to_string()));
        assert_eq!(match_known_device(&other, &live, &[]).as_deref(), Some("scanned"));
    }

    /// A connection winding down after it was superseded must not take its
    /// replacement down with it; only the current connection's end counts.
    #[tokio::test]
    async fn a_superseded_connections_end_does_not_disconnect_its_replacement() {
        let _guard = registry::ENV_TEST_LOCK.lock().await;
        isolate("generation_guard");

        let mut stub = PhoneStub::listening().await;
        let core = core_knowing("phone", &stub.ticket).await;
        let dialer = core.dialer();

        assert!(dialer.connect("phone", &stub.ticket, None).await);
        let first_gen = core.devices.lock().await.get("phone").unwrap().generation;
        let _first = stub.next_link(WITHIN).await.expect("first link");
        assert!(dialer.connect("phone", &stub.ticket, None).await, "an explicit connect dials again");
        let second_gen = core.devices.lock().await.get("phone").unwrap().generation;
        let _second = stub.next_link(WITHIN).await.expect("second link");
        assert_ne!(first_gen, second_gen);

        connection_ended(&core.devices, "phone", first_gen, None).await;
        assert!(core.devices.lock().await.get("phone").unwrap().connected, "the old connection's end is not the device's");

        connection_ended(&core.devices, "phone", second_gen, None).await;
        let events = core.get_events(Some("phone"), None).await.unwrap();
        assert!(!core.devices.lock().await.get("phone").unwrap().connected);
        // One `connected` (the second connect replaced a live link: no
        // transition), one `disconnected`.
        assert_eq!(
            events,
            vec![
                crate::core::watch::WatchEvent::Connected { device: "phone".into() },
                crate::core::watch::WatchEvent::Disconnected { device: "phone".into() },
            ]
        );

        stub.shutdown().await;
        unisolate();
    }

    /// A caller that queued behind someone else's dial takes that dial's result
    /// -- here a failure -- instead of starting its own: dialing again straight
    /// away would make a one-shot verb against an unreachable phone wait out the
    /// startup dial's failure and then its own.
    #[tokio::test]
    async fn a_caller_queued_behind_a_failed_dial_shares_its_failure() {
        let _guard = registry::ENV_TEST_LOCK.lock().await;
        isolate("shared_failure");

        // The phone *is* listening, so a (wrong) second dial would succeed and show.
        let stub = PhoneStub::listening().await;
        let core = Arc::new(core_knowing("phone", &stub.ticket).await);
        let dialer = core.dialer();

        let dial_lock = core.devices.lock().await.get("phone").unwrap().dial_lock.clone();
        let in_flight = dial_lock.lock_owned().await;

        let waiting = tokio::spawn({
            let dialer = dialer.clone();
            async move { dialer.ensure("phone", "unused", None).await }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!waiting.is_finished());

        // The dial we are queued behind finishes, leaving the device down.
        core.devices.lock().await.get_mut("phone").unwrap().dial_seq += 1;
        drop(in_flight);

        assert!(!waiting.await.unwrap(), "the waiter shares the failed dial's outcome");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(stub.accepted(), 0, "and does not dial for itself");

        stub.shutdown().await;
        unisolate();
    }

    /// The background redial never creates, resurrects or queues: an unknown
    /// device, a held one, and one that is already up are all left alone.
    #[tokio::test]
    async fn background_redial_skips_unknown_held_and_connected_devices() {
        let _guard = registry::ENV_TEST_LOCK.lock().await;
        isolate("redial_skips");

        let mut stub = PhoneStub::listening().await;
        let core = core_knowing("phone", &stub.ticket).await;
        let dialer = core.dialer();

        assert_eq!(dialer.redial_idle("nobody").await, DialOutcome::Skipped);
        assert!(!core.devices.lock().await.contains_key("nobody"), "must not resurrect a forgotten device");

        core.devices.lock().await.get_mut("phone").unwrap().held = true;
        assert_eq!(dialer.redial_idle("phone").await, DialOutcome::Skipped);
        assert_eq!(stub.accepted(), 0);

        core.devices.lock().await.get_mut("phone").unwrap().held = false;
        assert_eq!(dialer.redial_idle("phone").await, DialOutcome::Connected);
        eventually("the dial to land", WITHIN, || async { stub.accepted() == 1 }).await;
        let _link = stub.next_link(WITHIN).await.expect("link");
        assert_eq!(dialer.redial_idle("phone").await, DialOutcome::AlreadyConnected);

        stub.shutdown().await;
        unisolate();
    }

    /// relay spec: "Sessions SHALL learn the relay's ticket from a relay
    /// hint the phone shares at machine pairing time, persisted per device
    /// in the registry" — a `Frame::RelayHint` arriving on a device's stream
    /// is parsed and persisted via `registry::set_relay`, not surfaced as an
    /// inbox line, and a later real chat frame still reaches the inbox.
    #[tokio::test]
    async fn relay_hint_frame_persists_and_is_not_surfaced_to_the_inbox() {
        let _guard = registry::ENV_TEST_LOCK.lock().await;
        let dir = std::env::temp_dir().join(format!("azula-device-relay-hint-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("AZULA_REGISTRY_DIR", &dir);

        // The device must already be registered for `set_relay` to have a
        // file to persist into (mirrors a real pairing: the device is
        // registered before it ever sends a RelayHint).
        registry::add(
            Device { name: "phone".to_string(), ticket: "tk".to_string(), added_at: None, invite: None },
            false,
        )
        .unwrap();

        let (mut writer, reader) = tokio::io::duplex(8192);
        let inbox: Inbox = Arc::new(std::sync::Mutex::new(VecDeque::new()));
        let inbox_reader = inbox.clone();
        let handle = tokio::spawn(async move {
            read_frames_into(BufReader::new(reader), inbox_reader, "phone").await;
        });

        write_frame(&mut writer, &Frame::RelayHint { ticket: "relay-ticket-xyz".into() }).await.unwrap();
        write_frame(&mut writer, &Frame::Chat { text: "hello".into(), id: None }).await.unwrap();
        writer.shutdown().await.unwrap();
        handle.await.unwrap();

        let got: Vec<String> = inbox.lock().unwrap().drain(..).map(|e| e.human_line()).collect();
        assert_eq!(got, vec!["hello".to_string()], "the RelayHint must not be surfaced as an inbox line");
        assert_eq!(registry::relay_for("phone").as_deref(), Some("relay-ticket-xyz"));

        std::env::remove_var("AZULA_REGISTRY_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
