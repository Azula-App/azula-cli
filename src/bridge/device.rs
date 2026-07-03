//! Per-device connection state: the live device map, dialing (outbound) and
//! the accept-side handler (inbound) that registers azula app / peer-bridge
//! connections, and reconnect-by-node-id matching.
//!
//! Both directions converge on the same [`DeviceMap`]: `connect_device` fills
//! in an entry when the bridge dials out, and [`BridgeAcceptHandler`] fills in
//! (or updates) an entry when a device dials in. Each entry's [`Inbox`] is fed
//! by a background reader task for the lifetime of that connection. That
//! reader also reassembles inbound `file_begin`/`file_chunk`/`file_end`
//! sequences (see [`crate::filexfer`]), writing completed files to disk and
//! surfacing a `[received file: ...]` text line into the inbox.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::str::FromStr;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointId};
use iroh_tickets::endpoint::EndpointTicket;
use tokio::io::BufReader;
use tokio::sync::Mutex as AsyncMutex;
use tracing::{info, warn};

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

pub(super) type Inbox = Arc<std::sync::Mutex<VecDeque<String>>>;
type AppSend = Arc<AsyncMutex<Option<SendStream>>>;

/// Per-device live state.
#[derive(Clone, Debug)]
pub(super) struct DeviceConn {
    pub(super) send: AppSend,
    pub(super) inbox: Inbox,
    pub(super) ticket: String,
    /// The encoded invite string (`"azi…"`) this device was paired with, if
    /// any — re-presented in `Hello` on every (re)dial per the invitations
    /// spec, until the issuer has accepted and this becomes a known peer.
    pub(super) invite: Option<String>,
    pub(super) connected: bool,
    /// Turn counter for peer bridge conversations.
    pub(super) turns: Arc<std::sync::atomic::AtomicU64>,
    /// Whether this conversation has been closed (turn limit or explicit done).
    pub(super) closed: Arc<std::sync::atomic::AtomicBool>,
}

impl DeviceConn {
    pub(super) fn new(ticket: String) -> Self {
        DeviceConn {
            send: Arc::new(AsyncMutex::new(None)),
            inbox: Arc::new(std::sync::Mutex::new(VecDeque::new())),
            ticket,
            invite: None,
            connected: false,
            turns: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            closed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    pub(super) fn with_invite(mut self, invite: Option<String>) -> Self {
        self.invite = invite;
        self
    }

    /// Reset conversation state (turns=0, closed=false) — call on (re)connect.
    pub(super) fn reset_conversation(&self) {
        self.turns.store(0, Relaxed);
        self.closed.store(false, Relaxed);
    }
}

pub(super) type DeviceMap = Arc<AsyncMutex<HashMap<String, DeviceConn>>>;

// ---------------------------------------------------------------------------
// iroh dial helper
// ---------------------------------------------------------------------------

pub(super) async fn dial_device(
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
/// Sends `Frame::Hello { name: own_name, invite }` as the very first frame
/// (presenting `invite` — the encoded invite string, if this device was
/// paired via one — so an unknown-to-the-peer dial can pass its accept
/// gate), then the `thinking(false)` handshake.  Calls `reset_conversation()`
/// on the DeviceConn.
pub(super) async fn connect_device(
    endpoint: &Endpoint,
    name: &str,
    ticket: &str,
    devices: &DeviceMap,
    own_name: &str,
    invite: Option<&str>,
) -> bool {
    match dial_device(endpoint, ticket).await {
        Ok((mut send, recv)) => {
            // Send hello so the peer can name us (and verify our invite, if any).
            let hello = Frame::Hello { name: own_name.into(), invite: invite.map(String::from) };
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
            let inbox: Inbox = Arc::new(std::sync::Mutex::new(VecDeque::new()));
            let inbox_reader = inbox.clone();
            tokio::spawn(async move { reader_loop(recv, inbox_reader).await });

            let mut guard = devices.lock().await;
            let conn = guard
                .entry(name.to_string())
                .or_insert_with(|| DeviceConn::new(ticket.to_string()).with_invite(invite.map(String::from)));
            *conn.send.lock().await = Some(send);
            conn.inbox = inbox;
            conn.connected = true;
            conn.ticket = ticket.to_string();
            conn.invite = invite.map(String::from);
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

fn push_line(inbox: &Inbox, line: String) {
    // A poisoned inbox mutex (a prior holder panicked mid-push) shouldn't cascade
    // into every subsequent frame for this device — recover the inner value.
    inbox.lock().unwrap_or_else(|e| e.into_inner()).push_back(line);
}

/// Push a single frame into an inbox (Chat → text, A2uiAction → `ui-event:`
/// line), or fold it into an in-flight file transfer (FileBegin/FileChunk/
/// FileEnd) — completed transfers are written to disk and surfaced as a
/// `[received file: ...]` text line.
fn push_frame(inbox: &Inbox, transfers: &mut Transfers, frame: Frame) {
    match frame {
        Frame::Chat { text } => push_line(inbox, text),
        Frame::A2uiAction { action } => {
            push_line(inbox, format!("ui-event: {}", serde_json::to_string(&action).unwrap_or_default()));
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
                push_line(inbox, format!(
                    "[rejected file: {name} ({size} bytes) exceeds the {} byte (64 MiB) limit]",
                    filexfer::MAX_FILE_BYTES
                ));
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
                    let mut line = format!(
                        "[received file: {} ({}, {size} bytes) -> {}]",
                        pending.name,
                        pending.mime,
                        path.display()
                    );
                    if let Some(caption) = &pending.caption {
                        line.push_str(&format!(" caption: {caption}"));
                    }
                    push_line(inbox, line);
                }
                Err(e) => {
                    warn!(id = %id, name = %pending.name, error = %e, "bridge: failed to save received file");
                    push_line(inbox, format!("[failed to save received file '{}': {e}]", pending.name));
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
/// Generic over the reader so the behavior is unit-testable over an in-memory pipe.
pub(super) async fn read_frames_into<R: tokio::io::AsyncRead + Unpin>(reader: BufReader<R>, inbox: Inbox) {
    read_frames_into_with(reader, inbox, Transfers::new()).await
}

/// As [`read_frames_into`], but seeded with an existing `transfers` map — used
/// by `accept_incoming` so a file transfer started by a replayed first frame
/// isn't lost when handing off to the main read loop.
async fn read_frames_into_with<R: tokio::io::AsyncRead + Unpin>(
    mut reader: BufReader<R>,
    inbox: Inbox,
    mut transfers: Transfers,
) {
    loop {
        match read_frame(&mut reader).await {
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
// Node-id matching — reconnect recognition
// ---------------------------------------------------------------------------

/// Given the node id of an inbound connection, look it up against all known
/// devices (from the in-memory map and the registry) and return the existing
/// device name if a ticket matches.
///
/// This is a pure function (no I/O) so it is easily unit-tested.
pub(super) fn match_known_device(
    remote_node_id: &EndpointId,
    map_devices: &HashMap<String, DeviceConn>,
    registry_devices: &[Device],
) -> Option<String> {
    let remote_str = remote_node_id.to_string();

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
        if let Ok(et) = EndpointTicket::from_str(&ticket) {
            if et.endpoint_addr().id.to_string() == remote_str {
                return Some(name);
            }
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
pub(super) struct BridgeAcceptHandler {
    devices: DeviceMap,
    bind: String,
    /// The name this bridge announces to apps that connect in (the conversation
    /// title on the phone), e.g. "Claude".
    own_name: String,
    /// Our own node id — the invite-verification audience (rule 2: the
    /// invite's embedded ticket must name *us*) and signature-verification key.
    my_node_id: EndpointId,
    /// Admit invite-less strangers as unverified pending devices instead of
    /// closing the connection (transition escape hatch; `--allow-legacy`,
    /// default on for one release per the invitations spec).
    allow_legacy: bool,
    /// Counter to assign monotonically-increasing names to scanned devices.
    scan_counter: Arc<std::sync::atomic::AtomicU32>,
}

impl BridgeAcceptHandler {
    pub(super) fn new(
        devices: DeviceMap,
        bind: String,
        own_name: String,
        my_node_id: EndpointId,
        allow_legacy: bool,
    ) -> Self {
        Self {
            devices,
            bind,
            own_name,
            my_node_id,
            allow_legacy,
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
            self.my_node_id,
            self.allow_legacy,
        )
        .await
        .map_err(|e| AcceptError::from_boxed(e.into()))
    }
}

/// 15 s cap on waiting for a stranger's first frame — long enough for a real
/// dial, short enough that a silent connection doesn't tie up an accept slot.
const STRANGER_HELLO_TIMEOUT: Duration = Duration::from_secs(15);

async fn accept_incoming(
    connection: Connection,
    devices: DeviceMap,
    bind: String,
    own_name: String,
    counter: Arc<std::sync::atomic::AtomicU32>,
    my_node_id: EndpointId,
    allow_legacy: bool,
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

    // --- Node-id match: check if this is a known registered device ---
    // Snapshot current map entries and registry to avoid holding the lock
    // across async I/O (the bi-stream accept and frame read below).
    let node_id_match: Option<String> = {
        let guard = devices.lock().await;
        let reg = registry::load();
        match_known_device(&remote_id, &guard, &reg)
    };
    if let Some(ref matched) = node_id_match {
        info!(peer=%matched, "bridge: recognised reconnecting device by node id");
    }
    let known = node_id_match.is_some();

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
            Some(tok) => match invite::verify_inbound(&tok, my_node_id, &my_node_id) {
                Ok(v) => {
                    info!(%fallback_name, invite_id = %v.invite_id, "bridge: stranger presented a valid invite");
                    verified = Some(v);
                }
                Err(e) if allow_legacy => {
                    warn!(%fallback_name, error = %e, "bridge: invite verification failed; admitting as unverified (--allow-legacy)");
                }
                Err(e) => {
                    warn!(%fallback_name, error = %e, "bridge: invite verification failed; closing (pass --allow-legacy to admit anyway)");
                    return Ok(());
                }
            },
            None if allow_legacy => {
                info!(%fallback_name, "bridge: stranger connected without an invite; admitting as unverified (--allow-legacy)");
            }
            None => {
                warn!(%fallback_name, "bridge: stranger connected without a valid invite; closing (pass --allow-legacy to admit anyway)");
                return Ok(());
            }
        }
    }

    // Read the very first frame to determine the peer's name.
    // Priority: (1) node-id matched known device, (2) Hello frame, (3) scan-<id>.
    let recognised = known;
    let (peer_name, pending_frame, from_app) = match first_frame {
        Ok(Some(Frame::Hello { name, .. })) => {
            // An azula app announces its 64-hex node id as the Hello name; a peer
            // bridge announces a "bridge-…" name. Only app clients get our reply.
            let looks_like_node_id = name.len() == 64 && name.chars().all(|c| c.is_ascii_hexdigit());
            // Node-id match takes priority over hello name (a registered device
            // dialling in IS that device, regardless of what name it advertises).
            let resolved = node_id_match.unwrap_or_else(|| {
                if name.trim().is_empty() { fallback_name.clone() } else { name }
            });
            info!(peer=%resolved, "bridge: hello from peer");
            (resolved, None, recognised || looks_like_node_id)
        }
        Ok(Some(other)) => {
            // Non-hello first frame — use node-id match or fallback name, replay frame.
            let resolved = node_id_match.unwrap_or(fallback_name.clone());
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
        let _ = write_frame(&mut send, &Frame::Hello { name: own_name.clone(), invite: None }).await;
    }

    let inbox: Inbox = Arc::new(std::sync::Mutex::new(VecDeque::new()));
    let mut transfers = Transfers::new();

    // Replay a non-hello first frame if present.
    if let Some(frame) = pending_frame {
        push_frame(&inbox, &mut transfers, frame);
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
            invite: None,
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
    read_frames_into_with(reader, inbox, transfers).await;
    Ok(())
}
