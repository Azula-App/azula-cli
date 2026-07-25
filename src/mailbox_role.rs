//! The `relay` role (`azula relay`; `azula mailbox` is now an alias — relay
//! spec: "Relay Subsumes the Mailbox Role"): binds a linked identity's chat,
//! LLM, sync, and link ALPNs, and durably serves store-and-forward plus
//! bootstrap sync for the identity, per `specs/account-sync/spec.md`'s
//! "Mailbox Role Stores and Forwards" and "New Device Bootstrap Replays the
//! Logs" requirements, plus `specs/relay/spec.md`'s agent-chat and A2UI
//! snapshot capabilities. The module/file name and its "mailbox" internals
//! (`log_store_dir`, `CHAT_ALPN`, `ChatHandler`, …) are kept as-is
//! (cli-multi-session-relay task 4.1: "keep file/module names... to limit
//! churn") — only user-facing strings (the CLI command, banner, log lines)
//! say "relay".
//!
//! Deliberately independent of `mailbox.rs` (the CLI bridge's existing
//! per-device JSONL mailbox for bridge tooling, which the spec says stays
//! unchanged): identity-level offline delivery is built entirely on
//! `sync::LogStore` + `eventlog`/`certs`/`accept_gate`, never on
//! `mailbox.rs`.
//!
//! Layout, innermost-out:
//!   - [`run_chat_session`] — the testable core for [`CHAT_ALPN`]: gates a
//!     peer's first stream (`accept_gate::gate_peer`, certs + legacy
//!     invites) and folds every `Frame::Chat` into a `message_in` log entry
//!     (`sync::LogStore::append_own`).
//!   - [`ChatHandler`] — thin iroh `ProtocolHandler` wiring on top, exactly
//!     the `sync.rs`/`link.rs` pattern.
//!   - [`run_llm_session`] — the testable core for [`crate::mcp::LLM_ALPN`]
//!     (relay spec: "Relay Carries Agent Chat" / "Relay Holds A2UI Snapshots
//!     Outside the Log"): admits a session by its `azd…` session cert
//!     chaining to a known machine contact (no invite path on this ALPN),
//!     then folds `Frame::Chat` into `agent_in` log entries and
//!     `Frame::A2uiSnapshot` into [`crate::core::relay_a2ui::RelayA2uiStore`].
//!   - [`RelayLlmHandler`] — thin iroh wiring on top, mirroring
//!     [`ChatHandler`].
//!   - [`run`] — the `azula relay` command (also `azula mailbox`, unchanged
//!     call site in `cli/legacy.rs`): load the linked identity, bind its
//!     node key, and serve [`CHAT_ALPN`] + [`crate::mcp::LLM_ALPN`] +
//!     `sync::SYNC_ALPN` (with a [`crate::sync::PreSyncAckHook`] replaying
//!     pending A2UI snapshots) + `link::LINK_ALPN` (via
//!     `link::RootlessLinkHandler` — this device holds no root secret)
//!     until Ctrl-C.

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Result};
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{EndpointId, PublicKey, SecretKey};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tokio::sync::Mutex as AsyncMutex;
use tracing::{info, warn};

use crate::accept_gate::{gate_peer, CertGate, GatePeerOutcome};
use crate::certs::{DeviceCert, Revocation};
use crate::eventlog::{AgentInBody, Kind};
use crate::link::{RootlessLinkHandler, LINK_ALPN};
use crate::linked_identity::{self, NODE_IDENTITY_NAME};
use crate::proto::{read_frame, write_frame, Frame, IdentityBundle};
use crate::sync::{LogStore, PreSyncAckHook, SyncHandler, SYNC_ALPN};
use crate::{endpoint, identity};

/// ALPN identifier for the identity's peer-chat protocol (matches
/// azula-app's `Alpns.CHAT`). Only `azula mailbox` accepts it on the CLI
/// side — a plain `azula serve`/interactive CLI session never does.
pub const CHAT_ALPN: &[u8] = b"azula/chat/0";

// ---------------------------------------------------------------------------
// Bundle parsing helpers (pure, testable without any I/O)
// ---------------------------------------------------------------------------

/// Parse the root public keys of an identity bundle's contacts snapshot —
/// the mailbox's initial "known roots" set for `accept_gate::CertGate`.
/// Unparseable/node-id-only entries are skipped rather than failing the
/// whole bundle.
pub fn known_roots_from_bundle(bundle: &IdentityBundle) -> Vec<PublicKey> {
    bundle
        .contacts
        .iter()
        .filter_map(|c| c.root_pk.as_deref())
        .filter_map(|s| PublicKey::from_str(s).ok())
        .collect()
}

/// Decode and verify every revocation in an identity bundle, discarding any
/// that fail to decode or verify — callers (the sync/chat handlers) require
/// an already-verified revocation set, same contract as
/// `certs::DeviceCert::is_revoked_by`.
pub fn verified_revocations_from_bundle(bundle: &IdentityBundle) -> Vec<Revocation> {
    bundle
        .revocations
        .iter()
        .filter_map(|s| Revocation::decode(s).ok())
        .filter(|r| r.verify().is_ok())
        .collect()
}

// ---------------------------------------------------------------------------
// Chat session (testable core)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct MessageInBody<'a> {
    conversation: &'a str,
    from_device_pk: &'a str,
    text: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<&'a str>,
}

/// Run one mailbox chat session over any `AsyncRead`/`AsyncWrite` pair — an
/// in-memory duplex in this module's tests, a real iroh bi-stream via
/// [`ChatHandler`]: gate the peer's first stream (`accept_gate::gate_peer`),
/// announce ourselves with our own cert, then fold every inbound
/// `Frame::Chat` into a `message_in` entry on `device_secret`'s own log
/// (`store.append_own`) — the store-and-forward behavior "Mailbox Role
/// Stores and Forwards" describes. `conversation` is the peer's root public
/// key hex when it presented (or already held) a valid cert, else its
/// (legacy) transport node id hex, matching `eventlog`'s `message_in` body
/// shape `{conversation, from_device_pk, text, id?}`.
///
/// `revocations` (typically the identity bundle's baseline set) is merged
/// with [`LogStore::device_revocations`] before gating — any `device_revoke`
/// entry `store` has already learned via a prior sync is enforced too, not
/// just ones present in the caller's own baseline (device-linking spec:
/// "Own devices enforce revocation after sync").
#[allow(clippy::too_many_arguments)]
pub async fn run_chat_session<R, W>(
    reader: R,
    mut writer: W,
    remote_node_id: EndpointId,
    remote: &str,
    device_secret: &SecretKey,
    my_cert_encoded: &str,
    store: &LogStore,
    known_roots: &AsyncMutex<Vec<PublicKey>>,
    revocations: &[Revocation],
    allow_legacy: bool,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let my_node_id = device_secret.public();
    let mut reader = BufReader::new(reader);

    let mut live_revocations = revocations.to_vec();
    live_revocations.extend(store.device_revocations().await);

    let known_roots_snapshot = known_roots.lock().await.clone();
    let cert_gate = CertGate { known_roots: &known_roots_snapshot, revocations: &live_revocations };
    let device_name = format!("mailbox-peer-{}", &remote[..8.min(remote.len())]);

    let (replay, conversation_root) = match gate_peer(
        &mut reader,
        my_node_id,
        remote_node_id,
        allow_legacy,
        remote,
        &device_name,
        "mailbox",
        &cert_gate,
    )
    .await
    {
        GatePeerOutcome::Admit { replay, root_pk } => (replay, root_pk),
        GatePeerOutcome::Close => return Ok(()),
    };

    if let Some(root) = conversation_root {
        let mut roots = known_roots.lock().await;
        if !roots.contains(&root) {
            info!(%remote, %root, "mailbox: recorded new certified contact");
            roots.push(root);
        }
    }

    // Announce ourselves so the peer can pin/learn our identity too (spec:
    // certificate-holding peers include `Hello.cert` "on every ALPN in both
    // directions"). Best-effort — a write failure here just means the peer
    // won't learn us this time; it doesn't invalidate anything we're about
    // to receive from them.
    let _ = write_frame(
        &mut writer,
        &Frame::Hello { name: "mailbox".to_string(), invite: None, cert: Some(my_cert_encoded.to_string()) },
    )
    .await;

    let conversation = conversation_root.map(|r| r.to_string()).unwrap_or_else(|| remote.to_string());
    let from_device_pk = remote.to_string();

    if let Some(frame) = replay {
        handle_chat_frame(*frame, &conversation, &from_device_pk, device_secret, store).await;
    }

    loop {
        match read_frame(&mut reader).await {
            Ok(Some(frame)) => handle_chat_frame(frame, &conversation, &from_device_pk, device_secret, store).await,
            Ok(None) => return Ok(()),
            Err(e) => {
                warn!(%remote, error = %e, "mailbox: chat stream read error");
                return Ok(());
            }
        }
    }
}

/// Fold a single inbound frame: a `Chat` becomes a `message_in` entry on our
/// own log; anything else is ignored (this ALPN carries chat only).
async fn handle_chat_frame(
    frame: Frame,
    conversation: &str,
    from_device_pk: &str,
    device_secret: &SecretKey,
    store: &LogStore,
) {
    let Frame::Chat { text, id } = frame else { return };
    let body = MessageInBody { conversation, from_device_pk, text: &text, id: id.as_deref() };
    let body_json = match serde_json::to_string(&body) {
        Ok(j) => j,
        Err(e) => {
            warn!(error = %e, "mailbox: failed to serialize message_in body");
            return;
        }
    };
    if let Err(e) = store.append_own(device_secret, Kind::MessageIn, body_json).await {
        warn!(error = %e, "mailbox: failed to append inbound message");
    }
}

// ---------------------------------------------------------------------------
// iroh wiring — thin: all protocol logic lives in `run_chat_session`.
// ---------------------------------------------------------------------------

/// iroh `ProtocolHandler` for [`CHAT_ALPN`]: accepts a dialed-in bi stream
/// and hands it straight to [`run_chat_session`].
#[derive(Clone)]
pub struct ChatHandler {
    device_secret: Arc<SecretKey>,
    my_cert_encoded: String,
    store: LogStore,
    known_roots: Arc<AsyncMutex<Vec<PublicKey>>>,
    revocations: Vec<Revocation>,
    allow_legacy: bool,
}

impl ChatHandler {
    pub fn new(
        device_secret: Arc<SecretKey>,
        my_cert_encoded: String,
        store: LogStore,
        known_roots: Vec<PublicKey>,
        revocations: Vec<Revocation>,
        allow_legacy: bool,
    ) -> Self {
        Self {
            device_secret,
            my_cert_encoded,
            store,
            known_roots: Arc::new(AsyncMutex::new(known_roots)),
            revocations,
            allow_legacy,
        }
    }

    /// Share this handler's live known-roots set — a root a certified peer
    /// pins here (`run_chat_session`'s `gate_peer` call) becomes visible to
    /// whatever else holds this handle too. `azula relay`'s `run` hands the
    /// same handle to [`RelayLlmHandler`] so a contact recognized on one
    /// ALPN is recognized on the other (task 4.3: "derive [the LLM ALPN
    /// admission gate's known-contacts set] from the same fold/contact
    /// source `mailbox_role`'s chat gate uses").
    pub fn known_roots_handle(&self) -> Arc<AsyncMutex<Vec<PublicKey>>> {
        self.known_roots.clone()
    }
}

impl std::fmt::Debug for ChatHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatHandler")
            .field("device_pk", &self.device_secret.public())
            .field("allow_legacy", &self.allow_legacy)
            .finish()
    }
}

impl ProtocolHandler for ChatHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let remote_id = connection.remote_id();
        let remote = remote_id.to_string();
        let (send, recv) = connection.accept_bi().await.map_err(|e| AcceptError::from_boxed(e.into()))?;
        run_chat_session(
            recv,
            send,
            remote_id,
            &remote,
            &self.device_secret,
            &self.my_cert_encoded,
            &self.store,
            &self.known_roots,
            &self.revocations,
            self.allow_legacy,
        )
        .await
        .map_err(|e| AcceptError::from_boxed(e.into()))
    }
}

// ---------------------------------------------------------------------------
// LLM-ALPN admission (relay spec: "Relay Carries Agent Chat") — testable core
// ---------------------------------------------------------------------------

/// 15 s cap on waiting for a connecting session's first frame — mirrors
/// `accept_gate`'s `STRANGER_HELLO_TIMEOUT` (that constant is private to
/// that module, so this is its own copy rather than an export).
const LLM_HELLO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Admit a session dialing in on the LLM ALPN and, once admitted, fold its
/// `Chat`/`A2uiSnapshot` frames — relay spec's "Relay Carries Agent Chat" and
/// "Relay Holds A2UI Snapshots Outside the Log": the relay SHALL admit a
/// session "by the same certificate gate the phone applies (session cert
/// chaining to a machine root that is a known contact of the identity)".
///
/// Admission (task 4.3, all of which must hold): the first frame is
/// `Hello{cert}`; the cert decodes and `certs::verify_session_cert` passes
/// against `remote_node_id` (signature, [`FLAG_SESSION`](crate::certs::FLAG_SESSION),
/// unexpired, `device_pk == remote_node_id`); and `cert.root_pk` is already
/// in `known_roots` — the *same* live set [`ChatHandler`]'s `gate_peer` call
/// maintains (see [`ChatHandler::known_roots_handle`]), so a machine root
/// pinned as a contact via ordinary peer chat is recognized here too, and
/// vice versa. Anything else closes the connection outright — this ALPN has
/// no invite fallback (unlike [`run_chat_session`]'s stranger path): a
/// process without a valid session cert chaining to a known machine contact
/// is simply not admitted (relay spec: "Uncertified stranger refused by the
/// relay").
///
/// Once admitted, `conversation` for both folded kinds is the *session's*
/// public key hex (`cert.device_pk`, which — per `verify_session_cert` —
/// already equals `remote_node_id`): `Frame::Chat{text,id}` appends an
/// `agent_in` entry on `device_secret`'s own log (`from_name` from the
/// `Hello`, when non-empty), and `Frame::A2uiSnapshot` writes into
/// `a2ui_store` (its own `conversation` field is deliberately ignored here —
/// the connection's already-authenticated cert is the only trustworthy
/// source for that key, never a client-declared one). Any other frame is
/// ignored; this ALPN carries agent chat and A2UI snapshots only.
pub async fn run_llm_session<R, W>(
    reader: R,
    _writer: W,
    remote_node_id: EndpointId,
    device_secret: &SecretKey,
    store: &LogStore,
    a2ui_store: &crate::core::relay_a2ui::RelayA2uiStore,
    known_roots: &AsyncMutex<Vec<PublicKey>>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(reader);

    let first = match tokio::time::timeout(LLM_HELLO_TIMEOUT, read_frame(&mut reader)).await {
        Ok(result) => result,
        Err(_elapsed) => {
            info!(%remote_node_id, "relay: session's first frame timed out; closing");
            return Ok(());
        }
    };
    let Ok(Some(Frame::Hello { name, cert: Some(cert_str), .. })) = first else {
        info!(%remote_node_id, "relay: session presented no cert; closing (no invite fallback on this ALPN)");
        return Ok(());
    };
    let Ok(cert) = DeviceCert::decode(&cert_str) else {
        info!(%remote_node_id, "relay: session's cert did not decode; closing");
        return Ok(());
    };
    if let Err(e) = crate::certs::verify_session_cert(&cert, remote_node_id) {
        info!(%remote_node_id, error = %e, "relay: session cert failed verification; closing");
        return Ok(());
    }
    {
        let roots = known_roots.lock().await;
        if !roots.contains(&cert.root_pk) {
            info!(%remote_node_id, root_pk = %cert.root_pk, "relay: session's root is not a known contact; closing");
            return Ok(());
        }
    }

    let conversation = cert.device_pk.to_string();
    let from_name = if name.trim().is_empty() { None } else { Some(name) };
    info!(%remote_node_id, %conversation, "relay: session admitted on the LLM ALPN");

    loop {
        match read_frame(&mut reader).await {
            Ok(Some(Frame::Chat { text, id })) => {
                let body = AgentInBody { conversation: conversation.clone(), text, id, from_name: from_name.clone() };
                match serde_json::to_string(&body) {
                    Ok(body_json) => {
                        if let Err(e) = store.append_own(device_secret, Kind::AgentIn, body_json).await {
                            warn!(error = %e, "relay: failed to append agent_in");
                        }
                    }
                    Err(e) => warn!(error = %e, "relay: failed to serialize agent_in body"),
                }
            }
            Ok(Some(Frame::A2uiSnapshot { surface, components, data_model, lamport, .. })) => {
                if let Err(e) = a2ui_store.put(&conversation, &surface, components, data_model, lamport).await {
                    warn!(%surface, error = %e, "relay: dropped oversized A2UI snapshot");
                }
            }
            Ok(Some(_)) => {} // this ALPN carries agent chat + A2UI snapshots only
            Ok(None) => return Ok(()),
            Err(e) => {
                warn!(error = %e, "relay: llm stream read error");
                return Ok(());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// iroh wiring — thin: all protocol logic lives in `run_llm_session`.
// ---------------------------------------------------------------------------

/// iroh `ProtocolHandler` for [`crate::mcp::LLM_ALPN`]: accepts a dialed-in
/// bi stream and hands it straight to [`run_llm_session`].
#[derive(Clone)]
pub struct RelayLlmHandler {
    device_secret: Arc<SecretKey>,
    store: LogStore,
    a2ui_store: crate::core::relay_a2ui::RelayA2uiStore,
    known_roots: Arc<AsyncMutex<Vec<PublicKey>>>,
}

impl RelayLlmHandler {
    pub fn new(
        device_secret: Arc<SecretKey>,
        store: LogStore,
        a2ui_store: crate::core::relay_a2ui::RelayA2uiStore,
        known_roots: Arc<AsyncMutex<Vec<PublicKey>>>,
    ) -> Self {
        Self { device_secret, store, a2ui_store, known_roots }
    }
}

impl std::fmt::Debug for RelayLlmHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayLlmHandler").field("device_pk", &self.device_secret.public()).finish()
    }
}

impl ProtocolHandler for RelayLlmHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let remote_id = connection.remote_id();
        let (send, recv) = connection.accept_bi().await.map_err(|e| AcceptError::from_boxed(e.into()))?;
        run_llm_session(recv, send, remote_id, &self.device_secret, &self.store, &self.a2ui_store, &self.known_roots)
            .await
            .map_err(|e| AcceptError::from_boxed(e.into()))
    }
}

// ---------------------------------------------------------------------------
// `azula mailbox` command
// ---------------------------------------------------------------------------

/// `AZULA_MAILBOX_LOG_DIR` override (tests / custom deployments), else
/// `~/.azula/mailbox-log` — the identity-level sync log store this role
/// retains in full, entirely distinct from `mailbox.rs`'s per-device JSONL
/// queue.
pub fn log_store_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("AZULA_MAILBOX_LOG_DIR") {
        return Some(PathBuf::from(dir));
    }
    #[cfg(test)]
    {
        return Some(std::env::temp_dir().join("azula-test").join("mailbox-log"));
    }
    #[allow(unreachable_code)]
    {
        let home = std::env::var("HOME").ok()?;
        Some(PathBuf::from(home).join(".azula").join("mailbox-log"))
    }
}

/// Run `azula relay`: load the identity linked via `azula link`, bind its
/// node key, and serve the chat/LLM/sync/link ALPNs until Ctrl-C. relay
/// spec: "Relay Subsumes the Mailbox Role" — `azula mailbox` (`cli/legacy.rs`'s
/// `cmd_mailbox`) calls this exact function too, unchanged, so both commands
/// get identical behavior; kept named `mailbox_role::run` (not renamed) to
/// limit churn to files outside this phase's ownership.
pub async fn run(allow_legacy: bool) -> Result<()> {
    let linked = linked_identity::load()
        .context("no linked identity found -- run `azula link [--relay]` first")?;
    let cert = DeviceCert::decode(&linked.cert).context("relay: stored certificate is corrupt")?;
    cert.verify().context("relay: stored certificate no longer verifies")?;

    let revocations = verified_revocations_from_bundle(&linked.bundle);
    anyhow::ensure!(
        !cert.is_revoked_by(&revocations),
        "relay: this device's own certificate has been revoked; re-link with `azula link`"
    );
    let known_roots = known_roots_from_bundle(&linked.bundle);

    let (endpoint, ticket) = endpoint::bind_server_endpoint(NODE_IDENTITY_NAME).await?;
    let node_id = endpoint.id();
    anyhow::ensure!(
        cert.binds_to_connection(node_id),
        "relay: stored certificate's device key does not match this device's node id -- re-link with `azula link`"
    );

    let dir = log_store_dir().context("cannot resolve relay log directory ($HOME unset)")?;
    // multi-device-identity task 4.6: namespace by the identity's root pk,
    // already known from the stored, just-verified certificate -- never a
    // placeholder. See `sync::LogStore::open`'s doc comment.
    let store = LogStore::open(dir, cert.root_pk)?;
    let device_secret = Arc::new(identity::load_or_create_secret(NODE_IDENTITY_NAME));

    // relay spec: "Relay Holds A2UI Snapshots Outside the Log" -- a bounded
    // side store, namespaced by the same root pk, deliberately never fed
    // into `store` (the hash-chained identity log).
    let a2ui_dir = crate::core::relay_a2ui::default_store_dir()
        .context("cannot resolve relay A2UI store directory ($HOME unset)")?;
    let a2ui_store = crate::core::relay_a2ui::RelayA2uiStore::open(a2ui_dir, cert.root_pk)?;

    let banner = vec![
        "  Paste this code into the linked app to reconnect it here:".to_string(),
        String::new(),
        format!("    {ticket}"),
        String::new(),
        format!("  Short node id: {node_id}"),
        String::new(),
        "  Serving ALPNs:".to_string(),
        format!("    {}  peer chat (store-and-forward)", String::from_utf8_lossy(CHAT_ALPN)),
        format!("    {}  agent chat + A2UI snapshots (relay)", String::from_utf8_lossy(crate::mcp::LLM_ALPN)),
        format!("    {}  identity log sync (bootstrap source)", String::from_utf8_lossy(SYNC_ALPN)),
        format!(
            "    {}  link (always declines -- this device holds no root secret)",
            String::from_utf8_lossy(LINK_ALPN)
        ),
    ];
    endpoint::print_banner("azula relay", &banner);

    let chat_handler = ChatHandler::new(
        device_secret.clone(),
        linked.cert.clone(),
        store.clone(),
        known_roots,
        revocations.clone(),
        allow_legacy,
    );
    // task 4.3: the LLM ALPN's admission gate shares ChatHandler's live
    // known-roots set, so a contact pinned via one ALPN is recognized by
    // the other.
    let known_roots_shared = chat_handler.known_roots_handle();
    let llm_handler = RelayLlmHandler::new(device_secret, store.clone(), a2ui_store.clone(), known_roots_shared);

    // relay spec: "A2UI Snapshot Replay on Reconnect" -- after streaming a
    // sync session's catch-up gap but before this side's SyncAck (see
    // `sync::PreSyncAckHook`'s doc for why not after: the phone's bounded
    // catch-up mode stops listening the instant the ack arrives), replay
    // whatever pending A2UI snapshots that device hasn't seen yet, one
    // `SyncA2ui` frame per conversation with pending messages.
    let a2ui_store_for_hook = a2ui_store.clone();
    let pre_ack_hook: PreSyncAckHook = Arc::new(move |peer_device_pk: PublicKey| {
        let a2ui_store = a2ui_store_for_hook.clone();
        Box::pin(async move {
            let by_conversation = a2ui_store.drain_pending_messages_for_device(&peer_device_pk.to_string()).await;
            by_conversation
                .into_iter()
                .map(|(conversation, messages)| Frame::SyncA2ui { conversation, messages })
                .collect()
        })
    });
    let sync_handler = SyncHandler::new(cert, revocations, store).with_pre_ack_hook(pre_ack_hook);

    let router = Router::builder(endpoint)
        .accept(CHAT_ALPN, chat_handler)
        .accept(crate::mcp::LLM_ALPN, llm_handler)
        .accept(SYNC_ALPN, sync_handler)
        .accept(LINK_ALPN, RootlessLinkHandler)
        .spawn();

    info!("relay serving — press Ctrl-C to stop");
    tokio::signal::ctrl_c().await?;
    info!("shutting down…");
    router.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::Contact;

    fn seed(start: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = start.wrapping_add(i as u8);
        }
        s
    }

    fn test_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("azula-mailbox-role-test-{}", std::process::id())).join(name)
    }

    // --- known_roots_from_bundle / verified_revocations_from_bundle --------

    #[test]
    fn known_roots_from_bundle_parses_root_pk_contacts_and_skips_node_id_only() {
        let root = SecretKey::from_bytes(&seed(0x01)).public();
        let bundle = IdentityBundle {
            root_pk: "self".to_string(),
            certs: vec![],
            revocations: vec![],
            contacts: vec![
                Contact { root_pk: Some(root.to_string()), node_id: None, name: None },
                Contact { root_pk: None, node_id: Some("legacy-node-id".into()), name: None },
                Contact { root_pk: Some("not-a-valid-pubkey".into()), node_id: None, name: None },
            ],
            mailbox: None,
        };
        assert_eq!(known_roots_from_bundle(&bundle), vec![root]);
    }

    #[test]
    fn verified_revocations_from_bundle_keeps_only_verifying_entries() {
        let root = SecretKey::from_bytes(&seed(0x10));
        let device = SecretKey::from_bytes(&seed(0x20));
        let mut good = Revocation {
            version: 1,
            root_pk: root.public(),
            device_pk: device.public(),
            revoked_at: 1_767_225_600,
            signature: [0u8; 64],
        };
        good.sign(&root);
        let mut bad = good.clone();
        bad.signature[0] ^= 0xff;

        let bundle = IdentityBundle {
            root_pk: "self".to_string(),
            certs: vec![],
            revocations: vec![good.encode(), bad.encode(), "azr-not-even-valid-base32!!".to_string()],
            contacts: vec![],
            mailbox: None,
        };
        assert_eq!(verified_revocations_from_bundle(&bundle), vec![good]);
    }

    // --- run_chat_session (task 8.1 / 8.2) ----------------------------------

    fn make_cert(root: &SecretKey, device: &SecretKey, name: &str) -> DeviceCert {
        let mut cert = DeviceCert {
            version: 1,
            flags: 0,
            root_pk: root.public(),
            device_pk: device.public(),
            issued_at: 1_767_225_600,
            expires_at: 0,
            name: name.to_string(),
            signature: [0u8; 64],
        };
        cert.sign(root);
        cert
    }

    /// One simulated bidirectional connection.
    fn wire_pair() -> (
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
    ) {
        let (other_writer, my_reader) = tokio::io::duplex(8192);
        let (my_writer, other_reader) = tokio::io::duplex(8192);
        (other_writer, other_reader, my_reader, my_writer)
    }

    #[tokio::test]
    async fn chat_session_appends_message_in_for_a_known_certified_root() {
        let mailbox_root = SecretKey::from_bytes(&seed(0x01));
        let mailbox_device = SecretKey::from_bytes(&seed(0x02));
        let mailbox_cert = make_cert(&mailbox_root, &mailbox_device, "mailbox");

        let peer_root = SecretKey::from_bytes(&seed(0x03));
        let peer_device = SecretKey::from_bytes(&seed(0x04));
        let peer_cert = make_cert(&peer_root, &peer_device, "phone");

        let store = LogStore::open(test_dir("known_root_appends"), mailbox_root.public()).unwrap();
        let known_roots = AsyncMutex::new(vec![peer_root.public()]);

        let (mut other_writer, _other_reader, my_reader, my_writer) = wire_pair();
        write_frame(
            &mut other_writer,
            &Frame::Hello { name: "phone".into(), invite: None, cert: Some(peer_cert.encode()) },
        )
        .await
        .unwrap();
        write_frame(&mut other_writer, &Frame::Chat { text: "hello mailbox".into(), id: Some("abc123".into()) })
            .await
            .unwrap();
        drop(other_writer);

        run_chat_session(
            my_reader,
            my_writer,
            peer_device.public(),
            &peer_device.public().to_string(),
            &mailbox_device,
            &mailbox_cert.encode(),
            &store,
            &known_roots,
            &[],
            false,
        )
        .await
        .unwrap();

        let entries = store.read_from(&mailbox_device.public(), 0).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, Kind::MessageIn);
        let body: serde_json::Value = serde_json::from_str(&entries[0].body).unwrap();
        assert_eq!(body["conversation"].as_str().unwrap(), peer_root.public().to_string());
        assert_eq!(body["from_device_pk"].as_str().unwrap(), peer_device.public().to_string());
        assert_eq!(body["text"].as_str().unwrap(), "hello mailbox");
        assert_eq!(body["id"].as_str().unwrap(), "abc123");
    }

    #[tokio::test]
    async fn chat_session_closes_a_stranger_with_no_cert_and_no_invite() {
        let mailbox_device = SecretKey::from_bytes(&seed(0x05));
        let mailbox_root = SecretKey::from_bytes(&seed(0x06));
        let mailbox_cert = make_cert(&mailbox_root, &mailbox_device, "mailbox");
        let store = LogStore::open(test_dir("stranger_closed"), mailbox_root.public()).unwrap();
        let known_roots = AsyncMutex::new(Vec::new());

        let stranger = SecretKey::from_bytes(&seed(0x07));
        let (mut other_writer, _other_reader, my_reader, my_writer) = wire_pair();
        write_frame(&mut other_writer, &Frame::Chat { text: "hi".into(), id: None }).await.unwrap();
        drop(other_writer);

        run_chat_session(
            my_reader,
            my_writer,
            stranger.public(),
            &stranger.public().to_string(),
            &mailbox_device,
            &mailbox_cert.encode(),
            &store,
            &known_roots,
            &[],
            false, // strict: no --allow-legacy
        )
        .await
        .unwrap();

        // Nothing should have been appended -- the connection was closed by
        // the gate before any Chat frame could be processed.
        let entries = store.read_from(&mailbox_device.public(), 0).await.unwrap();
        assert!(entries.is_empty());
    }

    /// Task 6.5: a `device_revoke` entry already sitting in the mailbox's
    /// own `LogStore` (as if learned via a prior sync round) must be
    /// enforced against a peer whose root is otherwise a known contact --
    /// even though it's absent from `run_chat_session`'s own `revocations`
    /// argument (`&[]` here). Mirrors
    /// `sync::tests::hello_rejects_a_device_revoked_via_a_device_revoke_entry_already_in_the_store`
    /// for the chat ALPN's gate.
    #[tokio::test]
    async fn chat_session_rejects_a_device_revoked_via_a_device_revoke_entry_already_in_the_store() {
        let mailbox_device = SecretKey::from_bytes(&seed(0x08));
        let mailbox_root = SecretKey::from_bytes(&seed(0x09));
        let mailbox_cert = make_cert(&mailbox_root, &mailbox_device, "mailbox");

        let peer_root = SecretKey::from_bytes(&seed(0x0a));
        let peer_device = SecretKey::from_bytes(&seed(0x0b));
        let peer_cert = make_cert(&peer_root, &peer_device, "phone");

        let mut revocation = Revocation {
            version: 1,
            root_pk: peer_root.public(),
            device_pk: peer_device.public(),
            revoked_at: 1_767_225_600,
            signature: [0u8; 64],
        };
        revocation.sign(&peer_root);

        let store = LogStore::open(test_dir("chat_session_store_revoked"), mailbox_root.public()).unwrap();
        let body = serde_json::json!({ "revocation": revocation.encode() }).to_string();
        store.append_own(&mailbox_device, Kind::DeviceRevoke, body).await.unwrap();

        // The peer's root is already a known contact -- absent the
        // revocation, this would ride the root-match path with no invite
        // required at all.
        let known_roots = AsyncMutex::new(vec![peer_root.public()]);

        let (mut other_writer, _other_reader, my_reader, my_writer) = wire_pair();
        write_frame(
            &mut other_writer,
            &Frame::Hello { name: "phone".into(), invite: None, cert: Some(peer_cert.encode()) },
        )
        .await
        .unwrap();
        write_frame(&mut other_writer, &Frame::Chat { text: "should not land".into(), id: None })
            .await
            .unwrap();
        drop(other_writer);

        run_chat_session(
            my_reader,
            my_writer,
            peer_device.public(),
            &peer_device.public().to_string(),
            &mailbox_device,
            &mailbox_cert.encode(),
            &store,
            &known_roots,
            &[], // baseline is empty -- the revocation is only in the store
            false,
        )
        .await
        .unwrap();

        // Revoked -> not known -> falls through to the stranger path; no
        // invite + strict mode -> closed before the Chat frame is ever
        // processed. Only the DeviceRevoke entry the mailbox itself
        // authored should be on its own log -- no message_in from the
        // revoked peer.
        let entries = store.read_from(&mailbox_device.public(), 0).await.unwrap();
        assert!(
            entries.iter().all(|e| e.kind == Kind::DeviceRevoke),
            "no message_in should have been appended for a revoked device: {entries:?}"
        );
    }

    /// Real-transport smoke test, following
    /// `link::tests::link_handshake_completes_over_a_real_quic_connection`
    /// (the task-6.7 regression guard): the duplex tests above are blind to
    /// QUIC stream-establishment semantics — a real connection does not
    /// surface a freshly opened bi-stream to the acceptor until the dialer
    /// writes bytes on it. On this ALPN the dialer speaks first (its
    /// `Hello`), which is also what lets [`ChatHandler`]'s `accept_bi()`
    /// resolve at all — but the acceptor's first *frame-level* action is a
    /// read (`gate_peer`), so only a real-two-endpoint run proves the wiring
    /// isn't deadlock-shaped. Two real iroh endpoints, the same handler
    /// `azula mailbox` binds, a certified peer dialing in: the mailbox's
    /// announce `Hello` comes back and the `Chat` lands as a `message_in`
    /// entry. Edge cases stay on the fast duplex tests.
    #[tokio::test]
    async fn chat_session_stores_a_message_over_a_real_quic_connection() {
        use std::time::Duration;

        use iroh::endpoint::presets;
        use iroh::Endpoint;
        use tokio::time::timeout;

        let mailbox_root = SecretKey::from_bytes(&seed(0x30));
        let mailbox_device = SecretKey::from_bytes(&seed(0x31));
        let mailbox_cert = make_cert(&mailbox_root, &mailbox_device, "mailbox");

        let peer_root = SecretKey::from_bytes(&seed(0x32));
        let peer_device = SecretKey::from_bytes(&seed(0x33));
        let peer_cert = make_cert(&peer_root, &peer_device, "phone");

        let store = LogStore::open(test_dir("quic_chat"), mailbox_root.public()).unwrap();

        // The peer's cert must bind to its *transport* node id
        // (`accept_gate::check_cert`), so both endpoints are bound with
        // their device's own secret key rather than a random one.
        let server_ep = Endpoint::builder(presets::Minimal)
            .secret_key(mailbox_device.clone())
            .bind()
            .await
            .expect("server endpoint bind");
        let server_addr = server_ep.addr();
        let handler = ChatHandler::new(
            Arc::new(mailbox_device.clone()),
            mailbox_cert.encode(),
            store.clone(),
            vec![peer_root.public()],
            vec![],
            false, // strict: the cert path alone must admit the peer
        );
        let router = Router::builder(server_ep).accept(CHAT_ALPN, handler).spawn();

        let client_ep = Endpoint::builder(presets::Minimal)
            .secret_key(peer_device.clone())
            .bind()
            .await
            .expect("client endpoint bind");
        let conn = client_ep.connect(server_addr, CHAT_ALPN).await.expect("client connect");
        let (mut send, recv) = conn.open_bi().await.expect("open_bi");

        write_frame(
            &mut send,
            &Frame::Hello { name: "phone".into(), invite: None, cert: Some(peer_cert.encode()) },
        )
        .await
        .expect("write hello");
        write_frame(&mut send, &Frame::Chat { text: "over real quic".into(), id: None })
            .await
            .expect("write chat");

        // The mailbox announces itself back (spec: `Hello.cert` "on every
        // ALPN in both directions") — the reply reaching us over the real
        // connection is the session-completed signal.
        let mut reader = BufReader::new(recv);
        let announce = timeout(Duration::from_secs(30), read_frame(&mut reader))
            .await
            .expect("timed out waiting for the mailbox's announce Hello over a real connection")
            .expect("read Hello")
            .expect("stream closed before the mailbox's Hello");
        match announce {
            Frame::Hello { cert, .. } => {
                assert_eq!(cert.as_deref(), Some(mailbox_cert.encode().as_str()))
            }
            other => panic!("expected the mailbox's announce Hello, got {other:?}"),
        }

        // The Chat frame must land as a message_in entry on the mailbox's log.
        let landed = timeout(Duration::from_secs(30), async {
            loop {
                let entries = store.read_from(&mailbox_device.public(), 0).await.unwrap();
                if !entries.is_empty() {
                    return entries;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("timed out waiting for the message to land in the mailbox's store");
        assert_eq!(landed.len(), 1);
        assert_eq!(landed[0].kind, Kind::MessageIn);
        let body: serde_json::Value = serde_json::from_str(&landed[0].body).unwrap();
        assert_eq!(body["conversation"].as_str().unwrap(), peer_root.public().to_string());
        assert_eq!(body["from_device_pk"].as_str().unwrap(), peer_device.public().to_string());
        assert_eq!(body["text"].as_str().unwrap(), "over real quic");

        let _ = send.finish();
        conn.close(0u32.into(), b"done");
        let _ = router.shutdown().await;
        client_ep.close().await;
    }

    // --- Headline scenarios (tasks 8.3 / 9.1) -------------------------------
    //
    // These exercise `sync::run_session` + `sync::LogStore` directly (the
    // durability machinery the mailbox role is built on) rather than
    // `ChatHandler`/iroh sockets, per the "keep protocol logic testable
    // without real iroh sockets" instruction.

    fn make_entry(device: &SecretKey, seq: u64, lamport: u64, prev_hash: [u8; 32]) -> crate::eventlog::LogEntry {
        let mut e = crate::eventlog::LogEntry::new(Kind::MessageOut, device.public(), seq, lamport, seq * 1000, prev_hash, "{}".to_string());
        e.sign(device);
        e
    }

    async fn append_chain(store: &LogStore, device: &SecretKey, count: u64) {
        let mut prev_hash = [0u8; 32];
        for seq in 1..=count {
            let e = make_entry(device, seq, seq, prev_hash);
            prev_hash = e.hash();
            store.append(e).await.expect("append succeeds");
        }
    }

    /// Run one sync session between `left` and `right`'s stores until both
    /// converge on the union of what each held before the session started,
    /// or a 5s timeout elapses. Used below to simulate one device dialing
    /// the mailbox (never the two peer devices dialing each other).
    async fn sync_until_converged(
        left_cert: &DeviceCert,
        left_store: &LogStore,
        right_cert: &DeviceCert,
        right_store: &LogStore,
    ) {
        let (left_end, right_end) = tokio::io::duplex(1 << 20);
        let (left_reader, left_writer) = tokio::io::split(left_end);
        let (right_reader, right_writer) = tokio::io::split(right_end);

        let left_session = crate::sync::run_session(
            left_reader,
            left_writer,
            left_cert,
            &[],
            right_cert.device_pk,
            left_store.clone(),
        );
        let right_session = crate::sync::run_session(
            right_reader,
            right_writer,
            right_cert,
            &[],
            left_cert.device_pk,
            right_store.clone(),
        );

        let target_vector_len_ok = async {
            loop {
                let lv = left_store.vector().await;
                let rv = right_store.vector().await;
                if lv == rv {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        };

        let outcome: std::result::Result<(), String> = tokio::select! {
            r = left_session => Err(format!("left session ended early: {r:?}")),
            r = right_session => Err(format!("right session ended early: {r:?}")),
            _ = tokio::time::timeout(std::time::Duration::from_secs(5), target_vector_len_ok) => Ok(()),
        };
        outcome.expect("sync session should converge before timing out");
    }

    /// Task 9.1's headline scenario: two fake devices that are **never
    /// concurrently online** still converge with each other purely through
    /// the mailbox's copy of the logs (`specs/account-sync/spec.md`'s
    /// "Mailbox bridges two never-overlapping devices" scenario).
    #[tokio::test]
    async fn mailbox_bridges_two_never_concurrently_online_devices() {
        let root = SecretKey::from_bytes(&seed(0x10));
        let device_a = SecretKey::from_bytes(&seed(0x11));
        let device_b = SecretKey::from_bytes(&seed(0x12));
        let mailbox_device = SecretKey::from_bytes(&seed(0x13));
        let cert_a = make_cert(&root, &device_a, "a");
        let cert_b = make_cert(&root, &device_b, "b");
        let cert_mailbox = make_cert(&root, &mailbox_device, "mailbox");

        let store_a = LogStore::open(test_dir("bridge_a"), root.public()).unwrap();
        let store_b = LogStore::open(test_dir("bridge_b"), root.public()).unwrap();
        let store_mailbox = LogStore::open(test_dir("bridge_mailbox"), root.public()).unwrap();

        // Step 1: A alone appends, then syncs with the mailbox. B is offline
        // throughout this step -- never touches store_b or a connection.
        append_chain(&store_a, &device_a, 3).await;
        sync_until_converged(&cert_a, &store_a, &cert_mailbox, &store_mailbox).await;
        assert_eq!(store_mailbox.vector().await.get(&device_a.public().to_string()), Some(&3));

        // Step 2: A is now offline (dropped). B comes online for the first
        // time, appends its own entries, and syncs with the mailbox -- B
        // receives A's 3 entries it never saw directly, and the mailbox
        // receives B's 2.
        append_chain(&store_b, &device_b, 2).await;
        sync_until_converged(&cert_b, &store_b, &cert_mailbox, &store_mailbox).await;
        assert_eq!(store_b.vector().await.get(&device_a.public().to_string()), Some(&3), "B must learn A's entries via the mailbox alone");
        assert_eq!(store_mailbox.vector().await.get(&device_b.public().to_string()), Some(&2));

        // Step 3: B is now offline. A reconnects to the mailbox (still the
        // only device online besides the mailbox) and picks up B's entries.
        sync_until_converged(&cert_a, &store_a, &cert_mailbox, &store_mailbox).await;
        assert_eq!(store_a.vector().await.get(&device_b.public().to_string()), Some(&2), "A must learn B's entries via the mailbox alone");

        // A and B were never simultaneously connected to anything, let alone
        // each other -- yet their final views of the identity's logs match
        // exactly, entry for entry.
        for device in [&device_a, &device_b] {
            let from_a = store_a.read_from(&device.public(), 0).await.unwrap();
            let from_b = store_b.read_from(&device.public(), 0).await.unwrap();
            let from_mailbox = store_mailbox.read_from(&device.public(), 0).await.unwrap();
            assert_eq!(from_a, from_b);
            assert_eq!(from_a, from_mailbox);
        }
    }

    /// Task 8.3: a just-linked device sends an empty sync vector and
    /// receives the identity's full history from the mailbox alone, with no
    /// interactive sibling online at all (`specs/account-sync/spec.md`'s
    /// "Bootstrap from the mailbox" scenario).
    #[tokio::test]
    async fn bootstrap_from_an_empty_vector_receives_full_history_from_the_mailbox_only() {
        let root = SecretKey::from_bytes(&seed(0x20));
        let device_a = SecretKey::from_bytes(&seed(0x21));
        let device_b = SecretKey::from_bytes(&seed(0x22));
        let mailbox_device = SecretKey::from_bytes(&seed(0x23));
        let new_device = SecretKey::from_bytes(&seed(0x24));
        let cert_a = make_cert(&root, &device_a, "a");
        let cert_b = make_cert(&root, &device_b, "b");
        let cert_mailbox = make_cert(&root, &mailbox_device, "mailbox");
        let cert_new = make_cert(&root, &new_device, "new");

        // The mailbox already holds full history from two prior siblings
        // (built up exactly as in the store-and-forward scenario above).
        let store_a = LogStore::open(test_dir("bootstrap_a"), root.public()).unwrap();
        let store_b = LogStore::open(test_dir("bootstrap_b"), root.public()).unwrap();
        let store_mailbox = LogStore::open(test_dir("bootstrap_mailbox"), root.public()).unwrap();
        append_chain(&store_a, &device_a, 4).await;
        sync_until_converged(&cert_a, &store_a, &cert_mailbox, &store_mailbox).await;
        append_chain(&store_b, &device_b, 3).await;
        sync_until_converged(&cert_b, &store_b, &cert_mailbox, &store_mailbox).await;
        assert_eq!(store_mailbox.vector().await.len(), 2, "sanity: mailbox holds both devices' logs");

        // A brand-new, empty device store comes online with ONLY the
        // mailbox reachable -- no store_a/store_b session ever runs again
        // in this test.
        let store_new = LogStore::open(test_dir("bootstrap_new"), root.public()).unwrap();
        assert!(store_new.vector().await.is_empty(), "sanity: the new device starts with nothing");

        sync_until_converged(&cert_new, &store_new, &cert_mailbox, &store_mailbox).await;

        let new_vector = store_new.vector().await;
        assert_eq!(new_vector.get(&device_a.public().to_string()), Some(&4));
        assert_eq!(new_vector.get(&device_b.public().to_string()), Some(&3));
        for device in [&device_a, &device_b] {
            assert_eq!(
                store_new.read_from(&device.public(), 0).await.unwrap(),
                store_mailbox.read_from(&device.public(), 0).await.unwrap()
            );
        }
    }

    // --- run_llm_session (task 4.3: relay's LLM-ALPN admission gate) -------

    fn session_cert(machine: &SecretKey, session: &SecretKey) -> DeviceCert {
        crate::certs::mint_session_cert(machine, session.public(), crate::certs::DEFAULT_SESSION_EXPIRY)
    }

    #[tokio::test]
    async fn llm_session_admits_a_valid_session_cert_and_folds_chat_to_agent_in() {
        let machine = SecretKey::from_bytes(&seed(0x50));
        let session = SecretKey::from_bytes(&seed(0x51));
        let relay_device = SecretKey::from_bytes(&seed(0x52));
        let cert = session_cert(&machine, &session);

        let store = LogStore::open(test_dir("llm_admit"), machine.public()).unwrap();
        let a2ui_store =
            crate::core::relay_a2ui::RelayA2uiStore::open(test_dir("llm_admit_a2ui"), machine.public()).unwrap();
        let known_roots = AsyncMutex::new(vec![machine.public()]);

        let (mut other_writer, _other_reader, my_reader, my_writer) = wire_pair();
        write_frame(&mut other_writer, &Frame::Hello { name: "Claude".into(), invite: None, cert: Some(cert.encode()) })
            .await
            .unwrap();
        write_frame(&mut other_writer, &Frame::Chat { text: "hello from claude".into(), id: Some("abc123".into()) })
            .await
            .unwrap();
        drop(other_writer);

        run_llm_session(my_reader, my_writer, session.public(), &relay_device, &store, &a2ui_store, &known_roots)
            .await
            .unwrap();

        let entries = store.read_from(&relay_device.public(), 0).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, Kind::AgentIn);
        let body: AgentInBody = serde_json::from_str(&entries[0].body).unwrap();
        assert_eq!(body.conversation, session.public().to_string(), "conversation keyed by the SESSION's own pk");
        assert_eq!(body.text, "hello from claude");
        assert_eq!(body.id.as_deref(), Some("abc123"));
        assert_eq!(body.from_name.as_deref(), Some("Claude"));
    }

    #[tokio::test]
    async fn llm_session_closes_a_session_whose_root_is_not_a_known_contact() {
        let machine = SecretKey::from_bytes(&seed(0x53));
        let session = SecretKey::from_bytes(&seed(0x54));
        let relay_device = SecretKey::from_bytes(&seed(0x55));
        let cert = session_cert(&machine, &session);

        let store = LogStore::open(test_dir("llm_unknown_root"), machine.public()).unwrap();
        let a2ui_store =
            crate::core::relay_a2ui::RelayA2uiStore::open(test_dir("llm_unknown_root_a2ui"), machine.public())
                .unwrap();
        let known_roots = AsyncMutex::new(Vec::new()); // machine.public() is NOT a known contact

        let (mut other_writer, _other_reader, my_reader, my_writer) = wire_pair();
        write_frame(&mut other_writer, &Frame::Hello { name: "Claude".into(), invite: None, cert: Some(cert.encode()) })
            .await
            .unwrap();
        write_frame(&mut other_writer, &Frame::Chat { text: "should not land".into(), id: None }).await.unwrap();
        drop(other_writer);

        run_llm_session(my_reader, my_writer, session.public(), &relay_device, &store, &a2ui_store, &known_roots)
            .await
            .unwrap();

        assert!(
            store.read_from(&relay_device.public(), 0).await.unwrap().is_empty(),
            "an uncertified stranger (unknown root) must not be admitted -- relay spec's 'falls through to the ordinary invite path' has no invite concept on this ALPN, so closed"
        );
    }

    #[tokio::test]
    async fn llm_session_closes_a_connection_with_no_cert() {
        let machine = SecretKey::from_bytes(&seed(0x56));
        let session = SecretKey::from_bytes(&seed(0x57));
        let relay_device = SecretKey::from_bytes(&seed(0x58));

        let store = LogStore::open(test_dir("llm_no_cert"), machine.public()).unwrap();
        let a2ui_store =
            crate::core::relay_a2ui::RelayA2uiStore::open(test_dir("llm_no_cert_a2ui"), machine.public()).unwrap();
        let known_roots = AsyncMutex::new(vec![machine.public()]);

        let (mut other_writer, _other_reader, my_reader, my_writer) = wire_pair();
        write_frame(&mut other_writer, &Frame::Hello { name: "Claude".into(), invite: None, cert: None }).await.unwrap();
        write_frame(&mut other_writer, &Frame::Chat { text: "should not land".into(), id: None }).await.unwrap();
        drop(other_writer);

        run_llm_session(my_reader, my_writer, session.public(), &relay_device, &store, &a2ui_store, &known_roots)
            .await
            .unwrap();

        assert!(store.read_from(&relay_device.public(), 0).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn llm_session_stores_a2ui_snapshot_keyed_by_the_authenticated_session_not_the_client_claim() {
        let machine = SecretKey::from_bytes(&seed(0x59));
        let session = SecretKey::from_bytes(&seed(0x5a));
        let relay_device = SecretKey::from_bytes(&seed(0x5b));
        let cert = session_cert(&machine, &session);

        let store = LogStore::open(test_dir("llm_a2ui"), machine.public()).unwrap();
        let a2ui_store =
            crate::core::relay_a2ui::RelayA2uiStore::open(test_dir("llm_a2ui_snap"), machine.public()).unwrap();
        let known_roots = AsyncMutex::new(vec![machine.public()]);

        let (mut other_writer, _other_reader, my_reader, my_writer) = wire_pair();
        write_frame(&mut other_writer, &Frame::Hello { name: "Claude".into(), invite: None, cert: Some(cert.encode()) })
            .await
            .unwrap();
        write_frame(
            &mut other_writer,
            &Frame::A2uiSnapshot {
                conversation: "ignored-client-claim".into(),
                surface: "dice-1".into(),
                components: Some(serde_json::json!([{"id":"root"}])),
                data_model: None,
                lamport: 1,
            },
        )
        .await
        .unwrap();
        drop(other_writer);

        run_llm_session(my_reader, my_writer, session.public(), &relay_device, &store, &a2ui_store, &known_roots)
            .await
            .unwrap();

        let pending = a2ui_store.drain_pending_messages_for_device("some-phone").await;
        let conversation_key = session.public().to_string();
        assert!(
            pending.contains_key(&conversation_key),
            "must be stored under the SESSION's own authenticated pk, not the client-claimed conversation field; got keys: {:?}",
            pending.keys().collect::<Vec<_>>()
        );
        assert_eq!(pending[&conversation_key].len(), 2, "createSurface + updateComponents");
    }

    // --- Headline 4.7 scenario: relay-carried agent chat converges to the ---
    // --- phone purely via sync, exactly like `message_in`/mailbox already --
    // --- does for peer chat.                                              --

    /// relay spec's "Laptop asleep, message still delivered" / account-sync
    /// spec's "Relayed agent message folds into the session conversation": a
    /// session delivers `Chat` to the relay's LLM ALPN while the phone is
    /// offline (it never appears in this test at all during delivery); the
    /// phone later syncs with the relay and receives the resulting
    /// `agent_in` entry, keyed by the session's own public key.
    #[tokio::test]
    async fn session_delivers_chat_to_relay_and_phone_receives_agent_in_via_sync() {
        let machine = SecretKey::from_bytes(&seed(0x60));
        let session = SecretKey::from_bytes(&seed(0x61));
        let relay_device = SecretKey::from_bytes(&seed(0x62));
        let phone_device = SecretKey::from_bytes(&seed(0x63));
        let cert = session_cert(&machine, &session);
        let cert_relay = make_cert(&machine, &relay_device, "relay");
        let cert_phone = make_cert(&machine, &phone_device, "phone");

        let relay_store = LogStore::open(test_dir("convergence_relay"), machine.public()).unwrap();
        let a2ui_store =
            crate::core::relay_a2ui::RelayA2uiStore::open(test_dir("convergence_relay_a2ui"), machine.public())
                .unwrap();
        let known_roots = AsyncMutex::new(vec![machine.public()]);

        // Step 1: the session delivers a Chat frame to the relay's LLM-ALPN
        // admission path. The phone is never touched here at all -- it's
        // simply not part of this delivery.
        let (mut other_writer, _other_reader, my_reader, my_writer) = wire_pair();
        write_frame(&mut other_writer, &Frame::Hello { name: "Claude".into(), invite: None, cert: Some(cert.encode()) })
            .await
            .unwrap();
        write_frame(&mut other_writer, &Frame::Chat { text: "build failed, please look".into(), id: Some("retry-id-1".into()) })
            .await
            .unwrap();
        drop(other_writer);
        run_llm_session(my_reader, my_writer, session.public(), &relay_device, &relay_store, &a2ui_store, &known_roots)
            .await
            .unwrap();

        // Step 2: the phone, having been offline this whole time, syncs with
        // the relay and picks up the agent_in entry the relay logged.
        let phone_store = LogStore::open(test_dir("convergence_phone"), machine.public()).unwrap();
        sync_until_converged(&cert_phone, &phone_store, &cert_relay, &relay_store).await;

        let entries = phone_store.read_from(&relay_device.public(), 0).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, Kind::AgentIn);
        let body: AgentInBody = serde_json::from_str(&entries[0].body).unwrap();
        assert_eq!(body.conversation, session.public().to_string(), "keyed by the SESSION's public key");
        assert_eq!(body.text, "build failed, please look");
        assert_eq!(body.id.as_deref(), Some("retry-id-1"));
        assert_eq!(body.from_name.as_deref(), Some("Claude"));
        // Exact entry bytes decode: a byte round trip through the same
        // base64 codec the wire uses.
        assert_eq!(crate::eventlog::LogEntry::from_base64(&entries[0].to_base64()).unwrap(), entries[0]);
    }

    // --- A2UI snapshot replay on reconnect (task 4.6/4.7) -------------------

    /// Drive the "phone" side of one sync round manually rather than via
    /// `sync::run_session` (which only understands `SyncEntries`/`SyncAck`
    /// and deliberately ignores anything else, per its own doc comment) so
    /// this test can also capture `SyncA2ui` frames. Stops listening the
    /// instant `SyncAck` arrives -- mirrors the Kotlin receive loop's bounded
    /// `untilAck` catch-up cutoff the coordinator flagged, which is exactly
    /// why the relay's `PreSyncAckHook` fires *before* the ack, not after.
    async fn run_phone_side_capturing_sync_a2ui<R, W>(
        reader: R,
        mut writer: W,
        my_cert: &DeviceCert,
        store: &LogStore,
    ) -> Vec<Frame>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut reader = BufReader::new(reader);
        write_frame(&mut writer, &Frame::SyncHello { cert: my_cert.encode() }).await.unwrap();
        match read_frame(&mut reader).await.unwrap() {
            Some(Frame::SyncHello { .. }) => {}
            other => panic!("expected SyncHello, got {other:?}"),
        }
        let my_vector = store.vector().await;
        write_frame(&mut writer, &Frame::SyncVector { vector: my_vector }).await.unwrap();
        match read_frame(&mut reader).await.unwrap() {
            Some(Frame::SyncVector { .. }) => {}
            other => panic!("expected SyncVector, got {other:?}"),
        }

        let mut captured = Vec::new();
        loop {
            match read_frame(&mut reader).await.unwrap() {
                Some(Frame::SyncEntries { entries }) => {
                    for b64 in entries {
                        let entry = crate::eventlog::LogEntry::from_base64(&b64).unwrap();
                        let _ = store.append(entry).await;
                    }
                }
                Some(f @ Frame::SyncA2ui { .. }) => captured.push(f),
                Some(Frame::SyncAck { .. }) => break,
                Some(other) => panic!("unexpected frame: {other:?}"),
                None => break,
            }
        }
        captured
    }

    /// Builds the same `PreSyncAckHook` `azula relay`'s `run` wires up:
    /// drain `a2ui_store`'s pending messages for the syncing peer, one
    /// `SyncA2ui` frame per conversation.
    fn a2ui_replay_hook(a2ui_store: crate::core::relay_a2ui::RelayA2uiStore) -> PreSyncAckHook {
        Arc::new(move |peer_device_pk: PublicKey| {
            let store = a2ui_store.clone();
            Box::pin(async move {
                store
                    .drain_pending_messages_for_device(&peer_device_pk.to_string())
                    .await
                    .into_iter()
                    .map(|(conversation, messages)| Frame::SyncA2ui { conversation, messages })
                    .collect()
            })
        })
    }

    #[tokio::test]
    async fn replay_after_sync_delivers_pending_once_and_not_again_to_the_same_device() {
        let machine = SecretKey::from_bytes(&seed(0x64));
        let phone_device = SecretKey::from_bytes(&seed(0x65));
        let phone_device_pk = phone_device.public();
        let relay_device = SecretKey::from_bytes(&seed(0x66));
        let cert_relay = make_cert(&machine, &relay_device, "relay");
        let cert_phone = make_cert(&machine, &phone_device, "phone");

        let relay_store = LogStore::open(test_dir("replay_relay_store"), machine.public()).unwrap();
        let phone_store = LogStore::open(test_dir("replay_phone_store"), machine.public()).unwrap();
        let a2ui_store =
            crate::core::relay_a2ui::RelayA2uiStore::open(test_dir("replay_a2ui"), machine.public()).unwrap();
        a2ui_store.put("conv1", "dice-1", Some(serde_json::json!([{"id":"root"}])), None, 1).await.unwrap();
        let hook = a2ui_replay_hook(a2ui_store.clone());

        // First sync: the phone must receive the one pending SyncA2ui frame.
        let (a_end, b_end) = tokio::io::duplex(1 << 16);
        let (relay_reader, relay_writer) = tokio::io::split(a_end);
        let (phone_reader, phone_writer) = tokio::io::split(b_end);
        let cert_relay_owned = cert_relay.clone();
        let store_owned = relay_store.clone();
        let hook_owned = hook.clone();
        let relay_task = tokio::spawn(async move {
            crate::sync::run_session_with_hook(
                relay_reader, relay_writer, &cert_relay_owned, &[], phone_device_pk, store_owned, Some(hook_owned),
            )
            .await
        });
        let received = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            run_phone_side_capturing_sync_a2ui(phone_reader, phone_writer, &cert_phone, &phone_store),
        )
        .await
        .expect("timed out waiting for the first sync round to reach SyncAck");
        relay_task.abort();

        assert_eq!(received.len(), 1, "one SyncA2ui frame for the one pending conversation");
        match &received[0] {
            Frame::SyncA2ui { conversation, messages } => {
                assert_eq!(conversation, "conv1");
                assert_eq!(messages.len(), 2, "createSurface + updateComponents");
            }
            other => panic!("expected SyncA2ui, got {other:?}"),
        }

        // Second sync from the SAME device: the snapshot hasn't changed, so
        // nothing should replay again.
        let (a_end2, b_end2) = tokio::io::duplex(1 << 16);
        let (relay_reader2, relay_writer2) = tokio::io::split(a_end2);
        let (phone_reader2, phone_writer2) = tokio::io::split(b_end2);
        let cert_relay_owned2 = cert_relay.clone();
        let store_owned2 = relay_store.clone();
        let relay_task2 = tokio::spawn(async move {
            crate::sync::run_session_with_hook(
                relay_reader2, relay_writer2, &cert_relay_owned2, &[], phone_device_pk, store_owned2, Some(hook),
            )
            .await
        });
        let received2 = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            run_phone_side_capturing_sync_a2ui(phone_reader2, phone_writer2, &cert_phone, &phone_store),
        )
        .await
        .expect("timed out waiting for the second sync round to reach SyncAck");
        relay_task2.abort();

        assert!(received2.is_empty(), "already-delivered snapshot must not replay again to the same device");
    }

    #[tokio::test]
    async fn replay_after_sync_redelivers_once_the_snapshot_changes_again() {
        let machine = SecretKey::from_bytes(&seed(0x67));
        let phone_device = SecretKey::from_bytes(&seed(0x68));
        let phone_device_pk = phone_device.public();
        let relay_device = SecretKey::from_bytes(&seed(0x69));
        let cert_relay = make_cert(&machine, &relay_device, "relay");
        let cert_phone = make_cert(&machine, &phone_device, "phone");

        let relay_store = LogStore::open(test_dir("redeliver_relay_store"), machine.public()).unwrap();
        let phone_store = LogStore::open(test_dir("redeliver_phone_store"), machine.public()).unwrap();
        let a2ui_store =
            crate::core::relay_a2ui::RelayA2uiStore::open(test_dir("redeliver_a2ui"), machine.public()).unwrap();
        a2ui_store.put("conv1", "dice-1", Some(serde_json::json!([{"id":"root"}])), None, 1).await.unwrap();
        let hook = a2ui_replay_hook(a2ui_store.clone());

        let run_one_round = |hook: PreSyncAckHook| {
            let cert_relay = cert_relay.clone();
            let relay_store = relay_store.clone();
            let cert_phone = &cert_phone;
            let phone_store = &phone_store;
            async move {
                let (a_end, b_end) = tokio::io::duplex(1 << 16);
                let (relay_reader, relay_writer) = tokio::io::split(a_end);
                let (phone_reader, phone_writer) = tokio::io::split(b_end);
                let relay_task = tokio::spawn(async move {
                    crate::sync::run_session_with_hook(
                        relay_reader, relay_writer, &cert_relay, &[], phone_device_pk, relay_store, Some(hook),
                    )
                    .await
                });
                let received = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    run_phone_side_capturing_sync_a2ui(phone_reader, phone_writer, cert_phone, phone_store),
                )
                .await
                .expect("timed out waiting for a sync round to reach SyncAck");
                relay_task.abort();
                received
            }
        };

        assert_eq!(run_one_round(hook.clone()).await.len(), 1, "first sync delivers the pending snapshot");
        assert!(run_one_round(hook.clone()).await.is_empty(), "second sync (unchanged) delivers nothing");

        // The surface changes again -- a new lamport must redeliver.
        a2ui_store.put("conv1", "dice-1", Some(serde_json::json!([{"id":"root","text":"v2"}])), None, 2).await.unwrap();
        assert_eq!(run_one_round(hook).await.len(), 1, "a changed snapshot must replay again");
    }
}
