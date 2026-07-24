//! `azula/sync/0` session: catch-up + live replication of per-device
//! append-only logs between same-root certified sibling devices.
//!
//! See `azula-docs/openspec/changes/multi-device-identity/specs/account-sync/spec.md`'s
//! "Sync Runs Only Between Same-Root Certified Devices" requirement, which
//! this module implements exactly:
//!
//! 1. Mutual `SyncHello{cert}`. Each side verifies the peer's cert —
//!    signature valid, chains to *its own* root key, not revoked, and the
//!    cert's `device_pk` equals the connection's transport node id — closing
//!    the connection (no further writes) on any failure. See
//!    [`read_and_verify_hello`].
//! 2. Both sides send `SyncVector{vector}`: device public key hex to the
//!    highest **contiguous** `seq` held for that device.
//! 3. Each side streams `SyncEntries{entries}` for whatever the other side's
//!    vector says it's missing — per-device, ascending `seq`, at most
//!    [`MAX_ENTRIES_PER_FRAME`] entries per frame.
//! 4. Both send `SyncAck{vector}`.
//! 5. While the connection stays open, newly appended entries are pushed
//!    immediately as further `SyncEntries` frames — no new vector exchange.
//!
//! [`run_session`] is the whole protocol, generic over any
//! `AsyncRead`/`AsyncWrite` pair (an in-memory `tokio::io::duplex` in this
//! module's tests, or a real iroh `RecvStream`/`SendStream` pair via
//! [`SyncHandler`]/[`dial_sync`] — the "thin" iroh wiring on top). Storage is
//! [`LogStore`]: one append-only, newline-delimited base64-`LogEntry` file
//! per device public key (the same JSONL-per-line house style as
//! `mailbox.rs`), backed by an in-memory [`eventlog::DeviceLogChain`] per
//! device for O(1) chain validation without re-reading the whole file on
//! every append.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointAddr, PublicKey, SecretKey};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tokio::sync::{Mutex as AsyncMutex, Notify};
use tracing::{info, warn};

use crate::certs::{DeviceCert, Revocation};
use crate::eventlog::{DeviceLogChain, Kind, LogEntry};
use crate::proto::{read_frame, write_frame, Frame};

/// ALPN identifier for the account-sync protocol.
pub const SYNC_ALPN: &[u8] = b"azula/sync/0";

/// Cap on entries per `SyncEntries` frame (spec: "at most 64 per frame").
const MAX_ENTRIES_PER_FRAME: usize = 64;

/// Body shape of a `Kind::DeviceRevoke` log entry: `{revocation}`, an
/// `"azr…"`-encoded revocation statement (`specs/account-sync/spec.md`'s
/// "Event Kinds"). Used only by [`LogStore::device_revocations`].
#[derive(Deserialize)]
struct DeviceRevokeBody {
    revocation: String,
}

// ---------------------------------------------------------------------------
// Log store: per-device append-only files + in-memory chain-validation state
// ---------------------------------------------------------------------------

/// Per-device append-only log storage, namespaced by root identity: one file
/// per device public key (`<dir>/<root_pk_hex>/<device_pk_hex>.jsonl`), one
/// base64-encoded [`LogEntry`] per line — matching `mailbox.rs`'s JSONL house
/// style, but storing sync log entries rather than queued frames. Cheaply
/// [`Clone`] (an `Arc` handle) so both halves of a live session (and multiple
/// concurrent sessions with different siblings) can share one store.
///
/// multi-device-identity task 4.6: before this namespacing existed, `dir`
/// itself held the per-device files directly, with no binding to which root
/// identity's devices they belonged to. A device that authored entries while
/// enrolled in one identity, then linked into a different one, would keep
/// signing (and syncing) into the very same files under its new identity's
/// certified key — its old identity's private history would silently fold
/// into the new one. Root-scoping the directory means enrolling into an
/// identity starts a fresh, empty log set; see [`open`](Self::open) for the
/// one-time migration of a pre-existing flat layout.
#[derive(Clone, Debug)]
pub struct LogStore {
    dir: PathBuf,
    /// In-memory chain-validation cursor per device (plus the store-wide
    /// max-lamport tracker `append_own` needs), rebuilt from disk at
    /// [`open`](Self::open) time. The source of truth is always the disk
    /// file; this is purely an accept-fast-path cache so every append/accept
    /// doesn't have to re-read and re-validate the whole file.
    state: Arc<AsyncMutex<StoreState>>,
    /// Signalled after every successful [`append`](Self::append), so a live
    /// session's send loop can push new entries without polling.
    notify: Arc<Notify>,
}

/// The mutable state behind [`LogStore`]'s single lock: each device's chain
/// cursor, and the highest `lamport` this store has ever accepted for any
/// device (needed by [`LogStore::append_own`] — kept alongside `chains`,
/// not a separate lock, so the two never drift out of sync with each other).
#[derive(Debug, Default)]
struct StoreState {
    chains: HashMap<PublicKey, DeviceLogChain>,
    max_lamport: u64,
}

impl LogStore {
    /// Open (creating if needed) a log store for `root_pk` rooted at
    /// `<base_dir>/<root_pk_hex>/`, replaying every existing
    /// `<device_pk_hex>.jsonl` file there to rebuild each device's chain
    /// cursor and the store's max-lamport tracker. A file whose name isn't a
    /// valid device public key is skipped (logged); a file whose contents
    /// fail chain validation is a hard error (it can only mean on-disk
    /// corruption, since nothing but a successful [`append`](Self::append) —
    /// which validates first — ever writes to these files).
    ///
    /// `root_pk` is required, not defaulted: this store's entire purpose
    /// (task 4.6) is keeping one identity's logs from ever landing under a
    /// different one, so a call site with no root pk to hand over has a
    /// wiring bug that must surface, not a plausible-looking default to fall
    /// back on.
    ///
    /// One-time migration: if `base_dir` itself still holds `.jsonl` files
    /// directly (the pre-4.6 flat layout — this change's own 4.4 backfill may
    /// have written some there during development) and `root_pk`'s namespaced
    /// subdirectory doesn't exist yet, those files are moved under it rather
    /// than left orphaned or silently merged with whatever root now opens
    /// this store. See [`relocate_flat_layout_if_needed`].
    pub fn open(base_dir: impl Into<PathBuf>, root_pk: PublicKey) -> Result<Self> {
        let base_dir = base_dir.into();
        let dir = base_dir.join(root_pk.to_string());
        relocate_flat_layout_if_needed(&base_dir, &dir)?;
        std::fs::create_dir_all(&dir).with_context(|| format!("log store: create {}", dir.display()))?;

        let mut state = StoreState::default();
        for entry in
            std::fs::read_dir(&dir).with_context(|| format!("log store: read_dir {}", dir.display()))?
        {
            let entry = entry.with_context(|| format!("log store: read_dir entry in {}", dir.display()))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let Ok(device_pk) = PublicKey::from_str(stem) else {
                warn!(path = %path.display(), "log store: skipping file whose name isn't a device public key");
                continue;
            };

            let mut chain = DeviceLogChain::new(device_pk);
            for line in read_lines(&path)? {
                let log_entry = LogEntry::from_base64(&line)
                    .with_context(|| format!("log store: corrupt entry in {}", path.display()))?;
                state.max_lamport = state.max_lamport.max(log_entry.lamport);
                chain
                    .accept(&log_entry)
                    .with_context(|| format!("log store: corrupt chain in {}", path.display()))?;
            }
            if chain.seq() > 0 {
                state.chains.insert(device_pk, chain);
            }
        }

        Ok(Self { dir, state: Arc::new(AsyncMutex::new(state)), notify: Arc::new(Notify::new()) })
    }

    /// Validate `entry` through `eventlog`'s chain rules (signature, `seq`
    /// continuity, `prev_hash`) against whatever this store already holds
    /// for `entry.device_pk`, and — only on success — persist it and advance
    /// that device's cursor. On rejection nothing is written and the cursor
    /// is left exactly as it was. Serves both the local producer path (a
    /// device appending its own next entry) and the sync receive path (an
    /// inbound entry from a sibling) — the spec draws no distinction between
    /// them, and neither does `eventlog::LogEntry::validate_for_append`/
    /// `validate_for_receive`.
    pub async fn append(&self, entry: LogEntry) -> Result<()> {
        let mut state = self.state.lock().await;
        let mut chain = state
            .chains
            .get(&entry.device_pk)
            .cloned()
            .unwrap_or_else(|| DeviceLogChain::new(entry.device_pk));
        chain.accept(&entry)?;

        let path = device_file_path(&self.dir, &entry.device_pk);
        append_line(&path, &entry.to_base64())
            .with_context(|| format!("log store: append to {}", path.display()))?;

        state.max_lamport = state.max_lamport.max(entry.lamport);
        state.chains.insert(entry.device_pk, chain);
        drop(state);
        self.notify.notify_one();
        Ok(())
    }

    /// Build, sign, and append the next entry in `device_secret`'s own log:
    /// `seq`/`prev_hash` continue this store's existing chain for that
    /// device (or start it, if none yet — `seq` 1, all-zero `prev_hash`),
    /// and `lamport` is one greater than the highest lamport this store has
    /// accepted for *any* device — the account-sync spec's append-side rule
    /// ("`lamport`: one greater than the highest lamport the device has seen
    /// anywhere at append time"). Used both to record a sender's own
    /// `message_out` and a mailbox's inbound `message_in`; this module draws
    /// no distinction between them, matching `eventlog`'s own
    /// `validate_for_append`/`validate_for_receive` symmetry. Returns the
    /// appended, signed entry.
    pub async fn append_own(&self, device_secret: &SecretKey, kind: Kind, body: String) -> Result<LogEntry> {
        let device_pk = device_secret.public();
        let mut state = self.state.lock().await;
        let mut chain =
            state.chains.get(&device_pk).cloned().unwrap_or_else(|| DeviceLogChain::new(device_pk));
        let (seq, prev_hash) = match chain.cursor() {
            Some(c) => (c.seq + 1, c.hash),
            None => (1, [0u8; 32]),
        };
        let lamport = state.max_lamport + 1;
        let ts_ms = now_ms();

        let mut entry = LogEntry::new(kind, device_pk, seq, lamport, ts_ms, prev_hash, body);
        entry.sign(device_secret);
        chain
            .accept(&entry)
            .context("log store: freshly built own entry failed its own chain validation (bug)")?;

        let path = device_file_path(&self.dir, &device_pk);
        append_line(&path, &entry.to_base64())
            .with_context(|| format!("log store: append to {}", path.display()))?;

        state.max_lamport = state.max_lamport.max(lamport);
        state.chains.insert(device_pk, chain);
        drop(state);
        self.notify.notify_one();
        Ok(entry)
    }

    /// Every stored entry for `device_pk` with `seq > from_seq`, ascending
    /// (the on-disk file is already ascending by construction — only
    /// [`append`](Self::append)/[`append_own`](Self::append_own) ever write
    /// to it, and both validate seq continuity first).
    pub async fn read_from(&self, device_pk: &PublicKey, from_seq: u64) -> Result<Vec<LogEntry>> {
        let path = device_file_path(&self.dir, device_pk);
        let mut out = Vec::new();
        for line in read_lines(&path)? {
            let entry = LogEntry::from_base64(&line)
                .with_context(|| format!("log store: corrupt entry in {}", path.display()))?;
            if entry.seq > from_seq {
                out.push(entry);
            }
        }
        Ok(out)
    }

    /// The per-device high-water vector: device public key hex to the
    /// highest contiguous `seq` held for that device — exactly the shape
    /// `Frame::SyncVector`/`Frame::SyncAck` carry.
    pub async fn vector(&self) -> BTreeMap<String, u64> {
        let state = self.state.lock().await;
        state
            .chains
            .iter()
            .map(|(pk, chain)| (pk.to_string(), chain.seq()))
            .filter(|(_, seq)| *seq > 0)
            .collect()
    }

    /// Resolves after the next (or an already-pending) successful
    /// [`append`](Self::append) to any device in this store. Used by a live
    /// session's send loop to know when to recompute the vector and push
    /// whatever's new — never missed even if multiple appends land between
    /// two calls, since the loop always recomputes the full current vector
    /// rather than trusting a notification count.
    async fn notified(&self) {
        self.notify.notified().await;
    }

    /// Every `Kind::DeviceRevoke` entry held in this store (across every
    /// device's log) whose embedded revocation statement decodes and
    /// verifies. This is how a device picks up a revocation a sibling
    /// appended to *its own* log, once this store has synced that entry in
    /// — `specs/device-linking/spec.md`'s "Revocation Statements Invalidate
    /// Certificates" requirement: "Own devices enforce revocation after
    /// sync" ("it thereafter refuses sync and known-peer treatment for that
    /// device key"). An entry's own signature (already checked by
    /// `eventlog::DeviceLogChain` before it was ever accepted into this
    /// store) only proves who authored the *log entry* — it says nothing
    /// about whether the revocation payload embedded in its body is itself
    /// validly signed by a root secret, so that's verified here too, same
    /// discard-invalid contract as
    /// `mailbox_role::verified_revocations_from_bundle`.
    ///
    /// Called fresh by [`run_session`] on every session (see there) rather
    /// than cached, so a revocation synced in from one sibling is enforced
    /// against the very next connection — deliberately simple over fast:
    /// this crate's logs are small enough that a full per-device rescan on
    /// every accept is not a real cost.
    pub async fn device_revocations(&self) -> Vec<Revocation> {
        let devices: Vec<PublicKey> = {
            let state = self.state.lock().await;
            state.chains.keys().copied().collect()
        };
        let mut out = Vec::new();
        for device_pk in devices {
            let Ok(entries) = self.read_from(&device_pk, 0).await else { continue };
            for entry in entries {
                if entry.kind != Kind::DeviceRevoke {
                    continue;
                }
                let Ok(body) = serde_json::from_str::<DeviceRevokeBody>(&entry.body) else {
                    continue;
                };
                let Ok(rev) = Revocation::decode(&body.revocation) else { continue };
                if rev.verify().is_ok() {
                    out.push(rev);
                }
            }
        }
        out
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn device_file_path(dir: &Path, device_pk: &PublicKey) -> PathBuf {
    dir.join(format!("{device_pk}.jsonl"))
}

/// multi-device-identity task 4.6's one-time migration: if `namespaced_dir`
/// (this root's `<base_dir>/<root_pk_hex>/` subdirectory) doesn't exist yet,
/// AND `base_dir` itself directly holds flat `<device_pk_hex>.jsonl` files
/// (the layout every device's log store used before this task), those files
/// are moved under `namespaced_dir` instead of being left behind — this
/// change is still unreleased, so the only way a flat file can exist at all
/// is from the 4.4 backfill running during development against a build that
/// predates this task, in which case it was necessarily written under
/// whichever root is doing the migrating. A no-op if `namespaced_dir`
/// already exists (already migrated, or never had a flat layout to begin
/// with) or `base_dir` has no flat `.jsonl` files.
fn relocate_flat_layout_if_needed(base_dir: &Path, namespaced_dir: &Path) -> Result<()> {
    if namespaced_dir.exists() {
        return Ok(());
    }
    let Ok(read_dir) = std::fs::read_dir(base_dir) else {
        return Ok(()); // base_dir doesn't exist yet -- nothing to migrate.
    };
    let flat_files: Vec<PathBuf> = read_dir
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().and_then(|e| e.to_str()) == Some("jsonl"))
        .collect();
    if flat_files.is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(namespaced_dir)
        .with_context(|| format!("log store: create {}", namespaced_dir.display()))?;
    for file in flat_files {
        let Some(file_name) = file.file_name() else { continue };
        let dest = namespaced_dir.join(file_name);
        std::fs::rename(&file, &dest)
            .with_context(|| format!("log store: relocate {} to {}", file.display(), dest.display()))?;
    }
    Ok(())
}

/// Read a file's non-blank lines. A missing file reads as empty (a device
/// this store has never heard of yet).
fn read_lines(path: &Path) -> Result<Vec<String>> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(s.lines().filter(|l| !l.trim().is_empty()).map(str::to_string).collect()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(e).with_context(|| format!("log store: read {}", path.display())),
    }
}

fn append_line(path: &Path, line: &str) -> Result<()> {
    use std::io::Write as _;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{line}")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// Outcome of a sync session that ran to completion without a hard I/O
/// error.
#[derive(Debug)]
pub enum SyncOutcome {
    /// The peer's `SyncHello` failed verification (or a malformed/absent
    /// frame arrived instead) — the connection was closed before any vector
    /// or entry exchange. Carries a human-readable reason for logging.
    HelloRejected(String),
    /// The catch-up + live phase ran until one side's connection closed.
    Closed,
}

/// Run one `azula/sync/0` session end to end, per this module's doc comment.
/// Generic over any `AsyncRead`/`AsyncWrite` pair so it needs no real iroh
/// socket to test — see [`SyncHandler`]/[`dial_sync`] for the thin iroh
/// wiring, and this module's tests for an in-memory two-fake-device run.
///
/// `my_cert` is presented in our own `SyncHello`; its `root_pk` is also the
/// root identity the peer's cert must chain to (Sync Runs Only Between
/// Same-Root Certified Devices). `revocations` must already be
/// individually-verified (same contract as `certs::DeviceCert::is_revoked_by`)
/// — it's merged with [`LogStore::device_revocations`] (any `device_revoke`
/// entry `store` has already learned via a prior sync) before being applied,
/// so a revocation this device only knows about because a sibling synced it
/// in is enforced too, not just ones present in the caller's own baseline
/// (e.g. the identity bundle) — device-linking spec: "Own devices enforce
/// revocation after sync". `transport_peer_id` is the connection's actual
/// transport node id — the caller's job to obtain (e.g.
/// `iroh::endpoint::Connection::remote_id()`).
pub async fn run_session<R, W>(
    reader: R,
    mut writer: W,
    my_cert: &DeviceCert,
    revocations: &[Revocation],
    transport_peer_id: PublicKey,
    store: LogStore,
) -> Result<SyncOutcome>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(reader);

    // Merge the caller-provided baseline with anything this store has
    // already learned via a prior sync round, so a `device_revoke` entry
    // synced in from one sibling is enforced against the very next session
    // — recomputed fresh every time rather than cached (see
    // `LogStore::device_revocations`'s doc comment).
    let mut live_revocations = revocations.to_vec();
    live_revocations.extend(store.device_revocations().await);

    // Step 1 (spec: "begins with mutual SyncHello"): send ours, then verify
    // theirs. Any verification failure closes the connection with no
    // further writes at all — in particular, no SyncVector.
    write_frame(&mut writer, &Frame::SyncHello { cert: my_cert.encode() }).await?;
    if let Err(reason) =
        read_and_verify_hello(&mut reader, my_cert.root_pk, &live_revocations, transport_peer_id).await
    {
        return Ok(SyncOutcome::HelloRejected(reason));
    }

    // Step 2: both sides send their per-device high-water vector.
    let my_vector = store.vector().await;
    write_frame(&mut writer, &Frame::SyncVector { vector: my_vector.clone() }).await?;
    let peer_vector = match read_frame(&mut reader).await? {
        Some(Frame::SyncVector { vector }) => vector,
        other => bail!("sync: expected SyncVector after hello, got {other:?}"),
    };

    // Steps 3-5: stream the gap + ack while concurrently draining and
    // applying whatever the peer streams to us, then keep both directions
    // open for live push. Whichever direction ends first (peer disconnected,
    // or our own write failed because the peer's side closed) ends the
    // session — the two futures each own one exclusive half of the
    // connection, so no locking is needed between them beyond the shared
    // `LogStore`.
    let send_store = store.clone();
    tokio::select! {
        res = send_loop(writer, send_store, my_vector, peer_vector) => res?,
        res = recv_loop(reader, store) => res?,
    }
    Ok(SyncOutcome::Closed)
}

/// Read and verify the peer's `SyncHello`, per the spec's certificate
/// checks: signature valid, chains to `my_root_pk`, not revoked, and
/// `device_pk` matches `transport_peer_id`. Returns the peer's verified cert
/// on success, or a human-readable rejection reason (for [`SyncOutcome::HelloRejected`]) —
/// never a hard error, since any failure here is a normal "wrong peer"
/// outcome, not a bug.
async fn read_and_verify_hello<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    my_root_pk: PublicKey,
    revocations: &[Revocation],
    transport_peer_id: PublicKey,
) -> Result<DeviceCert, String> {
    let frame = match read_frame(reader).await {
        Ok(Some(f)) => f,
        Ok(None) => return Err("connection closed before sending SyncHello".to_string()),
        Err(e) => return Err(format!("malformed frame while awaiting SyncHello: {e}")),
    };
    let cert_str = match frame {
        Frame::SyncHello { cert } => cert,
        other => return Err(format!("expected SyncHello as the first frame, got {other:?}")),
    };
    let cert = DeviceCert::decode(&cert_str).map_err(|e| format!("malformed certificate: {e}"))?;
    cert.verify().map_err(|e| format!("certificate failed verification: {e}"))?;
    if cert.root_pk != my_root_pk {
        return Err("certificate chains to a different root identity".to_string());
    }
    if cert.is_revoked_by(revocations) {
        return Err("certificate's device key has been revoked".to_string());
    }
    if !cert.binds_to_connection(transport_peer_id) {
        return Err(
            "certificate's device key does not match the connection's transport node id".to_string(),
        );
    }
    Ok(cert)
}

/// Ship the peer's gap (per device, ascending `seq`, batched to
/// [`MAX_ENTRIES_PER_FRAME`]), then a `SyncAck`, then push whatever the
/// local store gains afterward — no new vector exchange, ever (spec: "Live
/// Push While Connected"). Runs until a write fails (the peer's side of the
/// connection closed).
async fn send_loop<W>(
    mut writer: W,
    store: LogStore,
    my_vector: BTreeMap<String, u64>,
    peer_vector: BTreeMap<String, u64>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    for (device_hex, &my_seq) in &my_vector {
        let peer_seq = peer_vector.get(device_hex).copied().unwrap_or(0);
        if peer_seq >= my_seq {
            continue;
        }
        send_gap(&mut writer, &store, device_hex, peer_seq).await?;
    }

    write_frame(&mut writer, &Frame::SyncAck { vector: my_vector.clone() }).await?;

    // Live push: whenever the store changes, ship whatever's newer than what
    // we've already pushed. No new SyncVector/SyncAck — just SyncEntries.
    let mut pushed = my_vector;
    loop {
        store.notified().await;
        let current = store.vector().await;
        for (device_hex, &seq) in &current {
            let sent = pushed.get(device_hex).copied().unwrap_or(0);
            if seq <= sent {
                continue;
            }
            send_gap(&mut writer, &store, device_hex, sent).await?;
        }
        pushed = current;
    }
}

/// Send every entry after `from_seq` for `device_hex`, batched to
/// [`MAX_ENTRIES_PER_FRAME`] entries per `SyncEntries` frame, in ascending
/// `seq` order.
async fn send_gap<W>(writer: &mut W, store: &LogStore, device_hex: &str, from_seq: u64) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let device_pk = PublicKey::from_str(device_hex)
        .with_context(|| format!("sync: unparseable device key {device_hex} in our own vector"))?;
    let entries = store.read_from(&device_pk, from_seq).await?;
    for chunk in entries.chunks(MAX_ENTRIES_PER_FRAME) {
        let batch: Vec<String> = chunk.iter().map(LogEntry::to_base64).collect();
        write_frame(writer, &Frame::SyncEntries { entries: batch }).await?;
    }
    Ok(())
}

/// Drain inbound frames and apply `SyncEntries` to `store`, validating each
/// entry through `eventlog`'s chain rules; a rejected entry is logged and
/// skipped without disturbing that device's cursor (spec: receivers "reject
/// ... and does not advance its cursor"). Runs until a clean EOF or read
/// error (the peer's side of the connection closed).
async fn recv_loop<R>(mut reader: BufReader<R>, store: LogStore) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    loop {
        match read_frame(&mut reader).await? {
            None => return Ok(()),
            Some(Frame::SyncEntries { entries }) => {
                for b64 in entries {
                    let entry = match LogEntry::from_base64(&b64) {
                        Ok(e) => e,
                        Err(e) => {
                            warn!(error = %e, "sync: received a malformed entry; skipping");
                            continue;
                        }
                    };
                    if let Err(e) = store.append(entry).await {
                        warn!(error = %e, "sync: rejected an inbound entry; cursor unchanged");
                    }
                }
            }
            // SyncAck is informational only; a stray hello/vector, or any
            // frame this build doesn't recognize (`Frame::Unknown`, or a
            // future sibling's new frame kind), is ignored rather than
            // tearing down an otherwise-healthy live session.
            Some(_) => {}
        }
    }
}

// ---------------------------------------------------------------------------
// iroh wiring — thin: all protocol logic lives in `run_session` above.
// ---------------------------------------------------------------------------

/// iroh `ProtocolHandler` for [`SYNC_ALPN`]: accepts a dialed-in bi stream
/// and hands it straight to [`run_session`].
#[derive(Clone, Debug)]
pub struct SyncHandler {
    my_cert: DeviceCert,
    revocations: Vec<Revocation>,
    store: LogStore,
}

impl SyncHandler {
    pub fn new(my_cert: DeviceCert, revocations: Vec<Revocation>, store: LogStore) -> Self {
        Self { my_cert, revocations, store }
    }
}

impl ProtocolHandler for SyncHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let transport_peer_id = connection.remote_id();
        let (send, recv) =
            connection.accept_bi().await.map_err(|e| AcceptError::from_boxed(e.into()))?;
        match run_session(recv, send, &self.my_cert, &self.revocations, transport_peer_id, self.store.clone())
            .await
        {
            Ok(SyncOutcome::HelloRejected(reason)) => {
                info!(%reason, "sync: rejected peer's hello");
                Ok(())
            }
            Ok(SyncOutcome::Closed) => Ok(()),
            Err(e) => Err(AcceptError::from_boxed(e.into())),
        }
    }
}

/// Dial a sibling device's [`SYNC_ALPN`] and run the session as the dialing
/// side.
pub async fn dial_sync(
    endpoint: &Endpoint,
    addr: EndpointAddr,
    my_cert: &DeviceCert,
    revocations: &[Revocation],
    store: LogStore,
) -> Result<SyncOutcome> {
    let conn = endpoint.connect(addr, SYNC_ALPN).await?;
    let transport_peer_id = conn.remote_id();
    let (send, recv) = conn.open_bi().await?;
    run_session(recv, send, my_cert, revocations, transport_peer_id, store).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;
    use tokio::io::AsyncWriteExt;

    fn test_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("azula-sync-test-{}", std::process::id())).join(name)
    }

    /// 32 sequential bytes starting at `start` (wrapping), for deterministic,
    /// never-random test keys — same convention as `certs.rs`/`eventlog.rs`.
    fn seed(start: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = start.wrapping_add(i as u8);
        }
        s
    }

    fn root_secret() -> SecretKey {
        SecretKey::from_bytes(&seed(0x00))
    }
    fn foreign_root_secret() -> SecretKey {
        SecretKey::from_bytes(&seed(0x40))
    }
    fn device_a_secret() -> SecretKey {
        SecretKey::from_bytes(&seed(0x80))
    }
    fn device_b_secret() -> SecretKey {
        SecretKey::from_bytes(&seed(0xc0))
    }

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

    fn make_entry(device: &SecretKey, seq: u64, prev_hash: [u8; 32]) -> LogEntry {
        let mut e = LogEntry {
            version: 1,
            kind: Kind::MessageOut,
            device_pk: device.public(),
            seq,
            lamport: seq,
            ts_ms: 1_767_225_600_000 + seq * 1000,
            prev_hash,
            body: "{}".to_string(),
            signature: [0u8; 64],
        };
        e.sign(device);
        e
    }

    /// Append `count` entries (seq 1..=count) authored by `device` to
    /// `store`, chaining each to the previous.
    async fn append_chain(store: &LogStore, device: &SecretKey, count: u64) {
        let mut prev_hash = [0u8; 32];
        for seq in 1..=count {
            let e = make_entry(device, seq, prev_hash);
            prev_hash = e.hash();
            store.append(e).await.expect("append succeeds");
        }
    }

    /// One simulated bidirectional connection: `attacker_writer`/`attacker_reader`
    /// are the "other side"'s ends; `my_reader`/`my_writer` are what gets
    /// passed into `run_session` under test.
    fn wire_pair() -> (
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
    ) {
        let (attacker_writer, my_reader) = tokio::io::duplex(8192);
        let (my_writer, attacker_reader) = tokio::io::duplex(8192);
        (attacker_writer, attacker_reader, my_reader, my_writer)
    }

    // --- Cert rejection paths (each must close before any vector exchange) --

    #[tokio::test]
    async fn hello_rejects_a_cert_for_a_different_root_before_any_vector_exchange() {
        let my_root = root_secret();
        let my_device = device_a_secret();
        let my_cert = make_cert(&my_root, &my_device, "victim");

        let foreign_root = foreign_root_secret();
        let attacker_device = device_b_secret();
        let attacker_cert = make_cert(&foreign_root, &attacker_device, "attacker");

        let (mut attacker_writer, attacker_reader, my_reader, my_writer) = wire_pair();
        write_frame(&mut attacker_writer, &Frame::SyncHello { cert: attacker_cert.encode() })
            .await
            .unwrap();

        let store = LogStore::open(test_dir("wrong_root"), my_root.public()).unwrap();
        let outcome =
            run_session(my_reader, my_writer, &my_cert, &[], attacker_device.public(), store).await.unwrap();
        match &outcome {
            SyncOutcome::HelloRejected(reason) => assert!(reason.contains("root"), "{reason}"),
            other => panic!("expected HelloRejected, got {other:?}"),
        }

        let mut r = BufReader::new(attacker_reader);
        assert!(matches!(read_frame(&mut r).await.unwrap(), Some(Frame::SyncHello { .. })));
        assert!(read_frame(&mut r).await.unwrap().is_none(), "nothing should follow the hello");
    }

    #[tokio::test]
    async fn hello_rejects_a_revoked_device_before_any_vector_exchange() {
        let my_root = root_secret();
        let my_device = device_a_secret();
        let my_cert = make_cert(&my_root, &my_device, "victim");

        let sibling_device = device_b_secret();
        let sibling_cert = make_cert(&my_root, &sibling_device, "sibling"); // same root

        let mut revocation = Revocation {
            version: 1,
            root_pk: my_root.public(),
            device_pk: sibling_device.public(),
            revoked_at: 1_767_225_600,
            signature: [0u8; 64],
        };
        revocation.sign(&my_root);
        revocation.verify().expect("revocation verifies");

        let (mut attacker_writer, attacker_reader, my_reader, my_writer) = wire_pair();
        write_frame(&mut attacker_writer, &Frame::SyncHello { cert: sibling_cert.encode() }).await.unwrap();

        let store = LogStore::open(test_dir("revoked_device"), my_root.public()).unwrap();
        let outcome =
            run_session(my_reader, my_writer, &my_cert, &[revocation], sibling_device.public(), store)
                .await
                .unwrap();
        match &outcome {
            SyncOutcome::HelloRejected(reason) => assert!(reason.contains("revok"), "{reason}"),
            other => panic!("expected HelloRejected, got {other:?}"),
        }

        let mut r = BufReader::new(attacker_reader);
        assert!(matches!(read_frame(&mut r).await.unwrap(), Some(Frame::SyncHello { .. })));
        assert!(read_frame(&mut r).await.unwrap().is_none());
    }

    /// Task 6.5: a revocation this device only knows about because it's
    /// already sitting in its own `LogStore` as a `device_revoke` entry
    /// (simulating a prior sync round) must be enforced even though it's
    /// absent from `run_session`'s own `revocations` argument (`&[]` here) —
    /// device-linking spec's "Own devices enforce revocation after sync":
    /// "it thereafter refuses sync ... for that device key".
    #[tokio::test]
    async fn hello_rejects_a_device_revoked_via_a_device_revoke_entry_already_in_the_store() {
        let my_root = root_secret();
        let my_device = device_a_secret();
        let my_cert = make_cert(&my_root, &my_device, "victim");

        let sibling_device = device_b_secret();
        let sibling_cert = make_cert(&my_root, &sibling_device, "sibling"); // same root

        let mut revocation = Revocation {
            version: 1,
            root_pk: my_root.public(),
            device_pk: sibling_device.public(),
            revoked_at: 1_767_225_600,
            signature: [0u8; 64],
        };
        revocation.sign(&my_root);

        let store = LogStore::open(test_dir("revoked_via_synced_entry"), my_root.public()).unwrap();
        let body = serde_json::json!({ "revocation": revocation.encode() }).to_string();
        store.append_own(&my_device, Kind::DeviceRevoke, body).await.unwrap();

        let (mut attacker_writer, attacker_reader, my_reader, my_writer) = wire_pair();
        write_frame(&mut attacker_writer, &Frame::SyncHello { cert: sibling_cert.encode() }).await.unwrap();

        // Empty baseline -- the revocation is only discoverable by scanning
        // the store itself.
        let outcome =
            run_session(my_reader, my_writer, &my_cert, &[], sibling_device.public(), store).await.unwrap();
        match &outcome {
            SyncOutcome::HelloRejected(reason) => assert!(reason.contains("revok"), "{reason}"),
            other => panic!("expected HelloRejected, got {other:?}"),
        }

        let mut r = BufReader::new(attacker_reader);
        assert!(matches!(read_frame(&mut r).await.unwrap(), Some(Frame::SyncHello { .. })));
        assert!(read_frame(&mut r).await.unwrap().is_none());
    }

    // --- LogStore::device_revocations (task 6.5) ----------------------------

    #[tokio::test]
    async fn device_revocations_returns_only_entries_that_decode_and_verify() {
        let author = device_a_secret();
        let store = LogStore::open(test_dir("device_revocations_filter"), root_secret().public()).unwrap();

        let root = root_secret();
        let revoked = device_b_secret();
        let mut good = Revocation {
            version: 1,
            root_pk: root.public(),
            device_pk: revoked.public(),
            revoked_at: 1_767_225_600,
            signature: [0u8; 64],
        };
        good.sign(&root);
        store
            .append_own(&author, Kind::DeviceRevoke, serde_json::json!({ "revocation": good.encode() }).to_string())
            .await
            .unwrap();

        // A DeviceRevoke entry whose embedded revocation's own signature
        // doesn't verify must be excluded, even though the log entry itself
        // (signed by `author`) is perfectly valid.
        let mut tampered = good.clone();
        tampered.signature[0] ^= 0xff;
        store
            .append_own(
                &author,
                Kind::DeviceRevoke,
                serde_json::json!({ "revocation": tampered.encode() }).to_string(),
            )
            .await
            .unwrap();

        // A DeviceRevoke entry whose body isn't even the right shape.
        store.append_own(&author, Kind::DeviceRevoke, "{}".to_string()).await.unwrap();

        // A non-DeviceRevoke entry must be ignored entirely.
        store.append_own(&author, Kind::MessageOut, "{}".to_string()).await.unwrap();

        assert_eq!(store.device_revocations().await, vec![good]);
    }

    #[tokio::test]
    async fn hello_rejects_a_cert_transport_node_id_mismatch_before_any_vector_exchange() {
        let my_root = root_secret();
        let my_device = device_a_secret();
        let my_cert = make_cert(&my_root, &my_device, "victim");

        let sibling_device = device_b_secret();
        let sibling_cert = make_cert(&my_root, &sibling_device, "sibling");
        let someone_else = foreign_root_secret(); // just a pubkey != sibling_device's

        let (mut attacker_writer, attacker_reader, my_reader, my_writer) = wire_pair();
        write_frame(&mut attacker_writer, &Frame::SyncHello { cert: sibling_cert.encode() }).await.unwrap();

        let store = LogStore::open(test_dir("node_id_mismatch"), my_root.public()).unwrap();
        // Transport peer id does NOT match sibling_cert.device_pk.
        let outcome =
            run_session(my_reader, my_writer, &my_cert, &[], someone_else.public(), store).await.unwrap();
        match &outcome {
            SyncOutcome::HelloRejected(reason) => {
                assert!(reason.contains("transport") || reason.contains("node id"), "{reason}")
            }
            other => panic!("expected HelloRejected, got {other:?}"),
        }

        let mut r = BufReader::new(attacker_reader);
        assert!(matches!(read_frame(&mut r).await.unwrap(), Some(Frame::SyncHello { .. })));
        assert!(read_frame(&mut r).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn hello_rejects_a_malformed_cert_before_any_vector_exchange() {
        let my_root = root_secret();
        let my_device = device_a_secret();
        let my_cert = make_cert(&my_root, &my_device, "victim");

        let (mut attacker_writer, attacker_reader, my_reader, my_writer) = wire_pair();
        write_frame(&mut attacker_writer, &Frame::SyncHello { cert: "not-a-real-cert".into() })
            .await
            .unwrap();

        let store = LogStore::open(test_dir("malformed_cert"), my_root.public()).unwrap();
        let outcome =
            run_session(my_reader, my_writer, &my_cert, &[], device_b_secret().public(), store).await.unwrap();
        match &outcome {
            SyncOutcome::HelloRejected(reason) => assert!(
                reason.contains("certificate") || reason.contains("malformed") || reason.contains("prefix"),
                "{reason}"
            ),
            other => panic!("expected HelloRejected, got {other:?}"),
        }

        let mut r = BufReader::new(attacker_reader);
        assert!(matches!(read_frame(&mut r).await.unwrap(), Some(Frame::SyncHello { .. })));
        assert!(read_frame(&mut r).await.unwrap().is_none());
    }

    // --- Vector exchange / batching / live push (send_loop in isolation) ----

    #[tokio::test]
    async fn send_loop_transfers_only_the_gap() {
        let device = device_a_secret();
        let store = LogStore::open(test_dir("gap_only"), root_secret().public()).unwrap();
        append_chain(&store, &device, 5).await;

        let my_vector = store.vector().await;
        let mut peer_vector = BTreeMap::new();
        peer_vector.insert(device.public().to_string(), 3u64);

        let (writer, reader) = tokio::io::duplex(8192);
        let handle = tokio::spawn(send_loop(writer, store.clone(), my_vector, peer_vector));

        let mut r = BufReader::new(reader);
        let entries_frame = read_frame(&mut r).await.unwrap().expect("entries frame");
        let entries = match entries_frame {
            Frame::SyncEntries { entries } => entries,
            other => panic!("expected SyncEntries, got {other:?}"),
        };
        assert_eq!(entries.len(), 2, "only the missing seq 4..=5 should be sent");
        let decoded: Vec<LogEntry> = entries.iter().map(|b| LogEntry::from_base64(b).unwrap()).collect();
        assert_eq!(decoded[0].seq, 4);
        assert_eq!(decoded[1].seq, 5);

        let ack_frame = read_frame(&mut r).await.unwrap().expect("ack frame");
        assert!(matches!(ack_frame, Frame::SyncAck { .. }));

        handle.abort();
    }

    #[tokio::test]
    async fn send_loop_batches_more_than_64_entries_into_multiple_ascending_frames() {
        let device = device_a_secret();
        let store = LogStore::open(test_dir("batching"), root_secret().public()).unwrap();
        append_chain(&store, &device, 130).await;

        let my_vector = store.vector().await;
        let peer_vector = BTreeMap::new(); // peer has nothing yet

        let (writer, reader) = tokio::io::duplex(1 << 20);
        let handle = tokio::spawn(send_loop(writer, store.clone(), my_vector, peer_vector));

        let mut r = BufReader::new(reader);
        let mut all_entries: Vec<LogEntry> = Vec::new();
        let mut frame_count = 0;
        loop {
            match read_frame(&mut r).await.unwrap() {
                Some(Frame::SyncEntries { entries }) => {
                    assert!(entries.len() <= 64, "frame exceeded the 64-entry cap: {}", entries.len());
                    frame_count += 1;
                    for b in entries {
                        all_entries.push(LogEntry::from_base64(&b).unwrap());
                    }
                }
                Some(Frame::SyncAck { .. }) => break,
                other => panic!("unexpected frame: {other:?}"),
            }
        }
        assert_eq!(frame_count, 3, "130 entries at <=64/frame should take 3 frames");
        assert_eq!(all_entries.len(), 130);
        for (i, e) in all_entries.iter().enumerate() {
            assert_eq!(e.seq, (i + 1) as u64, "entries must arrive in ascending per-device seq order");
        }

        handle.abort();
    }

    #[tokio::test]
    async fn live_push_delivers_new_entries_without_a_new_vector_exchange() {
        let device = device_a_secret();
        let store = LogStore::open(test_dir("live_push"), root_secret().public()).unwrap();

        let my_vector = store.vector().await; // empty
        let peer_vector = BTreeMap::new();

        let (writer, reader) = tokio::io::duplex(8192);
        let handle = tokio::spawn(send_loop(writer, store.clone(), my_vector, peer_vector));

        let mut r = BufReader::new(reader);
        let first = read_frame(&mut r).await.unwrap().expect("ack frame");
        assert!(matches!(first, Frame::SyncAck { .. }), "expected the initial ack, got {first:?}");

        // Append while the session is "live" — no new vector round trip
        // should happen; the very next frame must be the pushed entry.
        append_chain(&store, &device, 1).await;

        let second = read_frame(&mut r).await.unwrap().expect("live push frame");
        match second {
            Frame::SyncEntries { entries } => {
                assert_eq!(entries.len(), 1);
                let e = LogEntry::from_base64(&entries[0]).unwrap();
                assert_eq!(e.seq, 1);
                assert_eq!(e.device_pk, device.public());
            }
            other => panic!("expected a live-pushed SyncEntries frame with no new vector, got {other:?}"),
        }

        handle.abort();
    }

    // --- recv_loop: broken chain rejection + unknown frame resilience ------

    #[tokio::test]
    async fn recv_loop_rejects_broken_chain_and_does_not_advance_cursor() {
        let device = device_a_secret();
        let store = LogStore::open(test_dir("broken_chain"), root_secret().public()).unwrap();

        let e1 = make_entry(&device, 1, [0u8; 32]);
        store.append(e1.clone()).await.unwrap();

        let mut bogus_hash = e1.hash();
        bogus_hash[0] ^= 0xff;
        let e2_broken = make_entry(&device, 2, bogus_hash);
        let e2_valid = make_entry(&device, 2, e1.hash());

        let (mut writer, reader) = tokio::io::duplex(8192);
        write_frame(&mut writer, &Frame::SyncEntries { entries: vec![e2_broken.to_base64()] })
            .await
            .unwrap();
        write_frame(&mut writer, &Frame::SyncEntries { entries: vec![e2_valid.to_base64()] })
            .await
            .unwrap();
        drop(writer); // EOF after these two frames

        recv_loop(BufReader::new(reader), store.clone()).await.unwrap();

        let vector = store.vector().await;
        assert_eq!(
            vector.get(&device.public().to_string()),
            Some(&2),
            "the valid e2 should still land after the broken one is rejected"
        );

        let entries = store.read_from(&device.public(), 0).await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1], e2_valid, "the stored seq-2 entry must be the valid one, not the broken one");
    }

    #[tokio::test]
    async fn recv_loop_ignores_an_unrecognized_frame_type_and_keeps_processing() {
        let device = device_a_secret();
        let store = LogStore::open(test_dir("unknown_frame"), root_secret().public()).unwrap();
        let e1 = make_entry(&device, 1, [0u8; 32]);

        let (mut writer, reader) = tokio::io::duplex(8192);
        // A newer sibling's frame kind this build doesn't recognize.
        writer.write_all(br#"{"type":"sync_resync_request","foo":"bar"}"#).await.unwrap();
        writer.write_all(b"\n").await.unwrap();
        write_frame(&mut writer, &Frame::SyncEntries { entries: vec![e1.to_base64()] }).await.unwrap();
        drop(writer);

        recv_loop(BufReader::new(reader), store.clone()).await.unwrap();

        assert_eq!(store.vector().await.get(&device.public().to_string()), Some(&1));
    }

    // --- LogStore sanity: persists and rebuilds chain state from disk ------

    #[tokio::test]
    async fn log_store_persists_and_reopens_with_correct_vector() {
        let dir = test_dir("store_roundtrip");
        let device = device_a_secret();
        {
            let store = LogStore::open(&dir, root_secret().public()).unwrap();
            append_chain(&store, &device, 3).await;
            assert_eq!(store.vector().await.get(&device.public().to_string()), Some(&3));
        }
        // Reopen fresh — must rebuild chain state from disk alone.
        let reopened = LogStore::open(&dir, root_secret().public()).unwrap();
        assert_eq!(reopened.vector().await.get(&device.public().to_string()), Some(&3));
        let entries = reopened.read_from(&device.public(), 1).await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].seq, 2);
        assert_eq!(entries[1].seq, 3);
    }

    // --- LogStore::append_own (task 8.1 support) ----------------------------

    #[tokio::test]
    async fn append_own_chains_seq_and_prev_hash_for_its_own_device() {
        let device = device_a_secret();
        let store = LogStore::open(test_dir("append_own_chain"), root_secret().public()).unwrap();

        let e1 = store
            .append_own(&device, Kind::MessageOut, "{}".to_string())
            .await
            .unwrap();
        assert_eq!(e1.seq, 1);
        assert_eq!(e1.prev_hash, [0u8; 32]);
        e1.verify_signature().expect("append_own must sign the entry");

        let e2 = store
            .append_own(&device, Kind::MessageOut, "{}".to_string())
            .await
            .unwrap();
        assert_eq!(e2.seq, 2);
        assert_eq!(e2.prev_hash, e1.hash());

        assert_eq!(store.vector().await.get(&device.public().to_string()), Some(&2));
    }

    #[tokio::test]
    async fn append_own_lamport_exceeds_the_highest_seen_anywhere() {
        let device_a = device_a_secret();
        let device_b = device_b_secret();
        let store = LogStore::open(test_dir("append_own_lamport"), root_secret().public()).unwrap();

        // device_b's log (synced in from elsewhere) already has lamport 5.
        let mut foreign = LogEntry {
            version: 1,
            kind: Kind::MessageOut,
            device_pk: device_b.public(),
            seq: 1,
            lamport: 5,
            ts_ms: 1,
            prev_hash: [0u8; 32],
            body: "{}".to_string(),
            signature: [0u8; 64],
        };
        foreign.sign(&device_b);
        store.append(foreign).await.unwrap();

        // Our own next append must out-lamport the highest seen anywhere (5),
        // not just our own prior lamport (0 so far).
        let own = store
            .append_own(&device_a, Kind::MessageOut, "{}".to_string())
            .await
            .unwrap();
        assert_eq!(own.lamport, 6);

        let own2 = store
            .append_own(&device_a, Kind::MessageOut, "{}".to_string())
            .await
            .unwrap();
        assert_eq!(own2.lamport, 7);
    }

    // --- Two fake devices converge from divergent starting logs ------------

    #[tokio::test]
    async fn two_fake_devices_converge_from_divergent_logs() {
        let root = root_secret();
        let device_a = device_a_secret();
        let device_b = device_b_secret();
        let cert_a = make_cert(&root, &device_a, "a");
        let cert_b = make_cert(&root, &device_b, "b");

        let store_a = LogStore::open(test_dir("converge_a"), root.public()).unwrap();
        let store_b = LogStore::open(test_dir("converge_b"), root.public()).unwrap();

        // Divergent starting logs: A authored 3 entries B has never seen; B
        // authored 2 entries A has never seen. Neither has synced before.
        append_chain(&store_a, &device_a, 3).await;
        append_chain(&store_b, &device_b, 2).await;

        // One simulated bidirectional connection between the two fakes.
        let (a_end, b_end) = tokio::io::duplex(1 << 16);
        let (a_reader, a_writer) = tokio::io::split(a_end);
        let (b_reader, b_writer) = tokio::io::split(b_end);

        let empty_revocations: Vec<Revocation> = vec![];
        let session_a =
            run_session(a_reader, a_writer, &cert_a, &empty_revocations, device_b.public(), store_a.clone());
        let session_b =
            run_session(b_reader, b_writer, &cert_b, &empty_revocations, device_a.public(), store_b.clone());

        let a_hex = device_a.public().to_string();
        let b_hex = device_b.public().to_string();
        let converge_check = async {
            loop {
                let va = store_a.vector().await;
                let vb = store_b.vector().await;
                if va.get(&a_hex) == Some(&3)
                    && va.get(&b_hex) == Some(&2)
                    && vb.get(&a_hex) == Some(&3)
                    && vb.get(&b_hex) == Some(&2)
                {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        };

        let outcome: std::result::Result<(), String> = tokio::select! {
            r = session_a => Err(format!("session_a ended before convergence: {r:?}")),
            r = session_b => Err(format!("session_b ended before convergence: {r:?}")),
            r = tokio::time::timeout(std::time::Duration::from_secs(5), converge_check) => {
                r.map_err(|_| "timed out waiting for convergence".to_string())
            }
        };
        outcome.expect("two fake devices should converge");

        // Full state equality, not just the vector — every entry for every
        // device must be byte-identical on both sides.
        let a_entries_from_a = store_a.read_from(&device_a.public(), 0).await.unwrap();
        let a_entries_from_b = store_b.read_from(&device_a.public(), 0).await.unwrap();
        assert_eq!(a_entries_from_a, a_entries_from_b);

        let b_entries_from_a = store_a.read_from(&device_b.public(), 0).await.unwrap();
        let b_entries_from_b = store_b.read_from(&device_b.public(), 0).await.unwrap();
        assert_eq!(b_entries_from_a, b_entries_from_b);
    }

    /// Real-transport smoke test, following
    /// `link::tests::link_handshake_completes_over_a_real_quic_connection`
    /// (the task-6.7 regression guard). Every other test in this module runs
    /// over an in-memory duplex, which is live in both directions the moment
    /// it exists — while a real QUIC connection does not surface a freshly
    /// opened bi-stream to the acceptor until the dialer writes bytes on it.
    /// `azula/sync/0` should be immune by construction (the session opens
    /// with a *mutual* hello, and [`dial_sync`]'s first action after
    /// `open_bi` is a write, which is exactly what lets [`SyncHandler`]'s
    /// `accept_bi()` resolve) — but "immune by reasoning" is precisely the
    /// assumption that failed for `azula/link/0`, so this test settles it:
    /// two real iroh endpoints, the same handler `azula mailbox` binds, a
    /// real dial via [`dial_sync`], and full two-way convergence. If either
    /// side's first action ever becomes a read, this deadlocks and the
    /// timeout below fires. Edge cases stay on the fast duplex tests above.
    #[tokio::test]
    async fn sync_session_converges_over_a_real_quic_connection() {
        use iroh::endpoint::presets;
        use iroh::protocol::Router;

        let root = root_secret();
        let device_a = device_a_secret(); // dialer
        let device_b = device_b_secret(); // acceptor
        let cert_a = make_cert(&root, &device_a, "a");
        let cert_b = make_cert(&root, &device_b, "b");

        let store_a = LogStore::open(test_dir("quic_converge_a"), root.public()).unwrap();
        let store_b = LogStore::open(test_dir("quic_converge_b"), root.public()).unwrap();
        append_chain(&store_a, &device_a, 3).await;
        append_chain(&store_b, &device_b, 2).await;

        // The certs must bind to the connections' *transport* node ids
        // (`read_and_verify_hello` checks it), so each endpoint is bound
        // with its device's own secret key rather than a random one.
        let server_ep = Endpoint::builder(presets::Minimal)
            .secret_key(device_b.clone())
            .bind()
            .await
            .expect("server endpoint bind");
        let server_addr = server_ep.addr();
        let router = Router::builder(server_ep)
            .accept(SYNC_ALPN, SyncHandler::new(cert_b, vec![], store_b.clone()))
            .spawn();

        let client_ep = Endpoint::builder(presets::Minimal)
            .secret_key(device_a.clone())
            .bind()
            .await
            .expect("client endpoint bind");
        let dial = dial_sync(&client_ep, server_addr, &cert_a, &[], store_a.clone());

        let a_hex = device_a.public().to_string();
        let b_hex = device_b.public().to_string();
        let converge = async {
            loop {
                let va = store_a.vector().await;
                let vb = store_b.vector().await;
                if va.get(&a_hex) == Some(&3)
                    && va.get(&b_hex) == Some(&2)
                    && vb.get(&a_hex) == Some(&3)
                    && vb.get(&b_hex) == Some(&2)
                {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        };

        // The session stays open for live push after catch-up, so the dial
        // future completing at all before convergence is a failure.
        let outcome: std::result::Result<(), String> = tokio::select! {
            r = dial => Err(format!("dialing session ended before convergence: {r:?}")),
            r = tokio::time::timeout(std::time::Duration::from_secs(30), converge) => {
                r.map_err(|_| "timed out waiting for convergence over a real connection".to_string())
            }
        };
        outcome.expect("the two devices should converge over real QUIC");

        let _ = router.shutdown().await;
        client_ep.close().await;
    }

    /// Task 6.5, end to end: the literal device-linking spec scenario "Own
    /// devices enforce revocation after sync", using the *real* sync wire
    /// path (not `append_own`) to land the `device_revoke` entry. An
    /// unrelated sibling ("informant") already logged the revocation;
    /// device_a learns it purely by syncing with the informant, then --
    /// only afterward, in a wholly separate session -- the revoked device_b
    /// tries to connect to device_a directly and must be refused, even
    /// though device_a's own `revocations` argument is empty throughout.
    #[tokio::test]
    async fn device_revoked_via_a_real_sync_round_is_rejected_on_the_next_connection_attempt() {
        let root = root_secret();
        let device_a = device_a_secret(); // victim/acceptor
        let device_b = device_b_secret(); // will be revoked
        let informant = SecretKey::from_bytes(&seed(0x20)); // logged the revocation first

        let cert_a = make_cert(&root, &device_a, "a");
        let cert_b = make_cert(&root, &device_b, "b");
        let cert_informant = make_cert(&root, &informant, "informant");

        let mut revocation = Revocation {
            version: 1,
            root_pk: root.public(),
            device_pk: device_b.public(),
            revoked_at: 1_767_225_600,
            signature: [0u8; 64],
        };
        revocation.sign(&root);

        let store_a = LogStore::open(test_dir("real_sync_revoke_a"), root.public()).unwrap();
        let store_informant = LogStore::open(test_dir("real_sync_revoke_informant"), root.public()).unwrap();
        store_informant
            .append_own(
                &informant,
                Kind::DeviceRevoke,
                serde_json::json!({ "revocation": revocation.encode() }).to_string(),
            )
            .await
            .unwrap();

        // Round 1: device_a syncs with the informant over the real wire
        // path -- the device_revoke entry lands in store_a via ordinary
        // SyncEntries frames, not a direct store write.
        {
            let (a_end, informant_end) = tokio::io::duplex(1 << 16);
            let (a_reader, a_writer) = tokio::io::split(a_end);
            let (informant_reader, informant_writer) = tokio::io::split(informant_end);
            let session_a = run_session(a_reader, a_writer, &cert_a, &[], informant.public(), store_a.clone());
            let session_informant = run_session(
                informant_reader,
                informant_writer,
                &cert_informant,
                &[],
                device_a.public(),
                store_informant.clone(),
            );
            let converge = async {
                loop {
                    if store_a.vector().await.get(&informant.public().to_string()) == Some(&1) {
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            };
            let outcome: std::result::Result<(), String> = tokio::select! {
                r = session_a => Err(format!("session_a ended before convergence: {r:?}")),
                r = session_informant => Err(format!("session_informant ended before convergence: {r:?}")),
                r = tokio::time::timeout(std::time::Duration::from_secs(5), converge) => {
                    r.map_err(|_| "timed out waiting for convergence".to_string())
                }
            };
            outcome.expect("device_a should learn the informant's device_revoke entry via real sync");
        }

        // Round 2: afterward, and in a wholly separate session, device_b
        // (now revoked per what device_a learned in round 1) tries to
        // connect. device_a's own `revocations` argument is still `&[]`.
        let (mut attacker_writer, attacker_reader, my_reader, my_writer) = wire_pair();
        write_frame(&mut attacker_writer, &Frame::SyncHello { cert: cert_b.encode() }).await.unwrap();

        let outcome =
            run_session(my_reader, my_writer, &cert_a, &[], device_b.public(), store_a).await.unwrap();
        match &outcome {
            SyncOutcome::HelloRejected(reason) => assert!(reason.contains("revok"), "{reason}"),
            other => panic!("expected HelloRejected, got {other:?}"),
        }

        let mut r = BufReader::new(attacker_reader);
        assert!(matches!(read_frame(&mut r).await.unwrap(), Some(Frame::SyncHello { .. })));
        assert!(read_frame(&mut r).await.unwrap().is_none());
    }

    // --- LogStore root-identity namespacing (task 4.6) ----------------------

    /// The actual bug task 4.6 fixes: the same device key's entries authored
    /// under one root must not be visible to -- or overwritable by -- a
    /// `LogStore` opened for a *different* root at the same base directory.
    /// Before this task, both roots shared the same flat
    /// `<base_dir>/<device_pk_hex>.jsonl` file, so a device that changed
    /// identities would fold its old identity's private history into the
    /// new one.
    #[tokio::test]
    async fn two_different_roots_on_the_same_device_get_separate_log_sets() {
        let base_dir = test_dir("two_roots_same_device");
        let root_a = root_secret().public();
        let root_b = foreign_root_secret().public();
        let device = device_a_secret();

        let store_a = LogStore::open(&base_dir, root_a).unwrap();
        append_chain(&store_a, &device, 3).await;

        // A fresh store for a DIFFERENT root at the same base directory must
        // start with an empty log set -- it must not see the entries the
        // SAME device key authored under root_a.
        let store_b = LogStore::open(&base_dir, root_b).unwrap();
        assert!(store_b.vector().await.is_empty(), "root B's vector must not include root A's entries");
        assert!(store_b.read_from(&device.public(), 0).await.unwrap().is_empty());

        append_chain(&store_b, &device, 2).await;

        // Reopening root A's store must still show only its own 3 entries --
        // root B's 2 entries for the identical device key must not appear.
        let reopened_a = LogStore::open(&base_dir, root_a).unwrap();
        assert_eq!(reopened_a.vector().await.get(&device.public().to_string()), Some(&3));
        assert_eq!(reopened_a.read_from(&device.public(), 0).await.unwrap().len(), 3);

        // On disk, the two roots' logs live in distinct namespaced
        // subdirectories -- never the same file.
        assert!(base_dir.join(root_a.to_string()).join(format!("{}.jsonl", device.public())).exists());
        assert!(base_dir.join(root_b.to_string()).join(format!("{}.jsonl", device.public())).exists());
    }

    /// task 4.6's migration: a pre-existing flat-layout file (as the 4.4
    /// backfill may have written during this same unreleased change, before
    /// this task's namespacing landed) is relocated under the opening root's
    /// subdirectory rather than left behind or silently dropped.
    #[tokio::test]
    async fn pre_existing_flat_layout_is_relocated_under_the_opening_root() {
        let base_dir = test_dir("flat_layout_migration");
        let device = device_a_secret();
        std::fs::create_dir_all(&base_dir).unwrap();
        let flat_path = base_dir.join(format!("{}.jsonl", device.public()));
        let e1 = make_entry(&device, 1, [0u8; 32]);
        std::fs::write(&flat_path, format!("{}\n", e1.to_base64())).unwrap();

        let root = root_secret().public();
        let store = LogStore::open(&base_dir, root).unwrap();

        // The flat file's entry is visible through the now-namespaced store...
        assert_eq!(store.vector().await.get(&device.public().to_string()), Some(&1));
        // ...the flat file itself is gone...
        assert!(!flat_path.exists(), "the flat file must be moved, not merely read");
        // ...and its content now lives under the root's namespaced subdirectory.
        let namespaced_path = base_dir.join(root.to_string()).join(format!("{}.jsonl", device.public()));
        assert!(namespaced_path.exists());
    }

    /// A second `open` of the same root, after migration already ran once,
    /// must not try to migrate again (there's nothing left at the flat path)
    /// and must not disturb entries the namespaced store already holds.
    #[tokio::test]
    async fn migration_is_a_one_time_no_op_on_a_second_open() {
        let base_dir = test_dir("flat_layout_migration_idempotent");
        let device = device_a_secret();
        std::fs::create_dir_all(&base_dir).unwrap();
        let flat_path = base_dir.join(format!("{}.jsonl", device.public()));
        let e1 = make_entry(&device, 1, [0u8; 32]);
        std::fs::write(&flat_path, format!("{}\n", e1.to_base64())).unwrap();

        let root = root_secret().public();
        let store = LogStore::open(&base_dir, root).unwrap();
        append_chain(&store, &device_b_secret(), 1).await;
        drop(store);

        // Nothing left at the flat path to re-migrate; reopening must simply
        // rebuild from the namespaced directory, unaffected.
        let reopened = LogStore::open(&base_dir, root).unwrap();
        assert_eq!(reopened.vector().await.get(&device.public().to_string()), Some(&1));
        assert_eq!(reopened.vector().await.get(&device_b_secret().public().to_string()), Some(&1));
    }
}
