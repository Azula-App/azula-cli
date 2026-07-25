//! The relay's A2UI side store (relay spec: "Relay Holds A2UI Snapshots
//! Outside the Log") — latest snapshot per `(conversation, surface_id)`,
//! bounded at 256 KiB per surface, tombstoned on delete, never written into
//! the hash-chained identity log. Lives entirely on the relay side
//! (`mailbox_role.rs`'s LLM-ALPN admission path writes into it via
//! [`RelayA2uiStore::put`]; its sync pre-ack hook drains it via
//! [`RelayA2uiStore::drain_pending_messages_for_device`]) — distinct from
//! `SessionCore`'s own client-side per-surface retention, which exists so a
//! session can *build* a coalesced snapshot to send here in the first place.
//!
//! On-disk layout: `<dir>/<root_pk_hex>/<sanitized_conversation>__<sanitized
//! _surface>.json`, one JSON object per surface: `{"conversation":...,
//! "surface":...,"components":...|null,"data_model":...|null,"lamport":N}`
//! (`components: null` is the tombstone). Which devices have already
//! received a given snapshot's `lamport` (`delivered`) is intentionally
//! in-memory only, never persisted — a relay restart just means every
//! still-pending surface replays once more to every device on its next
//! sync, which is idempotent (`createSurface`/`updateComponents`/
//! `deleteSurface` are all overwrite/set operations on the phone).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex as AsyncMutex;

/// Per-surface cap (relay spec: "at most 256 KiB per surface"), measured as
/// the serialized `components` + `data_model` JSON byte length combined.
pub const MAX_SNAPSHOT_BYTES: usize = 256 * 1024;

/// A rejected [`RelayA2uiStore::put`]: the caller (the relay's LLM-ALPN
/// admission path) logs and drops the frame rather than erroring the
/// connection — design.md D6/task 4.5's primary enforcement is client-side
/// (a session checks the cap before ever sending); this is the relay's
/// defensive backstop.
#[derive(Debug)]
pub struct TooLarge {
    pub size: usize,
}

impl std::fmt::Display for TooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "snapshot is {} bytes, exceeds the {MAX_SNAPSHOT_BYTES} byte (256 KiB) per-surface cap", self.size)
    }
}
impl std::error::Error for TooLarge {}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OnDiskRecord {
    conversation: String,
    surface: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    components: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    data_model: Option<serde_json::Value>,
    lamport: u64,
}

#[derive(Debug, Clone)]
struct StoredSnapshot {
    components: Option<serde_json::Value>,
    data_model: Option<serde_json::Value>,
    lamport: u64,
}

impl StoredSnapshot {
    /// The ordinary A2UI wire messages replaying this snapshot represents:
    /// `createSurface` + `updateComponents` (+ `updateDataModel` if present)
    /// for a live snapshot, or a single `deleteSurface` for a tombstone —
    /// the exact shapes `SessionCore::send_a2ui_frame` sends on a live
    /// connection (relay spec: "pending A2UI snapshots SHALL replay to the
    /// phone as ordinary A2UI wire messages").
    fn to_wire_messages(&self, surface: &str) -> Vec<serde_json::Value> {
        let Some(components) = &self.components else {
            return vec![serde_json::json!({
                "version": "v0.9.1",
                "deleteSurface": { "surfaceId": surface }
            })];
        };
        let mut out = vec![
            serde_json::json!({
                "version": "v0.9.1",
                "createSurface": { "surfaceId": surface }
            }),
            serde_json::json!({
                "version": "v0.9.1",
                "updateComponents": { "surfaceId": surface, "components": components }
            }),
        ];
        if let Some(dm) = &self.data_model {
            out.push(serde_json::json!({
                "version": "v0.9.1",
                "updateDataModel": { "surfaceId": surface, "path": "", "value": dm }
            }));
        }
        out
    }
}

#[derive(Default)]
struct Inner {
    snapshots: HashMap<(String, String), StoredSnapshot>,
    /// device_pk_hex -> (conversation, surface) -> last lamport replayed to
    /// that device. In-memory only — see the module doc comment.
    delivered: HashMap<String, HashMap<(String, String), u64>>,
}

/// Cheaply [`Clone`] (an `Arc` handle), same convention as `sync::LogStore`.
#[derive(Clone)]
pub struct RelayA2uiStore {
    dir: PathBuf,
    inner: Arc<AsyncMutex<Inner>>,
}

fn sanitize(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect()
}

fn snapshot_path(dir: &Path, conversation: &str, surface: &str) -> PathBuf {
    dir.join(format!("{}__{}.json", sanitize(conversation), sanitize(surface)))
}

impl RelayA2uiStore {
    /// Open (creating if needed) the side store for `root_pk`, rooted at
    /// `<base_dir>/<root_pk_hex>/` — the same per-identity namespacing
    /// convention as `sync::LogStore::open`. Replays whatever snapshot files
    /// already exist on disk (a relay restart keeps its A2UI state; only the
    /// in-memory `delivered` bookkeeping resets — see the module doc).
    pub fn open(base_dir: impl Into<PathBuf>, root_pk: iroh::PublicKey) -> Result<Self> {
        let dir = base_dir.into().join(root_pk.to_string());
        std::fs::create_dir_all(&dir).with_context(|| format!("relay a2ui store: create {}", dir.display()))?;

        let mut snapshots = HashMap::new();
        for entry in
            std::fs::read_dir(&dir).with_context(|| format!("relay a2ui store: read_dir {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Ok(data) = std::fs::read_to_string(&path) else { continue };
            let Ok(record) = serde_json::from_str::<OnDiskRecord>(&data) else { continue };
            snapshots.insert(
                (record.conversation, record.surface),
                StoredSnapshot { components: record.components, data_model: record.data_model, lamport: record.lamport },
            );
        }

        Ok(Self { dir, inner: Arc::new(AsyncMutex::new(Inner { snapshots, delivered: HashMap::new() })) })
    }

    /// Store the latest snapshot for `(conversation, surface)`, overwriting
    /// whatever was there. `components: None` is a tombstone. Rejects (and
    /// leaves the store unchanged) anything over [`MAX_SNAPSHOT_BYTES`].
    pub async fn put(
        &self,
        conversation: &str,
        surface: &str,
        components: Option<serde_json::Value>,
        data_model: Option<serde_json::Value>,
        lamport: u64,
    ) -> std::result::Result<(), TooLarge> {
        let size = serde_json::to_vec(&components).map(|v| v.len()).unwrap_or(0)
            + serde_json::to_vec(&data_model).map(|v| v.len()).unwrap_or(0);
        if size > MAX_SNAPSHOT_BYTES {
            return Err(TooLarge { size });
        }

        let snapshot = StoredSnapshot { components, data_model, lamport };
        let record = OnDiskRecord {
            conversation: conversation.to_string(),
            surface: surface.to_string(),
            components: snapshot.components.clone(),
            data_model: snapshot.data_model.clone(),
            lamport,
        };
        if let Ok(json) = serde_json::to_string_pretty(&record) {
            let _ = std::fs::write(snapshot_path(&self.dir, conversation, surface), json);
        }

        let mut inner = self.inner.lock().await;
        inner.snapshots.insert((conversation.to_string(), surface.to_string()), snapshot);
        Ok(())
    }

    /// Every A2UI wire message owed to `device_pk_hex`, grouped by
    /// conversation: pending `(conversation, surface)` entries whose stored
    /// `lamport` is newer than what this device has already been marked as
    /// having received (or that it's never received at all). Marks each
    /// included key as delivered at its snapshot's current lamport before
    /// returning — optimistic rather than two-phase (a write failure right
    /// after this call means the device waits for the *next* change to that
    /// surface rather than an immediate retry; acceptable for this bounded,
    /// idempotent-replay side store).
    pub async fn drain_pending_messages_for_device(&self, device_pk_hex: &str) -> HashMap<String, Vec<serde_json::Value>> {
        let mut inner = self.inner.lock().await;
        let already = inner.delivered.entry(device_pk_hex.to_string()).or_default().clone();

        let mut by_conversation: HashMap<String, Vec<serde_json::Value>> = HashMap::new();
        let mut newly_delivered: Vec<((String, String), u64)> = Vec::new();
        for ((conversation, surface), snapshot) in inner.snapshots.iter() {
            let seen = already.get(&(conversation.clone(), surface.clone())).copied();
            if seen.map(|l| l >= snapshot.lamport).unwrap_or(false) {
                continue;
            }
            by_conversation.entry(conversation.clone()).or_default().extend(snapshot.to_wire_messages(surface));
            newly_delivered.push(((conversation.clone(), surface.clone()), snapshot.lamport));
        }

        if !newly_delivered.is_empty() {
            let entry = inner.delivered.entry(device_pk_hex.to_string()).or_default();
            for (key, lamport) in newly_delivered {
                entry.insert(key, lamport);
            }
        }

        by_conversation
    }
}

/// `AZULA_RELAY_A2UI_DIR` override (tests / custom deployments), else
/// `~/.azula/relay-a2ui` — sibling to `mailbox_role::log_store_dir()`'s
/// `~/.azula/mailbox-log`, kept as a distinct directory since A2UI snapshots
/// deliberately never enter the hash-chained log store.
pub fn default_store_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("AZULA_RELAY_A2UI_DIR") {
        return Some(PathBuf::from(dir));
    }
    #[cfg(test)]
    {
        return Some(std::env::temp_dir().join("azula-test").join("relay-a2ui"));
    }
    #[allow(unreachable_code)]
    {
        let home = std::env::var("HOME").ok()?;
        Some(PathBuf::from(home).join(".azula").join("relay-a2ui"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("azula-relay-a2ui-test-{}", std::process::id())).join(name)
    }

    fn root_pk() -> iroh::PublicKey {
        iroh::SecretKey::from_bytes(&[0x11u8; 32]).public()
    }

    #[tokio::test]
    async fn two_snapshots_for_the_same_surface_coalesce_to_one() {
        let store = RelayA2uiStore::open(test_dir("coalesce"), root_pk()).unwrap();
        store
            .put("conv1", "dice-1", Some(serde_json::json!([{"id":"root"}])), None, 1)
            .await
            .unwrap();
        store
            .put(
                "conv1",
                "dice-1",
                Some(serde_json::json!([{"id":"root","text":"v2"}])),
                Some(serde_json::json!({"you": 6})),
                2,
            )
            .await
            .unwrap();

        let pending = store.drain_pending_messages_for_device("device-a").await;
        assert_eq!(pending.len(), 1, "one conversation");
        let messages = &pending["conv1"];
        // createSurface + updateComponents + updateDataModel = 3 messages
        // for the LATEST snapshot only -- ten updates would still coalesce
        // to this same one-surface replay.
        assert_eq!(messages.len(), 3, "{messages:?}");
        assert!(messages[1]["updateComponents"]["components"][0]["text"] == "v2");
    }

    #[tokio::test]
    async fn tombstone_replays_as_delete_surface_only() {
        let store = RelayA2uiStore::open(test_dir("tombstone"), root_pk()).unwrap();
        store.put("conv1", "dice-1", Some(serde_json::json!([{"id":"root"}])), None, 1).await.unwrap();
        store.put("conv1", "dice-1", None, None, 2).await.unwrap();

        let pending = store.drain_pending_messages_for_device("device-a").await;
        let messages = &pending["conv1"];
        assert_eq!(messages.len(), 1);
        assert!(messages[0].get("deleteSurface").is_some(), "{messages:?}");
    }

    #[tokio::test]
    async fn oversized_snapshot_is_rejected_and_store_unchanged() {
        let store = RelayA2uiStore::open(test_dir("oversized"), root_pk()).unwrap();
        let huge_text = "x".repeat(MAX_SNAPSHOT_BYTES + 1);
        let err = store
            .put("conv1", "dice-1", Some(serde_json::json!({"text": huge_text})), None, 1)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("256 KiB"), "{err}");

        let pending = store.drain_pending_messages_for_device("device-a").await;
        assert!(pending.is_empty(), "the oversized snapshot must not have been stored");
    }

    #[tokio::test]
    async fn replay_not_resent_to_a_second_drain_for_the_same_device() {
        let store = RelayA2uiStore::open(test_dir("no_double_replay"), root_pk()).unwrap();
        store.put("conv1", "dice-1", Some(serde_json::json!([{"id":"root"}])), None, 1).await.unwrap();

        let first = store.drain_pending_messages_for_device("device-a").await;
        assert_eq!(first.len(), 1);

        let second = store.drain_pending_messages_for_device("device-a").await;
        assert!(second.is_empty(), "already-delivered snapshot must not replay again to the same device");

        // A different device that never synced still gets the full replay.
        let third = store.drain_pending_messages_for_device("device-b").await;
        assert_eq!(third.len(), 1);
    }

    #[tokio::test]
    async fn a_new_change_after_delivery_replays_again() {
        let store = RelayA2uiStore::open(test_dir("redelivers_on_change"), root_pk()).unwrap();
        store.put("conv1", "dice-1", Some(serde_json::json!([{"id":"root"}])), None, 1).await.unwrap();
        assert_eq!(store.drain_pending_messages_for_device("device-a").await.len(), 1);
        assert!(store.drain_pending_messages_for_device("device-a").await.is_empty());

        store.put("conv1", "dice-1", Some(serde_json::json!([{"id":"root","text":"v2"}])), None, 2).await.unwrap();
        assert_eq!(store.drain_pending_messages_for_device("device-a").await.len(), 1, "new lamport must replay again");
    }

    #[tokio::test]
    async fn reopening_the_store_reloads_persisted_snapshots_from_disk() {
        let dir = test_dir("persists");
        {
            let store = RelayA2uiStore::open(&dir, root_pk()).unwrap();
            store.put("conv1", "dice-1", Some(serde_json::json!([{"id":"root"}])), None, 1).await.unwrap();
        }
        let reopened = RelayA2uiStore::open(&dir, root_pk()).unwrap();
        let pending = reopened.drain_pending_messages_for_device("device-a").await;
        assert_eq!(pending.len(), 1, "snapshot must survive a reopen");
    }
}
