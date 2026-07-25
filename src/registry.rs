//! Device registry — persists known azula device tickets.
//!
//! Two scopes:
//!   - **project**: `<git-root>/.azula/devices.json`  (written when inside a git tree)
//!   - **global**:  `~/.azula/devices.json`
//!   - **runtime**: `<tempdir>/azula/bridge.json`      (live state, managed by bridge)
//!
//! `load()` merges both; project entries win on name collision.

use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result};
use iroh::EndpointId;
use iroh_tickets::endpoint::EndpointTicket;
use serde::{Deserialize, Serialize};

/// Serializes tests (in this file, `bridge/tests.rs`, and `accept_gate.rs`)
/// that mutate the process-global `AZULA_REGISTRY_DIR`/`AZULA_INVITES_DIR`/
/// `AZULA_MAILBOX_DIR` env vars, so two tests touching them concurrently —
/// which `cargo test`'s default parallelism otherwise allows — don't race
/// and read back a value neither of them set. Acquire for the full duration of env mutation plus
/// any calls whose behavior depends on it. A `tokio::sync::Mutex`, not
/// `std::sync::Mutex`: guards here are held across `.await` points.
#[cfg(test)]
pub(crate) static ENV_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A single registered device.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Device {
    pub name: String,
    pub ticket: String,
    pub added_at: Option<u64>,
    /// The encoded invite string (`"azi…"`) this device was paired with, if
    /// any — kept so a reconnect can keep presenting it (see
    /// `azula-docs/openspec/specs/invitations/design.md`'s "redeemer re-presents" rule).
    /// `None` for devices paired by bare ticket/legacy link, or accepted
    /// in before invites existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite: Option<String>,
}

/// On-disk format.
#[derive(Serialize, Deserialize, Default)]
pub struct RegistryFile {
    pub devices: Vec<Device>,
}

// ---------------------------------------------------------------------------
// Path resolution
// ---------------------------------------------------------------------------

/// When `AZULA_REGISTRY_DIR` is set, both the project and global registries
/// resolve under it (an override for tests / sandboxes, mirroring
/// `AZULA_MAILBOX_DIR`). Under `cfg(test)` we also default to an isolated temp
/// dir so the suite never writes the developer's real registry — the `connect`
/// tool persists every paired device via [`add`], so test fixtures like
/// `alice`/`bob` would otherwise pollute `<git-root>/.azula/devices.json`.
fn override_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("AZULA_REGISTRY_DIR") {
        return Some(PathBuf::from(dir));
    }
    #[cfg(test)]
    {
        return Some(std::env::temp_dir().join("azula-test").join("registry"));
    }
    #[allow(unreachable_code)]
    None
}

/// Walk up from cwd to find the first ancestor that contains a `.git` entry
/// (file or directory).  Returns `<root>/.azula/devices.json` or `None`.
pub fn project_path() -> Option<PathBuf> {
    if let Some(dir) = override_dir() {
        return Some(dir.join("devices.json"));
    }
    let mut dir = std::env::current_dir().ok()?;
    loop {
        if dir.join(".git").exists() {
            return Some(dir.join(".azula").join("devices.json"));
        }
        let parent = dir.parent()?;
        dir = parent.to_path_buf();
    }
}

/// Returns `~/.azula/devices.json`, or `None` if `$HOME` is unset.
pub fn global_path() -> Option<PathBuf> {
    if let Some(dir) = override_dir() {
        return Some(dir.join("global-devices.json"));
    }
    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".azula").join("devices.json"))
}

// ---------------------------------------------------------------------------
// Load / merge
// ---------------------------------------------------------------------------

/// Read and parse a single registry file. Returns an empty list if the file
/// is missing or unparseable — callers treat "no devices yet" and "corrupt
/// file" the same way. Exposed so other modules (e.g. `main`'s device listing)
/// can read a specific registry file without re-declaring its on-disk shape.
pub fn read_file(path: &Path) -> Vec<Device> {
    let data = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    match serde_json::from_str::<RegistryFile>(&data) {
        Ok(f) => f.devices,
        Err(_) => vec![],
    }
}

/// Load all known devices.  Global entries come first; project entries replace
/// any global entry with the same name.
pub fn load() -> Vec<Device> {
    let mut map: indexmap::IndexMap<String, Device> = indexmap::IndexMap::new();

    if let Some(g) = global_path() {
        for d in read_file(&g) {
            map.insert(d.name.clone(), d);
        }
    }

    if let Some(p) = project_path() {
        for d in read_file(&p) {
            map.insert(d.name.clone(), d);
        }
    }

    map.into_values().collect()
}

// ---------------------------------------------------------------------------
// Add / write
// ---------------------------------------------------------------------------

/// Persist `device` to the project registry (inside git tree, when `!global`)
/// or the global registry, whichever is appropriate.
///
/// Returns the path written.
pub fn add(device: Device, global: bool) -> Result<PathBuf> {
    let path = if !global {
        project_path().unwrap_or_else(|| {
            global_path().expect("neither project nor HOME path available")
        })
    } else {
        global_path().context("$HOME is unset; cannot resolve global registry path")?
    };

    let parent = path.parent().context("registry path has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("create dirs {}", parent.display()))?;

    // Write a brief README the first time.
    let readme = parent.join("README.md");
    if !readme.exists() {
        let _ = fs::write(
            &readme,
            "# .azula\n\nDevice registry for the azula CLI.\n\
             Edit `devices.json` to rename or remove devices.\n\
             Commit this file to share devices with your team.\n",
        );
    }

    // Read existing, replace same-name entry, write back.
    let mut existing = read_file(&path);
    if let Some(pos) = existing.iter().position(|d| d.name == device.name) {
        existing[pos] = device;
    } else {
        existing.push(device);
    }

    let content = serde_json::to_string_pretty(&RegistryFile { devices: existing })?;
    fs::write(&path, content).with_context(|| format!("write {}", path.display()))?;

    Ok(path)
}

/// Find a registered device whose ticket's embedded node id matches
/// `node_id`. Used by accept-side gates (`term.rs`, `mcp.rs`,
/// `accept_gate.rs`) to recognize a reconnecting known peer regardless of
/// what name it announces. Matches two `ticket` shapes: a dialable
/// `EndpointTicket` string (from `azula pair` / outbound dial), or a bare
/// node-id hex string (from accept-side registration, which has no
/// dialable address to store — see `accept_gate::gate_stranger`).
pub fn find_by_node_id(node_id: &EndpointId) -> Option<Device> {
    let node_id_str = node_id.to_string();
    load().into_iter().find(|d| {
        d.ticket == node_id_str
            || EndpointTicket::from_str(&d.ticket)
                .map(|t| &t.endpoint_addr().id == node_id)
                .unwrap_or(false)
    })
}

/// Remove `name` from both the project and global registry files (whichever
/// exist). Returns whether any entry was actually removed.
pub fn remove(name: &str) -> Result<bool> {
    let mut removed = false;
    for path in [project_path(), global_path()].into_iter().flatten() {
        if !path.exists() {
            continue;
        }
        let mut devices = read_file(&path);
        let before = devices.len();
        devices.retain(|d| d.name != name);
        if devices.len() == before {
            continue;
        }
        removed = true;
        let content = serde_json::to_string_pretty(&RegistryFile { devices })?;
        fs::write(&path, content).with_context(|| format!("write {}", path.display()))?;
    }
    Ok(removed)
}

// ---------------------------------------------------------------------------
// Relay hints (relay spec: "Sessions SHALL learn the relay's ticket from a
// relay hint the phone shares at machine pairing time, persisted per device
// in the registry")
// ---------------------------------------------------------------------------
//
// Deliberately a companion file (`relay-hints.json`) next to `devices.json`
// rather than a new field on [`Device`] itself: several call sites outside
// this phase's file ownership (`term.rs`, `accept_gate.rs`, `cli/legacy.rs`)
// construct `Device { .. }` struct literals exhaustively, and Rust has no
// notion of a "defaulted" struct-literal field short of touching every one of
// those sites with `..Default::default()` — which this phase's ownership
// boundary doesn't allow. This file shares `devices.json`'s project/global
// precedence and directories, so "persisted per device in the registry"
// still holds even though it's a sibling file rather than an extra key.

#[derive(Serialize, Deserialize, Default)]
struct RelayHintsFile {
    #[serde(default)]
    relays: std::collections::BTreeMap<String, String>,
}

/// The relay-hints sibling of a `devices.json` path (`project_path()`/
/// `global_path()` — both already include the devices filename). Named off
/// the devices file's own stem (`relay-hints.json` next to `devices.json`,
/// `global-relay-hints.json` next to `global-devices.json`) rather than
/// always `relay-hints.json`, so project and global stay distinct files even
/// under `AZULA_REGISTRY_DIR` test overrides, where [`override_dir`] resolves
/// both registries into the *same* directory and only their filenames differ.
fn relay_hints_path(devices_json_path: &Path) -> PathBuf {
    let stem = devices_json_path.file_stem().and_then(|s| s.to_str()).unwrap_or("devices");
    let hints_name = if stem == "global-devices" { "global-relay-hints.json" } else { "relay-hints.json" };
    match devices_json_path.parent() {
        Some(parent) => parent.join(hints_name),
        None => devices_json_path.with_file_name(hints_name),
    }
}

fn read_relay_hints(path: &Path) -> std::collections::BTreeMap<String, String> {
    let data = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return Default::default(),
    };
    serde_json::from_str::<RelayHintsFile>(&data).map(|f| f.relays).unwrap_or_default()
}

/// The relay ticket learned for `device_name`, if any. Global then project,
/// project wins on collision — the same merge precedence [`load`] uses.
pub fn relay_for(device_name: &str) -> Option<String> {
    let mut result = None;
    if let Some(g) = global_path() {
        if let Some(t) = read_relay_hints(&relay_hints_path(&g)).get(device_name) {
            result = Some(t.clone());
        }
    }
    if let Some(p) = project_path() {
        if let Some(t) = read_relay_hints(&relay_hints_path(&p)).get(device_name) {
            result = Some(t.clone());
        }
    }
    result
}

/// Persist a relay hint for `device_name`. Writes to whichever registry
/// directory (project checked first, then global) already holds that device,
/// so the hint lands "in the same file the device came from"; falls back to
/// the project registry's directory (same default [`add`] uses) if the
/// device isn't registered in either yet.
pub fn set_relay(device_name: &str, ticket: &str) -> Result<PathBuf> {
    let candidate_bases: Vec<PathBuf> = [project_path(), global_path()].into_iter().flatten().collect();

    let target = candidate_bases
        .iter()
        .find(|base| read_file(base).iter().any(|d| d.name == device_name))
        .or_else(|| candidate_bases.first())
        .context("registry: no project or global registry path available (is $HOME set?)")?
        .clone();

    let hints_path = relay_hints_path(&target);
    let mut hints = read_relay_hints(&hints_path);
    hints.insert(device_name.to_string(), ticket.to_string());

    if let Some(parent) = hints_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create dirs {}", parent.display()))?;
    }
    let content = serde_json::to_string_pretty(&RelayHintsFile { relays: hints })?;
    fs::write(&hints_path, content).with_context(|| format!("write {}", hints_path.display()))?;
    Ok(hints_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn isolated_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("azula-registry-test-{}-{name}", std::process::id()))
    }

    /// A `devices.json` written before `relay-hints.json` existed (i.e. the
    /// common case: no such file at all yet) still loads fine, and
    /// `relay_for` degrades to `None` rather than erroring — the "existing
    /// devices.json files load" requirement, reframed around the companion
    /// file this phase uses instead of a new `Device` struct field (see
    /// `set_relay`'s doc comment for why).
    #[tokio::test]
    async fn devices_load_unaffected_when_no_relay_hints_file_exists_yet() {
        let _guard = ENV_TEST_LOCK.lock().await;
        let dir = isolated_dir("no_hints_file");
        let _ = fs::remove_dir_all(&dir);
        std::env::set_var("AZULA_REGISTRY_DIR", &dir);

        add(Device { name: "phone".into(), ticket: "tk".into(), added_at: None, invite: None }, false).unwrap();

        let loaded = load();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "phone");
        assert_eq!(relay_for("phone"), None, "no relay hint recorded yet");

        std::env::remove_var("AZULA_REGISTRY_DIR");
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn set_relay_then_relay_for_round_trips() {
        let _guard = ENV_TEST_LOCK.lock().await;
        let dir = isolated_dir("round_trip");
        let _ = fs::remove_dir_all(&dir);
        std::env::set_var("AZULA_REGISTRY_DIR", &dir);

        add(Device { name: "phone".into(), ticket: "tk".into(), added_at: None, invite: None }, false).unwrap();
        set_relay("phone", "relay-ticket-1").unwrap();
        assert_eq!(relay_for("phone").as_deref(), Some("relay-ticket-1"));

        // A second hint for the same device overwrites, not appends.
        set_relay("phone", "relay-ticket-2").unwrap();
        assert_eq!(relay_for("phone").as_deref(), Some("relay-ticket-2"));

        std::env::remove_var("AZULA_REGISTRY_DIR");
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn set_relay_targets_the_global_registry_when_the_device_is_registered_there() {
        let _guard = ENV_TEST_LOCK.lock().await;
        let dir = isolated_dir("global_target");
        let _ = fs::remove_dir_all(&dir);
        std::env::set_var("AZULA_REGISTRY_DIR", &dir);

        add(Device { name: "phone".into(), ticket: "tk".into(), added_at: None, invite: None }, true).unwrap();
        set_relay("phone", "relay-ticket-g").unwrap();

        assert_eq!(relay_for("phone").as_deref(), Some("relay-ticket-g"));
        // Persisted next to `global-devices.json`, not `devices.json`.
        let global_hints = relay_hints_path(&global_path().unwrap());
        assert!(global_hints.exists());
        let project_hints = relay_hints_path(&project_path().unwrap());
        assert!(!project_hints.exists(), "must not have written the project-side hints file");

        std::env::remove_var("AZULA_REGISTRY_DIR");
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn set_relay_for_an_unregistered_device_falls_back_to_the_project_registry() {
        let _guard = ENV_TEST_LOCK.lock().await;
        let dir = isolated_dir("unregistered");
        let _ = fs::remove_dir_all(&dir);
        std::env::set_var("AZULA_REGISTRY_DIR", &dir);

        // No `add()` call at all -- the device isn't registered anywhere yet.
        set_relay("ghost", "relay-ticket-x").unwrap();
        assert_eq!(relay_for("ghost").as_deref(), Some("relay-ticket-x"));

        std::env::remove_var("AZULA_REGISTRY_DIR");
        let _ = fs::remove_dir_all(&dir);
    }
}
