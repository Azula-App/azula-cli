//! Device registry — persists known azula device tickets.
//!
//! Two scopes:
//!   - **project**: `<git-root>/.azula/devices.json`  (written when inside a git tree)
//!   - **global**:  `~/.azula/devices.json`
//!   - **runtime**: `<tempdir>/azula/bridge.json`      (live state, managed by bridge)
//!
//! `load()` merges both. A row is identified by the endpoint id its ticket
//! resolves to, not by its display name, so re-pairing a device updates its
//! own row and two different devices never collide; project entries win when
//! both files hold the same device.

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

/// Resolve a stored `ticket` to the endpoint id it names, for either shape the
/// registry holds: a dialable `EndpointTicket` string (written by `azula pair`
/// and outbound dial), or a bare endpoint-id hex string (written by
/// accept-side registration, which has no dialable address to store — see
/// `accept_gate::gate_stranger`).
///
/// `None` when the ticket is in neither shape — a hand-edited row, or a
/// format we don't recognize. Those rows stay identified by name alone, so
/// editing `devices.json` by hand (which the shipped README invites) can't
/// make a row unreachable.
pub fn endpoint_id_of(ticket: &str) -> Option<EndpointId> {
    if let Ok(id) = EndpointId::from_str(ticket) {
        return Some(id);
    }
    EndpointTicket::from_str(ticket).ok().map(|t| t.endpoint_addr().id)
}

/// The value that identifies a registry row. A device *is* its endpoint id;
/// the display name is a mutable label on top. Rows whose ticket doesn't
/// resolve fall back to name identity — see [`endpoint_id_of`].
///
/// The `id:`/`name:` prefixes keep an endpoint-id string from ever colliding
/// with a device someone named after one.
fn identity_key(d: &Device) -> String {
    match endpoint_id_of(&d.ticket) {
        Some(id) => format!("id:{id}"),
        None => format!("name:{}", d.name),
    }
}

/// Load all known devices, merging global then project.
///
/// Rows are identified by endpoint id (see [`identity_key`]), so the same
/// device present in both files merges to one row with the project entry
/// winning — regardless of what either file calls it.
pub fn load() -> Vec<Device> {
    let global = global_path().map(|p| read_file(&p)).unwrap_or_default();
    let project = project_path().map(|p| read_file(&p)).unwrap_or_default();
    merge(global, project)
}

/// Merge two registry files into the view every caller sees.
///
/// Split out from [`load`] so it can be tested without touching the
/// filesystem or the process-global registry-dir env var.
fn merge(global: Vec<Device>, project: Vec<Device>) -> Vec<Device> {
    let mut map: indexmap::IndexMap<String, Device> = indexmap::IndexMap::new();
    let mut from_project: std::collections::HashSet<String> = std::collections::HashSet::new();

    for d in global {
        map.insert(identity_key(&d), d);
    }
    for d in project {
        let key = identity_key(&d);
        from_project.insert(key.clone());
        map.insert(key, d);
    }

    // A display name has to resolve to exactly one device — it's the handle
    // `--device` and `ensure_device` look up. Two *different* devices can only
    // end up sharing a name across the two files (a hand edit, or rows written
    // before `add` disambiguated). The project registry's device keeps the
    // name, which is the precedence that applied when rows were keyed by name
    // outright; the other is shadowed, exactly as it was before this keying.
    let mut owner: indexmap::IndexMap<String, String> = indexmap::IndexMap::new();
    for (key, d) in map.iter() {
        let take = match owner.get(&d.name) {
            None => true,
            Some(held) => !from_project.contains(held) && from_project.contains(key),
        };
        if take {
            owner.insert(d.name.clone(), key.clone());
        }
    }

    let kept: std::collections::HashSet<String> = owner.into_values().collect();
    map.into_iter().filter(|(k, _)| kept.contains(k)).map(|(_, d)| d).collect()
}

/// Pick a display name for `device` that no *other* device in `existing` is
/// already using.
///
/// Silent overwrite was the bug this change exists to fix; a silent name
/// collision would just relocate it, since a name that resolves to two
/// devices makes `--device` ambiguous. So when the derived name is taken by a
/// different endpoint id, extend the hex run it came from — `198896c5` →
/// `198896c52` → `198896c52f` — which keeps the name derived from the device
/// rather than from an arbitrary counter, and preserves any role prefix
/// (`term-`, `mailbox-peer-`) the caller put in front of it.
///
/// Falls back to numeric suffixes for names not derived from the endpoint id,
/// and gives up extending at 16 hex chars: two endpoint ids sharing a 16-hex
/// prefix isn't a collision anyone will hit, and the loop needs a defined end.
fn disambiguate(device: &Device, existing: &[Device]) -> String {
    let taken = |candidate: &str| {
        existing.iter().any(|d| d.name == candidate && identity_key(d) != identity_key(device))
    };

    if !taken(&device.name) {
        return device.name.clone();
    }

    if let Some(id) = endpoint_id_of(&device.ticket) {
        let full = id.to_string();
        // Keep whatever precedes the 8-hex run (a role prefix, or nothing).
        if let Some(prefix) = full.get(..8).and_then(|short| device.name.strip_suffix(short)) {
            for len in 9..=16.min(full.len()) {
                if let Some(run) = full.get(..len) {
                    let candidate = format!("{prefix}{run}");
                    if !taken(&candidate) {
                        return candidate;
                    }
                }
            }
        }
    }

    (2..)
        .map(|n| format!("{}-{n}", device.name))
        .find(|candidate| !taken(candidate))
        .expect("an unused numeric suffix always exists")
}

// ---------------------------------------------------------------------------
// Add / write
// ---------------------------------------------------------------------------

/// What [`add`] persisted.
pub struct Added {
    /// The registry file written.
    pub path: PathBuf,
    /// The name the device is stored under. Not always the name passed in: a
    /// name already held by a *different* device is disambiguated, so callers
    /// that report back to the user must report this rather than what they
    /// asked for.
    pub name: String,
}

/// Persist `device` to the project registry (inside git tree, when `!global`)
/// or the global registry, whichever is appropriate.
pub fn add(device: Device, global: bool) -> Result<Added> {
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

    // Read existing, replace this device's own row, write back.
    //
    // The row is matched by endpoint id, not by display name: re-pairing a
    // device through a fresh invite carries different ticket text but the
    // same endpoint id, and must update its own row rather than fork a
    // duplicate — while two *different* devices must never collide, whatever
    // they happen to be called. Rows on either side that don't resolve to an
    // endpoint id fall back to name equality.
    let mut existing = read_file(&path);
    let pos = existing.iter().position(|d| match (endpoint_id_of(&device.ticket), endpoint_id_of(&d.ticket)) {
        (Some(incoming), Some(known)) => incoming == known,
        _ => d.name == device.name,
    });

    // Check the merged view, not just this file: a name has to be unambiguous
    // across both registries, since that's what callers resolve against.
    // `disambiguate` ignores this device's own row, so replacing it in place
    // never counts as colliding with itself.
    let mut device = device;
    let mut seen = load();
    seen.extend(existing.iter().cloned());
    device.name = disambiguate(&device, &seen);
    let name = device.name.clone();

    match pos {
        Some(pos) => existing[pos] = device,
        None => existing.push(device),
    }

    let content = serde_json::to_string_pretty(&RegistryFile { devices: existing })?;
    fs::write(&path, content).with_context(|| format!("write {}", path.display()))?;

    Ok(Added { path, name })
}

/// Find a registered device whose ticket's embedded endpoint id matches
/// `endpoint_id`. Used by accept-side gates (`term.rs`, `mcp.rs`,
/// `accept_gate.rs`) to recognize a reconnecting known peer regardless of
/// what name it announces.
pub fn find_by_endpoint_id(endpoint_id: &EndpointId) -> Option<Device> {
    load().into_iter().find(|d| endpoint_id_of(&d.ticket) == Some(*endpoint_id))
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

    /// A fresh endpoint id, and a dialable ticket naming it — the two shapes a
    /// `Device.ticket` can hold.
    fn endpoint() -> (EndpointId, String) {
        let id = iroh::SecretKey::generate().public();
        (id, EndpointTicket::new(iroh::EndpointAddr::from(id)).to_string())
    }

    fn dev(name: &str, ticket: &str) -> Device {
        Device { name: name.into(), ticket: ticket.into(), added_at: None, invite: None }
    }

    /// The bug this change fixes: two phones paired from invites both derived
    /// the name `endpoint`, and the second silently replaced the first.
    #[tokio::test]
    async fn two_devices_sharing_a_name_both_survive() {
        let _guard = ENV_TEST_LOCK.lock().await;
        let dir = isolated_dir("no_collision");
        let _ = fs::remove_dir_all(&dir);
        std::env::set_var("AZULA_REGISTRY_DIR", &dir);

        let (first_id, first_ticket) = endpoint();
        let (second_id, second_ticket) = endpoint();
        add(dev("endpoint", &first_ticket), false).unwrap();
        let second = add(dev("endpoint", &second_ticket), false).unwrap();

        let loaded = load();
        assert_eq!(loaded.len(), 2, "second pairing must not replace the first");
        assert_ne!(second.name, "endpoint", "the contested name must be disambiguated");
        assert!(find_by_endpoint_id(&first_id).is_some(), "first device still registered");
        assert!(find_by_endpoint_id(&second_id).is_some(), "second device registered");

        std::env::remove_var("AZULA_REGISTRY_DIR");
        let _ = fs::remove_dir_all(&dir);
    }

    /// Re-pairing through a fresh invite carries different ticket text but the
    /// same endpoint id: it must update that device's own row, not fork one —
    /// and must not disturb a name the user chose.
    #[tokio::test]
    async fn re_pairing_updates_the_devices_own_row() {
        let _guard = ENV_TEST_LOCK.lock().await;
        let dir = isolated_dir("re_pair");
        let _ = fs::remove_dir_all(&dir);
        std::env::set_var("AZULA_REGISTRY_DIR", &dir);

        let (id, ticket) = endpoint();
        add(dev("my-phone", &id.to_string()), false).unwrap();
        // Same device, now as a dialable ticket rather than a bare id.
        add(dev("my-phone", &ticket), false).unwrap();

        let loaded = load();
        assert_eq!(loaded.len(), 1, "same endpoint id must occupy one row");
        assert_eq!(loaded[0].ticket, ticket, "row updated to the newer ticket");

        std::env::remove_var("AZULA_REGISTRY_DIR");
        let _ = fs::remove_dir_all(&dir);
    }

    /// Hand-edited rows whose ticket names no endpoint id keep matching by
    /// name, so editing `devices.json` can't strand a row.
    #[tokio::test]
    async fn unresolvable_rows_still_match_by_name() {
        let _guard = ENV_TEST_LOCK.lock().await;
        let dir = isolated_dir("unresolvable");
        let _ = fs::remove_dir_all(&dir);
        std::env::set_var("AZULA_REGISTRY_DIR", &dir);

        add(dev("phone", "hand-written"), false).unwrap();
        add(dev("phone", "hand-written-again"), false).unwrap();

        let loaded = load();
        assert_eq!(loaded.len(), 1, "same name, unresolvable ticket: one row");
        assert_eq!(loaded[0].ticket, "hand-written-again");
        assert!(remove("phone").unwrap(), "and it stays forgettable");

        std::env::remove_var("AZULA_REGISTRY_DIR");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn merge_collapses_one_device_present_in_both_files() {
        let (_, ticket) = endpoint();
        let merged = merge(vec![dev("phone", &ticket)], vec![dev("renamed-phone", &ticket)]);
        assert_eq!(merged.len(), 1, "same endpoint id is one device");
        assert_eq!(merged[0].name, "renamed-phone", "project registry wins");
    }

    #[test]
    fn merge_keeps_distinct_devices_that_share_a_name() {
        let (_, a) = endpoint();
        let (_, b) = endpoint();
        let merged = merge(vec![dev("phone", &a)], vec![dev("phone", &b)]);
        // Both are real devices, but a name has to resolve to one of them.
        assert_eq!(merged.len(), 1, "a contested name resolves to a single device");
        assert_eq!(merged[0].ticket, b, "project registry wins the name");
    }

    #[test]
    fn disambiguate_extends_the_hex_run_and_keeps_any_prefix() {
        let (id, ticket) = endpoint();
        let short: String = id.to_string().chars().take(8).collect();
        let (_, other) = endpoint();

        let device = dev(&format!("term-{short}"), &ticket);
        let taken = vec![dev(&format!("term-{short}"), &other)];
        let picked = disambiguate(&device, &taken);

        assert_ne!(picked, device.name, "must not reuse a name another device holds");
        assert!(picked.starts_with(&format!("term-{short}")), "extends rather than replaces: {picked}");
    }

    #[test]
    fn disambiguate_leaves_a_devices_own_row_alone() {
        let (_, ticket) = endpoint();
        let device = dev("phone", &ticket);
        // The same device already on disk isn't a collision with itself.
        let existing = vec![dev("phone", &ticket)];
        assert_eq!(disambiguate(&device, &existing), "phone");
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
