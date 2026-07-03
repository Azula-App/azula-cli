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

/// A single registered device.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Device {
    pub name: String,
    pub ticket: String,
    pub added_at: Option<u64>,
    /// The encoded invite string (`"azi…"`) this device was paired with, if
    /// any — kept so a reconnect can keep presenting it (see
    /// `azula-docs/docs/invitations.md`'s "redeemer re-presents" rule).
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
/// `node_id`. Used by accept-side gates (`term.rs`, `bridge/device.rs`) to
/// recognize a reconnecting known peer regardless of what name it announces.
/// A device whose `ticket` doesn't parse as a dialable `EndpointTicket` (e.g.
/// one registered from a bare inbound node-id string) never matches.
pub fn find_by_node_id(node_id: &EndpointId) -> Option<Device> {
    load().into_iter().find(|d| {
        EndpointTicket::from_str(&d.ticket)
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
