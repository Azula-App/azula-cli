//! Device registry — persists known azula device tickets.
//!
//! Two scopes:
//!   - **project**: `<git-root>/.azula/devices.json`  (written when inside a git tree)
//!   - **global**:  `~/.azula/devices.json`
//!   - **runtime**: `<tempdir>/azula/bridge.json`      (live state, managed by bridge)
//!
//! `load()` merges both; project entries win on name collision.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// A single registered device.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Device {
    pub name: String,
    pub ticket: String,
    pub added_at: Option<u64>,
}

/// On-disk format.
#[derive(Serialize, Deserialize, Default)]
struct RegistryFile {
    devices: Vec<Device>,
}

// ---------------------------------------------------------------------------
// Path resolution
// ---------------------------------------------------------------------------

/// Walk up from cwd to find the first ancestor that contains a `.git` entry
/// (file or directory).  Returns `<root>/.azula/devices.json` or `None`.
pub fn project_path() -> Option<PathBuf> {
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
    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".azula").join("devices.json"))
}

// ---------------------------------------------------------------------------
// Load / merge
// ---------------------------------------------------------------------------

fn read_file(path: &PathBuf) -> Vec<Device> {
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
