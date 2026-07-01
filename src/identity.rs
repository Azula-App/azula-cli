//! Persistent node identity for the long-lived server commands.
//!
//! Per the iroh Endpoint guidance (https://docs.iroh.computer/concepts/endpoints.md)
//! an application should keep a single long-lived endpoint and reuse its
//! `SecretKey` across restarts so its node id — and thus the shareable connect
//! code — stays stable. Each server stores its raw 32-byte secret under
//! `~/.azula/<name>.key` (`serve.key`, `bridge.key`, `blackjack.key`).

use std::path::PathBuf;

use iroh::SecretKey;
use tracing::{info, warn};

/// `~/.azula/<name>.key`, or `None` if `$HOME` is unset.
fn key_path(name: &str) -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".azula").join(format!("{name}.key")))
}

/// Reuse the saved secret key for `name` if one exists, otherwise mint one and
/// save it so the next launch resumes with the same identity. Falls back to an
/// ephemeral key (and logs why) if the filesystem isn't usable.
pub fn load_or_create_secret(name: &str) -> SecretKey {
    let path = match key_path(name) {
        Some(p) => p,
        None => {
            warn!("$HOME unset — using an ephemeral key (connect code changes each run)");
            return SecretKey::generate();
        }
    };
    // The key is stored as its raw 32 secret bytes (SecretKey has no Display).
    if let Ok(bytes) = std::fs::read(&path) {
        if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
            info!(path = %path.display(), "resuming saved identity");
            return SecretKey::from_bytes(&arr);
        }
        warn!(path = %path.display(), "saved key unreadable — minting a new one");
    }
    let key = SecretKey::generate();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    match std::fs::write(&path, key.to_bytes()) {
        Ok(()) => info!(path = %path.display(), "saved new identity"),
        Err(e) => warn!(path = %path.display(), error = %e, "could not save key"),
    }
    key
}
