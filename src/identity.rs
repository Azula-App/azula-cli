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

/// `~/.azula/<name>.key`, or the `AZULA_KEY_DIR` override (tests / sandboxes,
/// mirroring `registry::override_dir`) — under `cfg(test)` this defaults to
/// an isolated temp dir even without the env var, so the test suite never
/// touches a developer's real `~/.azula`. Returns `None` only if there's no
/// override and `$HOME` is unset.
fn key_path(name: &str) -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("AZULA_KEY_DIR") {
        return Some(PathBuf::from(dir).join(format!("{name}.key")));
    }
    #[cfg(test)]
    {
        return Some(std::env::temp_dir().join("azula-test").join("keys").join(format!("{name}.key")));
    }
    #[allow(unreachable_code)]
    {
        let home = std::env::var("HOME").ok()?;
        Some(PathBuf::from(home).join(".azula").join(format!("{name}.key")))
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    // Only this one test mutates `AZULA_KEY_DIR`, so it doesn't need the
    // `ENV_TEST_LOCK` guard convention `registry.rs`/`accept_gate.rs` use for
    // env vars touched by multiple concurrent tests.
    #[test]
    fn distinct_identity_names_never_share_a_key() {
        let dir = std::env::temp_dir().join(format!("azula-identity-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("AZULA_KEY_DIR", &dir);

        // Task 6.4: `azula link`'s identity (named "link") must be distinct
        // from `serve`'s — the device-linking spec's "CLI Device Enrollment"
        // requirement that a linked device "keep its identity separate from
        // the CLI's other long-lived command identities".
        let link_key = load_or_create_secret("link");
        let serve_key = load_or_create_secret("serve");
        assert_ne!(link_key.to_bytes(), serve_key.to_bytes());
        assert!(dir.join("link.key").exists());
        assert!(dir.join("serve.key").exists());

        // Reuse: calling again for the same name resumes the same key rather
        // than minting a new one.
        let link_key_again = load_or_create_secret("link");
        assert_eq!(link_key.to_bytes(), link_key_again.to_bytes());

        std::env::remove_var("AZULA_KEY_DIR");
    }
}
