//! Persisted state for a CLI device enrolled into a multi-device identity
//! via `azula link`: the granted device certificate and identity bundle
//! delivered by `LinkGrant` (`certs::DeviceCert` / `proto::IdentityBundle`).
//!
//! The device's own endpoint secret is persisted separately, under its own
//! named identity ([`NODE_IDENTITY_NAME`], via
//! `identity::load_or_create_secret`) — distinct from `serve`/`bridge`/
//! `blackjack`'s own persistent identities, per the device-linking spec's
//! "CLI Device Enrollment" requirement ("keep its identity separate from
//! the CLI's other long-lived command identities"). Both `azula link`
//! (which produces this file) and `azula mailbox` (which consumes it to
//! serve the mailbox role for the identity) share this module.

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::proto::IdentityBundle;

/// The named identity `azula link`/`azula mailbox` persist their endpoint
/// secret under (`identity::load_or_create_secret(NODE_IDENTITY_NAME)`,
/// `~/.azula/link.key`) — distinct from `"serve"`/`"bridge"`/`"blackjack"`.
pub const NODE_IDENTITY_NAME: &str = "link";

/// On-disk shape of a linked device's granted state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinkedIdentity {
    /// This device's own granted certificate (`"azd…"`).
    pub cert: String,
    /// The identity bundle delivered alongside it.
    pub bundle: IdentityBundle,
}

/// `AZULA_LINK_DIR` override (tests / sandboxes, mirroring
/// `registry::override_dir`) — under `cfg(test)` this defaults to an
/// isolated temp dir even without the env var, so the test suite never
/// touches a developer's real `~/.azula`. Returns `None` only if there's no
/// override and `$HOME` is unset.
fn dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("AZULA_LINK_DIR") {
        return Some(PathBuf::from(dir));
    }
    #[cfg(test)]
    {
        return Some(std::env::temp_dir().join("azula-test").join("link"));
    }
    #[allow(unreachable_code)]
    {
        let home = std::env::var("HOME").ok()?;
        Some(PathBuf::from(home).join(".azula"))
    }
}

fn file_path() -> Option<PathBuf> {
    dir().map(|d| d.join("link-identity.json"))
}

/// Load the persisted linked identity, if `azula link` has ever completed
/// successfully. `None` if never linked, or the file is missing/corrupt —
/// per "Device Registry Persistence", losing this cache degrades to
/// re-linking, never to identity loss (the underlying endpoint key survives
/// independently, under [`NODE_IDENTITY_NAME`]).
pub fn load() -> Option<LinkedIdentity> {
    let path = file_path()?;
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

/// Persist a newly granted certificate + bundle, overwriting any previous
/// linked identity (re-running `azula link` re-links).
pub fn save(identity: &LinkedIdentity) -> Result<PathBuf> {
    let path = file_path().context("cannot resolve link identity path ($HOME unset)")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create dirs {}", parent.display()))?;
    }
    let content = serde_json::to_string_pretty(identity)?;
    std::fs::write(&path, content).with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::Contact;

    // Both tests below mutate the process-global `AZULA_LINK_DIR` env var;
    // guard with a lock (same convention as `registry::ENV_TEST_LOCK`) so
    // cargo test's default parallelism can't interleave them.
    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn test_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("azula-linked-identity-test-{}", std::process::id())).join(name)
    }

    fn sample() -> LinkedIdentity {
        LinkedIdentity {
            cert: "azd-example".to_string(),
            bundle: IdentityBundle {
                root_pk: "root-hex".to_string(),
                certs: vec!["azd-example".to_string()],
                revocations: vec![],
                contacts: vec![Contact {
                    root_pk: Some("contact-root".into()),
                    endpoint_id: None,
                    name: Some("Alice".into()),
                }],
                mailbox: None,
            },
        }
    }

    #[test]
    fn save_then_load_round_trips() {
        let _guard = ENV_TEST_LOCK.lock().unwrap();
        let dir = test_dir("round_trip");
        std::env::set_var("AZULA_LINK_DIR", &dir);

        assert!(load().is_none(), "nothing saved yet");
        let identity = sample();
        save(&identity).unwrap();
        assert_eq!(load(), Some(identity));

        std::env::remove_var("AZULA_LINK_DIR");
    }

    #[test]
    fn load_returns_none_when_nothing_saved() {
        let _guard = ENV_TEST_LOCK.lock().unwrap();
        let dir = test_dir("nothing_saved");
        std::env::set_var("AZULA_LINK_DIR", &dir);

        assert!(load().is_none());

        std::env::remove_var("AZULA_LINK_DIR");
    }

    #[test]
    fn re_saving_overwrites_the_previous_linked_identity() {
        let _guard = ENV_TEST_LOCK.lock().unwrap();
        let dir = test_dir("overwrite");
        std::env::set_var("AZULA_LINK_DIR", &dir);

        save(&sample()).unwrap();
        let mut second = sample();
        second.cert = "azd-relinked".to_string();
        save(&second).unwrap();
        assert_eq!(load(), Some(second));

        std::env::remove_var("AZULA_LINK_DIR");
    }
}
