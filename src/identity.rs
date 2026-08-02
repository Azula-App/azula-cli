//! Persistent endpoint identity for the long-lived server commands.
//!
//! Per the iroh Endpoint guidance (https://docs.iroh.computer/concepts/endpoints.md)
//! an application should keep a single long-lived endpoint and reuse its
//! `SecretKey` across restarts so its endpoint id — and thus the shareable connect
//! code — stays stable. Each server stores its raw 32-byte secret under
//! `~/.azula/<name>.key` (`serve.key`, `bridge.key`, `blackjack.key`).

use std::path::{Path, PathBuf};

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

// ---------------------------------------------------------------------------
// Machine identity (cli-multi-session-relay design.md D1)
// ---------------------------------------------------------------------------
//
// `~/.azula/machine.key` is the stable per-machine root that signs session
// certificates. On a machine that already ran `azula serve-mcp`/`azula mcp`
// before per-session keys existed, `~/.azula/bridge.key` holds that identity
// — it is adopted as-is (bytes copied to `machine.key`, `bridge.key` left in
// place untouched) so the endpoint id, and therefore every pairing the phone
// already has with this machine, is unchanged.
//
// CRITICAL: session-establishment code paths (binding the per-process
// session endpoint) must call `load_machine_secret_if_exists` — never
// `load_or_create_machine_secret` — so a headless environment (no
// `machine.key`, no `bridge.key` to adopt) never gets a machine identity
// written to disk merely because a session started (the headless spec's "no
// standing credential" requirement). Creation is reserved for explicit
// pairing-side flows: minting an invite against the machine identity
// (`azula invite --bridge`), the `start_pairing` tool / startup banner, or a
// future `azula pair` context.

/// Read a saved secret key's raw 32 bytes from `path`, if present and valid.
fn read_secret_at(path: &Path) -> Option<SecretKey> {
    let bytes = std::fs::read(path).ok()?;
    let arr = <[u8; 32]>::try_from(bytes.as_slice()).ok()?;
    Some(SecretKey::from_bytes(&arr))
}

/// Load the machine identity if one already exists on disk — reading
/// `~/.azula/machine.key`, or adopting `~/.azula/bridge.key` in place (D1's
/// migration) when only that exists — **without creating anything new**.
/// Returns `None` when neither file exists (or there's no resolvable key
/// directory, e.g. `$HOME` unset outside tests): callers on a
/// session-establishment path must treat that as "no machine identity here,"
/// never as licence to create one (see the module-level note above).
pub fn load_machine_secret_if_exists() -> Option<SecretKey> {
    let machine_path = key_path("machine")?;
    if let Some(key) = read_secret_at(&machine_path) {
        info!(path = %machine_path.display(), "resuming machine identity");
        return Some(key);
    }

    // No machine.key (or it was unreadable) — check bridge.key for adoption.
    let bridge_path = key_path("bridge")?;
    let key = read_secret_at(&bridge_path)?;

    // Adopt: persist the same bytes under machine.key; bridge.key is left
    // untouched so anything still reading it directly keeps working too.
    if let Some(dir) = machine_path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    match std::fs::write(&machine_path, key.to_bytes()) {
        Ok(()) => info!(
            path = %machine_path.display(),
            bridge_path = %bridge_path.display(),
            "adopted bridge.key as the machine identity (endpoint id unchanged)"
        ),
        Err(e) => warn!(path = %machine_path.display(), error = %e, "could not persist adopted machine key"),
    }
    Some(key)
}

/// As [`load_machine_secret_if_exists`], but mints and persists a fresh
/// machine key when neither `machine.key` nor `bridge.key` exists yet.
/// Reserved for explicit pairing-side flows (see the module-level note
/// above) — never call this from a session-establishment path.
pub fn load_or_create_machine_secret() -> SecretKey {
    if let Some(key) = load_machine_secret_if_exists() {
        return key;
    }
    load_or_create_secret("machine")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Point `AZULA_KEY_DIR` at a fresh, empty per-test directory and return
    /// it. Tests that mutate this process-global env var hold the shared
    /// `registry::ENV_TEST_LOCK` for the duration of the mutation (`cargo
    /// test`'s default parallelism would otherwise let them race and read
    /// back each other's directory).
    fn isolated_key_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("azula-identity-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("AZULA_KEY_DIR", &dir);
        dir
    }

    #[test]
    fn distinct_identity_names_never_share_a_key() {
        let _guard = crate::registry::ENV_TEST_LOCK.blocking_lock();
        let dir = isolated_key_dir("distinct_names");

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

    // --- Machine identity (design.md D1) -----------------------------------

    #[test]
    fn bridge_key_adopted_as_machine_key_preserves_endpoint_id() {
        let _guard = crate::registry::ENV_TEST_LOCK.blocking_lock();
        let dir = isolated_key_dir("adopt_bridge");

        // Simulate a pre-existing install: only bridge.key on disk.
        let bridge_key = load_or_create_secret("bridge");
        assert!(dir.join("bridge.key").exists());
        assert!(!dir.join("machine.key").exists());

        let adopted = load_machine_secret_if_exists().expect("bridge.key should be adopted");
        assert_eq!(
            adopted.to_bytes(),
            bridge_key.to_bytes(),
            "adopted machine key must be byte-identical to bridge.key (same endpoint id)"
        );
        assert_eq!(
            adopted.public(),
            bridge_key.public(),
            "the endpoint id (public key) must be unchanged by adoption"
        );

        // machine.key now exists on disk, with the same bytes; bridge.key is
        // untouched (still present, still readable, same content).
        assert!(dir.join("machine.key").exists());
        let machine_bytes = std::fs::read(dir.join("machine.key")).unwrap();
        assert_eq!(machine_bytes, bridge_key.to_bytes());
        let bridge_bytes = std::fs::read(dir.join("bridge.key")).unwrap();
        assert_eq!(bridge_bytes, bridge_key.to_bytes(), "bridge.key must be left in place, unchanged");

        // A second call resumes the now-adopted machine.key (not bridge.key
        // again) and still returns the same identity.
        let resumed = load_machine_secret_if_exists().expect("machine.key now exists");
        assert_eq!(resumed.to_bytes(), bridge_key.to_bytes());

        std::env::remove_var("AZULA_KEY_DIR");
    }

    #[test]
    fn no_machine_or_bridge_key_session_path_creates_nothing() {
        let _guard = crate::registry::ENV_TEST_LOCK.blocking_lock();
        let dir = isolated_key_dir("headless");

        // Neither machine.key nor bridge.key exists — the headless case.
        assert!(!dir.join("machine.key").exists());
        assert!(!dir.join("bridge.key").exists());

        // The session-establishment-safe accessor must return None and must
        // not write anything: "no standing credential" in a headless env.
        assert!(load_machine_secret_if_exists().is_none());
        assert!(!dir.join("machine.key").exists(), "load_machine_secret_if_exists must never create machine.key");
        assert!(!dir.join("bridge.key").exists());

        std::env::remove_var("AZULA_KEY_DIR");
    }

    #[test]
    fn load_or_create_machine_secret_creates_when_neither_exists() {
        let _guard = crate::registry::ENV_TEST_LOCK.blocking_lock();
        let dir = isolated_key_dir("create_machine");

        assert!(load_machine_secret_if_exists().is_none());

        let created = load_or_create_machine_secret();
        assert!(dir.join("machine.key").exists());
        assert!(!dir.join("bridge.key").exists(), "must not fabricate a bridge.key");

        // Idempotent: calling again resumes the same identity rather than
        // minting a fresh one.
        let resumed = load_or_create_machine_secret();
        assert_eq!(created.to_bytes(), resumed.to_bytes());
        // And the read-only accessor now sees it too.
        assert_eq!(load_machine_secret_if_exists().unwrap().to_bytes(), created.to_bytes());

        std::env::remove_var("AZULA_KEY_DIR");
    }

    #[test]
    fn load_or_create_machine_secret_adopts_bridge_key_when_present() {
        let _guard = crate::registry::ENV_TEST_LOCK.blocking_lock();
        let _dir = isolated_key_dir("create_or_adopt");

        let bridge_key = load_or_create_secret("bridge");
        let result = load_or_create_machine_secret();
        assert_eq!(
            result.to_bytes(),
            bridge_key.to_bytes(),
            "load_or_create_machine_secret must adopt an existing bridge.key rather than minting a fresh key"
        );

        std::env::remove_var("AZULA_KEY_DIR");
    }
}
