//! Per-process session key management (cli-multi-session-relay design.md
//! D2).
//!
//! Every azula process that talks to a device — an `azula mcp` server, a
//! terminal host, a scripted `--session` invocation — holds its own session
//! keypair, never the shared machine key directly (see `identity.rs` /
//! `certs.rs`). [`SessionKey::resolve`] is the single entry point:
//!
//! - An explicit name (`--session NAME`) or `AZULA_SESSION` selects a
//!   **named** session: a persistent key at `~/.azula/sessions/<name>.key`
//!   (created 0600 on first use), so repeated one-shot invocations land in
//!   the same phone conversation.
//! - With neither, a fresh **ephemeral** key is minted under
//!   `$TMPDIR/azula/sessions/` and deleted again when the returned
//!   [`SessionKey`] (or, more precisely, its guard) is dropped — nothing
//!   survives a clean exit, per the headless "no standing credential" rule.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use iroh::SecretKey;
use tracing::warn;

/// Which mode a resolved [`SessionKey`] is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionMode {
    /// Persistent, named by `--session`/`AZULA_SESSION`; the key file
    /// survives across invocations.
    Named,
    /// Fresh key for this process only; its file (if one was written) is
    /// removed again when the session's guard drops.
    Ephemeral,
}

/// A resolved session identity: its key, whether it's named or ephemeral, a
/// short display name for banners/logs/`azula sessions`, and — for an
/// ephemeral session — a guard that deletes the on-disk key file on drop.
pub struct SessionKey {
    pub secret: SecretKey,
    pub mode: SessionMode,
    pub display_name: String,
    /// On-disk path of the key file, if one was successfully written.
    path: Option<PathBuf>,
    /// Present only for ephemeral sessions; deletes `path` on drop. `None`
    /// for named sessions, whose file is meant to persist.
    _guard: Option<EphemeralGuard>,
}

/// Deletes its key file when dropped — the mechanism behind "ephemeral keys
/// live under `$TMPDIR/azula/sessions/` and are deleted on clean exit" (D2).
/// Note this is a `Drop` impl: it does **not** fire on `std::process::exit`
/// or a signal kill, only on an ordinary unwind/return out of scope. A later
/// phase wiring up signal handling should keep that gotcha in mind.
struct EphemeralGuard {
    path: PathBuf,
}

impl Drop for EphemeralGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

impl SessionKey {
    /// Resolve a session per D2: an explicit `name` (from `--session`), else
    /// `AZULA_SESSION`, selects a persistent named session; with neither set
    /// (or set to an empty string), mint a fresh ephemeral one.
    pub fn resolve(name: Option<&str>) -> Result<SessionKey> {
        let explicit = name
            .map(str::to_string)
            .or_else(|| std::env::var("AZULA_SESSION").ok())
            .filter(|s| !s.trim().is_empty());

        match explicit {
            Some(name) => Self::named(&name),
            None => Ok(Self::ephemeral()),
        }
    }

    /// The on-disk key file's path, if one was written (named sessions
    /// always have one; an ephemeral session's is `None` only if writing it
    /// failed, in which case the key still works, just in-memory only).
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    fn named(name: &str) -> Result<SessionKey> {
        let dir = sessions_dir()?;
        let path = dir.join(format!("{name}.key"));
        let secret = load_or_create_key_at(&path)?;
        Ok(SessionKey {
            secret,
            mode: SessionMode::Named,
            display_name: name.to_string(),
            path: Some(path),
            _guard: None,
        })
    }

    fn ephemeral() -> SessionKey {
        let secret = SecretKey::generate();
        let display_name = format!("mcp-{}", random_suffix());
        let dir = std::env::temp_dir().join("azula").join("sessions");
        let path = dir.join(format!("{display_name}.key"));

        let mut written_path = None;
        if let Err(e) = std::fs::create_dir_all(&dir) {
            warn!(dir = %dir.display(), error = %e, "session: could not create ephemeral session dir");
        } else {
            match write_key_secure(&path, &secret) {
                Ok(()) => written_path = Some(path.clone()),
                Err(e) => warn!(path = %path.display(), error = %e, "session: could not persist ephemeral key file"),
            }
        }

        SessionKey {
            secret,
            mode: SessionMode::Ephemeral,
            display_name,
            path: written_path.clone(),
            _guard: written_path.map(|path| EphemeralGuard { path }),
        }
    }
}

/// `~/.azula/sessions`, or the `AZULA_SESSIONS_DIR` override (tests /
/// sandboxes, mirroring `registry::AZULA_REGISTRY_DIR`). Under `cfg(test)`
/// this defaults to an isolated temp dir even without the env var, so the
/// test suite never touches a developer's real `~/.azula/sessions`.
fn sessions_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("AZULA_SESSIONS_DIR") {
        return Ok(PathBuf::from(dir));
    }
    #[cfg(test)]
    {
        return Ok(std::env::temp_dir().join("azula-test").join("sessions"));
    }
    #[allow(unreachable_code)]
    {
        let home = std::env::var("HOME").context("$HOME is unset; cannot resolve the session key directory")?;
        Ok(PathBuf::from(home).join(".azula").join("sessions"))
    }
}

/// Reuse the saved secret key at `path` if one exists, otherwise mint one,
/// persist it 0600, and return it.
fn load_or_create_key_at(path: &Path) -> Result<SecretKey> {
    if let Ok(bytes) = std::fs::read(path) {
        if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
            return Ok(SecretKey::from_bytes(&arr));
        }
        warn!(path = %path.display(), "session: saved key unreadable — minting a new one");
    }
    let key = SecretKey::generate();
    write_key_secure(path, &key)?;
    Ok(key)
}

fn write_key_secure(path: &Path, key: &SecretKey) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("create dirs {}", dir.display()))?;
    }
    std::fs::write(path, key.to_bytes()).with_context(|| format!("write {}", path.display()))?;
    restrict_permissions(path);
    Ok(())
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        warn!(path = %path.display(), error = %e, "session: could not set key file permissions to 0600");
    }
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) {}

/// A short random display-name suffix (4 lowercase hex chars, e.g. `3f9a`),
/// drawn from a freshly generated Ed25519 key's CSPRNG output rather than
/// pulling in a `rand` dependency — same trick `invite.rs` uses for its
/// invite id nonce.
fn random_suffix() -> String {
    let bytes = SecretKey::generate().to_bytes();
    data_encoding::HEXLOWER.encode(&bytes[..2])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes tests that mutate the process-global `AZULA_SESSIONS_DIR`
    /// env var — mirrors `registry::ENV_TEST_LOCK`.
    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn isolated_sessions_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("azula-session-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("AZULA_SESSIONS_DIR", &dir);
        dir
    }

    #[test]
    fn named_session_key_persists_across_two_resolves() {
        let _guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = isolated_sessions_dir("persist");

        let first = SessionKey::resolve(Some("blackjack")).expect("resolves");
        assert_eq!(first.mode, SessionMode::Named);
        assert_eq!(first.display_name, "blackjack");
        assert!(dir.join("blackjack.key").exists());

        let second = SessionKey::resolve(Some("blackjack")).expect("resolves again");
        assert_eq!(
            first.secret.to_bytes(),
            second.secret.to_bytes(),
            "the same session name must resolve to the same key across invocations"
        );

        std::env::remove_var("AZULA_SESSIONS_DIR");
    }

    #[test]
    fn distinct_named_sessions_get_distinct_keys() {
        let _guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _dir = isolated_sessions_dir("distinct");

        let cli = SessionKey::resolve(Some("cli")).expect("resolves");
        let other = SessionKey::resolve(Some("other")).expect("resolves");
        assert_ne!(cli.secret.to_bytes(), other.secret.to_bytes());

        std::env::remove_var("AZULA_SESSIONS_DIR");
    }

    #[test]
    fn env_var_selects_a_named_session_when_no_explicit_name() {
        let _guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = isolated_sessions_dir("env_named");
        std::env::set_var("AZULA_SESSION", "from-env");

        let resolved = SessionKey::resolve(None).expect("resolves");
        assert_eq!(resolved.mode, SessionMode::Named);
        assert_eq!(resolved.display_name, "from-env");
        assert!(dir.join("from-env.key").exists());

        std::env::remove_var("AZULA_SESSION");
        std::env::remove_var("AZULA_SESSIONS_DIR");
    }

    #[test]
    fn no_name_and_no_env_is_ephemeral() {
        let _guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _dir = isolated_sessions_dir("ephemeral_mode");
        std::env::remove_var("AZULA_SESSION"); // in case another test leaked it

        let resolved = SessionKey::resolve(None).expect("resolves");
        assert_eq!(resolved.mode, SessionMode::Ephemeral);
        assert!(resolved.display_name.starts_with("mcp-"));

        std::env::remove_var("AZULA_SESSIONS_DIR");
    }

    #[test]
    fn ephemeral_key_file_removed_on_guard_drop() {
        // AZULA_SESSION is process-global; guard against a concurrently
        // running test (e.g. `env_var_selects_a_named_session_when_no_explicit_name`)
        // having it set at this exact moment, which would make `resolve(None)`
        // pick the named branch instead of ephemeral.
        let _guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("AZULA_SESSION");

        let resolved = SessionKey::resolve(None).expect("resolves");
        let path = resolved.path().expect("ephemeral key should have been persisted").to_path_buf();
        assert!(path.exists(), "ephemeral key file should exist while the session is alive");

        drop(resolved);
        assert!(!path.exists(), "ephemeral key file must be removed once the session's guard drops");
    }

    #[test]
    fn two_ephemeral_sessions_get_distinct_keys_and_names() {
        let _guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("AZULA_SESSION");

        let a = SessionKey::resolve(None).expect("resolves");
        let b = SessionKey::resolve(None).expect("resolves");
        assert_ne!(a.secret.to_bytes(), b.secret.to_bytes());
        assert_ne!(a.display_name, b.display_name);
    }
}
