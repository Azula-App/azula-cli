//! Runtime state file — a snapshot of a session's device connections written
//! to `$TMPDIR/azula/bridge.json` on every connection change, so external
//! tooling (or a developer with `cat`) can see live bind address / pid /
//! per-device connected status without going through an MCP client, and so
//! `azula status --json` (`cli::status`) can report it without binding an
//! endpoint of its own.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::device::DeviceMap;

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct DeviceStatus {
    pub(crate) name: String,
    pub(crate) connected: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct BridgeState {
    pub(crate) bind: String,
    pub(crate) pid: u32,
    pub(crate) devices: Vec<DeviceStatus>,
}

/// `$TMPDIR/azula/bridge.json`, or the `AZULA_STATE_DIR` override (tests /
/// sandboxes, mirroring `registry::override_dir`) — the real path has no
/// per-process isolation today (every `azula mcp`/CLI process shares one
/// file, last writer wins), so tests that need a clean read must isolate via
/// this env var rather than relying on the shared temp path.
fn state_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("AZULA_STATE_DIR") {
        return PathBuf::from(dir);
    }
    std::env::temp_dir().join("azula")
}

fn state_path() -> PathBuf {
    state_dir().join("bridge.json")
}

pub(crate) async fn write_state(bind: &str, devices: &DeviceMap) {
    let path = state_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let guard = devices.lock().await;
    let statuses: Vec<DeviceStatus> = guard
        .iter()
        .map(|(name, conn)| DeviceStatus { name: name.clone(), connected: conn.connected })
        .collect();
    drop(guard);
    let state = BridgeState { bind: bind.to_string(), pid: std::process::id(), devices: statuses };
    if let Ok(json) = serde_json::to_string_pretty(&state) {
        let _ = std::fs::write(&path, json);
    }
}

/// Read the runtime state file, if one exists and parses. Used by
/// `azula status` — a pure filesystem read, no endpoint bound.
pub(crate) fn read_state() -> Option<BridgeState> {
    let data = std::fs::read_to_string(state_path()).ok()?;
    serde_json::from_str(&data).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::Mutex as AsyncMutex;

    #[tokio::test]
    async fn write_then_read_state_round_trips() {
        // `AZULA_STATE_DIR` is mutated by tests in this module *and*
        // `core::status`'s — share the crate-wide env-var lock (see its doc
        // comment) rather than a module-local one, or the two modules' tests
        // race on the same env var under `cargo test`'s default parallelism.
        let _guard = crate::registry::ENV_TEST_LOCK.lock().await;
        let dir = std::env::temp_dir().join(format!("azula-state-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("AZULA_STATE_DIR", &dir);

        let devices: DeviceMap = Arc::new(AsyncMutex::new(HashMap::new()));
        {
            let mut guard = devices.lock().await;
            guard.insert("phone".to_string(), super::super::device::DeviceConn::new("tk".to_string()));
        }
        {
            let guard = devices.lock().await;
            if let Some(conn) = guard.get("phone") {
                let mut c = conn.clone();
                c.connected = true;
                drop(guard);
                let mut guard = devices.lock().await;
                guard.insert("phone".to_string(), c);
            }
        }

        write_state("stdio", &devices).await;
        let state = read_state().expect("state file should be readable");
        assert_eq!(state.bind, "stdio");
        assert_eq!(state.devices.len(), 1);
        assert_eq!(state.devices[0].name, "phone");
        assert!(state.devices[0].connected);

        std::env::remove_var("AZULA_STATE_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn read_state_returns_none_when_missing() {
        let _guard = crate::registry::ENV_TEST_LOCK.lock().await;
        let dir = std::env::temp_dir().join(format!("azula-state-test-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("AZULA_STATE_DIR", &dir);

        assert!(read_state().is_none());

        std::env::remove_var("AZULA_STATE_DIR");
    }
}
