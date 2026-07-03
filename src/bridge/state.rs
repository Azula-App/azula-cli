//! Runtime state file — a snapshot of the bridge's device connections written
//! to `$TMPDIR/azula/bridge.json` on every connection change, so external
//! tooling (or a developer with `cat`) can see live bind address / pid /
//! per-device connected status without going through an MCP client.

use serde::{Deserialize, Serialize};

use super::device::DeviceMap;

#[derive(Serialize, Deserialize)]
struct DeviceStatus {
    name: String,
    connected: bool,
}

#[derive(Serialize, Deserialize)]
struct BridgeState {
    bind: String,
    pid: u32,
    devices: Vec<DeviceStatus>,
}

fn state_path() -> std::path::PathBuf {
    std::env::temp_dir().join("azula").join("bridge.json")
}

pub(super) async fn write_state(bind: &str, devices: &DeviceMap) {
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
