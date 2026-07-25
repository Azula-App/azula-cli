//! `azula status`'s report: machine identity, known devices (registry ∪ the
//! last-seen runtime state snapshot), and local sessions — computed purely
//! from disk, binding no endpoint (cli-surface spec: "`status --json`...
//! read the runtime state files ($TMPDIR/azula/bridge.json, sessions dir) +
//! registry; do not bind an endpoint").

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct MachineIdentityStatus {
    pub present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceStatusEntry {
    pub name: String,
    pub connected: bool,
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionStatusEntry {
    pub name: String,
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusReport {
    pub machine_identity: MachineIdentityStatus,
    pub devices: Vec<DeviceStatusEntry>,
    pub sessions: Vec<SessionStatusEntry>,
}

/// Compute the report. Reads: the machine identity key (read-only — never
/// creates one, same contract as every other session-establishment-adjacent
/// caller of `identity::load_machine_secret_if_exists`), the merged device
/// registry, the runtime state file (if any bridge/session process has
/// written one), and the sessions directory (named + ephemeral).
pub fn compute() -> StatusReport {
    let machine_identity = match crate::identity::load_machine_secret_if_exists() {
        Some(secret) => MachineIdentityStatus {
            present: true,
            node_id: Some(data_encoding::HEXLOWER.encode(secret.public().as_bytes())),
        },
        None => MachineIdentityStatus { present: false, node_id: None },
    };

    StatusReport { machine_identity, devices: device_statuses(), sessions: session_statuses() }
}

fn device_statuses() -> Vec<DeviceStatusEntry> {
    let project_names: Vec<String> = crate::registry::project_path()
        .map(|p| crate::registry::read_file(&p).into_iter().map(|d| d.name).collect())
        .unwrap_or_default();
    let global_names: Vec<String> = crate::registry::global_path()
        .map(|p| crate::registry::read_file(&p).into_iter().map(|d| d.name).collect())
        .unwrap_or_default();

    let known = crate::registry::load();
    let state = super::state::read_state();

    let mut names: Vec<String> = known.iter().map(|d| d.name.clone()).collect();
    if let Some(state) = &state {
        for d in &state.devices {
            if !names.contains(&d.name) {
                names.push(d.name.clone());
            }
        }
    }
    names.sort();

    names
        .into_iter()
        .map(|name| {
            let source = if project_names.contains(&name) {
                "project"
            } else if global_names.contains(&name) {
                "global"
            } else {
                "runtime"
            }
            .to_string();
            let connected = state
                .as_ref()
                .and_then(|s| s.devices.iter().find(|d| d.name == name))
                .map(|d| d.connected)
                .unwrap_or(false);
            DeviceStatusEntry { name, connected, source }
        })
        .collect()
}

fn session_statuses() -> Vec<SessionStatusEntry> {
    let mut sessions = Vec::new();

    if let Ok(dir) = crate::session::sessions_dir() {
        collect_key_files(&dir, "named", &mut sessions);
    }
    // Ephemeral session keys are not test-isolated by an env override (see
    // `session::SessionKey::ephemeral`'s doc) — always the real temp dir.
    let ephemeral_dir = std::env::temp_dir().join("azula").join("sessions");
    collect_key_files(&ephemeral_dir, "ephemeral", &mut sessions);

    sessions.sort_by(|a, b| a.name.cmp(&b.name));
    sessions
}

fn collect_key_files(dir: &std::path::Path, mode: &str, out: &mut Vec<SessionStatusEntry>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        if let Some(name) = key_file_stem(&entry.path()) {
            out.push(SessionStatusEntry { name, mode: mode.to_string(), pid: None });
        }
    }
}

fn key_file_stem(path: &std::path::Path) -> Option<String> {
    if path.extension().and_then(|e| e.to_str()) != Some("key") {
        return None;
    }
    path.file_stem().and_then(|s| s.to_str()).map(|s| s.to_string())
}

/// Render the report as the human-readable `azula status` text (no `--json`).
pub fn render_human(report: &StatusReport) -> String {
    let mut out = String::new();

    match &report.machine_identity {
        MachineIdentityStatus { present: true, node_id: Some(id) } => {
            let short = &id[..8.min(id.len())];
            out.push_str(&format!("Machine identity: present (node {short}…)\n"));
        }
        _ => out.push_str("Machine identity: none (headless — sessions self-certify)\n"),
    }
    out.push('\n');

    if report.devices.is_empty() {
        out.push_str("No devices registered. Use `azula pair <URL>` to add one.\n");
    } else {
        out.push_str(&format!("{:<20} {:<12} SOURCE\n", "DEVICE", "STATUS"));
        for d in &report.devices {
            let status = if d.connected { "connected" } else { "disconnected" };
            out.push_str(&format!("{:<20} {:<12} {}\n", d.name, status, d.source));
        }
    }
    out.push('\n');

    if report.sessions.is_empty() {
        out.push_str("No local sessions.\n");
    } else {
        out.push_str(&format!("{:<20} MODE\n", "SESSION"));
        for s in &report.sessions {
            out.push_str(&format!("{:<20} {}\n", s.name, s.mode));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn compute_against_seeded_temp_state_reports_devices_and_sessions() {
        // These tests mutate `AZULA_KEY_DIR`/`AZULA_REGISTRY_DIR`/
        // `AZULA_SESSIONS_DIR`/`AZULA_STATE_DIR`, all of which other
        // modules' tests (registry/identity/session/core::state) also
        // mutate under `cargo test`'s default parallelism — share the
        // crate-wide lock rather than a module-local one.
        let _guard = crate::registry::ENV_TEST_LOCK.lock().await;
        let root = std::env::temp_dir().join(format!("azula-status-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);

        let registry_dir = root.join("registry");
        let sessions_dir = root.join("sessions");
        let state_dir = root.join("state");
        let key_dir = root.join("keys");
        std::fs::create_dir_all(&sessions_dir).unwrap();
        std::fs::create_dir_all(&state_dir).unwrap();

        std::env::set_var("AZULA_REGISTRY_DIR", &registry_dir);
        std::env::set_var("AZULA_SESSIONS_DIR", &sessions_dir);
        std::env::set_var("AZULA_STATE_DIR", &state_dir);
        std::env::set_var("AZULA_KEY_DIR", &key_dir);

        // Seed a registered device (project registry, since AZULA_REGISTRY_DIR
        // makes both project/global resolve under the same override dir with
        // distinct filenames — see registry::override_dir).
        crate::registry::add(
            crate::registry::Device { name: "phone".into(), ticket: "tk".into(), added_at: None, invite: None },
            false,
        )
        .expect("seed device");

        // Seed a runtime state file reporting that device as connected.
        std::fs::write(
            state_dir.join("bridge.json"),
            serde_json::json!({"bind": "stdio", "pid": 123, "devices": [{"name": "phone", "connected": true}]}).to_string(),
        )
        .unwrap();

        // Seed a named session key file.
        std::fs::write(sessions_dir.join("cli.key"), [0u8; 32]).unwrap();

        // No machine.key/bridge.key seeded — headless case.
        let report = compute();
        assert!(!report.machine_identity.present);
        assert!(report.machine_identity.node_id.is_none());

        assert_eq!(report.devices.len(), 1);
        assert_eq!(report.devices[0].name, "phone");
        assert!(report.devices[0].connected);
        assert_eq!(report.devices[0].source, "project");

        assert!(report.sessions.iter().any(|s| s.name == "cli" && s.mode == "named"));

        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains(r#""machine_identity":{"present":false}"#), "{json}");
        assert!(json.contains(r#""devices":[{"name":"phone","connected":true,"source":"project"}]"#), "{json}");

        std::env::remove_var("AZULA_REGISTRY_DIR");
        std::env::remove_var("AZULA_SESSIONS_DIR");
        std::env::remove_var("AZULA_STATE_DIR");
        std::env::remove_var("AZULA_KEY_DIR");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn compute_reports_present_machine_identity_with_hex_node_id() {
        let _guard = crate::registry::ENV_TEST_LOCK.lock().await;
        let root = std::env::temp_dir().join(format!("azula-status-machine-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        std::env::set_var("AZULA_REGISTRY_DIR", root.join("registry"));
        std::env::set_var("AZULA_SESSIONS_DIR", root.join("sessions"));
        std::env::set_var("AZULA_STATE_DIR", root.join("state"));
        std::env::set_var("AZULA_KEY_DIR", root.join("keys"));

        let secret = crate::identity::load_or_create_machine_secret();
        let expected_hex = data_encoding::HEXLOWER.encode(secret.public().as_bytes());

        let report = compute();
        assert!(report.machine_identity.present);
        assert_eq!(report.machine_identity.node_id.as_deref(), Some(expected_hex.as_str()));

        std::env::remove_var("AZULA_REGISTRY_DIR");
        std::env::remove_var("AZULA_SESSIONS_DIR");
        std::env::remove_var("AZULA_STATE_DIR");
        std::env::remove_var("AZULA_KEY_DIR");
        let _ = std::fs::remove_dir_all(&root);
    }
}
