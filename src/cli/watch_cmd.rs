//! `azula watch` — the long-running inbox follower. Holds a [`crate::core::
//! SessionCore`] open (design.md D4: "`watch` holds the core open and
//! streams") and polls for connect/disconnect transitions plus new inbox
//! lines, classified via [`crate::core::watch::classify_inbox_line`] and
//! emitted as JSONL (`--json`) or the same human-readable lines
//! `get_messages`/`wait_for_reply` already print.

use anyhow::Result;

use crate::core::watch::WatchEvent;

#[derive(Debug, Clone, clap::Args)]
pub(super) struct WatchArgs {
    #[command(flatten)]
    device: super::DeviceArg,
    #[command(flatten)]
    session: super::SessionArg,
    /// Stream one JSON object per line instead of human-readable text.
    #[arg(long)]
    json: bool,
}

/// How often `watch` polls the device map / inboxes for changes.
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(300);

pub(super) async fn run(args: WatchArgs) -> Result<()> {
    let session_name = super::resolve_cli_session_name(args.session.session.clone());
    let est = crate::core::establish("cli", vec![], None, Some(session_name)).await?;
    let core = est.core;

    // If a specific --device was requested, it must be known up front —
    // otherwise `watch` would silently sit forever never matching anything.
    if let Some(only) = args.device.device.as_deref() {
        if let Err(e) = core.resolve_target_device(Some(only)).await {
            super::exit_core_error(&e);
        }
    }

    let mut last_connected: std::collections::HashMap<String, bool> = std::collections::HashMap::new();
    eprintln!("watching for inbound activity — Ctrl-C to stop");

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            _ = tokio::time::sleep(POLL_INTERVAL) => {}
        }

        for d in core.list_devices().await {
            if let Some(only) = args.device.device.as_deref() {
                if d.name != only {
                    continue;
                }
            }
            let connected = matches!(d.status, crate::core::DeviceLiveStatus::Connected);
            if last_connected.insert(d.name.clone(), connected) != Some(connected) {
                let event = if connected {
                    WatchEvent::Connected { device: d.name.clone() }
                } else {
                    WatchEvent::Disconnected { device: d.name.clone() }
                };
                emit(&event, args.json);
            }
        }

        // The only failure `get_messages` can return is "unknown device",
        // and that was already validated above — a live failure here (e.g.
        // the device was `disconnect --forget`-ed mid-watch) shouldn't kill
        // a long-running watcher.
        if let Ok(lines) = core.get_messages(args.device.device.as_deref()).await {
            for line in lines {
                emit(&crate::core::watch::classify_inbox_line(&line.device, &line.text), args.json);
            }
        }
    }
}

fn emit(event: &WatchEvent, json: bool) {
    if json {
        match serde_json::to_string(event) {
            Ok(line) => println!("{line}"),
            Err(e) => eprintln!("error: failed to serialize watch event: {e}"),
        }
    } else {
        println!("{}", event.human_line());
    }
}
