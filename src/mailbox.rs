//! Per-device persistent mailbox: store-and-forward queue for offline devices.
//!
//! Messages for offline devices are held in a JSONL file on disk and flushed
//! when the device reconnects.

use std::path::{Path, PathBuf};
use crate::proto::Frame;

const MAX_FRAMES: usize = 1000;

/// Returns the mailbox directory, in order of preference:
/// 1. `AZULA_MAILBOX_DIR` env var (for tests / overrides)
/// 2. Parent of global registry path + "mailbox"
/// 3. `std::env::temp_dir()/azula/mailbox`
pub fn mailbox_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("AZULA_MAILBOX_DIR") {
        return PathBuf::from(dir);
    }
    if let Some(global) = crate::registry::global_path() {
        if let Some(parent) = global.parent() {
            return parent.join("mailbox");
        }
    }
    std::env::temp_dir().join("azula").join("mailbox")
}

/// Sanitize a device name to a filesystem-safe filename component.
/// Non-alphanumeric chars become '_'.
fn sanitize(device: &str) -> String {
    device.chars().map(|c| if c.is_alphanumeric() { c } else { '_' }).collect()
}

fn device_path(dir: &Path, device: &str) -> PathBuf {
    dir.join(format!("{}.jsonl", sanitize(device)))
}

/// Append `frames` to the device's mailbox file in `dir`.
/// If the total would exceed MAX_FRAMES, keeps only the newest MAX_FRAMES.
pub fn enqueue_in(dir: &Path, device: &str, frames: &[Frame]) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = device_path(dir, device);

    // Load existing frames to check the cap.
    let existing = load_in(dir, device);
    let combined_count = existing.len() + frames.len();

    if combined_count > MAX_FRAMES {
        // Rewrite keeping only the newest MAX_FRAMES total.
        let all: Vec<Frame> = existing.into_iter().chain(frames.iter().cloned()).collect();
        let keep = &all[all.len() - MAX_FRAMES..];
        let mut content = String::new();
        for f in keep {
            content.push_str(&serde_json::to_string(f)?);
            content.push('\n');
        }
        std::fs::write(&path, content)?;
    } else {
        // Fast path: just append.
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        for f in frames {
            file.write_all(serde_json::to_string(f)?.as_bytes())?;
            file.write_all(b"\n")?;
        }
    }
    Ok(())
}

/// Enqueue frames using the default mailbox directory.
pub fn enqueue(device: &str, frames: &[Frame]) {
    if let Err(e) = enqueue_in(&mailbox_dir(), device, frames) {
        tracing::warn!(device=%device, error=%e, "mailbox: enqueue failed");
    }
}

/// Load all queued frames for a device from `dir`.
/// Skips malformed lines. Returns [] if no file.
pub fn load_in(dir: &Path, device: &str) -> Vec<Frame> {
    let path = device_path(dir, device);
    let data = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    data.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<Frame>(l).ok())
        .collect()
}

/// Load all queued frames using the default mailbox directory.
pub fn load(device: &str) -> Vec<Frame> {
    load_in(&mailbox_dir(), device)
}

/// Remove the mailbox file for a device in `dir`.
pub fn clear_in(dir: &Path, device: &str) {
    let path = device_path(dir, device);
    let _ = std::fs::remove_file(&path);
}

/// Remove the mailbox file for a device using the default directory.
pub fn clear(device: &str) {
    clear_in(&mailbox_dir(), device);
}

/// Returns true if the device has a non-empty mailbox file.
pub fn has_pending(device: &str) -> bool {
    let path = device_path(&mailbox_dir(), device);
    path.exists() && path.metadata().map(|m| m.len() > 0).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::Frame;

    fn test_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("azula-mbox-test-{}", std::process::id())).join(name)
    }

    #[test]
    fn round_trip() {
        let dir = test_dir("round_trip");
        let frames = vec![
            Frame::token("hello"),
            Frame::token_done(),
            Frame::thinking(false),
        ];
        enqueue_in(&dir, "phone", &frames).unwrap();
        let loaded = load_in(&dir, "phone");
        assert_eq!(loaded.len(), 3);
        // Check order: first should be token "hello"
        assert!(matches!(&loaded[0], Frame::Token { delta, done: false } if delta == "hello"));
        assert!(matches!(&loaded[1], Frame::Token { done: true, .. }));
        assert!(matches!(&loaded[2], Frame::Thinking { on: false }));
    }

    #[test]
    fn clear_empties() {
        let dir = test_dir("clear_empties");
        enqueue_in(&dir, "phone", &[Frame::token("hi")]).unwrap();
        assert!(!load_in(&dir, "phone").is_empty());
        clear_in(&dir, "phone");
        assert!(load_in(&dir, "phone").is_empty());
    }

    #[test]
    fn persistence_across_fresh_load() {
        let dir = test_dir("persistence");
        let frames = vec![Frame::Chat { text: "stored".into() }];
        enqueue_in(&dir, "dev1", &frames).unwrap();
        // Simulate a fresh load by calling load_in again from the same dir.
        let loaded = load_in(&dir, "dev1");
        assert_eq!(loaded.len(), 1);
        assert!(matches!(&loaded[0], Frame::Chat { text } if text == "stored"));
    }

    #[test]
    fn cap_trims_oldest() {
        let dir = test_dir("cap_trims");
        // Enqueue MAX_FRAMES frames first.
        let initial: Vec<Frame> = (0..MAX_FRAMES).map(|i| Frame::token(format!("msg-{i}"))).collect();
        enqueue_in(&dir, "dev2", &initial).unwrap();
        // Enqueue 5 more — should trim oldest.
        let extra: Vec<Frame> = (0..5).map(|i| Frame::token(format!("extra-{i}"))).collect();
        enqueue_in(&dir, "dev2", &extra).unwrap();
        let loaded = load_in(&dir, "dev2");
        assert_eq!(loaded.len(), MAX_FRAMES, "should cap at MAX_FRAMES");
        // Last 5 should be the extra frames.
        for (i, frame) in loaded[MAX_FRAMES - 5..].iter().enumerate() {
            assert!(matches!(frame, Frame::Token { delta, .. } if delta == &format!("extra-{i}")));
        }
        // First frame should be msg-5 (oldest surviving after trim).
        assert!(matches!(&loaded[0], Frame::Token { delta, .. } if delta == "msg-5"));
    }
}
