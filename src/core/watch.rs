//! `azula watch`'s event model: the JSONL contract for `--json` output
//! (cli-surface spec, "JSON Output Contracts") and the pure classifier that
//! turns a raw inbox line (as [`super::device`]'s reader loop already
//! produces — plain chat text, a `ui-event: {...}` line, or a
//! `[received file: ...]` line) into one of these typed events.
//!
//! Kept side-effect-free and unit-testable on its own — the live polling
//! loop (`cli::watch_cmd`) is a thin driver on top of this plus
//! [`super::SessionCore::get_messages`] and a connected/disconnected diff
//! over the device map.

use serde::Serialize;

/// One `azula watch --json` event: internally tagged on `"type"`, matching
/// the cli-surface spec's `{"type":"message"|"ui_event"|"file"|"connected"|
/// "disconnected","device":...,...}` shape. `ui_event` carries the A2UI
/// event payload verbatim under `"event"`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type")]
pub enum WatchEvent {
    #[serde(rename = "message")]
    Message { device: String, text: String },
    #[serde(rename = "ui_event")]
    UiEvent { device: String, event: serde_json::Value },
    #[serde(rename = "file")]
    File {
        device: String,
        name: String,
        mime: String,
        size: u64,
        path: String,
        /// The sender's caption, when the transfer carried one. Skipped
        /// entirely when absent, so the documented event shape for an
        /// uncaptioned file is byte-identical to before.
        #[serde(skip_serializing_if = "Option::is_none")]
        caption: Option<String>,
    },
    #[serde(rename = "connected")]
    Connected { device: String },
    #[serde(rename = "disconnected")]
    Disconnected { device: String },
}

impl WatchEvent {
    /// The device this event is about, regardless of variant.
    pub fn device(&self) -> &str {
        match self {
            WatchEvent::Message { device, .. }
            | WatchEvent::UiEvent { device, .. }
            | WatchEvent::File { device, .. }
            | WatchEvent::Connected { device }
            | WatchEvent::Disconnected { device } => device,
        }
    }

    /// The non-JSON human-readable line `azula watch` (without `--json`)
    /// prints — matches the wording `get_messages`/`wait_for_reply` already
    /// use for these same raw inbox lines, plus the two new connect/disconnect
    /// lines this streaming verb adds.
    pub fn human_line(&self) -> String {
        match self {
            WatchEvent::Message { device, text } => format!("\u{300a}{device}\u{300b} {text}"),
            WatchEvent::UiEvent { device, event } => {
                format!("\u{300a}{device}\u{300b} ui-event: {}", serde_json::to_string(event).unwrap_or_default())
            }
            WatchEvent::File { device, name, mime, size, path, caption } => {
                let mut line =
                    format!("\u{300a}{device}\u{300b} [received file: {name} ({mime}, {size} bytes) -> {path}]");
                if let Some(caption) = caption {
                    line.push_str(&format!(" caption: {caption}"));
                }
                line
            }
            WatchEvent::Connected { device } => format!("\u{300a}{device}\u{300b} connected"),
            WatchEvent::Disconnected { device } => format!("\u{300a}{device}\u{300b} disconnected"),
        }
    }
}

/// Classify one raw inbox line (as produced by [`super::device`]'s reader
/// loop) for `device` into a typed [`WatchEvent`]. Recognizes the two
/// special text shapes the reader emits (`ui-event: {...}` and
/// `[received file: NAME (MIME, SIZE bytes) -> PATH]`, optionally followed by
/// ` caption: ...`); anything else — including plain chat text and the
/// `[rejected file: ...]` / `[failed to save received file ...]` lines — is a
/// plain `message` event, same as today's `get_messages`/`wait_for_reply`
/// output treats them.
pub fn classify_inbox_line(device: &str, line: &str) -> WatchEvent {
    if let Some(rest) = line.strip_prefix("ui-event: ") {
        if let Ok(event) = serde_json::from_str::<serde_json::Value>(rest) {
            return WatchEvent::UiEvent { device: device.to_string(), event };
        }
    }

    if let Some(rest) = line.strip_prefix("[received file: ") {
        if let Some(parsed) = parse_received_file(rest) {
            return WatchEvent::File {
                device: device.to_string(),
                name: parsed.0,
                mime: parsed.1,
                size: parsed.2,
                path: parsed.3,
                caption: None,
            };
        }
    }

    WatchEvent::Message { device: device.to_string(), text: line.to_string() }
}

/// Parse the tail of a `[received file: NAME (MIME, SIZE bytes) -> PATH]`
/// line (everything after the `"[received file: "` prefix, so `rest` starts
/// at `NAME`), tolerating a trailing ` caption: ...` before the closing `]`.
/// Returns `(name, mime, size, path)`, or `None` if the shape doesn't match
/// (defensive — a future format change should degrade to a plain `message`
/// event, not a panic).
fn parse_received_file(rest: &str) -> Option<(String, String, u64, String)> {
    let arrow = rest.find(" -> ")?;
    let (name_and_meta, after_arrow) = rest.split_at(arrow);
    let after_arrow = &after_arrow[" -> ".len()..];

    let paren_start = name_and_meta.rfind('(')?;
    let name = name_and_meta[..paren_start].trim().to_string();
    let meta = name_and_meta[paren_start + 1..].trim_end();
    let meta = meta.strip_suffix(')')?;

    let (mime, size_part) = meta.split_once(',')?;
    let mime = mime.trim().to_string();
    let size_str = size_part.trim().strip_suffix("bytes")?.trim();
    let size: u64 = size_str.parse().ok()?;

    // `after_arrow` is `PATH]` or `PATH] caption: ...`.
    let path = after_arrow.split(']').next()?.trim().to_string();

    Some((name, mime, size, path))
}

/// One inbox entry as the reader loop actually observed it, before any
/// rendering.
///
/// The inbox used to hold pre-rendered `String`s, and `azula watch --json`
/// recovered structure by parsing them back with [`classify_inbox_line`].
/// That round-trip is lossy in a way that matters: a user who literally types
/// `ui-event: {"name":"x"}` is indistinguishable from a real A2UI tap, and a
/// file's caption is only recoverable by string-splitting. Carrying the type
/// from the reader means `get_events` — and `watch --json` with it — reports a
/// tap as a tap and that user's text as text.
///
/// [`Self::human_line`] reproduces exactly the string that used to be pushed,
/// so `get_messages`/`wait_for_reply` output is unchanged.
#[derive(Debug, Clone, PartialEq)]
pub enum InboxEntry {
    /// Chat text from the peer, verbatim.
    Message(String),
    /// An A2UI action payload from a tap on a rendered surface.
    UiEvent(serde_json::Value),
    /// A completed inbound file transfer, already written to disk.
    File { name: String, mime: String, size: u64, path: String, caption: Option<String> },
    /// A bracketed operational notice the reader emits about a transfer it
    /// could not complete (rejected for size, failed to save). Rendered and
    /// reported as ordinary message text, matching how `classify_inbox_line`
    /// has always treated these lines.
    Notice(String),
}

impl InboxEntry {
    /// The exact line this entry used to be stored as — what
    /// `get_messages`/`wait_for_reply` still print.
    pub fn human_line(&self) -> String {
        match self {
            InboxEntry::Message(text) => text.clone(),
            InboxEntry::UiEvent(action) => {
                format!("ui-event: {}", serde_json::to_string(action).unwrap_or_default())
            }
            InboxEntry::File { name, mime, size, path, caption } => {
                let mut line = format!("[received file: {name} ({mime}, {size} bytes) -> {path}]");
                if let Some(caption) = caption {
                    line.push_str(&format!(" caption: {caption}"));
                }
                line
            }
            InboxEntry::Notice(text) => text.clone(),
        }
    }

    /// Attach the source device and become the event `get_events` and
    /// `watch --json` emit.
    pub fn into_event(self, device: &str) -> WatchEvent {
        match self {
            InboxEntry::Message(text) => WatchEvent::Message { device: device.to_string(), text },
            InboxEntry::UiEvent(event) => WatchEvent::UiEvent { device: device.to_string(), event },
            InboxEntry::File { name, mime, size, path, caption } => {
                WatchEvent::File { device: device.to_string(), name, mime, size, path, caption }
            }
            // A notice is not a distinct wire event: it is text about the
            // conversation, and every existing consumer already reads it that way.
            InboxEntry::Notice(text) => WatchEvent::Message { device: device.to_string(), text },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn entry_human_line_matches_what_the_inbox_used_to_store() {
        assert_eq!(InboxEntry::Message("hey there".into()).human_line(), "hey there");

        let action = serde_json::json!({"name": "roll", "surfaceId": "dice-1"});
        assert_eq!(
            InboxEntry::UiEvent(action.clone()).human_line(),
            format!("ui-event: {}", serde_json::to_string(&action).unwrap())
        );

        let file = InboxEntry::File {
            name: "note.txt".into(),
            mime: "text/plain".into(),
            size: 16,
            path: "/tmp/azula/received/note.txt".into(),
            caption: None,
        };
        assert_eq!(
            file.human_line(),
            "[received file: note.txt (text/plain, 16 bytes) -> /tmp/azula/received/note.txt]"
        );

        let captioned = InboxEntry::File {
            name: "photo.png".into(),
            mime: "image/png".into(),
            size: 51200,
            path: "/tmp/photo.png".into(),
            caption: Some("a test image".into()),
        };
        assert_eq!(
            captioned.human_line(),
            "[received file: photo.png (image/png, 51200 bytes) -> /tmp/photo.png] caption: a test image"
        );
    }

    /// The reason the inbox carries structure at all: re-parsing a rendered
    /// line cannot tell a real tap from a user typing the same characters.
    #[test]
    fn typed_entry_distinguishes_a_tap_from_text_that_looks_like_one() {
        let spoof = r#"ui-event: {"name":"roll","surfaceId":"dice-1"}"#;

        // What the old round-trip did: the user's literal text becomes a tap.
        assert!(matches!(classify_inbox_line("phone", spoof), WatchEvent::UiEvent { .. }));

        // What the typed entry does: text stays text...
        let as_text = InboxEntry::Message(spoof.to_string()).into_event("phone");
        assert_eq!(as_text, WatchEvent::Message { device: "phone".into(), text: spoof.to_string() });

        // ...and a real tap is still a tap, payload intact.
        let real = InboxEntry::UiEvent(serde_json::json!({"name": "roll"})).into_event("phone");
        match real {
            WatchEvent::UiEvent { device, event } => {
                assert_eq!(device, "phone");
                assert_eq!(event["name"], "roll");
            }
            other => panic!("expected UiEvent, got {other:?}"),
        }
    }

    #[test]
    fn a_notice_reports_as_message_text() {
        let line = "[rejected file: huge.bin (99999999 bytes) exceeds the 67108864 byte (64 MiB) limit]";
        assert_eq!(
            InboxEntry::Notice(line.into()).into_event("phone"),
            WatchEvent::Message { device: "phone".into(), text: line.into() }
        );
    }

    #[test]
    fn uncaptioned_file_event_shape_is_unchanged_and_caption_is_additive() {
        let plain = InboxEntry::File {
            name: "a.png".into(),
            mime: "image/png".into(),
            size: 10,
            path: "/tmp/a.png".into(),
            caption: None,
        }
        .into_event("phone");
        assert_eq!(
            serde_json::to_string(&plain).unwrap(),
            r#"{"type":"file","device":"phone","name":"a.png","mime":"image/png","size":10,"path":"/tmp/a.png"}"#
        );

        let captioned = InboxEntry::File {
            name: "a.png".into(),
            mime: "image/png".into(),
            size: 10,
            path: "/tmp/a.png".into(),
            caption: Some("hi".into()),
        }
        .into_event("phone");
        assert!(serde_json::to_string(&captioned).unwrap().contains(r#""caption":"hi""#));
    }

    #[test]
    fn plain_chat_text_is_a_message_event() {
        let event = classify_inbox_line("phone", "hey there");
        assert_eq!(event, WatchEvent::Message { device: "phone".into(), text: "hey there".into() });
    }

    #[test]
    fn ui_event_line_parses_payload_verbatim() {
        let line = r#"ui-event: {"name":"roll","surfaceId":"dice-1","sourceComponentId":"rollBtn","context":{}}"#;
        let event = classify_inbox_line("phone", line);
        match &event {
            WatchEvent::UiEvent { device, event } => {
                assert_eq!(device, "phone");
                assert_eq!(event["name"], "roll");
                assert_eq!(event["surfaceId"], "dice-1");
            }
            other => panic!("expected UiEvent, got {other:?}"),
        }
    }

    #[test]
    fn received_file_line_parses_name_mime_size_path() {
        let line = "[received file: note.txt (text/plain, 16 bytes) -> /tmp/azula/received/note.txt]";
        let event = classify_inbox_line("phone", line);
        assert_eq!(
            event,
            WatchEvent::File {
                device: "phone".into(),
                name: "note.txt".into(),
                mime: "text/plain".into(),
                size: 16,
                path: "/tmp/azula/received/note.txt".into(),
                caption: None,
            }
        );
    }

    #[test]
    fn received_file_line_with_caption_still_parses() {
        let line = "[received file: photo.png (image/png, 51200 bytes) -> /tmp/photo.png] caption: a test image";
        let event = classify_inbox_line("phone", line);
        assert_eq!(
            event,
            WatchEvent::File {
                device: "phone".into(),
                name: "photo.png".into(),
                mime: "image/png".into(),
                size: 51200,
                path: "/tmp/photo.png".into(),
                caption: None,
            }
        );
    }

    #[test]
    fn rejected_file_line_falls_back_to_message() {
        let line = "[rejected file: huge.bin (99999999 bytes) exceeds the 67108864 byte (64 MiB) limit]";
        let event = classify_inbox_line("phone", line);
        assert_eq!(event, WatchEvent::Message { device: "phone".into(), text: line.into() });
    }

    #[test]
    fn watch_event_serializes_with_type_tag() {
        let event = WatchEvent::Connected { device: "phone".into() };
        let json = serde_json::to_string(&event).unwrap();
        assert_eq!(json, r#"{"type":"connected","device":"phone"}"#);

        let event = WatchEvent::Message { device: "phone".into(), text: "hi".into() };
        let json = serde_json::to_string(&event).unwrap();
        assert_eq!(json, r#"{"type":"message","device":"phone","text":"hi"}"#);

        let event = WatchEvent::File {
            device: "phone".into(),
            name: "a.png".into(),
            mime: "image/png".into(),
            size: 10,
            path: "/tmp/a.png".into(),
            caption: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert_eq!(
            json,
            r#"{"type":"file","device":"phone","name":"a.png","mime":"image/png","size":10,"path":"/tmp/a.png"}"#
        );
    }

    #[test]
    fn watch_event_device_accessor_covers_every_variant() {
        assert_eq!(WatchEvent::Connected { device: "d".into() }.device(), "d");
        assert_eq!(WatchEvent::Disconnected { device: "d".into() }.device(), "d");
        assert_eq!(WatchEvent::Message { device: "d".into(), text: "x".into() }.device(), "d");
    }
}
