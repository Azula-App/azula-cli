//! Wire protocol shared with the azula app clients.
//!
//! The wire format is newline-delimited JSON: each line is exactly one
//! [`Frame`] object serialized with serde_json, terminated by `'\n'`. The
//! `Frame` enum is internally tagged on a `"type"` field, which matches
//! kotlinx.serialization's default `classDiscriminator = "type"` for a sealed
//! class whose variants carry `@SerialName` annotations.
//!
//! Framing helpers ([`read_frame`] / [`write_frame`]) operate over any async
//! reader/writer. iroh's `RecvStream`/`SendStream` implement the tokio
//! `AsyncRead`/`AsyncWrite` traits, so they can be used directly.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt};

/// A single protocol frame. Internally tagged on `"type"` to match the Kotlin
/// client's sealed `Frame` class.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Frame {
    /// peer -> peer: the sender's display name, sent as the very first frame on
    /// a new outbound connection so the remote bridge can label the device.
    #[serde(rename = "hello")]
    Hello { name: String },

    /// client -> server (LLM prompt) and peer chat
    #[serde(rename = "chat")]
    Chat { text: String },

    /// client -> server (terminal keystrokes / command)
    #[serde(rename = "input")]
    Input { text: String },

    /// client -> server: the terminal's size in character cells, so the PTY
    /// wraps output to match the app's viewport.
    #[serde(rename = "resize")]
    Resize { cols: u16, rows: u16 },

    /// server -> client (LLM token stream)
    #[serde(rename = "token")]
    Token {
        delta: String,
        #[serde(default)]
        done: bool,
    },

    /// server -> client (thinking indicator)
    #[serde(rename = "thinking")]
    Thinking { on: bool },

    /// server -> client (shell output chunk)
    #[serde(rename = "term")]
    Term { line: String },

    /// server -> client: an A2UI message (create/update/delete surface)
    #[serde(rename = "a2ui")]
    A2ui { message: serde_json::Value },

    /// client -> server: a user action on an A2UI surface
    #[serde(rename = "a2ui_action")]
    A2uiAction { action: serde_json::Value },

    /// file transfer: begins a multipart transfer (encoding: "base64" | "binary")
    #[serde(rename = "file_begin")]
    FileBegin {
        id: String,
        name: String,
        mime: String,
        size: u64,
        encoding: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        caption: Option<String>,
    },

    /// file transfer: one base64-encoded chunk (used when encoding == "base64")
    #[serde(rename = "file_chunk")]
    FileChunk { id: String, seq: u32, data: String },

    /// file transfer: signals that all body bytes / chunks have been sent
    #[serde(rename = "file_end")]
    FileEnd { id: String },

    /// peer -> peer: the sender's chosen profile (a "persona"). Sent over the
    /// CHAT ALPN only; the app uses it to name the conversation and show an
    /// avatar. Servers ignore it. All fields but `name` are optional so the
    /// sender can share a subset; an empty `name` means "name not shared".
    #[serde(rename = "profile")]
    Profile {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        /// base64-encoded, downscaled avatar image bytes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        avatar: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mime: Option<String>,
    },
}

impl Frame {
    pub fn token(delta: impl Into<String>) -> Frame {
        Frame::Token {
            delta: delta.into(),
            done: false,
        }
    }

    pub fn token_done() -> Frame {
        Frame::Token {
            delta: String::new(),
            done: true,
        }
    }

    pub fn thinking(on: bool) -> Frame {
        Frame::Thinking { on }
    }

    pub fn term(line: impl Into<String>) -> Frame {
        Frame::Term { line: line.into() }
    }
}

/// Serialize `frame` as a single newline-terminated JSON line and write it to
/// `writer`, flushing afterwards.
pub async fn write_frame<W>(writer: &mut W, frame: &Frame) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let mut line = serde_json::to_string(frame)?;
    line.push('\n');
    writer.write_all(line.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

/// Read a single newline-delimited [`Frame`] from a buffered reader.
///
/// Returns `Ok(None)` on a clean end-of-stream (no more bytes). Blank lines are
/// skipped. A malformed JSON line yields an `Err`.
pub async fn read_frame<R>(reader: &mut tokio::io::BufReader<R>) -> Result<Option<Frame>>
where
    R: AsyncRead + Unpin,
{
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            // Clean EOF.
            return Ok(None);
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            // Skip blank keepalive lines.
            continue;
        }
        let frame: Frame = serde_json::from_str(trimmed)?;
        return Ok(Some(frame));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_frame_roundtrips_with_type_tag() {
        let f = Frame::Hello { name: "alice".into() };
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(json, r#"{"type":"hello","name":"alice"}"#);
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Frame::Hello { name } if name == "alice"));
    }

    #[test]
    fn chat_frame_roundtrips_with_type_tag() {
        let f = Frame::Chat {
            text: "hello".into(),
        };
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(json, r#"{"type":"chat","text":"hello"}"#);
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Frame::Chat { text } if text == "hello"));
    }

    #[test]
    fn token_done_default_is_false() {
        let json = r#"{"type":"token","delta":"hi"}"#;
        let f: Frame = serde_json::from_str(json).unwrap();
        assert!(matches!(f, Frame::Token { done: false, .. }));
    }

    #[test]
    fn file_begin_roundtrips_with_type_tag() {
        let f = Frame::FileBegin {
            id: "abc-123".into(),
            name: "photo.png".into(),
            mime: "image/png".into(),
            size: 51200,
            encoding: "base64".into(),
            caption: None,
        };
        let json = serde_json::to_string(&f).unwrap();
        // Must have the correct "type" tag to interop with Kotlin's @SerialName("file_begin").
        assert!(json.contains(r#""type":"file_begin""#), "wrong type tag: {json}");
        assert!(json.contains(r#""name":"photo.png""#), "missing name: {json}");
        assert!(json.contains(r#""size":51200"#), "missing size: {json}");
        assert!(json.contains(r#""encoding":"base64""#), "missing encoding: {json}");
        // caption is None — should be absent (skip_serializing_if).
        assert!(!json.contains("caption"), "caption should be absent: {json}");
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Frame::FileBegin { size: 51200, .. }));
    }

    #[test]
    fn file_begin_with_caption_roundtrips() {
        let f = Frame::FileBegin {
            id: "x1".into(),
            name: "img.jpg".into(),
            mime: "image/jpeg".into(),
            size: 1024,
            encoding: "binary".into(),
            caption: Some("look at this".into()),
        };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains(r#""caption":"look at this""#), "missing caption: {json}");
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(
            matches!(&back, Frame::FileBegin { caption: Some(c), .. } if c == "look at this")
        );
    }

    #[test]
    fn file_chunk_roundtrips_with_type_tag() {
        let f = Frame::FileChunk {
            id: "abc-123".into(),
            seq: 0,
            data: "SGVsbG8=".into(), // base64("Hello")
        };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains(r#""type":"file_chunk""#), "wrong type tag: {json}");
        assert!(json.contains(r#""seq":0"#), "missing seq: {json}");
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Frame::FileChunk { seq: 0, .. }));
    }

    #[test]
    fn file_end_roundtrips_with_type_tag() {
        let f = Frame::FileEnd { id: "abc-123".into() };
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(json, r#"{"type":"file_end","id":"abc-123"}"#);
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Frame::FileEnd { id } if id == "abc-123"));
    }

    #[test]
    fn a2ui_frame_roundtrips_with_type_tag() {
        let msg = serde_json::json!({
            "version": "v0.9.1",
            "createSurface": { "surfaceId": "dice-1" }
        });
        let f = Frame::A2ui { message: msg.clone() };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains(r#""type":"a2ui""#), "wrong type tag: {json}");
        assert!(json.contains("createSurface"), "missing payload: {json}");
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Frame::A2ui { .. }));
    }

    #[test]
    fn a2ui_action_frame_roundtrips_with_type_tag() {
        let action = serde_json::json!({
            "version": "v0.9.1",
            "action": { "name": "roll", "surfaceId": "dice-1", "sourceComponentId": "rollBtn", "context": {} }
        });
        let f = Frame::A2uiAction { action: action.clone() };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains(r#""type":"a2ui_action""#), "wrong type tag: {json}");
        assert!(json.contains("roll"), "missing action name: {json}");
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Frame::A2uiAction { .. }));
    }
}
