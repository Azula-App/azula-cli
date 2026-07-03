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

    /// peer -> peer: metadata for a streamed media attachment (image/audio/video/
    /// file). The body is NOT sent inline — the receiver pulls it on demand over
    /// the `azula/media/0` ALPN by dialing `fetch_ticket`, the sender's own
    /// ticket at offer time. `thumb_b64` is a small (<=32 KiB) preview. azula-cli
    /// never accepts the CHAT ALPN, so it never needs to construct or act on
    /// this frame — it exists here only so an unrecognized-but-tagged frame like
    /// this one deserializes cleanly instead of erroring out a stream.
    #[serde(rename = "media_offer")]
    MediaOffer {
        id: String,
        kind: String,
        name: String,
        mime: String,
        size: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        caption: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        width: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        height: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none", rename = "durationMs")]
        duration_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none", rename = "thumbB64")]
        thumb_b64: Option<String>,
        #[serde(rename = "fetchTicket")]
        fetch_ticket: String,
    },

    /// Any frame type this build doesn't recognize. Forward-compatibility
    /// fallback: an unrecognized "type" tag deserializes into this variant
    /// instead of failing the whole read, so a stream isn't torn down just
    /// because the app added a new frame kind the server doesn't know about
    /// yet. Never constructed for sending.
    #[serde(other)]
    Unknown,
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
    fn media_offer_roundtrips_with_type_tag() {
        let f = Frame::MediaOffer {
            id: "m1".into(),
            kind: "image".into(),
            name: "photo.png".into(),
            mime: "image/png".into(),
            size: 51200,
            caption: Some("look at this".into()),
            width: Some(800),
            height: Some(600),
            duration_ms: None,
            thumb_b64: Some("Zm9v".into()),
            fetch_ticket: "ticket-abc".into(),
        };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains(r#""type":"media_offer""#), "wrong type tag: {json}");
        assert!(json.contains(r#""kind":"image""#), "missing kind: {json}");
        assert!(json.contains(r#""size":51200"#), "missing size: {json}");
        assert!(json.contains(r#""width":800"#), "missing width: {json}");
        assert!(json.contains(r#""height":600"#), "missing height: {json}");
        assert!(json.contains(r#""thumbB64":"Zm9v""#), "missing thumbB64: {json}");
        assert!(json.contains(r#""fetchTicket":"ticket-abc""#), "missing fetchTicket: {json}");
        // duration_ms is None — should be absent (skip_serializing_if).
        assert!(!json.contains("durationMs"), "durationMs should be absent: {json}");

        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            &back,
            Frame::MediaOffer { fetch_ticket, .. } if fetch_ticket == "ticket-abc"
        ));
    }

    #[test]
    fn media_offer_with_duration_roundtrips() {
        let f = Frame::MediaOffer {
            id: "m2".into(),
            kind: "video".into(),
            name: "clip.mp4".into(),
            mime: "video/mp4".into(),
            size: 1_048_576,
            caption: None,
            width: None,
            height: None,
            duration_ms: Some(5000),
            thumb_b64: None,
            fetch_ticket: "ticket-xyz".into(),
        };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains(r#""durationMs":5000"#), "missing durationMs: {json}");
        assert!(!json.contains("caption"), "caption should be absent: {json}");
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Frame::MediaOffer { duration_ms: Some(5000), .. }));
    }

    #[test]
    fn media_offer_from_kotlin_with_explicit_null_optionals_decodes() {
        // kotlinx.serialization's FrameCodec uses encodeDefaults = true, so unlike
        // this side's `skip_serializing_if`, the Kotlin sender emits explicit
        // `"field":null` for unset optionals rather than omitting them. serde's
        // `Option<T>` already accepts a JSON null as None regardless of the
        // `default` attribute, but pin that interop down with a literal line as
        // actually produced by FrameCodec.encode(Frame.MediaOffer(...)).
        let json = r#"{"type":"media_offer","id":"att-1","kind":"image","name":"photo.png","mime":"image/png","size":51200,"caption":"look at this","width":800,"height":600,"durationMs":null,"thumbB64":"Zm9v","fetchTicket":"ticket-abc"}"#;
        let back: Frame = serde_json::from_str(json).unwrap();
        match back {
            Frame::MediaOffer {
                id,
                kind,
                width,
                height,
                duration_ms,
                thumb_b64,
                fetch_ticket,
                ..
            } => {
                assert_eq!(id, "att-1");
                assert_eq!(kind, "image");
                assert_eq!(width, Some(800));
                assert_eq!(height, Some(600));
                assert_eq!(duration_ms, None);
                assert_eq!(thumb_b64.as_deref(), Some("Zm9v"));
                assert_eq!(fetch_ticket, "ticket-abc");
            }
            other => panic!("expected MediaOffer, got {other:?}"),
        }
    }

    #[test]
    fn unknown_type_tag_decodes_to_unknown_variant() {
        let json = r#"{"type":"totally_new_frame","foo":"bar"}"#;
        let f: Frame = serde_json::from_str(json).unwrap();
        assert!(matches!(f, Frame::Unknown));
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
