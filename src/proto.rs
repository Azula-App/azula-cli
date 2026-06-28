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
    /// client -> server (LLM prompt) and peer chat
    #[serde(rename = "chat")]
    Chat { text: String },

    /// client -> server (terminal keystrokes / command)
    #[serde(rename = "input")]
    Input { text: String },

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

    /// passthrough; server may ignore
    #[serde(rename = "widget")]
    Widget { widget: serde_json::Value },
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
}
