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
//!
//! A frame line is capped at [`MAX_FRAME_LINE_BYTES`]; [`read_frame`] fails a
//! longer one with [`FrameTooLong`] instead of buffering it (see
//! `azula-docs/openspec/specs/wire-protocols/design.md`, "Frame size cap").

use std::collections::BTreeMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt};

/// The longest frame line [`read_frame`] accepts, in bytes, not counting the
/// terminating `\n`. It's the same 16 MiB per-message cap irpc uses, and
/// comfortably above the largest legitimate frame: the frames with their own
/// bounds top out well under 1 MiB (a 64 KiB `term` replay chunk is at most
/// 384 KiB once JSON-escaped), and the batched ones split by
/// [`BATCH_BYTES_PER_FRAME`]. Kotlin's `LineBuffer` enforces the same number
/// (`MAX_FRAME_LINE_BYTES` in azula-app's `network-api`).
pub const MAX_FRAME_LINE_BYTES: usize = 16 * 1024 * 1024;

/// Byte budget for senders that pack a variable number of items into one
/// frame (`sync_entries`, `sync_a2ui`): a batch is closed once its items reach
/// this many bytes, so it stays far below [`MAX_FRAME_LINE_BYTES`] whatever
/// the items' sizes. Only a single item bigger than the whole budget gets a
/// frame to itself above it. See [`size_batches`].
pub const BATCH_BYTES_PER_FRAME: usize = MAX_FRAME_LINE_BYTES / 4;

/// [`read_frame`]'s error for a line longer than [`MAX_FRAME_LINE_BYTES`]. A
/// protocol error: callers end the stream on it, exactly as on any other
/// `read_frame` error, and never skip past it to the next line.
#[derive(Debug)]
pub struct FrameTooLong {
    pub limit: usize,
}

impl std::fmt::Display for FrameTooLong {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "frame line exceeds the {} byte cap", self.limit)
    }
}

impl std::error::Error for FrameTooLong {}

// ---------------------------------------------------------------------------
// Identity bundle (device-linking spec: the payload `LinkGrant` delivers)
// ---------------------------------------------------------------------------

/// A contact entry inside an [`IdentityBundle`] snapshot: pins either the
/// contact's root public key (a certified contact) or its legacy endpoint id —
/// exactly one of the two, never both — plus an optional display name.
/// Senders are responsible for setting exactly one of `root_pk`/`endpoint_id`;
/// this is not enforced at the type level, matching `certs.rs`'s convention
/// of leaving encode-side invariants to the caller.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Contact {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "rootPk")]
    pub root_pk: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "endpointId")]
    pub endpoint_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// The identity snapshot delivered inside a `LinkGrant` (device-linking
/// spec: "the grant SHALL deliver the new certificate and an identity
/// bundle: root public key, all known certificates, revocation set,
/// contacts snapshot, and a mailbox hint when one exists"). `mailbox` is the
/// connect ticket of a mailbox-role sibling, when the identity has one —
/// omitted otherwise.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct IdentityBundle {
    #[serde(rename = "rootPk")]
    pub root_pk: String,
    /// `"azd…"`-encoded device certificates (`certs::DeviceCert::encode`).
    pub certs: Vec<String>,
    /// `"azr…"`-encoded revocation statements (`certs::Revocation::encode`).
    pub revocations: Vec<String>,
    pub contacts: Vec<Contact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mailbox: Option<String>,
}

/// A single protocol frame. Internally tagged on `"type"` to match the Kotlin
/// client's sealed `Frame` class.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Frame {
    /// peer -> peer: the sender's display name, sent as the very first frame on
    /// a new outbound connection so the remote bridge can label the device.
    /// `invite` carries the full encoded invite string (`"azi…"`) when the
    /// sender is dialing in as an unrecognized stranger presenting an invite
    /// (see `invite.rs` / `azula-docs/openspec/specs/invitations/design.md`); omitted between
    /// already-known peers. Old peers omit/ignore this field — no version
    /// negotiation. `cert` is the sender's `"azd…"`-encoded device
    /// certificate, when it has one (multi-device-identity); an invalid cert
    /// is treated the same as an absent one. Additive/optional so old peers
    /// that omit it keep working (task 7.1 — wire format only, no
    /// validation/attach-on-send wiring here).
    #[serde(rename = "hello")]
    Hello {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        invite: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cert: Option<String>,
    },

    /// client -> server (LLM prompt) and peer chat. `id` is 16 random bytes
    /// as lowercase hex, used for retry deduplication (multi-device-identity,
    /// task 7.1); additive/optional so old peers that omit it keep working.
    #[serde(rename = "chat")]
    Chat {
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },

    /// client -> server (terminal keystrokes / command)
    #[serde(rename = "input")]
    Input { text: String },

    /// client -> server: the terminal's size in character cells, so the PTY
    /// wraps output to match the app's viewport.
    #[serde(rename = "resize")]
    Resize { cols: u16, rows: u16 },

    /// client -> server: attach to a persistent shell session, or (when
    /// `session` is absent/null) create a brand new persistent one. Sending
    /// this as a stream's very first frame opts into `azula serve`'s
    /// persistent-session path; a client that never sends it gets the exact
    /// pre-existing ephemeral behavior — the PTY dies with the stream and
    /// nothing is kept in the server's session registry. See
    /// `term.rs`'s module docs for the full compat story.
    #[serde(rename = "term_attach")]
    TermAttach {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session: Option<String>,
    },

    /// server -> client: acknowledges a `term_attach`. `resumed` is `true`
    /// when an existing PTY was reattached — a ring-buffer replay follows
    /// immediately as ordinary `Frame::Term` chunks, before any new live
    /// output — or `false` when a fresh persistent session was created (the
    /// requested `session` id, if any, either didn't exist or belonged to a
    /// different peer).
    #[serde(rename = "term_session")]
    TermSession {
        session: String,
        #[serde(default)]
        resumed: bool,
    },

    /// server -> client: the persistent session's shell exited. The session
    /// id is now gone from the server's registry — a later `term_attach` for
    /// it creates a fresh session instead of resuming.
    #[serde(rename = "term_exit")]
    TermExit {
        session: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<i32>,
    },

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

    // -----------------------------------------------------------------
    // Sync (`azula/sync/0`) and link (`azula/link/0`) frames — see `sync.rs`
    // and `azula-docs/openspec/changes/multi-device-identity/specs/
    // {account-sync,device-linking}/spec.md`. These JSON shapes are fixed:
    // the Kotlin client is written to match them byte-for-byte.
    // -----------------------------------------------------------------

    /// device -> device (sync ALPN): first frame on a new connection. `cert`
    /// is the sender's `"azd…"`-encoded device certificate
    /// (`certs::DeviceCert`). Each side verifies the other's cert — chains
    /// to its own root key, not revoked, `device_pk` matches the
    /// connection's transport endpoint id — before any vector or entry
    /// exchange; any failure closes the connection (see `sync.rs`'s
    /// `run_session`).
    #[serde(rename = "sync_hello")]
    SyncHello { cert: String },

    /// device -> device (sync ALPN): the sender's per-device high-water
    /// vector — device public key hex to the highest **contiguous** `seq`
    /// held for that device.
    #[serde(rename = "sync_vector")]
    SyncVector { vector: BTreeMap<String, u64> },

    /// device -> device (sync ALPN): a batch of base64-encoded log entries
    /// (`eventlog::LogEntry::to_base64`/`from_base64`), at most 64 per
    /// frame, per-device in ascending `seq` order.
    #[serde(rename = "sync_entries")]
    SyncEntries { entries: Vec<String> },

    /// device -> device (sync ALPN): acknowledges that the vector exchange
    /// above is complete. Sent after the last `SyncEntries` batch; entries
    /// appended afterwards are pushed live as further `SyncEntries` frames
    /// with no further `SyncVector`/`SyncAck` round trip.
    #[serde(rename = "sync_ack")]
    SyncAck { vector: BTreeMap<String, u64> },

    /// new device -> root-holding device (link ALPN): first frame,
    /// presenting the new device's freshly generated endpoint public key,
    /// requested display name, and requested roles bitfield (see
    /// `certs::FLAG_MAILBOX`/`FLAG_BOT`).
    #[serde(rename = "link_hello")]
    LinkHello {
        #[serde(rename = "devicePk")]
        device_pk: String,
        name: String,
        roles: u8,
    },

    /// root-holding device -> new device (link ALPN): grants a certificate
    /// plus an [`IdentityBundle`] snapshot. Sent only after explicit user
    /// confirmation on the root-holding device (device-linking spec).
    #[serde(rename = "link_grant")]
    LinkGrant { cert: String, bundle: IdentityBundle },

    /// root-holding device -> new device (link ALPN): the link was declined
    /// (or otherwise failed) — no certificate exists.
    #[serde(rename = "link_reject")]
    LinkReject { reason: String },

    // -----------------------------------------------------------------
    // Relay frames (cli-multi-session-relay `relay` capability) — see
    // `mailbox_role.rs`'s LLM-ALPN admission path and `core::relay_a2ui`.
    // -----------------------------------------------------------------

    /// phone -> session/machine (sent on the app device's existing chat/LLM
    /// stream at pairing time): the identity's relay dial ticket, so a
    /// session that can't reach the phone directly knows where to deliver
    /// queueable traffic instead (relay spec: "Sessions SHALL learn the
    /// relay's ticket from a relay hint the phone shares at machine pairing
    /// time"). Sessions only parse and persist this (`registry::set_relay`) —
    /// never construct it for sending.
    #[serde(rename = "relay_hint")]
    RelayHint { ticket: String },

    /// session -> relay (LLM ALPN): a coalesced full-surface A2UI snapshot,
    /// replacing whatever the relay previously held for `(conversation,
    /// surface)`. `components: None` is a tombstone (the surface was
    /// deleted); `data_model: None` means "no data model to set" (distinct
    /// from an explicit empty object). `lamport` is a per-session monotonic
    /// sequence the relay uses to ignore a stale, out-of-order snapshot.
    #[serde(rename = "a2ui_snapshot")]
    A2uiSnapshot {
        conversation: String,
        surface: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        components: Option<serde_json::Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        data_model: Option<serde_json::Value>,
        lamport: u64,
    },

    /// relay -> phone (sync ALPN, after catch-up): replay of pending A2UI
    /// snapshots for one conversation, sent as ordinary A2UI wire messages
    /// (`createSurface`/`updateComponents`/`updateDataModel`, or
    /// `deleteSurface` for a tombstone) — the same object shapes
    /// `Frame::A2ui.message` carries on a live connection.
    #[serde(rename = "sync_a2ui")]
    SyncA2ui { conversation: String, messages: Vec<serde_json::Value> },

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
/// skipped. A malformed JSON line yields an `Err`, and so does a line longer
/// than [`MAX_FRAME_LINE_BYTES`] ([`FrameTooLong`]) — detected after reading at
/// most one byte past the cap, so a peer can't make this buffer an unbounded
/// line.
pub async fn read_frame<R>(reader: &mut tokio::io::BufReader<R>) -> Result<Option<Frame>>
where
    R: AsyncRead + Unpin,
{
    loop {
        let mut line = Vec::new();
        // One byte past the cap is enough to tell a line of exactly
        // MAX_FRAME_LINE_BYTES plus its `\n` from one that runs longer.
        let n = (&mut *reader).take(MAX_FRAME_LINE_BYTES as u64 + 1).read_until(b'\n', &mut line).await?;
        if n == 0 {
            // Clean EOF.
            return Ok(None);
        }
        if line.last() != Some(&b'\n') && n > MAX_FRAME_LINE_BYTES {
            return Err(FrameTooLong { limit: MAX_FRAME_LINE_BYTES }.into());
        }
        let end = line.iter().rposition(|&b| b != b'\r' && b != b'\n').map_or(0, |i| i + 1);
        if end == 0 {
            // Skip blank keepalive lines.
            continue;
        }
        let frame: Frame = serde_json::from_slice(&line[..end])?;
        return Ok(Some(frame));
    }
}

/// Split `items` into consecutive batches of at most `max_items` items whose
/// `size`s sum to at most `max_bytes`. An item bigger than `max_bytes` on its
/// own still goes out, alone in its batch — the receiver is the one to judge
/// it against [`MAX_FRAME_LINE_BYTES`]. Lazy, so a caller mapping entries to
/// their wire form only holds one batch's worth at a time.
pub fn size_batches<I, F>(items: I, max_items: usize, max_bytes: usize, size: F) -> SizeBatches<I::IntoIter, F>
where
    I: IntoIterator,
    F: Fn(&I::Item) -> usize,
{
    SizeBatches { items: items.into_iter().peekable(), max_items, max_bytes, size }
}

/// Iterator returned by [`size_batches`].
pub struct SizeBatches<I: Iterator, F> {
    items: std::iter::Peekable<I>,
    max_items: usize,
    max_bytes: usize,
    size: F,
}

impl<I, F> Iterator for SizeBatches<I, F>
where
    I: Iterator,
    F: Fn(&I::Item) -> usize,
{
    type Item = Vec<I::Item>;

    fn next(&mut self) -> Option<Vec<I::Item>> {
        let first = self.items.next()?;
        let mut bytes = (self.size)(&first);
        let mut batch = vec![first];
        while batch.len() < self.max_items {
            let mut item_bytes = 0;
            let fits = |item: &I::Item| {
                item_bytes = (self.size)(item);
                bytes + item_bytes <= self.max_bytes
            };
            let Some(next) = self.items.next_if(fits) else { break };
            bytes += item_bytes;
            batch.push(next);
        }
        Some(batch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_frame_roundtrips_with_type_tag() {
        let f = Frame::Hello { name: "alice".into(), invite: None, cert: None };
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(json, r#"{"type":"hello","name":"alice"}"#);
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Frame::Hello { name, invite: None, cert: None } if name == "alice"));
    }

    #[test]
    fn hello_frame_with_invite_roundtrips() {
        let f = Frame::Hello { name: "alice".into(), invite: Some("azi...".into()), cert: None };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains(r#""invite":"azi...""#), "missing invite: {json}");
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Frame::Hello { invite: Some(i), .. } if i == "azi..."));
    }

    #[test]
    fn hello_frame_without_invite_field_decodes() {
        // Old peers omit the field entirely.
        let json = r#"{"type":"hello","name":"bob"}"#;
        let back: Frame = serde_json::from_str(json).unwrap();
        assert!(matches!(back, Frame::Hello { name, invite: None, cert: None } if name == "bob"));
    }

    #[test]
    fn chat_frame_roundtrips_with_type_tag() {
        let f = Frame::Chat {
            text: "hello".into(),
            id: None,
        };
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(json, r#"{"type":"chat","text":"hello"}"#);
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Frame::Chat { text, id: None } if text == "hello"));
    }

    // --- Hello.cert / Chat.id (task 7.1) -------------------------------------
    // Additive/optional wire fields: omitted when absent, tolerant of legacy
    // peers that never send them. No cert validation or attach-on-send wiring
    // here — that's tasks 7.2/7.3/7.4.

    #[test]
    fn hello_cert_roundtrips() {
        let f = Frame::Hello { name: "alice".into(), invite: None, cert: Some("azd-mine".into()) };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains(r#""cert":"azd-mine""#), "missing cert: {json}");
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Frame::Hello { cert: Some(c), .. } if c == "azd-mine"));
    }

    #[test]
    fn hello_cert_omitted_from_json_when_absent() {
        let f = Frame::Hello { name: "alice".into(), invite: None, cert: None };
        let json = serde_json::to_string(&f).unwrap();
        assert!(!json.contains("cert"), "cert should be absent: {json}");
    }

    #[test]
    fn hello_without_cert_field_still_parses() {
        // Legacy-peer compatibility: a frame from a build that doesn't know
        // about `cert` at all must still parse, with cert defaulting to None.
        let json = r#"{"type":"hello","name":"bob"}"#;
        let back: Frame = serde_json::from_str(json).unwrap();
        assert!(matches!(back, Frame::Hello { name, cert: None, .. } if name == "bob"));
    }

    #[test]
    fn chat_id_roundtrips() {
        let f = Frame::Chat { text: "hi".into(), id: Some("0123456789abcdef0123456789abcdef".into()) };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains(r#""id":"0123456789abcdef0123456789abcdef""#), "missing id: {json}");
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Frame::Chat { id: Some(i), .. } if i == "0123456789abcdef0123456789abcdef"));
    }

    #[test]
    fn chat_id_omitted_from_json_when_absent() {
        let f = Frame::Chat { text: "hi".into(), id: None };
        let json = serde_json::to_string(&f).unwrap();
        assert!(!json.contains("\"id\""), "id should be absent: {json}");
    }

    #[test]
    fn chat_without_id_field_still_parses() {
        // Legacy-peer compatibility: a frame from a build that doesn't know
        // about `id` at all must still parse, with id defaulting to None.
        let json = r#"{"type":"chat","text":"hi"}"#;
        let back: Frame = serde_json::from_str(json).unwrap();
        assert!(matches!(back, Frame::Chat { text, id: None } if text == "hi"));
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
    fn term_attach_with_session_roundtrips() {
        let f = Frame::TermAttach { session: Some("abc123".into()) };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains(r#""type":"term_attach""#), "wrong type tag: {json}");
        assert!(json.contains(r#""session":"abc123""#), "missing session: {json}");
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Frame::TermAttach { session: Some(s) } if s == "abc123"));
    }

    #[test]
    fn term_attach_kotlin_null_session_decodes_to_none() {
        // kotlinx.serialization's FrameCodec uses encodeDefaults = true, so a
        // "create a new session" term_attach is sent with an explicit
        // `"session":null` rather than the field omitted entirely.
        let json = r#"{"type":"term_attach","session":null}"#;
        let back: Frame = serde_json::from_str(json).unwrap();
        assert!(matches!(back, Frame::TermAttach { session: None }));
    }

    #[test]
    fn term_attach_missing_session_field_decodes_to_none() {
        let json = r#"{"type":"term_attach"}"#;
        let back: Frame = serde_json::from_str(json).unwrap();
        assert!(matches!(back, Frame::TermAttach { session: None }));
    }

    #[test]
    fn term_session_roundtrips_resumed_true() {
        let f = Frame::TermSession { session: "sess-1".into(), resumed: true };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains(r#""type":"term_session""#), "wrong type tag: {json}");
        assert!(json.contains(r#""resumed":true"#), "missing resumed: {json}");
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Frame::TermSession { session, resumed: true } if session == "sess-1"));
    }

    #[test]
    fn term_session_resumed_defaults_to_false_when_absent() {
        let json = r#"{"type":"term_session","session":"sess-2"}"#;
        let back: Frame = serde_json::from_str(json).unwrap();
        assert!(matches!(back, Frame::TermSession { session, resumed: false } if session == "sess-2"));
    }

    #[test]
    fn term_exit_roundtrips_with_code() {
        let f = Frame::TermExit { session: "sess-1".into(), code: Some(0) };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains(r#""type":"term_exit""#), "wrong type tag: {json}");
        assert!(json.contains(r#""code":0"#), "missing code: {json}");
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Frame::TermExit { session, code: Some(0) } if session == "sess-1"));
    }

    #[test]
    fn term_exit_without_code_omits_field() {
        let f = Frame::TermExit { session: "sess-1".into(), code: None };
        let json = serde_json::to_string(&f).unwrap();
        assert!(!json.contains("code"), "code should be absent: {json}");
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Frame::TermExit { code: None, .. }));
    }

    #[test]
    fn unknown_type_tag_decodes_to_unknown_variant() {
        let json = r#"{"type":"totally_new_frame","foo":"bar"}"#;
        let f: Frame = serde_json::from_str(json).unwrap();
        assert!(matches!(f, Frame::Unknown));
    }

    // --- Sync / link frames (task 5.1) --------------------------------------

    #[test]
    fn sync_hello_roundtrips_with_type_tag() {
        let f = Frame::SyncHello { cert: "azd-example-cert".into() };
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(json, r#"{"type":"sync_hello","cert":"azd-example-cert"}"#);
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Frame::SyncHello { cert } if cert == "azd-example-cert"));
    }

    #[test]
    fn sync_vector_roundtrips_with_type_tag() {
        let mut vector = BTreeMap::new();
        vector.insert("aabb".to_string(), 3u64);
        let f = Frame::SyncVector { vector: vector.clone() };
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(json, r#"{"type":"sync_vector","vector":{"aabb":3}}"#);
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Frame::SyncVector { vector: v } if v == vector));
    }

    #[test]
    fn sync_entries_roundtrips_with_type_tag() {
        let f = Frame::SyncEntries { entries: vec!["ZW50cnkx".into(), "ZW50cnky".into()] };
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(json, r#"{"type":"sync_entries","entries":["ZW50cnkx","ZW50cnky"]}"#);
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Frame::SyncEntries { entries } if entries.len() == 2));
    }

    #[test]
    fn sync_ack_roundtrips_with_type_tag() {
        let mut vector = BTreeMap::new();
        vector.insert("ccdd".to_string(), 7u64);
        let f = Frame::SyncAck { vector: vector.clone() };
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(json, r#"{"type":"sync_ack","vector":{"ccdd":7}}"#);
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Frame::SyncAck { vector: v } if v == vector));
    }

    #[test]
    fn link_hello_roundtrips_with_type_tag() {
        let f = Frame::LinkHello { device_pk: "abcd1234".into(), name: "laptop".into(), roles: 1 };
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(json, r#"{"type":"link_hello","devicePk":"abcd1234","name":"laptop","roles":1}"#);
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            back,
            Frame::LinkHello { device_pk, name, roles: 1 } if device_pk == "abcd1234" && name == "laptop"
        ));
    }

    #[test]
    fn link_grant_roundtrips_with_type_tag() {
        let bundle = IdentityBundle {
            root_pk: "root-hex".into(),
            certs: vec!["azd1".into()],
            revocations: vec![],
            contacts: vec![Contact { root_pk: Some("contact-root".into()), endpoint_id: None, name: Some("Alice".into()) }],
            mailbox: Some("mailbox-ticket".into()),
        };
        let f = Frame::LinkGrant { cert: "azd-mine".into(), bundle: bundle.clone() };
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(
            json,
            r#"{"type":"link_grant","cert":"azd-mine","bundle":{"rootPk":"root-hex","certs":["azd1"],"revocations":[],"contacts":[{"rootPk":"contact-root","name":"Alice"}],"mailbox":"mailbox-ticket"}}"#
        );
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Frame::LinkGrant { cert, bundle: b } if cert == "azd-mine" && b == bundle));
    }

    #[test]
    fn link_grant_bundle_omits_mailbox_and_uses_endpoint_id_contact() {
        let bundle = IdentityBundle {
            root_pk: "root-hex".into(),
            certs: vec![],
            revocations: vec![],
            contacts: vec![Contact { root_pk: None, endpoint_id: Some("legacy-endpoint".into()), name: None }],
            mailbox: None,
        };
        let f = Frame::LinkGrant { cert: "azd-mine".into(), bundle };
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(
            json,
            r#"{"type":"link_grant","cert":"azd-mine","bundle":{"rootPk":"root-hex","certs":[],"revocations":[],"contacts":[{"endpointId":"legacy-endpoint"}]}}"#
        );
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Frame::LinkGrant { .. }));
    }

    #[test]
    fn link_reject_roundtrips_with_type_tag() {
        let f = Frame::LinkReject { reason: "user declined".into() };
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(json, r#"{"type":"link_reject","reason":"user declined"}"#);
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Frame::LinkReject { reason } if reason == "user declined"));
    }

    #[test]
    fn unrecognized_sync_frame_type_decodes_to_unknown() {
        // A future sibling introduces a new sync/link frame kind this build
        // doesn't know about yet — must not error the whole read.
        let json = r#"{"type":"sync_resync_request","foo":"bar"}"#;
        let f: Frame = serde_json::from_str(json).unwrap();
        assert!(matches!(f, Frame::Unknown));
    }

    // --- Relay frames (cli-multi-session-relay relay capability) -----------

    #[test]
    fn relay_hint_roundtrips_with_type_tag() {
        let f = Frame::RelayHint { ticket: "relay-ticket-abc".into() };
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(json, r#"{"type":"relay_hint","ticket":"relay-ticket-abc"}"#);
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Frame::RelayHint { ticket } if ticket == "relay-ticket-abc"));
    }

    #[test]
    fn a2ui_snapshot_roundtrips_with_type_tag() {
        let f = Frame::A2uiSnapshot {
            conversation: "cafebabe".into(),
            surface: "dice-1".into(),
            components: Some(serde_json::json!([{"id":"root","component":"Text"}])),
            data_model: Some(serde_json::json!({"you":1})),
            lamport: 3,
        };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains(r#""type":"a2ui_snapshot""#), "wrong type tag: {json}");
        assert!(json.contains(r#""conversation":"cafebabe""#), "missing conversation: {json}");
        assert!(json.contains(r#""surface":"dice-1""#), "missing surface: {json}");
        assert!(json.contains(r#""lamport":3"#), "missing lamport: {json}");
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Frame::A2uiSnapshot { lamport: 3, .. }));
    }

    #[test]
    fn a2ui_snapshot_tombstone_omits_components_and_data_model() {
        let f = Frame::A2uiSnapshot {
            conversation: "cafebabe".into(),
            surface: "dice-1".into(),
            components: None,
            data_model: None,
            lamport: 4,
        };
        let json = serde_json::to_string(&f).unwrap();
        assert!(!json.contains("components"), "components should be absent (tombstone): {json}");
        assert!(!json.contains("data_model"), "data_model should be absent: {json}");
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Frame::A2uiSnapshot { components: None, data_model: None, .. }));
    }

    #[test]
    fn sync_a2ui_roundtrips_with_type_tag() {
        let messages = vec![
            serde_json::json!({"version":"v0.9.1","createSurface":{"surfaceId":"dice-1"}}),
            serde_json::json!({"version":"v0.9.1","updateComponents":{"surfaceId":"dice-1","components":[]}}),
        ];
        let f = Frame::SyncA2ui { conversation: "cafebabe".into(), messages: messages.clone() };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains(r#""type":"sync_a2ui""#), "wrong type tag: {json}");
        assert!(json.contains(r#""conversation":"cafebabe""#), "missing conversation: {json}");
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Frame::SyncA2ui { messages: m, .. } if m.len() == 2));
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

#[cfg(test)]
mod size_cap_tests {
    use super::*;
    use tokio::io::BufReader;

    const CHAT_PREFIX: &[u8] = br#"{"type":"chat","text":""#;
    const CHAT_SUFFIX: &[u8] = br#""}"#;

    /// A `chat` frame line (no `\n`) exactly `len` bytes long.
    fn chat_line_of_len(len: usize) -> Vec<u8> {
        let mut line = Vec::with_capacity(len + 1);
        line.extend_from_slice(CHAT_PREFIX);
        line.resize(len - CHAT_SUFFIX.len(), b'x');
        line.extend_from_slice(CHAT_SUFFIX);
        assert_eq!(line.len(), len);
        line
    }

    #[tokio::test]
    async fn read_frame_accepts_a_line_exactly_at_the_cap() {
        let mut bytes = chat_line_of_len(MAX_FRAME_LINE_BYTES);
        bytes.push(b'\n');
        bytes.extend_from_slice(b"{\"type\":\"thinking\",\"on\":true}\n");
        let mut r = BufReader::new(&bytes[..]);

        match read_frame(&mut r).await.unwrap() {
            Some(Frame::Chat { text, .. }) => {
                assert_eq!(text.len(), MAX_FRAME_LINE_BYTES - CHAT_PREFIX.len() - CHAT_SUFFIX.len());
            }
            other => panic!("expected the at-cap chat frame, got {other:?}"),
        }
        // The stream carries on normally after a line right at the cap.
        assert!(matches!(read_frame(&mut r).await.unwrap(), Some(Frame::Thinking { on: true })));
        assert!(read_frame(&mut r).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn read_frame_rejects_a_line_one_byte_over_the_cap() {
        let mut bytes = chat_line_of_len(MAX_FRAME_LINE_BYTES + 1);
        bytes.push(b'\n');
        bytes.extend_from_slice(b"{\"type\":\"thinking\",\"on\":true}\n");
        let mut r = BufReader::new(&bytes[..]);

        // An error, not a skipped line: the well-formed frame behind it is
        // never handed out in its place.
        let err = read_frame(&mut r).await.expect_err("an over-cap line must fail the read");
        assert!(err.downcast_ref::<FrameTooLong>().is_some(), "wrong error: {err:#}");
    }

    #[tokio::test]
    async fn read_frame_gives_up_on_an_endless_line_just_past_the_cap() {
        // A peer that never sends `\n`. Bounded at 4x the cap so a regression
        // ends in a wrong-error assertion instead of exhausting memory.
        const BUF_CAPACITY: usize = 8 * 1024;
        let total = 4 * MAX_FRAME_LINE_BYTES as u64;
        let mut r = BufReader::with_capacity(BUF_CAPACITY, tokio::io::repeat(b'x').take(total));

        let err = read_frame(&mut r).await.expect_err("an endless line must fail the read");
        assert!(err.downcast_ref::<FrameTooLong>().is_some(), "wrong error: {err:#}");
        let consumed = (total - r.get_ref().limit()) as usize;
        assert!(
            consumed <= MAX_FRAME_LINE_BYTES + 1 + BUF_CAPACITY,
            "read {consumed} bytes of an endless line; the cap is {MAX_FRAME_LINE_BYTES}"
        );
    }

    #[tokio::test]
    async fn read_frame_accepts_an_unterminated_final_line_under_the_cap() {
        let bytes = br#"{"type":"thinking","on":false}"#;
        let mut r = BufReader::new(&bytes[..]);
        assert!(matches!(read_frame(&mut r).await.unwrap(), Some(Frame::Thinking { on: false })));
        assert!(read_frame(&mut r).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn read_frame_still_skips_blank_and_crlf_lines() {
        let bytes = b"\n\r\n{\"type\":\"thinking\",\"on\":true}\r\n";
        let mut r = BufReader::new(&bytes[..]);
        assert!(matches!(read_frame(&mut r).await.unwrap(), Some(Frame::Thinking { on: true })));
        assert!(read_frame(&mut r).await.unwrap().is_none());
    }

    #[test]
    fn size_batches_caps_item_count() {
        let batches: Vec<Vec<usize>> = size_batches(vec![1, 1, 1, 1, 1], 2, usize::MAX, |n| *n).collect();
        assert_eq!(batches, vec![vec![1, 1], vec![1, 1], vec![1]]);
    }

    #[test]
    fn size_batches_caps_bytes_inclusively() {
        let batches: Vec<Vec<usize>> = size_batches(vec![2, 3, 1, 4, 4], 64, 5, |n| *n).collect();
        assert_eq!(batches, vec![vec![2, 3], vec![1, 4], vec![4]]);
    }

    #[test]
    fn size_batches_sends_an_oversize_item_alone() {
        let batches: Vec<Vec<usize>> = size_batches(vec![2, 10, 2, 2], 64, 5, |n| *n).collect();
        assert_eq!(batches, vec![vec![2], vec![10], vec![2, 2]]);
    }

    #[test]
    fn size_batches_of_nothing_is_empty() {
        assert_eq!(size_batches(Vec::<usize>::new(), 64, 5, |n| *n).count(), 0);
    }
}
