//! File transfer helpers shared by the outbound `send_file` tool and the
//! bridge's inbound frame reader.
//!
//! Wire format (must match the app's reference implementation,
//! `azula-app/network-api/src/dev/azula/net/FileTransfer.kt`, exactly):
//! [`Frame::FileBegin`] (metadata: id/name/mime/size/encoding/caption) → N ×
//! [`Frame::FileChunk`] (each carrying a standard RFC 4648, padded base64
//! encoding of a 32 KiB slice of the raw bytes, `seq` counting from 0) →
//! [`Frame::FileEnd`]. This is the "legacy inline" path used for LLM-bridge
//! conversations (as opposed to the peer-to-peer `MediaOffer`/fetch path,
//! which streams over a separate ALPN and is out of scope here).
//!
//! [`build_file_frames`] is the pure send-side helper (bytes → frames);
//! [`FileAssembler`] is the pure receive-side helper (frames → bytes). Both
//! are exercised directly by unit tests below, independent of the iroh
//! transport.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::proto::Frame;

/// Maximum accepted file size (64 MiB), matching the app's `MAX_FILE_BYTES`.
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// Size of each `FileChunk` slice (32 KiB), matching the app's default.
pub const CHUNK_SIZE: usize = 32 * 1024;

/// Wire encoding used for outbound transfers (the app only sends/accepts
/// base64 from its File-attach path).
pub const ENCODING_BASE64: &str = "base64";

// ---------------------------------------------------------------------------
// Send side: bytes -> frames
// ---------------------------------------------------------------------------

/// Build the `FileBegin` + `FileChunk`×N + `FileEnd` frame sequence for
/// `bytes`, base64-encoded in [`CHUNK_SIZE`] slices. Returns an error if
/// `bytes` exceeds [`MAX_FILE_BYTES`].
pub fn build_file_frames(
    id: String,
    name: String,
    mime: String,
    caption: Option<String>,
    bytes: &[u8],
) -> Result<Vec<Frame>> {
    let size = bytes.len() as u64;
    if size > MAX_FILE_BYTES {
        bail!("file too large: {size} bytes (max {MAX_FILE_BYTES} / 64 MiB)");
    }

    let mut frames = Vec::with_capacity(2 + bytes.len().div_ceil(CHUNK_SIZE));
    frames.push(Frame::FileBegin {
        id: id.clone(),
        name,
        mime,
        size,
        encoding: ENCODING_BASE64.to_string(),
        caption,
    });

    for (seq, chunk) in bytes.chunks(CHUNK_SIZE).enumerate() {
        frames.push(Frame::FileChunk {
            id: id.clone(),
            seq: seq as u32,
            data: STANDARD.encode(chunk),
        });
    }

    frames.push(Frame::FileEnd { id });
    Ok(frames)
}

/// Infer a MIME type from `path`'s extension. A small built-in table — no
/// mime-guessing crate is currently a workspace dependency, so this stays a
/// short match rather than pulling one in. Falls back to
/// `application/octet-stream` for anything unrecognized.
pub fn guess_mime(path: &Path) -> String {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" => "audio/ogg",
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        "md" => "text/markdown",
        _ => "application/octet-stream",
    }
    .to_string()
}

// ---------------------------------------------------------------------------
// Receive side: frames -> bytes
// ---------------------------------------------------------------------------

/// Accumulates `FileChunk` data (by base64-decoding each as it arrives) for a
/// single in-flight transfer until `FileEnd`. Mirrors the app's
/// `receiveFile` reassembly loop. The caller (the bridge's per-connection
/// frame reader) is responsible for keying one of these per in-flight
/// `FileBegin.id` and feeding it chunks in arrival order.
#[derive(Debug, Default)]
pub struct FileAssembler {
    chunks: Vec<Vec<u8>>,
}

impl FileAssembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Base64-decode `data` and store it. Returns an error on malformed
    /// base64; the caller decides whether to drop the whole transfer or just
    /// this chunk.
    pub fn push_chunk(&mut self, data: &str) -> Result<()> {
        let bytes = STANDARD.decode(data).context("invalid base64 in file_chunk")?;
        self.chunks.push(bytes);
        Ok(())
    }

    /// Consume the assembler, concatenating all chunks in arrival order.
    pub fn finish(self) -> Vec<u8> {
        self.chunks.concat()
    }
}

// ---------------------------------------------------------------------------
// Received-file storage
// ---------------------------------------------------------------------------

/// Returns the directory received files are written to, in order of
/// preference:
/// 1. `AZULA_RECEIVED_DIR` env var (tests / overrides)
/// 2. Parent of the global registry path + "received" (i.e. `~/.azula/received`)
/// 3. `std::env::temp_dir()/azula/received`
pub fn received_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("AZULA_RECEIVED_DIR") {
        return PathBuf::from(dir);
    }
    if let Some(global) = crate::registry::global_path() {
        if let Some(parent) = global.parent() {
            return parent.join("received");
        }
    }
    std::env::temp_dir().join("azula").join("received")
}

/// Sanitize `name` (an untrusted, peer-supplied file name) to a safe leaf
/// filename: strips any directory components and replaces characters other
/// than alphanumerics/`.`/`-`/`_`/space with `_`. Never returns an empty
/// string.
fn sanitize_filename(name: &str) -> String {
    let leaf = Path::new(name)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("file");
    let cleaned: String = leaf
        .chars()
        .map(|c| if c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | ' ') { c } else { '_' })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        "file".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Pick a filename under `dir` that doesn't already exist, appending
/// `-1`, `-2`, … before the extension on collision.
fn unique_path(dir: &Path, filename: &str) -> PathBuf {
    let candidate = dir.join(filename);
    if !candidate.exists() {
        return candidate;
    }
    let path = Path::new(filename);
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or(filename);
    let ext = path.extension().and_then(|s| s.to_str());
    for n in 1..10_000u32 {
        let name = match ext {
            Some(e) => format!("{stem}-{n}.{e}"),
            None => format!("{stem}-{n}"),
        };
        let candidate = dir.join(&name);
        if !candidate.exists() {
            return candidate;
        }
    }
    // Astronomically unlikely fallback so this always terminates.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    dir.join(format!("{filename}-{nanos}"))
}

/// Write `bytes` under `dir` as `name` (sanitized), handling filename
/// collisions. Returns the (best-effort canonicalized, i.e. absolute) path
/// written.
pub fn save_received_file(dir: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf> {
    std::fs::create_dir_all(dir).with_context(|| format!("create dirs {}", dir.display()))?;
    let sanitized = sanitize_filename(name);
    let path = unique_path(dir, &sanitized);
    std::fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))?;
    Ok(path.canonicalize().unwrap_or(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(name: &str) -> PathBuf {
        std::env::temp_dir()
            .join(format!("azula-filexfer-test-{}", std::process::id()))
            .join(name)
    }

    /// A pure send->receive round trip: chunk bytes into frames, then feed
    /// the chunk frames back through a `FileAssembler` and assert the
    /// reassembled bytes match the original.
    #[test]
    fn chunk_and_reassemble_round_trips_multi_chunk() {
        // 3.5 chunks worth of pseudo-random bytes.
        let size = CHUNK_SIZE * 3 + CHUNK_SIZE / 2;
        let bytes: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();

        let frames = build_file_frames(
            "id-1".into(),
            "photo.png".into(),
            "image/png".into(),
            Some("caption".into()),
            &bytes,
        )
        .unwrap();

        // 1 begin + 4 chunks + 1 end.
        assert_eq!(frames.len(), 6, "unexpected frame count: {}", frames.len());
        assert!(matches!(&frames[0], Frame::FileBegin { size: s, encoding, .. } if *s == size as u64 && encoding == "base64"));
        assert!(matches!(&frames[5], Frame::FileEnd { id } if id == "id-1"));

        let mut assembler = FileAssembler::new();
        for f in &frames[1..frames.len() - 1] {
            match f {
                Frame::FileChunk { id, data, .. } => {
                    assert_eq!(id, "id-1");
                    assembler.push_chunk(data).unwrap();
                }
                other => panic!("expected FileChunk, got {other:?}"),
            }
        }
        let reassembled = assembler.finish();
        assert_eq!(reassembled, bytes);
    }

    #[test]
    fn chunk_and_reassemble_round_trips_empty_file() {
        let frames = build_file_frames("id-2".into(), "empty.txt".into(), "text/plain".into(), None, &[]).unwrap();
        // 1 begin + 0 chunks + 1 end.
        assert_eq!(frames.len(), 2);
        assert!(matches!(&frames[0], Frame::FileBegin { size: 0, .. }));
    }

    #[test]
    fn chunk_and_reassemble_round_trips_exact_chunk_boundary() {
        let bytes = vec![7u8; CHUNK_SIZE * 2];
        let frames = build_file_frames("id-3".into(), "f.bin".into(), "application/octet-stream".into(), None, &bytes).unwrap();
        // 1 begin + 2 chunks + 1 end.
        assert_eq!(frames.len(), 4);

        let mut assembler = FileAssembler::new();
        for f in &frames[1..frames.len() - 1] {
            if let Frame::FileChunk { data, .. } = f {
                assembler.push_chunk(data).unwrap();
            }
        }
        assert_eq!(assembler.finish(), bytes);
    }

    #[test]
    fn build_file_frames_rejects_oversize() {
        let bytes = vec![0u8; (MAX_FILE_BYTES + 1) as usize];
        let err = build_file_frames("id-4".into(), "big.bin".into(), "application/octet-stream".into(), None, &bytes)
            .expect_err("should reject file over the 64 MiB cap");
        assert!(err.to_string().contains("too large"), "unexpected error: {err}");
    }

    #[test]
    fn assembler_rejects_bad_base64() {
        let mut assembler = FileAssembler::new();
        assert!(assembler.push_chunk("not valid base64!!").is_err());
    }

    #[test]
    fn guess_mime_matches_known_extensions() {
        assert_eq!(guess_mime(Path::new("a.png")), "image/png");
        assert_eq!(guess_mime(Path::new("a.JPG")), "image/jpeg");
        assert_eq!(guess_mime(Path::new("a.jpeg")), "image/jpeg");
        assert_eq!(guess_mime(Path::new("a.gif")), "image/gif");
        assert_eq!(guess_mime(Path::new("a.webp")), "image/webp");
        assert_eq!(guess_mime(Path::new("a.svg")), "image/svg+xml");
        assert_eq!(guess_mime(Path::new("a.mp4")), "video/mp4");
        assert_eq!(guess_mime(Path::new("a.mov")), "video/quicktime");
        assert_eq!(guess_mime(Path::new("a.mp3")), "audio/mpeg");
        assert_eq!(guess_mime(Path::new("a.wav")), "audio/wav");
        assert_eq!(guess_mime(Path::new("a.ogg")), "audio/ogg");
        assert_eq!(guess_mime(Path::new("a.pdf")), "application/pdf");
        assert_eq!(guess_mime(Path::new("a.txt")), "text/plain");
        assert_eq!(guess_mime(Path::new("a.md")), "text/markdown");
        assert_eq!(guess_mime(Path::new("a.unknownext")), "application/octet-stream");
        assert_eq!(guess_mime(Path::new("noext")), "application/octet-stream");
    }

    #[test]
    fn save_received_file_sanitizes_and_writes() {
        let dir = test_dir("sanitize");
        let _ = std::fs::remove_dir_all(&dir);
        let path = save_received_file(&dir, "../../etc/weird name?.png", b"hello").unwrap();
        // `file_name()` already strips directory components, so only the
        // leaf's disallowed characters get replaced.
        assert_eq!(path.file_name().unwrap().to_str().unwrap(), "weird name_.png");
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
        assert!(path.is_absolute(), "expected an absolute path, got {}", path.display());
    }

    #[test]
    fn save_received_file_handles_name_collisions() {
        let dir = test_dir("collisions");
        let _ = std::fs::remove_dir_all(&dir);
        let p1 = save_received_file(&dir, "photo.png", b"one").unwrap();
        let p2 = save_received_file(&dir, "photo.png", b"two").unwrap();
        assert_ne!(p1, p2, "second write should not clobber the first");
        assert_eq!(std::fs::read(&p1).unwrap(), b"one");
        assert_eq!(std::fs::read(&p2).unwrap(), b"two");
        assert_eq!(p2.file_name().unwrap().to_str().unwrap(), "photo-1.png");
    }
}
