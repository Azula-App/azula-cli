//! The frame codec shared by every hop (`vm/README.md` §1): `u32 BE
//! header_len`, `u32 BE payload_len`, a UTF-8 JSON object header carrying a
//! string `"t"`, then raw payload bytes. Works over any tokio byte stream, so
//! the same code reads iroh streams and Unix sockets.

use std::io;

use serde_json::{json, Map, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest accepted header (`1 ..= MAX_HEADER` bytes).
pub const MAX_HEADER: usize = 65_536;
/// Largest accepted payload (`0 ..= MAX_PAYLOAD` bytes).
pub const MAX_PAYLOAD: usize = 1_048_576;

/// One decoded frame.
#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    /// The JSON header object (always has a string `"t"`).
    pub header: Map<String, Value>,
    pub payload: Vec<u8>,
}

/// Why a frame could not be read or written.
#[derive(Debug)]
pub enum FrameError {
    /// Out-of-range length, non-UTF-8, non-object JSON or missing `"t"`.
    Protocol(String),
    /// The stream ended in the middle of a frame.
    Truncated,
    Io(io::Error),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Protocol(m) => write!(f, "protocol error: {m}"),
            FrameError::Truncated => write!(f, "stream ended mid-frame"),
            FrameError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for FrameError {}

impl Frame {
    /// A header-only frame. `header` must be a JSON object with a string `"t"`.
    pub fn new(header: Value) -> Self {
        Self::with_payload(header, Vec::new())
    }

    pub fn with_payload(header: Value, payload: Vec<u8>) -> Self {
        let header = match header {
            Value::Object(m) => m,
            _ => Map::new(),
        };
        Frame { header, payload }
    }

    /// `{"t": t}`.
    pub fn of_type(t: &str) -> Self {
        Self::new(json!({ "t": t }))
    }

    /// The frame's `"t"`.
    pub fn t(&self) -> &str {
        self.header.get("t").and_then(Value::as_str).unwrap_or("")
    }

    pub fn str_field(&self, key: &str) -> Option<&str> {
        self.header.get(key).and_then(Value::as_str)
    }

    /// Wire bytes of this frame.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let h = serde_json::to_vec(&self.header).map_err(|e| FrameError::Protocol(e.to_string()))?;
        if h.is_empty() || h.len() > MAX_HEADER {
            return Err(FrameError::Protocol("header length out of range".into()));
        }
        if self.payload.len() > MAX_PAYLOAD {
            return Err(FrameError::Protocol("payload length out of range".into()));
        }
        let mut out = Vec::with_capacity(8 + h.len() + self.payload.len());
        out.extend_from_slice(&(h.len() as u32).to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&h);
        out.extend_from_slice(&self.payload);
        Ok(out)
    }
}

/// Write one frame (a single `write_all`, so frames never interleave) and flush.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &Frame) -> Result<(), FrameError> {
    let buf = frame.encode()?;
    w.write_all(&buf).await.map_err(FrameError::Io)?;
    w.flush().await.map_err(FrameError::Io)
}

/// Read one frame. `Ok(None)` is a clean EOF on a frame boundary.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Frame>, FrameError> {
    let mut len = [0u8; 8];
    let mut got = 0;
    while got < len.len() {
        match r.read(&mut len[got..]).await {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(FrameError::Truncated),
            Ok(n) => got += n,
            Err(e) => return Err(FrameError::Io(e)),
        }
    }
    let hlen = u32::from_be_bytes([len[0], len[1], len[2], len[3]]) as usize;
    let plen = u32::from_be_bytes([len[4], len[5], len[6], len[7]]) as usize;
    if hlen == 0 || hlen > MAX_HEADER {
        return Err(FrameError::Protocol(format!("header length {hlen} out of range")));
    }
    if plen > MAX_PAYLOAD {
        return Err(FrameError::Protocol(format!("payload length {plen} out of range")));
    }
    let mut hbuf = vec![0u8; hlen];
    read_full(r, &mut hbuf).await?;
    let mut payload = vec![0u8; plen];
    read_full(r, &mut payload).await?;
    let text = std::str::from_utf8(&hbuf).map_err(|_| FrameError::Protocol("header is not UTF-8".into()))?;
    let header = match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(m)) => m,
        Ok(_) => return Err(FrameError::Protocol("header is not a JSON object".into())),
        Err(e) => return Err(FrameError::Protocol(format!("header is not JSON: {e}"))),
    };
    if !header.get("t").is_some_and(Value::is_string) {
        return Err(FrameError::Protocol("header has no string \"t\"".into()));
    }
    Ok(Some(Frame { header, payload }))
}

async fn read_full<R: AsyncRead + Unpin>(r: &mut R, buf: &mut [u8]) -> Result<(), FrameError> {
    r.read_exact(buf).await.map(|_| ()).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            FrameError::Truncated
        } else {
            FrameError::Io(e)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTOR: [u8; 24] = [
        0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x02, 0x7b, 0x22, 0x74, 0x22, 0x3a, 0x22, 0x73, 0x74, 0x64,
        0x6f, 0x75, 0x74, 0x22, 0x7d, 0x68, 0x69,
    ];

    #[test]
    fn test_vector_encodes_exactly() {
        let f = Frame::with_payload(json!({"t": "stdout"}), b"hi".to_vec());
        assert_eq!(f.encode().unwrap(), VECTOR);
    }

    #[tokio::test]
    async fn test_vector_decodes() {
        let mut r = &VECTOR[..];
        let f = read_frame(&mut r).await.unwrap().unwrap();
        assert_eq!(f.t(), "stdout");
        assert_eq!(f.payload, b"hi");
        assert!(read_frame(&mut r).await.unwrap().is_none(), "clean EOF");
    }

    async fn decode(bytes: &[u8]) -> Result<Option<Frame>, FrameError> {
        let mut r = bytes;
        read_frame(&mut r).await
    }

    fn raw(h: &[u8], p: &[u8]) -> Vec<u8> {
        let mut v = (h.len() as u32).to_be_bytes().to_vec();
        v.extend((p.len() as u32).to_be_bytes());
        v.extend(h);
        v.extend(p);
        v
    }

    #[tokio::test]
    async fn rejects_bad_frames() {
        assert!(matches!(decode(&raw(b"", b"")).await, Err(FrameError::Protocol(_))), "empty header");
        assert!(matches!(decode(&raw(b"[1]", b"")).await, Err(FrameError::Protocol(_))), "non-object");
        assert!(matches!(decode(&raw(b"{\"x\":1}", b"")).await, Err(FrameError::Protocol(_))), "no t");
        assert!(matches!(decode(&raw(b"{\"t\":1}", b"")).await, Err(FrameError::Protocol(_))), "t not string");
        assert!(matches!(decode(&raw(&[0xff, 0xfe], b"")).await, Err(FrameError::Protocol(_))), "non-utf8");
        let mut huge_header = ((MAX_HEADER + 1) as u32).to_be_bytes().to_vec();
        huge_header.extend(0u32.to_be_bytes());
        assert!(matches!(decode(&huge_header).await, Err(FrameError::Protocol(_))));
        let mut huge_payload = 7u32.to_be_bytes().to_vec();
        huge_payload.extend(((MAX_PAYLOAD + 1) as u32).to_be_bytes());
        assert!(matches!(decode(&huge_payload).await, Err(FrameError::Protocol(_))));
        assert!(matches!(decode(&VECTOR[..12]).await, Err(FrameError::Truncated)));
        assert!(matches!(decode(&VECTOR[..3]).await, Err(FrameError::Truncated)));
    }

    #[tokio::test]
    async fn limits_are_inclusive_and_unknown_fields_ignored() {
        let f = Frame::with_payload(json!({"t": "stdin", "extra": [1, 2]}), vec![7; MAX_PAYLOAD]);
        let bytes = f.encode().unwrap();
        let back = decode(&bytes).await.unwrap().unwrap();
        assert_eq!(back.payload.len(), MAX_PAYLOAD);
        assert_eq!(back.t(), "stdin");
        let too_big = Frame::with_payload(json!({"t": "stdin"}), vec![0; MAX_PAYLOAD + 1]);
        assert!(too_big.encode().is_err());
    }

    #[tokio::test]
    async fn round_trips_over_a_duplex_pipe() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let w = tokio::spawn(async move {
            for i in 0..5u8 {
                write_frame(&mut a, &Frame::with_payload(json!({"t": "stdout"}), vec![i; 100])).await.unwrap();
            }
        });
        for i in 0..5u8 {
            let f = read_frame(&mut b).await.unwrap().unwrap();
            assert_eq!(f.payload, vec![i; 100]);
        }
        w.await.unwrap();
    }
}
