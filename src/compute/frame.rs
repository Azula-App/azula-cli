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
        let mut out = encode_head(&self.header, self.payload.len(), self.payload.len())?;
        out.extend_from_slice(&self.payload);
        Ok(out)
    }
}

/// Everything before the payload: both lengths and the header. Checks both
/// limits. `spare` is room to leave for whatever the caller appends.
fn encode_head(header: &Map<String, Value>, payload_len: usize, spare: usize) -> Result<Vec<u8>, FrameError> {
    let h = serde_json::to_vec(header).map_err(|e| FrameError::Protocol(e.to_string()))?;
    if h.is_empty() || h.len() > MAX_HEADER {
        return Err(FrameError::Protocol("header length out of range".into()));
    }
    if payload_len > MAX_PAYLOAD {
        return Err(FrameError::Protocol("payload length out of range".into()));
    }
    let mut out = Vec::with_capacity(8 + h.len() + spare);
    out.extend_from_slice(&(h.len() as u32).to_be_bytes());
    out.extend_from_slice(&(payload_len as u32).to_be_bytes());
    out.extend_from_slice(&h);
    Ok(out)
}

/// Write one frame (a single `write_all`, so frames never interleave) and flush.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &Frame) -> Result<(), FrameError> {
    let buf = frame.encode()?;
    w.write_all(&buf).await.map_err(FrameError::Io)?;
    w.flush().await.map_err(FrameError::Io)
}

/// [`write_frame`] for a payload the caller keeps: the same bytes on the wire,
/// with `payload` handed to the writer as it is rather than copied into an
/// encoded frame first. That takes two writes, which the exclusive `w` keeps
/// together; if a limit is exceeded, neither happens.
pub async fn write_frame_parts<W: AsyncWrite + Unpin>(w: &mut W, header: &Map<String, Value>, payload: &[u8]) -> Result<(), FrameError> {
    let head = encode_head(header, payload.len(), 0)?;
    w.write_all(&head).await.map_err(FrameError::Io)?;
    w.write_all(payload).await.map_err(FrameError::Io)?;
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

    // --- write_frame_parts ---------------------------------------------------

    /// A writer that takes at most `step` bytes at a time, is not ready every
    /// other call, and can stop: after `limit` bytes it fails, or accepts nothing.
    struct Choppy {
        out: Vec<u8>,
        step: usize,
        limit: usize,
        fail: bool,
        ready: bool,
        /// Address of each byte run it was handed (only the part it took).
        taken: Vec<(usize, usize)>,
    }

    impl Choppy {
        fn new(step: usize) -> Self {
            Choppy { out: Vec::new(), step, limit: usize::MAX, fail: false, ready: false, taken: Vec::new() }
        }
    }

    impl AsyncWrite for Choppy {
        fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<io::Result<usize>> {
            self.ready = !self.ready;
            if !self.ready {
                cx.waker().wake_by_ref();
                return std::task::Poll::Pending;
            }
            let n = buf.len().min(self.step).min(self.limit - self.out.len());
            if n == 0 && self.fail {
                return std::task::Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
            }
            self.out.extend_from_slice(&buf[..n]);
            self.taken.push((buf.as_ptr() as usize, n));
            std::task::Poll::Ready(Ok(n))
        }
        fn poll_flush(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// xorshift64: random enough for headers and sizes, and the same every run.
    struct Rng(u64);

    impl Rng {
        fn below(&mut self, n: usize) -> usize {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 % n as u64) as usize
        }

        fn header(&mut self) -> Map<String, Value> {
            let mut m = Map::new();
            m.insert("t".into(), json!(["data", "stdin", "eof", "x"][self.below(4)]));
            for i in 0..self.below(6) {
                let v = match self.below(5) {
                    0 => json!(self.0),
                    1 => json!("\u{1F980} \"quoted\"\n\u{0}".repeat(self.below(4))),
                    2 => json!([null, true, {"k": self.below(9)}]),
                    3 => json!("y".repeat(self.below(2000))),
                    _ => Value::Null,
                };
                m.insert(format!("k{i}"), v);
            }
            m
        }
    }

    #[tokio::test]
    async fn parts_put_the_same_bytes_on_the_wire_as_encode() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let fixed = [0, 1, 2, 511, 512, 513, 65_536, 512 * 1024, MAX_PAYLOAD - 1, MAX_PAYLOAD];
        for i in 0..120 {
            let len = fixed.get(i).copied().unwrap_or_else(|| rng.below(20_000));
            let payload: Vec<u8> = (0..len).map(|j| (j.wrapping_mul(131) ^ i) as u8).collect();
            let header = rng.header();
            let want = Frame { header: header.clone(), payload: payload.clone() }.encode().unwrap();
            // One byte at a time for small frames, otherwise odd sizes that straddle the header/payload seam.
            let step = if len < 600 { 1 + rng.below(5) } else { 1 + rng.below(9_000) };
            for step in [step, usize::MAX] {
                let mut w = Choppy::new(step);
                write_frame_parts(&mut w, &header, &payload).await.unwrap();
                assert!(w.out == want, "frame {i}: {len} byte payload, {step} bytes per write");
            }
        }
    }

    #[tokio::test]
    async fn parts_hand_over_the_payload_itself_not_a_copy() {
        let payload = vec![7u8; 512 * 1024];
        let header = Frame::of_type("data").header;
        let own = payload.as_ptr() as usize..payload.as_ptr() as usize + payload.len();
        let from_payload = |w: &Choppy| w.taken.iter().filter(|(at, n)| own.contains(at) && at + n <= own.end).map(|(_, n)| n).sum::<usize>();

        let mut w = Choppy::new(100_000);
        write_frame_parts(&mut w, &header, &payload).await.unwrap();
        assert_eq!(from_payload(&w), payload.len(), "every payload byte comes from the caller's buffer");

        // What this replaces: the writer only ever saw the encoded copy.
        let mut w = Choppy::new(100_000);
        write_frame(&mut w, &Frame { header, payload: payload.clone() }).await.unwrap();
        assert_eq!(from_payload(&w), 0);
    }

    #[tokio::test]
    async fn parts_refuse_what_encode_refuses_before_writing_anything() {
        let data = Frame::of_type("data").header;
        let mut huge = data.clone();
        huge.insert("pad".into(), json!("x".repeat(MAX_HEADER)));
        for (header, payload) in [(&data, vec![0; MAX_PAYLOAD + 1]), (&huge, vec![0; 3])] {
            let mut w = Choppy::new(usize::MAX);
            assert!(matches!(write_frame_parts(&mut w, header, &payload).await, Err(FrameError::Protocol(_))));
            assert!(w.out.is_empty(), "a refused frame must not leave a partial one on the stream");
        }
    }

    #[tokio::test]
    async fn parts_report_a_writer_that_fails_or_stops() {
        let header = Frame::of_type("data").header;
        let payload = vec![3u8; 100];
        let whole = Frame { header: header.clone(), payload: payload.clone() }.encode().unwrap();
        let head = whole.len() - payload.len();
        // In the header, on the seam, one byte into the payload, one byte short of the end.
        for limit in [0, 5, head - 1, head, head + 1, whole.len() - 1] {
            for (fail, kind) in [(true, io::ErrorKind::ConnectionReset), (false, io::ErrorKind::WriteZero)] {
                let mut w = Choppy { limit, fail, ..Choppy::new(7) };
                match write_frame_parts(&mut w, &header, &payload).await {
                    Err(FrameError::Io(e)) => assert_eq!(e.kind(), kind, "stopped at {limit}"),
                    other => panic!("stopped at {limit}: {other:?}"),
                }
                assert_eq!(w.out, whole[..limit]);
            }
        }
    }
}
