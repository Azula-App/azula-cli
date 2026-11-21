//! Frame codec shared by every hop (see vm/README.md section 1).

use std::io::{self, Read, Write};

use serde_json::{Map, Value};

pub const MAX_HEADER: usize = 65_536;
pub const MAX_PAYLOAD: usize = 1_048_576;

#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    pub t: String,
    pub header: Map<String, Value>,
    pub payload: Vec<u8>,
}

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Serialize one frame. Errors if either part exceeds its limit.
pub fn encode(header: &Value, payload: &[u8]) -> io::Result<Vec<u8>> {
    let h = serde_json::to_vec(header).map_err(|e| bad(e.to_string()))?;
    if h.is_empty() || h.len() > MAX_HEADER {
        return Err(bad("header length out of range"));
    }
    if payload.len() > MAX_PAYLOAD {
        return Err(bad("payload length out of range"));
    }
    let mut buf = Vec::with_capacity(8 + h.len() + payload.len());
    buf.extend_from_slice(&(h.len() as u32).to_be_bytes());
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(&h);
    buf.extend_from_slice(payload);
    Ok(buf)
}

pub fn write_frame<W: Write>(w: &mut W, header: &Value, payload: &[u8]) -> io::Result<()> {
    let buf = encode(header, payload)?;
    w.write_all(&buf)?;
    w.flush()
}

/// Read one frame. `Ok(None)` means clean EOF before the first byte.
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Option<Frame>> {
    let mut len = [0u8; 8];
    let mut got = 0;
    while got < len.len() {
        match r.read(&mut len[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let hl = u32::from_be_bytes([len[0], len[1], len[2], len[3]]) as usize;
    let pl = u32::from_be_bytes([len[4], len[5], len[6], len[7]]) as usize;
    if hl == 0 || hl > MAX_HEADER {
        return Err(bad("header length out of range"));
    }
    if pl > MAX_PAYLOAD {
        return Err(bad("payload length out of range"));
    }
    let mut hb = vec![0u8; hl];
    r.read_exact(&mut hb)?;
    let mut payload = vec![0u8; pl];
    r.read_exact(&mut payload)?;
    let text = std::str::from_utf8(&hb).map_err(|_| bad("header is not UTF-8"))?;
    let header = match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(m)) => m,
        Ok(_) => return Err(bad("header is not a JSON object")),
        Err(e) => return Err(bad(format!("header is not JSON: {e}"))),
    };
    let t = match header.get("t") {
        Some(Value::String(s)) => s.clone(),
        _ => return Err(bad("header lacks string field \"t\"")),
    };
    Ok(Some(Frame { t, header, payload }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const VECTOR: [u8; 24] = [
        0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x02, 0x7b, 0x22, 0x74, 0x22, 0x3a, 0x22, 0x73,
        0x74, 0x64, 0x6f, 0x75, 0x74, 0x22, 0x7d, 0x68, 0x69,
    ];

    #[test]
    fn test_vector_encode() {
        assert_eq!(encode(&json!({"t":"stdout"}), b"hi").unwrap(), VECTOR);
    }

    #[test]
    fn test_vector_decode() {
        let f = read_frame(&mut &VECTOR[..]).unwrap().unwrap();
        assert_eq!(f.t, "stdout");
        assert_eq!(f.payload, b"hi");
    }

    #[test]
    fn clean_eof_is_none() {
        assert!(read_frame(&mut &b""[..]).unwrap().is_none());
        assert!(read_frame(&mut &b"\0\0"[..]).is_err());
    }

    #[test]
    fn rejects_bad_lengths() {
        let zero_header = [0u8; 8];
        assert!(read_frame(&mut &zero_header[..]).is_err());
        let mut v = (MAX_HEADER as u32 + 1).to_be_bytes().to_vec();
        v.extend_from_slice(&[0, 0, 0, 0]);
        assert!(read_frame(&mut &v[..]).is_err());
        let mut v = 2u32.to_be_bytes().to_vec();
        v.extend_from_slice(&(MAX_PAYLOAD as u32 + 1).to_be_bytes());
        assert!(read_frame(&mut &v[..]).is_err());
        assert!(encode(&json!({"t":"x"}), &vec![0u8; MAX_PAYLOAD + 1]).is_err());
        assert!(encode(&json!({"t":"x"}), &vec![0u8; MAX_PAYLOAD]).is_ok());
    }

    #[test]
    fn rejects_bad_headers() {
        for h in [
            &b"[1]"[..],
            b"{\"x\":1}",
            b"{\"t\":1}",
            b"nope",
            b"\xff\xfe",
        ] {
            let mut v = (h.len() as u32).to_be_bytes().to_vec();
            v.extend_from_slice(&[0, 0, 0, 0]);
            v.extend_from_slice(h);
            assert!(read_frame(&mut &v[..]).is_err(), "{h:?}");
        }
    }
}
