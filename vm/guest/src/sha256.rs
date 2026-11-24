//! SHA-256 for transfers and job identity, from the `sha2` crate: it picks the
//! CPU's SHA instructions at run time (ARMv8 SHA2 or x86 SHA-NI) and falls back
//! to portable code without them. The digests are the same either way.

use sha2::Digest;

#[derive(Clone, Default)]
pub struct Sha256(sha2::Sha256);

impl Sha256 {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub fn finalize(self) -> [u8; 32] {
        self.0.finalize().into()
    }

    pub fn hex(self) -> String {
        crate::util::hex(&self.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(data: &[u8]) -> String {
        let mut s = Sha256::new();
        s.update(data);
        s.hex()
    }

    #[test]
    fn vectors() {
        assert_eq!(
            h(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            h(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            h(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn million_a_in_odd_chunks() {
        let mut s = Sha256::new();
        let chunk = [b'a'; 997];
        let mut left = 1_000_000usize;
        while left > 0 {
            let n = left.min(chunk.len());
            s.update(&chunk[..n]);
            left -= n;
        }
        assert_eq!(
            s.hex(),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    // ---- the scalar implementation this replaced, kept as an independent reference ----

    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    #[derive(Clone)]
    pub struct Reference {
        h: [u32; 8],
        buf: [u8; 64],
        buf_len: usize,
        total: u64,
    }

    impl Default for Reference {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Reference {
        pub fn new() -> Self {
            Reference {
                h: [
                    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
                    0x1f83d9ab, 0x5be0cd19,
                ],
                buf: [0; 64],
                buf_len: 0,
                total: 0,
            }
        }

        fn block(&mut self, b: &[u8; 64]) {
            let mut w = [0u32; 64];
            for i in 0..16 {
                w[i] = u32::from_be_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let [mut a, mut b_, mut c, mut d, mut e, mut f, mut g, mut h] = self.h;
            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ (!e & g);
                let t1 = h
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b_) ^ (a & c) ^ (b_ & c);
                let t2 = s0.wrapping_add(maj);
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b_;
                b_ = a;
                a = t1.wrapping_add(t2);
            }
            for (x, y) in self.h.iter_mut().zip([a, b_, c, d, e, f, g, h]) {
                *x = x.wrapping_add(y);
            }
        }

        pub fn update(&mut self, mut data: &[u8]) {
            self.total += data.len() as u64;
            if self.buf_len > 0 {
                let take = (64 - self.buf_len).min(data.len());
                self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
                self.buf_len += take;
                data = &data[take..];
                if self.buf_len < 64 {
                    return;
                }
                let b = self.buf;
                self.block(&b);
                self.buf_len = 0;
            }
            while data.len() >= 64 {
                let mut b = [0u8; 64];
                b.copy_from_slice(&data[..64]);
                self.block(&b);
                data = &data[64..];
            }
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }

        pub fn finalize(mut self) -> [u8; 32] {
            let bits = self.total * 8;
            let mut pad = vec![0x80u8];
            let rem = (self.buf_len + 1) % 64;
            let zeros = if rem <= 56 { 56 - rem } else { 120 - rem };
            pad.extend(std::iter::repeat_n(0u8, zeros));
            pad.extend_from_slice(&bits.to_be_bytes());
            let total = self.total;
            self.update(&pad);
            self.total = total;
            let mut out = [0u8; 32];
            for (i, v) in self.h.iter().enumerate() {
                out[4 * i..4 * i + 4].copy_from_slice(&v.to_be_bytes());
            }
            out
        }
    }

    /// Every length from 0 to 300 (all padding cases), and a few chunkings of longer input.
    #[test]
    fn matches_the_scalar_reference() {
        let data: Vec<u8> = (0..200_000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 24) as u8)
            .collect();
        for len in (0..=300).chain([4095, 4096, 4097, 65_535, 65_536, 200_000]) {
            let mut a = Sha256::new();
            a.update(&data[..len]);
            let mut b = Reference::new();
            b.update(&data[..len]);
            assert_eq!(a.finalize(), b.finalize(), "len {len}");
        }
        for chunk in [1usize, 63, 64, 65, 1000, 65_536] {
            let mut a = Sha256::new();
            let mut b = Reference::new();
            for c in data.chunks(chunk) {
                a.update(c);
                b.update(c);
            }
            assert_eq!(a.finalize(), b.finalize(), "chunk {chunk}");
        }
    }

    /// `hash_prefix` resumes a transfer by cloning mid-stream state: the clone must continue alike.
    #[test]
    fn a_cloned_hasher_continues_independently() {
        let mut a = Sha256::new();
        a.update(b"hello ");
        let mut b = a.clone();
        a.update(b"world");
        b.update(b"there");
        assert_eq!(a.hex(), h(b"hello world"));
        assert_eq!(b.hex(), h(b"hello there"));
    }

    /// `cargo test --release -- --ignored --nocapture throughput`
    #[test]
    #[ignore = "benchmark"]
    fn throughput() {
        let data = vec![0x5au8; 64 << 20];
        for (name, f) in [
            (
                "sha2",
                Box::new(|d: &[u8]| {
                    let mut s = Sha256::new();
                    s.update(d);
                    s.finalize()
                }) as Box<dyn Fn(&[u8]) -> [u8; 32]>,
            ),
            (
                "scalar",
                Box::new(|d: &[u8]| {
                    let mut s = Reference::new();
                    s.update(d);
                    s.finalize()
                }),
            ),
        ] {
            f(&data); // warm up
            let mut best = f64::MAX;
            for _ in 0..5 {
                let t = std::time::Instant::now();
                std::hint::black_box(f(&data));
                best = best.min(t.elapsed().as_secs_f64());
            }
            println!(
                "{name}: {:.0} MiB/s",
                data.len() as f64 / 1_048_576.0 / best
            );
        }
    }
}
