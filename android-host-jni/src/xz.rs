//! A pull-based xz decoder (liblzma, threaded) for unpacking the guest image on the phone. Java
//! class `app.azula.vmhost.NativeXz`, static native methods:
//!
//! ```java
//! static native int  capabilities();                     // CAP_* bits
//! static native long create(int threads, long memLimit); // a handle, or 0
//! static native long decode(long handle, byte[] in, int inOff, int inLen,
//!                           byte[] out, int outOff, int outLen, boolean finish);
//! static native void destroy(long handle);
//! ```
//!
//! `decode` returns a negative [`Fail`] code, or [`Step::pack`]'s `consumed | produced << 31 |
//! END << 62`. It may take less input and give less output than asked; a call that does neither
//! wants more input (or `finish`). `finish` says that no input follows what this call passes.
//! The first failure sticks.
//!
//! It accepts what the Java decoder it stands in for (`org.tukaani.xz.XZInputStream`) accepts:
//! concatenated streams, and zero padding after a stream in multiples of four bytes.
//!
//! Debian compresses the image with `xz -T`, so it holds dozens of independent 24 MiB blocks with
//! their sizes in the block headers, and [`create`]'s `threads` decode that many at once. A file
//! that is one block decodes on one thread.
//!
//! Handles are looked up in a table, never dereferenced, so a stale or repeated one is
//! [`Fail::Closed`] rather than a crash.

use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError};

use jni::objects::{JByteArray, JClass};
use jni::sys::{jboolean, jbyte, jint, jlong, JNI_FALSE};
use jni::JNIEnv;
use liblzma::stream::{Action, Error, MtStreamBuilder, Status, Stream};

/// `capabilities()`: this library decodes xz.
const CAP_DECODE: jint = 1;
/// `capabilities()`: `create`'s `threads` is honoured.
const CAP_THREADS: jint = 2;

/// The most input a `decode` call takes, and the most output it gives.
const CHUNK_MAX: usize = 1 << 20;

/// Far more threads than a phone has cores; liblzma allocates per thread.
const THREADS_MAX: u32 = 32;

/// Never allocate more than this, whatever a block header asks for: the app decodes the archive
/// while it downloads, before its checksum is known.
const MEMLIMIT_STOP: u64 = 512 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
enum Fail {
    /// Not an xz file.
    Format = -1,
    Corrupt = -2,
    /// The input ended inside a stream.
    Truncated = -3,
    /// Out of memory, or [`MEMLIMIT_STOP`].
    Memory = -4,
    /// A filter or option this decoder doesn't know.
    Unsupported = -5,
    /// No such handle: destroyed, or never created.
    Closed = -6,
    /// A null array, or a range outside it.
    Args = -7,
    Internal = -8,
}

impl From<Error> for Fail {
    fn from(e: Error) -> Self {
        match e {
            Error::Data => Self::Corrupt,
            Error::Format => Self::Format,
            Error::Mem | Error::MemLimit => Self::Memory,
            Error::Options | Error::NoCheck | Error::UnsupportedCheck => Self::Unsupported,
            Error::Program => Self::Internal,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Step {
    consumed: usize,
    produced: usize,
    /// The whole input is decoded; only ever set on `finish`.
    end: bool,
}

impl Step {
    /// Both counts are at most [`CHUNK_MAX`], so 31 bits each is plenty.
    fn pack(self) -> jlong {
        self.consumed as jlong | (self.produced as jlong) << 31 | (self.end as jlong) << 62
    }
}

enum At {
    /// Inside a stream; `first` until one has ended.
    Stream { first: bool },
    /// After a stream, with this many zero bytes of padding seen.
    Padding(u64),
    Failed(Fail),
}

struct Decoder {
    threads: u32,
    mem_limit: u64,
    stream: Stream,
    at: At,
}

impl Decoder {
    fn new(threads: u32, mem_limit: u64) -> Result<Self, Fail> {
        let threads = threads.clamp(1, THREADS_MAX);
        Ok(Self { threads, mem_limit, stream: Self::open(threads, mem_limit)?, at: At::Stream { first: true } })
    }

    /// The threaded decoder, or the plain one if that can't be set up.
    fn open(threads: u32, mem_limit: u64) -> Result<Stream, Fail> {
        if threads > 1 {
            // `mem_limit` is soft: it bounds how many blocks are in flight, and a block too big
            // for it decodes alone.
            let mt = MtStreamBuilder::new().threads(threads).memlimit_threading(mem_limit).memlimit_stop(MEMLIMIT_STOP).decoder();
            if let Ok(s) = mt {
                return Ok(s);
            }
        }
        Ok(Stream::new_stream_decoder(MEMLIMIT_STOP, 0)?)
    }

    fn decode(&mut self, input: &[u8], out: &mut [u8], finish: bool) -> Result<Step, Fail> {
        let r = self.advance(input, out, finish);
        if let Err(f) = r {
            self.at = At::Failed(f);
        }
        r
    }

    fn advance(&mut self, input: &[u8], out: &mut [u8], finish: bool) -> Result<Step, Fail> {
        let mut step = Step::default();
        loop {
            match self.at {
                At::Failed(f) => return Err(f),
                At::Stream { first } => {
                    let (in0, out0) = (self.stream.total_in(), self.stream.total_out());
                    let action = if finish { Action::Finish } else { Action::Run };
                    let status = self.stream.process(&input[step.consumed..], &mut out[step.produced..], action);
                    step.consumed += (self.stream.total_in() - in0) as usize;
                    step.produced += (self.stream.total_out() - out0) as usize;
                    match status {
                        Ok(Status::StreamEnd) => self.at = At::Padding(0),
                        // No input, room for output, and still nothing to give.
                        Ok(Status::MemNeeded) if finish && step.produced < out.len() => return Err(Fail::Truncated),
                        Ok(_) => return Ok(step),
                        // What follows a stream isn't a stream.
                        Err(Error::Format) if !first => return Err(Fail::Corrupt),
                        Err(e) => return Err(e.into()),
                    }
                }
                At::Padding(seen) => {
                    let rest = &input[step.consumed..];
                    let zeros = rest.iter().take_while(|b| **b == 0).count();
                    step.consumed += zeros;
                    let seen = seen + zeros as u64;
                    self.at = At::Padding(seen);
                    let more = zeros < rest.len();
                    if !more && !finish {
                        return Ok(step);
                    }
                    if !seen.is_multiple_of(4) {
                        return Err(Fail::Corrupt);
                    }
                    if !more {
                        step.end = true;
                        return Ok(step);
                    }
                    self.stream = Self::open(self.threads, self.mem_limit)?;
                    self.at = At::Stream { first: false };
                }
            }
        }
    }
}

/// A decoder and the buffers its bytes cross JNI in. The arrays are copied, not pinned:
/// liblzma can block on its worker threads, and a pinned array would stall the collector.
struct Handle {
    decoder: Decoder,
    input: Vec<jbyte>,
    output: Vec<jbyte>,
}

static HANDLES: LazyLock<Mutex<HashMap<i64, Arc<Mutex<Handle>>>>> = LazyLock::new(Mutex::default);
static NEXT_HANDLE: AtomicI64 = AtomicI64::new(1);

fn handles() -> MutexGuard<'static, HashMap<i64, Arc<Mutex<Handle>>>> {
    HANDLES.lock().unwrap_or_else(PoisonError::into_inner)
}

fn create(threads: jint, mem_limit: jlong) -> Result<i64, Fail> {
    let decoder = Decoder::new(threads.max(1) as u32, mem_limit.max(1) as u64)?;
    let id = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    handles().insert(id, Arc::new(Mutex::new(Handle { decoder, input: Vec::new(), output: Vec::new() })));
    Ok(id)
}

fn find(id: i64) -> Result<Arc<Mutex<Handle>>, Fail> {
    handles().get(&id).cloned().ok_or(Fail::Closed)
}

/// A `decode` under way on another thread finishes first; the decoder is freed after it.
fn destroy(id: i64) {
    let gone = handles().remove(&id);
    drop(gone); // Outside the table's lock: it joins the worker threads.
}

/// `off..off + len` of an array of `cap` elements, or [`Fail::Args`].
fn range(off: jint, len: jint, cap: jint) -> Result<usize, Fail> {
    match off.checked_add(len) {
        Some(end) if off >= 0 && len >= 0 && end <= cap => Ok(len as usize),
        _ => Err(Fail::Args),
    }
}

fn as_u8(b: &[jbyte]) -> &[u8] {
    // SAFETY: i8 and u8 have the same layout.
    unsafe { slice::from_raw_parts(b.as_ptr().cast(), b.len()) }
}

fn as_u8_mut(b: &mut [jbyte]) -> &mut [u8] {
    // SAFETY: as above, and the borrow is exclusive.
    unsafe { slice::from_raw_parts_mut(b.as_mut_ptr().cast(), b.len()) }
}

/// One Java array's range, as the caller gave it.
struct Span<'a, 'b> {
    array: &'a JByteArray<'b>,
    off: jint,
    len: jint,
}

impl Span<'_, '_> {
    /// How many bytes of it one call handles. Checked here so the copies can't throw.
    fn chunk(&self, env: &JNIEnv) -> Result<usize, Fail> {
        if self.array.is_null() {
            return Err(Fail::Args);
        }
        let cap = env.get_array_length(self.array).map_err(|_| Fail::Args)?;
        Ok(range(self.off, self.len, cap)?.min(CHUNK_MAX))
    }
}

fn decode(env: &JNIEnv, id: i64, input: Span, output: Span, finish: bool) -> Result<Step, Fail> {
    let (in_len, out_len) = (input.chunk(env)?, output.chunk(env)?);
    let handle = find(id)?;
    let mut h = handle.lock().map_err(|_| Fail::Internal)?;
    let h = &mut *h;
    h.input.resize(in_len, 0);
    h.output.resize(out_len, 0);
    env.get_byte_array_region(input.array, input.off, &mut h.input).map_err(|_| Fail::Args)?;
    // A clipped input isn't the last of it.
    let last = finish && in_len == input.len as usize;
    let step = h.decoder.decode(as_u8(&h.input), as_u8_mut(&mut h.output), last)?;
    env.set_byte_array_region(output.array, output.off, &h.output[..step.produced]).map_err(|_| Fail::Args)?;
    Ok(step)
}

/// Run `f`; a panic is [`Fail::Internal`], never an unwind into the JVM.
fn guarded<T>(f: impl FnOnce() -> Result<T, Fail>) -> Result<T, Fail> {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(Err(Fail::Internal))
}

#[no_mangle]
pub extern "system" fn Java_app_azula_vmhost_NativeXz_capabilities(_: JNIEnv, _: JClass) -> jint {
    CAP_DECODE | CAP_THREADS
}

#[no_mangle]
pub extern "system" fn Java_app_azula_vmhost_NativeXz_create(_: JNIEnv, _: JClass, threads: jint, mem_limit: jlong) -> jlong {
    guarded(|| create(threads, mem_limit)).unwrap_or(0)
}

#[no_mangle]
#[allow(clippy::too_many_arguments)] // The JNI signature.
pub extern "system" fn Java_app_azula_vmhost_NativeXz_decode(
    env: JNIEnv,
    _: JClass,
    handle: jlong,
    input: JByteArray,
    in_off: jint,
    in_len: jint,
    output: JByteArray,
    out_off: jint,
    out_len: jint,
    finish: jboolean,
) -> jlong {
    let input = Span { array: &input, off: in_off, len: in_len };
    let output = Span { array: &output, off: out_off, len: out_len };
    match guarded(|| decode(&env, handle, input, output, finish != JNI_FALSE)) {
        Ok(step) => step.pack(),
        Err(f) => f as jlong,
    }
}

#[no_mangle]
pub extern "system" fn Java_app_azula_vmhost_NativeXz_destroy(_: JNIEnv, _: JClass, handle: jlong) {
    let _ = guarded(|| {
        destroy(handle);
        Ok(())
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use liblzma::stream::Check;

    const MEM: u64 = 64 << 20;
    /// Every test input decodes the same on the plain and the threaded decoder.
    const THREADS: [u32; 3] = [1, 2, 4];

    /// Compressible but not trivial: pseudo-random bytes in runs.
    fn data(len: usize) -> Vec<u8> {
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let mut out = Vec::with_capacity(len + 64);
        while out.len() < len {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let run = (x >> 40) as usize % 40 + 1;
            if x & 3 == 0 {
                out.resize(out.len() + run, (x >> 8) as u8);
            } else {
                out.extend_from_slice(&x.to_le_bytes());
            }
        }
        out.truncate(len);
        out
    }

    fn encode(mut s: Stream, plain: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(plain.len() * 2 + 4096);
        let mut at = 0;
        loop {
            let before = s.total_in();
            let status = s.process_vec(&plain[at..], &mut out, Action::Finish).unwrap();
            at += (s.total_in() - before) as usize;
            if matches!(status, Status::StreamEnd) {
                return out;
            }
            out.reserve(4096);
        }
    }

    /// `xz -T`'s layout: independent blocks with their sizes in the headers.
    fn multi_block(plain: &[u8], block: u64) -> Vec<u8> {
        encode(MtStreamBuilder::new().threads(2).block_size(block).preset(1).check(Check::Crc64).encoder().unwrap(), plain)
    }

    fn single_block(plain: &[u8]) -> Vec<u8> {
        encode(Stream::new_easy_encoder(1, Check::Crc64).unwrap(), plain)
    }

    /// Feeds `xz` the way the app does: `in_chunk` at a time, then `finish` with nothing left.
    fn run(d: &mut Decoder, xz: &[u8], in_chunk: usize, out_chunk: usize) -> Result<Vec<u8>, Fail> {
        let mut out = Vec::new();
        let mut buf = vec![0; out_chunk];
        let (mut at, mut end) = (0, 0);
        let mut idle = 0;
        loop {
            if at == end && end < xz.len() {
                end = (end + in_chunk).min(xz.len());
            }
            let last = at == end;
            let s = d.decode(&xz[at..end], &mut buf, last)?;
            at += s.consumed;
            out.extend_from_slice(&buf[..s.produced]);
            if s.end {
                assert_eq!(at, xz.len(), "ended with input left");
                return Ok(out);
            }
            idle = if s.consumed + s.produced == 0 { idle + 1 } else { 0 };
            assert!(idle < 8, "no progress and no error");
        }
    }

    fn decode_all(threads: u32, xz: &[u8], in_chunk: usize, out_chunk: usize) -> Result<Vec<u8>, Fail> {
        run(&mut Decoder::new(threads, MEM).unwrap(), xz, in_chunk, out_chunk)
    }

    #[test]
    fn round_trips_multi_and_single_block_files() {
        let plain = data(3 << 20);
        for xz in [multi_block(&plain, 256 << 10), single_block(&plain)] {
            for t in THREADS {
                assert!(decode_all(t, &xz, 64 << 10, 256 << 10).unwrap() == plain, "threads {t}");
            }
        }
    }

    #[test]
    fn the_multi_block_fixture_really_has_blocks() {
        // Its header promises both sizes, which is what lets liblzma decode blocks in parallel.
        let xz = multi_block(&data(1 << 20), 128 << 10);
        assert_eq!(xz[13] & 0xc0, 0xc0);
        let one = single_block(&data(1 << 20));
        assert_eq!(one[13] & 0xc0, 0);
    }

    #[test]
    fn tiny_chunks_work() {
        let plain = data(20_000);
        for xz in [multi_block(&plain, 4096), single_block(&plain)] {
            for t in THREADS {
                for (i, o) in [(1, 1), (1, 4096), (4096, 1), (3, 7), (13, 1000)] {
                    assert!(decode_all(t, &xz, i, o).unwrap() == plain, "threads {t} chunks {i}/{o}");
                }
            }
        }
    }

    #[test]
    fn an_empty_file_decodes_to_nothing() {
        for t in THREADS {
            assert_eq!(decode_all(t, &single_block(b""), 64, 64), Ok(Vec::new()));
        }
    }

    #[test]
    fn a_memory_limit_below_one_block_still_decodes() {
        let plain = data(1 << 20);
        let xz = multi_block(&plain, 256 << 10);
        let mut d = Decoder::new(4, 1).unwrap();
        assert!(run(&mut d, &xz, 8192, 8192).unwrap() == plain);
    }

    #[test]
    fn truncated_input_is_an_error_at_every_cut() {
        let plain = data(40_000);
        for xz in [multi_block(&plain, 8192), single_block(&plain)] {
            for t in THREADS {
                for cut in (0..xz.len()).step_by(97).chain(xz.len() - 40..xz.len()) {
                    assert_eq!(decode_all(t, &xz[..cut], 4096, 4096).unwrap_err(), Fail::Truncated, "threads {t} cut {cut} of {}", xz.len());
                }
            }
        }
    }

    #[test]
    fn corrupt_input_is_an_error_at_every_byte() {
        let plain = data(6_000);
        for xz in [multi_block(&plain, 2048), single_block(&plain)] {
            for t in THREADS {
                for at in 0..xz.len() {
                    let mut bad = xz.clone();
                    bad[at] ^= 0x55;
                    assert!(decode_all(t, &bad, 1024, 1024).is_err(), "threads {t} byte {at} of {}", xz.len());
                }
            }
        }
    }

    #[test]
    fn a_failure_sticks() {
        let mut d = Decoder::new(2, MEM).unwrap();
        let mut buf = [0; 64];
        assert_eq!(d.decode(b"this is not an xz file", &mut buf, false), Err(Fail::Format));
        assert_eq!(d.decode(&single_block(b"fine"), &mut buf, true), Err(Fail::Format));
    }

    #[test]
    fn garbage_after_the_stream_is_corrupt() {
        let plain = data(5_000);
        for t in THREADS {
            for tail in [&b"garbage after the end"[..], b"\x01", b"\0\0\0\0x"] {
                let mut xz = multi_block(&plain, 1024);
                xz.extend_from_slice(tail);
                let e = decode_all(t, &xz, 512, 512).unwrap_err();
                // A lone byte could still be the start of another stream.
                assert!(e == Fail::Corrupt || (tail.len() < 12 && e == Fail::Truncated), "threads {t} tail {tail:?}: {e:?}");
            }
        }
    }

    #[test]
    fn zero_padding_and_concatenated_streams_are_accepted() {
        let (a, b) = (data(5_000), data(3_000));
        for t in THREADS {
            let mut xz = multi_block(&a, 1024);
            xz.extend_from_slice(&[0; 8]);
            assert!(decode_all(t, &xz, 777, 777).unwrap() == a);
            xz.extend_from_slice(&single_block(&b));
            xz.extend_from_slice(&[0; 4]);
            for chunk in [1, 5, 4096, 1 << 16] {
                assert!(decode_all(t, &xz, chunk, 4096).unwrap() == [&a[..], &b].concat(), "threads {t} chunk {chunk}");
            }
            xz.push(0);
            assert_eq!(decode_all(t, &xz, 4096, 4096).unwrap_err(), Fail::Corrupt, "padding isn't a multiple of four");
        }
    }

    #[test]
    fn a_whole_file_in_one_finishing_call_works() {
        let plain = data(100_000);
        let xz = multi_block(&plain, 16 << 10);
        let mut out = vec![0; plain.len() + 1];
        for t in THREADS {
            let s = Decoder::new(t, MEM).unwrap().decode(&xz, &mut out, true).unwrap();
            assert_eq!(s, Step { consumed: xz.len(), produced: plain.len(), end: true });
            assert!(out[..plain.len()] == plain);
        }
    }

    #[test]
    fn a_huge_dictionary_hits_the_memory_cap_instead_of_allocating() {
        // Dictionary size code 40 is 4 GiB. Rewrite the block header's LZMA2 property and its CRC.
        let mut xz = single_block(&data(1000));
        let len = (xz[12] as usize + 1) * 4;
        let at = (12..12 + len).find(|&i| xz[i] == 0x21 && xz[i + 1] == 1).unwrap() + 2;
        xz[at] = 40;
        let crc = crc32(&xz[12..12 + len - 4]);
        xz[12 + len - 4..12 + len].copy_from_slice(&crc.to_le_bytes());
        for t in THREADS {
            assert_eq!(decode_all(t, &xz, 4096, 4096).unwrap_err(), Fail::Memory, "threads {t}");
        }
    }

    fn crc32(b: &[u8]) -> u32 {
        !b.iter().fold(!0u32, |c, &x| (0..8).fold(c ^ x as u32, |c, _| if c & 1 == 1 { c >> 1 ^ 0xedb8_8320 } else { c >> 1 }))
    }

    #[test]
    fn handles_survive_double_destroy_and_use_after_destroy() {
        let id = create(4, MEM as jlong).unwrap();
        assert!(find(id).is_ok());
        destroy(id);
        destroy(id);
        assert_eq!(find(id).err(), Some(Fail::Closed));
        for bogus in [0, -1, i64::MAX, i64::MIN] {
            destroy(bogus);
            assert_eq!(find(bogus).err(), Some(Fail::Closed));
        }
        // A decode that already holds it isn't pulled out from under.
        let id = create(4, MEM as jlong).unwrap();
        let held = find(id).unwrap();
        destroy(id);
        let plain = data(50_000);
        assert!(run(&mut held.lock().unwrap().decoder, &multi_block(&plain, 8192), 4096, 4096).unwrap() == plain);
    }

    #[test]
    fn create_clamps_silly_arguments() {
        for (t, m) in [(0, 0), (-5, -5), (jint::MAX, jlong::MAX)] {
            let id = create(t, m).unwrap();
            destroy(id);
        }
    }

    #[test]
    fn dropping_a_decoder_mid_stream_stops_its_threads() {
        let xz = multi_block(&data(4 << 20), 256 << 10);
        let mut d = Decoder::new(4, MEM).unwrap();
        d.decode(&xz[..xz.len() / 2], &mut [0; 100], false).unwrap();
    }

    #[test]
    fn ranges_are_checked() {
        assert_eq!(range(0, 10, 10), Ok(10));
        assert_eq!(range(10, 0, 10), Ok(0));
        for (o, l, c) in [(-1, 5, 10), (0, -1, 10), (6, 5, 10), (jint::MAX, 1, 10), (1, jint::MAX, 10)] {
            assert_eq!(range(o, l, c), Err(Fail::Args));
        }
    }

    #[test]
    fn a_panic_is_an_error() {
        assert_eq!(guarded::<()>(|| panic!("boom")), Err(Fail::Internal));
    }

    #[test]
    fn steps_pack_into_a_non_negative_long() {
        let s = Step { consumed: CHUNK_MAX, produced: CHUNK_MAX, end: true }.pack();
        assert!(s > 0);
        assert_eq!(s & 0x7fff_ffff, CHUNK_MAX as i64);
        assert_eq!(s >> 31 & 0x7fff_ffff, CHUNK_MAX as i64);
        assert_eq!(s >> 62, 1);
        assert_eq!(Step::default().pack(), 0);
    }
}
