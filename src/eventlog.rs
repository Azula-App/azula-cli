//! Per-device append-only signed log entry codec, chain verification, and the
//! cross-device total-order comparator that the state fold depends on.
//!
//! See `azula-docs/openspec/changes/multi-device-identity/specs/account-sync/spec.md`
//! for the normative requirements (`design.md` section 4 restates the same
//! layout; where the two differ, `spec.md` is the intent).
//!
//! Wire layout (all integers big-endian):
//!
//! ```text
//! offset  size  field
//! 0       1     version (0x01)
//! 1       1     kind (see `Kind`)
//! 2       32    device_pk (author device public key)
//! 34      8     seq (u64, per-device, first entry 1, strictly +1)
//! 42      8     lamport (u64)
//! 50      8     ts_ms (u64 unix milliseconds; display only, never ordering)
//! 58      32    prev_hash (SHA-256 of the previous entry's full bytes; all
//!               zeros at seq 1)
//! 90      4     body_len (u32)
//! 94      n     body (UTF-8 JSON, kind-specific)
//! 94+n    64    signature, Ed25519 by the device key over [0, 94+n)
//! ```
//!
//! Entries are transported base64 inside JSON sync frames (`SyncEntries`) —
//! see [`LogEntry::to_base64`]/[`LogEntry::from_base64`] alongside the raw
//! [`LogEntry::to_bytes`]/[`LogEntry::from_bytes`] codec. There is no `"az…"`
//! string form for entries (unlike `certs.rs`'s payloads): they never leave
//! the sync protocol as a standalone shareable token.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use iroh::{PublicKey, SecretKey, Signature};
use sha2::{Digest, Sha256};

const VERSION: u8 = 1;
const SIGNATURE_LEN: usize = 64;
const PREV_HASH_LEN: usize = 32;
/// version(1) + kind(1) + device_pk(32) + seq(8) + lamport(8) + ts_ms(8) +
/// prev_hash(32) + body_len(4), i.e. everything before the variable-length
/// body. `1+1+32+8+8+8+32+4 = 94`.
const HEADER_LEN: usize = 94;

// ---------------------------------------------------------------------------
// Event kind
// ---------------------------------------------------------------------------

/// A log entry's `kind` byte. Unknown bytes are preserved verbatim (never
/// rejected) so newer siblings can introduce new kinds without breaking
/// older devices — they store and re-serve entries of a kind they don't
/// recognize, just excluding them from their own derived state (the fold).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// `{conversation, text, id?}`
    MessageOut,
    /// `{conversation, from_device_pk, text, id?}`
    MessageIn,
    /// `{conversation, up_to_lamport}`
    ReadMarker,
    /// `{root_pk | endpoint_id, name?}`
    ContactAdd,
    /// same body shape as `ContactAdd`
    ContactRemove,
    /// `{cert}`
    DeviceAdd,
    /// `{revocation}`
    DeviceRevoke,
    /// `{name?, description?}`
    ProfileUpdate,
    /// `{conversation, text, id?, from_name?}` — relay-carried agent chat,
    /// inbound to the identity (cli-multi-session-relay's relay capability:
    /// a session delivered this to the relay while the phone was
    /// unreachable). `conversation` is the SESSION's public key in hex, not
    /// a contact root/endpoint id like the peer-chat kinds above.
    AgentIn,
    /// `{conversation, text, id?}` — the identity's reply to an agent
    /// conversation, keyed the same way as [`Kind::AgentIn`].
    AgentOut,
    /// Any kind byte this build doesn't recognize.
    Unknown(u8),
}

impl Kind {
    pub const fn to_byte(self) -> u8 {
        match self {
            Kind::MessageOut => 0x01,
            Kind::MessageIn => 0x02,
            Kind::ReadMarker => 0x03,
            Kind::ContactAdd => 0x04,
            Kind::ContactRemove => 0x05,
            Kind::DeviceAdd => 0x06,
            Kind::DeviceRevoke => 0x07,
            Kind::ProfileUpdate => 0x08,
            Kind::AgentIn => 0x09,
            Kind::AgentOut => 0x0A,
            Kind::Unknown(b) => b,
        }
    }

    pub const fn from_byte(b: u8) -> Self {
        match b {
            0x01 => Kind::MessageOut,
            0x02 => Kind::MessageIn,
            0x03 => Kind::ReadMarker,
            0x04 => Kind::ContactAdd,
            0x05 => Kind::ContactRemove,
            0x06 => Kind::DeviceAdd,
            0x07 => Kind::DeviceRevoke,
            0x08 => Kind::ProfileUpdate,
            0x09 => Kind::AgentIn,
            0x0A => Kind::AgentOut,
            other => Kind::Unknown(other),
        }
    }
}

// ---------------------------------------------------------------------------
// Agent kind bodies (cli-multi-session-relay relay capability)
// ---------------------------------------------------------------------------

/// Body of a [`Kind::AgentIn`] entry: `{"conversation":…,"text":…,"id":…,
/// "from_name":…}`. `conversation` is the session's public key in hex (not a
/// contact root/endpoint id, unlike the peer-chat kinds). Field order and
/// `skip_serializing_if` are pinned — the Kotlin decoder is byte-exact
/// against this shape (see `eventlog::tests::cross_language_vector_agent_in_entry`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AgentInBody {
    pub conversation: String,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_name: Option<String>,
}

/// Body of a [`Kind::AgentOut`] entry: `{"conversation":…,"text":…,"id":…}`,
/// keyed the same way as [`AgentInBody`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AgentOutBody {
    pub conversation: String,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

// ---------------------------------------------------------------------------
// Log entry
// ---------------------------------------------------------------------------

/// A decoded (or about-to-be-encoded) log entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub version: u8,
    pub kind: Kind,
    pub device_pk: PublicKey,
    pub seq: u64,
    pub lamport: u64,
    pub ts_ms: u64,
    /// SHA-256 of the previous entry's full wire bytes; all zeros at `seq == 1`.
    pub prev_hash: [u8; PREV_HASH_LEN],
    /// UTF-8 JSON, kind-specific. Opaque here — the fold layer interprets it.
    pub body: String,
    pub signature: [u8; SIGNATURE_LEN],
}

impl LogEntry {
    /// Construct a new entry with the current wire version and a zeroed
    /// (invalid) signature — callers MUST call [`Self::sign`] before it's
    /// valid to append or transport. A small convenience so callers outside
    /// this module (e.g. `sync::LogStore::append_own`) don't need to know
    /// the wire version number or repeat this field list.
    pub fn new(
        kind: Kind,
        device_pk: PublicKey,
        seq: u64,
        lamport: u64,
        ts_ms: u64,
        prev_hash: [u8; PREV_HASH_LEN],
        body: String,
    ) -> Self {
        LogEntry {
            version: VERSION,
            kind,
            device_pk,
            seq,
            lamport,
            ts_ms,
            prev_hash,
            body,
            signature: [0u8; SIGNATURE_LEN],
        }
    }

    /// Bytes covered by the signature: everything up to (not including) the
    /// signature itself.
    fn pre_signature_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_LEN + self.body.len());
        buf.push(self.version);
        buf.push(self.kind.to_byte());
        buf.extend_from_slice(self.device_pk.as_bytes());
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.extend_from_slice(&self.lamport.to_be_bytes());
        buf.extend_from_slice(&self.ts_ms.to_be_bytes());
        buf.extend_from_slice(&self.prev_hash);
        buf.extend_from_slice(&(self.body.len() as u32).to_be_bytes());
        buf.extend_from_slice(self.body.as_bytes());
        buf
    }

    /// Full wire bytes, including the trailing signature.
    fn to_wire_bytes(&self) -> Vec<u8> {
        let mut buf = self.pre_signature_bytes();
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Raw wire bytes (this is what gets base64-encoded for `SyncEntries`,
    /// and what a `prev_hash` chains against — see [`Self::hash`]).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_wire_bytes()
    }

    /// Decode raw wire bytes. Rejects truncation, overlong trailing bytes,
    /// an unsupported version, or a non-UTF-8 body.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::decode_bytes(bytes)
    }

    /// Base64 (standard, padded) of the raw wire bytes, for embedding inside
    /// a `SyncEntries` JSON frame.
    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.to_wire_bytes())
    }

    /// Decode from the base64 form produced by [`Self::to_base64`].
    pub fn from_base64(s: &str) -> Result<Self> {
        let bytes = STANDARD.decode(s).context("log entry: invalid base64")?;
        Self::decode_bytes(&bytes)
    }

    fn decode_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            bail!(
                "log entry: payload truncated (need at least {HEADER_LEN} header bytes, got {})",
                bytes.len()
            );
        }
        let version = bytes[0];
        if version != VERSION {
            bail!("log entry: unsupported version {version} (expected {VERSION})");
        }
        let kind = Kind::from_byte(bytes[1]);
        let device_pk = PublicKey::from_bytes(bytes[2..34].try_into().unwrap())
            .context("log entry: invalid device_pk")?;
        let seq = u64::from_be_bytes(bytes[34..42].try_into().unwrap());
        let lamport = u64::from_be_bytes(bytes[42..50].try_into().unwrap());
        let ts_ms = u64::from_be_bytes(bytes[50..58].try_into().unwrap());
        let mut prev_hash = [0u8; PREV_HASH_LEN];
        prev_hash.copy_from_slice(&bytes[58..90]);
        let body_len = u32::from_be_bytes(bytes[90..94].try_into().unwrap()) as usize;

        let body_end = HEADER_LEN.checked_add(body_len).context("log entry: body_len overflow")?;
        if bytes.len() < body_end {
            bail!(
                "log entry: payload truncated mid-body (need at least {body_end} bytes, got {})",
                bytes.len()
            );
        }
        let sig_end = body_end
            .checked_add(SIGNATURE_LEN)
            .context("log entry: signature offset overflow")?;
        if bytes.len() < sig_end {
            bail!(
                "log entry: payload truncated mid-signature (need exactly {sig_end} bytes, got {})",
                bytes.len()
            );
        }
        if bytes.len() > sig_end {
            bail!(
                "log entry: payload overlong (need exactly {sig_end} bytes, got {})",
                bytes.len()
            );
        }

        let body = std::str::from_utf8(&bytes[HEADER_LEN..body_end])
            .context("log entry: body is not valid UTF-8")?
            .to_string();
        let mut signature = [0u8; SIGNATURE_LEN];
        signature.copy_from_slice(&bytes[body_end..sig_end]);

        Ok(LogEntry {
            version,
            kind,
            device_pk,
            seq,
            lamport,
            ts_ms,
            prev_hash,
            body,
            signature,
        })
    }

    /// Sign in place with the author device's secret key, overwriting any
    /// prior signature.
    pub fn sign(&mut self, device_secret: &SecretKey) {
        let msg = self.pre_signature_bytes();
        self.signature = device_secret.sign(&msg).to_bytes();
    }

    /// Verify the trailing signature against this entry's own `device_pk`.
    pub fn verify_signature(&self) -> Result<()> {
        let msg = self.pre_signature_bytes();
        let sig = Signature::from_bytes(&self.signature);
        self.device_pk
            .verify(&msg, &sig)
            .context("log entry: signature verification failed")
    }

    /// SHA-256 of this entry's full wire bytes — what the *next* entry's
    /// `prev_hash` must equal for the chain to extend validly.
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.to_wire_bytes());
        hasher.finalize().into()
    }

    /// Validate this entry as the next one for its own `device_pk`'s log,
    /// given `prev` — the cursor of the last accepted entry for that device,
    /// or `None` if none has been accepted yet (in which case this entry
    /// must be `seq == 1` with an all-zero `prev_hash`). Checks the
    /// signature, `seq` continuity, and the `prev_hash` chain. The spec draws
    /// no distinction between the append side (validating your own next
    /// entry before writing it) and the receive side (validating a synced
    /// entry before accepting it) — both call this; see
    /// [`Self::validate_for_append`] / [`Self::validate_for_receive`].
    fn validate_next(&self, prev: Option<&Cursor>) -> Result<()> {
        self.verify_signature()?;
        match prev {
            None => {
                if self.seq != 1 {
                    bail!("log entry: first entry for a device must have seq 1, got {}", self.seq);
                }
                if self.prev_hash != [0u8; PREV_HASH_LEN] {
                    bail!("log entry: first entry's prev_hash must be all zeros");
                }
            }
            Some(cursor) => {
                if self.seq != cursor.seq + 1 {
                    bail!(
                        "log entry: seq {} is not the previous seq {} + 1",
                        self.seq,
                        cursor.seq
                    );
                }
                if self.prev_hash != cursor.hash {
                    bail!("log entry: prev_hash does not match the previously accepted entry's hash");
                }
            }
        }
        Ok(())
    }

    /// Append-side check: validate this entry before writing it to your own
    /// device's log, given the cursor of the entry you last wrote (`None`
    /// before the first).
    pub fn validate_for_append(&self, prev: Option<&Cursor>) -> Result<()> {
        self.validate_next(prev)
    }

    /// Receive-side check: validate an inbound synced entry before accepting
    /// it into your copy of the author's log, given the cursor of the last
    /// entry you accepted for that device (`None` before the first). Rejects
    /// (and does not advance any cursor for) a broken signature, a seq gap,
    /// or a broken `prev_hash` chain.
    pub fn validate_for_receive(&self, prev: Option<&Cursor>) -> Result<()> {
        self.validate_next(prev)
    }
}

/// The chain-validation state needed to check the *next* entry for one
/// device's log: the last accepted entry's `seq` and full-bytes hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    pub seq: u64,
    pub hash: [u8; 32],
}

/// Tracks the accept cursor for a single device's log and validates each
/// entry against it in order. Doesn't store entries — just enough state
/// (`seq`, previous full-entry hash) to validate the next one. On
/// rejection, the cursor is left exactly as it was, so a broken entry never
/// advances past the point of failure.
#[derive(Debug, Clone)]
pub struct DeviceLogChain {
    device_pk: PublicKey,
    cursor: Option<Cursor>,
}

impl DeviceLogChain {
    pub fn new(device_pk: PublicKey) -> Self {
        Self { device_pk, cursor: None }
    }

    /// The highest accepted `seq`, or `0` if nothing has been accepted yet.
    pub fn seq(&self) -> u64 {
        self.cursor.map(|c| c.seq).unwrap_or(0)
    }

    /// The cursor (`seq` + hash) of the last accepted entry, or `None` if
    /// nothing has been accepted yet — what the *next* entry for this
    /// device must chain from (`seq + 1`, `prev_hash = hash`). Used by
    /// `sync::LogStore::append_own` to build a device's own next entry.
    pub fn cursor(&self) -> Option<Cursor> {
        self.cursor
    }

    /// Validate `entry` (must be authored by this chain's `device_pk`) and,
    /// only on success, advance the cursor to it. On rejection the cursor is
    /// left untouched.
    pub fn accept(&mut self, entry: &LogEntry) -> Result<()> {
        if entry.device_pk != self.device_pk {
            bail!("log entry: device_pk does not match this chain's device");
        }
        entry.validate_for_receive(self.cursor.as_ref())?;
        self.cursor = Some(Cursor { seq: entry.seq, hash: entry.hash() });
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Total order (spec: "Derived State Is a Deterministic Fold")
// ---------------------------------------------------------------------------

/// The `(lamport, ts_ms, device_pk)` ascending total order every derived-state
/// fold must use. Deterministic and coordination-free: any two devices
/// holding the same set of entries sort them identically.
pub fn cmp_total_order(a: &LogEntry, b: &LogEntry) -> std::cmp::Ordering {
    (a.lamport, a.ts_ms, a.device_pk.as_bytes()).cmp(&(b.lamport, b.ts_ms, b.device_pk.as_bytes()))
}

/// Sort key form of [`cmp_total_order`], for use with `sort_by_key` /
/// `Iterator::max_by_key` etc.
pub fn total_order_key(entry: &LogEntry) -> (u64, u64, [u8; 32]) {
    (entry.lamport, entry.ts_ms, *entry.device_pk.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Fixed test fixtures --------------------------------------------
    //
    // Fixed, hardcoded 32-byte secret key seeds (never random) so every
    // encoding here is deterministic and reproducible; task 2.4 lifts these
    // into cross-language vectors.

    #[cfg(test)]
    mod fixtures {
        /// A first device's secret key seed: 32 sequential bytes 0x60..=0x7f.
        pub const DEVICE_A_SEED: [u8; 32] = [
            0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
            0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b,
            0x7c, 0x7d, 0x7e, 0x7f,
        ];
        /// A second device's secret key seed: 32 sequential bytes 0x80..=0x9f.
        pub const DEVICE_B_SEED: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
    }
    use fixtures::{DEVICE_A_SEED, DEVICE_B_SEED};

    fn device_a_secret() -> SecretKey {
        SecretKey::from_bytes(&DEVICE_A_SEED)
    }
    fn device_b_secret() -> SecretKey {
        SecretKey::from_bytes(&DEVICE_B_SEED)
    }

    const ZERO_HASH: [u8; 32] = [0u8; 32];

    fn entry(seq: u64, lamport: u64, prev_hash: [u8; 32], body: &str, secret: &SecretKey) -> LogEntry {
        let mut e = LogEntry {
            version: VERSION,
            kind: Kind::MessageOut,
            device_pk: secret.public(),
            seq,
            lamport,
            ts_ms: 1_767_225_600_000 + seq * 1000,
            prev_hash,
            body: body.to_string(),
            signature: [0u8; SIGNATURE_LEN],
        };
        e.sign(secret);
        e
    }

    // --- Round trip / decode strictness -------------------------------------

    #[test]
    fn entry_round_trips_through_bytes() {
        let secret = device_a_secret();
        let e = entry(1, 1, ZERO_HASH, r#"{"conversation":"abcd","text":"hi"}"#, &secret);
        let bytes = e.to_bytes();
        let decoded = LogEntry::from_bytes(&bytes).expect("decodes");
        assert_eq!(decoded, e);
        decoded.verify_signature().expect("verifies");
    }

    #[test]
    fn entry_round_trips_through_base64() {
        let secret = device_a_secret();
        let e = entry(1, 1, ZERO_HASH, r#"{"conversation":"abcd","text":"hi"}"#, &secret);
        let b64 = e.to_base64();
        let decoded = LogEntry::from_base64(&b64).expect("decodes");
        assert_eq!(decoded, e);
    }

    #[test]
    fn entry_truncated_is_rejected() {
        let secret = device_a_secret();
        let bytes = entry(1, 1, ZERO_HASH, "{}", &secret).to_bytes();
        let err = LogEntry::from_bytes(&bytes[..bytes.len() - 1]).unwrap_err();
        assert!(err.to_string().contains("truncated"), "{err}");
    }

    #[test]
    fn entry_overlong_is_rejected() {
        let secret = device_a_secret();
        let mut bytes = entry(1, 1, ZERO_HASH, "{}", &secret).to_bytes();
        bytes.push(0);
        let err = LogEntry::from_bytes(&bytes).unwrap_err();
        assert!(err.to_string().contains("overlong"), "{err}");
    }

    #[test]
    fn entry_bad_base64_is_rejected() {
        let err = LogEntry::from_base64("not valid base64!!").unwrap_err();
        assert!(err.to_string().contains("base64"), "{err}");
    }

    #[test]
    fn entry_non_utf8_body_is_rejected() {
        let secret = device_a_secret();
        let mut bytes = entry(1, 1, ZERO_HASH, "ok", &secret).to_bytes();
        // body occupies bytes [94, 94+2); poke an invalid UTF-8 byte into it.
        bytes[94] = 0xff;
        let err = LogEntry::from_bytes(&bytes).unwrap_err();
        assert!(err.to_string().contains("UTF-8"), "{err}");
    }

    #[test]
    fn entry_version_mismatch_is_rejected() {
        let secret = device_a_secret();
        let mut bytes = entry(1, 1, ZERO_HASH, "{}", &secret).to_bytes();
        bytes[0] = 0x02;
        let err = LogEntry::from_bytes(&bytes).unwrap_err();
        assert!(err.to_string().contains("version"), "{err}");
    }

    #[test]
    fn unknown_kind_byte_round_trips() {
        let secret = device_a_secret();
        let mut e = entry(1, 1, ZERO_HASH, "{}", &secret);
        e.kind = Kind::Unknown(0x7f);
        e.sign(&secret);
        let bytes = e.to_bytes();
        let decoded = LogEntry::from_bytes(&bytes).expect("decodes");
        assert_eq!(decoded.kind, Kind::Unknown(0x7f));
        // Re-serveable: re-encoding an unknown-kind entry reproduces the
        // same bytes exactly.
        assert_eq!(decoded.to_bytes(), bytes);
    }

    #[test]
    fn known_kind_bytes_round_trip_to_named_variants() {
        for (byte, kind) in [
            (0x01, Kind::MessageOut),
            (0x02, Kind::MessageIn),
            (0x03, Kind::ReadMarker),
            (0x04, Kind::ContactAdd),
            (0x05, Kind::ContactRemove),
            (0x06, Kind::DeviceAdd),
            (0x07, Kind::DeviceRevoke),
            (0x08, Kind::ProfileUpdate),
            (0x09, Kind::AgentIn),
            (0x0A, Kind::AgentOut),
        ] {
            assert_eq!(Kind::from_byte(byte), kind);
            assert_eq!(kind.to_byte(), byte);
        }
    }

    // --- LogEntry::new / DeviceLogChain::cursor (task 8.1 support) ----------

    #[test]
    fn new_constructs_current_version_with_zeroed_signature() {
        let e = LogEntry::new(Kind::MessageOut, device_a_secret().public(), 1, 1, 123, ZERO_HASH, "{}".to_string());
        assert_eq!(e.version, VERSION);
        assert_eq!(e.signature, [0u8; SIGNATURE_LEN]);
        assert_eq!(e.seq, 1);
        assert_eq!(e.lamport, 1);
        assert_eq!(e.ts_ms, 123);
    }

    #[test]
    fn chain_cursor_reflects_last_accepted_entry() {
        let secret = device_a_secret();
        let mut chain = DeviceLogChain::new(secret.public());
        assert_eq!(chain.cursor(), None);

        let e1 = entry(1, 1, ZERO_HASH, "{}", &secret);
        chain.accept(&e1).unwrap();
        assert_eq!(chain.cursor(), Some(Cursor { seq: 1, hash: e1.hash() }));

        let e2 = entry(2, 2, e1.hash(), "{}", &secret);
        chain.accept(&e2).unwrap();
        assert_eq!(chain.cursor(), Some(Cursor { seq: 2, hash: e2.hash() }));
    }

    // --- Chain validation ----------------------------------------------------

    #[test]
    fn three_entry_chain_accepts() {
        let secret = device_a_secret();
        let e1 = entry(1, 1, ZERO_HASH, "{}", &secret);
        let e2 = entry(2, 2, e1.hash(), "{}", &secret);
        let e3 = entry(3, 3, e2.hash(), "{}", &secret);

        let mut chain = DeviceLogChain::new(secret.public());
        chain.accept(&e1).expect("e1 accepts");
        chain.accept(&e2).expect("e2 accepts");
        chain.accept(&e3).expect("e3 accepts");
        assert_eq!(chain.seq(), 3);
    }

    #[test]
    fn broken_prev_hash_rejects_and_does_not_advance_cursor() {
        let secret = device_a_secret();
        let e1 = entry(1, 1, ZERO_HASH, "{}", &secret);
        // e2 claims a prev_hash that doesn't match e1's actual hash.
        let mut bogus_hash = e1.hash();
        bogus_hash[0] ^= 0xff;
        let e2_broken = entry(2, 2, bogus_hash, "{}", &secret);

        let mut chain = DeviceLogChain::new(secret.public());
        chain.accept(&e1).expect("e1 accepts");
        let err = chain.accept(&e2_broken).unwrap_err();
        assert!(err.to_string().contains("prev_hash"), "{err}");
        // Cursor did not advance: the real e2 (correct prev_hash) still accepts.
        assert_eq!(chain.seq(), 1);
        let e2 = entry(2, 2, e1.hash(), "{}", &secret);
        chain.accept(&e2).expect("real e2 still accepts after rejecting the broken one");
        assert_eq!(chain.seq(), 2);
    }

    #[test]
    fn seq_gap_is_rejected() {
        let secret = device_a_secret();
        let e1 = entry(1, 1, ZERO_HASH, "{}", &secret);
        let e3 = entry(3, 3, e1.hash(), "{}", &secret); // skips seq 2

        let mut chain = DeviceLogChain::new(secret.public());
        chain.accept(&e1).expect("e1 accepts");
        let err = chain.accept(&e3).unwrap_err();
        assert!(err.to_string().contains("seq"), "{err}");
        assert_eq!(chain.seq(), 1);
    }

    #[test]
    fn first_entry_must_have_seq_1_and_zero_prev_hash() {
        let secret = device_a_secret();
        let bad_seq = entry(2, 1, ZERO_HASH, "{}", &secret);
        let mut chain = DeviceLogChain::new(secret.public());
        assert!(chain.accept(&bad_seq).is_err());
        assert_eq!(chain.seq(), 0);

        let mut nonzero_prev_hash = [0u8; 32];
        nonzero_prev_hash[0] = 1;
        let bad_prev = entry(1, 1, nonzero_prev_hash, "{}", &secret);
        let mut chain2 = DeviceLogChain::new(secret.public());
        assert!(chain2.accept(&bad_prev).is_err());
        assert_eq!(chain2.seq(), 0);
    }

    #[test]
    fn tampered_body_invalidates_signature() {
        let secret = device_a_secret();
        let mut e = entry(1, 1, ZERO_HASH, r#"{"text":"hi"}"#, &secret);
        e.body = r#"{"text":"pwned"}"#.to_string(); // signature no longer covers this body
        assert!(e.verify_signature().is_err());

        let mut chain = DeviceLogChain::new(secret.public());
        assert!(chain.accept(&e).is_err());
        assert_eq!(chain.seq(), 0);
    }

    #[test]
    fn wrong_device_is_rejected_by_chain() {
        let a = device_a_secret();
        let b = device_b_secret();
        let e1 = entry(1, 1, ZERO_HASH, "{}", &b); // authored by b

        let mut chain = DeviceLogChain::new(a.public()); // chain tracks a
        assert!(chain.accept(&e1).is_err());
        assert_eq!(chain.seq(), 0);
    }

    // --- Total order -----------------------------------------------------

    #[test]
    fn total_order_sorts_by_lamport_then_ts_then_device_pk() {
        let a = device_a_secret();
        let b = device_b_secret();

        let e_a1 = entry(1, 5, ZERO_HASH, "{}", &a);
        let e_b1 = entry(1, 5, ZERO_HASH, "{}", &b); // same lamport+ts as e_a1
        let e_a2 = entry(2, 10, e_a1.hash(), "{}", &a);

        let mut entries = vec![e_a2.clone(), e_b1.clone(), e_a1.clone()];
        entries.sort_by(cmp_total_order);

        // e_a1 and e_b1 share (lamport=5, ts_ms=?) — ts_ms differs by seq in
        // our fixture helper (ts_ms = base + seq*1000), both seq=1 so ts_ms
        // ties too; tiebreak is device_pk ascending.
        let (lo, hi) = if a.public() <= b.public() { (&e_a1, &e_b1) } else { (&e_b1, &e_a1) };
        assert_eq!(&entries[0], lo);
        assert_eq!(&entries[1], hi);
        assert_eq!(entries[2], e_a2);

        // sort_by_key with `total_order_key` agrees with `cmp_total_order`.
        let mut by_key = vec![e_a2, e_b1, e_a1];
        by_key.sort_by_key(total_order_key);
        assert_eq!(by_key, entries);
    }

    /// Cross-language test vector (task 2.4): the three-entry log companion to
    /// certs.rs's `cross_language_vector_cert_and_revocation` -- same fixed-seed approach, real
    /// Ed25519 via `device_a_secret()`. See
    /// `azula-docs/openspec/changes/multi-device-identity/design.md`'s "Cross-Language Test
    /// Vectors" section for the full recorded vector (Kotlin's `CrossLanguageVectorTest` decodes
    /// these exact base64 literals and re-encodes them, since `core` has no real Ed25519 to
    /// independently produce them).
    #[test]
    fn cross_language_vector_three_entry_log() {
        let secret = device_a_secret();
        let device_a_pk_hex = "174553b456dddfc6908ecab1c101fe6ab21e2baa0617795b7d43a63482993fd5";
        assert_eq!(data_encoding::HEXLOWER.encode(secret.public().as_bytes()), device_a_pk_hex);

        let base_ts_ms: u64 = 1700000000000;
        let mut e1 = LogEntry {
            version: VERSION,
            kind: Kind::MessageOut,
            device_pk: secret.public(),
            seq: 1,
            lamport: 1,
            ts_ms: base_ts_ms,
            prev_hash: ZERO_HASH,
            body: "{\"conversation\":\"cafebabe\",\"text\":\"hello\"}".to_string(),
            signature: [0u8; SIGNATURE_LEN],
        };
        e1.sign(&secret);
        let mut e2 = LogEntry {
            version: VERSION,
            kind: Kind::MessageOut,
            device_pk: secret.public(),
            seq: 2,
            lamport: 2,
            ts_ms: base_ts_ms + 1000,
            prev_hash: e1.hash(),
            body: "{\"conversation\":\"cafebabe\",\"text\":\"how are you?\"}".to_string(),
            signature: [0u8; SIGNATURE_LEN],
        };
        e2.sign(&secret);
        let mut e3 = LogEntry {
            version: VERSION,
            kind: Kind::ReadMarker,
            device_pk: secret.public(),
            seq: 3,
            lamport: 3,
            ts_ms: base_ts_ms + 2000,
            prev_hash: e2.hash(),
            body: "{\"conversation\":\"cafebabe\",\"up_to_lamport\":2}".to_string(),
            signature: [0u8; SIGNATURE_LEN],
        };
        e3.sign(&secret);

        // task 4.2: the relay's agent_in kind, chained after e3 -- same
        // device key, exact body pinned by the cli-multi-session-relay
        // design (the Kotlin side pins the identical bytes for this entry).
        let mut e4 = LogEntry {
            version: VERSION,
            kind: Kind::AgentIn,
            device_pk: secret.public(),
            seq: 4,
            lamport: 4,
            ts_ms: 1700000003000,
            prev_hash: e3.hash(),
            body: "{\"conversation\":\"cafebabe\",\"text\":\"hello from claude\",\"id\":\"00112233445566778899aabbccddeeff\",\"from_name\":\"Claude\"}".to_string(),
            signature: [0u8; SIGNATURE_LEN],
        };
        e4.sign(&secret);

        let e1_b64 ="AQEXRVO0Vt3fxpCOyrHBAf5qsh4rqgYXeVt9Q6Y0gpk/1QAAAAAAAAABAAAAAAAAAAEAAAGLz+VoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKnsiY29udmVyc2F0aW9uIjoiY2FmZWJhYmUiLCJ0ZXh0IjoiaGVsbG8ifcGRps3rZKzaqY89ynl1jzSQHWo5uV7rH7c99fvWTKXitnG6toGFF22x7msZ8FfCOM5pI8np8hIEcoKU6zpD3g8=";
        let e2_b64 = "AQEXRVO0Vt3fxpCOyrHBAf5qsh4rqgYXeVt9Q6Y0gpk/1QAAAAAAAAACAAAAAAAAAAIAAAGLz+Vr6JPE2ChDzHnzP1NBar+E+2Eot1hBahj0YSL63ueXvfF+AAAAMXsiY29udmVyc2F0aW9uIjoiY2FmZWJhYmUiLCJ0ZXh0IjoiaG93IGFyZSB5b3U/In3kE3/9rXJwLJWL1Pi6E0zhf0U/JhmcFx5J0XMo1c/TXIXHlESSlq7nv/F9a98bySkg0wbjfO6k4BXOKq7Q6ewC";
        let e3_b64 = "AQMXRVO0Vt3fxpCOyrHBAf5qsh4rqgYXeVt9Q6Y0gpk/1QAAAAAAAAADAAAAAAAAAAMAAAGLz+Vv0JKxBpleoFRawCUpkr1rwKJsTtMBX2QLTCs9/CIkuocSAAAALXsiY29udmVyc2F0aW9uIjoiY2FmZWJhYmUiLCJ1cF90b19sYW1wb3J0IjoyfYGB/vAipgFl+KPw+qRjJ1Ei+/BX2gcb7DBqCp5OY/i01eZnE4ixyjLEKCzwG2yZ+pcXpkoPcb6dv0gcpWRPAgE=";
        assert_eq!(e1.to_base64(), e1_b64);
        assert_eq!(e2.to_base64(), e2_b64);
        assert_eq!(e3.to_base64(), e3_b64);

        // task 4.2 pinned vector: computed once here and recorded byte-for-byte
        // in the change's design.md / this agent's report -- the Kotlin side
        // decodes this exact literal and re-encodes it.
        let e4_b64 = "AQkXRVO0Vt3fxpCOyrHBAf5qsh4rqgYXeVt9Q6Y0gpk/1QAAAAAAAAAEAAAAAAAAAAQAAAGLz+VzuGr8OX3ecU73ydjngR0PYI8/ydUIrXhzoBEurdhakwBLAAAAc3siY29udmVyc2F0aW9uIjoiY2FmZWJhYmUiLCJ0ZXh0IjoiaGVsbG8gZnJvbSBjbGF1ZGUiLCJpZCI6IjAwMTEyMjMzNDQ1NTY2Nzc4ODk5YWFiYmNjZGRlZWZmIiwiZnJvbV9uYW1lIjoiQ2xhdWRlIn23LV+7/fV81iMfv/PrprZt9lfbZZY/+OexSqyBPoqhHHt28rCquBnuNQOFpU2Sc1+epS98Fre41O87NDdm/ykP";
        assert_eq!(e4.to_base64(), e4_b64);

        let h1_hex = "93c4d82843cc79f33f53416abf84fb6128b758416a18f46122fadee797bdf17e";
        let h2_hex = "92b106995ea0545ac0252992bd6bc0a26c4ed3015f640b4c2b3dfc2224ba8712";
        let h3_hex = "6afc397dde714ef7c9d8e7811d0f608f3fc9d508ad7873a0112eadd85a93004b";
        assert_eq!(data_encoding::HEXLOWER.encode(&e1.hash()), h1_hex);
        assert_eq!(data_encoding::HEXLOWER.encode(&e2.hash()), h2_hex);
        assert_eq!(data_encoding::HEXLOWER.encode(&e3.hash()), h3_hex);

        let h4_hex = "522670c48faff21d9ff3558aa93aef34999ec625e5a1d322082a6ff6a6676433";
        assert_eq!(data_encoding::HEXLOWER.encode(&e4.hash()), h4_hex);

        // Chain validates end to end via the same DeviceLogChain machinery the account-sync
        // fold depends on.
        let mut chain = DeviceLogChain::new(secret.public());
        chain.accept(&e1).expect("e1 accepts");
        chain.accept(&e2).expect("e2 accepts");
        chain.accept(&e3).expect("e3 accepts");
        chain.accept(&e4).expect("e4 accepts");
        assert_eq!(chain.seq(), 4);

        // Byte-identical round trip through base64 -- matches what Kotlin's
        // `CrossLanguageVectorTest` decodes and re-encodes on its side.
        assert_eq!(LogEntry::from_base64(e1_b64).unwrap(), e1);
        assert_eq!(LogEntry::from_base64(e2_b64).unwrap(), e2);
        assert_eq!(LogEntry::from_base64(e3_b64).unwrap(), e3);
        assert_eq!(LogEntry::from_base64(e4_b64).unwrap(), e4);
    }

    #[test]
    fn agent_body_field_order_and_optional_omission() {
        let full = AgentInBody {
            conversation: "cafebabe".to_string(),
            text: "hello from claude".to_string(),
            id: Some("00112233445566778899aabbccddeeff".to_string()),
            from_name: Some("Claude".to_string()),
        };
        let json = serde_json::to_string(&full).unwrap();
        assert_eq!(
            json,
            r#"{"conversation":"cafebabe","text":"hello from claude","id":"00112233445566778899aabbccddeeff","from_name":"Claude"}"#
        );

        let minimal = AgentInBody {
            conversation: "cafebabe".to_string(),
            text: "hi".to_string(),
            id: None,
            from_name: None,
        };
        let json = serde_json::to_string(&minimal).unwrap();
        assert_eq!(json, r#"{"conversation":"cafebabe","text":"hi"}"#);
        let back: AgentInBody = serde_json::from_str(&json).unwrap();
        assert_eq!(back, minimal);

        let out = AgentOutBody { conversation: "cafebabe".to_string(), text: "hi".to_string(), id: None };
        let json = serde_json::to_string(&out).unwrap();
        assert_eq!(json, r#"{"conversation":"cafebabe","text":"hi"}"#);
    }
}
