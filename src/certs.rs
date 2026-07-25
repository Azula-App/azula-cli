//! Device certificate (`azd`), revocation (`azr`), and QR-link (`azl`) payload
//! codecs, plus the BIP-39 verification-word derivation used during QR-link
//! enrollment.
//!
//! See `azula-docs/openspec/changes/multi-device-identity/specs/device-linking/spec.md`
//! for the normative requirements (`design.md` sections 2 and 3 restate the
//! same layouts; where the two differ, `spec.md` is the intent).
//!
//! Wire layout for a **device certificate** (all integers big-endian):
//!
//! ```text
//! offset  size  field
//! 0       1     version (0x01)
//! 1       1     flags (bit0 = mailbox role, bit1 = bot role — reserved,
//!                never set by this change — bits 2-7 reserved: 0 on encode,
//!                ignored on decode)
//! 2       32    root_pk (Ed25519 root public key)
//! 34      32    device_pk (Ed25519 device / iroh node public key)
//! 66      4     issued_at (unix seconds)
//! 70      4     expires_at (unix seconds; 0 = never)
//! 74      1     name_len (n, 0..=63)
//! 75      n     name (UTF-8 device display name)
//! 75+n    64    signature, Ed25519 by the root secret over [0, 75+n)
//! ```
//!
//! Encoded string form: `"azd" + base32(payload)`, RFC 4648 no-padding,
//! lowercase — matching `invite.rs`'s `"azi…"` convention.
//!
//! Wire layout for a **revocation statement**:
//!
//! ```text
//! offset  size  field
//! 0       1     version (0x01)
//! 1       32    root_pk
//! 33      32    device_pk (the revoked device)
//! 65      4     revoked_at (unix seconds)
//! 69      64    signature, Ed25519 by the root secret over [0, 69)
//! ```
//!
//! Encoded string form: `"azr" + base32(payload)`.
//!
//! Wire layout for a **QR-link payload** (no signature — it carries no
//! authority, just an invitation to be scanned):
//!
//! ```text
//! offset  size  field
//! 0       1     version (0x01)
//! 1       32    device_pk (the new device's freshly generated node key)
//! 33      1     name_len (n)
//! 34      n     name (UTF-8 requested display name)
//! 34+n    2     ticket_len (m)
//! 36+n    m     ticket (opaque connect ticket bytes)
//! ```
//!
//! Encoded string form: `"azl" + base32(payload)`.
//!
//! ## Verification is self-contained, but binding is the caller's job
//!
//! Per the spec's "Certificate Verification Is Self-Contained" requirement,
//! [`DeviceCert::verify`] needs no external lookup: it checks `version == 1`,
//! verifies the signature against the cert's own embedded `root_pk`, and
//! checks `expires_at`. It does **not** check revocation (see
//! [`DeviceCert::is_revoked_by`], which takes the verifier's own revocation
//! set) and it confers **no identity association** by itself — a cert is
//! just an association claim. Callers MUST additionally check
//! [`DeviceCert::binds_to_connection`] (the connection's transport node id
//! equals `device_pk`) before treating a presented cert as identifying the
//! peer on that connection.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use iroh::{EndpointId, PublicKey, SecretKey, Signature};
use sha2::{Digest, Sha256};

use crate::bip39_wordlist::WORDLIST;

/// bit 0 of a certificate's `flags`: the device holds the mailbox role.
pub const FLAG_MAILBOX: u8 = 0x01;
/// bit 1 of a certificate's `flags`: the device holds the bot role. Reserved
/// — never set by this change (see `design.md`'s Non-Goals).
pub const FLAG_BOT: u8 = 0x02;
/// bit 2 of a certificate's `flags`: this is a **session** certificate
/// (cli-multi-session-relay design.md D1), not a sibling-device enrollment.
/// `root_pk` is a machine identity, `device_pk` is a per-process session key;
/// holding one grants conversation access to peers paired with the machine —
/// no sync participation, no log authorship, no link-granting authority (see
/// the device-linking spec's "Session Certificate Kind" requirement).
pub const FLAG_SESSION: u8 = 0x04;

/// Default session certificate validity (design.md D1/D2): 7 days from
/// mint time, overridable per session by callers that pass a different
/// `expires` to [`mint_session_cert`].
pub const DEFAULT_SESSION_EXPIRY: Duration = Duration::from_secs(7 * 24 * 60 * 60);

const VERSION: u8 = 1;
const SIGNATURE_LEN: usize = 64;
const MAX_NAME_LEN: usize = 63;

const CERT_PREFIX: &str = "azd";
/// version(1) + flags(1) + root_pk(32) + device_pk(32) + issued_at(4) +
/// expires_at(4) + name_len(1), i.e. everything before the variable-length
/// name. `1+1+32+32+4+4+1 = 75`, matching the spec's `75 + name_len + 64`.
const CERT_HEADER_LEN: usize = 75;

const REVOCATION_PREFIX: &str = "azr";
/// version(1) + root_pk(32) + device_pk(32) + revoked_at(4) = 69 fixed bytes
/// before the signature.
const REVOCATION_HEADER_LEN: usize = 69;
const REVOCATION_LEN: usize = REVOCATION_HEADER_LEN + SIGNATURE_LEN;

const LINK_PREFIX: &str = "azl";
/// version(1) + device_pk(32) + name_len(1), before the variable-length name.
const LINK_HEADER_LEN: usize = 34;

// ---------------------------------------------------------------------------
// Shared base32 helpers ("az…" + unpadded lowercase RFC 4648, per invite.rs)
// ---------------------------------------------------------------------------

fn encode_with_prefix(prefix: &str, bytes: &[u8]) -> String {
    let mut out = String::from(prefix);
    data_encoding::BASE32_NOPAD.encode_append(bytes, &mut out);
    out.make_ascii_lowercase();
    out
}

fn decode_with_prefix(prefix: &'static str, s: &str) -> Result<Vec<u8>> {
    let rest = s
        .strip_prefix(prefix)
        .with_context(|| format!("{prefix}: missing {prefix:?} prefix"))?;
    data_encoding::BASE32_NOPAD
        .decode(rest.to_ascii_uppercase().as_bytes())
        .with_context(|| format!("{prefix}: invalid base32"))
}

fn now_unix() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Device certificate ("azd")
// ---------------------------------------------------------------------------

/// A decoded (or about-to-be-encoded) device certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCert {
    pub version: u8,
    pub flags: u8,
    pub root_pk: PublicKey,
    pub device_pk: PublicKey,
    pub issued_at: u32,
    pub expires_at: u32,
    /// UTF-8 display name. Callers must keep this at or under
    /// [`MAX_NAME_LEN`] (63) bytes — [`sign`](Self::sign)/[`encode`](Self::encode)
    /// assume it (matching `invite.rs`'s ticket-length convention: encode-side
    /// values are the caller's responsibility, decode-side is strict).
    pub name: String,
    pub signature: [u8; SIGNATURE_LEN],
}

impl DeviceCert {
    pub fn is_mailbox(&self) -> bool {
        self.flags & FLAG_MAILBOX != 0
    }

    pub fn is_bot(&self) -> bool {
        self.flags & FLAG_BOT != 0
    }

    /// True if this cert carries [`FLAG_SESSION`] — a per-process session
    /// certificate rather than a sibling-device enrollment.
    pub fn is_session(&self) -> bool {
        self.flags & FLAG_SESSION != 0
    }

    /// Bytes covered by the signature: everything up to (not including) the
    /// signature itself.
    fn pre_signature_bytes(&self) -> Vec<u8> {
        debug_assert!(
            self.name.len() <= MAX_NAME_LEN,
            "cert: name exceeds {MAX_NAME_LEN} bytes; caller must validate before signing/encoding"
        );
        let mut buf = Vec::with_capacity(CERT_HEADER_LEN + self.name.len());
        buf.push(self.version);
        buf.push(self.flags);
        buf.extend_from_slice(self.root_pk.as_bytes());
        buf.extend_from_slice(self.device_pk.as_bytes());
        buf.extend_from_slice(&self.issued_at.to_be_bytes());
        buf.extend_from_slice(&self.expires_at.to_be_bytes());
        buf.push(self.name.len() as u8);
        buf.extend_from_slice(self.name.as_bytes());
        buf
    }

    /// Full wire bytes, including the trailing signature.
    fn to_wire_bytes(&self) -> Vec<u8> {
        let mut buf = self.pre_signature_bytes();
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Encode as `"azd" + base32(payload)`, RFC 4648 no-pad, lowercase.
    pub fn encode(&self) -> String {
        encode_with_prefix(CERT_PREFIX, &self.to_wire_bytes())
    }

    /// Decode from the `"azd…"` string form. Rejects anything that doesn't
    /// decode, or whose inner structure is inconsistent: wrong prefix, bad
    /// base32, truncation, overlong trailing bytes, `name_len` over 63, or a
    /// non-UTF-8 name.
    pub fn decode(s: &str) -> Result<Self> {
        let bytes = decode_with_prefix(CERT_PREFIX, s)?;
        Self::decode_bytes(&bytes)
    }

    fn decode_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < CERT_HEADER_LEN {
            bail!(
                "cert: payload truncated (need at least {CERT_HEADER_LEN} header bytes, got {})",
                bytes.len()
            );
        }
        let version = bytes[0];
        if version != VERSION {
            bail!("cert: unsupported version {version} (expected {VERSION})");
        }
        let flags = bytes[1];
        let root_pk = PublicKey::from_bytes(bytes[2..34].try_into().unwrap())
            .context("cert: invalid root_pk")?;
        let device_pk = PublicKey::from_bytes(bytes[34..66].try_into().unwrap())
            .context("cert: invalid device_pk")?;
        let issued_at = u32::from_be_bytes(bytes[66..70].try_into().unwrap());
        let expires_at = u32::from_be_bytes(bytes[70..74].try_into().unwrap());
        let name_len = bytes[74] as usize;
        if name_len > MAX_NAME_LEN {
            bail!("cert: name_len {name_len} exceeds max {MAX_NAME_LEN}");
        }

        let expected_len = CERT_HEADER_LEN + name_len + SIGNATURE_LEN;
        if bytes.len() < expected_len {
            bail!(
                "cert: payload truncated (need exactly {expected_len} bytes for name_len={name_len}, got {})",
                bytes.len()
            );
        }
        if bytes.len() > expected_len {
            bail!(
                "cert: payload overlong (need exactly {expected_len} bytes for name_len={name_len}, got {})",
                bytes.len()
            );
        }

        let name_end = CERT_HEADER_LEN + name_len;
        let name = std::str::from_utf8(&bytes[CERT_HEADER_LEN..name_end])
            .context("cert: name is not valid UTF-8")?
            .to_string();
        let mut signature = [0u8; SIGNATURE_LEN];
        signature.copy_from_slice(&bytes[name_end..expected_len]);

        Ok(DeviceCert { version, flags, root_pk, device_pk, issued_at, expires_at, name, signature })
    }

    /// Sign in place: computes the signature over the pre-signature bytes
    /// with the root secret. Overwrites any prior signature.
    pub fn sign(&mut self, root_secret: &SecretKey) {
        let msg = self.pre_signature_bytes();
        self.signature = root_secret.sign(&msg).to_bytes();
    }

    /// Self-contained verification per the spec: `version == 1`, signature
    /// verifies against the cert's own embedded `root_pk`, and `expires_at`
    /// is `0` or in the future. Does **not** check revocation (see
    /// [`is_revoked_by`](Self::is_revoked_by)) and does **not** bind the cert
    /// to any connection (see [`binds_to_connection`](Self::binds_to_connection)).
    pub fn verify(&self) -> Result<()> {
        if self.version != VERSION {
            bail!("cert: unsupported version {} (expected {VERSION})", self.version);
        }
        let msg = self.pre_signature_bytes();
        let sig = Signature::from_bytes(&self.signature);
        self.root_pk.verify(&msg, &sig).context("cert: signature verification failed")?;
        let now = now_unix();
        if self.expires_at != 0 && now >= self.expires_at {
            bail!("cert: expired");
        }
        Ok(())
    }

    /// True if this cert's `device_pk` (under this cert's `root_pk`) is named
    /// by any revocation in `revocations`. Callers must have already called
    /// [`Revocation::verify`] on every element themselves — this does not
    /// re-verify them, it only matches keys.
    pub fn is_revoked_by<'a, I>(&self, revocations: I) -> bool
    where
        I: IntoIterator<Item = &'a Revocation>,
    {
        revocations
            .into_iter()
            .any(|r| r.root_pk == self.root_pk && r.device_pk == self.device_pk)
    }

    /// A certificate confers nothing unless the connection's transport node
    /// id equals the certificate's device public key. Callers MUST call this
    /// (or perform the equivalent comparison) before treating a presented,
    /// verified cert as identifying the peer on a given connection.
    pub fn binds_to_connection(&self, connection_node_id: EndpointId) -> bool {
        self.device_pk == connection_node_id
    }
}

// ---------------------------------------------------------------------------
// Session certificates (cli-multi-session-relay design.md D1/D3)
// ---------------------------------------------------------------------------

/// Mint a session certificate: `root_pk` = `machine_secret`'s public key,
/// `device_pk` = `session_pk`, [`FLAG_SESSION`] set, signed by
/// `machine_secret`, expiring `expires` from now (pass
/// [`DEFAULT_SESSION_EXPIRY`] for the default 7 days). The session's display
/// name lives in the app's `Profile` frame, not the cert, so `name` is left
/// empty here.
///
/// Passing the session's own secret as `machine_secret` (so `root_pk ==
/// device_pk == session_pk`) produces the self-certified shape a headless
/// process uses when it has no machine identity to chain to — see
/// [`mint_self_certified_session`], which does exactly that.
pub fn mint_session_cert(machine_secret: &SecretKey, session_pk: PublicKey, expires: Duration) -> DeviceCert {
    let issued_at = now_unix();
    let expires_at = issued_at.saturating_add(expires.as_secs().min(u32::MAX as u64) as u32);
    let mut cert = DeviceCert {
        version: VERSION,
        flags: FLAG_SESSION,
        root_pk: machine_secret.public(),
        device_pk: session_pk,
        issued_at,
        expires_at,
        name: String::new(),
        signature: [0u8; SIGNATURE_LEN],
    };
    cert.sign(machine_secret);
    cert
}

/// Self-certify a headless session (device-linking spec's "Self-certified
/// headless session" scenario): the session key doubles as its own root
/// (`root_pk == device_pk == session_pk`), mirroring the app's
/// upgrade-in-place self-cert shape. Same minting path as
/// [`mint_session_cert`] — the session key just signs itself.
pub fn mint_self_certified_session(session_secret: &SecretKey, expires: Duration) -> DeviceCert {
    mint_session_cert(session_secret, session_secret.public(), expires)
}

/// Verify a decoded session certificate against `expected_transport_peer`
/// (the live connection's transport node id), enforcing every check that's
/// self-contained to the cert plus the connection:
///
/// 1. structural/signature validity against the cert's own embedded
///    `root_pk`, and non-expiry ([`DeviceCert::verify`]);
/// 2. [`FLAG_SESSION`] is set;
/// 3. `device_pk == expected_transport_peer`.
///
/// Does **not** check that `root_pk` belongs to an already-paired machine
/// contact, and does not check revocation — those require a registry the
/// caller holds and this module doesn't; callers must additionally check
/// `cert.root_pk` themselves (see the session-identity spec's "Phone
/// Auto-Accepts Certified Sessions" requirement — all of these checks plus
/// the registry check are required together).
pub fn verify_session_cert(cert: &DeviceCert, expected_transport_peer: EndpointId) -> Result<()> {
    cert.verify()?;
    if !cert.is_session() {
        bail!("session cert: FLAG_SESSION not set");
    }
    if !cert.binds_to_connection(expected_transport_peer) {
        bail!("session cert: device_pk does not match the transport peer");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Revocation statement ("azr")
// ---------------------------------------------------------------------------

/// A decoded (or about-to-be-encoded) revocation statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    pub version: u8,
    pub root_pk: PublicKey,
    pub device_pk: PublicKey,
    pub revoked_at: u32,
    pub signature: [u8; SIGNATURE_LEN],
}

impl Revocation {
    fn pre_signature_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(REVOCATION_HEADER_LEN);
        buf.push(self.version);
        buf.extend_from_slice(self.root_pk.as_bytes());
        buf.extend_from_slice(self.device_pk.as_bytes());
        buf.extend_from_slice(&self.revoked_at.to_be_bytes());
        buf
    }

    fn to_wire_bytes(&self) -> Vec<u8> {
        let mut buf = self.pre_signature_bytes();
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Encode as `"azr" + base32(payload)`, RFC 4648 no-pad, lowercase.
    pub fn encode(&self) -> String {
        encode_with_prefix(REVOCATION_PREFIX, &self.to_wire_bytes())
    }

    /// Decode from the `"azr…"` string form. Rejects wrong prefix, bad
    /// base32, and any length other than exactly [`REVOCATION_LEN`] bytes.
    pub fn decode(s: &str) -> Result<Self> {
        let bytes = decode_with_prefix(REVOCATION_PREFIX, s)?;
        Self::decode_bytes(&bytes)
    }

    fn decode_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < REVOCATION_LEN {
            bail!(
                "revocation: payload truncated (need exactly {REVOCATION_LEN} bytes, got {})",
                bytes.len()
            );
        }
        if bytes.len() > REVOCATION_LEN {
            bail!(
                "revocation: payload overlong (need exactly {REVOCATION_LEN} bytes, got {})",
                bytes.len()
            );
        }
        let version = bytes[0];
        if version != VERSION {
            bail!("revocation: unsupported version {version} (expected {VERSION})");
        }
        let root_pk = PublicKey::from_bytes(bytes[1..33].try_into().unwrap())
            .context("revocation: invalid root_pk")?;
        let device_pk = PublicKey::from_bytes(bytes[33..65].try_into().unwrap())
            .context("revocation: invalid device_pk")?;
        let revoked_at = u32::from_be_bytes(bytes[65..69].try_into().unwrap());
        let mut signature = [0u8; SIGNATURE_LEN];
        signature.copy_from_slice(&bytes[REVOCATION_HEADER_LEN..REVOCATION_LEN]);

        Ok(Revocation { version, root_pk, device_pk, revoked_at, signature })
    }

    /// Sign in place, overwriting any prior signature.
    pub fn sign(&mut self, root_secret: &SecretKey) {
        let msg = self.pre_signature_bytes();
        self.signature = root_secret.sign(&msg).to_bytes();
    }

    /// `version == 1` and the signature verifies against the embedded
    /// `root_pk`. A verified revocation permanently invalidates the named
    /// device's certificates for that root regardless of `expires_at` — that
    /// invalidation is applied via [`DeviceCert::is_revoked_by`], not here.
    pub fn verify(&self) -> Result<()> {
        if self.version != VERSION {
            bail!("revocation: unsupported version {} (expected {VERSION})", self.version);
        }
        let msg = self.pre_signature_bytes();
        let sig = Signature::from_bytes(&self.signature);
        self.root_pk.verify(&msg, &sig).context("revocation: signature verification failed")
    }
}

// ---------------------------------------------------------------------------
// QR-link payload ("azl") — unsigned, carries no authority
// ---------------------------------------------------------------------------

/// A decoded (or about-to-be-encoded) QR-link payload. Unlike the cert and
/// revocation, this carries no signature — it's an invitation to be scanned,
/// not a grant of authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkPayload {
    pub version: u8,
    pub device_pk: PublicKey,
    pub name: String,
    /// Opaque connect ticket bytes (e.g. `iroh_tickets::endpoint::EndpointTicket::encode_bytes`).
    pub ticket: Vec<u8>,
}

impl LinkPayload {
    /// Construct a new (v1) link payload for `device_pk`/`name`/`ticket` —
    /// convenience so callers outside this module (e.g. `azula link`) don't
    /// need to know the wire version number.
    pub fn new(device_pk: PublicKey, name: String, ticket: Vec<u8>) -> Self {
        LinkPayload { version: VERSION, device_pk, name, ticket }
    }

    fn to_wire_bytes(&self) -> Vec<u8> {
        debug_assert!(self.name.len() <= u8::MAX as usize, "link: name_len must fit in 1 byte");
        debug_assert!(self.ticket.len() <= u16::MAX as usize, "link: ticket_len must fit in 2 bytes");
        let mut buf = Vec::with_capacity(LINK_HEADER_LEN + self.name.len() + 2 + self.ticket.len());
        buf.push(self.version);
        buf.extend_from_slice(self.device_pk.as_bytes());
        buf.push(self.name.len() as u8);
        buf.extend_from_slice(self.name.as_bytes());
        buf.extend_from_slice(&(self.ticket.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.ticket);
        buf
    }

    /// Encode as `"azl" + base32(payload)`, RFC 4648 no-pad, lowercase.
    pub fn encode(&self) -> String {
        encode_with_prefix(LINK_PREFIX, &self.to_wire_bytes())
    }

    /// Decode from the `"azl…"` string form. Rejects wrong prefix, bad
    /// base32, truncation at any of the two variable-length fields, overlong
    /// trailing bytes, and a non-UTF-8 name.
    pub fn decode(s: &str) -> Result<Self> {
        let bytes = decode_with_prefix(LINK_PREFIX, s)?;
        Self::decode_bytes(&bytes)
    }

    fn decode_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < LINK_HEADER_LEN {
            bail!(
                "link: payload truncated (need at least {LINK_HEADER_LEN} header bytes, got {})",
                bytes.len()
            );
        }
        let version = bytes[0];
        if version != VERSION {
            bail!("link: unsupported version {version} (expected {VERSION})");
        }
        let device_pk = PublicKey::from_bytes(bytes[1..33].try_into().unwrap())
            .context("link: invalid device_pk")?;
        let name_len = bytes[33] as usize;

        let name_end = LINK_HEADER_LEN
            .checked_add(name_len)
            .context("link: name_len overflow")?;
        let ticket_len_end = name_end
            .checked_add(2)
            .context("link: ticket_len offset overflow")?;
        if bytes.len() < ticket_len_end {
            bail!(
                "link: payload truncated mid-name (need at least {ticket_len_end} bytes, got {})",
                bytes.len()
            );
        }
        let name = std::str::from_utf8(&bytes[LINK_HEADER_LEN..name_end])
            .context("link: name is not valid UTF-8")?
            .to_string();

        let ticket_len = u16::from_be_bytes(bytes[name_end..ticket_len_end].try_into().unwrap()) as usize;
        let expected_len = ticket_len_end
            .checked_add(ticket_len)
            .context("link: ticket_len overflow")?;
        if bytes.len() < expected_len {
            bail!(
                "link: payload truncated mid-ticket (need exactly {expected_len} bytes, got {})",
                bytes.len()
            );
        }
        if bytes.len() > expected_len {
            bail!(
                "link: payload overlong (need exactly {expected_len} bytes, got {})",
                bytes.len()
            );
        }
        let ticket = bytes[ticket_len_end..expected_len].to_vec();

        Ok(LinkPayload { version, device_pk, name, ticket })
    }
}

// ---------------------------------------------------------------------------
// Verification words (task 2.5): SHA-256(lower_pk || higher_pk) -> 4 BIP-39
// words, for the QR-link enrollment screen shown on both devices.
// ---------------------------------------------------------------------------

/// Derive the four BIP-39 verification words for a QR-link session between
/// two device public keys. Per the spec: `SHA-256(lower_pk || higher_pk)`
/// where the two keys are sorted bytewise ascending, then the first 44 bits
/// are read as four 11-bit big-endian indices into the BIP-39 English
/// wordlist ([`crate::bip39_wordlist::WORDLIST`]).
///
/// Argument order doesn't matter — the two keys are sorted internally, so
/// both sides of a link (whichever key they pass first) derive the same
/// four words.
pub fn verification_words(a: &PublicKey, b: &PublicKey) -> [&'static str; 4] {
    let (lower, higher) = if a.as_bytes() <= b.as_bytes() { (a, b) } else { (b, a) };

    let mut hasher = Sha256::new();
    hasher.update(lower.as_bytes());
    hasher.update(higher.as_bytes());
    let digest = hasher.finalize();

    let mut words = [""; 4];
    for (i, slot) in words.iter_mut().enumerate() {
        let idx = read_11_bits(&digest, i * 11);
        *slot = WORDLIST[idx as usize];
    }
    words
}

/// Read an 11-bit big-endian value starting at bit offset `bit_offset` (bit 0
/// is the most-significant bit of `bytes[0]`), MSB-first, across byte
/// boundaries as needed.
fn read_11_bits(bytes: &[u8], bit_offset: usize) -> u16 {
    let mut value: u16 = 0;
    for i in 0..11 {
        let bit_index = bit_offset + i;
        let byte = bytes[bit_index / 8];
        let bit = (byte >> (7 - (bit_index % 8))) & 1;
        value = (value << 1) | u16::from(bit);
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Fixed test fixtures --------------------------------------------
    //
    // Fixed, hardcoded 32-byte secret key seeds (never random) so every
    // encoding here is deterministic and reproducible. Task 2.4 lifts these
    // into cross-language vectors, so they're kept as obvious, named consts
    // rather than generated inline.

    #[cfg(test)]
    mod fixtures {
        /// Root identity secret key seed (test-only, never a real identity):
        /// 32 sequential bytes 0x00..=0x1f.
        pub const ROOT_SEED: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        /// A first device's secret key seed: 32 sequential bytes 0x20..=0x3f.
        pub const DEVICE_SEED: [u8; 32] = [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
            0x3c, 0x3d, 0x3e, 0x3f,
        ];
        /// A second device's secret key seed, for verification-word and
        /// multi-device tests: 32 sequential bytes 0x40..=0x5f.
        pub const DEVICE2_SEED: [u8; 32] = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
            0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b,
            0x5c, 0x5d, 0x5e, 0x5f,
        ];
    }
    use fixtures::{DEVICE2_SEED, DEVICE_SEED, ROOT_SEED};

    fn root_secret() -> SecretKey {
        SecretKey::from_bytes(&ROOT_SEED)
    }
    fn device_secret() -> SecretKey {
        SecretKey::from_bytes(&DEVICE_SEED)
    }
    fn device2_secret() -> SecretKey {
        SecretKey::from_bytes(&DEVICE2_SEED)
    }

    fn signed_cert(name: &str, expires_at: u32) -> DeviceCert {
        let root = root_secret();
        let device = device_secret();
        let mut cert = DeviceCert {
            version: VERSION,
            flags: FLAG_MAILBOX,
            root_pk: root.public(),
            device_pk: device.public(),
            issued_at: 1_767_225_600,
            expires_at,
            name: name.to_string(),
            signature: [0u8; SIGNATURE_LEN],
        };
        cert.sign(&root);
        cert
    }

    // --- DeviceCert: round-trip ------------------------------------------

    #[test]
    fn cert_round_trips_through_encode_decode() {
        let cert = signed_cert("phone", 0);
        let encoded = cert.encode();
        assert!(encoded.starts_with(CERT_PREFIX));
        let decoded = DeviceCert::decode(&encoded).expect("decodes");
        assert_eq!(decoded, cert);
        decoded.verify().expect("verifies");
    }

    #[test]
    fn cert_flags_round_trip_including_reserved_bits() {
        // Reserved bits 2-7 are "0 on encode, ignored on decode" for certs we
        // mint — but a byte-for-byte round trip of a foreign cert (one we
        // only decode, never re-sign) must still preserve them exactly.
        let mut cert = signed_cert("phone", 0);
        cert.flags = 0xff; // mailbox + bot + all reserved bits
        cert.sign(&root_secret());
        let decoded = DeviceCert::decode(&cert.encode()).expect("decodes");
        assert_eq!(decoded.flags, 0xff);
        assert!(decoded.is_mailbox());
        assert!(decoded.is_bot());
    }

    #[test]
    fn cert_truncated_is_rejected() {
        let cert = signed_cert("phone", 0);
        let bytes = cert.to_wire_bytes();
        let err = DeviceCert::decode_bytes(&bytes[..bytes.len() - 1]).unwrap_err();
        assert!(err.to_string().contains("truncated"), "{err}");
    }

    #[test]
    fn cert_overlong_is_rejected() {
        let cert = signed_cert("phone", 0);
        let mut bytes = cert.to_wire_bytes();
        bytes.push(0xaa);
        let err = DeviceCert::decode_bytes(&bytes).unwrap_err();
        assert!(err.to_string().contains("overlong"), "{err}");
    }

    #[test]
    fn cert_bad_prefix_is_rejected() {
        let cert = signed_cert("phone", 0);
        let encoded = cert.encode();
        let bad = format!("azx{}", &encoded[3..]);
        let err = DeviceCert::decode(&bad).unwrap_err();
        assert!(err.to_string().contains("prefix"), "{err}");
    }

    #[test]
    fn cert_bad_base32_is_rejected() {
        let err = DeviceCert::decode("azd not-valid-base32!!!").unwrap_err();
        assert!(err.to_string().contains("base32"), "{err}");
    }

    #[test]
    fn cert_name_len_over_63_is_rejected() {
        let cert = signed_cert("phone", 0);
        let mut bytes = cert.to_wire_bytes();
        bytes[74] = 64; // name_len byte
        let err = DeviceCert::decode_bytes(&bytes).unwrap_err();
        assert!(err.to_string().contains("name_len"), "{err}");
    }

    #[test]
    fn cert_non_utf8_name_is_rejected() {
        let mut cert = signed_cert("ok", 0);
        cert.name = "ok".to_string();
        cert.sign(&root_secret());
        let mut bytes = cert.to_wire_bytes();
        // name occupies bytes [75, 75+2); poke an invalid UTF-8 byte into it.
        bytes[75] = 0xff;
        let err = DeviceCert::decode_bytes(&bytes).unwrap_err();
        assert!(err.to_string().contains("UTF-8"), "{err}");
    }

    #[test]
    fn cert_version_mismatch_is_rejected() {
        let cert = signed_cert("phone", 0);
        let mut bytes = cert.to_wire_bytes();
        bytes[0] = 0x02;
        let err = DeviceCert::decode_bytes(&bytes).unwrap_err();
        assert!(err.to_string().contains("version"), "{err}");
    }

    #[test]
    fn cert_expires_at_zero_never_expires() {
        let cert = signed_cert("phone", 0);
        cert.verify().expect("never expires");
    }

    #[test]
    fn cert_expired_fails() {
        let cert = signed_cert("phone", 1); // 1 second past epoch: always past
        let err = cert.verify().unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
    }

    #[test]
    fn cert_tampered_signature_fails() {
        let mut cert = signed_cert("phone", 0);
        cert.signature[0] ^= 0xff;
        assert!(cert.verify().is_err());
    }

    #[test]
    fn cert_wrong_connection_node_id_does_not_bind() {
        let cert = signed_cert("phone", 0);
        assert!(cert.binds_to_connection(cert.device_pk));
        assert!(!cert.binds_to_connection(device2_secret().public()));
    }

    #[test]
    fn cert_revoked_device_is_rejected() {
        let cert = signed_cert("phone", 0);
        let root = root_secret();
        let mut revocation = Revocation {
            version: VERSION,
            root_pk: root.public(),
            device_pk: cert.device_pk,
            revoked_at: 1_767_225_600,
            signature: [0u8; SIGNATURE_LEN],
        };
        revocation.sign(&root);
        revocation.verify().expect("revocation verifies");
        assert!(cert.is_revoked_by(&[revocation]));

        // A revocation for a different device doesn't match.
        let mut other = Revocation {
            version: VERSION,
            root_pk: root.public(),
            device_pk: device2_secret().public(),
            revoked_at: 1_767_225_600,
            signature: [0u8; SIGNATURE_LEN],
        };
        other.sign(&root);
        assert!(!cert.is_revoked_by(&[other]));
    }

    // --- Session certificates (design.md D1/D3) -----------------------------

    #[test]
    fn session_cert_mint_and_verify_happy_path() {
        let machine = root_secret();
        let session = device_secret();
        let cert = mint_session_cert(&machine, session.public(), DEFAULT_SESSION_EXPIRY);

        assert_eq!(cert.root_pk, machine.public());
        assert_eq!(cert.device_pk, session.public());
        assert!(cert.is_session());
        assert!(!cert.is_mailbox());

        verify_session_cert(&cert, session.public()).expect("valid session cert should verify");
    }

    #[test]
    fn session_cert_expired_is_rejected() {
        let machine = root_secret();
        let session = device_secret();
        let mut cert = mint_session_cert(&machine, session.public(), DEFAULT_SESSION_EXPIRY);
        // Force expiry into the past and re-sign (mint_session_cert already
        // signed with the future expiry — mutate + re-sign so the signature
        // still matches the tampered expires_at).
        cert.expires_at = 1;
        cert.sign(&machine);

        let err = verify_session_cert(&cert, session.public()).unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
    }

    #[test]
    fn session_cert_missing_flag_session_is_rejected() {
        let machine = root_secret();
        let session = device_secret();
        // A cert that verifies fine (well-formed, signed, unexpired) but was
        // never flagged as a session cert — e.g. a plain mailbox device cert.
        let mut cert = mint_session_cert(&machine, session.public(), DEFAULT_SESSION_EXPIRY);
        cert.flags = FLAG_MAILBOX;
        cert.sign(&machine);

        cert.verify().expect("cert is otherwise well-formed");
        let err = verify_session_cert(&cert, session.public()).unwrap_err();
        assert!(err.to_string().contains("FLAG_SESSION"), "{err}");
    }

    #[test]
    fn session_cert_transport_binding_mismatch_is_rejected() {
        let machine = root_secret();
        let session = device_secret();
        let other = device2_secret();
        let cert = mint_session_cert(&machine, session.public(), DEFAULT_SESSION_EXPIRY);

        // The cert itself is perfectly valid; it just isn't presented on a
        // connection whose transport peer id matches device_pk.
        let err = verify_session_cert(&cert, other.public()).unwrap_err();
        assert!(err.to_string().contains("transport"), "{err}");
    }

    #[test]
    fn self_certified_session_verifies() {
        let session = device_secret();
        let cert = mint_self_certified_session(&session, DEFAULT_SESSION_EXPIRY);

        assert_eq!(cert.root_pk, session.public());
        assert_eq!(cert.device_pk, session.public(), "self-cert: root_pk == device_pk == session_pk");
        assert!(cert.is_session());

        verify_session_cert(&cert, session.public()).expect("self-certified session cert should verify");
    }

    // --- Revocation --------------------------------------------------------

    fn signed_revocation() -> Revocation {
        let root = root_secret();
        let mut r = Revocation {
            version: VERSION,
            root_pk: root.public(),
            device_pk: device_secret().public(),
            revoked_at: 1_767_225_600,
            signature: [0u8; SIGNATURE_LEN],
        };
        r.sign(&root);
        r
    }

    #[test]
    fn revocation_round_trips_through_encode_decode() {
        let r = signed_revocation();
        let encoded = r.encode();
        assert!(encoded.starts_with(REVOCATION_PREFIX));
        let decoded = Revocation::decode(&encoded).expect("decodes");
        assert_eq!(decoded, r);
        decoded.verify().expect("verifies");
    }

    #[test]
    fn revocation_truncated_is_rejected() {
        let r = signed_revocation();
        let bytes = r.to_wire_bytes();
        let err = Revocation::decode_bytes(&bytes[..bytes.len() - 1]).unwrap_err();
        assert!(err.to_string().contains("truncated"), "{err}");
    }

    #[test]
    fn revocation_overlong_is_rejected() {
        let r = signed_revocation();
        let mut bytes = r.to_wire_bytes();
        bytes.push(0);
        let err = Revocation::decode_bytes(&bytes).unwrap_err();
        assert!(err.to_string().contains("overlong"), "{err}");
    }

    #[test]
    fn revocation_bad_prefix_is_rejected() {
        let bad = format!("azx{}", &signed_revocation().encode()[3..]);
        let err = Revocation::decode(&bad).unwrap_err();
        assert!(err.to_string().contains("prefix"), "{err}");
    }

    #[test]
    fn revocation_bad_base32_is_rejected() {
        let err = Revocation::decode("azr???").unwrap_err();
        assert!(err.to_string().contains("base32"), "{err}");
    }

    #[test]
    fn revocation_tampered_signature_fails() {
        let mut r = signed_revocation();
        r.signature[0] ^= 0xff;
        assert!(r.verify().is_err());
    }

    // --- LinkPayload ---------------------------------------------------------

    fn link_payload(name: &str) -> LinkPayload {
        LinkPayload {
            version: VERSION,
            device_pk: device_secret().public(),
            name: name.to_string(),
            ticket: b"azula-test-endpoint-ticket-bytes".to_vec(),
        }
    }

    #[test]
    fn link_new_constructs_current_version() {
        let ticket = b"azula-test-endpoint-ticket-bytes".to_vec();
        let payload = LinkPayload::new(device_secret().public(), "laptop".to_string(), ticket);
        assert_eq!(payload.version, VERSION);
        assert_eq!(payload, link_payload("laptop"));
    }

    #[test]
    fn link_round_trips_through_encode_decode() {
        let payload = link_payload("laptop");
        let encoded = payload.encode();
        assert!(encoded.starts_with(LINK_PREFIX));
        let decoded = LinkPayload::decode(&encoded).expect("decodes");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn link_truncated_is_rejected() {
        let bytes = link_payload("laptop").to_wire_bytes();
        let err = LinkPayload::decode_bytes(&bytes[..bytes.len() - 1]).unwrap_err();
        assert!(err.to_string().contains("truncated"), "{err}");
    }

    #[test]
    fn link_overlong_is_rejected() {
        let mut bytes = link_payload("laptop").to_wire_bytes();
        bytes.push(0);
        let err = LinkPayload::decode_bytes(&bytes).unwrap_err();
        assert!(err.to_string().contains("overlong"), "{err}");
    }

    #[test]
    fn link_bad_prefix_is_rejected() {
        let bad = format!("azx{}", &link_payload("laptop").encode()[3..]);
        let err = LinkPayload::decode(&bad).unwrap_err();
        assert!(err.to_string().contains("prefix"), "{err}");
    }

    #[test]
    fn link_bad_base32_is_rejected() {
        let err = LinkPayload::decode("azl***").unwrap_err();
        assert!(err.to_string().contains("base32"), "{err}");
    }

    #[test]
    fn link_non_utf8_name_is_rejected() {
        let mut bytes = link_payload("ok").to_wire_bytes();
        // name occupies bytes [34, 34+2); poke an invalid UTF-8 byte into it.
        bytes[34] = 0xff;
        let err = LinkPayload::decode_bytes(&bytes).unwrap_err();
        assert!(err.to_string().contains("UTF-8"), "{err}");
    }

    #[test]
    fn link_version_mismatch_is_rejected() {
        let mut bytes = link_payload("laptop").to_wire_bytes();
        bytes[0] = 0x02;
        let err = LinkPayload::decode_bytes(&bytes).unwrap_err();
        assert!(err.to_string().contains("version"), "{err}");
    }

    // --- Verification words (task 2.5) --------------------------------------

    #[test]
    fn verification_words_are_order_independent() {
        let a = device_secret().public();
        let b = device2_secret().public();
        assert_eq!(verification_words(&a, &b), verification_words(&b, &a));
    }

    /// Fixed vector: `verification_words(DEVICE_SEED.public, DEVICE2_SEED.public)`
    /// pinned as literals so task 2.4 can lift this exact vector into the
    /// cross-language (Kotlin) test suite. Argument order doesn't matter (see
    /// `verification_words_are_order_independent`) — the function sorts the
    /// two keys bytewise itself before hashing.
    #[test]
    fn verification_words_fixed_vector() {
        let a = device_secret().public();
        let b = device2_secret().public();
        let words = verification_words(&a, &b);
        assert_eq!(words, ["lab", "chest", "brief", "dial"]);
    }

    /// Cross-language test vector (task 2.4): fixed root/device keypairs and
    /// timestamps, real Ed25519 (not `FakeEd25519`), pinned so a Kotlin test can decode these
    /// exact literals and assert a byte-identical re-encode. See
    /// `azula-docs/openspec/changes/multi-device-identity/design.md`'s "Cross-Language Test
    /// Vectors" section for the full recorded vector.
    #[test]
    fn cross_language_vector_cert_and_revocation() {
        let root = root_secret();
        let device = device_secret();

        let root_pk_hex = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
        let device_pk_hex = "29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7";
        assert_eq!(data_encoding::HEXLOWER.encode(root.public().as_bytes()), root_pk_hex);
        assert_eq!(data_encoding::HEXLOWER.encode(device.public().as_bytes()), device_pk_hex);

        let mut cert = DeviceCert {
            version: VERSION,
            flags: FLAG_MAILBOX,
            root_pk: root.public(),
            device_pk: device.public(),
            issued_at: 1700000000,
            expires_at: 0,
            name: "phone".to_string(),
            signature: [0u8; SIGNATURE_LEN],
        };
        cert.sign(&root);
        let cert_str = "azdaeaqhiihx7z44ef6dvyn2ghhjpajsz7e2yyjxjinl4o5zbtecjktdobjvs5ocqn4zlylelq2stju2c6hgypfe3il7yjmrf4uxsjsfftn25svh4iaaaaaaaafobug63tfmaoceghoxhw2izrder7gokgmn5mtfm6dcccvqx376ddtmdz5swwdr4wykbkbc6bepxvgiufuqe2anhvsakshdxcriw5q2yly35bjidq";
        assert_eq!(cert.encode(), cert_str);
        let decoded = DeviceCert::decode(cert_str).expect("decodes");
        assert_eq!(decoded, cert);
        decoded.verify().expect("verifies");

        let mut revocation = Revocation {
            version: VERSION,
            root_pk: root.public(),
            device_pk: device.public(),
            revoked_at: 1700100000,
            signature: [0u8; SIGNATURE_LEN],
        };
        revocation.sign(&root);
        let revocation_str = "azraeb2cb576phbbpq5odorrz2lycmwpzgwgcn2kdk7dxoimzaskuy3qknmxlqudpgk6czc4guu2ngqxrzwdzjg2c76clejpff4smrjm3oxmvkxpiaxs7pd5e3ex3xekzy7yomqy3hyyshxcsw275gv7gbi45c7buxlsjmywp7nnwtixxhfixig32cgjge624upt6tztt2eqovmqiroq4ma4";
        assert_eq!(revocation.encode(), revocation_str);
        let decoded_revocation = Revocation::decode(revocation_str).expect("decodes");
        assert_eq!(decoded_revocation, revocation);
        decoded_revocation.verify().expect("verifies");
    }
}
