//! Invite payload codec, signing, and the issuer-side invite store.
//!
//! See `azula-docs/docs/invitations.md` for the full spec: payload layout,
//! encoding, link formats, verification rules, and the shared test vectors
//! this module's tests must pass byte-for-byte.
//!
//! Wire layout (all integers big-endian):
//!
//! ```text
//! offset  size  field
//! 0       1     version (0x01)
//! 1       1     flags (bit0 = signed, bit1 = single-use)
//! 2       8     invite_id
//! 10      4     issued_at (unix seconds)
//! 14      4     expires_at (unix seconds; 0 = never)
//! 18      2     ticket_len (n)
//! 20      n     ticket (opaque EndpointTicket bytes)
//! 20+n    64    signature (present iff flags bit0), Ed25519 over [0, 20+n)
//! ```
//!
//! Encoded string form: `"azi" + base32(payload)`, RFC 4648 no-padding,
//! lowercase.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use iroh::{PublicKey, SecretKey, Signature};
use iroh_tickets::endpoint::EndpointTicket;
use iroh_tickets::Ticket as _;
use serde::{Deserialize, Serialize};

/// bit 0 of `flags`: the payload carries a trailing Ed25519 signature.
pub const FLAG_SIGNED: u8 = 0x01;
/// bit 1 of `flags`: the invite is single-use (consumed on first successful accept).
pub const FLAG_SINGLE_USE: u8 = 0x02;

const VERSION: u8 = 1;
const PREFIX: &str = "azi";
/// Fixed header size before the variable-length ticket: version(1) + flags(1)
/// + invite_id(8) + issued_at(4) + expires_at(4) + ticket_len(2).
const HEADER_LEN: usize = 20;
const SIGNATURE_LEN: usize = 64;

/// A decoded (or about-to-be-encoded) invite payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitePayload {
    pub version: u8,
    pub flags: u8,
    pub invite_id: [u8; 8],
    pub issued_at: u32,
    pub expires_at: u32,
    /// Opaque issuer `EndpointTicket` bytes (`iroh_tickets::Ticket::encode_bytes`).
    pub ticket: Vec<u8>,
    pub signature: Option<[u8; SIGNATURE_LEN]>,
}

impl InvitePayload {
    pub fn is_signed(&self) -> bool {
        self.flags & FLAG_SIGNED != 0
    }

    pub fn is_single_use(&self) -> bool {
        self.flags & FLAG_SINGLE_USE != 0
    }

    /// Lowercase-hex render of `invite_id` — the display fingerprint.
    pub fn invite_id_hex(&self) -> String {
        hex_encode(&self.invite_id)
    }

    /// Bytes covered by the signature: everything up to (not including) the
    /// signature itself.
    fn pre_signature_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_LEN + self.ticket.len());
        buf.push(self.version);
        buf.push(self.flags);
        buf.extend_from_slice(&self.invite_id);
        buf.extend_from_slice(&self.issued_at.to_be_bytes());
        buf.extend_from_slice(&self.expires_at.to_be_bytes());
        buf.extend_from_slice(&(self.ticket.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.ticket);
        buf
    }

    /// Full wire bytes, including the trailing signature if present.
    fn to_wire_bytes(&self) -> Vec<u8> {
        let mut buf = self.pre_signature_bytes();
        if let Some(sig) = &self.signature {
            buf.extend_from_slice(sig);
        }
        buf
    }

    /// Encode as `"azi" + base32(payload)`, RFC 4648 no-pad, lowercase.
    pub fn encode(&self) -> String {
        let mut out = String::from(PREFIX);
        data_encoding::BASE32_NOPAD.encode_append(&self.to_wire_bytes(), &mut out);
        out.make_ascii_lowercase();
        out
    }

    /// Decode from the `"azi…"` string form. Rejects anything that doesn't
    /// decode, or whose inner structure is inconsistent: wrong prefix, bad
    /// base32, truncation, a `ticket_len` that overruns the buffer, or a
    /// missing/short signature when flags bit 0 is set.
    pub fn decode(s: &str) -> Result<Self> {
        let rest = s.strip_prefix(PREFIX).context("invite: missing \"azi\" prefix")?;
        let bytes = data_encoding::BASE32_NOPAD
            .decode(rest.to_ascii_uppercase().as_bytes())
            .context("invite: invalid base32")?;
        Self::decode_bytes(&bytes)
    }

    fn decode_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            bail!(
                "invite: payload truncated (need at least {HEADER_LEN} header bytes, got {})",
                bytes.len()
            );
        }
        let version = bytes[0];
        if version != VERSION {
            bail!("invite: unsupported version {version} (expected {VERSION})");
        }
        let flags = bytes[1];
        let mut invite_id = [0u8; 8];
        invite_id.copy_from_slice(&bytes[2..10]);
        let issued_at = u32::from_be_bytes(bytes[10..14].try_into().unwrap());
        let expires_at = u32::from_be_bytes(bytes[14..18].try_into().unwrap());
        let ticket_len = u16::from_be_bytes(bytes[18..20].try_into().unwrap()) as usize;

        let ticket_end = HEADER_LEN
            .checked_add(ticket_len)
            .context("invite: ticket_len overflow")?;
        if bytes.len() < ticket_end {
            bail!(
                "invite: payload truncated mid-ticket (need {ticket_end} bytes, got {})",
                bytes.len()
            );
        }
        let ticket = bytes[HEADER_LEN..ticket_end].to_vec();

        let signature = if flags & FLAG_SIGNED != 0 {
            let sig_end = ticket_end
                .checked_add(SIGNATURE_LEN)
                .context("invite: signature length overflow")?;
            if bytes.len() < sig_end {
                bail!("invite: flagged signed but signature is missing or truncated");
            }
            let mut sig = [0u8; SIGNATURE_LEN];
            sig.copy_from_slice(&bytes[ticket_end..sig_end]);
            Some(sig)
        } else {
            None
        };

        Ok(InvitePayload { version, flags, invite_id, issued_at, expires_at, ticket, signature })
    }

    /// Sign in place: sets the signed flag bit and computes the signature
    /// over the pre-signature bytes with `key`. Overwrites any prior signature.
    pub fn sign(&mut self, key: &SecretKey) {
        self.flags |= FLAG_SIGNED;
        let msg = self.pre_signature_bytes();
        self.signature = Some(key.sign(&msg).to_bytes());
    }

    /// Verify the trailing signature against `key`. Errors if unsigned or invalid.
    pub fn verify_signature(&self, key: &PublicKey) -> Result<()> {
        let sig_bytes = self.signature.context("invite: no signature to verify")?;
        let msg = self.pre_signature_bytes();
        let sig = Signature::from_bytes(&sig_bytes);
        key.verify(&msg, &sig).context("invite: signature verification failed")
    }

    /// Decode the embedded ticket bytes into an [`EndpointTicket`].
    pub fn ticket(&self) -> Result<EndpointTicket> {
        EndpointTicket::decode_bytes(&self.ticket).context("invite: embedded ticket bytes are invalid")
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn now_unix() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Issuer-side store: ~/.azula/invites.json
// ---------------------------------------------------------------------------

/// An invite this node has minted, as persisted in the issuer-side store.
/// Revocation is deletion from this list.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssuedInvite {
    /// Lowercase-hex `invite_id` — also the display fingerprint.
    pub id: String,
    pub created_at: u32,
    /// Unix seconds; `0` = never expires.
    pub expires_at: u32,
    pub flags: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default)]
    pub consumed: bool,
}

impl IssuedInvite {
    pub fn is_signed(&self) -> bool {
        self.flags & FLAG_SIGNED != 0
    }
    pub fn is_single_use(&self) -> bool {
        self.flags & FLAG_SINGLE_USE != 0
    }
    pub fn is_expired(&self, now: u32) -> bool {
        self.expires_at != 0 && now >= self.expires_at
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct StoreFile {
    #[serde(default)]
    issued: Vec<IssuedInvite>,
}

/// Directory the invite store lives in: `AZULA_INVITES_DIR` override, else
/// `~/.azula`. Mirrors `registry::global_path`'s override convention.
/// Returns `None` only if there's no override and `$HOME` is unset.
pub fn store_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("AZULA_INVITES_DIR") {
        return Some(PathBuf::from(dir));
    }
    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".azula"))
}

/// `~/.azula/invites.json`, or the `AZULA_INVITES_DIR` override.
pub fn store_path() -> Option<PathBuf> {
    store_dir().map(|d| d.join("invites.json"))
}

fn load_store_in(dir: &Path) -> StoreFile {
    let data = match std::fs::read_to_string(dir.join("invites.json")) {
        Ok(s) => s,
        Err(_) => return StoreFile::default(),
    };
    serde_json::from_str(&data).unwrap_or_default()
}

fn save_store_in(dir: &Path, store: &StoreFile) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create dirs {}", dir.display()))?;
    let path = dir.join("invites.json");
    let content = serde_json::to_string_pretty(store)?;
    std::fs::write(&path, content).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// List all issued invites (oldest first, as stored) from the default store dir.
pub fn list() -> Vec<IssuedInvite> {
    match store_dir() {
        Some(dir) => list_in(&dir),
        None => Vec::new(),
    }
}

/// As [`list`], but against an explicit store directory (used by tests, and
/// by callers that already resolved [`store_dir`]).
pub fn list_in(dir: &Path) -> Vec<IssuedInvite> {
    load_store_in(dir).issued
}

/// How long an invite should live, per `--expires`.
#[derive(Debug, Clone, Copy)]
pub enum Expiry {
    Never,
    In(std::time::Duration),
}

impl Expiry {
    fn expires_at(self, issued_at: u32) -> u32 {
        match self {
            Expiry::Never => 0,
            Expiry::In(d) => issued_at.saturating_add(d.as_secs() as u32),
        }
    }
}

/// Mint a new invite wrapping `ticket` (the issuer's own dialable
/// `EndpointTicket`, in its canonical string form) against the default store
/// dir (`AZULA_INVITES_DIR` or `~/.azula`).
pub fn mint(
    ticket_str: &str,
    expiry: Expiry,
    sign: bool,
    single_use: bool,
    label: Option<String>,
    secret_key: &SecretKey,
) -> Result<(InvitePayload, IssuedInvite)> {
    let dir = store_dir().context("cannot resolve invite store dir ($HOME unset)")?;
    mint_in(&dir, ticket_str, expiry, sign, single_use, label, secret_key)
}

/// As [`mint`], but against an explicit store directory. Persists the
/// [`IssuedInvite`] record and returns it alongside the payload (ready to
/// `.encode()`).
pub fn mint_in(
    dir: &Path,
    ticket_str: &str,
    expiry: Expiry,
    sign: bool,
    single_use: bool,
    label: Option<String>,
    secret_key: &SecretKey,
) -> Result<(InvitePayload, IssuedInvite)> {
    let ticket = EndpointTicket::from_str(ticket_str).context("invite: invalid own ticket")?;
    let ticket_bytes = ticket.encode_bytes();

    let issued_at = now_unix();
    let expires_at = expiry.expires_at(issued_at);

    let mut flags = 0u8;
    if single_use {
        flags |= FLAG_SINGLE_USE;
    }

    // Random 8-byte nonce, drawn from a freshly generated Ed25519 key's CSPRNG
    // output rather than pulling in a `rand` dependency.
    let invite_id: [u8; 8] = SecretKey::generate().to_bytes()[..8].try_into().unwrap();

    let mut payload = InvitePayload {
        version: VERSION,
        flags,
        invite_id,
        issued_at,
        expires_at,
        ticket: ticket_bytes,
        signature: None,
    };
    if sign {
        payload.sign(secret_key);
    }

    let record = IssuedInvite {
        id: payload.invite_id_hex(),
        created_at: issued_at,
        expires_at,
        flags: payload.flags,
        label,
        consumed: false,
    };

    let mut store = load_store_in(dir);
    store.issued.push(record.clone());
    save_store_in(dir, &store)?;

    Ok((payload, record))
}

/// Revoke (delete) every issued invite whose id starts with `id_prefix`, in
/// the default store dir. Returns the number removed.
pub fn revoke(id_prefix: &str) -> Result<usize> {
    let dir = store_dir().context("cannot resolve invite store dir ($HOME unset)")?;
    revoke_in(&dir, id_prefix)
}

/// As [`revoke`], but against an explicit store directory.
pub fn revoke_in(dir: &Path, id_prefix: &str) -> Result<usize> {
    let mut store = load_store_in(dir);
    let before = store.issued.len();
    store.issued.retain(|i| !i.id.starts_with(id_prefix));
    let removed = before - store.issued.len();
    if removed > 0 {
        save_store_in(dir, &store)?;
    }
    Ok(removed)
}

/// Mark an issued invite consumed (single-use gate) in the default store dir.
/// No-op if unknown.
pub fn mark_consumed(id: &str) -> Result<()> {
    let dir = store_dir().context("cannot resolve invite store dir ($HOME unset)")?;
    mark_consumed_in(&dir, id)
}

/// As [`mark_consumed`], but against an explicit store directory.
pub fn mark_consumed_in(dir: &Path, id: &str) -> Result<()> {
    let mut store = load_store_in(dir);
    if let Some(rec) = store.issued.iter_mut().find(|i| i.id == id) {
        rec.consumed = true;
        save_store_in(dir, &store)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Verification (accept side)
// ---------------------------------------------------------------------------

/// The result of successfully verifying an inbound invite token.
#[derive(Debug, Clone)]
pub struct VerifiedInvite {
    pub invite_id: String,
    pub ticket: EndpointTicket,
    pub label: Option<String>,
    pub single_use: bool,
}

/// Verify an inbound invite token against the default store dir. See
/// [`verify_inbound_in`] for the rules.
pub fn verify_inbound(token: &str, my_node_id: PublicKey, my_key: &PublicKey) -> Result<VerifiedInvite> {
    let dir = store_dir().context("cannot resolve invite store dir ($HOME unset)")?;
    verify_inbound_in(&dir, token, my_node_id, my_key)
}

/// Verify an inbound invite token per the spec's rules 1-6:
/// 1. decodes, `version == 1`;
/// 2. the embedded ticket's node id is `my_node_id`;
/// 3. `invite_id` exists in the store at `dir` (⇒ not revoked);
/// 4. not expired;
/// 5. if signed, the signature verifies against `my_key`;
/// 6. if single-use, not already consumed.
///
/// Does **not** mark the invite consumed — call [`mark_consumed_in`] after
/// the caller has actually admitted the connection.
pub fn verify_inbound_in(
    dir: &Path,
    token: &str,
    my_node_id: PublicKey,
    my_key: &PublicKey,
) -> Result<VerifiedInvite> {
    let payload = InvitePayload::decode(token)?; // rule 1 (version) enforced in decode

    let ticket = payload.ticket()?;
    if ticket.endpoint_addr().id != my_node_id {
        bail!("invite: was not issued by/addressed to this node");
    }

    let id_hex = payload.invite_id_hex();
    let store = load_store_in(dir);
    let record = store
        .issued
        .iter()
        .find(|i| i.id == id_hex)
        .context("invite: unknown or revoked")?;

    let now = now_unix();
    if payload.expires_at != 0 && now >= payload.expires_at {
        bail!("invite: expired");
    }

    if payload.is_signed() {
        payload.verify_signature(my_key)?;
    }

    if payload.is_single_use() && record.consumed {
        bail!("invite: already consumed (single-use)");
    }

    Ok(VerifiedInvite {
        invite_id: id_hex,
        ticket,
        label: record.label.clone(),
        single_use: payload.is_single_use(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Shared test vectors (azula-docs/docs/invitations.md) ---
    // Signing key: RFC 8032 TEST 1 (test-only, never a real identity).
    const TEST_SEED: [u8; 32] = hex_array_32(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    );
    const TEST_PUBLIC: [u8; 32] = hex_array_32(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    );

    const V1_PAYLOAD_HEX: &str = "01000123456789abcdef6955b900000000000020617a756c612d746573742d656e64706f696e742d7469636b65742d6279746573";
    const V1_ENCODED: &str = "aziaeaaci2fm6e2xtppnfk3saaaaaaaaabamf5hk3dbfv2gk43ufvsw4zdqn5uw45bnoruwg23foqwwe6lumvzq";

    const V2_SIGNED_INPUT_HEX: &str = "01030123456789abcdef6955b90069570a800020617a756c612d746573742d656e64706f696e742d7469636b65742d6279746573";
    const V2_SIGNATURE_HEX: &str = "9eb8e484ee62f7dcd62a1ba6e8da24d8acbb978e70390684c55d60d93feb9a48c1dd6ca3f3da5d77ea5bbeffdc20d6c905fd0c10f093841665a4177db5994907";
    const V2_ENCODED: &str = "aziaebqci2fm6e2xtppnfk3sadjk4fiaabamf5hk3dbfv2gk43ufvsw4zdqn5uw45bnoruwg23foqwwe6lumvzz5oheqtxgf5642yvbxjxi3isnrlf3s6hhaoigqtcv2ygzh7vzusgb3vwkh462lv36uw5677ocbvwjax6qyehqsocbmznec563lgkja4";

    const TEST_TICKET_ASCII: &[u8] = b"azula-test-endpoint-ticket-bytes";
    const TEST_INVITE_ID: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    const TEST_ISSUED_AT: u32 = 1767225600;
    const TEST_EXPIRES_AT_V2: u32 = 1767312000; // issued_at + 86400

    const fn hex_array_32(s: &str) -> [u8; 32] {
        let b = s.as_bytes();
        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            out[i] = (hex_val(b[i * 2]) << 4) | hex_val(b[i * 2 + 1]);
            i += 1;
        }
        out
    }

    const fn hex_val(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        }
    }

    fn hex_to_vec(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn v1_payload() -> InvitePayload {
        InvitePayload {
            version: 1,
            flags: 0x00,
            invite_id: TEST_INVITE_ID,
            issued_at: TEST_ISSUED_AT,
            expires_at: 0,
            ticket: TEST_TICKET_ASCII.to_vec(),
            signature: None,
        }
    }

    fn v2_payload() -> InvitePayload {
        InvitePayload {
            version: 1,
            flags: 0x03,
            invite_id: TEST_INVITE_ID,
            issued_at: TEST_ISSUED_AT,
            expires_at: TEST_EXPIRES_AT_V2,
            ticket: TEST_TICKET_ASCII.to_vec(),
            signature: Some(hex_to_vec(V2_SIGNATURE_HEX).try_into().unwrap()),
        }
    }

    #[test]
    fn v1_decodes_to_expected_fields() {
        let bytes = hex_to_vec(V1_PAYLOAD_HEX);
        let decoded = InvitePayload::decode_bytes(&bytes).expect("v1 decodes");
        assert_eq!(decoded, v1_payload());
        assert_eq!(decoded.invite_id_hex(), "0123456789abcdef");
    }

    #[test]
    fn v1_decode_from_encoded_string() {
        let decoded = InvitePayload::decode(V1_ENCODED).expect("v1 decodes from string");
        assert_eq!(decoded, v1_payload());
    }

    #[test]
    fn v1_reencodes_byte_identical() {
        assert_eq!(v1_payload().encode(), V1_ENCODED);
    }

    #[test]
    fn v2_decode_from_encoded_string() {
        let decoded = InvitePayload::decode(V2_ENCODED).expect("v2 decodes from string");
        assert_eq!(decoded, v2_payload());
        assert_eq!(decoded.pre_signature_bytes(), hex_to_vec(V2_SIGNED_INPUT_HEX));
    }

    #[test]
    fn v2_reencodes_byte_identical() {
        assert_eq!(v2_payload().encode(), V2_ENCODED);
    }

    #[test]
    fn version_byte_0x02_is_rejected() {
        let mut bytes = hex_to_vec(V1_PAYLOAD_HEX);
        bytes[0] = 0x02;
        let err = InvitePayload::decode_bytes(&bytes).unwrap_err();
        assert!(err.to_string().contains("version"), "{err}");
    }

    #[test]
    fn truncated_mid_ticket_is_rejected() {
        let bytes = hex_to_vec(V1_PAYLOAD_HEX);
        // Header says ticket_len=32; cut off partway through the ticket.
        let truncated = &bytes[..bytes.len() - 5];
        let err = InvitePayload::decode_bytes(truncated).unwrap_err();
        assert!(err.to_string().contains("truncated"), "{err}");
    }

    #[test]
    fn header_truncation_is_rejected() {
        let bytes = hex_to_vec(V1_PAYLOAD_HEX);
        let err = InvitePayload::decode_bytes(&bytes[..10]).unwrap_err();
        assert!(err.to_string().contains("truncated"), "{err}");
    }

    #[test]
    fn signed_flag_without_signature_bytes_is_rejected() {
        // Header + ticket only, but flags bit0 set — no trailing signature.
        let mut bytes = hex_to_vec(V1_PAYLOAD_HEX);
        bytes[1] = 0x01;
        let err = InvitePayload::decode_bytes(&bytes).unwrap_err();
        assert!(err.to_string().contains("signature"), "{err}");
    }

    #[test]
    fn v2_signature_verifies_against_test_public_key() {
        let key = PublicKey::from_bytes(&TEST_PUBLIC).expect("valid test pubkey");
        v2_payload().verify_signature(&key).expect("v2 signature verifies");
    }

    #[test]
    fn v2_signature_rejected_when_last_byte_flipped() {
        let key = PublicKey::from_bytes(&TEST_PUBLIC).expect("valid test pubkey");
        let mut tampered = v2_payload();
        let mut sig = tampered.signature.unwrap();
        sig[63] ^= 0x01;
        tampered.signature = Some(sig);
        assert!(tampered.verify_signature(&key).is_err());
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let secret = SecretKey::from_bytes(&TEST_SEED);
        // Build the V2 payload's fields but without its signature, sign it
        // ourselves, and check we reproduce the shared vector's signature
        // exactly (Ed25519 signing is deterministic per RFC 8032).
        let mut payload = v2_payload();
        payload.signature = None;
        payload.flags &= !FLAG_SIGNED;
        payload.sign(&secret);
        assert!(payload.is_signed());
        payload.verify_signature(&secret.public()).expect("self-signed verifies");
        assert_eq!(payload.signature.unwrap().to_vec(), hex_to_vec(V2_SIGNATURE_HEX));
    }

    // --- Store / verify_inbound tests ---
    //
    // Each test uses its own explicit store dir via the `_in` functions
    // (rather than the `AZULA_INVITES_DIR`-env-var-based public wrappers), so
    // tests running concurrently on other threads never race on shared
    // mutable process state.

    fn isolated_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("azula-invite-test-{}", std::process::id()))
            .join(name);
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn fake_ticket_string() -> String {
        let addr = iroh::EndpointAddr::from(SecretKey::generate().public());
        EndpointTicket::new(addr).to_string()
    }

    #[test]
    fn mint_list_revoke_round_trip() {
        let dir = isolated_dir("mint_list_revoke");
        let secret = SecretKey::generate();
        let ticket_str = fake_ticket_string();
        let (payload, record) =
            mint_in(&dir, &ticket_str, Expiry::Never, false, false, Some("phone".into()), &secret).unwrap();
        assert_eq!(record.label.as_deref(), Some("phone"));
        assert_eq!(payload.invite_id_hex(), record.id);

        let listed = list_in(&dir);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, record.id);

        let removed = revoke_in(&dir, &record.id[..6]).unwrap();
        assert_eq!(removed, 1);
        assert!(list_in(&dir).is_empty());
    }

    #[test]
    fn verify_inbound_accepts_valid_unsigned_invite() {
        let dir = isolated_dir("verify_valid");
        let secret = SecretKey::generate();
        let node_id = secret.public();
        let ticket_str = EndpointTicket::new(iroh::EndpointAddr::from(node_id)).to_string();
        let (payload, _) = mint_in(&dir, &ticket_str, Expiry::Never, false, false, None, &secret).unwrap();
        let token = payload.encode();

        let verified = verify_inbound_in(&dir, &token, node_id, &node_id).expect("verifies");
        assert_eq!(verified.invite_id, payload.invite_id_hex());
    }

    #[test]
    fn verify_inbound_rejects_unknown_invite_id() {
        let dir = isolated_dir("verify_unknown");
        let secret = SecretKey::generate();
        let node_id = secret.public();
        let ticket_str = EndpointTicket::new(iroh::EndpointAddr::from(node_id)).to_string();
        // Mint, then revoke — the token now refers to an id absent from the store.
        let (payload, record) =
            mint_in(&dir, &ticket_str, Expiry::Never, false, false, None, &secret).unwrap();
        revoke_in(&dir, &record.id).unwrap();
        let token = payload.encode();

        assert!(verify_inbound_in(&dir, &token, node_id, &node_id).is_err());
    }

    #[test]
    fn verify_inbound_rejects_expired() {
        let dir = isolated_dir("verify_expired");
        let secret = SecretKey::generate();
        let node_id = secret.public();
        let ticket_str = EndpointTicket::new(iroh::EndpointAddr::from(node_id)).to_string();
        let (mut payload, _) =
            mint_in(&dir, &ticket_str, Expiry::Never, false, false, None, &secret).unwrap();
        // Force expiry into the past directly on the payload (bypassing mint's
        // clock) — verify_inbound checks expiry from the *payload*, not the store.
        payload.expires_at = 1;
        let token = payload.encode();

        let err = verify_inbound_in(&dir, &token, node_id, &node_id).unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
    }

    #[test]
    fn verify_inbound_rejects_wrong_node_id() {
        let dir = isolated_dir("verify_wrong_node");
        let secret = SecretKey::generate();
        let node_id = secret.public();
        let ticket_str = EndpointTicket::new(iroh::EndpointAddr::from(node_id)).to_string();
        let (payload, _) = mint_in(&dir, &ticket_str, Expiry::Never, false, false, None, &secret).unwrap();
        let token = payload.encode();

        let other = SecretKey::generate().public();
        assert!(verify_inbound_in(&dir, &token, other, &other).is_err());
    }

    #[test]
    fn verify_inbound_rejects_bad_signature() {
        let dir = isolated_dir("verify_bad_sig");
        let secret = SecretKey::generate();
        let node_id = secret.public();
        let ticket_str = EndpointTicket::new(iroh::EndpointAddr::from(node_id)).to_string();
        let (mut payload, _) =
            mint_in(&dir, &ticket_str, Expiry::Never, true, false, None, &secret).unwrap();
        assert!(payload.is_signed());
        let mut sig = payload.signature.unwrap();
        sig[0] ^= 0xff;
        payload.signature = Some(sig);
        let token = payload.encode();

        assert!(verify_inbound_in(&dir, &token, node_id, &node_id).is_err());
    }

    #[test]
    fn verify_inbound_rejects_consumed_single_use() {
        let dir = isolated_dir("verify_consumed");
        let secret = SecretKey::generate();
        let node_id = secret.public();
        let ticket_str = EndpointTicket::new(iroh::EndpointAddr::from(node_id)).to_string();
        let (payload, record) =
            mint_in(&dir, &ticket_str, Expiry::Never, false, true, None, &secret).unwrap();
        let token = payload.encode();

        // First use succeeds.
        let verified = verify_inbound_in(&dir, &token, node_id, &node_id).expect("first use verifies");
        assert!(verified.single_use);
        mark_consumed_in(&dir, &record.id).unwrap();

        // Second use is rejected.
        let err = verify_inbound_in(&dir, &token, node_id, &node_id).unwrap_err();
        assert!(err.to_string().contains("consumed"), "{err}");
    }
}
