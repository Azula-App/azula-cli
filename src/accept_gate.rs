//! Shared accept-side invite gate for `azula serve`'s ALPN handlers.
//!
//! `mcp.rs`'s `LlmHandler` and `term.rs`'s `TermHandler` have the same
//! connection shape: a loop of independent bi-streams with no existing
//! per-stream handshake, so gating runs once per connection on the first
//! stream only. A known peer (registry endpoint-id match, checked by the caller)
//! skips the gate entirely; a stranger's first stream must open with
//! `Hello.invite`, verified the same way `bridge/device.rs`'s accept path
//! verifies it. See `azula-docs/openspec/specs/invitations/design.md`.
//!
//! `bridge/device.rs`'s own accept path is *not* built on this helper — it
//! also has to resolve a peer display name from the `Hello`, reply with its
//! own `Hello`, and register into a live `DeviceMap`, none of which apply
//! here — but the invite-verification rules are identical.

use std::time::Duration;

use iroh::{EndpointId, PublicKey};
use tokio::io::{AsyncRead, BufReader};
use tracing::{info, warn};

use crate::certs::{DeviceCert, Revocation};
use crate::invite;
use crate::proto::{read_frame, Frame};
use crate::registry::{self, Device};

/// 15 s cap on waiting for a stranger's first frame — long enough for a real
/// dial, short enough that a silent connection doesn't tie up an accept slot.
const STRANGER_HELLO_TIMEOUT: Duration = Duration::from_secs(15);

/// Outcome of gating a stranger's first stream.
pub enum GateOutcome {
    /// Admit the connection. Nothing is ever left over for the caller to
    /// process: only a `Hello` can pass the gate, and the gate consumes it
    /// whole. (`gate_peer`'s `GatePeerOutcome` does carry a `replay` — a
    /// peer known by root match may open with a real frame.)
    Admit,
    Close,
}

/// Require the first frame of a stranger's first stream to be a `Hello`
/// carrying a valid invite (verified against `my_endpoint_id`'s issued-invite
/// store). Registers the device (as `azula pair` would, named `device_name`)
/// and marks single-use invites consumed on success; closes otherwise. There
/// is no escape hatch — a stranger with no invite, or an invite that fails to
/// verify, is dropped. `component` tags log lines (e.g. `"llm"`, `"term"`) so
/// the two callers' logs stay distinguishable.
pub async fn gate_stranger<R>(
    reader: &mut BufReader<R>,
    my_endpoint_id: EndpointId,
    remote: &str,
    device_name: &str,
    component: &str,
) -> GateOutcome
where
    R: AsyncRead + Unpin,
{
    let first = match tokio::time::timeout(STRANGER_HELLO_TIMEOUT, read_frame(reader)).await {
        Ok(result) => result,
        Err(_elapsed) => {
            info!(%remote, component, "stranger's first frame timed out; closing");
            return GateOutcome::Close;
        }
    };

    let invite_token = match &first {
        Ok(Some(Frame::Hello { invite: Some(tok), .. })) => Some(tok.clone()),
        _ => None,
    };

    let verified = match invite_token {
        Some(tok) => match invite::verify_inbound(&tok, my_endpoint_id, &my_endpoint_id) {
            Ok(v) => {
                info!(%remote, component, invite_id = %v.invite_id, "stranger presented a valid invite");
                v
            }
            Err(e) => {
                warn!(%remote, component, error = %e, "invite verification failed; closing");
                return GateOutcome::Close;
            }
        },
        None => {
            warn!(%remote, component, "stranger connected without a valid invite; closing");
            return GateOutcome::Close;
        }
    };

    let device = Device {
        name: device_name.to_string(),
        ticket: remote.to_string(),
        added_at: Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        ),
        invite: None,
    };
    if let Err(e) = registry::add(device, false) {
        warn!(%remote, component, error = %e, "failed to register invite-verified device");
    }
    if verified.single_use {
        if let Err(e) = invite::mark_consumed(&verified.invite_id) {
            warn!(%remote, component, error = %e, "failed to mark invite consumed");
        }
    }

    GateOutcome::Admit
}

// ---------------------------------------------------------------------------
// Cert-aware gate (multi-device-identity): the mailbox's accept path
// ---------------------------------------------------------------------------
//
// `gate_stranger` above is untouched (and stays the gate `term.rs`/`mcp.rs`
// use — those ALPNs have no cert/root concept). `gate_peer` below is an
// additive extension for ALPNs that understand `Hello.cert`, per
// `specs/invitations/spec.md`'s "Hello Carries an Optional Device
// Certificate" and (MODIFIED) "Known Peers Bypass the Invite Gate"
// requirements: a cert that verifies, isn't revoked, and chains to an
// already-known contact root is admitted with no invite required at all;
// anything else (no cert, a cert that fails to decode/verify, one bound to
// the wrong connection, or a revoked device) is treated exactly as if no
// cert had been presented and falls through to the ordinary invite path.

/// Inputs needed to check a presented `Hello.cert` against this device's
/// known contacts and revocations.
pub struct CertGate<'a> {
    /// Root public keys already accepted as contacts.
    pub known_roots: &'a [PublicKey],
    /// Already-verified revocation statements this device holds (same
    /// contract as `certs::DeviceCert::is_revoked_by`: callers must have
    /// verified each one themselves).
    pub revocations: &'a [Revocation],
}

/// Outcome of checking one presented `Hello.cert` (if any) against a
/// [`CertGate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertCheck {
    /// The cert verifies, binds to this connection, isn't revoked, and its
    /// root is already a known contact — known by root match, no invite
    /// needed (spec: "A contact's new device is known by root").
    KnownByRoot { root_pk: PublicKey },
    /// The cert verifies, binds to this connection, and isn't revoked, but
    /// its root is not (yet) a known contact — falls through to the
    /// ordinary invite path; if that admits the connection, its root should
    /// be recorded as a new contact (spec: "Accepting a certified stranger
    /// pins the root").
    CertifiedStranger { root_pk: PublicKey },
    /// No cert was presented, it failed to decode/verify, didn't bind to
    /// this connection (transport endpoint id != the cert's device key), or its
    /// device key has been revoked — every one of these is treated exactly
    /// as if the field were absent (spec: "a certificate that fails
    /// verification SHALL be treated exactly as if the field were absent");
    /// a revoked device is folded in here rather than given a distinct
    /// outcome because the observable behavior the spec asks for is
    /// identical either way — "SHALL NOT be treated as known and SHALL fall
    /// through to the stranger path".
    Absent,
}

/// Check a presented `Hello.cert` (`"azd…"`, or `None`) against `gate`, for
/// a connection whose transport peer id is `connection_endpoint_id`.
pub fn check_cert(cert: Option<&str>, connection_endpoint_id: EndpointId, gate: &CertGate<'_>) -> CertCheck {
    let Some(cert_str) = cert else { return CertCheck::Absent };
    let Ok(cert) = DeviceCert::decode(cert_str) else { return CertCheck::Absent };
    if cert.verify().is_err() {
        return CertCheck::Absent;
    }
    if !cert.binds_to_connection(connection_endpoint_id) {
        return CertCheck::Absent;
    }
    if cert.is_revoked_by(gate.revocations) {
        return CertCheck::Absent;
    }
    if gate.known_roots.contains(&cert.root_pk) {
        CertCheck::KnownByRoot { root_pk: cert.root_pk }
    } else {
        CertCheck::CertifiedStranger { root_pk: cert.root_pk }
    }
}

/// Outcome of gating a peer's first stream through the cert-aware path.
pub enum GatePeerOutcome {
    /// Admit the connection. `replay` is a frame already consumed off the
    /// stream that the caller must still process (mirrors
    /// [`GateOutcome::Admit`]). `root_pk` is set whenever this connection is
    /// now associated with a certified root — whether it was already known,
    /// or a certified stranger the invite path just admitted, whose root the
    /// caller should now record as a contact.
    Admit { replay: Option<Box<Frame>>, root_pk: Option<PublicKey> },
    Close,
}

/// Gate a peer's first stream for an ALPN that understands `Hello.cert`
/// (the mailbox's chat ALPN). A cert that verifies, binds to this
/// connection, isn't revoked, and chains to an already-known contact root is
/// admitted immediately — no invite required. Otherwise (no cert, an
/// invalid one, one bound to the wrong connection, a revoked one, or a valid
/// but not-yet-known root) this falls through to exactly the same
/// invite-verification rules [`gate_stranger`] uses.
#[allow(clippy::too_many_arguments)]
pub async fn gate_peer<R>(
    reader: &mut BufReader<R>,
    my_endpoint_id: EndpointId,
    remote_endpoint_id: EndpointId,
    remote: &str,
    device_name: &str,
    component: &str,
    cert_gate: &CertGate<'_>,
) -> GatePeerOutcome
where
    R: AsyncRead + Unpin,
{
    let first = match tokio::time::timeout(STRANGER_HELLO_TIMEOUT, read_frame(reader)).await {
        Ok(result) => result,
        Err(_elapsed) => {
            info!(%remote, component, "peer's first frame timed out; closing");
            return GatePeerOutcome::Close;
        }
    };

    let (cert_field, invite_field) = match &first {
        Ok(Some(Frame::Hello { cert, invite, .. })) => (cert.clone(), invite.clone()),
        _ => (None, None),
    };

    let cert_check = check_cert(cert_field.as_deref(), remote_endpoint_id, cert_gate);
    if let CertCheck::KnownByRoot { root_pk } = cert_check {
        info!(%remote, component, %root_pk, "peer known by certified root match; admitting without an invite");
        return GatePeerOutcome::Admit { replay: replay_of(first), root_pk: Some(root_pk) };
    }

    let verified = match invite_field {
        Some(tok) => match invite::verify_inbound(&tok, my_endpoint_id, &my_endpoint_id) {
            Ok(v) => {
                info!(%remote, component, invite_id = %v.invite_id, "peer presented a valid invite");
                v
            }
            Err(e) => {
                warn!(%remote, component, error = %e, "invite verification failed; closing");
                return GatePeerOutcome::Close;
            }
        },
        None => {
            warn!(%remote, component, "peer connected without a valid invite; closing");
            return GatePeerOutcome::Close;
        }
    };

    let device = Device {
        name: device_name.to_string(),
        ticket: remote.to_string(),
        added_at: Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        ),
        invite: None,
    };
    if let Err(e) = registry::add(device, false) {
        warn!(%remote, component, error = %e, "failed to register invite-verified peer");
    }
    if verified.single_use {
        if let Err(e) = invite::mark_consumed(&verified.invite_id) {
            warn!(%remote, component, error = %e, "failed to mark invite consumed");
        }
    }

    let root_pk = match cert_check {
        CertCheck::CertifiedStranger { root_pk } => Some(root_pk),
        _ => None,
    };
    GatePeerOutcome::Admit { replay: replay_of(first), root_pk }
}

/// Shared by [`gate_peer`]: a non-`Hello` first frame must be replayed into
/// the session so it isn't lost; a `Hello` is fully consumed by the gate.
fn replay_of(first: anyhow::Result<Option<Frame>>) -> Option<Box<Frame>> {
    match first {
        Ok(Some(Frame::Hello { .. })) => None,
        Ok(Some(other)) => Some(Box::new(other)),
        Ok(None) | Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::write_frame;

    // The reject-path tests below never reach the issued-invite store: an
    // unparseable token fails in `InvitePayload::decode` before any store
    // lookup, and "no invite at all" never calls `verify_inbound` in the
    // first place — so they need no `AZULA_INVITES_DIR`/`AZULA_REGISTRY_DIR`
    // isolation and can safely run concurrently with the rest of the suite.

    #[tokio::test]
    async fn invalid_invite_token_closes() {
        let endpoint_id = iroh::SecretKey::generate().public();
        let (mut writer, reader) = tokio::io::duplex(4096);
        let mut buf_reader = BufReader::new(reader);
        write_frame(
            &mut writer,
            &Frame::Hello { name: "peer".into(), invite: Some("azi-not-a-real-token".into()), cert: None },
        )
        .await
        .unwrap();

        let outcome = gate_stranger(&mut buf_reader, endpoint_id, "remote-invalid", "peer-device", "test").await;
        assert!(matches!(outcome, GateOutcome::Close));
    }

    #[tokio::test]
    async fn no_invite_closes() {
        let endpoint_id = iroh::SecretKey::generate().public();
        let (mut writer, reader) = tokio::io::duplex(4096);
        let mut buf_reader = BufReader::new(reader);
        // A legacy client that never sends Hello at all — its first real
        // frame arrives directly.
        write_frame(&mut writer, &Frame::Chat { text: "hi".into(), id: None }).await.unwrap();

        let outcome = gate_stranger(&mut buf_reader, endpoint_id, "remote-none", "peer-device", "test").await;
        assert!(matches!(outcome, GateOutcome::Close));
    }

    #[tokio::test]
    async fn clean_eof_closes() {
        let endpoint_id = iroh::SecretKey::generate().public();
        let (writer, reader) = tokio::io::duplex(4096);
        drop(writer); // immediate EOF, no first frame at all
        let mut buf_reader = BufReader::new(reader);

        let outcome = gate_stranger(&mut buf_reader, endpoint_id, "remote-eof", "peer-device", "test").await;
        assert!(matches!(outcome, GateOutcome::Close));
    }

    /// The one test that exercises the full success path (valid invite ->
    /// admit, no replay). Touches the real issued-invite store, isolated via
    /// an env var override — same convention
    /// `bridge::tests::start_pairing_mints_invite_unless_legacy_ticket` uses,
    /// and both hold `ENV_TEST_LOCK` so they can't race each other.
    ///
    /// Deliberately does *not* assert the registry side effect
    /// (`registry::find_by_endpoint_id` after this returns): `registry.rs`'s
    /// `cfg(test)` fallback dir is a single path shared by every registry
    /// test in the crate that doesn't set `AZULA_REGISTRY_DIR` itself, so
    /// asserting against it here would race with unrelated tests running in
    /// parallel. The `GateOutcome` returned by `gate_stranger` doesn't depend
    /// on the registry write succeeding (its error is only logged), so this
    /// still fully exercises the verification path under test; the
    /// registration side effect is covered by the real two-process E2E run
    /// (see the invitations E2E report) and by `bridge/tests.rs`'s
    /// `match_known_device_by_endpoint_id`/`reconnect_by_endpoint_id_flushes_mailbox`.
    #[tokio::test]
    async fn valid_invite_admits_with_no_replay() {
        // Holds ENV_TEST_LOCK for the whole body — see its doc comment.
        let _guard = registry::ENV_TEST_LOCK.lock().await;

        let base = std::env::temp_dir()
            .join(format!("azula-accept-gate-test-{}", std::process::id()))
            .join("valid_invite");
        let _ = std::fs::remove_dir_all(&base);
        std::env::set_var("AZULA_INVITES_DIR", base.join("invites"));

        let secret = iroh::SecretKey::generate();
        let endpoint_id = secret.public();
        let ticket_str = iroh_tickets::endpoint::EndpointTicket::new(iroh::EndpointAddr::from(endpoint_id)).to_string();
        let (payload, _) =
            invite::mint(&ticket_str, invite::Expiry::Never, false, false, None, &secret).unwrap();
        let token = payload.encode();

        let (mut writer, reader) = tokio::io::duplex(4096);
        let mut buf_reader = BufReader::new(reader);
        write_frame(&mut writer, &Frame::Hello { name: "peer".into(), invite: Some(token), cert: None }).await.unwrap();

        let outcome = gate_stranger(&mut buf_reader, endpoint_id, "remote-valid", "peer-device", "test").await;
        assert!(matches!(outcome, GateOutcome::Admit));

        std::env::remove_var("AZULA_INVITES_DIR");
    }

    // --- check_cert / gate_peer (task 8.2: cert-aware accept-gate parity) --

    fn seed(start: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = start.wrapping_add(i as u8);
        }
        s
    }

    fn cert_gate_root_secret() -> iroh::SecretKey {
        iroh::SecretKey::from_bytes(&seed(0x00))
    }
    fn cert_gate_device_secret() -> iroh::SecretKey {
        iroh::SecretKey::from_bytes(&seed(0x20))
    }

    fn make_cert(root: &iroh::SecretKey, device: &iroh::SecretKey) -> DeviceCert {
        let mut cert = DeviceCert {
            version: 1,
            flags: 0,
            root_pk: root.public(),
            device_pk: device.public(),
            issued_at: 1_767_225_600,
            expires_at: 0,
            name: "peer".to_string(),
            signature: [0u8; 64],
        };
        cert.sign(root);
        cert
    }

    #[test]
    fn check_cert_admits_a_known_root() {
        let root = cert_gate_root_secret();
        let device = cert_gate_device_secret();
        let cert = make_cert(&root, &device);
        let known_roots = [root.public()];
        let gate = CertGate { known_roots: &known_roots, revocations: &[] };

        let outcome = check_cert(Some(&cert.encode()), device.public(), &gate);
        assert_eq!(outcome, CertCheck::KnownByRoot { root_pk: root.public() });
    }

    #[test]
    fn check_cert_reports_certified_stranger_when_root_not_yet_known() {
        let root = cert_gate_root_secret();
        let device = cert_gate_device_secret();
        let cert = make_cert(&root, &device);
        let gate = CertGate { known_roots: &[], revocations: &[] };

        let outcome = check_cert(Some(&cert.encode()), device.public(), &gate);
        assert_eq!(outcome, CertCheck::CertifiedStranger { root_pk: root.public() });
    }

    #[test]
    fn check_cert_treats_a_revoked_device_as_absent_even_for_a_known_root() {
        let root = cert_gate_root_secret();
        let device = cert_gate_device_secret();
        let cert = make_cert(&root, &device);
        let mut revocation = Revocation {
            version: 1,
            root_pk: root.public(),
            device_pk: device.public(),
            revoked_at: 1_767_225_600,
            signature: [0u8; 64],
        };
        revocation.sign(&root);
        let known_roots = [root.public()];
        let revocations = [revocation];
        let gate = CertGate { known_roots: &known_roots, revocations: &revocations };

        let outcome = check_cert(Some(&cert.encode()), device.public(), &gate);
        assert_eq!(outcome, CertCheck::Absent);
    }

    #[test]
    fn check_cert_treats_a_bad_signature_as_absent() {
        let root = cert_gate_root_secret();
        let device = cert_gate_device_secret();
        let mut cert = make_cert(&root, &device);
        cert.signature[0] ^= 0xff;
        let known_roots = [root.public()];
        let gate = CertGate { known_roots: &known_roots, revocations: &[] };

        let outcome = check_cert(Some(&cert.encode()), device.public(), &gate);
        assert_eq!(outcome, CertCheck::Absent);
    }

    #[test]
    fn check_cert_treats_a_wrong_connection_binding_as_absent() {
        let root = cert_gate_root_secret();
        let device = cert_gate_device_secret();
        let cert = make_cert(&root, &device);
        let known_roots = [root.public()];
        let gate = CertGate { known_roots: &known_roots, revocations: &[] };

        // The presented cert's device_pk doesn't match this connection's
        // transport endpoint id.
        let someone_else = iroh::SecretKey::from_bytes(&seed(0x40)).public();
        let outcome = check_cert(Some(&cert.encode()), someone_else, &gate);
        assert_eq!(outcome, CertCheck::Absent);
    }

    #[test]
    fn check_cert_treats_absent_field_as_absent() {
        let gate = CertGate { known_roots: &[], revocations: &[] };
        let outcome = check_cert(None, cert_gate_device_secret().public(), &gate);
        assert_eq!(outcome, CertCheck::Absent);
    }

    #[tokio::test]
    async fn gate_peer_admits_a_known_cert_root_with_no_invite_needed() {
        let root = cert_gate_root_secret();
        let device = cert_gate_device_secret();
        let cert = make_cert(&root, &device);
        let my_endpoint_id = iroh::SecretKey::generate().public();
        let known_roots = [root.public()];
        let gate = CertGate { known_roots: &known_roots, revocations: &[] };

        let (mut writer, reader) = tokio::io::duplex(4096);
        let mut buf_reader = BufReader::new(reader);
        write_frame(
            &mut writer,
            &Frame::Hello { name: "peer".into(), invite: None, cert: Some(cert.encode()) },
        )
        .await
        .unwrap();

        // No invite at all -- only the root match can admit this connection.
        let outcome = gate_peer(
            &mut buf_reader,
            my_endpoint_id,
            device.public(),
            "remote-known-root",
            "peer-device",
            "test",
            &gate,
        )
        .await;
        match outcome {
            GatePeerOutcome::Admit { replay: None, root_pk: Some(r) } => assert_eq!(r, root.public()),
            _ => panic!("expected Admit{{root_pk: Some}}"),
        }
    }

    #[tokio::test]
    async fn gate_peer_falls_through_to_stranger_path_for_a_revoked_device_and_closes_without_invite() {
        let root = cert_gate_root_secret();
        let device = cert_gate_device_secret();
        let cert = make_cert(&root, &device);
        let mut revocation = Revocation {
            version: 1,
            root_pk: root.public(),
            device_pk: device.public(),
            revoked_at: 1_767_225_600,
            signature: [0u8; 64],
        };
        revocation.sign(&root);
        let my_endpoint_id = iroh::SecretKey::generate().public();
        let known_roots = [root.public()];
        let revocations = [revocation];
        let gate = CertGate { known_roots: &known_roots, revocations: &revocations };

        let (mut writer, reader) = tokio::io::duplex(4096);
        let mut buf_reader = BufReader::new(reader);
        write_frame(
            &mut writer,
            &Frame::Hello { name: "peer".into(), invite: None, cert: Some(cert.encode()) },
        )
        .await
        .unwrap();

        // Revoked -> not treated as known -> falls to the stranger path;
        // no invite -> closed. This is the spec's "Revoked device does not
        // ride the root match" scenario.
        let outcome = gate_peer(
            &mut buf_reader,
            my_endpoint_id,
            device.public(),
            "remote-revoked",
            "peer-device",
            "test",
            &gate,
        )
        .await;
        assert!(matches!(outcome, GatePeerOutcome::Close));
    }

    #[tokio::test]
    async fn gate_peer_never_trusts_an_invalid_cert_but_still_admits_via_a_valid_invite() {
        // Holds ENV_TEST_LOCK for the whole body — touches the real
        // issued-invite store, same convention as `valid_invite_admits_with_no_replay`.
        let _guard = registry::ENV_TEST_LOCK.lock().await;
        let base = std::env::temp_dir()
            .join(format!("azula-accept-gate-test-{}", std::process::id()))
            .join("gate_peer_invalid_cert");
        let _ = std::fs::remove_dir_all(&base);
        std::env::set_var("AZULA_INVITES_DIR", base.join("invites"));

        let root = cert_gate_root_secret();
        let device = cert_gate_device_secret();
        let mut cert = make_cert(&root, &device);
        cert.signature[0] ^= 0xff; // invalid signature
        let known_roots = [root.public()]; // even though the root would be known...
        let gate = CertGate { known_roots: &known_roots, revocations: &[] };

        let my_secret = iroh::SecretKey::generate();
        let my_endpoint_id = my_secret.public();
        let ticket_str = iroh_tickets::endpoint::EndpointTicket::new(iroh::EndpointAddr::from(my_endpoint_id)).to_string();
        let (payload, _) =
            invite::mint(&ticket_str, invite::Expiry::Never, false, false, None, &my_secret).unwrap();
        let token = payload.encode();

        let (mut writer, reader) = tokio::io::duplex(4096);
        let mut buf_reader = BufReader::new(reader);
        write_frame(
            &mut writer,
            &Frame::Hello { name: "peer".into(), invite: Some(token), cert: Some(cert.encode()) },
        )
        .await
        .unwrap();

        let outcome = gate_peer(
            &mut buf_reader,
            my_endpoint_id,
            device.public(),
            "remote-invalid-cert",
            "peer-device",
            "test",
            &gate,
        )
        .await;
        // Admitted via the invite, NOT via the (invalid) cert -- so no root
        // is reported.
        match outcome {
            GatePeerOutcome::Admit { replay: None, root_pk: None } => {}
            _ => panic!("expected Admit{{root_pk: None}} (admitted by invite, not by the untrusted cert)"),
        }

        std::env::remove_var("AZULA_INVITES_DIR");
    }

    #[tokio::test]
    async fn gate_peer_admits_a_certified_stranger_via_invite_and_reports_its_root() {
        let _guard = registry::ENV_TEST_LOCK.lock().await;
        let base = std::env::temp_dir()
            .join(format!("azula-accept-gate-test-{}", std::process::id()))
            .join("gate_peer_certified_stranger");
        let _ = std::fs::remove_dir_all(&base);
        std::env::set_var("AZULA_INVITES_DIR", base.join("invites"));

        let root = cert_gate_root_secret();
        let device = cert_gate_device_secret();
        let cert = make_cert(&root, &device);
        let gate = CertGate { known_roots: &[], revocations: &[] }; // root not yet known

        let my_secret = iroh::SecretKey::generate();
        let my_endpoint_id = my_secret.public();
        let ticket_str = iroh_tickets::endpoint::EndpointTicket::new(iroh::EndpointAddr::from(my_endpoint_id)).to_string();
        let (payload, _) =
            invite::mint(&ticket_str, invite::Expiry::Never, false, false, None, &my_secret).unwrap();
        let token = payload.encode();

        let (mut writer, reader) = tokio::io::duplex(4096);
        let mut buf_reader = BufReader::new(reader);
        write_frame(
            &mut writer,
            &Frame::Hello { name: "peer".into(), invite: Some(token), cert: Some(cert.encode()) },
        )
        .await
        .unwrap();

        let outcome = gate_peer(
            &mut buf_reader,
            my_endpoint_id,
            device.public(),
            "remote-certified-stranger",
            "peer-device",
            "test",
            &gate,
        )
        .await;
        match outcome {
            GatePeerOutcome::Admit { replay: None, root_pk: Some(r) } => assert_eq!(r, root.public()),
            _ => panic!("expected Admit{{root_pk: Some}} (a certified stranger admitted by invite pins its root)"),
        }

        std::env::remove_var("AZULA_INVITES_DIR");
    }
}
