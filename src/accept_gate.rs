//! Shared accept-side invite gate for `azula serve`'s ALPN handlers.
//!
//! `mcp.rs`'s `LlmHandler` and `term.rs`'s `TermHandler` have the same
//! connection shape: a loop of independent bi-streams with no existing
//! per-stream handshake, so gating runs once per connection on the first
//! stream only. A known peer (registry node-id match, checked by the caller)
//! skips the gate entirely; a stranger's first stream must open with
//! `Hello.invite`, verified the same way `bridge/device.rs`'s accept path
//! verifies it. See `azula-docs/openspec/specs/invitations/design.md`.
//!
//! `bridge/device.rs`'s own accept path is *not* built on this helper — it
//! also has to resolve a peer display name from the `Hello`, reply with its
//! own `Hello`, and register into a live `DeviceMap`, none of which apply
//! here — but the invite-verification rules are identical.

use std::time::Duration;

use iroh::EndpointId;
use tokio::io::{AsyncRead, BufReader};
use tracing::{info, warn};

use crate::invite;
use crate::proto::{read_frame, Frame};
use crate::registry::{self, Device};

/// 15 s cap on waiting for a stranger's first frame — long enough for a real
/// dial, short enough that a silent connection doesn't tie up an accept slot.
const STRANGER_HELLO_TIMEOUT: Duration = Duration::from_secs(15);

/// Outcome of gating a stranger's first stream.
pub enum GateOutcome {
    /// Admit the connection; `replay` is a frame already consumed off the
    /// stream while gating that the caller must still process (e.g. a
    /// legacy client's first real frame sent with no preceding `Hello`).
    Admit { replay: Option<Box<Frame>> },
    Close,
}

/// Require the first frame of a stranger's first stream to be a `Hello`
/// carrying a valid invite (verified against `my_node_id`'s issued-invite
/// store). Registers the device (as `azula pair` would, named `device_name`)
/// and marks single-use invites consumed on success. Falls back to admitting
/// unverified when `allow_legacy` is set (transition escape hatch);
/// otherwise closes. `component` tags log lines (e.g. `"llm"`, `"term"`) so
/// the two callers' logs stay distinguishable.
pub async fn gate_stranger<R>(
    reader: &mut BufReader<R>,
    my_node_id: EndpointId,
    allow_legacy: bool,
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
        Some(tok) => match invite::verify_inbound(&tok, my_node_id, &my_node_id) {
            Ok(v) => {
                info!(%remote, component, invite_id = %v.invite_id, "stranger presented a valid invite");
                Some(v)
            }
            Err(e) if allow_legacy => {
                warn!(%remote, component, error = %e, "invite verification failed; admitting as unverified (--allow-legacy)");
                None
            }
            Err(e) => {
                warn!(%remote, component, error = %e, "invite verification failed; closing (pass --allow-legacy to admit anyway)");
                return GateOutcome::Close;
            }
        },
        None if allow_legacy => {
            info!(%remote, component, "stranger connected without an invite; admitting as unverified (--allow-legacy)");
            None
        }
        None => {
            warn!(%remote, component, "stranger connected without a valid invite; closing (pass --allow-legacy to admit anyway)");
            return GateOutcome::Close;
        }
    };

    if let Some(v) = verified {
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
        if v.single_use {
            if let Err(e) = invite::mark_consumed(&v.invite_id) {
                warn!(%remote, component, error = %e, "failed to mark invite consumed");
            }
        }
    }

    // A non-Hello first frame (legacy client that sends its real first frame
    // immediately) must be replayed into the session so it isn't lost; a
    // Hello frame is fully consumed by the gate and has nothing to replay.
    let replay = match first {
        Ok(Some(Frame::Hello { .. })) => None,
        Ok(Some(other)) => Some(Box::new(other)),
        Ok(None) | Err(_) => None,
    };
    GateOutcome::Admit { replay }
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
    async fn invalid_invite_token_closes_when_strict() {
        let node_id = iroh::SecretKey::generate().public();
        let (mut writer, reader) = tokio::io::duplex(4096);
        let mut buf_reader = BufReader::new(reader);
        write_frame(&mut writer, &Frame::Hello { name: "peer".into(), invite: Some("azi-not-a-real-token".into()) })
            .await
            .unwrap();

        let outcome = gate_stranger(&mut buf_reader, node_id, false, "remote-invalid", "peer-device", "test").await;
        assert!(matches!(outcome, GateOutcome::Close));
    }

    #[tokio::test]
    async fn invalid_invite_token_admits_unverified_when_legacy_allowed() {
        let node_id = iroh::SecretKey::generate().public();
        let (mut writer, reader) = tokio::io::duplex(4096);
        let mut buf_reader = BufReader::new(reader);
        write_frame(&mut writer, &Frame::Hello { name: "peer".into(), invite: Some("azi-not-a-real-token".into()) })
            .await
            .unwrap();

        let outcome = gate_stranger(&mut buf_reader, node_id, true, "remote-invalid-legacy", "peer-device", "test").await;
        assert!(matches!(outcome, GateOutcome::Admit { replay: None }));
    }

    #[tokio::test]
    async fn no_invite_closes_when_strict() {
        let node_id = iroh::SecretKey::generate().public();
        let (mut writer, reader) = tokio::io::duplex(4096);
        let mut buf_reader = BufReader::new(reader);
        // A legacy client that never sends Hello at all — its first real
        // frame arrives directly.
        write_frame(&mut writer, &Frame::Chat { text: "hi".into() }).await.unwrap();

        let outcome = gate_stranger(&mut buf_reader, node_id, false, "remote-none", "peer-device", "test").await;
        assert!(matches!(outcome, GateOutcome::Close));
    }

    #[tokio::test]
    async fn no_invite_admits_unverified_and_replays_the_frame_when_legacy_allowed() {
        let node_id = iroh::SecretKey::generate().public();
        let (mut writer, reader) = tokio::io::duplex(4096);
        let mut buf_reader = BufReader::new(reader);
        write_frame(&mut writer, &Frame::Chat { text: "hi".into() }).await.unwrap();

        let outcome = gate_stranger(&mut buf_reader, node_id, true, "remote-none-legacy", "peer-device", "test").await;
        match outcome {
            GateOutcome::Admit { replay } => {
                assert!(
                    matches!(replay.as_deref(), Some(Frame::Chat { text }) if text == "hi"),
                    "the stranger's first real frame must be replayed, not dropped"
                );
            }
            GateOutcome::Close => panic!("expected the connection to be admitted"),
        }
    }

    #[tokio::test]
    async fn clean_eof_closes_when_strict() {
        let node_id = iroh::SecretKey::generate().public();
        let (writer, reader) = tokio::io::duplex(4096);
        drop(writer); // immediate EOF, no first frame at all
        let mut buf_reader = BufReader::new(reader);

        let outcome = gate_stranger(&mut buf_reader, node_id, false, "remote-eof", "peer-device", "test").await;
        assert!(matches!(outcome, GateOutcome::Close));
    }

    /// The one test that exercises the full success path (valid invite ->
    /// admit, no replay). Touches the real issued-invite store, isolated via
    /// an env var override — same convention
    /// `bridge::tests::start_pairing_mints_invite_unless_legacy_ticket` uses,
    /// and both hold `ENV_TEST_LOCK` so they can't race each other.
    ///
    /// Deliberately does *not* assert the registry side effect
    /// (`registry::find_by_node_id` after this returns): `registry.rs`'s
    /// `cfg(test)` fallback dir is a single path shared by every registry
    /// test in the crate that doesn't set `AZULA_REGISTRY_DIR` itself, so
    /// asserting against it here would race with unrelated tests running in
    /// parallel. The `GateOutcome` returned by `gate_stranger` doesn't depend
    /// on the registry write succeeding (its error is only logged), so this
    /// still fully exercises the verification path under test; the
    /// registration side effect is covered by the real two-process E2E run
    /// (see the invitations E2E report) and by `bridge/tests.rs`'s
    /// `match_known_device_by_node_id`/`reconnect_by_node_id_flushes_mailbox`.
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
        let node_id = secret.public();
        let ticket_str = iroh_tickets::endpoint::EndpointTicket::new(iroh::EndpointAddr::from(node_id)).to_string();
        let (payload, _) =
            invite::mint(&ticket_str, invite::Expiry::Never, false, false, None, &secret).unwrap();
        let token = payload.encode();

        let (mut writer, reader) = tokio::io::duplex(4096);
        let mut buf_reader = BufReader::new(reader);
        write_frame(&mut writer, &Frame::Hello { name: "peer".into(), invite: Some(token) }).await.unwrap();

        let outcome = gate_stranger(&mut buf_reader, node_id, false, "remote-valid", "peer-device", "test").await;
        assert!(matches!(outcome, GateOutcome::Admit { replay: None }));

        std::env::remove_var("AZULA_INVITES_DIR");
    }
}
