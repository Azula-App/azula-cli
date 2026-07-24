//! Ticket / URL parsing for `azula pair` and `--device`.
//!
//! [`parse_ticket`] accepts four **legacy** forms (kept forever for outbound
//! dialing per the invitations transition policy):
//!   - `https://azula.app/s/<token>`
//!   - `https://azula.app/connect/<token>`
//!   - `azula://connect?code=<token>`
//!   - a bare token (anything else)
//!
//! [`parse`] additionally recognizes the **invite** forms
//! (`https://azula.app/i/<payload>`, `azula://i?c=<payload>`, a bare
//! `azi…` payload) and tags the result so callers can tell an invite from a
//! raw ticket — see `azula-docs/openspec/specs/invitations/design.md`.
//!
//! In all cases the token/payload is returned with no query-string, fragment,
//! or trailing slash. No network access is performed; nothing is validated
//! beyond stripping the URL wrapper (invite payload validity is `invite::decode`'s job).

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::PublicKey;
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tokio::sync::{oneshot, Mutex as AsyncMutex};

use crate::proto::{read_frame, write_frame, Frame, IdentityBundle};

/// ALPN identifier for the QR-link device-enrollment protocol: a new device
/// dials this after a root-holding device scans its `azl…` payload, and the
/// two exchange `Frame::LinkHello` / `Frame::LinkGrant` / `Frame::LinkReject`
/// (see `proto.rs` and
/// `azula-docs/openspec/changes/multi-device-identity/specs/device-linking/spec.md`).
///
/// The azula CLI only ever plays the *new device* role (`azula link`) — it
/// holds no root secret and never grants links to others (`CLI Device
/// Enrollment`). [`run_new_device_session`]/[`LinkHandler`] implement that
/// side; [`RootlessLinkHandler`] is what an already-linked CLI device (e.g.
/// `azula mailbox`) answers with if something dials its link ALPN anyway —
/// it always declines, since only a root-holding device can ever grant one.
pub const LINK_ALPN: &[u8] = b"azula/link/0";

// ---------------------------------------------------------------------------
// New-device session (task 6.4)
// ---------------------------------------------------------------------------

/// Outcome of one completed `azula/link/0` session, from the *new device*'s
/// side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkOutcome {
    /// The root-holding device confirmed and granted a certificate plus an
    /// identity bundle.
    Granted { cert: String, bundle: IdentityBundle },
    /// The root-holding device declined (or the attempt otherwise failed on
    /// its side) — no certificate exists; callers MUST persist nothing.
    Rejected { reason: String },
}

/// Run the new-device side of one `azula/link/0` session over any
/// `AsyncRead`/`AsyncWrite` pair — an in-memory duplex in this module's
/// tests, a real iroh bi-stream via [`LinkHandler`]: send `LinkHello`
/// (presenting our freshly generated `device_pk`, requested `name`, and
/// requested `roles` bitfield — see `certs::FLAG_MAILBOX`/`FLAG_BOT`), then
/// wait for the root-holding device's `LinkGrant`/`LinkReject`. Per the
/// spec, the verification words are derived and displayed by the caller
/// (from the two device public keys) before this function is even called —
/// this function only carries the frame exchange.
pub async fn run_new_device_session<R, W>(
    reader: R,
    mut writer: W,
    device_pk: PublicKey,
    name: &str,
    roles: u8,
) -> Result<LinkOutcome>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    write_frame(
        &mut writer,
        &Frame::LinkHello { device_pk: device_pk.to_string(), name: name.to_string(), roles },
    )
    .await?;

    let mut reader = BufReader::new(reader);
    match read_frame(&mut reader).await? {
        Some(Frame::LinkGrant { cert, bundle }) => Ok(LinkOutcome::Granted { cert, bundle }),
        Some(Frame::LinkReject { reason }) => Ok(LinkOutcome::Rejected { reason }),
        Some(other) => bail!("link: expected LinkGrant or LinkReject after LinkHello, got {other:?}"),
        None => bail!("link: connection closed before granting or rejecting"),
    }
}

// ---------------------------------------------------------------------------
// iroh wiring — thin: all protocol logic lives in `run_new_device_session`.
// ---------------------------------------------------------------------------

/// One-shot accept-side handler for `azula link`: on the first inbound
/// `azula/link/0` connection, prints the four verification words (per the
/// spec, "before any grant is possible") as soon as the transport peer id is
/// known — which is exactly when a `Connection` is first available, so this
/// is the only place that can do it — then runs [`run_new_device_session`]
/// and reports the result exactly once on the channel handed to
/// [`Self::new`]. A second connection while a result is already in flight
/// (or delivered) is accepted and immediately dropped with nothing sent —
/// `azula link` only ever completes one linking attempt per invocation.
#[derive(Clone)]
pub struct LinkHandler {
    device_pk: PublicKey,
    name: String,
    roles: u8,
    result_tx: Arc<AsyncMutex<Option<oneshot::Sender<LinkOutcome>>>>,
}

impl LinkHandler {
    pub fn new(device_pk: PublicKey, name: String, roles: u8, result_tx: oneshot::Sender<LinkOutcome>) -> Self {
        Self { device_pk, name, roles, result_tx: Arc::new(AsyncMutex::new(Some(result_tx))) }
    }
}

impl std::fmt::Debug for LinkHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkHandler")
            .field("device_pk", &self.device_pk)
            .field("name", &self.name)
            .field("roles", &self.roles)
            .finish()
    }
}

impl ProtocolHandler for LinkHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let mut slot = self.result_tx.lock().await;
        let Some(tx) = slot.take() else {
            // A result was already delivered (or is in flight) for this
            // one-shot session; nothing more to do with a second dial.
            return Ok(());
        };
        drop(slot);

        let remote_id = connection.remote_id();
        let words = crate::certs::verification_words(&self.device_pk, &remote_id);
        println!();
        println!("  Verification words: {}", words.join(" "));
        println!("  Confirm these match the words shown on the other device before it grants.");
        println!();

        let (send, recv) = connection.accept_bi().await.map_err(|e| AcceptError::from_boxed(e.into()))?;
        let outcome = run_new_device_session(recv, send, self.device_pk, &self.name, self.roles)
            .await
            .map_err(|e| AcceptError::from_boxed(e.into()))?;
        let _ = tx.send(outcome);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Rootless side (task 8.1): what an already-linked device answers with
// ---------------------------------------------------------------------------

/// Run the rootless side of one `azula/link/0` session: best-effort read
/// whatever the dialer sends (bounded by a short timeout so a silent dialer
/// can't hang the connection), then always reply `LinkReject` — this device
/// holds no root secret and can never grant a link (`QR-linked device cannot
/// enroll others`).
pub async fn run_rootless_session<R, W>(reader: R, mut writer: W) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(reader);
    let _ = tokio::time::timeout(Duration::from_secs(5), read_frame(&mut reader)).await;
    write_frame(
        &mut writer,
        &Frame::LinkReject {
            reason: "this device holds no root secret and cannot enroll other devices".to_string(),
        },
    )
    .await
}

/// Accept-side handler for [`LINK_ALPN`] on a device that holds no root
/// secret (any azula-cli device once linked, e.g. `azula mailbox`). See
/// [`run_rootless_session`].
#[derive(Clone, Debug, Default)]
pub struct RootlessLinkHandler;

impl ProtocolHandler for RootlessLinkHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let (send, recv) = connection.accept_bi().await.map_err(|e| AcceptError::from_boxed(e.into()))?;
        run_rootless_session(recv, send).await.map_err(|e| AcceptError::from_boxed(e.into()))
    }
}

/// A parsed link/token, tagged by which family it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    /// An encoded invite payload (an `"azi…"` string), from any invite link form.
    Invite(String),
    /// A raw ticket / legacy connect token.
    Ticket(String),
}

/// Parse any supported link or bare token and classify it as an invite or a
/// raw ticket. Tries the invite forms first
/// (`https://azula.app/i/<payload>`, `azula://i?c=<payload>`, bare `azi…`),
/// then falls back to [`parse_ticket`]'s four legacy ticket forms.
pub fn parse(input: &str) -> Option<Parsed> {
    let s = input.trim();
    if s.is_empty() {
        return None;
    }

    // --- azula://i?c=<payload> ---
    if let Some(rest) = s.strip_prefix("azula://i") {
        let query = rest.trim_start_matches('?');
        for part in query.split('&') {
            if let Some(v) = part.strip_prefix("c=") {
                let token = strip_fragment(v).trim_end_matches('/');
                if !token.is_empty() {
                    return Some(Parsed::Invite(token.to_string()));
                }
            }
        }
        return None;
    }

    // --- https://azula.app/i/<payload> ---
    if let Some(rest) = s.strip_prefix("https://azula.app/i/") {
        let token = strip_query_and_fragment(rest).trim_end_matches('/');
        return if token.is_empty() { None } else { Some(Parsed::Invite(token.to_string())) };
    }

    // --- bare azi… payload (checked before the legacy bare-token fallback so
    // an invite pasted without a URL wrapper is still classified correctly) ---
    if s.starts_with("azi") && !s.contains("://") && !s.contains('/') {
        let token = strip_query_and_fragment(s);
        if !token.is_empty() {
            return Some(Parsed::Invite(token.to_string()));
        }
    }

    // --- legacy forms: /s/, /connect/, azula://connect?code=, bare token ---
    parse_ticket(s).map(Parsed::Ticket)
}

/// Parse a ticket from any supported **legacy** URL / bare-token form.
///
/// Returns `None` only if the input is completely empty after trimming.
pub fn parse_ticket(input: &str) -> Option<String> {
    let s = input.trim();
    if s.is_empty() {
        return None;
    }

    // --- azula://connect?code=<token> ---
    if let Some(rest) = s.strip_prefix("azula://connect") {
        // rest is either "" or "?..." or "#..."
        let query = rest.trim_start_matches('?');
        for part in query.split('&') {
            if let Some(v) = part.strip_prefix("code=") {
                let token = strip_fragment(v).trim_end_matches('/');
                if !token.is_empty() {
                    return Some(token.to_string());
                }
            }
        }
        // If we had the scheme but no code= param, treat rest as bare token
        // (should not happen in practice, but be defensive).
        return None;
    }

    // --- https://azula.app/s/<token> ---
    if let Some(rest) = s.strip_prefix("https://azula.app/s/") {
        let token = strip_query_and_fragment(rest).trim_end_matches('/');
        if !token.is_empty() {
            return Some(token.to_string());
        }
        return None;
    }

    // --- https://azula.app/connect/<token> ---
    if let Some(rest) = s.strip_prefix("https://azula.app/connect/") {
        let token = strip_query_and_fragment(rest).trim_end_matches('/');
        if !token.is_empty() {
            return Some(token.to_string());
        }
        return None;
    }

    // --- bare token ---
    // Strip any trailing fragment/query that might have crept in.
    let token = strip_query_and_fragment(s).trim_end_matches('/');
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

/// Remove `?…` and `#…` suffixes.
fn strip_query_and_fragment(s: &str) -> &str {
    let s = if let Some(pos) = s.find('?') { &s[..pos] } else { s };
    if let Some(pos) = s.find('#') { &s[..pos] } else { s }
}

/// Remove `#…` suffix only (used after we've already consumed the `?` part).
fn strip_fragment(s: &str) -> &str {
    if let Some(pos) = s.find('#') { &s[..pos] } else { s }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slash_s_url() {
        assert_eq!(
            parse_ticket("https://azula.app/s/abc123"),
            Some("abc123".into())
        );
    }

    #[test]
    fn slash_s_url_with_trailing_slash() {
        assert_eq!(
            parse_ticket("https://azula.app/s/abc123/"),
            Some("abc123".into())
        );
    }

    #[test]
    fn connect_url() {
        assert_eq!(
            parse_ticket("https://azula.app/connect/mytoken"),
            Some("mytoken".into())
        );
    }

    #[test]
    fn azula_scheme() {
        assert_eq!(
            parse_ticket("azula://connect?code=phonetok"),
            Some("phonetok".into())
        );
    }

    #[test]
    fn azula_scheme_extra_params() {
        assert_eq!(
            parse_ticket("azula://connect?code=phonetok&v=2"),
            Some("phonetok".into())
        );
    }

    #[test]
    fn bare_token() {
        assert_eq!(parse_ticket("testtoken123"), Some("testtoken123".into()));
    }

    #[test]
    fn empty_returns_none() {
        assert_eq!(parse_ticket(""), None);
        assert_eq!(parse_ticket("  "), None);
    }

    // --- Parsed::/parse() ---

    #[test]
    fn parse_invite_https_link() {
        assert_eq!(
            parse("https://azula.app/i/aziaeaaci2fm6e2xtppnfk3sa"),
            Some(Parsed::Invite("aziaeaaci2fm6e2xtppnfk3sa".into()))
        );
    }

    #[test]
    fn parse_invite_https_link_trailing_slash() {
        assert_eq!(
            parse("https://azula.app/i/aziaeaaci2fm6e2xtppnfk3sa/"),
            Some(Parsed::Invite("aziaeaaci2fm6e2xtppnfk3sa".into()))
        );
    }

    #[test]
    fn parse_invite_custom_scheme() {
        assert_eq!(
            parse("azula://i?c=aziaeaaci2fm6e2xtppnfk3sa"),
            Some(Parsed::Invite("aziaeaaci2fm6e2xtppnfk3sa".into()))
        );
    }

    #[test]
    fn parse_invite_custom_scheme_extra_params() {
        assert_eq!(
            parse("azula://i?c=aziaeaaci2fm6e2xtppnfk3sa&v=2"),
            Some(Parsed::Invite("aziaeaaci2fm6e2xtppnfk3sa".into()))
        );
    }

    #[test]
    fn parse_bare_invite_payload() {
        assert_eq!(
            parse("aziaeaaci2fm6e2xtppnfk3sa"),
            Some(Parsed::Invite("aziaeaaci2fm6e2xtppnfk3sa".into()))
        );
    }

    #[test]
    fn parse_legacy_slash_s_is_ticket() {
        assert_eq!(parse("https://azula.app/s/abc123"), Some(Parsed::Ticket("abc123".into())));
    }

    #[test]
    fn parse_legacy_connect_is_ticket() {
        assert_eq!(
            parse("https://azula.app/connect/mytoken"),
            Some(Parsed::Ticket("mytoken".into()))
        );
    }

    #[test]
    fn parse_legacy_custom_scheme_is_ticket() {
        assert_eq!(
            parse("azula://connect?code=phonetok"),
            Some(Parsed::Ticket("phonetok".into()))
        );
    }

    #[test]
    fn parse_bare_non_invite_token_is_ticket() {
        assert_eq!(parse("testtoken123"), Some(Parsed::Ticket("testtoken123".into())));
    }

    #[test]
    fn parse_empty_returns_none() {
        assert_eq!(parse(""), None);
        assert_eq!(parse("  "), None);
    }

    // --- run_new_device_session / run_rootless_session (task 6.4 / 8.1) ----

    use crate::certs::FLAG_MAILBOX;
    use crate::proto::Contact;
    use iroh::SecretKey;

    fn seed(start: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = start.wrapping_add(i as u8);
        }
        s
    }

    fn sample_bundle() -> IdentityBundle {
        IdentityBundle {
            root_pk: "root-hex".to_string(),
            certs: vec!["azd-example".to_string()],
            revocations: vec![],
            contacts: vec![Contact { root_pk: Some("contact-root".into()), node_id: None, name: Some("Alice".into()) }],
            mailbox: None,
        }
    }

    /// One simulated bidirectional connection: `other_writer`/`other_reader`
    /// are the "other side"'s ends; `my_reader`/`my_writer` are what gets
    /// passed into the function under test.
    fn wire_pair() -> (
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
    ) {
        let (other_writer, my_reader) = tokio::io::duplex(8192);
        let (my_writer, other_reader) = tokio::io::duplex(8192);
        (other_writer, other_reader, my_reader, my_writer)
    }

    #[tokio::test]
    async fn new_device_session_sends_hello_and_receives_a_grant() {
        let device_pk = SecretKey::from_bytes(&seed(0x10)).public();
        let (mut other_writer, mut other_reader, my_reader, my_writer) = wire_pair();

        let bundle = sample_bundle();
        write_frame(&mut other_writer, &Frame::LinkGrant { cert: "azd-granted".into(), bundle: bundle.clone() })
            .await
            .unwrap();

        let outcome = run_new_device_session(my_reader, my_writer, device_pk, "laptop", FLAG_MAILBOX)
            .await
            .expect("session completes");
        assert_eq!(outcome, LinkOutcome::Granted { cert: "azd-granted".into(), bundle });

        // The other side must have received exactly the LinkHello we sent.
        let mut r = BufReader::new(&mut other_reader);
        let hello = read_frame(&mut r).await.unwrap().expect("hello frame");
        match hello {
            Frame::LinkHello { device_pk: pk, name, roles } => {
                assert_eq!(pk, device_pk.to_string());
                assert_eq!(name, "laptop");
                assert_eq!(roles, FLAG_MAILBOX, "--mailbox must set the mailbox role bit");
            }
            other => panic!("expected LinkHello, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn new_device_session_without_mailbox_flag_sends_zero_roles() {
        let device_pk = SecretKey::from_bytes(&seed(0x11)).public();
        let (mut other_writer, mut other_reader, my_reader, my_writer) = wire_pair();
        write_frame(&mut other_writer, &Frame::LinkReject { reason: "nope".into() }).await.unwrap();

        let _ = run_new_device_session(my_reader, my_writer, device_pk, "phone", 0).await.unwrap();

        let mut r = BufReader::new(&mut other_reader);
        match read_frame(&mut r).await.unwrap().expect("hello frame") {
            Frame::LinkHello { roles, .. } => assert_eq!(roles, 0),
            other => panic!("expected LinkHello, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn new_device_session_on_reject_yields_rejected_and_no_cert() {
        let device_pk = SecretKey::from_bytes(&seed(0x12)).public();
        let (mut other_writer, _other_reader, my_reader, my_writer) = wire_pair();
        write_frame(&mut other_writer, &Frame::LinkReject { reason: "user declined".into() }).await.unwrap();

        let outcome = run_new_device_session(my_reader, my_writer, device_pk, "phone", 0).await.unwrap();
        assert_eq!(outcome, LinkOutcome::Rejected { reason: "user declined".into() });
    }

    #[tokio::test]
    async fn new_device_session_errors_on_an_unexpected_frame() {
        let device_pk = SecretKey::from_bytes(&seed(0x13)).public();
        let (mut other_writer, _other_reader, my_reader, my_writer) = wire_pair();
        write_frame(&mut other_writer, &Frame::SyncAck { vector: Default::default() }).await.unwrap();

        let err = run_new_device_session(my_reader, my_writer, device_pk, "phone", 0).await.unwrap_err();
        assert!(err.to_string().contains("LinkGrant"), "{err}");
    }

    #[tokio::test]
    async fn new_device_session_errors_on_clean_close_before_any_reply() {
        let device_pk = SecretKey::from_bytes(&seed(0x14)).public();
        let (other_writer, _other_reader, my_reader, my_writer) = wire_pair();
        drop(other_writer); // immediate EOF, no grant/reject at all

        let err = run_new_device_session(my_reader, my_writer, device_pk, "phone", 0).await.unwrap_err();
        assert!(err.to_string().contains("closed"), "{err}");
    }

    #[tokio::test]
    async fn rootless_session_always_rejects() {
        let (mut other_writer, mut other_reader, my_reader, my_writer) = wire_pair();
        write_frame(
            &mut other_writer,
            &Frame::LinkHello { device_pk: "abcd".into(), name: "someone".into(), roles: 0 },
        )
        .await
        .unwrap();

        run_rootless_session(my_reader, my_writer).await.expect("rootless session never hard-errors");

        let mut r = BufReader::new(&mut other_reader);
        match read_frame(&mut r).await.unwrap().expect("a reply") {
            Frame::LinkReject { reason } => assert!(reason.contains("no root secret"), "{reason}"),
            other => panic!("expected LinkReject, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rootless_session_rejects_even_with_no_incoming_frame() {
        let (other_writer, mut other_reader, my_reader, my_writer) = wire_pair();
        drop(other_writer); // dialer sent nothing at all

        run_rootless_session(my_reader, my_writer).await.expect("rootless session never hard-errors");

        let mut r = BufReader::new(&mut other_reader);
        assert!(matches!(read_frame(&mut r).await.unwrap(), Some(Frame::LinkReject { .. })));
    }
}
