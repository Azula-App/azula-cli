//! QR-code pairing helpers.
//!
//! Provides small utilities to build a pairing URL and render it as a compact
//! Unicode QR block suitable for dark terminals.

use qrcode::render::unicode::Dense1x2;
use qrcode::QrCode;

use crate::link::{self, Parsed};

/// Build the universal-link / deep-link pairing URL for a **legacy** raw
/// ticket (`--legacy-ticket` escape hatch; superseded by [`invite_url`]).
pub fn pairing_url(ticket: &str) -> String {
    format!("https://azula.app/s/{ticket}")
}

/// Build the canonical share link for an encoded invite payload
/// (`https://azula.app/i/<payload>`; see `azula-docs/openspec/specs/invitations/design.md`).
pub fn invite_url(encoded: &str) -> String {
    format!("https://azula.app/i/{encoded}")
}

/// Resolve what a `azula qr <CODE>` argument should actually encode.
///
/// `azula qr` is documented as taking "any ticket, URL, or bare token", so an
/// argument that is **already** a full azula link — any `https://azula.app/…`
/// (`/i/` invites, `/l/` device-link codes, the retired `/s/` form) or any
/// `azula://…` custom-scheme URL — is encoded verbatim. Only bare input gets a
/// wrapper built for it: an `azi…` invite payload becomes an [`invite_url`],
/// and anything else is treated as a raw ticket and wrapped by [`pairing_url`].
///
/// The verbatim pass-through is the point. `azula terminal new` hands the user
/// an `https://azula.app/i/<payload>` link, and feeding that straight back to
/// `azula qr` used to `/s/`-prefix it into
/// `https://azula.app/s/https://azula.app/i/<payload>` — a double-wrapped URL
/// whose QR could not pair anything. Closing the legacy escape hatch turned
/// that into an outright rejection (`link::parse_ticket` refuses URL-shaped
/// input), which is no better: the one link the terminal flow prints was still
/// the one input `azula qr` would not take.
///
/// Returns `None` when there is nothing to encode — empty input, or bare input
/// that is not a usable token (e.g. a non-azula URL).
pub fn qr_target(input: &str) -> Option<String> {
    let s = input.trim();
    if s.is_empty() {
        return None;
    }
    if is_azula_link(s) {
        return Some(s.to_string());
    }
    // Bare input: let `link::parse` say whether it's an invite payload or a
    // raw ticket, so an `azi…` payload is never dressed up as a `/s/` ticket.
    match link::parse(s) {
        Some(Parsed::Invite(payload)) => Some(invite_url(&payload)),
        Some(Parsed::Ticket(token)) => Some(pairing_url(&token)),
        None => None,
    }
}

/// Is `s` already a complete azula link (either URL family)?
fn is_azula_link(s: &str) -> bool {
    s.starts_with("https://azula.app/") || s.starts_with("azula://")
}

/// Encode `data` as a QR code and render it as a compact Unicode string using
/// Dense1x2 half-block characters.  The result includes a quiet zone and works
/// on a typical dark terminal (dark module = "█", light module = " ").
pub fn render_qr(data: &str) -> String {
    // Gracefully degrade: if the data is too long or contains unencodable
    // characters, return a helpful message rather than panicking.
    let code = match QrCode::new(data.as_bytes()) {
        Ok(c) => c,
        Err(e) => return format!("(QR render error: {e})"),
    };
    code.render::<Dense1x2>()
        .quiet_zone(true)
        .dark_color(Dense1x2::Dark)
        .light_color(Dense1x2::Light)
        .build()
}

/// Print a labelled pairing block to stdout: title, URL, a blank line, the QR
/// code, and a camera-hint. `--legacy-ticket` escape hatch; prefer
/// [`print_invite_pairing`].
pub fn print_pairing(title: &str, ticket: &str) {
    print_pairing_url(title, &pairing_url(ticket));
}

/// As [`print_pairing`], but for an encoded invite payload
/// (`https://azula.app/i/<payload>`).
pub fn print_invite_pairing(title: &str, encoded_invite: &str) {
    print_pairing_url(title, &invite_url(encoded_invite));
}

/// Print a labelled pairing block for an already-fully-formed URL (as
/// opposed to [`print_pairing`]/[`print_invite_pairing`], which build the URL
/// from a ticket/encoded-invite themselves) — e.g. `SessionCore::pairing_url`'s
/// return value, which is one or the other already resolved.
pub fn print_pairing_url(title: &str, url: &str) {
    let qr = render_qr(url);
    println!();
    println!("  {title}");
    println!();
    println!("  {url}");
    println!();
    println!("{qr}");
    println!("  Scan with your phone's camera, or open the URL.");
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYLOAD: &str = "aziaeaaci2fm6e2xtppnfk3sa";

    // --- bare input: a wrapper is built ---------------------------------

    #[test]
    fn bare_ticket_token_is_wrapped() {
        assert_eq!(
            qr_target("testtoken123").as_deref(),
            Some("https://azula.app/s/testtoken123")
        );
    }

    #[test]
    fn bare_invite_payload_is_wrapped_as_an_invite_not_a_ticket() {
        // `/s/` is the raw-ticket wrapper; an `azi…` payload is an invite and
        // must get `/i/`, or the QR encodes a link nothing can redeem.
        assert_eq!(qr_target(PAYLOAD).as_deref(), Some("https://azula.app/i/aziaeaaci2fm6e2xtppnfk3sa"));
    }

    // --- full links: passed through verbatim, never re-wrapped -----------

    /// The reported bug: the link `azula terminal new` prints, handed straight
    /// back to `azula qr`, must survive untouched.
    #[test]
    fn invite_url_passes_through_verbatim() {
        let url = format!("https://azula.app/i/{PAYLOAD}");
        assert_eq!(qr_target(&url).as_deref(), Some(url.as_str()));
    }

    #[test]
    fn slash_s_url_passes_through_verbatim() {
        // Documented as accepted by `azula qr` since before the `/s/` form was
        // retired; whatever the link's fate, it must not become
        // `https://azula.app/s/https://azula.app/s/…`.
        assert_eq!(
            qr_target("https://azula.app/s/abc123").as_deref(),
            Some("https://azula.app/s/abc123")
        );
    }

    #[test]
    fn azula_connect_scheme_url_passes_through_verbatim() {
        assert_eq!(
            qr_target("azula://connect?code=phonetok").as_deref(),
            Some("azula://connect?code=phonetok")
        );
    }

    #[test]
    fn azula_invite_scheme_url_passes_through_verbatim() {
        let url = format!("azula://i?c={PAYLOAD}");
        assert_eq!(qr_target(&url).as_deref(), Some(url.as_str()));
    }

    #[test]
    fn device_link_url_passes_through_verbatim() {
        // `/l/` is what `azula link` prints — a different payload family, but
        // the same "already a link" rule covers it.
        let url = format!("https://azula.app/l/{PAYLOAD}");
        assert_eq!(qr_target(&url).as_deref(), Some(url.as_str()));
    }

    /// No azula link of any family may come back double-wrapped.
    #[test]
    fn no_link_form_is_ever_double_wrapped() {
        for input in [
            format!("https://azula.app/i/{PAYLOAD}"),
            format!("azula://i?c={PAYLOAD}"),
            format!("https://azula.app/l/{PAYLOAD}"),
            "https://azula.app/s/abc123".to_string(),
            "https://azula.app/connect/mytoken".to_string(),
            "azula://connect?code=phonetok".to_string(),
        ] {
            let out = qr_target(&input).expect("a link always resolves to a target");
            assert_eq!(out, input, "{input} was rewritten");
            assert!(!out.contains("/s/https://"), "{input} was double-wrapped into {out}");
        }
    }

    // --- surrounding whitespace, and input with nothing to encode --------

    #[test]
    fn surrounding_whitespace_is_trimmed() {
        let padded = format!("  https://azula.app/i/{PAYLOAD}\n");
        assert_eq!(qr_target(&padded).as_deref(), Some(format!("https://azula.app/i/{PAYLOAD}").as_str()));
        assert_eq!(qr_target("  tok123  ").as_deref(), Some("https://azula.app/s/tok123"));
    }

    #[test]
    fn empty_input_has_no_target() {
        assert_eq!(qr_target(""), None);
        assert_eq!(qr_target("   "), None);
    }

    #[test]
    fn a_non_azula_url_has_no_target() {
        // Not a pass-through candidate and not a bare token either: rejected
        // rather than wrapped into `https://azula.app/s/https://example.com/x`.
        assert_eq!(qr_target("https://example.com/x"), None);
    }

    // --- the rendered block actually encodes the resolved URL ------------

    #[test]
    fn rendering_a_pass_through_link_produces_a_real_qr() {
        let url = qr_target(&format!("https://azula.app/i/{PAYLOAD}")).unwrap();
        let rendered = render_qr(&url);
        assert!(!rendered.contains("QR render error"), "{rendered}");
        assert!(rendered.contains('█'), "expected dark modules in the rendered block");
    }
}
