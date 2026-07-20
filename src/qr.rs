//! QR-code pairing helpers.
//!
//! Provides small utilities to build a pairing URL and render it as a compact
//! Unicode QR block suitable for dark terminals.

use qrcode::render::unicode::Dense1x2;
use qrcode::QrCode;

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

fn print_pairing_url(title: &str, url: &str) {
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
