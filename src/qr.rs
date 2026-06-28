//! QR-code pairing helpers.
//!
//! Provides small utilities to build a pairing URL and render it as a compact
//! Unicode QR block suitable for dark terminals.

use qrcode::render::unicode::Dense1x2;
use qrcode::QrCode;

/// Build the universal-link / deep-link pairing URL for a given ticket.
pub fn pairing_url(ticket: &str) -> String {
    format!("https://azula.app/s/{ticket}")
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
/// code, and a camera-hint.  Reused by both `serve` and `serve-mcp`.
pub fn print_pairing(title: &str, ticket: &str) {
    let url = pairing_url(ticket);
    let qr = render_qr(&url);
    println!();
    println!("  {title}");
    println!();
    println!("  {url}");
    println!();
    println!("{qr}");
    println!("  Scan with your phone's camera, or open the URL.");
    println!();
}
