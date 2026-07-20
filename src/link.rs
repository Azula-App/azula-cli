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
}
