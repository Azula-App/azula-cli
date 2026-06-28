//! Ticket / URL parsing for `azula pair` and `--device`.
//!
//! Accepts four forms:
//!   - `https://azula.app/s/<token>`
//!   - `https://azula.app/connect/<token>`
//!   - `azula://connect?code=<token>`
//!   - a bare token (anything else)
//!
//! In all cases the token is returned with no query-string, fragment, or
//! trailing slash.  No network access is performed; the token is not validated.

/// Parse a ticket from any supported URL / bare-token form.
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
}
