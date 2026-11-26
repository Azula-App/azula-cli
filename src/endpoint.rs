//! Shared startup helpers for the long-lived server commands (`serve`, the
//! `serve-mcp`/`mcp` bridge, and the `blackjack` demo): binding an iroh
//! endpoint with a persisted identity and printing the startup banner.

use std::time::Duration;

use anyhow::{bail, Result};
use iroh::endpoint::presets;
use iroh::tls::CaTlsConfig;
use iroh::{Endpoint, SecretKey, Watcher};
use iroh_tickets::endpoint::EndpointTicket;
use tracing::{info, warn};
use url::Url;

use crate::identity;

/// Everything that varies between the endpoints azula binds.
///
/// Process-wide environment knobs (`HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY`,
/// `AZULA_RELAY_ONLY`, `AZULA_TLS_ROOTS`) apply on top of these to *every*
/// endpoint; see [`bind_with_options`].
#[derive(Debug, Clone)]
pub struct EndpointOptions {
    pub secret: SecretKey,
    /// ALPNs to accept. Empty is fine when a `Router` registers its own later.
    pub alpns: Vec<Vec<u8>>,
    /// Disable every direct IP/UDP transport so only the relay path is used
    /// (also forced on by `AZULA_RELAY_ONLY=1`).
    pub relay_only: bool,
    /// `None` waits for the relay forever (the historic behaviour); `Some(d)`
    /// fails with an actionable error if no relay is connected within `d`.
    /// Not used with `wait_online: false`.
    pub online_timeout: Option<Duration>,
    /// `false` returns as soon as the endpoint is bound, without waiting for a
    /// relay. The caller then finds out whether one is reachable, e.g. with
    /// [`relay_unreachable`].
    pub wait_online: bool,
    /// `Some((keep_alive, idle_timeout))` sets the QUIC keep-alive interval and
    /// idle timeout for every connection on this endpoint (both directions),
    /// via `iroh::endpoint::QuicTransportConfig::builder()`'s
    /// `keep_alive_interval` / `max_idle_timeout`. `None` keeps iroh's
    /// defaults. Compute uses 2 s / 10 s so a vanished peer is noticed fast.
    pub quic_timeouts: Option<(Duration, Duration)>,
    /// `Some(url)` homes the endpoint on that one relay instead of n0's
    /// default map: `Builder::relay_mode(RelayMode::Custom(RelayMap::from(url)))`
    /// (iroh 1.5, `iroh::endpoint::RelayMode`, `iroh::RelayMap: From<RelayUrl>`).
    /// Compute clients use the token's relay so both directions of a
    /// connection meet on the host's relay. Address discovery is unchanged.
    pub relay_url: Option<iroh::RelayUrl>,
}

impl EndpointOptions {
    pub fn new(secret: SecretKey) -> Self {
        Self {
            secret,
            alpns: Vec::new(),
            relay_only: false,
            online_timeout: None,
            wait_online: true,
            quic_timeouts: None,
            relay_url: None,
        }
    }
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

fn env_truthy(name: &str) -> bool {
    env_nonempty(name)
        .is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
}

/// Replace `user:pass@` in any URL-ish text so credentials never reach logs
/// or error messages.
pub fn redact_credentials(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find("://") {
        let (head, tail) = rest.split_at(i + 3);
        out.push_str(head);
        let end = tail
            .find(|c: char| c.is_whitespace() || c == '/' || c == '"' || c == '\'')
            .unwrap_or(tail.len());
        match tail[..end].rfind('@') {
            Some(at) => {
                out.push_str("<redacted>@");
                rest = &tail[at + 1..];
            }
            None => rest = tail,
        }
    }
    out.push_str(rest);
    out
}

/// Does `host` match a `NO_PROXY`-style list (`*`, exact, `.suffix`, `suffix`)?
fn no_proxy_matches(list: &str, host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    list.split(',')
        .map(|e| e.trim().trim_end_matches('.').to_ascii_lowercase())
        .any(|e| {
            if e.is_empty() {
                return false;
            }
            if e == "*" {
                return true;
            }
            let e = e.trim_start_matches("*.").trim_start_matches('.');
            host == e || host.ends_with(&format!(".{e}"))
        })
}

/// The proxy to send relay (HTTPS) traffic through, from the environment.
///
/// iroh's own `Builder::proxy_from_env` prefers `HTTP_PROXY` and ignores
/// `NO_PROXY`; relay traffic is HTTPS, so we prefer `HTTPS_PROXY` and honor
/// `NO_PROXY`. iroh only takes one proxy URL for all of its HTTP(S) traffic,
/// so the proxy is skipped only when *every* default relay host is excluded.
fn proxy_from_env(relay_hosts: &[String]) -> Option<Url> {
    let url = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"]
        .iter()
        .find_map(|n| env_nonempty(n))
        .and_then(|v| v.parse::<Url>().ok())?;
    if let Some(no) = env_nonempty("NO_PROXY").or_else(|| env_nonempty("no_proxy")) {
        if !relay_hosts.is_empty() && relay_hosts.iter().all(|h| no_proxy_matches(&no, h)) {
            return None;
        }
    }
    Some(url)
}

fn default_relay_urls() -> Vec<String> {
    iroh::defaults::prod::default_relay_map()
        .urls::<Vec<_>>()
        .iter()
        .map(|u| u.to_string())
        .collect()
}

/// TLS trust for relay/pkarr/DNS HTTPS: the OS store when a proxy is in play
/// (cloud proxies re-sign TLS with a CA installed in the system store),
/// relay-only is requested, or `AZULA_TLS_ROOTS=system`; otherwise iroh's
/// embedded Mozilla roots, exactly as before. `AZULA_TLS_ROOTS=embedded`
/// forces the old behaviour.
fn use_system_roots(proxied: bool, relay_only: bool) -> bool {
    match env_nonempty("AZULA_TLS_ROOTS")
        .map(|v| v.to_ascii_lowercase())
        .as_deref()
    {
        Some("system") => true,
        Some("embedded") => false,
        _ => proxied || relay_only,
    }
}

async fn bind_once(
    opts: &EndpointOptions,
    proxy: Option<&Url>,
    relay_only: bool,
    system_roots: bool,
) -> Result<Endpoint> {
    let mut b = Endpoint::builder(presets::N0).secret_key(opts.secret.clone());
    if !opts.alpns.is_empty() {
        b = b.alpns(opts.alpns.clone());
    }
    if let Some(url) = proxy {
        b = b.proxy_url(url.clone());
    }
    if relay_only {
        b = b.clear_ip_transports();
    }
    if let Some(url) = &opts.relay_url {
        b = b.relay_mode(iroh::endpoint::RelayMode::Custom(iroh::RelayMap::from(url.clone())));
    }
    if let Some((keep_alive, idle)) = opts.quic_timeouts {
        let idle = iroh::endpoint::IdleTimeout::try_from(idle)?;
        b = b.transport_config(
            iroh::endpoint::QuicTransportConfig::builder()
                .keep_alive_interval(keep_alive)
                .max_idle_timeout(Some(idle))
                .build(),
        );
    }
    if system_roots {
        b = b.ca_tls_config(CaTlsConfig::system());
    }
    Ok(b.bind().await?)
}

/// Bind an endpoint with `opts` plus the process-wide environment knobs.
///
/// * Proxy: `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY` (and lowercase) for relay
///   connections, via `iroh::endpoint::Builder::proxy_url`.
/// * Relay-only: `opts.relay_only` or `AZULA_RELAY_ONLY=1` removes all IP
///   transports via `Builder::clear_ip_transports`.
/// * TLS: system trust store via `CaTlsConfig::system()` (iroh's
///   `platform-verifier` feature) when proxied / relay-only; see
///   [`use_system_roots`]. Falls back to the embedded roots (with a warning)
///   if the OS store can't be loaded.
///
/// With `online_timeout: Some(d)` this waits at most `d` for a relay
/// connection and otherwise returns an error naming the relay URLs tried.
pub async fn bind_with_options(opts: EndpointOptions) -> Result<Endpoint> {
    let relay_only = opts.relay_only || env_truthy("AZULA_RELAY_ONLY");
    let proxy = proxy_from_env(
        &default_relay_urls()
            .iter()
            .filter_map(|u| Url::parse(u).ok())
            .filter_map(|u| u.host_str().map(str::to_owned))
            .collect::<Vec<_>>(),
    );
    let system_roots = use_system_roots(proxy.is_some(), relay_only);
    if let Some(p) = &proxy {
        let shown = redact_credentials(p.as_str());
        info!("relay traffic via proxy {shown}");
    }
    if relay_only {
        info!("relay-only: direct IP transports disabled");
    }

    let endpoint = match bind_once(&opts, proxy.as_ref(), relay_only, system_roots).await {
        Ok(ep) => ep,
        Err(err) if system_roots => {
            warn!("system TLS roots unavailable ({err:#}); falling back to embedded roots");
            bind_once(&opts, proxy.as_ref(), relay_only, false).await?
        }
        Err(err) => return Err(err),
    };

    if !opts.wait_online {
        return Ok(endpoint);
    }
    info!("bringing endpoint online…");
    match opts.online_timeout {
        None => endpoint.online().await,
        Some(d) => {
            if tokio::time::timeout(d, endpoint.online()).await.is_err() {
                let msg = relay_unreachable(&endpoint, &opts, d);
                endpoint.close().await;
                bail!(msg);
            }
        }
    }
    Ok(endpoint)
}

/// What to tell someone whose endpoint hasn't reached a relay within `waited`:
/// the relays tried, whether a proxy was used, and the last error.
pub fn relay_unreachable(endpoint: &Endpoint, opts: &EndpointOptions, waited: Duration) -> String {
    let mut status = endpoint.home_relay_status();
    let mut tried: Vec<String> = Vec::new();
    let mut last_err = None;
    for s in status.get() {
        tried.push(s.url().to_string());
        if last_err.is_none() {
            last_err = s.last_error().map(|e| redact_credentials(&format!("{e:#}")));
        }
    }
    if tried.is_empty() {
        tried = match &opts.relay_url {
            Some(u) => vec![u.to_string()],
            None => default_relay_urls(),
        };
    }
    let proxy = proxy_from_env(
        &default_relay_urls().iter().filter_map(|u| Url::parse(u).ok()).filter_map(|u| u.host_str().map(str::to_owned)).collect::<Vec<_>>(),
    );
    let proxy_note = match &proxy {
        Some(p) => format!("via proxy {}", redact_credentials(p.as_str())),
        None => "with no HTTPS_PROXY/HTTP_PROXY set".to_owned(),
    };
    let detail = last_err.map(|e| format!(" Last error: {e}.")).unwrap_or_default();
    format!(
        "could not reach an iroh relay within {}s (tried {}; {proxy_note}).{detail} \
                     Check that the HTTPS proxy is configured (HTTPS_PROXY) and its allowlist permits these relay hosts on port 443, \
                     and that the proxy's CA is in the system trust store.",
        waited.as_secs_f32(),
                    tried.join(", "),
    )
}

/// Bind an iroh endpoint with an explicit secret key, wait for it to come
/// online (no deadline), and return it along with its connect ticket. This is
/// the "bind → online → ticket" sequence every server command needs before
/// standing up its own ALPN handlers; [`bind_server_endpoint`] and
/// [`bind_machine_endpoint`] are thin wrappers that resolve `secret` from a
/// persisted identity first. Goes through [`bind_with_options`], so proxy,
/// relay-only and TLS-trust environment settings apply.
pub async fn bind_endpoint_with_secret(secret: SecretKey) -> Result<(Endpoint, String)> {
    let endpoint = bind_with_options(EndpointOptions::new(secret)).await?;
    let ticket = EndpointTicket::new(endpoint.addr()).to_string();
    Ok((endpoint, ticket))
}

/// Bind an iroh endpoint reusing the persisted secret key for `identity_name`,
/// wait for it to come online, and return it along with its connect ticket.
pub async fn bind_server_endpoint(identity_name: &str) -> Result<(Endpoint, String)> {
    bind_endpoint_with_secret(identity::load_or_create_secret(identity_name)).await
}

/// As [`bind_server_endpoint`], but for the machine identity
/// (`~/.azula/machine.key`, adopting `bridge.key` in place if that's all that
/// exists — see `identity::load_or_create_machine_secret`). Creation is
/// allowed here: callers of this function are explicit pairing-side flows
/// (`azula invite --bridge`, `start_pairing`, the bridge startup banner),
/// never a bare session-establishment path.
pub async fn bind_machine_endpoint() -> Result<(Endpoint, String)> {
    bind_endpoint_with_secret(identity::load_or_create_machine_secret()).await
}

/// Print a boxed startup banner: a centered `title`, then each of `body` on
/// its own line. Callers format `body` with whatever's relevant (ticket, endpoint
/// id, ALPNs, HTTP endpoint, …) — this just owns the shared framing.
pub fn print_banner(title: &str, body: &[String]) {
    const INNER_WIDTH: usize = 60;
    let title_len = title.chars().count();
    let left = (INNER_WIDTH.saturating_sub(title_len)) / 2;
    let right = INNER_WIDTH.saturating_sub(title_len).saturating_sub(left);

    println!();
    println!("  ╔{}╗", "═".repeat(INNER_WIDTH));
    println!("  ║{}{}{}║", " ".repeat(left), title, " ".repeat(right));
    println!("  ╚{}╝", "═".repeat(INNER_WIDTH));
    println!();
    for line in body {
        println!("{line}");
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_proxy_credentials() {
        assert_eq!(redact_credentials("http://u:p@proxy:3128/x"), "http://<redacted>@proxy:3128/x");
        assert_eq!(redact_credentials("err via https://a:b@h and http://c@d"), "err via https://<redacted>@h and http://<redacted>@d");
        assert_eq!(redact_credentials("https://relay.example/"), "https://relay.example/");
    }

    #[test]
    fn no_proxy_matching() {
        assert!(no_proxy_matches("*", "use1-1.relay.n0.iroh.link"));
        assert!(no_proxy_matches("localhost, .n0.iroh.link", "use1-1.relay.n0.iroh.link."));
        assert!(no_proxy_matches("iroh.link", "euc1-1.relay.n0.iroh.link"));
        assert!(!no_proxy_matches("localhost,10.0.0.0/8", "use1-1.relay.n0.iroh.link"));
        assert!(!no_proxy_matches("", "x.y"));
    }
}
