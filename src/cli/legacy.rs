//! Commands kept unchanged by the cli-multi-session-relay CLI restructure —
//! `pair`/`devices`/`qr`/`invite`/`invites`/`link` — plus the `serve` command
//! body, moved here verbatim from the old `main.rs` (`cli::mod`'s
//! `Command::Serve` hidden alias and the bare-invocation default both call
//! [`serve`]).

use anyhow::{Context, Result};
use iroh::endpoint::presets;
use iroh_tickets::endpoint::EndpointTicket;
use iroh_tickets::Ticket as _;
use tracing::{info, warn};

use crate::certs::{self, FLAG_MAILBOX};
use crate::invite::{self, Expiry};
use crate::link::{self, LinkHandler, LinkOutcome, Parsed};
use crate::linked_identity::{self, LinkedIdentity, NODE_IDENTITY_NAME};
use crate::mcp::{LlmHandler, McpConfig, McpTransport, LLM_ALPN};
use crate::proto::IdentityBundle;
use crate::term::{TermHandler, TERM_ALPN};
use crate::{endpoint, mailbox_role, qr, registry};
use iroh::protocol::Router;

/// Options for `azula pair`.
#[derive(Debug, Clone, clap::Args)]
pub(super) struct PairArgs {
    /// The invite link (https://azula.app/i/<payload>, azula://i?c=<payload>,
    /// bare azi... payload), legacy ticket URL, or bare token.
    pub(super) url: String,

    /// Display name for this device.
    #[arg(long)]
    pub(super) name: Option<String>,

    /// Save to the global (~/.azula) registry instead of the project registry.
    #[arg(long)]
    pub(super) global: bool,
}

/// Options for `azula qr`.
#[derive(Debug, Clone, clap::Args)]
pub(super) struct QrArgs {
    /// A ticket, `https://azula.app/s/<token>`, or `azula://connect?code=<token>` URL.
    pub(super) code: String,
}

/// Options for `azula invite`: mints by default, or `revoke <id-prefix>` to delete one.
#[derive(Debug, Clone, clap::Args)]
pub(super) struct InviteCliArgs {
    #[command(subcommand)]
    pub(super) action: Option<InviteAction>,

    #[command(flatten)]
    pub(super) mint: InviteMintArgs,
}

#[derive(Debug, Clone, clap::Subcommand)]
pub(super) enum InviteAction {
    /// Revoke (delete) an issued invite by id or id-prefix.
    Revoke(InviteRevokeArgs),
}

#[derive(Debug, Clone, clap::Args)]
pub(super) struct InviteMintArgs {
    /// Validity window: `1h`, `24h`, `7d`, or `never`.
    #[arg(long, default_value = "24h")]
    expires: String,

    /// Sign the invite with this node's key so the redeemer/azula.app can
    /// verify authenticity before dialing.
    #[arg(long)]
    sign: bool,

    /// The invite may only be redeemed once.
    #[arg(long = "single-use")]
    single_use: bool,

    /// A note shown next to this invite in `azula invites` (e.g. a recipient's name).
    #[arg(long)]
    label: Option<String>,

    /// Mint against the bridge identity (the one `azula mcp` uses) instead of
    /// the default `serve` identity. Use this to hand out a pairing invite
    /// for a running bridge from the CLI — a plain `azula invite` mints for
    /// a different key and won't be accepted by `azula mcp` (only that
    /// bridge's own startup banner or `start_pairing` tool output will be).
    #[arg(long)]
    bridge: bool,
}

#[derive(Debug, Clone, clap::Args)]
pub(super) struct InviteRevokeArgs {
    /// The invite id (or a unique prefix of it) shown by `azula invites`.
    pub(super) id_prefix: String,
}

/// Options for `azula link`.
#[derive(Debug, Clone, clap::Args)]
pub(super) struct LinkArgs {
    /// Display name to present to the root-holding device. Defaults to this
    /// machine's hostname.
    #[arg(long, value_name = "NAME")]
    name: Option<String>,

    /// Request the mailbox role — the root-holding device's confirmation UI
    /// shows this before granting.
    #[arg(long)]
    mailbox: bool,
}

/// Options for the deprecated `azula mailbox` alias.
#[derive(Debug, Clone, clap::Args)]
pub(super) struct MailboxArgs {
    /// Admit invite-less unverified strangers instead of closing the
    /// connection (same convention as `serve`/`serve-mcp`).
    #[arg(long = "allow-legacy", default_value_t = true, action = clap::ArgAction::Set)]
    pub(super) allow_legacy: bool,
}

/// Options for the `serve` command (also used when run with no subcommand).
#[derive(Debug, Clone, clap::Args)]
pub(super) struct ServeArgs {
    /// Spawn an MCP server as a child process over stdio. Value is a full
    /// command line, e.g. `npx -y @modelcontextprotocol/server-everything`.
    /// Mutually exclusive with --mcp-url.
    #[arg(long, env = "AZULA_MCP_STDIO", conflicts_with = "mcp_url")]
    mcp_stdio: Option<String>,

    /// Connect to a remote MCP server over Streamable HTTP / SSE, e.g.
    /// `https://example.com/mcp`. Mutually exclusive with --mcp-stdio.
    #[arg(long, env = "AZULA_MCP_URL")]
    mcp_url: Option<String>,

    /// MCP tool to call to push a message. Defaults to the first tool the
    /// server lists.
    #[arg(long, env = "AZULA_MCP_TOOL")]
    mcp_tool: Option<String>,

    /// JSON argument name that carries the message text in the tool call.
    #[arg(long, env = "AZULA_MCP_MESSAGE_ARG", default_value = "message")]
    mcp_message_arg: String,

    /// Serve only the remote-terminal ALPN (no LLM). A client that connects then
    /// opens a terminal session directly instead of an LLM chat — handy for the
    /// Docker shell container.
    #[arg(long, env = "AZULA_TERM_ONLY")]
    term_only: bool,

    /// Admit invite-less unknown strangers into the remote-shell ALPN as
    /// unverified instead of closing the connection. Transition escape hatch
    /// — default on for one release, then off (see
    /// azula-docs/openspec/specs/invitations/design.md). Does not affect the LLM relay ALPN,
    /// which has no device-registry concept.
    #[arg(long = "allow-legacy", default_value_t = true, action = clap::ArgAction::Set)]
    allow_legacy: bool,

    /// Print the raw dial ticket in the startup pairing QR instead of minting
    /// a signed 24h invite.
    #[arg(long = "legacy-ticket")]
    legacy_ticket: bool,

    /// Override the name a connecting terminal announces to the app (sent as
    /// `Frame::Profile.name`, becomes the conversation title). Defaults to
    /// this machine's hostname.
    #[arg(long, value_name = "NAME")]
    name: Option<String>,

    /// Override the description a connecting terminal announces to the app
    /// (sent as `Frame::Profile.description`, becomes the conversation
    /// sub-line). Defaults to the shell's launch working directory.
    #[arg(long, value_name = "DESCRIPTION")]
    description: Option<String>,

    /// How long (in minutes) a detached persistent terminal session's shell
    /// stays alive waiting for a `term_attach` reattach before it's killed.
    /// `0` disables persistence entirely — a `term_attach` handshake is
    /// still honored, but the shell never outlives its stream (same as a
    /// legacy client, just speaking the new frames).
    #[arg(long = "session-ttl", value_name = "MINUTES", default_value_t = 60)]
    session_ttl: u64,
}

pub(super) fn cmd_pair(args: PairArgs) -> Result<()> {
    let (token, invite_str) = match link::parse(&args.url) {
        Some(Parsed::Invite(payload)) => {
            let decoded = invite::InvitePayload::decode(&payload)
                .with_context(|| format!("invalid invite: {:?}", args.url))?;
            let ticket = decoded.ticket().context("invalid invite ticket")?;
            (ticket.to_string(), Some(payload))
        }
        Some(Parsed::Ticket(t)) => (t, None),
        None => {
            eprintln!("error: could not extract a token from {:?}", args.url);
            std::process::exit(1);
        }
    };

    let name = args.name.unwrap_or_else(|| {
        token.chars().take(8).collect()
    });

    let device = registry::Device {
        name: name.clone(),
        ticket: token.clone(),
        added_at: Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        ),
        invite: invite_str,
    };

    let path = registry::add(device, args.global)?;

    println!("Paired device '{}' (ticket: {}…)", name, token.chars().take(8).collect::<String>());
    println!("Saved to: {}", path.display());
    Ok(())
}

pub(super) fn cmd_devices() -> Result<()> {
    let known = registry::load();

    if known.is_empty() {
        println!("No devices registered. Use `azula pair <URL>` to add one.");
        return Ok(());
    }

    // Determine which registry file each device came from for the "source" column.
    let global_devices: Vec<String> = registry::global_path()
        .map(|p| registry::read_file(&p).into_iter().map(|d| d.name).collect())
        .unwrap_or_default();

    let project_devices: Vec<String> = registry::project_path()
        .map(|p| registry::read_file(&p).into_iter().map(|d| d.name).collect())
        .unwrap_or_default();

    println!("{:<20} {:<12} SOURCE", "NAME", "FINGERPRINT");
    println!("{}", "-".repeat(48));
    for d in &known {
        let fingerprint: String = d.ticket.chars().take(8).collect();
        let source = if project_devices.contains(&d.name) {
            "project"
        } else if global_devices.contains(&d.name) {
            "global"
        } else {
            "?"
        };
        println!("{:<20} {:<12} {}", d.name, format!("{fingerprint}…"), source);
    }
    Ok(())
}

pub(super) fn cmd_qr(args: QrArgs) -> Result<()> {
    let token = match link::parse_ticket(&args.code) {
        Some(t) => t,
        None => {
            eprintln!("error: could not extract a token from {:?}", args.code);
            std::process::exit(1);
        }
    };
    qr::print_pairing("Pairing code:", &token);
    Ok(())
}

/// Parse `--expires` (`1h`, `24h`, `7d`, `never`) into an [`Expiry`].
fn parse_expiry(s: &str) -> Result<Expiry> {
    match s {
        "never" => Ok(Expiry::Never),
        "1h" => Ok(Expiry::In(std::time::Duration::from_secs(60 * 60))),
        "24h" => Ok(Expiry::In(std::time::Duration::from_secs(24 * 60 * 60))),
        "7d" => Ok(Expiry::In(std::time::Duration::from_secs(7 * 24 * 60 * 60))),
        other => anyhow::bail!("invalid --expires {other:?}; expected 1h, 24h, 7d, or never"),
    }
}

pub(super) async fn cmd_invite_mint(args: InviteMintArgs) -> Result<()> {
    let expiry = parse_expiry(&args.expires)?;

    // `serve` (default) persists its own node key; `--bridge` mints against
    // the **machine** identity (`~/.azula/machine.key`, adopting an existing
    // `bridge.key` in place — see `identity::load_or_create_machine_secret`)
    // — the root that every `azula mcp` session's cert chains to
    // (cli-multi-session-relay design.md D1). This is one of the explicit
    // pairing-side flows allowed to create a machine identity if none exists
    // yet. Getting the identity wrong is the #1 way a minted invite
    // mysteriously fails verification, so it's always printed alongside the
    // result.
    let identity_label = if args.bridge { "machine" } else { "serve" };
    let (endpoint, ticket) = if args.bridge {
        endpoint::bind_machine_endpoint().await?
    } else {
        endpoint::bind_server_endpoint("serve").await?
    };
    let node_id = endpoint.id();

    let (payload, record) = invite::mint(
        &ticket,
        expiry,
        args.sign,
        args.single_use,
        args.label.clone(),
        endpoint.secret_key(),
    )?;
    let encoded = payload.encode();
    let url = qr::invite_url(&encoded);

    let node_id_str = node_id.to_string();
    println!(
        "Minted invite {} for the {identity_label} identity (node {}…)",
        record.id,
        &node_id_str[..8.min(node_id_str.len())]
    );
    println!("  expires: {}", describe_expiry(record.expires_at));
    if let Some(label) = &record.label {
        println!("  label: {label}");
    }
    println!("  signed: {}, single-use: {}", record.is_signed(), record.is_single_use());
    if args.bridge {
        println!("  pairs with: any azula mcp session on this machine (sessions present a cert chained to this machine identity)");
    } else {
        println!("  pairs with: azula serve (this same identity); NOT azula mcp — mint with --bridge for that");
    }
    println!();
    qr::print_invite_pairing("Share this invite:", &encoded);
    println!("  {url}");
    Ok(())
}

fn describe_expiry(expires_at: u32) -> String {
    if expires_at == 0 {
        "never".to_string()
    } else {
        format!("unix {expires_at}")
    }
}

pub(super) fn cmd_invites() -> Result<()> {
    let issued = invite::list();
    if issued.is_empty() {
        println!("No invites issued. Use `azula invite` to mint one.");
        return Ok(());
    }

    println!(
        "{:<18} {:<12} {:<20} {:<10} {:<8} LABEL",
        "ID", "CREATED", "EXPIRES", "CONSUMED", "FLAGS"
    );
    println!("{}", "-".repeat(90));
    for i in &issued {
        let expires = if i.expires_at == 0 { "never".to_string() } else { i.expires_at.to_string() };
        let mut flags = Vec::new();
        if i.is_signed() {
            flags.push("signed");
        }
        if i.is_single_use() {
            flags.push("single-use");
        }
        let flags = if flags.is_empty() { "-".to_string() } else { flags.join(",") };
        println!(
            "{:<18} {:<12} {:<20} {:<10} {:<8} {}",
            i.id,
            i.created_at,
            expires,
            i.consumed,
            flags,
            i.label.as_deref().unwrap_or("-"),
        );
    }
    Ok(())
}

pub(super) fn cmd_invite_revoke(args: InviteRevokeArgs) -> Result<()> {
    let removed = invite::revoke(&args.id_prefix)?;
    if removed == 0 {
        eprintln!("No invite matching {:?} found.", args.id_prefix);
        std::process::exit(1);
    }
    println!("Revoked {removed} invite(s) matching {:?}.", args.id_prefix);
    Ok(())
}

/// `azula link`: generate (or reuse) the `"link"`-named persisted node key
/// (kept separate from `serve`/`bridge`/`blackjack`'s own identities — see
/// `identity::load_or_create_secret`), print the `azl…` payload as a
/// terminal QR and copyable string, accept the inbound `azula/link/0` dial,
/// and persist whatever the root-holding device grants (or nothing, on
/// `LinkReject`).
pub(super) async fn cmd_link(args: LinkArgs) -> Result<()> {
    let secret = crate::identity::load_or_create_secret(NODE_IDENTITY_NAME);
    let endpoint = iroh::Endpoint::builder(presets::N0).secret_key(secret).bind().await?;
    info!("bringing endpoint online…");
    endpoint.online().await;
    let device_pk = endpoint.id();

    let name = args.name.clone().unwrap_or_else(default_link_name);
    let roles = if args.mailbox { FLAG_MAILBOX } else { 0 };

    let ticket = EndpointTicket::new(endpoint.addr());
    let payload = certs::LinkPayload::new(device_pk, name.clone(), ticket.encode_bytes());
    let encoded = payload.encode();

    println!();
    println!("  Scan this on the device that already holds your identity");
    println!("  (or paste the string there):");
    println!();
    println!("  {encoded}");
    println!();
    println!("{}", qr::render_qr(&encoded));
    println!("  Waiting for it to connect… (Ctrl-C to cancel)");

    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    let handler = LinkHandler::new(device_pk, name, roles, result_tx);
    let router = Router::builder(endpoint).accept(link::LINK_ALPN, handler).spawn();

    let outcome = tokio::select! {
        outcome = result_rx => outcome.context("link: session ended without a result")?,
        _ = tokio::signal::ctrl_c() => {
            router.shutdown().await?;
            println!("Cancelled — nothing was saved.");
            return Ok(());
        }
    };
    router.shutdown().await?;

    match outcome {
        LinkOutcome::Granted { cert, bundle } => match verify_granted_cert(&cert, device_pk, &bundle) {
            Ok(()) => {
                linked_identity::save(&LinkedIdentity { cert, bundle })?;
                println!();
                println!("Linked! Certificate and identity bundle saved.");
                println!("Run `azula mailbox` to serve this identity's mailbox role from this machine.");
            }
            Err(e) => {
                println!();
                println!("Link request was granted, but the certificate did not check out ({e}); nothing was saved.");
            }
        },
        LinkOutcome::Rejected { reason } => {
            println!();
            println!("Link request was declined: {reason}");
            println!("Nothing was saved.");
        }
    }
    Ok(())
}

/// Verify a freshly granted certificate before persisting it, per
/// `specs/device-linking/spec.md`'s "Certificate Verification Is
/// Self-Contained" and "Revocation Statements Invalidate Certificates": it
/// must verify (signature + expiry), its `device_pk` must equal this
/// device's own freshly generated key (a `LinkGrant` should always name us,
/// never a different device), and it must not already be revoked per the
/// accompanying bundle's own revocation set. Catches a malformed or
/// already-revoked grant immediately, rather than silently persisting it
/// and only discovering the problem later when `azula mailbox` tries to use
/// it.
fn verify_granted_cert(cert_str: &str, device_pk: iroh::PublicKey, bundle: &IdentityBundle) -> Result<()> {
    let cert = certs::DeviceCert::decode(cert_str).context("certificate is malformed")?;
    cert.verify().context("certificate failed verification")?;
    anyhow::ensure!(
        cert.binds_to_connection(device_pk),
        "certificate's device key does not match this device's own key"
    );
    let revocations = mailbox_role::verified_revocations_from_bundle(bundle);
    anyhow::ensure!(
        !cert.is_revoked_by(&revocations),
        "certificate's device key is already revoked in the accompanying bundle"
    );
    Ok(())
}

/// Default display name for `azula link` when `--name` is omitted: this
/// machine's hostname, falling back to `"azula-cli"` if empty/unavailable.
fn default_link_name() -> String {
    let raw = gethostname::gethostname().to_string_lossy().into_owned();
    if raw.trim().is_empty() {
        "azula-cli".to_string()
    } else {
        raw
    }
}

pub(super) async fn cmd_mailbox(args: MailboxArgs) -> Result<()> {
    mailbox_role::run(args.allow_legacy).await
}

/// `azula serve` — bind the iroh endpoint, print the ticket, and serve until
/// Ctrl-C. Kept wired exactly as it was before the cli-multi-session-relay
/// restructure (both the explicit, now-hidden-and-deprecated `azula serve`
/// alias and the bare `azula` invocation call this); term/LLM serve code is
/// not being deleted this release.
pub(super) async fn serve(args: ServeArgs) -> Result<()> {
    // Bind with the n0 defaults (public discovery + relays), reusing a persisted
    // key so the node id (and connect code) stays stable across restarts.
    let (endpoint, ticket) = endpoint::bind_server_endpoint("serve").await?;
    let node_id = endpoint.id();

    // `0` disables persistence outright (no reaper needed — sessions never
    // survive a detach in that mode, see `term::bind_attachment`).
    let session_ttl = if args.session_ttl == 0 {
        None
    } else {
        Some(std::time::Duration::from_secs(args.session_ttl * 60))
    };
    if let Some(ttl) = session_ttl {
        crate::term::spawn_ttl_reaper(ttl);
    }

    // MCP backend config. Exactly one transport flag may be set (clap enforces
    // mutual exclusion); neither set is allowed and yields the canned fallback.
    let transport = match (args.mcp_stdio, args.mcp_url) {
        (Some(cmd), _) => Some(McpTransport::Stdio(cmd)),
        (_, Some(url)) => Some(McpTransport::Url(url)),
        (None, None) => None,
    };
    let mcp_config = McpConfig {
        transport: transport.clone(),
        tool: args.mcp_tool,
        message_arg: args.mcp_message_arg,
    };

    let mcp_target = match &transport {
        Some(McpTransport::Stdio(cmd)) => format!("stdio: {cmd}"),
        Some(McpTransport::Url(url)) => format!("http: {url}"),
        None => "none (canned fallback)".to_string(),
    };
    let mut banner_lines = vec![
        "  Paste this code into the azula app to connect:".to_string(),
        String::new(),
        format!("    {ticket}"),
        String::new(),
        format!("  Short node id: {node_id}"),
        String::new(),
        "  Serving ALPNs:".to_string(),
    ];
    if !args.term_only {
        banner_lines.push(format!("    azula/llm/0   MCP relay  -> {mcp_target}"));
    }
    let session_ttl_desc = match session_ttl {
        Some(ttl) => format!("{} min", ttl.as_secs() / 60),
        None => "disabled (--session-ttl 0)".to_string(),
    };
    banner_lines.push(format!("    azula/term/0  remote shell (session ttl: {session_ttl_desc})"));
    endpoint::print_banner("azula server", &banner_lines);

    // Mint a signed 24h invite for the startup pairing QR instead of printing
    // the raw ticket, unless --legacy-ticket asks for the old behavior (or
    // minting fails, e.g. $HOME unset).
    let startup_invite = if args.legacy_ticket {
        None
    } else {
        let expiry = Expiry::In(std::time::Duration::from_secs(24 * 60 * 60));
        match invite::mint(&ticket, expiry, true, false, None, endpoint.secret_key()) {
            Ok((payload, _)) => Some(payload.encode()),
            Err(e) => {
                warn!(error = %e, "invite: failed to mint startup invite; falling back to raw ticket");
                None
            }
        }
    };
    match &startup_invite {
        Some(encoded) => qr::print_invite_pairing("Pair by scanning:", encoded),
        None => qr::print_pairing("Pair by scanning:", &ticket),
    }

    // Establish the shared upstream MCP session eagerly (when a transport flag
    // is set). A connect failure is non-fatal: log it and fall back to the
    // no-MCP responder so the iroh path stays usable.
    let mcp = match crate::mcp::connect(&mcp_config).await {
        Ok(handle) => handle,
        Err(e) => {
            warn!(error = %e, "mcp: eager connect failed; using canned fallback responder");
            None
        }
    };

    // A Router dispatches incoming connections by ALPN to the handlers. In
    // term-only mode we skip the LLM ALPN so a connecting client lands directly
    // in a terminal (the client keeps the highest-priority ALPN a peer accepts).
    let router = if args.term_only {
        info!("term-only mode: serving the remote shell, no LLM");
        Router::builder(endpoint)
            .accept(
                TERM_ALPN,
                TermHandler::new(node_id, args.allow_legacy, args.name.clone(), args.description.clone(), session_ttl),
            )
            .spawn()
    } else {
        Router::builder(endpoint)
            .accept(LLM_ALPN, LlmHandler::new(mcp, node_id, args.allow_legacy))
            .accept(
                TERM_ALPN,
                TermHandler::new(node_id, args.allow_legacy, args.name.clone(), args.description.clone(), session_ttl),
            )
            .spawn()
    };

    info!("serving — press Ctrl-C to stop");
    tokio::signal::ctrl_c().await?;
    info!("shutting down…");
    router.shutdown().await?;
    // A live persistent session's PTY-reader thread is parked in a blocking
    // read from a shell that's still running; #[tokio::main]'s runtime
    // (dropped when this function returns) would otherwise hang waiting for
    // that thread to join. Kill every session's shell so it unblocks.
    crate::term::kill_all_sessions();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certs::DeviceCert;
    use iroh::SecretKey;

    // Fixed, deterministic seeds -- same convention as certs.rs/sync.rs.
    fn seed(start: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = start.wrapping_add(i as u8);
        }
        s
    }

    fn make_cert(root: &SecretKey, device: &SecretKey) -> DeviceCert {
        let mut cert = DeviceCert {
            version: 1,
            flags: 0,
            root_pk: root.public(),
            device_pk: device.public(),
            issued_at: 1_767_225_600,
            expires_at: 0,
            name: "new-device".to_string(),
            signature: [0u8; 64],
        };
        cert.sign(root);
        cert
    }

    fn empty_bundle(root: &SecretKey) -> IdentityBundle {
        IdentityBundle {
            root_pk: root.public().to_string(),
            certs: vec![],
            revocations: vec![],
            contacts: vec![],
            mailbox: None,
        }
    }

    #[test]
    fn verify_granted_cert_accepts_a_valid_unrevoked_grant() {
        let root = SecretKey::from_bytes(&seed(0x01));
        let device = SecretKey::from_bytes(&seed(0x02));
        let cert = make_cert(&root, &device);
        let bundle = empty_bundle(&root);

        verify_granted_cert(&cert.encode(), device.public(), &bundle).expect("a valid, unrevoked grant passes");
    }

    #[test]
    fn verify_granted_cert_rejects_a_malformed_certificate() {
        let device = SecretKey::from_bytes(&seed(0x03));
        let bundle = empty_bundle(&SecretKey::from_bytes(&seed(0x04)));

        let err = verify_granted_cert("not-a-real-cert", device.public(), &bundle).unwrap_err();
        assert!(err.to_string().contains("malformed"), "{err}");
    }

    #[test]
    fn verify_granted_cert_rejects_a_cert_naming_a_different_device() {
        let root = SecretKey::from_bytes(&seed(0x05));
        let granted_device = SecretKey::from_bytes(&seed(0x06));
        let cert = make_cert(&root, &granted_device);
        let bundle = empty_bundle(&root);

        // Our own freshly generated device key differs from the cert's.
        let our_device_pk = SecretKey::from_bytes(&seed(0x07)).public();
        let err = verify_granted_cert(&cert.encode(), our_device_pk, &bundle).unwrap_err();
        assert!(err.to_string().contains("does not match"), "{err}");
    }

    #[test]
    fn verify_granted_cert_rejects_a_cert_already_revoked_in_the_bundle() {
        let root = SecretKey::from_bytes(&seed(0x08));
        let device = SecretKey::from_bytes(&seed(0x09));
        let cert = make_cert(&root, &device);

        let mut revocation = certs::Revocation {
            version: 1,
            root_pk: root.public(),
            device_pk: device.public(),
            revoked_at: 1_767_225_600,
            signature: [0u8; 64],
        };
        revocation.sign(&root);
        let mut bundle = empty_bundle(&root);
        bundle.revocations.push(revocation.encode());

        let err = verify_granted_cert(&cert.encode(), device.public(), &bundle).unwrap_err();
        assert!(err.to_string().contains("revoked"), "{err}");
    }
}
