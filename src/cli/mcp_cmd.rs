//! `azula mcp` — the noun-verb MCP entry point: stdio by default,
//! `--http BIND` for the old `serve-mcp` HTTP transport (cli-surface spec:
//! "`azula mcp [--http BIND] [--session NAME] [--device URL]... [--name N]
//! [--max-turns N]` — stdio by default; `--http` replaces `serve-mcp`").
//!
//! This is a clap-args-only module — the actual server stand-up
//! (`bridge::run` / `bridge::run_stdio`, built on `core::establish`) is
//! unchanged and lives in `crate::bridge`.

use anyhow::Result;

/// Options for `azula mcp` (stdio by default; `--http` for the HTTP transport).
#[derive(Debug, Clone, clap::Args)]
pub(super) struct McpArgs {
    /// Serve MCP over Streamable HTTP on this address (path is /mcp) instead
    /// of stdio. Replaces the old `serve-mcp` command.
    #[arg(long, env = "AZULA_MCP_BIND", value_name = "BIND")]
    pub(super) http: Option<String>,

    /// A device ticket URL to connect to (repeatable). Each value is a URL or
    /// bare ticket in any form accepted by `azula pair`.
    #[arg(long = "device", value_name = "URL", action = clap::ArgAction::Append)]
    pub(super) device: Option<Vec<String>>,

    /// Display name for this session (sent as `hello` to peer bridges/the app
    /// so they can identify it by name). Defaults to "Claude" over stdio, or
    /// `bridge-<first 8 chars of endpoint id>` over `--http`.
    #[arg(long, value_name = "NAME")]
    pub(super) name: Option<String>,

    /// Hard per-peer turn cap for bridge-to-bridge `say` conversations. Once
    /// either side reaches this many turns the conversation is closed.
    #[arg(long = "max-turns", value_name = "N", default_value_t = 20)]
    pub(super) max_turns: u64,

    /// Admit invite-less unknown strangers as unverified pending devices
    /// instead of closing the connection. Transition escape hatch — default
    /// on for one release, then off (see azula-docs/openspec/specs/invitations/design.md).
    #[arg(long = "allow-legacy", default_value_t = true, action = clap::ArgAction::Set)]
    pub(super) allow_legacy: bool,

    /// Print the raw dial ticket in the startup pairing output instead of
    /// minting a signed 24h invite.
    #[arg(long = "legacy-ticket")]
    pub(super) legacy_ticket: bool,

    /// Use a persistent named session (key at `~/.azula/sessions/<name>.key`)
    /// instead of a fresh ephemeral one for this process — repeated
    /// invocations with the same name land in the same phone conversation.
    /// Also settable via `AZULA_SESSION`.
    #[arg(long, env = "AZULA_SESSION", value_name = "NAME")]
    pub(super) session: Option<String>,
}

pub(super) async fn run(args: McpArgs) -> Result<()> {
    let devices = args.device.clone().unwrap_or_default();
    // Preserve each pre-restructure command's own default: stdio (the old
    // `mcp`) defaulted the announced name to "Claude"; `--http` (the old
    // `serve-mcp`) had no default, falling back to `bridge-<endpoint id>` inside
    // `core::establish`.
    let name = args.name.clone().or_else(|| if args.http.is_none() { Some("Claude".to_string()) } else { None });

    match args.http {
        Some(bind) => {
            crate::bridge::run(bind, devices, name, args.max_turns, args.allow_legacy, args.legacy_ticket, args.session).await
        }
        None => crate::bridge::run_stdio(devices, name, args.max_turns, args.allow_legacy, args.legacy_ticket, args.session).await,
    }
}

// ---------------------------------------------------------------------------
// Deprecated alias: `azula serve-mcp` -> `azula mcp --http`
// ---------------------------------------------------------------------------

/// Options for the deprecated `serve-mcp` alias — kept identical to the
/// pre-restructure `ServeMcpArgs` shape so existing invocations keep working
/// unmodified.
#[derive(Debug, Clone, clap::Args)]
pub(super) struct ServeMcpArgs {
    /// Address to serve the MCP-over-HTTP endpoint on (path is /mcp).
    #[arg(long, env = "AZULA_MCP_BIND", default_value = "127.0.0.1:8765")]
    bind: String,

    #[arg(long = "device", value_name = "URL", action = clap::ArgAction::Append)]
    device: Option<Vec<String>>,

    #[arg(long, value_name = "NAME")]
    name: Option<String>,

    #[arg(long = "max-turns", value_name = "N", default_value_t = 20)]
    max_turns: u64,

    #[arg(long = "allow-legacy", default_value_t = true, action = clap::ArgAction::Set)]
    allow_legacy: bool,

    #[arg(long = "legacy-ticket")]
    legacy_ticket: bool,

    #[arg(long, env = "AZULA_SESSION", value_name = "NAME")]
    session: Option<String>,
}

pub(super) async fn run_serve_mcp_alias(args: ServeMcpArgs) -> Result<()> {
    super::print_deprecation_notice("serve-mcp", "azula mcp --http <bind>");
    crate::bridge::run(args.bind, args.device.unwrap_or_default(), args.name, args.max_turns, args.allow_legacy, args.legacy_ticket, args.session).await
}
