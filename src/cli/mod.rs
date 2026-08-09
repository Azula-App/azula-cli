//! The `azula` CLI: noun-verb command taxonomy (`message`, `ui`, `file`,
//! `watch`, `status`, `mcp`) plus the existing `pair`/`devices`/`qr`/
//! `invite`/`invites`/`link` and, hidden, the deprecated `serve`/
//! `serve-mcp`/`mailbox` aliases — `azula-docs/openspec/changes/
//! cli-multi-session-relay/specs/cli-surface/spec.md`.
//!
//! Every one-shot verb (`message`, `ui`, `file`, `watch`, `status`) is a thin
//! clap layer over [`crate::core::SessionCore`] — the same core the MCP tool
//! surface (`crate::bridge::tools::AzulaBridge`) uses ("CLI and MCP Share One
//! Core"). `run` (`run_cmd`) and `terminal` (`terminal_cmd`) are D5: they
//! build their own dedicated `TermHandler`/`Router` the way `azula serve`
//! does rather than going through `SessionCore` — see their module docs.
//! `relay` (`relay_cmd`, D6) is likewise additive to the `Command` enum
//! below.

mod file;
mod legacy;
mod mcp_cmd;
mod run_cmd;
mod terminal_cmd;
mod message;
mod status_cmd;
mod ui;
mod watch_cmd;
mod relay_cmd;

use anyhow::Result;
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};

use crate::core::SessionCore;

/// Command-line interface.
#[derive(Debug, Parser)]
#[command(name = "azula", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    session: SessionLabel,

    #[command(flatten)]
    serve: legacy::ServeArgs,
}

/// How this invocation's session identifies itself to a device.
///
/// Written before the subcommand (`azula --name deploy message send …`), and
/// deliberately *not* a clap global: `pair` and `link` define their own
/// `--name` meaning a different noun, and propagating a same-named global into
/// them would make an established invocation ambiguous.
///
/// These used to live on [`legacy::ServeArgs`], which the root flattens — so
/// clap accepted them for every subcommand while only the bare-`azula` branch
/// ever read them, and every other verb discarded them in silence. Anything
/// that can't apply them now says so; see [`reject_session_label`].
#[derive(Debug, Clone, clap::Args)]
pub(super) struct SessionLabel {
    /// Override the name this session announces to the app (sent as
    /// `Frame::Hello`/`Frame::Profile.name`, and used as the conversation
    /// title). Defaults to this machine's hostname when serving, or
    /// `bridge-<endpoint id>` for a one-shot verb.
    #[arg(long, value_name = "NAME")]
    pub(super) name: Option<String>,

    /// Override the description this session announces to the app (sent as
    /// `Frame::Profile.description`, becomes the conversation sub-line).
    /// Defaults to the shell's launch working directory when serving.
    #[arg(long, value_name = "DESCRIPTION")]
    pub(super) description: Option<String>,
}

impl SessionLabel {
    fn is_set(&self) -> bool {
        self.name.is_some() || self.description.is_some()
    }
}

/// Refuse a session label on a verb that opens no session.
///
/// Accepting a flag and throwing it away is the defect this change exists to
/// fix; a verb that can't honour one owes the user an error instead.
fn reject_session_label(label: &SessionLabel, verb: &str) -> Result<()> {
    if !label.is_set() {
        return Ok(());
    }
    let flag = if label.name.is_some() { "--name" } else { "--description" };
    anyhow::bail!(
        "`{flag}` labels the session a device sees, and `azula {verb}` opens none.\n\
         Drop it, or see `azula {verb} --help` — some verbs take a `--name` of their own."
    )
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the MCP↔iroh server: stdio by default, or Streamable HTTP with
    /// `--http` (replaces `serve-mcp`).
    Mcp(mcp_cmd::McpArgs),

    /// Run a command in a PTY, handing off to an interactive shell in the
    /// same session on failure (or always/never) so a phone or `azula
    /// terminal attach` can pick up where it left off.
    Run(run_cmd::RunArgs),
    /// Host, manage, or attach to persistent terminal sessions: bare `azula
    /// terminal` hosts one inline; `new`/`list`/`kill` manage detached
    /// background hosts; `attach <name|url>` is the CLI client.
    Terminal(terminal_cmd::TerminalArgs),

    /// Send or receive chat-style messages with a device.
    Message(message::MessageArgs),
    /// Render, update, or delete an A2UI surface, or print the component catalog.
    Ui(ui::UiArgs),
    /// Send a local file to a device.
    File(file::FileArgs),
    /// Follow a device's inbox: messages, A2UI events, files, connect/disconnect.
    Watch(watch_cmd::WatchArgs),
    /// Show machine identity, known devices, and local sessions.
    Status(status_cmd::StatusArgs),

    /// Serve the identity's always-on relay role: store-and-forward for
    /// agent chat and A2UI snapshots when a session can't reach the phone
    /// directly, plus the identity log sync/bootstrap role `azula mailbox`
    /// (kept as an alias) has always served.
    Relay(relay_cmd::RelayArgs),

    /// Pair a new device: save its ticket to the registry.
    Pair(legacy::PairArgs),
    /// List all registered devices and their registry source.
    Devices {
        /// Machine-readable output: a JSON array of
        /// `{name,fingerprint,source,relay}`.
        #[arg(long)]
        json: bool,
    },
    /// Print a QR code for a ticket, URL, or bare token.
    Qr(legacy::QrArgs),
    /// Mint a new invite (or, with `revoke`, delete a previously issued one).
    Invite(legacy::InviteCliArgs),
    /// List all invites this endpoint has issued.
    Invites,
    /// Link this CLI as a new device of an existing multi-device identity:
    /// print an `azl…` QR/string for a root-holding device to scan, then
    /// wait for it to grant a certificate.
    Link(legacy::LinkArgs),

    // --- Deprecated aliases (cli-surface spec: kept one release, hidden
    // from --help, each prints a stderr notice then delegates). ---
    /// Deprecated: use the bare `azula` invocation or a future `azula terminal`.
    #[command(hide = true)]
    Serve(legacy::ServeArgs),
    /// Deprecated: use `azula mcp --http <bind>`.
    #[command(hide = true)]
    ServeMcp(mcp_cmd::ServeMcpArgs),
    /// Deprecated: use the same command; kept as an explicit alias name.
    #[command(hide = true)]
    Mailbox(legacy::MailboxArgs),
}

// ---------------------------------------------------------------------------
// Shared per-verb argument fragments
// ---------------------------------------------------------------------------

/// `--device NAME`, flattened into every one-shot verb. cli-surface spec:
/// "`--device D` matches a registry device by name; with exactly one
/// registered device it may be omitted (defaulting to it); error listing
/// candidates otherwise" — see [`resolve_or_exit`]/`SessionCore::
/// resolve_target_device`.
#[derive(Debug, Clone, clap::Args)]
struct DeviceArg {
    #[arg(long = "device", value_name = "NAME")]
    device: Option<String>,
}

/// `--session NAME` (also `AZULA_SESSION`), flattened into every one-shot
/// verb. Unset resolves to the shared `cli` persistent session (design.md
/// D2) via [`resolve_cli_session_name`], never an ephemeral one.
#[derive(Debug, Clone, clap::Args)]
struct SessionArg {
    #[arg(long, env = "AZULA_SESSION", value_name = "NAME")]
    session: Option<String>,
}

/// One-shot CLI verbs default to the persistent `cli` session (design.md D2:
/// "One-shot CLI verbs (`message`, `ui`, `watch`): session name `cli`... NOT
/// ephemeral") unless `--session`/`AZULA_SESSION` names one explicitly. Pure
/// and side-effect-free so it's directly unit-testable without binding an
/// endpoint.
fn resolve_cli_session_name(explicit: Option<String>) -> String {
    explicit.unwrap_or_else(|| "cli".to_string())
}

/// Resolve `--device` against `core`'s known devices, exiting the process
/// (usage error, exit code 2) if it's missing/ambiguous or names an unknown
/// device — the shared behavior every device-targeting one-shot verb needs.
async fn resolve_or_exit(core: &SessionCore, requested: Option<&str>) -> String {
    match core.resolve_target_device(requested).await {
        Ok(d) => d,
        Err(e) => exit_core_error(&e),
    }
}

/// Print `e`'s message to stderr and exit with its cli-surface-spec exit
/// code (`2` usage/validation, `1` operational failure).
fn exit_core_error(e: &crate::core::CoreError) -> ! {
    eprintln!("error: {e}");
    std::process::exit(e.exit_code());
}

/// Print one JSON value as a single line to stdout (`--json` output), or a
/// clear error to stderr (exit 1) if it somehow fails to serialize.
fn print_json<T: serde::Serialize>(value: &T) {
    match serde_json::to_string(value) {
        Ok(line) => println!("{line}"),
        Err(e) => {
            eprintln!("error: failed to serialize JSON output: {e}");
            std::process::exit(1);
        }
    }
}

/// Print a one-line stderr deprecation notice for a hidden legacy alias —
/// cli-surface spec: "prints a deprecation notice to stderr" — before
/// delegating to the replacement's behavior.
fn print_deprecation_notice(old: &str, new: &str) {
    eprintln!("warning: `azula {old}` is deprecated and will be removed in a future release; use `{new}` instead.");
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Build the top-level `clap::Command`, attaching the full A2UI catalog to
/// `azula ui render --help`'s long form. `#[command(long_about = "...")]`
/// only accepts a string literal (same constraint as the MCP tool
/// description — see `catalog`'s module docs), so the catalog text is
/// attached here programmatically instead of duplicating it into the
/// attribute.
fn build_command() -> clap::Command {
    let cmd = Cli::command();
    cmd.mut_subcommand("ui", |ui_cmd| {
        ui_cmd.mut_subcommand("render", |render_cmd| {
            render_cmd.long_about(format!(
                "Render an A2UI declarative surface on a device. Components JSON comes from FILE or stdin (`-`).\n\n{}",
                crate::catalog::A2UI_CATALOG
            ))
        })
    })
}

/// Parse `std::env::args()` and dispatch to the matching command. The single
/// entry point `main.rs` calls.
pub async fn run() -> Result<()> {
    let matches = build_command().get_matches();
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    dispatch(cli).await
}

async fn dispatch(cli: Cli) -> Result<()> {
    let label = cli.session;
    match cli.command {
        Some(Command::Mcp(args)) => mcp_cmd::run(args).await,

        Some(Command::Run(args)) => std::process::exit(run_cmd::run(args).await),
        Some(Command::Terminal(args)) => terminal_cmd::run(args).await,

        Some(Command::Message(args)) => match args.action {
            message::MessageAction::Send(a) => message::send(a, &label).await,
            message::MessageAction::Recv(a) => message::recv(a, &label).await,
        },
        Some(Command::Ui(args)) => match args.action {
            ui::UiAction::Render(a) => ui::render(a, &label).await,
            ui::UiAction::Update(a) => ui::update(a, &label).await,
            ui::UiAction::Delete(a) => ui::delete(a, &label).await,
            ui::UiAction::Catalog(a) => {
                reject_session_label(&label, "ui catalog")?;
                ui::catalog(a)
            }
        },
        Some(Command::File(args)) => match args.action {
            file::FileAction::Send(a) => file::send(a, &label).await,
        },
        Some(Command::Watch(args)) => watch_cmd::run(args, &label).await,
        Some(Command::Status(args)) => {
            reject_session_label(&label, "status")?;
            status_cmd::run(args)
        }
        Some(Command::Relay(args)) => relay_cmd::cmd_relay(args).await,

        Some(Command::Pair(args)) => {
            reject_session_label(&label, "pair")?;
            legacy::cmd_pair(args)
        }
        Some(Command::Devices { json }) => {
            reject_session_label(&label, "devices")?;
            legacy::cmd_devices(json)
        }
        Some(Command::Qr(args)) => {
            reject_session_label(&label, "qr")?;
            legacy::cmd_qr(args)
        }
        Some(Command::Invite(args)) => {
            reject_session_label(&label, "invite")?;
            match args.action {
                Some(legacy::InviteAction::Revoke(r)) => legacy::cmd_invite_revoke(r),
                None => legacy::cmd_invite_mint(args.mint).await,
            }
        }
        Some(Command::Invites) => {
            reject_session_label(&label, "invites")?;
            legacy::cmd_invites()
        }
        Some(Command::Link(args)) => {
            reject_session_label(&label, "link")?;
            legacy::cmd_link(args).await
        }

        Some(Command::Serve(args)) => {
            print_deprecation_notice("serve", "azula (bare invocation), or a future `azula terminal`");
            legacy::serve(args, &label).await
        }
        Some(Command::ServeMcp(args)) => mcp_cmd::run_serve_mcp_alias(args).await,
        Some(Command::Mailbox(args)) => {
            print_deprecation_notice("mailbox", "azula relay");
            legacy::cmd_mailbox(args).await
        }

        // Bare `azula` (no subcommand): unchanged pre-restructure default —
        // no deprecation notice, since nothing named "serve" was typed.
        None => legacy::serve(cli.serve, &label).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(argv: &[&str]) -> Cli {
        Cli::from_arg_matches(&build_command().get_matches_from(argv)).expect("parse")
    }

    /// The defect: `--name` parsed at the root (it was flattened in from
    /// `ServeArgs`) and then every subcommand dropped it on the floor. It has
    /// to reach the verb now.
    #[test]
    fn session_label_before_a_subcommand_reaches_the_verb() {
        let cli = parse(&["azula", "--name", "deploy", "--description", "prod push", "message", "send", "hi"]);
        assert_eq!(cli.session.name.as_deref(), Some("deploy"));
        assert_eq!(cli.session.description.as_deref(), Some("prod push"));
        assert!(matches!(cli.command, Some(Command::Message(_))));
    }

    /// `pair --name` names *the device being paired* — a different noun from
    /// the session label. Promoting the globals must not have changed it,
    /// which is why `SessionLabel` is not a clap global.
    #[test]
    fn pair_keeps_its_own_name_option() {
        let cli = parse(&["azula", "pair", "https://azula.app/i/abc", "--name", "my-phone"]);
        assert!(cli.session.name.is_none(), "must not bind to the session label");
        match cli.command {
            Some(Command::Pair(args)) => assert_eq!(args.name.as_deref(), Some("my-phone")),
            other => panic!("expected pair, got {other:?}"),
        }
    }

    #[test]
    fn bare_invocation_still_takes_the_label() {
        let cli = parse(&["azula", "--name", "laptop"]);
        assert!(cli.command.is_none(), "bare azula still serves");
        assert_eq!(cli.session.name.as_deref(), Some("laptop"));
    }

    #[test]
    fn a_verb_that_opens_no_session_rejects_the_label() {
        let label = SessionLabel { name: Some("deploy".into()), description: None };
        let err = reject_session_label(&label, "devices").expect_err("must reject");
        assert!(err.to_string().contains("--name"), "names the offending flag: {err}");
        assert!(err.to_string().contains("devices"), "names the verb: {err}");
    }

    #[test]
    fn an_unset_label_is_never_rejected() {
        let label = SessionLabel { name: None, description: None };
        assert!(reject_session_label(&label, "devices").is_ok());
    }

    #[test]
    fn explicit_session_flag_wins_over_the_cli_default() {
        assert_eq!(resolve_cli_session_name(Some("blackjack".to_string())), "blackjack");
    }

    #[test]
    fn one_shot_verbs_default_to_the_shared_cli_session() {
        // design.md D2: message/ui/file/watch/status default to the
        // persistent `cli` session, never an ephemeral one — unlike `azula
        // mcp`, which passes `None` straight through to `SessionKey::resolve`
        // and gets a fresh ephemeral session per process.
        assert_eq!(resolve_cli_session_name(None), "cli");
    }

    #[test]
    fn command_tree_builds_without_panicking() {
        // `mut_subcommand("ui", ...)`/`mut_subcommand("render", ...)` panic
        // if those subcommand names ever drift from the enum variant names
        // clap derives them from — this is the trip wire.
        let cmd = build_command();
        cmd.debug_assert();
    }

    #[test]
    fn ui_render_help_carries_the_a2ui_catalog() {
        let cmd = build_command();
        let render = cmd
            .find_subcommand("ui")
            .and_then(|ui| ui.find_subcommand("render"))
            .expect("ui render subcommand exists");
        let long_about = render.get_long_about().map(|s| s.to_string()).unwrap_or_default();
        assert!(long_about.contains("STRUCTURE:"), "expected the A2UI catalog in `ui render`'s long_about");
    }
}
