//! `azula relay` — relay spec: "Relay Subsumes the Mailbox Role": `azula
//! relay` SHALL serve the always-on identity role previously provided by
//! `azula mailbox` (kept as an alias — `cli/legacy.rs`'s `cmd_mailbox`, owned
//! by a different phase, still calls the exact same [`mailbox_role::run`]).
//! This module is a thin clap layer over that shared implementation, same
//! shape as `cli/legacy.rs`'s `MailboxArgs`/`cmd_mailbox`.

use anyhow::Result;

use crate::mailbox_role;

/// Options for `azula relay`.
#[derive(Debug, Clone, clap::Args)]
pub(super) struct RelayArgs {
    /// Admit invite-less unverified strangers instead of closing the
    /// connection (same convention as `serve`/`serve-mcp`/`mailbox`).
    #[arg(long = "allow-legacy", default_value_t = true, action = clap::ArgAction::Set)]
    pub(super) allow_legacy: bool,
}

pub(super) async fn cmd_relay(args: RelayArgs) -> Result<()> {
    mailbox_role::run(args.allow_legacy).await
}
