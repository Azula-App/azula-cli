//! `azula relay` — relay spec: "Relay Subsumes the Mailbox Role": `azula
//! relay` SHALL serve the always-on identity role previously provided by
//! `azula mailbox` (kept as an alias — `cli/legacy.rs`'s `cmd_mailbox`, owned
//! by a different phase, still calls the exact same [`mailbox_role::run`]).
//! This module is a thin clap layer over that shared implementation, same
//! shape as `cli/legacy.rs`'s `MailboxArgs`/`cmd_mailbox`.

use anyhow::Result;

use crate::mailbox_role;

/// Options for `azula relay`. Takes none — the invite gate is
/// unconditional since the legacy escape hatch was retired.
#[derive(Debug, Clone, clap::Args)]
pub(super) struct RelayArgs {}

pub(super) async fn cmd_relay(_args: RelayArgs) -> Result<()> {
    mailbox_role::run().await
}
