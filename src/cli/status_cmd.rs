//! `azula status` — machine identity, known devices, and local sessions,
//! read from disk (no endpoint bound — see `core::status`).

use anyhow::Result;

#[derive(Debug, Clone, clap::Args)]
pub(super) struct StatusArgs {
    /// Machine-readable output: `{"machine_identity":{...},"devices":[...],
    /// "sessions":[...]}`.
    #[arg(long)]
    json: bool,
}

pub(super) fn run(args: StatusArgs) -> Result<()> {
    let report = crate::core::status::compute();
    if args.json {
        super::print_json(&report);
    } else {
        print!("{}", crate::core::status::render_human(&report));
    }
    Ok(())
}
