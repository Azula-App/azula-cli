//! azula-demos — standalone demo binaries built on the `azula` library crate.
//!
//! * `demo-ui`   — dial a registered device and push a sample A2UI dice
//!   surface, for manual testing of the render → event → update loop.
//! * `blackjack` — spin up an A2UI Blackjack table; print a connect code and
//!   deal a hand to each app that connects.

mod blackjack;
mod demo;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "azula-demos", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Push a sample A2UI surface to a connected device for manual testing.
    DemoUi(DemoUiArgs),
    /// Spin up an A2UI Blackjack table; print a connect code and deal a hand to
    /// each app that connects.
    Blackjack,
}

/// Options for `azula-demos demo-ui`.
#[derive(Debug, Clone, clap::Args)]
struct DemoUiArgs {
    /// A registered device name, or a ticket / pairing URL to dial directly.
    device: String,

    /// Render the sample surface and exit without listening for events.
    #[arg(long)]
    once: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::DemoUi(args) => demo::run(args.device, args.once).await,
        Command::Blackjack => blackjack::run().await,
    }
}
