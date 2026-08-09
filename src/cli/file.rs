//! `azula file send`.

use anyhow::Result;

#[derive(Debug, Clone, clap::Args)]
pub(super) struct FileArgs {
    #[command(subcommand)]
    pub(super) action: FileAction,
}

#[derive(Debug, Clone, clap::Subcommand)]
pub(super) enum FileAction {
    /// Send a local file to a device as an inline attachment.
    Send(FileSendArgs),
}

#[derive(Debug, Clone, clap::Args)]
pub(super) struct FileSendArgs {
    #[command(flatten)]
    device: super::DeviceArg,
    #[command(flatten)]
    session: super::SessionArg,
    /// Path to the local file to send. Mime type is inferred from the
    /// extension. Files over 64 MiB are rejected. Requires a live
    /// connection — unlike `message send`, this is not queued for an
    /// offline device.
    path: std::path::PathBuf,
    /// Optional caption shown alongside the attachment in the app.
    #[arg(long)]
    caption: Option<String>,
    /// Machine-readable output.
    #[arg(long)]
    json: bool,
}

pub(super) async fn send(args: FileSendArgs, label: &super::SessionLabel) -> Result<()> {
    let session_name = super::resolve_cli_session_name(args.session.session.clone());
    let est =
        crate::core::establish("cli", vec![], label.name.clone(), label.description.clone(), Some(session_name)).await?;
    let core = est.core;
    let device = super::resolve_or_exit(&core, args.device.device.as_deref()).await;

    match core.send_file(&device, &args.path, args.caption).await {
        Ok(sent) => {
            if args.json {
                super::print_json(&serde_json::json!({
                    "status": "sent",
                    "device": device,
                    "name": sent.name,
                    "mime": sent.mime,
                    "size": sent.size,
                }));
            } else {
                println!("sent '{}' ({}, {} bytes) to '{}'", sent.name, sent.mime, sent.size, device);
            }
        }
        Err(e) => super::exit_core_error(&e),
    }
    Ok(())
}
