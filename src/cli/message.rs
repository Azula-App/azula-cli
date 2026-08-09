//! `azula message send|recv`.

use anyhow::Result;

#[derive(Debug, Clone, clap::Args)]
pub(super) struct MessageArgs {
    #[command(subcommand)]
    pub(super) action: MessageAction,
}

#[derive(Debug, Clone, clap::Subcommand)]
pub(super) enum MessageAction {
    /// Send a text message to a device (queues via the offline mailbox if unreachable).
    Send(MessageSendArgs),
    /// Drain (or long-poll for) inbound messages from a device.
    Recv(MessageRecvArgs),
}

#[derive(Debug, Clone, clap::Args)]
pub(super) struct MessageSendArgs {
    #[command(flatten)]
    device: super::DeviceArg,
    #[command(flatten)]
    session: super::SessionArg,
    /// The message text to send.
    text: String,
    /// Machine-readable output.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, clap::Args)]
pub(super) struct MessageRecvArgs {
    #[command(flatten)]
    device: super::DeviceArg,
    #[command(flatten)]
    session: super::SessionArg,
    /// Long-poll up to this many seconds for a reply instead of draining
    /// whatever's already queued.
    #[arg(long, value_name = "SECS")]
    wait: Option<u64>,
    /// Machine-readable output: one JSON object per drained/received line.
    #[arg(long)]
    json: bool,
}

pub(super) async fn send(args: MessageSendArgs, label: &super::SessionLabel) -> Result<()> {
    let session_name = super::resolve_cli_session_name(args.session.session.clone());
    let est =
        crate::core::establish("cli", vec![], label.name.clone(), label.description.clone(), Some(session_name)).await?;
    let core = est.core;
    let device = super::resolve_or_exit(&core, args.device.device.as_deref()).await;

    match core.send_message(&device, args.text).await {
        Ok(crate::core::SendOutcome::Sent) => {
            if args.json {
                super::print_json(&serde_json::json!({"status": "sent", "device": device}));
            } else {
                println!("ok");
            }
        }
        Ok(crate::core::SendOutcome::Queued) => {
            if args.json {
                super::print_json(&serde_json::json!({"status": "queued", "device": device}));
            } else {
                println!("queued for delivery to '{device}' (offline)");
            }
        }
        Err(e) => super::exit_core_error(&e),
    }
    Ok(())
}

pub(super) async fn recv(args: MessageRecvArgs, label: &super::SessionLabel) -> Result<()> {
    let session_name = super::resolve_cli_session_name(args.session.session.clone());
    let est =
        crate::core::establish("cli", vec![], label.name.clone(), label.description.clone(), Some(session_name)).await?;
    let core = est.core;

    match args.wait {
        Some(secs) => {
            let device = super::resolve_or_exit(&core, args.device.device.as_deref()).await;
            match core.wait_for_reply(&device, secs).await {
                Ok(crate::core::WaitOutcome::Lines(lines)) => print_lines(&device, lines, args.json),
                Ok(crate::core::WaitOutcome::TimedOut) => {
                    if args.json {
                        super::print_json(&serde_json::json!({"status": "timeout", "device": device}));
                    } else {
                        println!("(no reply within {secs}s)");
                    }
                }
                Err(e) => super::exit_core_error(&e),
            }
        }
        None => match core.get_messages(args.device.device.as_deref()).await {
            Ok(lines) if lines.is_empty() => {
                if !args.json {
                    println!("(no new messages)");
                }
            }
            Ok(lines) => {
                for line in lines {
                    if args.json {
                        super::print_json(&serde_json::json!({"device": line.device, "text": line.text}));
                    } else {
                        println!("\u{300a}{}\u{300b} {}", line.device, line.text);
                    }
                }
            }
            Err(e) => super::exit_core_error(&e),
        },
    }
    Ok(())
}

fn print_lines(device: &str, lines: Vec<String>, json: bool) {
    for text in lines {
        if json {
            super::print_json(&serde_json::json!({"device": device, "text": text}));
        } else {
            println!("\u{300a}{device}\u{300b} {text}");
        }
    }
}
