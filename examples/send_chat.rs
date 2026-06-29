//! Dial an azula app peer by its endpoint ticket and send a chat message.
//!
//! Usage: cargo run --example send_chat -- "<ticket>" "<message...>"
//!
//! Connects on the peer ("zuko") chat ALPN and writes a `hello` then a `chat`
//! frame (newline-delimited JSON), which the app shows as an incoming message.

use std::str::FromStr;

use anyhow::{bail, Context, Result};
use iroh::endpoint::presets;
use iroh::Endpoint;
use iroh_tickets::endpoint::EndpointTicket;
use tokio::io::AsyncWriteExt;

const CHAT_ALPN: &[u8] = b"azula/chat/0";

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let ticket = args.next().context("usage: send_chat <ticket> <message...>")?;
    let message = args.collect::<Vec<_>>().join(" ");
    if message.is_empty() {
        bail!("usage: send_chat <ticket> <message...>");
    }

    let endpoint = Endpoint::bind(presets::N0).await?;
    eprintln!("bound endpoint {}", endpoint.id());

    // Make sure our own relay/discovery is up before dialing (bounded).
    let _ = tokio::time::timeout(std::time::Duration::from_secs(15), endpoint.online()).await;
    eprintln!("online");

    let ticket = EndpointTicket::from_str(ticket.trim())?;
    let addr = ticket.endpoint_addr().clone();

    let hello = serde_json::json!({ "type": "hello", "name": "Claude" }).to_string();
    let chat = serde_json::json!({ "type": "chat", "text": message }).to_string();

    // iroh has no offline store: the peer must be online when we connect. Retry
    // until the phone's app is foreground/bound (or we hit the deadline), so the
    // message lands the moment it reconnects.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15 * 60);
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        eprintln!("[{attempt}] dialing {} on {}…", addr.id, String::from_utf8_lossy(CHAT_ALPN));
        let attempt_res = tokio::time::timeout(std::time::Duration::from_secs(12), async {
            let conn = endpoint.connect(addr.clone(), CHAT_ALPN).await?;
            let (mut send, _recv) = conn.open_bi().await?;
            send.write_all(format!("{hello}\n").as_bytes()).await?;
            send.write_all(format!("{chat}\n").as_bytes()).await?;
            send.flush().await?;
            // Let the app read and render before we tear the connection down.
            tokio::time::sleep(std::time::Duration::from_secs(4)).await;
            let _ = send.finish();
            anyhow::Ok(())
        })
        .await;

        match attempt_res {
            Ok(Ok(())) => {
                eprintln!("delivered: {chat}");
                break;
            }
            Ok(Err(e)) => eprintln!("[{attempt}] send failed: {e}"),
            Err(_) => eprintln!("[{attempt}] connect timed out (phone offline?)"),
        }

        if tokio::time::Instant::now() >= deadline {
            endpoint.close().await;
            anyhow::bail!("gave up after {attempt} attempts — phone never came online");
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }

    endpoint.close().await;
    eprintln!("done");
    Ok(())
}
