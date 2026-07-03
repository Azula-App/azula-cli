//! `demo-ui` — push a sample A2UI surface to a connected device for quick
//! manual testing of the render → event → update loop, without needing an MCP
//! client. Dials the device on the LLM ALPN (the same channel `serve-mcp`
//! uses), renders a dice surface, and — unless `--once` — listens for the
//! user's taps and re-rolls in response.

use std::time::Duration;

use anyhow::Result;
use iroh::endpoint::presets;
use iroh::Endpoint;
use iroh_tickets::endpoint::EndpointTicket;
use serde_json::{json, Value};
use tokio::io::BufReader;

use azula::mcp::LLM_ALPN;
use azula::proto::{read_frame, write_frame, Frame};
use azula::{link, registry};

const DICE: [&str; 6] = ["⚀", "⚁", "⚂", "⚃", "⚄", "⚅"];
const SURFACE_ID: &str = "demo-dice";
const CATALOG: &str = "https://a2ui.org/specification/v0_9_1/catalogs/basic/catalog.json";

pub async fn run(device: String, once: bool) -> Result<()> {
    // Resolve a registered device name first; otherwise treat the arg as a
    // ticket / pairing URL in any form `azula pair` accepts.
    let ticket = registry::load()
        .into_iter()
        .find(|d| d.name == device)
        .map(|d| d.ticket)
        .or_else(|| link::parse_ticket(&device))
        .ok_or_else(|| {
            anyhow::anyhow!("'{device}' is not a known device name or a valid ticket/URL")
        })?;

    // Validate the ticket before binding an endpoint, so bad input fails fast
    // with a clear message (and doesn't leave a dangling endpoint).
    use std::str::FromStr;
    let addr = EndpointTicket::from_str(&ticket)
        .map_err(|_| {
            anyhow::anyhow!("'{device}' didn't resolve to a known device or a valid azula ticket")
        })?
        .endpoint_addr()
        .clone();

    let endpoint = Endpoint::bind(presets::N0).await?;
    println!("bringing endpoint online…");
    endpoint.online().await;

    println!("dialing device '{device}'…");
    let conn = endpoint.connect(addr, LLM_ALPN).await?;
    // The dialer writes first (the app accepts the bi stream on its side).
    let (mut send, recv) = conn.open_bi().await?;
    write_frame(&mut send, &Frame::thinking(false)).await?;

    for msg in dice_surface_messages() {
        write_frame(&mut send, &Frame::A2ui { message: msg }).await?;
    }
    println!("✓ rendered surface '{SURFACE_ID}' in the device's azula conversation.");

    if once {
        // Give QUIC a moment to flush before the endpoint drops.
        tokio::time::sleep(Duration::from_millis(800)).await;
        return Ok(());
    }

    println!("listening for taps — press the ROLL button in the app (Ctrl-C to quit).");
    let mut reader = BufReader::new(recv);
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => { println!("\nbye"); break; }
            frame = read_frame(&mut reader) => match frame {
                Ok(Some(Frame::A2uiAction { action })) => {
                    println!("ui-event: {}", serde_json::to_string(&action).unwrap_or_default());
                    let name = action.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    if name == "roll" {
                        let (a, b) = roll_two();
                        let result = match a.cmp(&b) {
                            std::cmp::Ordering::Greater => "you win 🏆",
                            std::cmp::Ordering::Less => "device wins",
                            std::cmp::Ordering::Equal => "tie — roll again",
                        };
                        for (path, value) in [
                            ("/dice/you", json!(DICE[a])),
                            ("/dice/them", json!(DICE[b])),
                            ("/dice/result", json!(result)),
                        ] {
                            write_frame(&mut send, &Frame::A2ui {
                                message: json!({
                                    "version": "v0.9.1",
                                    "updateDataModel": { "surfaceId": SURFACE_ID, "path": path, "value": value }
                                }),
                            })
                            .await?;
                        }
                        println!("  → rolled {} vs {}: {result}", a + 1, b + 1);
                    }
                }
                Ok(Some(_)) => {}
                Ok(None) => { println!("device closed the stream"); break; }
                Err(e) => { eprintln!("read error: {e}"); break; }
            }
        }
    }
    Ok(())
}

/// The A2UI messages that build the dice surface (mirrors the app's built-in
/// dice example so it renders identically).
fn dice_surface_messages() -> Vec<Value> {
    let components = json!([
        { "id": "root",    "component": "Card",   "child": "col" },
        { "id": "col",     "component": "Column", "children": ["title", "faces", "result", "rollBtn"], "align": "center" },
        { "id": "title",   "component": "Text",   "text": "AZULA · DICE", "variant": "caption" },
        { "id": "faces",   "component": "Row",    "children": ["you", "vs", "them"], "justify": "center", "align": "center" },
        { "id": "you",     "component": "Text",   "text": { "path": "/dice/you" },  "variant": "h1" },
        { "id": "vs",      "component": "Text",   "text": "vs", "variant": "body" },
        { "id": "them",    "component": "Text",   "text": { "path": "/dice/them" }, "variant": "h1" },
        { "id": "result",  "component": "Text",   "text": { "path": "/dice/result" }, "variant": "body" },
        { "id": "rollL",   "component": "Text",   "text": "ROLL" },
        { "id": "rollBtn", "component": "Button", "child": "rollL", "variant": "primary",
          "action": { "event": { "name": "roll" } } }
    ]);
    vec![
        json!({ "version": "v0.9.1", "createSurface": { "surfaceId": SURFACE_ID, "catalogId": CATALOG } }),
        json!({ "version": "v0.9.1", "updateComponents": { "surfaceId": SURFACE_ID, "components": components } }),
        json!({ "version": "v0.9.1", "updateDataModel": {
            "surfaceId": SURFACE_ID, "path": "",
            "value": { "dice": { "you": "?", "them": "?", "result": "tap ROLL" } }
        } }),
    ]
}

/// Two dice indices (0..=5) seeded from the wall clock — good enough for a demo
/// (no `rand` dependency). The two values use different mixes so they decorrelate.
fn roll_two() -> (usize, usize) {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let a = ((n.wrapping_mul(2654435761) >> 16) % 6) as usize;
    let b = ((n.wrapping_mul(40503).wrapping_add(0x9E37_79B9) >> 8) % 6) as usize;
    (a, b)
}
