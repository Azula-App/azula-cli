//! `serve-mcp` — the MCP↔iroh bridge.
//!
//! This is the inverse of `serve`'s LLM channel. It runs an **MCP server** over
//! Streamable HTTP that an external LLM client connects to (the public face of
//! `https://azula.app/mcp/<token>`), and bridges that LLM to a running Azula app
//! **over iroh**: it dials the app on the `azula/llm/0` ALPN using the app's
//! ticket, then exposes two tools — `get_messages` (read what the user typed in
//! the app's azula conversation) and `send_message` (reply, rendered as the
//! streamed azula-assistant message in the app).
//!
//! v1 is one session per process (one `--app-ticket`); multi-tenant routing by
//! token is future work (see site/URLS.md).

use std::collections::VecDeque;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Result;
use iroh::endpoint::{presets, RecvStream, SendStream};
use iroh::Endpoint;
use iroh_tickets::endpoint::EndpointTicket;
use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, ServerCapabilities, ServerInfo};
use rmcp::schemars;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::StreamableHttpService;
use rmcp::{tool, tool_handler, tool_router, ErrorData, ServerHandler};
use tokio::io::BufReader;
use tokio::sync::Mutex as AsyncMutex;
use tracing::{info, warn};

use crate::mcp::LLM_ALPN;
use crate::proto::{read_frame, write_frame, Frame};

type Inbox = Arc<std::sync::Mutex<VecDeque<String>>>;
type AppSend = Arc<AsyncMutex<Option<SendStream>>>;

#[derive(serde::Deserialize, schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
struct SendArgs {
    /// The text to deliver to the user in the azula app.
    text: String,
}

/// MCP server handler bridging an LLM client to the Azula app over iroh.
#[derive(Clone)]
pub struct Bridge {
    inbox: Inbox,
    app_send: AppSend,
    // Used by the #[tool_handler] macro; dead-code analysis can't see that.
    #[allow(dead_code)]
    tool_router: ToolRouter<Bridge>,
}

#[tool_router]
impl Bridge {
    fn new(inbox: Inbox, app_send: AppSend) -> Self {
        Self { inbox, app_send, tool_router: Self::tool_router() }
    }

    #[tool(description = "Read new messages the user typed in the azula app's assistant conversation. Drains the queue.")]
    async fn get_messages(&self) -> Result<CallToolResult, ErrorData> {
        let msgs: Vec<String> = {
            let mut q = self.inbox.lock().unwrap();
            q.drain(..).collect()
        };
        let text = if msgs.is_empty() { "(no new messages)".to_string() } else { msgs.join("\n") };
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }

    #[tool(description = "Send a reply to the user; it appears as the streamed azula-assistant message in the app.")]
    async fn send_message(&self, Parameters(args): Parameters<SendArgs>) -> Result<CallToolResult, ErrorData> {
        let mut guard = self.app_send.lock().await;
        let Some(send) = guard.as_mut() else {
            return Ok(CallToolResult::error(vec![Content::text("azula app is not connected")]));
        };
        for frame in [Frame::thinking(true), Frame::token(args.text), Frame::token_done(), Frame::thinking(false)] {
            write_frame(send, &frame)
                .await
                .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        }
        Ok(CallToolResult::success(vec![Content::text("ok")]))
    }
}

#[tool_handler]
impl ServerHandler for Bridge {
    fn get_info(&self) -> ServerInfo {
        // ServerInfo is #[non_exhaustive] — build from default, then set fields.
        let mut info = ServerInfo::default();
        info.instructions = Some(
            "Bridge to an azula app session over iroh. Call get_messages to read what the user \
             typed in their azula conversation, and send_message to reply to them."
                .into(),
        );
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info
    }
}

pub async fn run(app_ticket: String, bind: String) -> Result<()> {
    let endpoint = Endpoint::bind(presets::N0).await?;
    info!("bridge endpoint coming online…");
    endpoint.online().await;

    let inbox: Inbox = Arc::new(std::sync::Mutex::new(VecDeque::new()));
    let app_send: AppSend = Arc::new(AsyncMutex::new(None));
    let fingerprint = app_ticket.chars().take(8).collect::<String>();

    // Dial the Azula app over iroh (best effort — the HTTP server still starts
    // if the app is unreachable; tools then report "not connected").
    match connect_app(&endpoint, &app_ticket).await {
        Ok((mut send, recv)) => {
            // The dialer must write first or the app never accept_bi's the stream.
            if let Err(e) = write_frame(&mut send, &Frame::thinking(false)).await {
                warn!(error = %e, "bridge: handshake write failed");
            }
            *app_send.lock().await = Some(send);
            let inbox_reader = inbox.clone();
            tokio::spawn(async move { reader_loop(recv, inbox_reader).await });
            info!("bridge: connected to azula app session {fingerprint}…");
        }
        Err(e) => warn!(error = %e, "bridge: could not reach the azula app; tools will report disconnected"),
    }

    // MCP server over Streamable HTTP, mounted at /mcp.
    let inbox_svc = inbox.clone();
    let app_send_svc = app_send.clone();
    let service = StreamableHttpService::new(
        move || Ok(Bridge::new(inbox_svc.clone(), app_send_svc.clone())),
        Arc::new(LocalSessionManager::default()),
        Default::default(),
    );
    let router = axum::Router::new().nest_service("/mcp", service);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    print_banner(&bind, &fingerprint);
    axum::serve(listener, router).await?;
    Ok(())
}

async fn connect_app(endpoint: &Endpoint, ticket: &str) -> Result<(SendStream, RecvStream)> {
    let ticket = EndpointTicket::from_str(ticket)?;
    let addr = ticket.endpoint_addr().clone();
    let conn = endpoint.connect(addr, LLM_ALPN).await?;
    Ok(conn.open_bi().await?)
}

async fn reader_loop(recv: RecvStream, inbox: Inbox) {
    let mut reader = BufReader::new(recv);
    loop {
        match read_frame(&mut reader).await {
            Ok(Some(Frame::Chat { text })) => inbox.lock().unwrap().push_back(text),
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(e) => {
                warn!(error = %e, "bridge: app stream read error");
                break;
            }
        }
    }
}

fn print_banner(bind: &str, fingerprint: &str) {
    println!();
    println!("  azula MCP bridge");
    println!("  MCP endpoint:  http://{bind}/mcp");
    println!("  app session:   {fingerprint}…");
    println!("  Add the endpoint URL to an MCP-capable LLM client. Point");
    println!("  https://azula.app/mcp/<token> (or mcp.azula.app) at this address.");
    println!();
}
