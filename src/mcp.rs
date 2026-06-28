//! MCP (Model Context Protocol) relay protocol handler.
//!
//! Serves the `azula/llm/0` ALPN. On each connection the server accepts the
//! client-opened bi stream, then loops reading [`Frame::Chat`] prompts. For
//! each prompt it emits a `Thinking{on:true}` frame, pushes the message into a
//! shared upstream MCP session by calling a tool, streams the tool's text
//! result back as `Token{delta}` frames, then a terminal
//! `Token{delta:"",done:true}` and `Thinking{on:false}`.
//!
//! The backend is an MCP server reached as a *client* via the official Rust MCP
//! SDK ([`rmcp`]). One shared client session is established at `serve` startup
//! (over stdio child-process or Streamable HTTP) and shared across all azula
//! app clients. If no MCP transport is configured — or the eager connect fails
//! — the handler falls back to a canned word-by-word notice so the end-to-end
//! iroh path stays testable.

use std::sync::Arc;

use anyhow::Result;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler};
use rmcp::model::{CallToolRequestParams, CallToolResult, RawContent};
use rmcp::service::{RoleClient, RunningService};
use rmcp::ServiceExt;
use serde_json::{Map, Value};
use tokio::io::BufReader;
use tracing::{debug, info, warn};

use crate::proto::{read_frame, write_frame, Frame};

/// ALPN identifier for the LLM relay protocol.
pub const LLM_ALPN: &[u8] = b"azula/llm/0";

/// Notice streamed back when no MCP server is configured (or the connect
/// failed). Sent word-by-word so the app still sees a streaming effect.
const NO_MCP_NOTICE: &str =
    "azula: no MCP server configured — start the server with --mcp-stdio or --mcp-url";

/// Which transport to use for the upstream MCP client session.
#[derive(Debug, Clone)]
pub enum McpTransport {
    /// Spawn an MCP server as a child process and talk to it over stdio.
    /// The string is a full command line (split with `shell-words`).
    Stdio(String),
    /// Connect to a remote MCP server over Streamable HTTP / SSE.
    Url(String),
}

/// Configuration for the MCP client backend.
#[derive(Debug, Clone)]
pub struct McpConfig {
    /// `None` => no transport configured; use the canned fallback responder.
    pub transport: Option<McpTransport>,
    /// Tool to call to push a message. `None` => pick the first tool listed.
    pub tool: Option<String>,
    /// JSON argument name carrying the message text.
    pub message_arg: String,
}

impl Default for McpConfig {
    fn default() -> Self {
        McpConfig {
            transport: None,
            tool: None,
            message_arg: "message".to_string(),
        }
    }
}

/// A live, shared MCP client session plus the resolved tool/arg selection.
///
/// The running service keeps the transport alive; the peer it exposes is cheap
/// to clone and drives concurrent JSON-RPC requests (ids are matched
/// internally), so no external lock is needed around `call_tool`.
struct McpSession {
    service: RunningService<RoleClient, ()>,
    /// The tool name used to push messages.
    tool: String,
    /// The JSON argument key the message text is placed under.
    message_arg: String,
}

/// Establish the shared MCP client session described by `config`.
///
/// Returns `Ok(None)` when no transport is configured. On a transport that is
/// configured but fails to connect, returns `Err` (the caller logs and falls
/// back to the no-MCP responder rather than crashing).
pub async fn connect(config: &McpConfig) -> Result<Option<Arc<McpHandle>>> {
    let Some(transport) = config.transport.clone() else {
        return Ok(None);
    };

    let service = match transport {
        McpTransport::Stdio(cmdline) => {
            use rmcp::transport::TokioChildProcess;
            use tokio::process::Command;

            let parts = shell_words::split(&cmdline)
                .map_err(|e| anyhow::anyhow!("parsing --mcp-stdio command line: {e}"))?;
            let (program, args) = parts
                .split_first()
                .ok_or_else(|| anyhow::anyhow!("--mcp-stdio command line is empty"))?;
            info!(program = %program, args = ?args, "mcp: spawning stdio server");
            let mut cmd = Command::new(program);
            cmd.args(args);
            let child = TokioChildProcess::new(cmd)?;
            ().serve(child).await?
        }
        McpTransport::Url(url) => {
            use rmcp::transport::StreamableHttpClientTransport;

            info!(%url, "mcp: connecting over streamable http");
            let transport = StreamableHttpClientTransport::from_uri(url);
            ().serve(transport).await?
        }
    };

    // Resolve which tool to call: explicit `--mcp-tool`, else the first listed.
    let tool = match &config.tool {
        Some(name) => {
            info!(tool = %name, "mcp: using configured tool");
            name.clone()
        }
        None => {
            let tools = service.list_tools(Default::default()).await?;
            let first = tools
                .tools
                .first()
                .ok_or_else(|| anyhow::anyhow!("MCP server exposes no tools to call"))?;
            let name = first.name.to_string();
            info!(
                tool = %name,
                available = tools.tools.len(),
                "mcp: no --mcp-tool given; defaulting to first tool"
            );
            name
        }
    };

    Ok(Some(Arc::new(McpHandle(McpSession {
        service,
        tool,
        message_arg: config.message_arg.clone(),
    }))))
}

/// Shared, cloneable handle to the upstream MCP session.
pub struct McpHandle(McpSession);

impl McpHandle {
    /// Push `text` into the MCP session by calling the selected tool, and
    /// return the concatenated text content of the result.
    async fn ask(&self, text: &str) -> Result<String> {
        let mut args = Map::new();
        args.insert(self.0.message_arg.clone(), Value::String(text.to_string()));

        let result = self
            .0
            .service
            .call_tool(CallToolRequestParams::new(self.0.tool.clone()).with_arguments(args))
            .await?;

        Ok(render_result(&result))
    }
}

/// Concatenate the text content blocks of a [`CallToolResult`]. If the result
/// is flagged as an error, prefix the extracted text with an error note so the
/// caller can surface it.
fn render_result(result: &CallToolResult) -> String {
    let text = extract_text(result);
    if result.is_error.unwrap_or(false) {
        if text.is_empty() {
            "[mcp tool error]".to_string()
        } else {
            format!("[mcp tool error] {text}")
        }
    } else {
        text
    }
}

/// Concatenate the `text` of every text content block in `result`.
fn extract_text(result: &CallToolResult) -> String {
    let mut out = String::new();
    for content in &result.content {
        if let RawContent::Text(t) = &content.raw {
            out.push_str(&t.text);
        }
    }
    out
}

/// Protocol handler for the LLM relay ALPN, backed by a shared MCP session.
#[derive(Clone)]
pub struct LlmHandler {
    /// `None` => no/failed MCP session; use the canned fallback responder.
    mcp: Option<Arc<McpHandle>>,
}

impl LlmHandler {
    pub fn new(mcp: Option<Arc<McpHandle>>) -> Self {
        if mcp.is_none() {
            warn!(
                "no MCP server configured (or connect failed); the LLM relay will reply with a \
                 canned notice. Pass --mcp-stdio or --mcp-url to enable real responses."
            );
        }
        LlmHandler { mcp }
    }
}

impl std::fmt::Debug for LlmHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LlmHandler")
            .field("mcp", &self.mcp.is_some())
            .finish()
    }
}

impl ProtocolHandler for LlmHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let this = self.clone();
        this.handle(connection)
            .await
            .map_err(|e| AcceptError::from_boxed(e.into()))
    }
}

impl LlmHandler {
    async fn handle(self, connection: Connection) -> Result<()> {
        let remote = connection.remote_id().to_string();
        info!(%remote, "llm: client connected");

        // Each bi stream is an independent LLM session, so one connection can
        // host many sessions. Loop accepting new streams.
        loop {
            let (send, recv) = match connection.accept_bi().await {
                Ok(pair) => pair,
                Err(e) => {
                    debug!(%remote, error = %e, "llm: connection closed");
                    return Ok(());
                }
            };
            let this = self.clone();
            let remote = remote.clone();
            tokio::spawn(async move {
                if let Err(e) = this.session(send, recv, remote.clone()).await {
                    warn!(%remote, error = %e, "llm: session error");
                }
            });
        }
    }

    /// Handle one LLM session bi stream: read prompts, stream answers.
    async fn session(self, send: SendStream, recv: RecvStream, remote: String) -> Result<()> {
        let mut send = send;
        let mut reader = BufReader::new(recv);

        loop {
            let frame = match read_frame(&mut reader).await? {
                Some(f) => f,
                None => {
                    debug!(%remote, "llm: stream closed by client");
                    break;
                }
            };

            match frame {
                Frame::Chat { text } => {
                    info!(%remote, prompt = %truncate(&text, 80), "llm: prompt");
                    write_frame(&mut send, &Frame::thinking(true)).await?;

                    let result = match &self.mcp {
                        Some(mcp) => stream_mcp(mcp, &text, &mut send).await,
                        None => stream_canned(&mut send).await,
                    };

                    if let Err(e) = result {
                        warn!(%remote, error = %e, "llm: backend error");
                        write_frame(&mut send, &Frame::token(format!("\n[mcp error: {e}]"))).await?;
                    }

                    write_frame(&mut send, &Frame::token_done()).await?;
                    write_frame(&mut send, &Frame::thinking(false)).await?;
                }
                // Ignore other frame kinds on the LLM channel.
                other => {
                    debug!(%remote, ?other, "llm: ignoring non-chat frame");
                }
            }
        }

        let _ = send.finish();
        Ok(())
    }
}

/// Call the MCP tool and stream its text result back word-by-word as `Token`
/// frames so the app shows a streaming effect.
async fn stream_mcp<W>(mcp: &McpHandle, text: &str, send: &mut W) -> Result<()>
where
    W: tokio::io::AsyncWriteExt + Unpin,
{
    let reply = mcp.ask(text).await?;
    stream_words(&reply, send, 0).await
}

/// Canned fallback: stream the no-MCP notice word-by-word as `Token` frames.
async fn stream_canned<W>(send: &mut W) -> Result<()>
where
    W: tokio::io::AsyncWriteExt + Unpin,
{
    stream_words(NO_MCP_NOTICE, send, 40).await
}

/// Stream `text` to `send` one whitespace-delimited word at a time, preserving
/// a single leading space between words. `delay_ms` throttles between words (0
/// to disable).
async fn stream_words<W>(text: &str, send: &mut W, delay_ms: u64) -> Result<()>
where
    W: tokio::io::AsyncWriteExt + Unpin,
{
    for (i, word) in text.split_whitespace().enumerate() {
        let chunk = if i == 0 {
            word.to_string()
        } else {
            format!(" {word}")
        };
        write_frame(send, &Frame::token(chunk)).await?;
        if delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }
    }
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max).collect();
        format!("{cut}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::Content;

    #[test]
    fn extracts_and_concatenates_text_blocks() {
        let result =
            CallToolResult::success(vec![Content::text("Hello, "), Content::text("world")]);
        assert_eq!(extract_text(&result), "Hello, world");
    }

    #[test]
    fn render_plain_result_is_just_text() {
        let result = CallToolResult::success(vec![Content::text("ok")]);
        assert_eq!(render_result(&result), "ok");
    }

    #[test]
    fn render_error_result_is_prefixed() {
        let result = CallToolResult::error(vec![Content::text("boom")]);
        assert_eq!(render_result(&result), "[mcp tool error] boom");
    }

    #[test]
    fn render_empty_error_result_has_placeholder() {
        let result = CallToolResult::error(vec![]);
        assert_eq!(render_result(&result), "[mcp tool error]");
    }
}
