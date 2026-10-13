//! Shared fixtures for the presence/redial tests: a stand-in "phone" — a real
//! in-process iroh endpoint speaking `LLM_ALPN` — and the env isolation every
//! test that dials needs.

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{presets, Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::Endpoint;
use iroh_tickets::endpoint::EndpointTicket;
use tokio::io::BufReader;
use tokio::sync::mpsc;

use super::device::{DeviceConn, DeviceMap};
use super::presence::PresenceTimings;
use super::SessionCore;
use crate::mcp::LLM_ALPN;
use crate::proto::{read_frame, Frame};

/// Point every on-disk store a dial can touch (registry, mailbox, runtime state)
/// at a fresh directory under the temp dir, so a test never reads or writes the
/// real `~/.azula`. The caller must hold `registry::ENV_TEST_LOCK` for its whole
/// body and call [`unisolate`] last.
pub(crate) fn isolate(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("azula-presence-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::env::set_var("AZULA_REGISTRY_DIR", dir.join("registry"));
    std::env::set_var("AZULA_MAILBOX_DIR", dir.join("mailbox"));
    std::env::set_var("AZULA_STATE_DIR", dir.join("state"));
    dir
}

pub(crate) fn unisolate() {
    std::env::remove_var("AZULA_REGISTRY_DIR");
    std::env::remove_var("AZULA_MAILBOX_DIR");
    std::env::remove_var("AZULA_STATE_DIR");
}

/// Presence timings short enough for a test to watch several attempts.
pub(crate) fn fast_timings() -> PresenceTimings {
    PresenceTimings {
        tick: Duration::from_millis(25),
        initial_backoff: Duration::from_millis(25),
        max_backoff: Duration::from_millis(100),
        redelivery_backoff: Duration::from_millis(50),
        dial_timeout: Duration::from_secs(5),
    }
}

/// Poll `cond` until it holds, panicking with `what` after `within`.
pub(crate) async fn eventually<F, Fut>(what: &str, within: Duration, mut cond: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + within;
    loop {
        if cond().await {
            return;
        }
        assert!(tokio::time::Instant::now() < deadline, "timed out after {within:?} waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// One accepted connection from the session, as the phone sees it.
pub(crate) struct PhoneLink {
    pub(crate) conn: Connection,
    pub(crate) send: SendStream,
    pub(crate) recv: BufReader<RecvStream>,
}

impl PhoneLink {
    /// Send the session a frame, as the phone.
    pub(crate) async fn send_frame(&mut self, frame: &Frame) {
        crate::proto::write_frame(&mut self.send, frame).await.expect("phone write");
    }

    /// Next frame the session sent, or `None` on EOF/timeout.
    pub(crate) async fn next_frame(&mut self) -> Option<Frame> {
        match tokio::time::timeout(Duration::from_secs(5), read_frame(&mut self.recv)).await {
            Ok(Ok(frame)) => frame,
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
struct StubHandler {
    accepted: Arc<AtomicUsize>,
    links: mpsc::UnboundedSender<PhoneLinkParts>,
    /// Close every connection on arrival instead of holding it — a phone that
    /// refuses the session over and over.
    refuse: bool,
}

type PhoneLinkParts = (Connection, SendStream, RecvStream);

impl ProtocolHandler for StubHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        self.accepted.fetch_add(1, SeqCst);
        if self.refuse {
            connection.close(0u32.into(), b"refused");
            return Ok(());
        }
        let (send, recv) = connection.accept_bi().await.map_err(|e| AcceptError::from_boxed(e.into()))?;
        let _ = self.links.send((connection.clone(), send, recv));
        // Holding the connection open is the handler's job: it closes when this returns.
        connection.closed().await;
        Ok(())
    }
}

/// A fake phone: an iroh endpoint that can be told when to start answering on
/// `LLM_ALPN`, counts the connections it receives, and hands each accepted
/// stream pair to the test.
pub(crate) struct PhoneStub {
    pub(crate) endpoint: Endpoint,
    pub(crate) ticket: String,
    accepted: Arc<AtomicUsize>,
    links_tx: mpsc::UnboundedSender<PhoneLinkParts>,
    links_rx: mpsc::UnboundedReceiver<PhoneLinkParts>,
    router: Option<Router>,
}

impl PhoneStub {
    /// Bound but not yet listening: a dial gets "no application protocol" and
    /// fails — the phone that is asleep when the session starts.
    pub(crate) async fn bind() -> Self {
        let endpoint = Endpoint::bind(presets::Minimal).await.expect("bind phone endpoint");
        let ticket = EndpointTicket::new(endpoint.addr()).to_string();
        let (links_tx, links_rx) = mpsc::unbounded_channel();
        PhoneStub { endpoint, ticket, accepted: Arc::new(AtomicUsize::new(0)), links_tx, links_rx, router: None }
    }

    /// As [`Self::bind`], and answering from the start.
    pub(crate) async fn listening() -> Self {
        let mut stub = Self::bind().await;
        stub.listen(false);
        stub
    }

    /// Start answering on `LLM_ALPN`. With `refuse`, every connection is closed
    /// the moment it arrives.
    pub(crate) fn listen(&mut self, refuse: bool) {
        let handler = StubHandler { accepted: self.accepted.clone(), links: self.links_tx.clone(), refuse };
        self.router = Some(Router::builder(self.endpoint.clone()).accept(LLM_ALPN, handler).spawn());
    }

    /// Connections accepted so far.
    pub(crate) fn accepted(&self) -> usize {
        self.accepted.load(SeqCst)
    }

    /// The next stream pair the session opened, waiting up to `within`.
    pub(crate) async fn next_link(&mut self, within: Duration) -> Option<PhoneLink> {
        let (conn, send, recv) = tokio::time::timeout(within, self.links_rx.recv()).await.ok()??;
        Some(PhoneLink { conn, send, recv: BufReader::new(recv) })
    }

    pub(crate) async fn shutdown(self) {
        if let Some(router) = self.router {
            let _ = router.shutdown().await;
        }
        self.endpoint.close().await;
    }
}

/// A `SessionCore` over its own endpoint with `phone` known at `ticket` but not
/// yet connected.
pub(crate) async fn core_knowing(phone: &str, ticket: &str) -> SessionCore {
    let ep = Endpoint::bind(presets::Minimal).await.expect("bind session endpoint");
    let devices: DeviceMap = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    devices.lock().await.insert(phone.to_string(), DeviceConn::new(ticket.to_string()));
    SessionCore::from_parts(
        Arc::new(ep),
        devices,
        "test".to_string(),
        "session-ticket".to_string(),
        "session".to_string(),
        "azd-test-cert".to_string(),
        None,
    )
}
