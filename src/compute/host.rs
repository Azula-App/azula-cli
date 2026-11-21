//! Host-side orchestration (macOS): the dedicated host key, `host.json`, the
//! `serve.lock`, `compute serve` itself and grant minting (`vm/BROKER.md` §6).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use iroh::protocol::Router;
use iroh::SecretKey;
use serde::{Deserialize, Serialize};
use tracing::info;

use super::broker::Broker;
use super::vm::VmBackend;
use super::grants::{create_private_dir, unix_now, write_private_atomic, FileLock, Grant, GrantStore, MintOptions, Token};
use super::vmmgr::{find_guest_bin, find_helper, install_guest_bin, Paths, RealBackend};
use super::{compute_dir, vm_dir, ALPN};
use crate::endpoint::{bind_with_options, print_banner, EndpointOptions};

/// `host.json`: where the host can be reached.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub endpoint_id: String,
    pub relay_url: String,
    pub updated: u64,
}

fn host_key_path() -> PathBuf {
    compute_dir().join("host.key")
}

fn host_json_path() -> PathBuf {
    compute_dir().join("host.json")
}

fn lock_path() -> PathBuf {
    compute_dir().join("serve.lock")
}

/// The compute host key: raw 32 bytes, 0600, never shared with any other
/// azula identity. Created on first use.
pub fn load_or_create_host_key() -> Result<SecretKey> {
    let path = host_key_path();
    if let Ok(bytes) = std::fs::read(&path) {
        let arr = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| anyhow!("{} is not a 32-byte key", path.display()))?;
        return Ok(SecretKey::from_bytes(&arr));
    }
    create_private_dir(&compute_dir())?;
    let key = SecretKey::generate();
    write_private_atomic(&path, &key.to_bytes())?;
    Ok(key)
}

pub fn read_host_info() -> Option<HostInfo> {
    serde_json::from_slice(&std::fs::read(host_json_path()).ok()?).ok()
}

fn write_host_info(info: &HostInfo) -> Result<()> {
    write_private_atomic(&host_json_path(), &serde_json::to_vec_pretty(info)?)
}

fn grant_store() -> GrantStore {
    GrantStore::new(compute_dir())
}

/// `compute serve`: run the broker until SIGINT/SIGTERM, then stop every VM
/// it started.
pub async fn serve(allow_sleep: bool) -> Result<()> {
    let dir = compute_dir();
    create_private_dir(&dir)?;
    let Some(_lock) = FileLock::try_exclusive(&lock_path())? else {
        bail!("`azula compute serve` is already running on this host (holding {})", lock_path().display());
    };
    let key = load_or_create_host_key()?;

    let paths = Paths::new(vm_dir());
    let helper = find_helper()?;
    let guest_bin = find_guest_bin()?;
    install_guest_bin(&paths, &guest_bin)?;
    std::fs::create_dir_all(paths.vms())?;

    let mut opts = EndpointOptions::new(key);
    opts.alpns = vec![ALPN.to_vec()];
    opts.online_timeout = Some(Duration::from_secs(30));
    opts.quic_timeouts = Some(super::QUIC_TIMEOUTS);
    let endpoint = bind_with_options(opts).await?;
    let id = endpoint.id().to_string();
    let relay = endpoint.addr().relay_urls().next().map(|u| u.to_string()).ok_or_else(|| anyhow!("the endpoint has no home relay"))?;
    write_host_info(&HostInfo { endpoint_id: id.clone(), relay_url: relay.clone(), updated: unix_now() })?;

    let backend = Arc::new(RealBackend::new(paths.clone(), helper).allow_sleep(allow_sleep));
    let guard_task = backend.spawn_sleep_guard();
    let host = gethostname::gethostname().to_string_lossy().into_owned();
    let broker = Broker::new(backend.clone(), grant_store(), host);
    let watcher = broker.spawn_watcher();
    let router = Router::builder(endpoint).accept(ALPN, broker).spawn();

    print_banner(
        "azula compute",
        &[
            format!("  endpoint id : {id}"),
            format!("  relay       : {relay}"),
            format!("  VM dir      : {}", paths.root.display()),
            String::new(),
            "  Mint a token with `azula compute grant`; Ctrl-C stops the broker and its VMs.".to_owned(),
        ],
    );

    wait_for_shutdown_signal().await;
    info!("shutting down: stopping VMs");
    watcher.abort();
    let _ = router.shutdown().await;
    backend.shutdown().await;
    guard_task.abort();
    Ok(())
}

async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

/// The relay URL to put in a new token: `host.json` if it names this host
/// key; otherwise (and only when no serve is running) bind the host key
/// briefly to learn its home relay. Never binds the key while serve holds it,
/// because the relay would drop serve's connection.
async fn resolve_host(key: &SecretKey) -> Result<HostInfo> {
    let id = key.public().to_string();
    if let Some(h) = read_host_info().filter(|h| h.endpoint_id == id && !h.relay_url.is_empty()) {
        return Ok(h);
    }
    create_private_dir(&compute_dir())?;
    let Some(_lock) = FileLock::try_exclusive(&lock_path())? else {
        bail!("`compute serve` is running but {} is missing; restart it so it can record its relay", host_json_path().display());
    };
    let mut opts = EndpointOptions::new(key.clone());
    opts.online_timeout = Some(Duration::from_secs(20));
    let ep = bind_with_options(opts).await.context("learning the host's home relay")?;
    let relay = ep.addr().relay_urls().next().map(|u| u.to_string()).ok_or_else(|| anyhow!("the endpoint has no home relay"))?;
    ep.close().await;
    let info = HostInfo { endpoint_id: id, relay_url: relay, updated: unix_now() };
    write_host_info(&info)?;
    Ok(info)
}

/// Mint a grant and its token.
pub async fn grant(opts: &MintOptions) -> Result<(Grant, String)> {
    let key = load_or_create_host_key()?;
    let host = resolve_host(&key).await?;
    let (grant, secret) = grant_store().mint(opts)?;
    let token = Token { host: host.endpoint_id, relay: host.relay_url, grant: grant.id.clone(), secret };
    Ok((grant, token.encode()))
}

pub fn list_grants() -> Result<Vec<Grant>> {
    grant_store().list()
}

pub fn revoke(id: &str, cancel_jobs: bool) -> Result<bool> {
    grant_store().revoke(id, cancel_jobs)
}
