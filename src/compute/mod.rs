//! Remote compute: run commands in a disposable Linux VM on an Apple silicon
//! Mac, from anywhere, over iroh. See `vm/README.md` (frames, guest and helper
//! protocols, bundles) and `vm/BROKER.md` (this module's contract) in the
//! repository, and the `remote-compute-vm` change in azula-docs.
//!
//! * [`frame`] — the wire codec shared by every hop.
//! * [`grants`] — the grant store and `azc1.` bearer tokens.
//! * [`vm`] — the [`vm::VmBackend`] trait the broker drives.
//! * [`broker`] — `compute serve`: authenticate, authorize, splice.
//! * [`client`] — the cross-platform `exec`/`doctor`/`vm` client.
//! * `vmmgr` / `host` — the real VM manager and host verbs (macOS only).

use std::path::PathBuf;

pub mod broker;
pub mod client;
pub mod frame;
pub mod grants;
pub mod guest;
pub mod seed;
#[cfg(target_os = "macos")]
pub mod host;
#[cfg(target_os = "macos")]
pub mod vmmgr;
pub mod vm;

#[cfg(test)]
mod tests;

/// ALPN of the client-to-broker protocol.
pub const ALPN: &[u8] = b"azula/compute/1";
/// Protocol version carried in `hello`/`welcome`.
pub const PROTO_VERSION: u32 = 1;
/// Version string both sides announce.
pub fn agent() -> String {
    format!("azula/{}", env!("CARGO_PKG_VERSION"))
}

/// Why a host verb cannot run here.
pub const HOST_ONLY_MSG: &str = "compute hosting requires Apple silicon macOS";

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// `~/.azula/compute` (`AZULA_COMPUTE_DIR` overrides it, for tests): the host
/// key, `grants.json`, `host.json` and `serve.lock`.
pub fn compute_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("AZULA_COMPUTE_DIR").filter(|d| !d.is_empty()) {
        return PathBuf::from(d);
    }
    home().unwrap_or_else(|| PathBuf::from(".")).join(".azula").join("compute")
}

/// `~/.azula/vm` (`AZULA_VM_DIR` overrides it, for tests): images, share, VMs.
pub fn vm_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("AZULA_VM_DIR").filter(|d| !d.is_empty()) {
        return PathBuf::from(d);
    }
    home().unwrap_or_else(|| PathBuf::from(".")).join(".azula").join("vm")
}

/// A VM name is a path component and a hostname: lowercase letters, digits and
/// `-`, 1..=63 chars, not starting or ending with `-`.
pub fn valid_vm_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The first 8 hex chars of an endpoint id, for log lines.
pub fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}
