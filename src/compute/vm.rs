//! What the broker needs from a VM manager, so the broker is testable without
//! a hypervisor. The real macOS implementation is `vmmgr::RealBackend`; the
//! tests use a fake whose `vsock.sock` is served by an in-process task.

use std::future::Future;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Lifecycle state of a VM as the broker sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmState {
    Stopped,
    Starting,
    Running,
    Stopping,
}

impl VmState {
    pub fn as_str(self) -> &'static str {
        match self {
            VmState::Stopped => "stopped",
            VmState::Starting => "starting",
            VmState::Running => "running",
            VmState::Stopping => "stopping",
        }
    }
}

/// `VmInfo` of `vm/BROKER.md` §5.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VmInfo {
    pub name: String,
    pub state: String,
    /// `ready`, `unreachable` or `unknown`.
    pub worker: String,
    pub image: String,
    pub cpus: u32,
    pub memory_mb: u64,
    pub disk_gb: u64,
    /// The guest's `pong` frame header when the worker answered.
    pub worker_info: Option<Value>,
}

/// A failure the broker reports to the client as `{"t":"error","code",…}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmError {
    pub code: &'static str,
    pub msg: String,
}

impl VmError {
    pub fn new(code: &'static str, msg: impl Into<String>) -> Self {
        Self { code, msg: msg.into() }
    }

    pub fn unknown(name: &str) -> Self {
        Self::new("unknown_vm", format!("no VM named `{name}` (see `azula vm list` on the host)"))
    }
}

impl std::fmt::Display for VmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.msg)
    }
}

impl std::error::Error for VmError {}

/// The VM manager behind the broker. Methods that wait return `Send` futures
/// so the broker can run on the multi-threaded runtime.
pub trait VmBackend: Send + Sync + 'static {
    /// Names of every VM bundle, sorted.
    fn names(&self) -> Result<Vec<String>, VmError>;
    /// Current state; `unknown_vm` if there is no such VM.
    fn state(&self, name: &str) -> Result<VmState, VmError>;
    /// Full status, including a worker ping when running.
    fn info(&self, name: &str) -> impl Future<Output = Result<VmInfo, VmError>> + Send;
    /// Start the VM and return once its worker answers a ping. Idempotent:
    /// starting a running VM succeeds, starting one that is starting waits.
    fn start(&self, name: &str) -> impl Future<Output = Result<(), VmError>> + Send;
    /// Stop the VM and return once it has stopped.
    fn stop(&self, name: &str) -> impl Future<Output = Result<(), VmError>> + Send;
    /// Where the VM's worker socket is (present only while running).
    fn vsock_path(&self, name: &str) -> PathBuf;
    /// Stop every VM this backend started (broker shutdown).
    fn shutdown(&self) -> impl Future<Output = ()> + Send;
}

/// The `--vm` default rule (`vm/BROKER.md` §7): the grant's only VM when it
/// names exactly one concrete VM, else `default`.
pub fn default_vm_for(grant_vms: &[String]) -> String {
    match grant_vms {
        [one] if one != "*" => one.clone(),
        _ => "default".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vm_default_rule() {
        assert_eq!(default_vm_for(&["build".into()]), "build");
        assert_eq!(default_vm_for(&["*".into()]), "default");
        assert_eq!(default_vm_for(&["a".into(), "b".into()]), "default");
        assert_eq!(default_vm_for(&[]), "default");
    }
}
