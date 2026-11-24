//! azula-guest: the job worker that runs inside the azula remote-compute VM.
//! Protocol: vm/README.md sections 1 and 2.

pub mod activation;
pub mod files;
pub mod frame;
pub mod identity;
pub mod jobs;
pub mod server;
pub mod sha256;
pub mod stdin_queue;
pub mod util;

#[cfg(target_os = "linux")]
pub mod vsock;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
