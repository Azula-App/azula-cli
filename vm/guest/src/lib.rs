//! azula-guest: the job worker that runs inside the azula remote-compute VM.
//! Protocol: vm/README.md sections 1 and 2.

pub mod frame;
pub mod identity;
pub mod server;

#[cfg(target_os = "linux")]
pub mod vsock;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
