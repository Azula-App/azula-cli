//! azula — server-side companion for the azula p2p app.
//!
//! Binds an iroh endpoint, prints a shareable ticket, and serves two ALPN
//! protocols to connecting azula app clients:
//!
//! * `azula/llm/0`  — an LLM relay that acts as an MCP (Model Context Protocol)
//!   *client*: it pushes each chat message into a shared upstream MCP session
//!   and streams the tool result back. A canned notice is streamed when no MCP
//!   server is configured.
//! * `azula/term/0` — a remote shell ("SSH"-like) bridge over a PTY
//!
//! This crate is the library half of the `azula` binary (see `main.rs`); the
//! `azula-demos` crate (in `demos/`) depends on it for the standalone demo
//! binaries that used to live here.

pub mod accept_gate;
pub mod bip39_wordlist;
pub mod bridge;
pub mod certs;
pub mod endpoint;
pub mod eventlog;
pub mod filexfer;
pub mod identity;
pub mod invite;
pub mod link;
pub mod linked_identity;
pub mod mailbox;
pub mod mailbox_role;
pub mod mcp;
pub mod proto;
pub mod qr;
pub mod registry;
pub mod session;
pub mod sync;
pub mod term;
