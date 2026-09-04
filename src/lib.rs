//! neton — structured local network observation for AI agents (JSON in, JSON out).
//!
//! The library is shared between the `neton` CLI binary and its `serve` mode:
//! every action produces serde-serializable models so the CLI and the HTTP API
//! emit the exact same JSON shapes.

pub mod actions;
pub mod arp;
pub mod cli;
pub mod device;
pub mod dispatch;
pub mod dns_ptr;
pub mod mcp;
pub mod models;
pub mod oui;
pub mod scan;
pub mod serve;
