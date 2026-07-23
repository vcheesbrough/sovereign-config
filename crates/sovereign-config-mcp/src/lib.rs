//! First-party Sovereign Config local stdio MCP server library.
//!
//! The binary in `main.rs` is a thin wrapper over these modules; exposing them
//! as a library lets the integration harness drive the exact same server over
//! in-memory streams. See the crate binary for the runtime entry point.

#![forbid(unsafe_code)]

pub mod backend;
pub mod errors;
pub mod native;
pub mod protocol;
pub mod server;
pub mod tools;

/// Release version: the deploy-stamped `SOVEREIGN_CONFIG_RELEASE` when present
/// (set by the release build so the served installer is protocol-matched),
/// otherwise the crate version for source builds.
pub const SERVER_VERSION: &str = match option_env!("SOVEREIGN_CONFIG_RELEASE") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};
