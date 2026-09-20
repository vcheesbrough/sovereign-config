//! The `Configuration` gRPC service: configuration values, their paths, and
//! their stored representation.
//!
//! - `service` — the shared implementation, in no protocol version's terms.
//! - `v3` — the `v3` tonic impl: a translation shim over `service`.
//! - `authz` — per-request path parsing and permission checks.
//! - `store` — every `PostgreSQL` row type and query.
//! - `paths` — pure fold-path arithmetic (collision, parents, ancestors).
//! - `subtree` — pure validation of a `ReplaceSubTree` mutation.
//! - `content` — mapping a stored value onto its masked representation.
//! - `startup` — the start-of-day secret encryption pass.

mod authz;
mod content;
mod paths;
mod service;
mod startup;
mod store;
mod subtree;
mod v3;

pub(crate) use service::ConfigurationService;
pub(crate) use startup::encrypt_stored_secrets;
pub(crate) use v3::V3Configuration;

/// Classification of a value the caller may read back in the clear.
const PLAIN: &str = "plain";
/// Classification of a value stored as ciphertext and masked on read.
const SECRET: &str = "secret";

#[cfg(test)]
mod tests;
