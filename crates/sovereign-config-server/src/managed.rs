//! Managed application connection lifecycle service.
//!
//! Implements the `ManagedConnections` gRPC service: listing safe metadata,
//! and creating, rotating, and revoking machine connections whose credentials
//! live only in Authentik. Each connection carries an operator-selected
//! permission set (read/write/manage) on its root. Sovereign Config persists
//! non-secret lifecycle metadata and returns each connection URL exactly once.
//!
//! - `service` — the shared implementation, in no protocol version's terms:
//!   authorization and the lifecycle flows.
//! - `v3` — the `v3` tonic impl: a translation shim over `service`.
//! - `provisioning` — Authentik orchestration, compensation, reconciliation.
//! - `store` — every `PostgreSQL` row type and query.
//! - `identity` — generated connection ids, usernames, and app passwords.
//! - `wire` — version-free metadata and the bounded `Status` values.

mod identity;
mod provisioning;
mod service;
mod store;
mod v3;
mod wire;

pub(crate) use service::{ManagedConnectionsService, ManagedSettings};
pub(crate) use v3::V3ManagedConnections;

#[cfg(test)]
mod tests;
