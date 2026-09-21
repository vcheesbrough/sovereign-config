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
//! - `shim` — the one adapter every version's shim instantiates, and the
//!   validation policies a version chooses between.
//! - `v3`, `v4` — each version's tonic impl: `shim` pointed at that version's
//!   generated types.
//! - `provisioning` — Authentik orchestration, compensation, reconciliation.
//! - `store` — every `PostgreSQL` row type and query.
//! - `identity` — generated connection ids, usernames, and app passwords.
//! - `wire` — version-free metadata and the bounded `Status` values.

mod identity;
mod provisioning;
mod service;
mod shim;
mod store;
mod v3;
mod v4;
mod wire;

pub(crate) use service::{ManagedConnectionsService, ManagedSettings};
pub(crate) use v3::V3ManagedConnections;
pub(crate) use v4::V4ManagedConnections;

#[cfg(test)]
mod shim_tests;
#[cfg(test)]
mod tests;
