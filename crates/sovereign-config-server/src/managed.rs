//! Managed application connection lifecycle service.
//!
//! Implements the `ManagedConnections` gRPC service: listing safe metadata,
//! and creating, rotating, and revoking machine connections whose credentials
//! live only in Authentik. Each connection carries an operator-selected
//! permission set (read/write/manage) on its root. Sovereign Config persists
//! non-secret lifecycle metadata and returns each connection URL exactly once.
//!
//! - `service` — the tonic impl, authorization, and the lifecycle flows.
//! - `provisioning` — Authentik orchestration, compensation, reconciliation.
//! - `store` — every `PostgreSQL` row type and query.
//! - `identity` — generated connection ids, usernames, and app passwords.
//! - `wire` — metadata mapping and the bounded `Status` values.

mod identity;
mod provisioning;
mod service;
mod store;
mod wire;

pub(crate) use service::{ManagedConnectionsService, ManagedSettings};

#[cfg(test)]
mod tests;
