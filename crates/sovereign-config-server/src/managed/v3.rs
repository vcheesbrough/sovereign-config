//! The `v3` wire shim over [`super::ManagedConnectionsService`]: the shared
//! adapter in [`super::shim`], pointed at `v3`'s generated types.
//!
//! `v3` validates nothing here ([`Deferred`]): a permission selection with an
//! unknown or no tag is handed down as `None` for the shared implementation to
//! reject, in the order `v3` has always failed in. Retiring `v3` is deleting
//! this file.

use sovereign_config_proto::sovereign::config::v3 as proto;

use super::shim::{Deferred, managed_connections_shim};

managed_connections_shim!(V3ManagedConnections, Deferred);
