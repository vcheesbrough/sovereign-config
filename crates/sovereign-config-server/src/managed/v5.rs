//! The `v5` wire shim over [`super::ManagedConnectionsService`]: the shared
//! adapter in [`super::shim`], pointed at `v5`'s generated types.
//!
//! `v5` refuses an untranslatable permission selection itself ([`Upfront`])
//! before the shared implementation is called.

use sovereign_config_proto::sovereign::config::v5 as proto;

use super::shim::{Upfront, managed_connections_shim};

managed_connections_shim!(V5ManagedConnections, Upfront);
