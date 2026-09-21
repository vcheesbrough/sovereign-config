//! The `v4` wire shim over [`super::ManagedConnectionsService`]: the shared
//! adapter in [`super::shim`], pointed at `v4`'s generated types.
//!
//! `v4` refuses an untranslatable permission selection itself ([`Upfront`])
//! before the shared implementation is called.

use sovereign_config_proto::sovereign::config::v4 as proto;

use super::shim::{Upfront, managed_connections_shim};

managed_connections_shim!(V4ManagedConnections, Upfront);
