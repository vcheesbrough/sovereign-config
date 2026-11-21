//! The `v6` wire shim over [`super::ManagedConnectionsService`]: the shared
//! adapter in [`super::shim`], pointed at `v6`'s generated types and written
//! in `v6`'s wire form ([`JsonSafe`]: microsecond timestamps).
//!
//! `v6` refuses an untranslatable permission selection itself ([`Upfront`])
//! before the shared implementation is called, as `v4` and `v5` do.

use sovereign_config_proto::sovereign::config::v6 as proto;

use super::shim::{Upfront, managed_connections_shim};
use crate::rpc::JsonSafe;

managed_connections_shim!(V6ManagedConnections, Upfront, JsonSafe);
