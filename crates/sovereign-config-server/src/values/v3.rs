//! The `v3` wire shim over [`super::ConfigurationService`]: the shared
//! adapter in [`super::shim`], pointed at `v3`'s generated types.
//!
//! `v3` validates nothing here ([`Deferred`]). Input it cannot translate — an
//! unset oneof — is handed down as `None` for the shared implementation to
//! reject after it has authorized, which is the order `v3` has always failed
//! in and so the order it must keep. Retiring `v3` is deleting this file.

use sovereign_config_proto::sovereign::config::v3 as proto;

use super::shim::{Deferred, configuration_shim};

configuration_shim!(V3Configuration, Deferred);
