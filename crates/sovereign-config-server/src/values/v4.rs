//! The `v4` wire shim over [`super::ConfigurationService`]: the shared
//! adapter in [`super::shim`], pointed at `v4`'s generated types.
//!
//! `v4` validates its own input before the shared implementation authorizes
//! ([`Upfront`]), so a malformed request is `INVALID_ARGUMENT` whoever sends
//! it. That is the one way `v4`'s `Configuration` differs from `v3`'s.

use sovereign_config_proto::sovereign::config::v4 as proto;

use super::shim::{Upfront, configuration_shim};

configuration_shim!(V4Configuration, Upfront);
