//! The `v5` wire shim over [`super::ConfigurationService`]: the shared
//! adapter in [`super::shim`], pointed at `v5`'s generated types.
//!
//! `v5` validates its own input before the shared implementation authorizes
//! ([`Upfront`]), so a malformed request is `INVALID_ARGUMENT` whoever sends
//! it. Unchanged from `v4`.

use sovereign_config_proto::sovereign::config::v5 as proto;

use super::shim::{Upfront, configuration_shim};

configuration_shim!(V5Configuration, Upfront);
