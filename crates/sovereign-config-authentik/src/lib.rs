//! Authentik as the identity provider managed connections are provisioned
//! in: the one implementation of
//! [`sovereign_config_identity::ManagedIdentityProvider`].
//!
//! - `config` — [`AuthentikConfig`]: the administration origin (derived from
//!   the issuer), token, grants attribute, browsing group and timeout, and
//!   their validation.
//! - `client` — the REST client, one method per Authentik call.
//! - `provider` — [`AuthentikProvider`]: the trait's operations in terms of
//!   those calls, and Authentik's integer primary keys as opaque
//!   [`sovereign_config_identity::AccountId`]s.
//! - `password` — the replacement app passwords it generates.
//!
//! Only the server's `main.rs` builds one; everything else sees the trait.

#![forbid(unsafe_code)]

mod client;
mod config;
mod password;
mod provider;

pub use config::AuthentikConfig;
pub use provider::AuthentikProvider;
