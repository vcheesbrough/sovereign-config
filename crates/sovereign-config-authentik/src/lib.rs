//! Authentik as the server's identity provider: everything the server
//! takes from one ([`sovereign_config_identity::IdentityProvider`]), and
//! everything it knows about Authentik.
//!
//! - `settings` — [`from_variables`]: Authentik's variables, parsed and
//!   validated into the whole provider, and [`verification_rules`]: how its
//!   access tokens are read.
//! - `config` — [`AuthentikConfig`]: the administration origin (derived from
//!   the issuer), token, grants attribute, browsing group and timeout, and
//!   their validation.
//! - `client` — the REST client, one method per Authentik call.
//! - `provider` — [`AuthentikProvider`]: the trait's operations in terms of
//!   those calls, and Authentik's integer primary keys as opaque
//!   [`sovereign_config_identity::AccountId`]s.
//! - `password` — the replacement app passwords it generates.
//! - `setup` — [`Setup`]: `migrate`'s Authentik step, which checks the
//!   running Authentik and applies the environment's blueprint.
//!
//! - `tests/blueprints.rs` holds the setup files (`authentik/blueprint*.yaml`)
//!   to the realm contract's terms.
//!
//! Only the server's provider selection names this crate; everything else
//! sees the contract.

#![forbid(unsafe_code)]

mod client;
mod config;
mod password;
mod provider;
mod settings;
mod setup;

pub use config::AuthentikConfig;
pub use provider::AuthentikProvider;
pub use settings::{NAME, from_variables, verification_rules};
pub use setup::Setup;
