#![forbid(unsafe_code)]
//! Ergonomic application-configuration facade over the Sovereign Config native
//! client.
//!
//! A managed connection URL — as provisioned through the Sovereign Config web UI
//! — is a self-contained credential encoding an OIDC issuer, a client-credentials
//! secret, and one canonical configuration root. [`Provider`] takes such a URL,
//! authenticates with the client-credentials grant, reads only the encoded
//! subtree over native gRPC, and deserializes it into your application's
//! configuration type.
//!
//! ```no_run
//! use serde::Deserialize;
//! use sovereign_config_provider::{Provider, ProviderError};
//!
//! #[derive(Deserialize)]
//! struct AppConfig {
//!     database_url: String,
//!     feature_flag: String,
//! }
//!
//! # async fn example(url: &str) -> Result<(), ProviderError> {
//! let provider = Provider::connect(url).await?;
//! let config: AppConfig = provider.load().await?;
//! # let _ = config;
//! # Ok(())
//! # }
//! ```
//!
//! # Contract
//!
//! - **Managed connections only.** [`Provider::connect`] rejects human
//!   device-flow URLs; an unattended application must be given a managed
//!   client-credentials URL.
//! - **No caching.** Each [`Provider::load`] acquires a fresh access token, reads
//!   the subtree, and reveals each secret leaf anew. Nothing — token, subtree,
//!   or secret — is retained across or within calls.
//! - **No retries.** Any failed step returns a bounded [`ProviderError`]
//!   immediately.
//! - **Redaction.** No error, log, or public value exposes the connection URL,
//!   its fragment, a token, an app password, the issuer, a service-account
//!   identity, a grant, or a configuration value.
//! - **Secret leaves cost one reveal each.** Secret-classified values are masked
//!   in ordinary reads, so [`Provider::load`] issues one additional
//!   `reveal_secret` RPC per secret leaf under the root. The RPC count of a load
//!   therefore scales with the number of secret leaves in your configuration.
//!
//! # Compatibility
//!
//! This crate is distributed as tagged workspace source and must be built from
//! the same tag as the Sovereign Config server it talks to. It speaks the `v3`
//! protocol and targets the workspace `rust-version`.
//!
//! # Async runtime
//!
//! The underlying transport is `!Send`; drive [`Provider::connect`] and
//! [`Provider::load`] on the task owning the runtime (a current-thread runtime,
//! or `spawn_local`/`LocalSet`), not on a `Send`-bound `tokio::spawn`.

mod error;
mod mapping;
mod token;

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use sovereign_config_client::{AccessTokenProvider, Transport, ValueTransport};
use sovereign_config_core::{
    ConfigPath, ConnectionUrl, PROTOCOL_VERSION, ServiceStatus, ValueContent,
};
use sovereign_config_native::TonicTransport;

pub use error::ProviderError;
use mapping::subtree_to_json;
use token::ManagedTokenProvider;

/// A read-only handle to one managed configuration subtree.
pub struct Provider {
    transport: TonicTransport,
    token: ManagedTokenProvider,
    root: ConfigPath,
}

impl Provider {
    /// Parses a version-1 managed connection URL and connects the native gRPC
    /// channel.
    ///
    /// Connecting performs exactly one unauthenticated `GetVersion` call to
    /// negotiate protocol compatibility and acquires no access token. The URL
    /// must carry a client-credentials secret; human device-flow URLs are
    /// rejected.
    ///
    /// # Errors
    ///
    /// - [`ProviderError::MalformedUrl`] — the URL is invalid or non-canonical.
    /// - [`ProviderError::UnsupportedCredential`] — the URL is a human
    ///   device-flow URL rather than a managed connection.
    /// - [`ProviderError::IncompatibleProtocol`] — the service protocol does
    ///   not match this release.
    /// - [`ProviderError::Unavailable`] — the gRPC endpoint is unreachable.
    pub async fn connect(url: &str) -> Result<Self, ProviderError> {
        let connection = ConnectionUrl::parse(url)?;
        let authentication = connection
            .client_authentication()
            .ok_or(ProviderError::UnsupportedCredential)?
            .clone();
        let transport = TonicTransport::connect(connection.endpoint().to_owned()).await?;
        let reply = transport.get_version(PROTOCOL_VERSION).await?;
        let status = ServiceStatus::negotiate(reply.application_version, reply.protocol_version);
        if !status.compatible {
            return Err(ProviderError::IncompatibleProtocol);
        }
        let token = ManagedTokenProvider::new(
            connection.issuer().to_owned(),
            connection.client_id().to_owned(),
            authentication,
        );
        Ok(Self {
            transport,
            token,
            root: connection.root().clone(),
        })
    }

    /// Loads the connection's permitted subtree and deserializes it into `T`.
    ///
    /// Acquires one fresh client-credentials token, issues one `get_subtree`
    /// read, then one `reveal_secret` read per secret-classified leaf, assembles
    /// a JSON tree of the real values relative to the connection root, and
    /// deserializes it. Nothing is cached across or within calls; no step is
    /// retried.
    ///
    /// # Errors
    ///
    /// Returns a bounded, redacted [`ProviderError`]:
    /// - [`ProviderError::AuthenticationFailed`] — token acquisition or the read
    ///   was rejected.
    /// - [`ProviderError::PermissionDenied`] — the connection is not authorized.
    /// - [`ProviderError::IncompatibleProtocol`] / [`ProviderError::InvalidRequest`]
    ///   / [`ProviderError::NotFound`] / [`ProviderError::Unavailable`] — mapped
    ///   from the underlying transport.
    /// - [`ProviderError::InvalidConversion`] — the subtree could not be
    ///   converted into `T`.
    pub async fn load<T: DeserializeOwned>(&self) -> Result<T, ProviderError> {
        let token = self
            .token
            .access_token()
            .await?
            .ok_or(ProviderError::AuthenticationFailed)?;
        let subtree = self.transport.get_subtree(&self.root, &token).await?;
        let mut revealed = BTreeMap::new();
        for value in &subtree.values {
            if matches!(value.value, ValueContent::Secret(_)) {
                let secret = self.transport.reveal_secret(&value.path, &token).await?;
                revealed.insert(value.path.clone(), secret);
            }
        }
        let json = subtree_to_json(&self.root, &subtree.values, &revealed)?;
        serde_json::from_value(json).map_err(|_| ProviderError::InvalidConversion)
    }

    /// The canonical configuration root this connection is confined to.
    ///
    /// Returned as a string slice so consumers depend only on this crate.
    /// Not secret; safe to log or include in diagnostics.
    #[must_use]
    pub fn root(&self) -> &str {
        self.root.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::{Provider, ProviderError};

    async fn connect_error(url: &str) -> ProviderError {
        match Provider::connect(url).await {
            Ok(_) => panic!("connect unexpectedly succeeded"),
            Err(error) => error,
        }
    }

    #[tokio::test]
    async fn connect_rejects_malformed_url_before_any_network() {
        assert_eq!(
            connect_error("not-a-connection-url").await,
            ProviderError::MalformedUrl
        );
    }

    #[tokio::test]
    async fn connect_rejects_human_device_flow_url_before_any_network() {
        let url = "https://config.example.test/apps/api#v=1&issuer=https%3A%2F%2Fauth.example.test%2Fapplication%2Fo%2Fconfig%2F&client_id=sovereign-config";
        assert_eq!(
            connect_error(url).await,
            ProviderError::UnsupportedCredential
        );
    }
}
