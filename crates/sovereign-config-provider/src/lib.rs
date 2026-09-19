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
//! // Field names are Sovereign Config path segments (lowercase, digits, `-`,
//! // and `_`), so nested structs mirror the path hierarchy and idiomatic
//! // snake_case field names map across directly.
//! #[derive(Deserialize)]
//! struct Database {
//!     url: String,
//!     password: String,
//! }
//!
//! #[derive(Deserialize)]
//! struct AppConfig {
//!     feature: String,
//!     database: Database,
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
//! This crate is distributed as tagged workspace source and targets the
//! workspace `rust-version`. It does **not** have to be built from the same tag
//! as the server it talks to: it speaks a set of protocol versions, and
//! [`Provider::connect`] negotiates the highest version both ends serve. A
//! server upgraded ahead of this build keeps working, so a server deploy does
//! not require redeploying the applications that consume it.
//!
//! A build fails only once the server has *retired* every version this crate
//! speaks — an announced, observable event rather than a side effect of an
//! upgrade. Either way it surfaces as [`ProviderError::IncompatibleProtocol`]:
//! from [`Provider::connect`] when no version is shared, and from
//! [`Provider::load`] for a provider that connected *before* the retirement,
//! whose next call reaches a route the server no longer has. See
//! `## Protocol versioning` in the repository `README.md` for the deprecation
//! procedure and the metric that gates it.
//!
//! Release 2.15.0 widened the canonical path grammar to permit `_` in segments.
//! A build older than 2.15.0 rejects such a path as non-canonical and fails the
//! whole response carrying it, so one underscored value breaks every
//! [`Provider::load`] over a subtree containing it — it does not degrade to a
//! partial result. Rebuild this crate against tag 2.15.0 or later before any
//! underscored path is created in the configuration you consume.
//!
//! # Async runtime
//!
//! The underlying transport is `!Send`; drive [`Provider::connect`] and
//! [`Provider::load`] on the task owning the runtime (a current-thread runtime,
//! or `spawn_local`/`LocalSet`), not on a `Send`-bound `tokio::spawn`.
//!
//! # `config` integration
//!
//! Enable the optional `config` feature for `SovereignConfigSource`, a
//! [`config`](https://docs.rs/config) source that loads the managed subtree when
//! the configuration is built.

#[cfg(feature = "config")]
mod config_source;
mod error;
mod mapping;
mod token;

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use sovereign_config_client::{AccessTokenProvider, ValueTransport, negotiate};
use sovereign_config_core::{ConfigPath, ConnectionUrl, ValueContent};
use sovereign_config_native::{TonicChannel, TonicTransport};

#[cfg(feature = "config")]
pub use config_source::SovereignConfigSource;
pub use error::ProviderError;
use mapping::{Tree, build_tree, tree_to_json};
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
    /// - [`ProviderError::IncompatibleProtocol`] — the service serves no
    ///   protocol version this release speaks.
    /// - [`ProviderError::Unavailable`] — the gRPC endpoint is unreachable.
    pub async fn connect(url: &str) -> Result<Self, ProviderError> {
        let connection = ConnectionUrl::parse(url)?;
        let authentication = connection
            .client_authentication()
            .ok_or(ProviderError::UnsupportedCredential)?
            .clone();
        let channel = TonicChannel::connect(connection.endpoint().to_owned()).await?;
        // The version negotiated here is the version every later `load` travels
        // on: `speaking` is the only way to a transport that can read values,
        // so the handshake's answer cannot be dropped on the floor.
        let transport = channel.speaking(negotiate(&channel).await?.protocol_version);
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
    /// Every stored value is text, and this method deserializes **strictly** —
    /// it does not coerce a leaf like `"8080"` into a numeric or boolean field.
    /// `T` therefore maps cleanly only when its leaves are `String`-shaped. For a
    /// typed `T` (integers, booleans, …), enable the `config` feature and load
    /// through `SovereignConfigSource`, or hand [`Provider::load_json`] to the
    /// [`config`](https://docs.rs/config) crate, both of which coerce string
    /// leaves to the target type.
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
        let json = tree_to_json(self.load_tree().await?);
        serde_json::from_value(json).map_err(|_| ProviderError::InvalidConversion)
    }

    /// Loads the connection's permitted subtree as a JSON string.
    ///
    /// Identical to [`Provider::load`] in what it reads and reveals, but returns
    /// the subtree serialized as pretty JSON instead of deserializing it. This is
    /// the ergonomic entry point for a layered configuration builder such as the
    /// [`config`](https://docs.rs/config) crate — hand the string to
    /// `File::from_str(.., FileFormat::Json)` as one source. Consumers using this
    /// need no `serde_json` dependency of their own.
    ///
    /// The returned string contains the real, revealed configuration values
    /// (including secrets), so treat it as sensitive: never log it or place it in
    /// diagnostics.
    ///
    /// # Errors
    ///
    /// Returns the same bounded, redacted [`ProviderError`] set as
    /// [`Provider::load`].
    pub async fn load_json(&self) -> Result<String, ProviderError> {
        let json = tree_to_json(self.load_tree().await?);
        serde_json::to_string_pretty(&json).map_err(|_| ProviderError::InvalidConversion)
    }

    /// Acquires one fresh token, reads the subtree, reveals every secret leaf,
    /// and nests the real values into a format-neutral tree relative to the root.
    ///
    /// This is the shared load path: `load`/`load_json` transcode the tree to
    /// JSON, while the `config` source transcodes it to `config::Value` — neither
    /// re-reads nor re-nests, and the `config` path never touches JSON.
    pub(crate) async fn load_tree(&self) -> Result<Tree, ProviderError> {
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
        build_tree(&self.root, &subtree.values, &revealed)
    }

    /// The canonical configuration root this connection is confined to.
    ///
    /// Returned as a string slice so consumers depend only on this crate.
    /// Not secret; safe to log or include in diagnostics.
    #[must_use]
    pub fn root(&self) -> &str {
        self.root.as_str()
    }

    /// The protocol version this connection negotiated, and the version every
    /// [`Provider::load`] travels on.
    ///
    /// Returned as a string slice so consumers depend only on this crate. Not
    /// secret; safe to log or include in diagnostics, and worth logging at
    /// startup — it is what the service's per-version traffic counters will
    /// attribute this application to.
    #[must_use]
    pub fn protocol_version(&self) -> &'static str {
        self.transport.protocol_version().as_str()
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
