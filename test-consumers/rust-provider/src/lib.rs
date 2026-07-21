//! External consumer fixture for `sovereign-config-provider`.
//!
//! This crate depends only on the provider's public API — no
//! `sovereign-config-core`, `-client`, or `-native` — proving that a downstream
//! application can compile against the tagged provider source and load typed
//! configuration from a managed connection root.
#![forbid(unsafe_code)]

use serde::Deserialize;
use sovereign_config_provider::{Provider, ProviderError};

/// A representative application configuration loaded from a managed root.
#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub database_url: String,
    pub feature_flag: String,
}

/// Connects with a managed connection URL and loads typed configuration.
///
/// The success path is compiled here and exercised for real against a
/// provisioned connection in the development smoke sequence; the offline tests
/// below cover the pre-network rejection paths.
///
/// # Errors
///
/// Returns the [`ProviderError`] surfaced by [`Provider::connect`] or
/// [`Provider::load`].
pub async fn load_config(url: &str) -> Result<AppConfig, ProviderError> {
    Provider::connect(url).await?.load().await
}

/// The connection's root is a plain `&str`, so reading it needs no Sovereign
/// Config core/client/native type — only this crate.
#[must_use]
pub fn connected_root(provider: &Provider) -> &str {
    provider.root()
}

#[cfg(test)]
mod tests {
    use super::load_config;
    use sovereign_config_provider::ProviderError;

    #[tokio::test]
    async fn malformed_url_is_rejected_without_network() {
        let error = load_config("not-a-connection-url").await.unwrap_err();
        assert_eq!(error, ProviderError::MalformedUrl);
    }

    #[tokio::test]
    async fn human_device_flow_url_is_rejected_without_network() {
        let url = "https://config.example.test/apps/api#v=1&issuer=https%3A%2F%2Fauth.example.test%2Fapplication%2Fo%2Fconfig%2F&client_id=sovereign-config";
        let error = load_config(url).await.unwrap_err();
        assert_eq!(error, ProviderError::UnsupportedCredential);
    }
}
