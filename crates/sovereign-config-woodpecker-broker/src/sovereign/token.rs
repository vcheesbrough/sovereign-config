//! A caching client-credentials token provider.
//!
//! `sovereign-config-provider` deliberately acquires a fresh token per load.
//! The broker is a long-lived service on the pipeline-start path, so it caches
//! instead — but conservatively:
//!
//! - the cached lifetime is `min(expires_in - skew, ceiling)`, floored, so a
//!   provider that reports an implausibly long life still gets re-checked;
//! - `expires_in` is optional in OAuth 2.0, so its absence falls back to the
//!   ceiling rather than caching indefinitely;
//! - the cache can be invalidated, and the reader does so on any
//!   `Unauthenticated` response. Without that, a token revoked before it lapsed
//!   would break every request until the TTL ran out.
//!
//! Lives on the reader thread, so interior mutability is a plain [`RefCell`]
//! and the provider is `!Send` like everything else here.

use std::{
    cell::RefCell,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use sovereign_config_client::AccessTokenProvider;
use sovereign_config_core::{ClientError, Secret};
use sovereign_config_native::DeviceFlowClient;

/// Re-acquire this far before the reported expiry, to cover the round trip and
/// clock skew between the broker and the issuer.
const REFRESH_SKEW: Duration = Duration::from_secs(30);
/// Never cache for less than this, so a pathological `expires_in` cannot turn
/// every request into two round trips.
const MIN_TTL: Duration = Duration::from_secs(15);

pub(crate) struct CachedTokenProvider {
    issuer: String,
    client_id: String,
    authentication: Secret,
    ceiling: Duration,
    cached: RefCell<Option<(Secret, Instant)>>,
}

impl CachedTokenProvider {
    pub(crate) fn new(
        issuer: String,
        client_id: String,
        authentication: Secret,
        ceiling: Duration,
    ) -> Self {
        Self {
            issuer,
            client_id,
            authentication,
            ceiling,
            cached: RefCell::new(None),
        }
    }

    /// Drops the cached token so the next request acquires a fresh one.
    ///
    /// Called when the service rejects a token the cache still considered
    /// valid — the authoritative signal that it is not.
    pub(crate) fn invalidate(&self) {
        self.cached.borrow_mut().take();
    }

    fn cached_token(&self) -> Option<Secret> {
        let cached = self.cached.borrow();
        let (token, expires_at) = cached.as_ref()?;
        (Instant::now() < *expires_at).then(|| token.clone())
    }

    fn lifetime(&self, reported: Option<Duration>) -> Duration {
        reported
            .map_or(self.ceiling, |life| life.saturating_sub(REFRESH_SKEW))
            .min(self.ceiling)
            .max(MIN_TTL)
    }
}

#[async_trait(?Send)]
impl AccessTokenProvider for CachedTokenProvider {
    async fn access_token(&self) -> Result<Option<Secret>, ClientError> {
        if let Some(token) = self.cached_token() {
            return Ok(Some(token));
        }
        let tokens = DeviceFlowClient::discover(&self.issuer, self.client_id.clone())
            .await?
            .client_credentials(&self.authentication)
            .await?;
        let expires_at = Instant::now() + self.lifetime(tokens.expires_in);
        *self.cached.borrow_mut() = Some((tokens.access_token.clone(), expires_at));
        Ok(Some(tokens.access_token))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use sovereign_config_core::Secret;

    use super::{CachedTokenProvider, MIN_TTL};

    fn provider(ceiling: Duration) -> CachedTokenProvider {
        CachedTokenProvider::new(
            "https://auth.example.test/".to_owned(),
            "broker".to_owned(),
            Secret::new("credential-sentinel"),
            ceiling,
        )
    }

    #[test]
    fn a_reported_lifetime_is_reduced_by_the_refresh_skew() {
        let provider = provider(Duration::from_secs(3600));
        assert_eq!(
            provider.lifetime(Some(Duration::from_secs(300))),
            Duration::from_secs(270)
        );
    }

    #[test]
    fn the_ceiling_caps_an_implausibly_long_lifetime() {
        let provider = provider(Duration::from_secs(300));
        assert_eq!(
            provider.lifetime(Some(Duration::from_secs(86_400))),
            Duration::from_secs(300)
        );
    }

    #[test]
    fn an_absent_lifetime_falls_back_to_the_ceiling_rather_than_forever() {
        let provider = provider(Duration::from_secs(120));
        assert_eq!(provider.lifetime(None), Duration::from_secs(120));
    }

    #[test]
    fn a_pathologically_short_lifetime_is_floored() {
        let generous = provider(Duration::from_secs(300));
        for reported in [Duration::from_secs(1), Duration::from_secs(31)] {
            assert_eq!(generous.lifetime(Some(reported)), MIN_TTL);
        }
        // Even a ceiling below the floor cannot drive it lower.
        assert_eq!(provider(Duration::from_secs(1)).lifetime(None), MIN_TTL);
    }

    #[test]
    fn invalidating_an_empty_cache_is_harmless() {
        let provider = provider(Duration::from_secs(300));
        provider.invalidate();
        assert!(provider.cached_token().is_none());
    }
}
