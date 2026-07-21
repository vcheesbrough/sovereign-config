use async_trait::async_trait;
use sovereign_config_client::AccessTokenProvider;
use sovereign_config_core::{ClientError, Secret};
use sovereign_config_native::DeviceFlowClient;

/// A client-credentials [`AccessTokenProvider`] for a managed connection.
///
/// Every call to [`AccessTokenProvider::access_token`] performs a fresh OIDC
/// discovery and a fresh `client_credentials` grant against the connection's
/// issuer. No token is stored between calls, so the "no token caching" contract
/// holds regardless of how often the client asks for one.
pub(crate) struct ManagedTokenProvider {
    issuer: String,
    client_id: String,
    authentication: Secret,
}

impl ManagedTokenProvider {
    pub(crate) fn new(issuer: String, client_id: String, authentication: Secret) -> Self {
        Self {
            issuer,
            client_id,
            authentication,
        }
    }
}

#[async_trait(?Send)]
impl AccessTokenProvider for ManagedTokenProvider {
    async fn access_token(&self) -> Result<Option<Secret>, ClientError> {
        let tokens = DeviceFlowClient::discover(&self.issuer, self.client_id.clone())
            .await?
            .client_credentials(&self.authentication)
            .await?;
        Ok(Some(tokens.access_token))
    }
}
