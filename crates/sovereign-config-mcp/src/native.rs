//! Production [`Backend`] backed by the public client library and the native
//! transport/credential/OIDC layer.
//!
//! Every operation resolves the selected profile, connects, negotiates the
//! protocol version, and mints a fresh access token per call — the same
//! no-cache, no-shortcut path the first-party CLI uses. Authorization is always
//! the server's decision; this adapter never pre-authorizes, widens a request,
//! or expands a delegated prefix.

use async_trait::async_trait;
use sovereign_config_client::{AccessTokenProvider, Client, negotiate};
use sovereign_config_core::{
    AddPathMetadata, AuthenticationStatus, ClientError, ConfigPath, ConnectionId, ConnectionUrl,
    DeleteMetadata, DisplayName, ErrorKind, ManagedConnectionMetadata, ManagedPermissions,
    PlainValue, ProvisionedManagedConnection, PutMetadata, ReplaceMetadata, RevealedSecret, Secret,
    SecretInput, ServiceStatus, SubTreeMutationValue, ValueListing, ValuePaths, ValueSubTree,
};
use sovereign_config_native::{
    CredentialStore, DeviceFlowClient, ProfileStore, TonicChannel, TonicTransport,
    default_credential_directory, default_profile_path,
};
use tokio::sync::mpsc::UnboundedSender;

use crate::backend::{Backend, LoginPrompt, ServiceReport};

/// A live administration backend bound to one profile name (or the default).
pub struct NativeBackend {
    profile: Option<String>,
}

impl NativeBackend {
    #[must_use]
    pub const fn new(profile: Option<String>) -> Self {
        Self { profile }
    }

    /// Resolves the selected profile's connection. Re-read on every call so a
    /// profile edit is picked up without restarting and nothing is cached.
    fn connection(&self) -> Result<ConnectionUrl, ClientError> {
        ProfileStore::new(default_profile_path()?).connection(self.profile.as_deref())
    }

    fn credential_store(connection: &ConnectionUrl) -> Result<CredentialStore, ClientError> {
        Ok(CredentialStore::new(
            &default_credential_directory()?,
            connection,
        ))
    }

    async fn discover(connection: &ConnectionUrl) -> Result<DeviceFlowClient, ClientError> {
        DeviceFlowClient::discover(connection.issuer(), connection.client_id().to_owned()).await
    }

    /// Mints a fresh access token, refreshing or using client-credentials as the
    /// profile dictates. Returns `None` only when no stored human credential
    /// exists (logged out).
    async fn maybe_access_token(connection: &ConnectionUrl) -> Result<Option<Secret>, ClientError> {
        if let Some(authentication) = connection.client_authentication() {
            let token = Self::discover(connection)
                .await?
                .client_credentials(authentication)
                .await?
                .access_token;
            return Ok(Some(token));
        }
        let store = Self::credential_store(connection)?;
        let Some(refresh) = store.load()? else {
            return Ok(None);
        };
        let oidc = Self::discover(connection).await?;
        let tokens = match oidc.refresh(&refresh).await {
            Ok(tokens) => tokens,
            Err(error) if error.kind == ErrorKind::Unauthenticated => {
                store.delete()?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        if let Some(rotated) = &tokens.refresh_token {
            store.store(rotated)?;
        }
        Ok(Some(tokens.access_token))
    }

    async fn access_token(connection: &ConnectionUrl) -> Result<Secret, ClientError> {
        Self::maybe_access_token(connection)
            .await?
            .ok_or_else(|| ClientError::new(ErrorKind::Unauthenticated, "authentication required"))
    }

    /// Connects, negotiates the protocol version, and returns an authenticated
    /// client. Version negotiation happens before any token is used so an
    /// incompatible service fails fast without touching credentials.
    async fn operational_client(
        &self,
    ) -> Result<Client<TonicTransport, InMemoryToken>, ClientError> {
        let connection = self.connection()?;
        let (_, transport) = Self::negotiated(&connection).await?;
        let token = Self::access_token(&connection).await?;
        Ok(Client::new(transport, InMemoryToken(token)))
    }

    /// Connects and negotiates, returning what the service reported together
    /// with the transport that speaks it. The two always travel as a pair, so
    /// what this backend reports is what its later calls are routed on.
    async fn negotiated(
        connection: &ConnectionUrl,
    ) -> Result<(ServiceStatus, TonicTransport), ClientError> {
        let channel = TonicChannel::connect(connection.endpoint().to_owned()).await?;
        let status = negotiate(&channel).await?;
        let transport = channel.speaking(status.protocol_version);
        Ok((status, transport))
    }
}

#[async_trait(?Send)]
impl Backend for NativeBackend {
    async fn service_status(&self) -> Result<ServiceReport, ClientError> {
        let (status, transport) = Self::negotiated(&self.connection()?).await?;
        // The version the `status` tool prints is read back off the transport
        // that would carry this session's traffic, rather than reported
        // alongside it — so an operator is never told a version the client is
        // not the one dialling. The application version comes from a versioned
        // call on that same transport: the handshake carries versions only.
        Ok(ServiceReport {
            application_version: transport.dialer_version().await?.application_version,
            protocol_version: transport.protocol_version(),
            deprecation_date: status.deprecation_date,
        })
    }

    async fn authentication_status(&self) -> Result<AuthenticationStatus, ClientError> {
        let connection = self.connection()?;
        let Some(token) = Self::maybe_access_token(&connection).await? else {
            return Ok(AuthenticationStatus {
                authenticated: false,
            });
        };
        let (_, transport) = Self::negotiated(&connection).await?;
        Client::new(transport, InMemoryToken(token))
            .authentication_status()
            .await
    }

    async fn login(&self, prompts: UnboundedSender<LoginPrompt>) -> Result<(), ClientError> {
        let connection = self.connection()?;
        if connection.client_authentication().is_some() {
            return Err(ClientError::new(
                ErrorKind::InvalidRequest,
                "profile uses managed authentication",
            ));
        }
        let store = Self::credential_store(&connection)?;
        let oidc = Self::discover(&connection).await?;
        let authorization = oidc.begin().await?;
        // Surface the verification details before polling so the caller can act
        // on them; a dropped receiver simply means no one is listening.
        let _ = prompts.send(LoginPrompt {
            verification_uri: authorization.verification_uri.clone(),
            user_code: authorization.user_code.clone(),
            verification_uri_complete: authorization.verification_uri_complete.clone(),
        });
        let tokens = oidc.poll(authorization).await?;
        let refresh = tokens.refresh_token.ok_or_else(|| {
            ClientError::new(
                ErrorKind::Unavailable,
                "the identity provider did not issue a refresh credential",
            )
        })?;
        store.store(&refresh)?;
        Ok(())
    }

    async fn logout(&self) -> Result<(), ClientError> {
        let connection = self.connection()?;
        if connection.client_authentication().is_some() {
            return Err(ClientError::new(
                ErrorKind::InvalidRequest,
                "profile uses managed authentication",
            ));
        }
        Self::credential_store(&connection)?.delete()
    }

    async fn get_subtree(&self, path: &ConfigPath) -> Result<ValueSubTree, ClientError> {
        self.operational_client().await?.get_subtree(path).await
    }

    async fn list_values(&self, path: &ConfigPath) -> Result<ValueListing, ClientError> {
        self.operational_client().await?.list_values(path).await
    }

    async fn put_value(
        &self,
        path: &ConfigPath,
        value: &PlainValue,
    ) -> Result<PutMetadata, ClientError> {
        self.operational_client()
            .await?
            .put_value(path, value)
            .await
    }

    async fn put_secret(
        &self,
        path: &ConfigPath,
        value: &SecretInput,
    ) -> Result<PutMetadata, ClientError> {
        self.operational_client()
            .await?
            .put_secret(path, value)
            .await
    }

    async fn replace_subtree(
        &self,
        path: &ConfigPath,
        values: &[SubTreeMutationValue],
    ) -> Result<ReplaceMetadata, ClientError> {
        self.operational_client()
            .await?
            .replace_subtree(path, values)
            .await
    }

    async fn delete_values(
        &self,
        path: &ConfigPath,
        recurse: bool,
    ) -> Result<DeleteMetadata, ClientError> {
        self.operational_client()
            .await?
            .delete_values(path, recurse)
            .await
    }

    async fn reveal_secret(&self, path: &ConfigPath) -> Result<RevealedSecret, ClientError> {
        self.operational_client().await?.reveal_secret(path).await
    }

    async fn add_value_path(
        &self,
        source: &ConfigPath,
        new_path: &ConfigPath,
    ) -> Result<AddPathMetadata, ClientError> {
        self.operational_client()
            .await?
            .add_value_path(source, new_path)
            .await
    }

    async fn list_value_paths(&self, path: &ConfigPath) -> Result<ValuePaths, ClientError> {
        self.operational_client()
            .await?
            .list_value_paths(path)
            .await
    }

    async fn list_connections(&self) -> Result<Vec<ManagedConnectionMetadata>, ClientError> {
        self.operational_client()
            .await?
            .list_managed_connections()
            .await
    }

    async fn create_connection(
        &self,
        display_name: &DisplayName,
        root: &ConfigPath,
        permissions: &ManagedPermissions,
    ) -> Result<ProvisionedManagedConnection, ClientError> {
        self.operational_client()
            .await?
            .create_managed_connection(display_name, root, permissions)
            .await
    }

    async fn rotate_connection(
        &self,
        connection_id: &ConnectionId,
    ) -> Result<ProvisionedManagedConnection, ClientError> {
        self.operational_client()
            .await?
            .rotate_managed_connection(connection_id)
            .await
    }

    async fn revoke_connection(&self, connection_id: &ConnectionId) -> Result<(), ClientError> {
        self.operational_client()
            .await?
            .revoke_managed_connection(connection_id)
            .await
    }
}

/// Supplies a pre-fetched access token to the client for one operation.
struct InMemoryToken(Secret);

#[async_trait(?Send)]
impl AccessTokenProvider for InMemoryToken {
    async fn access_token(&self) -> Result<Option<Secret>, ClientError> {
        Ok(Some(self.0.clone()))
    }
}
