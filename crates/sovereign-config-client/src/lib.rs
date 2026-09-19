#![forbid(unsafe_code)]

use async_trait::async_trait;
use sovereign_config_core::{
    AddPathMetadata, AuthenticationStatus, ClientError, ConfigPath, ConnectionId, DeleteMetadata,
    DisplayName, ErrorKind, ManagedConnectionMetadata, ManagedPermissions, PlainValue,
    ProtocolVersion, ProvisionedManagedConnection, PutMetadata, ReplaceMetadata, RevealedSecret,
    Secret, SecretInput, ServiceStatus, SubTreeMutationValue, Timestamp, ValueListing, ValuePaths,
    ValueSubTree,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RpcCode {
    Unauthenticated,
    PermissionDenied,
    FailedPrecondition,
    InvalidArgument,
    NotFound,
    AlreadyExists,
    Unavailable,
    Other,
}

#[must_use]
pub fn map_rpc_status(code: RpcCode) -> ClientError {
    match code {
        RpcCode::Unauthenticated => {
            ClientError::new(ErrorKind::Unauthenticated, "authentication required")
        }
        RpcCode::PermissionDenied => {
            ClientError::new(ErrorKind::PermissionDenied, "permission denied")
        }
        RpcCode::FailedPrecondition => ClientError::new(
            ErrorKind::IncompatibleProtocol,
            "service protocol is incompatible",
        ),
        RpcCode::InvalidArgument => {
            ClientError::new(ErrorKind::InvalidRequest, "request is invalid")
        }
        RpcCode::NotFound => ClientError::new(ErrorKind::NotFound, "configuration value not found"),
        RpcCode::AlreadyExists => {
            ClientError::new(ErrorKind::Conflict, "configuration path already exists")
        }
        RpcCode::Unavailable => ClientError::new(ErrorKind::Unavailable, "service is unavailable"),
        RpcCode::Other => ClientError::new(ErrorKind::Internal, "request failed"),
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VersionReply {
    pub application_version: String,
    /// The version the session will speak, echoed by the server.
    pub protocol_version: String,
    /// Every version the server serves. Empty from a server older than 2.25.0,
    /// which [`ServiceStatus::negotiate`] treats as `[protocol_version]`.
    pub supported_protocol_versions: Vec<String>,
}

#[async_trait(?Send)]
pub trait Transport {
    async fn get_version(&self, protocol_version: &str) -> Result<VersionReply, ClientError>;
    async fn get_identity(&self, bearer: &Secret) -> Result<AuthenticationStatus, ClientError>;
}

#[async_trait(?Send)]
pub trait ValueTransport: Transport {
    async fn list_values(
        &self,
        path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<ValueListing, ClientError>;

    async fn get_subtree(
        &self,
        path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<ValueSubTree, ClientError>;
    async fn put_value(
        &self,
        path: &ConfigPath,
        value: &PlainValue,
        bearer: &Secret,
    ) -> Result<PutMetadata, ClientError>;
    async fn put_secret(
        &self,
        path: &ConfigPath,
        value: &SecretInput,
        bearer: &Secret,
    ) -> Result<PutMetadata, ClientError>;
    async fn replace_subtree(
        &self,
        path: &ConfigPath,
        values: &[SubTreeMutationValue],
        bearer: &Secret,
    ) -> Result<ReplaceMetadata, ClientError>;
    async fn delete_values(
        &self,
        path: &ConfigPath,
        recurse: bool,
        bearer: &Secret,
    ) -> Result<DeleteMetadata, ClientError>;
    async fn reveal_secret(
        &self,
        path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<RevealedSecret, ClientError>;
    async fn add_value_path(
        &self,
        source: &ConfigPath,
        new_path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<AddPathMetadata, ClientError>;
    async fn list_value_paths(
        &self,
        path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<ValuePaths, ClientError>;
}

#[async_trait(?Send)]
pub trait ManagedConnectionTransport: Transport {
    async fn list_managed_connections(
        &self,
        bearer: &Secret,
    ) -> Result<Vec<ManagedConnectionMetadata>, ClientError>;
    async fn create_managed_connection(
        &self,
        display_name: &DisplayName,
        root: &ConfigPath,
        permissions: &ManagedPermissions,
        bearer: &Secret,
    ) -> Result<ProvisionedManagedConnection, ClientError>;
    async fn rotate_managed_connection(
        &self,
        connection_id: &ConnectionId,
        bearer: &Secret,
    ) -> Result<ProvisionedManagedConnection, ClientError>;
    async fn revoke_managed_connection(
        &self,
        connection_id: &ConnectionId,
        bearer: &Secret,
    ) -> Result<(), ClientError>;
}

#[async_trait(?Send)]
pub trait AccessTokenProvider {
    async fn access_token(&self) -> Result<Option<Secret>, ClientError>;
}

impl<T, A> Client<T, A>
where
    T: ManagedConnectionTransport,
    A: AccessTokenProvider,
{
    /// Lists safe metadata for connections rooted in manageable paths.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication, authorization, or dependency error.
    pub async fn list_managed_connections(
        &self,
    ) -> Result<Vec<ManagedConnectionMetadata>, ClientError> {
        let token = self.required_token().await?;
        self.transport.list_managed_connections(&token).await
    }

    /// Creates one managed connection with the selected permissions on its
    /// root and returns its one-time URL.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication, authorization, validation, or
    /// dependency error; no URL is returned on any failure.
    pub async fn create_managed_connection(
        &self,
        display_name: &DisplayName,
        root: &ConfigPath,
        permissions: &ManagedPermissions,
    ) -> Result<ProvisionedManagedConnection, ClientError> {
        let token = self.required_token().await?;
        self.transport
            .create_managed_connection(display_name, root, permissions, &token)
            .await
    }

    /// Rotates one managed connection credential and returns its one-time URL.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication, authorization, validation,
    /// missing-connection, or dependency error; ambiguous rotation returns an
    /// error and no URL.
    pub async fn rotate_managed_connection(
        &self,
        connection_id: &ConnectionId,
    ) -> Result<ProvisionedManagedConnection, ClientError> {
        let token = self.required_token().await?;
        self.transport
            .rotate_managed_connection(connection_id, &token)
            .await
    }

    /// Permanently revokes one managed connection without returning a secret.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication, authorization, validation,
    /// missing-connection, or dependency error.
    pub async fn revoke_managed_connection(
        &self,
        connection_id: &ConnectionId,
    ) -> Result<(), ClientError> {
        let token = self.required_token().await?;
        self.transport
            .revoke_managed_connection(connection_id, &token)
            .await
    }
}

impl<T, A> Client<T, A>
where
    T: ValueTransport,
    A: AccessTokenProvider,
{
    /// Lists readable values directly below a namespace and its existing readable paths.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication, validation, or dependency error.
    pub async fn list_values(&self, path: &ConfigPath) -> Result<ValueListing, ClientError> {
        let token = self.required_token().await?;
        self.transport.list_values(path, &token).await
    }

    /// Reads every configuration value at or below a selected path.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication, authorization, validation, missing-value,
    /// or dependency error.
    pub async fn get_subtree(&self, path: &ConfigPath) -> Result<ValueSubTree, ClientError> {
        let token = self.required_token().await?;
        self.transport.get_subtree(path, &token).await
    }

    /// Creates or replaces one exact configuration value without retrying.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication, authorization, validation, or dependency error.
    pub async fn put_value(
        &self,
        path: &ConfigPath,
        value: &PlainValue,
    ) -> Result<PutMetadata, ClientError> {
        let token = self.required_token().await?;
        self.transport.put_value(path, value, &token).await
    }

    /// Creates or replaces one exact secret without reading it back.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication, authorization, validation, or dependency error.
    pub async fn put_secret(
        &self,
        path: &ConfigPath,
        value: &SecretInput,
    ) -> Result<PutMetadata, ClientError> {
        let token = self.required_token().await?;
        self.transport.put_secret(path, value, &token).await
    }

    /// Atomically replaces every value at or below a selected path.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication, authorization, validation, or dependency error.
    pub async fn replace_subtree(
        &self,
        path: &ConfigPath,
        values: &[SubTreeMutationValue],
    ) -> Result<ReplaceMetadata, ClientError> {
        let token = self.required_token().await?;
        self.transport.replace_subtree(path, values, &token).await
    }

    /// Permanently deletes one exact value or a complete subtree without retrying.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication, authorization, validation, missing-value,
    /// or dependency error.
    pub async fn delete_values(
        &self,
        path: &ConfigPath,
        recurse: bool,
    ) -> Result<DeleteMetadata, ClientError> {
        let token = self.required_token().await?;
        self.transport.delete_values(path, recurse, &token).await
    }

    /// Explicitly reveals one secret value.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication, authorization, validation, missing-value,
    /// classification, or dependency error.
    pub async fn reveal_secret(&self, path: &ConfigPath) -> Result<RevealedSecret, ClientError> {
        let token = self.required_token().await?;
        self.transport.reveal_secret(path, &token).await
    }

    /// Exposes an existing value at an additional canonical path.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication, authorization, validation, missing-value,
    /// conflict, or dependency error.
    pub async fn add_value_path(
        &self,
        source: &ConfigPath,
        new_path: &ConfigPath,
    ) -> Result<AddPathMetadata, ClientError> {
        let token = self.required_token().await?;
        self.transport
            .add_value_path(source, new_path, &token)
            .await
    }

    /// Lists every path resolving to the same value that the caller may read.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication, authorization, validation, missing-value,
    /// or dependency error.
    pub async fn list_value_paths(&self, path: &ConfigPath) -> Result<ValuePaths, ClientError> {
        let token = self.required_token().await?;
        self.transport.list_value_paths(path, &token).await
    }
}

/// Validates a protobuf timestamp before exposing it to presentation code.
///
/// # Errors
///
/// Returns a bounded error when the timestamp is outside the supported range.
pub fn timestamp(seconds: i64, nanos: i32) -> Result<Timestamp, ClientError> {
    let timestamp = Timestamp { seconds, nanos };
    timestamp.to_system_time()?;
    Ok(timestamp)
}

pub struct Client<T, A> {
    transport: T,
    authentication: A,
}

impl<T, A> Client<T, A>
where
    T: Transport,
    A: AccessTokenProvider,
{
    pub const fn new(transport: T, authentication: A) -> Self {
        Self {
            transport,
            authentication,
        }
    }

    /// Fetches and negotiates the service version without caching or retrying.
    ///
    /// Asks for the newest version this build speaks and settles on the highest
    /// version the server also serves, so a server ahead of this build still
    /// works.
    ///
    /// # Errors
    ///
    /// Returns a bounded transport or protocol compatibility error.
    pub async fn service_status(&self) -> Result<ServiceStatus, ClientError> {
        let reply = self
            .transport
            .get_version(ProtocolVersion::PREFERRED.as_str())
            .await?;
        ServiceStatus::negotiate(
            reply.application_version,
            &reply.protocol_version,
            &reply.supported_protocol_versions,
        )
    }

    /// Fetches authenticated identity state with a freshly supplied access token.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication or transport error.
    pub async fn authentication_status(&self) -> Result<AuthenticationStatus, ClientError> {
        let token = self.authentication.access_token().await?.ok_or_else(|| {
            ClientError::new(ErrorKind::Unauthenticated, "authentication required")
        })?;
        self.transport.get_identity(&token).await
    }

    async fn required_token(&self) -> Result<Secret, ClientError> {
        self.authentication
            .access_token()
            .await?
            .ok_or_else(|| ClientError::new(ErrorKind::Unauthenticated, "authentication required"))
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, rc::Rc};

    use async_trait::async_trait;
    use sovereign_config_core::{AuthenticationStatus, ClientError, ErrorKind, Secret};

    use super::{AccessTokenProvider, Client, RpcCode, Transport, VersionReply, map_rpc_status};

    struct CountingTransport(Rc<Cell<usize>>);

    #[async_trait(?Send)]
    impl Transport for CountingTransport {
        async fn get_version(&self, protocol: &str) -> Result<VersionReply, ClientError> {
            self.0.set(self.0.get() + 1);
            Ok(VersionReply {
                application_version: "1.5.0".into(),
                protocol_version: protocol.into(),
                supported_protocol_versions: vec![protocol.into()],
            })
        }

        async fn get_identity(&self, _: &Secret) -> Result<AuthenticationStatus, ClientError> {
            self.0.set(self.0.get() + 1);
            Ok(AuthenticationStatus {
                authenticated: true,
            })
        }
    }

    struct Authentication;

    #[async_trait(?Send)]
    impl AccessTokenProvider for Authentication {
        async fn access_token(&self) -> Result<Option<Secret>, ClientError> {
            Ok(Some(Secret::new("token-sentinel")))
        }
    }

    #[tokio::test]
    async fn each_operation_calls_transport_without_cache_or_retry() {
        let calls = Rc::new(Cell::new(0));
        let client = Client::new(CountingTransport(Rc::clone(&calls)), Authentication);
        client.service_status().await.unwrap();
        client.service_status().await.unwrap();
        client.authentication_status().await.unwrap();
        assert_eq!(calls.get(), 3);
    }

    #[test]
    fn status_mapping_is_bounded() {
        assert_eq!(
            map_rpc_status(RpcCode::Unauthenticated).kind,
            ErrorKind::Unauthenticated
        );
        assert_eq!(
            map_rpc_status(RpcCode::Unavailable).to_string(),
            "service is unavailable"
        );
    }
}
