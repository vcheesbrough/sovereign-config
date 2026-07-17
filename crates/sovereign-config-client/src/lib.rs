#![forbid(unsafe_code)]

use async_trait::async_trait;
use sovereign_config_core::{
    AuthenticationStatus, ClientError, ConfigPath, DeleteMetadata, ErrorKind, PROTOCOL_VERSION,
    PlainValue, PutMetadata, ReplaceMetadata, Secret, ServiceStatus, SubTreeValue, Timestamp,
    ValueListing, ValueSubTree,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RpcCode {
    Unauthenticated,
    PermissionDenied,
    FailedPrecondition,
    InvalidArgument,
    NotFound,
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
        RpcCode::Unavailable => ClientError::new(ErrorKind::Unavailable, "service is unavailable"),
        RpcCode::Other => ClientError::new(ErrorKind::Internal, "request failed"),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionReply {
    pub application_version: String,
    pub protocol_version: String,
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
    async fn replace_subtree(
        &self,
        path: &ConfigPath,
        values: &[SubTreeValue],
        bearer: &Secret,
    ) -> Result<ReplaceMetadata, ClientError>;
    async fn delete_values(
        &self,
        path: &ConfigPath,
        recurse: bool,
        bearer: &Secret,
    ) -> Result<DeleteMetadata, ClientError>;
}

#[async_trait(?Send)]
pub trait AccessTokenProvider {
    async fn access_token(&self) -> Result<Option<Secret>, ClientError>;
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

    /// Atomically replaces every value at or below a selected path.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication, authorization, validation, or dependency error.
    pub async fn replace_subtree(
        &self,
        path: &ConfigPath,
        values: &[SubTreeValue],
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

    async fn required_token(&self) -> Result<Secret, ClientError> {
        self.authentication
            .access_token()
            .await?
            .ok_or_else(|| ClientError::new(ErrorKind::Unauthenticated, "authentication required"))
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
    /// # Errors
    ///
    /// Returns a bounded transport or protocol compatibility error.
    pub async fn service_status(&self) -> Result<ServiceStatus, ClientError> {
        let reply = self.transport.get_version(PROTOCOL_VERSION).await?;
        let status = ServiceStatus::negotiate(reply.application_version, reply.protocol_version);
        if !status.compatible {
            return Err(ClientError::new(
                ErrorKind::IncompatibleProtocol,
                "service protocol is incompatible",
            ));
        }
        Ok(status)
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
                application_version: "1.4.0".into(),
                protocol_version: protocol.into(),
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
