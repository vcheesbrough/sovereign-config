//! The administration boundary the MCP server drives.
//!
//! Every capability the server exposes as a tool is a method here, expressed in
//! the shared client library's own domain types. Splitting this out as a trait
//! keeps the JSON-RPC/tool layer testable against a faithful mock that returns
//! the same [`ClientError`] classes the real gRPC transport produces, while the
//! production [`crate::native::NativeBackend`] speaks to a live server through
//! the public client library only.

use async_trait::async_trait;
use sovereign_config_core::{
    AuthenticationStatus, ClientError, ConfigPath, ConnectionId, DeleteMetadata, DisplayName,
    ManagedConnectionMetadata, ManagedPermissions, PlainValue, ProvisionedManagedConnection,
    PutMetadata, ReplaceMetadata, RevealedSecret, SecretInput, ServiceStatus, SubTreeMutationValue,
    ValueListing, ValueSubTree,
};
use tokio::sync::mpsc::UnboundedSender;

/// Non-secret device-authorization details surfaced to the caller while a
/// login is in progress. The device code itself is never included.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoginPrompt {
    pub verification_uri: String,
    pub user_code: String,
    pub verification_uri_complete: Option<String>,
}

/// The full set of administration operations the server can expose. Each call
/// is independent: implementations must not cache values or authorization
/// across calls, matching the client library's no-cache contract.
#[async_trait(?Send)]
pub trait Backend {
    async fn service_status(&self) -> Result<ServiceStatus, ClientError>;
    async fn authentication_status(&self) -> Result<AuthenticationStatus, ClientError>;

    /// Runs an explicit device-authorization login. The implementation sends a
    /// single [`LoginPrompt`] (verification URI and user code) on `prompts` as
    /// soon as the provider issues one, then polls to completion using the
    /// provider's interval and expiry before returning.
    async fn login(&self, prompts: UnboundedSender<LoginPrompt>) -> Result<(), ClientError>;
    async fn logout(&self) -> Result<(), ClientError>;

    async fn get_subtree(&self, path: &ConfigPath) -> Result<ValueSubTree, ClientError>;
    async fn list_values(&self, path: &ConfigPath) -> Result<ValueListing, ClientError>;
    async fn put_value(
        &self,
        path: &ConfigPath,
        value: &PlainValue,
    ) -> Result<PutMetadata, ClientError>;
    async fn put_secret(
        &self,
        path: &ConfigPath,
        value: &SecretInput,
    ) -> Result<PutMetadata, ClientError>;
    async fn replace_subtree(
        &self,
        path: &ConfigPath,
        values: &[SubTreeMutationValue],
    ) -> Result<ReplaceMetadata, ClientError>;
    async fn delete_values(
        &self,
        path: &ConfigPath,
        recurse: bool,
    ) -> Result<DeleteMetadata, ClientError>;
    async fn reveal_secret(&self, path: &ConfigPath) -> Result<RevealedSecret, ClientError>;

    async fn list_connections(&self) -> Result<Vec<ManagedConnectionMetadata>, ClientError>;
    async fn create_connection(
        &self,
        display_name: &DisplayName,
        root: &ConfigPath,
        permissions: &ManagedPermissions,
    ) -> Result<ProvisionedManagedConnection, ClientError>;
    async fn rotate_connection(
        &self,
        connection_id: &ConnectionId,
    ) -> Result<ProvisionedManagedConnection, ClientError>;
    async fn revoke_connection(&self, connection_id: &ConnectionId) -> Result<(), ClientError>;
}
