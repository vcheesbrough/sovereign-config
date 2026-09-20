//! The `v3` wire shim over [`ManagedConnectionsService`]: translation only.
//!
//! Each RPC builds the call context, restates its message in the shared
//! implementation's version-free terms, and encodes the result as `v3`. It
//! validates nothing, decides nothing and records no metric. Input it cannot
//! translate — a permission selection with an unknown or no tag — is handed
//! down as `None` for the shared implementation to reject, so every protocol
//! version fails a bad request with the same error and in the same order. A
//! second version is a sibling of this file, never an edit to the shared
//! implementation.

use std::sync::Arc;

use sovereign_config_core::{ManagedConnectionState, ManagedPermissions};
use sovereign_config_proto::sovereign::config::v3::{
    self, CreateManagedConnectionRequest, CreateManagedConnectionResponse,
    ListManagedConnectionsRequest, ListManagedConnectionsResponse, RevokeManagedConnectionRequest,
    RevokeManagedConnectionResponse, RotateManagedConnectionRequest,
    RotateManagedConnectionResponse, managed_connections_server::ManagedConnections,
};
use tonic::{Request, Response, Status};

use super::ManagedConnectionsService;
use super::wire::{ConnectionMetadata, ProvisionedConnection};
use crate::rpc::{CallContext, to_proto_timestamp};

pub(crate) struct V3ManagedConnections {
    pub(super) shared: Arc<ManagedConnectionsService>,
}

impl V3ManagedConnections {
    pub(crate) const fn new(shared: Arc<ManagedConnectionsService>) -> Self {
        Self { shared }
    }
}

const fn state(state: ManagedConnectionState) -> v3::ManagedConnectionState {
    match state {
        ManagedConnectionState::Provisioning => v3::ManagedConnectionState::Provisioning,
        ManagedConnectionState::Active => v3::ManagedConnectionState::Active,
        ManagedConnectionState::RotationUnknown => v3::ManagedConnectionState::RotationUnknown,
        ManagedConnectionState::Revoking => v3::ManagedConnectionState::Revoking,
        ManagedConnectionState::CleanupRequired => v3::ManagedConnectionState::CleanupRequired,
    }
}

fn metadata(metadata: ConnectionMetadata) -> v3::ManagedConnectionMetadata {
    v3::ManagedConnectionMetadata {
        connection_id: metadata.connection_id,
        display_name: metadata.display_name,
        root: metadata.root,
        state: state(metadata.state) as i32,
        permissions: metadata.permissions.to_proto(),
        created_at: Some(to_proto_timestamp(metadata.created_at)),
        updated_at: Some(to_proto_timestamp(metadata.updated_at)),
    }
}

/// The metadata and the URL a create or rotate returns exactly once.
fn provisioned(connection: ProvisionedConnection) -> (v3::ManagedConnectionMetadata, String) {
    let connection_url = connection.connection_url.canonical().expose().to_owned();
    (metadata(connection.metadata), connection_url)
}

#[tonic::async_trait]
impl ManagedConnections for V3ManagedConnections {
    async fn list_managed_connections(
        &self,
        request: Request<ListManagedConnectionsRequest>,
    ) -> Result<Response<ListManagedConnectionsResponse>, Status> {
        let context = CallContext::from_request(&request);
        let connections = self.shared.list_managed_connections(&context).await?;
        Ok(Response::new(ListManagedConnectionsResponse {
            connections: connections.into_iter().map(metadata).collect(),
        }))
    }

    async fn create_managed_connection(
        &self,
        request: Request<CreateManagedConnectionRequest>,
    ) -> Result<Response<CreateManagedConnectionResponse>, Status> {
        let context = CallContext::from_request(&request);
        let message = request.get_ref();
        let permissions = ManagedPermissions::from_proto(&message.permissions).ok();
        let (metadata, connection_url) = provisioned(
            self.shared
                .create_managed_connection(
                    &context,
                    &message.display_name,
                    &message.root,
                    permissions,
                )
                .await?,
        );
        Ok(Response::new(CreateManagedConnectionResponse {
            metadata: Some(metadata),
            connection_url,
        }))
    }

    async fn rotate_managed_connection(
        &self,
        request: Request<RotateManagedConnectionRequest>,
    ) -> Result<Response<RotateManagedConnectionResponse>, Status> {
        let context = CallContext::from_request(&request);
        let (metadata, connection_url) = provisioned(
            self.shared
                .rotate_managed_connection(&context, &request.get_ref().connection_id)
                .await?,
        );
        Ok(Response::new(RotateManagedConnectionResponse {
            metadata: Some(metadata),
            connection_url,
        }))
    }

    async fn revoke_managed_connection(
        &self,
        request: Request<RevokeManagedConnectionRequest>,
    ) -> Result<Response<RevokeManagedConnectionResponse>, Status> {
        let context = CallContext::from_request(&request);
        self.shared
            .revoke_managed_connection(&context, &request.get_ref().connection_id)
            .await?;
        Ok(Response::new(RevokeManagedConnectionResponse {}))
    }
}
