//! The one `ManagedConnections` adapter every protocol version's shim
//! instantiates. See `values/shim.rs` for why it is a macro: one adapter,
//! written once, pointed at each version's generated package in turn — never
//! copied, and never chained through another version's shim.

use sovereign_config_core::ManagedPermissions;
use tonic::Status;

use super::wire::invalid_request;

/// What a version's shim checks before it calls the shared implementation.
pub(super) trait Validation {
    /// A create's permission selection, as it translated. `None` when it had
    /// no version-free form: empty, unknown or unspecified.
    #[expect(
        clippy::result_large_err,
        reason = "tonic::Status is the crate's RPC error type and is returned by value"
    )]
    fn permissions(selection: Option<&ManagedPermissions>) -> Result<(), Status>;
}

/// **`v3`'s policy: validate nothing here**, and let the shared implementation
/// reject an untranslatable selection where `v3` always has.
pub(super) struct Deferred;

impl Validation for Deferred {
    fn permissions(_: Option<&ManagedPermissions>) -> Result<(), Status> {
        Ok(())
    }
}

/// **The policy from `v4` on:** an untranslatable selection is refused before
/// the shared implementation is called, with the shared implementation's own
/// wording.
pub(super) struct Upfront;

impl Validation for Upfront {
    fn permissions(selection: Option<&ManagedPermissions>) -> Result<(), Status> {
        selection.map(|_| ()).ok_or_else(invalid_request)
    }
}

/// Defines `$shim`, the tonic `ManagedConnections` impl for the generated
/// package the invoking module imports as `proto`, validating with
/// `$validation`. A refusal is counted through the shared implementation, so
/// the operation metric sees it exactly as it sees one the shared
/// implementation made.
macro_rules! managed_connections_shim {
    ($shim:ident, $validation:ty) => {
        pub(crate) struct $shim {
            pub(super) shared: std::sync::Arc<super::ManagedConnectionsService>,
        }

        impl $shim {
            pub(crate) const fn new(
                shared: std::sync::Arc<super::ManagedConnectionsService>,
            ) -> Self {
                Self { shared }
            }
        }

        const fn state(
            state: sovereign_config_core::ManagedConnectionState,
        ) -> proto::ManagedConnectionState {
            use sovereign_config_core::ManagedConnectionState as State;
            match state {
                State::Provisioning => proto::ManagedConnectionState::Provisioning,
                State::Active => proto::ManagedConnectionState::Active,
                State::RotationUnknown => proto::ManagedConnectionState::RotationUnknown,
                State::Revoking => proto::ManagedConnectionState::Revoking,
                State::CleanupRequired => proto::ManagedConnectionState::CleanupRequired,
            }
        }

        fn metadata(metadata: super::wire::ConnectionMetadata) -> proto::ManagedConnectionMetadata {
            proto::ManagedConnectionMetadata {
                connection_id: metadata.connection_id,
                display_name: metadata.display_name,
                root: metadata.root,
                state: state(metadata.state) as i32,
                permissions: metadata.permissions.to_proto(),
                created_at: Some(crate::rpc::to_proto_timestamp(metadata.created_at)),
                updated_at: Some(crate::rpc::to_proto_timestamp(metadata.updated_at)),
            }
        }

        /// The metadata and the URL a create or rotate returns exactly once.
        fn provisioned(
            connection: super::wire::ProvisionedConnection,
        ) -> (proto::ManagedConnectionMetadata, String) {
            let connection_url = connection.connection_url.canonical().expose().to_owned();
            (metadata(connection.metadata), connection_url)
        }

        #[tonic::async_trait]
        impl proto::managed_connections_server::ManagedConnections for $shim {
            async fn list_managed_connections(
                &self,
                request: tonic::Request<proto::ListManagedConnectionsRequest>,
            ) -> Result<tonic::Response<proto::ListManagedConnectionsResponse>, tonic::Status> {
                let context = crate::rpc::CallContext::from_request(&request);
                let connections = self.shared.list_managed_connections(&context).await?;
                Ok(tonic::Response::new(
                    proto::ListManagedConnectionsResponse {
                        connections: connections.into_iter().map(metadata).collect(),
                    },
                ))
            }

            async fn create_managed_connection(
                &self,
                request: tonic::Request<proto::CreateManagedConnectionRequest>,
            ) -> Result<tonic::Response<proto::CreateManagedConnectionResponse>, tonic::Status>
            {
                let context = crate::rpc::CallContext::from_request(&request);
                let message = request.get_ref();
                let permissions =
                    sovereign_config_core::ManagedPermissions::from_proto(&message.permissions)
                        .ok();
                <$validation as super::shim::Validation>::permissions(permissions.as_ref())
                    .map_err(|status| {
                        self.shared
                            .refused(crate::metrics::ManagedOperation::Create, status)
                    })?;
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
                Ok(tonic::Response::new(
                    proto::CreateManagedConnectionResponse {
                        metadata: Some(metadata),
                        connection_url,
                    },
                ))
            }

            async fn rotate_managed_connection(
                &self,
                request: tonic::Request<proto::RotateManagedConnectionRequest>,
            ) -> Result<tonic::Response<proto::RotateManagedConnectionResponse>, tonic::Status>
            {
                let context = crate::rpc::CallContext::from_request(&request);
                let (metadata, connection_url) = provisioned(
                    self.shared
                        .rotate_managed_connection(&context, &request.get_ref().connection_id)
                        .await?,
                );
                Ok(tonic::Response::new(
                    proto::RotateManagedConnectionResponse {
                        metadata: Some(metadata),
                        connection_url,
                    },
                ))
            }

            async fn revoke_managed_connection(
                &self,
                request: tonic::Request<proto::RevokeManagedConnectionRequest>,
            ) -> Result<tonic::Response<proto::RevokeManagedConnectionResponse>, tonic::Status>
            {
                let context = crate::rpc::CallContext::from_request(&request);
                self.shared
                    .revoke_managed_connection(&context, &request.get_ref().connection_id)
                    .await?;
                Ok(tonic::Response::new(
                    proto::RevokeManagedConnectionResponse {},
                ))
            }
        }
    };
}

pub(super) use managed_connections_shim;
