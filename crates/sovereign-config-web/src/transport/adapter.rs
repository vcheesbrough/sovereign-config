//! The one browser dialer every protocol version instantiates.
//!
//! Each version's generated messages live in their own package, and its routes
//! are plain strings naming that package, so one dialer cannot be written
//! against all of them as ordinary code. [`version_dialer`] is that dialer,
//! written once: a version's module imports its generated package as `proto`
//! and invokes it with the version and its label, then adds whatever that
//! version alone has — today, how it answers an audit query. It is never copied
//! and never chained, so retiring a version is still deleting one file.

/// Defines `Dialer` and its routes for `$version`, whose package label is
/// `$label`, over the messages the invoking module imports as `proto`, with
/// the imports its body needs — which the invoking module may use too.
macro_rules! version_dialer {
    ($version:expr, $label:literal) => {
        use async_trait::async_trait;
        use sovereign_config_client::{
            AuditTransport, ManagedConnectionTransport, SessionTransport, Transport,
            ValueTransport, VersionReply, timestamp,
        };
        use sovereign_config_core::{
            AddPathMetadata, AuditPage, AuditQuery, AuthenticationStatus, ClientError, ConfigPath,
            ConnectionId, ConnectionUrl, DeleteMetadata, DisplayName, ListedValue,
            ManagedConnectionMetadata, ManagedConnectionState, ManagedPermissions, MaskedSecret,
            PlainValue, ProtocolVersion, ProvisionedManagedConnection, PutMetadata,
            ReplaceMetadata, RevealedConnectionUrl, RevealedSecret, Secret, SecretInput,
            SubTreeMutationContent, SubTreeMutationValue, SubTreeValue, Timestamp, ValueContent,
            ValueListing, ValuePaths, ValueSubTree,
        };

        use crate::browser::browser_error;

        use super::grpc_unary;

        /// The version this module speaks. Reported as the session's version,
        /// so it is read from the same place the routes come from.
        const VERSION: ProtocolVersion = $version;

        const GET_VERSION: &str = concat!("/sovereign.config.", $label, ".System/GetVersion");
        const GET_IDENTITY: &str = concat!("/sovereign.config.", $label, ".System/GetIdentity");
        const LIST_VALUES: &str =
            concat!("/sovereign.config.", $label, ".Configuration/ListValues");
        const GET_SUB_TREE: &str =
            concat!("/sovereign.config.", $label, ".Configuration/GetSubTree");
        const PUT_VALUE: &str = concat!("/sovereign.config.", $label, ".Configuration/PutValue");
        const REPLACE_SUB_TREE: &str = concat!(
            "/sovereign.config.",
            $label,
            ".Configuration/ReplaceSubTree"
        );
        const DELETE_VALUES: &str =
            concat!("/sovereign.config.", $label, ".Configuration/DeleteValues");
        const REVEAL_SECRET: &str =
            concat!("/sovereign.config.", $label, ".Configuration/RevealSecret");
        const ADD_VALUE_PATH: &str =
            concat!("/sovereign.config.", $label, ".Configuration/AddValuePath");
        const LIST_VALUE_PATHS: &str = concat!(
            "/sovereign.config.",
            $label,
            ".Configuration/ListValuePaths"
        );
        const LIST_MANAGED_CONNECTIONS: &str = concat!(
            "/sovereign.config.",
            $label,
            ".ManagedConnections/ListManagedConnections"
        );
        const CREATE_MANAGED_CONNECTION: &str = concat!(
            "/sovereign.config.",
            $label,
            ".ManagedConnections/CreateManagedConnection"
        );
        const ROTATE_MANAGED_CONNECTION: &str = concat!(
            "/sovereign.config.",
            $label,
            ".ManagedConnections/RotateManagedConnection"
        );
        const REVOKE_MANAGED_CONNECTION: &str = concat!(
            "/sovereign.config.",
            $label,
            ".ManagedConnections/RevokeManagedConnection"
        );

        /// Every route this version dials, for the test that checks each one names the
        /// version the session negotiated.
        #[cfg(test)]
        pub(super) const ROUTES: &[&str] = &[
            GET_VERSION,
            GET_IDENTITY,
            LIST_VALUES,
            GET_SUB_TREE,
            PUT_VALUE,
            REPLACE_SUB_TREE,
            DELETE_VALUES,
            REVEAL_SECRET,
            ADD_VALUE_PATH,
            LIST_VALUE_PATHS,
            LIST_MANAGED_CONNECTIONS,
            CREATE_MANAGED_CONNECTION,
            ROTATE_MANAGED_CONNECTION,
            REVOKE_MANAGED_CONNECTION,
        ];

        /// This version's gRPC-Web routes and mapping.
        #[derive(Clone, Copy)]
        pub(super) struct Dialer;

        #[async_trait(?Send)]
        impl SessionTransport for Dialer {
            fn version(&self) -> ProtocolVersion {
                VERSION
            }

            async fn get_version(&self) -> Result<VersionReply, ClientError> {
                let response: proto::GetVersionResponse = grpc_unary(
                    GET_VERSION,
                    &proto::GetVersionRequest {
                        protocol_version: VERSION.as_str().to_owned(),
                    },
                    None,
                )
                .await?;
                Ok(VersionReply {
                    application_version: response.application_version,
                    protocol_version: response.protocol_version,
                    supported_protocol_versions: response.supported_protocol_versions,
                })
            }
        }

        #[async_trait(?Send)]
        impl Transport for Dialer {
            async fn get_identity(
                &self,
                bearer: &Secret,
            ) -> Result<AuthenticationStatus, ClientError> {
                let response: proto::GetIdentityResponse =
                    grpc_unary(GET_IDENTITY, &proto::GetIdentityRequest {}, Some(bearer)).await?;
                Ok(AuthenticationStatus {
                    authenticated: response.authenticated,
                })
            }
        }

        #[async_trait(?Send)]
        impl ValueTransport for Dialer {
            async fn list_values(
                &self,
                path: &ConfigPath,
                bearer: &Secret,
            ) -> Result<ValueListing, ClientError> {
                let response: proto::ListValuesResponse = grpc_unary(
                    LIST_VALUES,
                    &proto::ListValuesRequest {
                        path: path.as_str().to_owned(),
                    },
                    Some(bearer),
                )
                .await?;
                let values = response
                    .values
                    .into_iter()
                    .map(|value| {
                        let alias_paths = value
                            .alias_paths
                            .into_iter()
                            .map(|path| {
                                ConfigPath::parse_operation(path).map_err(|_| browser_error())
                            })
                            .collect::<Result<Vec<_>, ClientError>>()?;
                        Ok(ListedValue {
                            path: ConfigPath::parse_operation(value.path)
                                .map_err(|_| browser_error())?,
                            value: listed_content(value.classification, value.content)?,
                            created_at: proto_timestamp(value.created_at)?,
                            updated_at: proto_timestamp(value.updated_at)?,
                            alias_paths,
                        })
                    })
                    .collect::<Result<Vec<_>, ClientError>>()?;
                let paths = response
                    .paths
                    .into_iter()
                    .map(|path| ConfigPath::parse_selection(path).map_err(|_| browser_error()))
                    .collect::<Result<Vec<_>, ClientError>>()?;
                Ok(ValueListing { values, paths })
            }

            async fn get_subtree(
                &self,
                path: &ConfigPath,
                bearer: &Secret,
            ) -> Result<ValueSubTree, ClientError> {
                let response: proto::GetSubTreeResponse = grpc_unary(
                    GET_SUB_TREE,
                    &proto::GetSubTreeRequest {
                        path: path.as_str().to_owned(),
                    },
                    Some(bearer),
                )
                .await?;
                let values = response
                    .values
                    .into_iter()
                    .map(|value| {
                        let value_path =
                            ConfigPath::parse_operation(value.path).map_err(|_| browser_error())?;
                        if !value_path.is_at_or_below(path) {
                            return Err(browser_error());
                        }
                        Ok(SubTreeValue {
                            path: value_path,
                            value: subtree_content(value.classification, value.content)?,
                        })
                    })
                    .collect::<Result<Vec<_>, ClientError>>()?;
                Ok(ValueSubTree { values })
            }

            async fn put_value(
                &self,
                path: &ConfigPath,
                value: &PlainValue,
                bearer: &Secret,
            ) -> Result<PutMetadata, ClientError> {
                put(
                    path,
                    proto::put_value_request::Content::PlainValue(value.expose().to_owned()),
                    bearer,
                )
                .await
            }

            async fn put_secret(
                &self,
                path: &ConfigPath,
                value: &SecretInput,
                bearer: &Secret,
            ) -> Result<PutMetadata, ClientError> {
                put(
                    path,
                    proto::put_value_request::Content::SecretValue(value.expose().to_owned()),
                    bearer,
                )
                .await
            }

            async fn replace_subtree(
                &self,
                path: &ConfigPath,
                values: &[SubTreeMutationValue],
                bearer: &Secret,
            ) -> Result<ReplaceMetadata, ClientError> {
                let response: proto::ReplaceSubTreeResponse = grpc_unary(
                    REPLACE_SUB_TREE,
                    &proto::ReplaceSubTreeRequest {
                        path: path.as_str().to_owned(),
                        values: values.iter().map(mutation_value).collect(),
                    },
                    Some(bearer),
                )
                .await?;
                Ok(ReplaceMetadata {
                    updated_at: proto_timestamp(response.updated_at)?,
                    value_count: response.value_count,
                })
            }

            async fn delete_values(
                &self,
                path: &ConfigPath,
                recurse: bool,
                bearer: &Secret,
            ) -> Result<DeleteMetadata, ClientError> {
                let response: proto::DeleteValuesResponse = grpc_unary(
                    DELETE_VALUES,
                    &proto::DeleteValuesRequest {
                        path: path.as_str().to_owned(),
                        recurse,
                    },
                    Some(bearer),
                )
                .await?;
                Ok(DeleteMetadata {
                    deleted_at: proto_timestamp(response.deleted_at)?,
                    deleted_count: response.deleted_count,
                })
            }

            async fn reveal_secret(
                &self,
                path: &ConfigPath,
                bearer: &Secret,
            ) -> Result<RevealedSecret, ClientError> {
                let response: proto::RevealSecretResponse = grpc_unary(
                    REVEAL_SECRET,
                    &proto::RevealSecretRequest {
                        path: path.as_str().to_owned(),
                    },
                    Some(bearer),
                )
                .await?;
                if response.value.contains('\0') {
                    return Err(browser_error());
                }
                Ok(RevealedSecret::new(response.value))
            }

            async fn add_value_path(
                &self,
                source: &ConfigPath,
                new_path: &ConfigPath,
                bearer: &Secret,
            ) -> Result<AddPathMetadata, ClientError> {
                let response: proto::AddValuePathResponse = grpc_unary(
                    ADD_VALUE_PATH,
                    &proto::AddValuePathRequest {
                        source_path: source.as_str().to_owned(),
                        new_path: new_path.as_str().to_owned(),
                    },
                    Some(bearer),
                )
                .await?;
                Ok(AddPathMetadata {
                    created_at: proto_timestamp(response.created_at)?,
                })
            }

            async fn list_value_paths(
                &self,
                path: &ConfigPath,
                bearer: &Secret,
            ) -> Result<ValuePaths, ClientError> {
                let response: proto::ListValuePathsResponse = grpc_unary(
                    LIST_VALUE_PATHS,
                    &proto::ListValuePathsRequest {
                        path: path.as_str().to_owned(),
                    },
                    Some(bearer),
                )
                .await?;
                let paths = response
                    .paths
                    .into_iter()
                    .map(|path| ConfigPath::parse_operation(path).map_err(|_| browser_error()))
                    .collect::<Result<Vec<_>, ClientError>>()?;
                Ok(ValuePaths { paths })
            }
        }

        #[async_trait(?Send)]
        impl ManagedConnectionTransport for Dialer {
            async fn list_managed_connections(
                &self,
                bearer: &Secret,
            ) -> Result<Vec<ManagedConnectionMetadata>, ClientError> {
                let response: proto::ListManagedConnectionsResponse = grpc_unary(
                    LIST_MANAGED_CONNECTIONS,
                    &proto::ListManagedConnectionsRequest {},
                    Some(bearer),
                )
                .await?;
                response
                    .connections
                    .into_iter()
                    .map(managed_metadata)
                    .collect()
            }

            async fn create_managed_connection(
                &self,
                display_name: &DisplayName,
                root: &ConfigPath,
                permissions: &ManagedPermissions,
                bearer: &Secret,
            ) -> Result<ProvisionedManagedConnection, ClientError> {
                let response: proto::CreateManagedConnectionResponse = grpc_unary(
                    CREATE_MANAGED_CONNECTION,
                    &proto::CreateManagedConnectionRequest {
                        display_name: display_name.as_str().to_owned(),
                        root: root.as_str().to_owned(),
                        permissions: permissions.to_proto(),
                    },
                    Some(bearer),
                )
                .await?;
                provisioned_connection(response.metadata, &response.connection_url)
            }

            async fn rotate_managed_connection(
                &self,
                connection_id: &ConnectionId,
                bearer: &Secret,
            ) -> Result<ProvisionedManagedConnection, ClientError> {
                let response: proto::RotateManagedConnectionResponse = grpc_unary(
                    ROTATE_MANAGED_CONNECTION,
                    &proto::RotateManagedConnectionRequest {
                        connection_id: connection_id.as_str().to_owned(),
                    },
                    Some(bearer),
                )
                .await?;
                provisioned_connection(response.metadata, &response.connection_url)
            }

            async fn revoke_managed_connection(
                &self,
                connection_id: &ConnectionId,
                bearer: &Secret,
            ) -> Result<(), ClientError> {
                let _: proto::RevokeManagedConnectionResponse = grpc_unary(
                    REVOKE_MANAGED_CONNECTION,
                    &proto::RevokeManagedConnectionRequest {
                        connection_id: connection_id.as_str().to_owned(),
                    },
                    Some(bearer),
                )
                .await?;
                Ok(())
            }
        }

        /// Plain and secret writes are the same RPC with a different content arm, so
        /// the two entry points differ only in the arm they build.
        async fn put(
            path: &ConfigPath,
            content: proto::put_value_request::Content,
            bearer: &Secret,
        ) -> Result<PutMetadata, ClientError> {
            let response: proto::PutValueResponse = grpc_unary(
                PUT_VALUE,
                &proto::PutValueRequest {
                    path: path.as_str().to_owned(),
                    content: Some(content),
                },
                Some(bearer),
            )
            .await?;
            Ok(PutMetadata {
                created_at: proto_timestamp(response.created_at)?,
                updated_at: proto_timestamp(response.updated_at)?,
            })
        }

        fn mutation_value(value: &SubTreeMutationValue) -> proto::SubTreeMutationValue {
            proto::SubTreeMutationValue {
                path: value.path.as_str().to_owned(),
                content: Some(match &value.value {
                    SubTreeMutationContent::Plain(value) => {
                        proto::sub_tree_mutation_value::Content::PlainValue(
                            value.expose().to_owned(),
                        )
                    }
                    SubTreeMutationContent::PreserveSecret => {
                        proto::sub_tree_mutation_value::Content::PreserveSecret(
                            proto::PreserveSecret {},
                        )
                    }
                }),
            }
        }

        fn managed_metadata(
            metadata: proto::ManagedConnectionMetadata,
        ) -> Result<ManagedConnectionMetadata, ClientError> {
            Ok(ManagedConnectionMetadata {
                connection_id: ConnectionId::parse(metadata.connection_id)
                    .map_err(|_| browser_error())?,
                display_name: DisplayName::parse(metadata.display_name)
                    .map_err(|_| browser_error())?,
                root: ConfigPath::parse_selection(metadata.root).map_err(|_| browser_error())?,
                state: managed_state(metadata.state)?,
                permissions: ManagedPermissions::from_proto(&metadata.permissions)
                    .map_err(|_| browser_error())?,
                created_at: proto_timestamp(metadata.created_at)?,
                updated_at: proto_timestamp(metadata.updated_at)?,
            })
        }

        fn managed_state(state: i32) -> Result<ManagedConnectionState, ClientError> {
            match proto::ManagedConnectionState::try_from(state) {
                Ok(proto::ManagedConnectionState::Provisioning) => {
                    Ok(ManagedConnectionState::Provisioning)
                }
                Ok(proto::ManagedConnectionState::Active) => Ok(ManagedConnectionState::Active),
                Ok(proto::ManagedConnectionState::RotationUnknown) => {
                    Ok(ManagedConnectionState::RotationUnknown)
                }
                Ok(proto::ManagedConnectionState::Revoking) => Ok(ManagedConnectionState::Revoking),
                Ok(proto::ManagedConnectionState::CleanupRequired) => {
                    Ok(ManagedConnectionState::CleanupRequired)
                }
                _ => Err(browser_error()),
            }
        }

        fn provisioned_connection(
            metadata: Option<proto::ManagedConnectionMetadata>,
            connection_url: &str,
        ) -> Result<ProvisionedManagedConnection, ClientError> {
            let metadata = managed_metadata(metadata.ok_or_else(browser_error)?)?;
            let connection = ConnectionUrl::parse(connection_url).map_err(|_| browser_error())?;
            if connection.client_authentication().is_none() || connection.root() != &metadata.root {
                return Err(browser_error());
            }
            Ok(ProvisionedManagedConnection {
                metadata,
                connection_url: RevealedConnectionUrl::new(connection),
            })
        }

        fn listed_content(
            classification: i32,
            content: Option<proto::listed_value::Content>,
        ) -> Result<ValueContent, ClientError> {
            match (
                proto::ValueClassification::try_from(classification),
                content,
            ) {
                (
                    Ok(proto::ValueClassification::Plain),
                    Some(proto::listed_value::Content::PlainValue(value)),
                ) if !value.contains('\0') => Ok(ValueContent::Plain(PlainValue::new(value))),
                (
                    Ok(proto::ValueClassification::Secret),
                    Some(proto::listed_value::Content::MaskedSecret(_)),
                ) => Ok(ValueContent::Secret(MaskedSecret)),
                _ => Err(browser_error()),
            }
        }

        fn subtree_content(
            classification: i32,
            content: Option<proto::sub_tree_value::Content>,
        ) -> Result<ValueContent, ClientError> {
            match (
                proto::ValueClassification::try_from(classification),
                content,
            ) {
                (
                    Ok(proto::ValueClassification::Plain),
                    Some(proto::sub_tree_value::Content::PlainValue(value)),
                ) if !value.contains('\0') => Ok(ValueContent::Plain(PlainValue::new(value))),
                (
                    Ok(proto::ValueClassification::Secret),
                    Some(proto::sub_tree_value::Content::MaskedSecret(_)),
                ) => Ok(ValueContent::Secret(MaskedSecret)),
                _ => Err(browser_error()),
            }
        }

        fn proto_timestamp(
            value: Option<prost_types::Timestamp>,
        ) -> Result<Timestamp, ClientError> {
            let value = value.ok_or_else(browser_error)?;
            timestamp(value.seconds, value.nanos)
        }
    };
}

pub(super) use version_dialer;
