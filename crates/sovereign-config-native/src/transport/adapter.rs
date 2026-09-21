//! The one native dialer every protocol version instantiates.
//!
//! Each version's generated stubs live in their own package, so one dialer
//! cannot be written against all of them as ordinary code. [`version_dialer`] is that
//! dialer, written once: a version's module imports its generated package as
//! `proto` and invokes it, then adds whatever that version alone has — which
//! today is how it answers an audit query. It is never copied and never
//! chained, so retiring a version is still deleting one file.
//!
//! Only proto↔core translation belongs here. Anything that looks like logic
//! belongs in core.

/// Defines `Dialer`, speaking `$version` over the package the invoking module
/// imports as `proto`, and the imports its body needs — which the invoking
/// module may use too. Paths resolve where the macro is invoked.
macro_rules! version_dialer {
    ($version:expr) => {
        use async_trait::async_trait;
        use sovereign_config_client::{
            AuditTransport, ManagedConnectionTransport, RpcCode, SessionTransport, Transport,
            ValueTransport, VersionReply, map_rpc_status, timestamp,
        };
        use sovereign_config_core::{
            AddPathMetadata, AuditPage, AuditQuery, AuthenticationStatus, ClientError, ConfigPath,
            ConnectionId, ConnectionUrl, DeleteMetadata, DisplayName, ListedValue,
            ManagedConnectionMetadata, ManagedConnectionState, ManagedPermissions, MaskedSecret,
            PlainValue, ProtocolVersion, ProvisionedManagedConnection, PutMetadata,
            ReplaceMetadata, RevealedConnectionUrl, RevealedSecret, Secret, SecretInput,
            SubTreeMutationContent, SubTreeMutationValue, SubTreeValue, ValueContent, ValueListing,
            ValuePaths, ValueSubTree,
        };
        use tonic::transport::Channel;

        use super::{authenticated_request, map_status};

        /// The version this module speaks. Reported as the session's version,
        /// so it is read from the same place the routes come from.
        const VERSION: ProtocolVersion = $version;

        /// This version's stubs, bound to one connected channel.
        pub(super) struct Dialer {
            channel: Channel,
        }

        impl Dialer {
            pub(super) const fn new(channel: Channel) -> Self {
                Self { channel }
            }

            fn configuration(&self) -> proto::configuration_client::ConfigurationClient<Channel> {
                proto::configuration_client::ConfigurationClient::new(self.channel.clone())
            }

            fn managed_connections(
                &self,
            ) -> proto::managed_connections_client::ManagedConnectionsClient<Channel> {
                proto::managed_connections_client::ManagedConnectionsClient::new(
                    self.channel.clone(),
                )
            }

            fn system(&self) -> proto::system_client::SystemClient<Channel> {
                proto::system_client::SystemClient::new(self.channel.clone())
            }
        }

        #[async_trait(?Send)]
        impl SessionTransport for Dialer {
            fn version(&self) -> ProtocolVersion {
                VERSION
            }

            async fn get_version(&self) -> Result<VersionReply, ClientError> {
                let response = self
                    .system()
                    .get_version(proto::GetVersionRequest {
                        protocol_version: VERSION.as_str().to_owned(),
                    })
                    .await
                    .map_err(|status| map_status(&status))?
                    .into_inner();
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
                let response = self
                    .system()
                    .get_identity(authenticated_request(proto::GetIdentityRequest {}, bearer)?)
                    .await
                    .map_err(|status| map_status(&status))?
                    .into_inner();
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
                let response = self
                    .configuration()
                    .list_values(authenticated_request(
                        proto::ListValuesRequest {
                            path: path.as_str().to_owned(),
                        },
                        bearer,
                    )?)
                    .await
                    .map_err(|status| map_status(&status))?
                    .into_inner();
                let values = response
                    .values
                    .into_iter()
                    .map(|value| {
                        let created_at = value.created_at.ok_or_else(invalid_response)?;
                        let updated_at = value.updated_at.ok_or_else(invalid_response)?;
                        let alias_paths = value
                            .alias_paths
                            .into_iter()
                            .map(|path| {
                                ConfigPath::parse_operation(path).map_err(|_| invalid_response())
                            })
                            .collect::<Result<Vec<_>, ClientError>>()?;
                        Ok(ListedValue {
                            path: ConfigPath::parse_operation(value.path)
                                .map_err(|_| invalid_response())?,
                            value: listed_content(value.classification, value.content)?,
                            created_at: timestamp(created_at.seconds, created_at.nanos)?,
                            updated_at: timestamp(updated_at.seconds, updated_at.nanos)?,
                            alias_paths,
                        })
                    })
                    .collect::<Result<Vec<_>, ClientError>>()?;
                let paths = response
                    .paths
                    .into_iter()
                    .map(|path| ConfigPath::parse_selection(path).map_err(|_| invalid_response()))
                    .collect::<Result<Vec<_>, ClientError>>()?;
                Ok(ValueListing { values, paths })
            }

            async fn get_subtree(
                &self,
                path: &ConfigPath,
                bearer: &Secret,
            ) -> Result<ValueSubTree, ClientError> {
                let response = self
                    .configuration()
                    .get_sub_tree(authenticated_request(
                        proto::GetSubTreeRequest {
                            path: path.as_str().to_owned(),
                        },
                        bearer,
                    )?)
                    .await
                    .map_err(|status| map_status(&status))?
                    .into_inner();
                let values = response
                    .values
                    .into_iter()
                    .map(|value| {
                        let value_path = ConfigPath::parse_operation(value.path)
                            .map_err(|_| invalid_response())?;
                        if !value_path.is_at_or_below(path) {
                            return Err(invalid_response());
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
                self.put(
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
                self.put(
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
                let response = self
                    .configuration()
                    .replace_sub_tree(authenticated_request(
                        proto::ReplaceSubTreeRequest {
                            path: path.as_str().to_owned(),
                            values: values.iter().map(mutation_value).collect(),
                        },
                        bearer,
                    )?)
                    .await
                    .map_err(|status| map_status(&status))?
                    .into_inner();
                let updated_at = response.updated_at.ok_or_else(invalid_response)?;
                Ok(ReplaceMetadata {
                    updated_at: timestamp(updated_at.seconds, updated_at.nanos)?,
                    value_count: response.value_count,
                })
            }

            async fn delete_values(
                &self,
                path: &ConfigPath,
                recurse: bool,
                bearer: &Secret,
            ) -> Result<DeleteMetadata, ClientError> {
                let response = self
                    .configuration()
                    .delete_values(authenticated_request(
                        proto::DeleteValuesRequest {
                            path: path.as_str().to_owned(),
                            recurse,
                        },
                        bearer,
                    )?)
                    .await
                    .map_err(|status| map_status(&status))?
                    .into_inner();
                let deleted_at = response.deleted_at.ok_or_else(invalid_response)?;
                Ok(DeleteMetadata {
                    deleted_at: timestamp(deleted_at.seconds, deleted_at.nanos)?,
                    deleted_count: response.deleted_count,
                })
            }

            async fn reveal_secret(
                &self,
                path: &ConfigPath,
                bearer: &Secret,
            ) -> Result<RevealedSecret, ClientError> {
                let response = self
                    .configuration()
                    .reveal_secret(authenticated_request(
                        proto::RevealSecretRequest {
                            path: path.as_str().to_owned(),
                        },
                        bearer,
                    )?)
                    .await
                    .map_err(|status| map_status(&status))?
                    .into_inner();
                if response.value.contains('\0') {
                    return Err(invalid_response());
                }
                Ok(RevealedSecret::new(response.value))
            }

            async fn add_value_path(
                &self,
                source: &ConfigPath,
                new_path: &ConfigPath,
                bearer: &Secret,
            ) -> Result<AddPathMetadata, ClientError> {
                let response = self
                    .configuration()
                    .add_value_path(authenticated_request(
                        proto::AddValuePathRequest {
                            source_path: source.as_str().to_owned(),
                            new_path: new_path.as_str().to_owned(),
                        },
                        bearer,
                    )?)
                    .await
                    .map_err(|status| map_status(&status))?
                    .into_inner();
                let created_at = response.created_at.ok_or_else(invalid_response)?;
                Ok(AddPathMetadata {
                    created_at: timestamp(created_at.seconds, created_at.nanos)?,
                })
            }

            async fn list_value_paths(
                &self,
                path: &ConfigPath,
                bearer: &Secret,
            ) -> Result<ValuePaths, ClientError> {
                let response = self
                    .configuration()
                    .list_value_paths(authenticated_request(
                        proto::ListValuePathsRequest {
                            path: path.as_str().to_owned(),
                        },
                        bearer,
                    )?)
                    .await
                    .map_err(|status| map_status(&status))?
                    .into_inner();
                let paths = response
                    .paths
                    .into_iter()
                    .map(|path| ConfigPath::parse_operation(path).map_err(|_| invalid_response()))
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
                let response = self
                    .managed_connections()
                    .list_managed_connections(authenticated_request(
                        proto::ListManagedConnectionsRequest {},
                        bearer,
                    )?)
                    .await
                    .map_err(|status| map_status(&status))?
                    .into_inner();
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
                let response = self
                    .managed_connections()
                    .create_managed_connection(authenticated_request(
                        proto::CreateManagedConnectionRequest {
                            display_name: display_name.as_str().to_owned(),
                            root: root.as_str().to_owned(),
                            permissions: permissions.to_proto(),
                        },
                        bearer,
                    )?)
                    .await
                    .map_err(|status| map_status(&status))?
                    .into_inner();
                provisioned_connection(response.metadata, &response.connection_url)
            }

            async fn rotate_managed_connection(
                &self,
                connection_id: &ConnectionId,
                bearer: &Secret,
            ) -> Result<ProvisionedManagedConnection, ClientError> {
                let response = self
                    .managed_connections()
                    .rotate_managed_connection(authenticated_request(
                        proto::RotateManagedConnectionRequest {
                            connection_id: connection_id.as_str().to_owned(),
                        },
                        bearer,
                    )?)
                    .await
                    .map_err(|status| map_status(&status))?
                    .into_inner();
                provisioned_connection(response.metadata, &response.connection_url)
            }

            async fn revoke_managed_connection(
                &self,
                connection_id: &ConnectionId,
                bearer: &Secret,
            ) -> Result<(), ClientError> {
                self.managed_connections()
                    .revoke_managed_connection(authenticated_request(
                        proto::RevokeManagedConnectionRequest {
                            connection_id: connection_id.as_str().to_owned(),
                        },
                        bearer,
                    )?)
                    .await
                    .map_err(|status| map_status(&status))?;
                Ok(())
            }
        }

        impl Dialer {
            /// Plain and secret writes are the same RPC with a different content arm,
            /// so the two entry points differ only in the arm they build.
            async fn put(
                &self,
                path: &ConfigPath,
                content: proto::put_value_request::Content,
                bearer: &Secret,
            ) -> Result<PutMetadata, ClientError> {
                let response = self
                    .configuration()
                    .put_value(authenticated_request(
                        proto::PutValueRequest {
                            path: path.as_str().to_owned(),
                            content: Some(content),
                        },
                        bearer,
                    )?)
                    .await
                    .map_err(|status| map_status(&status))?
                    .into_inner();
                let created_at = response.created_at.ok_or_else(invalid_response)?;
                let updated_at = response.updated_at.ok_or_else(invalid_response)?;
                Ok(PutMetadata {
                    created_at: timestamp(created_at.seconds, created_at.nanos)?,
                    updated_at: timestamp(updated_at.seconds, updated_at.nanos)?,
                })
            }
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
            let created_at = metadata.created_at.ok_or_else(invalid_response)?;
            let updated_at = metadata.updated_at.ok_or_else(invalid_response)?;
            Ok(ManagedConnectionMetadata {
                connection_id: ConnectionId::parse(metadata.connection_id)
                    .map_err(|_| invalid_response())?,
                display_name: DisplayName::parse(metadata.display_name)
                    .map_err(|_| invalid_response())?,
                root: ConfigPath::parse_selection(metadata.root).map_err(|_| invalid_response())?,
                state: managed_state(metadata.state)?,
                permissions: ManagedPermissions::from_proto(&metadata.permissions)
                    .map_err(|_| invalid_response())?,
                created_at: timestamp(created_at.seconds, created_at.nanos)?,
                updated_at: timestamp(updated_at.seconds, updated_at.nanos)?,
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
                _ => Err(invalid_response()),
            }
        }

        fn provisioned_connection(
            metadata: Option<proto::ManagedConnectionMetadata>,
            connection_url: &str,
        ) -> Result<ProvisionedManagedConnection, ClientError> {
            let metadata = managed_metadata(metadata.ok_or_else(invalid_response)?)?;
            let connection =
                ConnectionUrl::parse(connection_url).map_err(|_| invalid_response())?;
            if connection.client_authentication().is_none() || connection.root() != &metadata.root {
                return Err(invalid_response());
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
                _ => Err(invalid_response()),
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
                _ => Err(invalid_response()),
            }
        }

        fn invalid_response() -> ClientError {
            map_rpc_status(RpcCode::Other)
        }
    };
}

pub(super) use version_dialer;
