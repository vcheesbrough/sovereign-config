//! The `sovereign.config.v3` dialer for the browser: this version's gRPC-Web
//! route paths and its proto↔core mapping, and nothing else.
//!
//! Every route here names `sovereign.config.v3`, because the gRPC route path
//! embeds the package name. That is what makes a version's dispatch deletable:
//! retiring `v3` is deleting this file and its arm of [`super::dialer`].
//!
//! Domain types stay version-free in `sovereign-config-core`, so a second
//! version is a second translation shim over one set of domain types — never a
//! forked client.

use async_trait::async_trait;
use sovereign_config_client::{
    ManagedConnectionTransport, SessionTransport, Transport, ValueTransport, VersionReply,
    timestamp,
};
use sovereign_config_core::{
    AddPathMetadata, AuthenticationStatus, ClientError, ConfigPath, ConnectionId, ConnectionUrl,
    DeleteMetadata, DisplayName, ListedValue, ManagedConnectionMetadata, ManagedConnectionState,
    ManagedPermissions, MaskedSecret, PlainValue, ProtocolVersion, ProvisionedManagedConnection,
    PutMetadata, ReplaceMetadata, RevealedConnectionUrl, RevealedSecret, Secret, SecretInput,
    SubTreeMutationContent, SubTreeMutationValue, SubTreeValue, Timestamp, ValueContent,
    ValueListing, ValuePaths, ValueSubTree,
};
use sovereign_config_proto::sovereign::config::v3::{
    AddValuePathRequest, AddValuePathResponse, CreateManagedConnectionRequest,
    CreateManagedConnectionResponse, DeleteValuesRequest, DeleteValuesResponse, GetIdentityRequest,
    GetIdentityResponse, GetSubTreeRequest, GetSubTreeResponse, GetVersionRequest,
    GetVersionResponse, ListManagedConnectionsRequest, ListManagedConnectionsResponse,
    ListValuePathsRequest, ListValuePathsResponse, ListValuesRequest, ListValuesResponse,
    ManagedConnectionMetadata as ProtoManagedConnectionMetadata,
    ManagedConnectionState as ProtoManagedConnectionState, PreserveSecret, PutValueRequest,
    PutValueResponse, ReplaceSubTreeRequest, ReplaceSubTreeResponse, RevealSecretRequest,
    RevealSecretResponse, RevokeManagedConnectionRequest, RevokeManagedConnectionResponse,
    RotateManagedConnectionRequest, RotateManagedConnectionResponse,
    SubTreeMutationValue as ProtoSubTreeMutationValue, ValueClassification as ProtoClassification,
    listed_value, put_value_request, sub_tree_mutation_value, sub_tree_value,
};

use crate::browser::browser_error;

use super::grpc_unary;

/// The version this module speaks. Reported as the session's version, so it is
/// read from the same place the routes come from.
const VERSION: ProtocolVersion = ProtocolVersion::V3;

const GET_VERSION: &str = "/sovereign.config.v3.System/GetVersion";
const GET_IDENTITY: &str = "/sovereign.config.v3.System/GetIdentity";
const LIST_VALUES: &str = "/sovereign.config.v3.Configuration/ListValues";
const GET_SUB_TREE: &str = "/sovereign.config.v3.Configuration/GetSubTree";
const PUT_VALUE: &str = "/sovereign.config.v3.Configuration/PutValue";
const REPLACE_SUB_TREE: &str = "/sovereign.config.v3.Configuration/ReplaceSubTree";
const DELETE_VALUES: &str = "/sovereign.config.v3.Configuration/DeleteValues";
const REVEAL_SECRET: &str = "/sovereign.config.v3.Configuration/RevealSecret";
const ADD_VALUE_PATH: &str = "/sovereign.config.v3.Configuration/AddValuePath";
const LIST_VALUE_PATHS: &str = "/sovereign.config.v3.Configuration/ListValuePaths";
const LIST_MANAGED_CONNECTIONS: &str =
    "/sovereign.config.v3.ManagedConnections/ListManagedConnections";
const CREATE_MANAGED_CONNECTION: &str =
    "/sovereign.config.v3.ManagedConnections/CreateManagedConnection";
const ROTATE_MANAGED_CONNECTION: &str =
    "/sovereign.config.v3.ManagedConnections/RotateManagedConnection";
const REVOKE_MANAGED_CONNECTION: &str =
    "/sovereign.config.v3.ManagedConnections/RevokeManagedConnection";

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

/// The `v3` gRPC-Web routes and mapping.
#[derive(Clone, Copy)]
pub(super) struct Dialer;

#[async_trait(?Send)]
impl SessionTransport for Dialer {
    fn version(&self) -> ProtocolVersion {
        VERSION
    }

    async fn get_version(&self) -> Result<VersionReply, ClientError> {
        let response: GetVersionResponse = grpc_unary(
            GET_VERSION,
            &GetVersionRequest {
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
    async fn get_identity(&self, bearer: &Secret) -> Result<AuthenticationStatus, ClientError> {
        let response: GetIdentityResponse =
            grpc_unary(GET_IDENTITY, &GetIdentityRequest {}, Some(bearer)).await?;
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
        let response: ListValuesResponse = grpc_unary(
            LIST_VALUES,
            &ListValuesRequest {
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
                    .map(|path| ConfigPath::parse_operation(path).map_err(|_| browser_error()))
                    .collect::<Result<Vec<_>, ClientError>>()?;
                Ok(ListedValue {
                    path: ConfigPath::parse_operation(value.path).map_err(|_| browser_error())?,
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
        let response: GetSubTreeResponse = grpc_unary(
            GET_SUB_TREE,
            &GetSubTreeRequest {
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
            put_value_request::Content::PlainValue(value.expose().to_owned()),
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
            put_value_request::Content::SecretValue(value.expose().to_owned()),
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
        let response: ReplaceSubTreeResponse = grpc_unary(
            REPLACE_SUB_TREE,
            &ReplaceSubTreeRequest {
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
        let response: DeleteValuesResponse = grpc_unary(
            DELETE_VALUES,
            &DeleteValuesRequest {
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
        let response: RevealSecretResponse = grpc_unary(
            REVEAL_SECRET,
            &RevealSecretRequest {
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
        let response: AddValuePathResponse = grpc_unary(
            ADD_VALUE_PATH,
            &AddValuePathRequest {
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
        let response: ListValuePathsResponse = grpc_unary(
            LIST_VALUE_PATHS,
            &ListValuePathsRequest {
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
        let response: ListManagedConnectionsResponse = grpc_unary(
            LIST_MANAGED_CONNECTIONS,
            &ListManagedConnectionsRequest {},
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
        let response: CreateManagedConnectionResponse = grpc_unary(
            CREATE_MANAGED_CONNECTION,
            &CreateManagedConnectionRequest {
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
        let response: RotateManagedConnectionResponse = grpc_unary(
            ROTATE_MANAGED_CONNECTION,
            &RotateManagedConnectionRequest {
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
        let _: RevokeManagedConnectionResponse = grpc_unary(
            REVOKE_MANAGED_CONNECTION,
            &RevokeManagedConnectionRequest {
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
    content: put_value_request::Content,
    bearer: &Secret,
) -> Result<PutMetadata, ClientError> {
    let response: PutValueResponse = grpc_unary(
        PUT_VALUE,
        &PutValueRequest {
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

fn mutation_value(value: &SubTreeMutationValue) -> ProtoSubTreeMutationValue {
    ProtoSubTreeMutationValue {
        path: value.path.as_str().to_owned(),
        content: Some(match &value.value {
            SubTreeMutationContent::Plain(value) => {
                sub_tree_mutation_value::Content::PlainValue(value.expose().to_owned())
            }
            SubTreeMutationContent::PreserveSecret => {
                sub_tree_mutation_value::Content::PreserveSecret(PreserveSecret {})
            }
        }),
    }
}

fn managed_metadata(
    metadata: ProtoManagedConnectionMetadata,
) -> Result<ManagedConnectionMetadata, ClientError> {
    Ok(ManagedConnectionMetadata {
        connection_id: ConnectionId::parse(metadata.connection_id).map_err(|_| browser_error())?,
        display_name: DisplayName::parse(metadata.display_name).map_err(|_| browser_error())?,
        root: ConfigPath::parse_selection(metadata.root).map_err(|_| browser_error())?,
        state: managed_state(metadata.state)?,
        permissions: ManagedPermissions::from_proto(&metadata.permissions)
            .map_err(|_| browser_error())?,
        created_at: proto_timestamp(metadata.created_at)?,
        updated_at: proto_timestamp(metadata.updated_at)?,
    })
}

fn managed_state(state: i32) -> Result<ManagedConnectionState, ClientError> {
    match ProtoManagedConnectionState::try_from(state) {
        Ok(ProtoManagedConnectionState::Provisioning) => Ok(ManagedConnectionState::Provisioning),
        Ok(ProtoManagedConnectionState::Active) => Ok(ManagedConnectionState::Active),
        Ok(ProtoManagedConnectionState::RotationUnknown) => {
            Ok(ManagedConnectionState::RotationUnknown)
        }
        Ok(ProtoManagedConnectionState::Revoking) => Ok(ManagedConnectionState::Revoking),
        Ok(ProtoManagedConnectionState::CleanupRequired) => {
            Ok(ManagedConnectionState::CleanupRequired)
        }
        _ => Err(browser_error()),
    }
}

fn provisioned_connection(
    metadata: Option<ProtoManagedConnectionMetadata>,
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
    content: Option<listed_value::Content>,
) -> Result<ValueContent, ClientError> {
    match (ProtoClassification::try_from(classification), content) {
        (Ok(ProtoClassification::Plain), Some(listed_value::Content::PlainValue(value)))
            if !value.contains('\0') =>
        {
            Ok(ValueContent::Plain(PlainValue::new(value)))
        }
        (Ok(ProtoClassification::Secret), Some(listed_value::Content::MaskedSecret(_))) => {
            Ok(ValueContent::Secret(MaskedSecret))
        }
        _ => Err(browser_error()),
    }
}

fn subtree_content(
    classification: i32,
    content: Option<sub_tree_value::Content>,
) -> Result<ValueContent, ClientError> {
    match (ProtoClassification::try_from(classification), content) {
        (Ok(ProtoClassification::Plain), Some(sub_tree_value::Content::PlainValue(value)))
            if !value.contains('\0') =>
        {
            Ok(ValueContent::Plain(PlainValue::new(value)))
        }
        (Ok(ProtoClassification::Secret), Some(sub_tree_value::Content::MaskedSecret(_))) => {
            Ok(ValueContent::Secret(MaskedSecret))
        }
        _ => Err(browser_error()),
    }
}

fn proto_timestamp(value: Option<prost_types::Timestamp>) -> Result<Timestamp, ClientError> {
    let value = value.ok_or_else(browser_error)?;
    timestamp(value.seconds, value.nanos)
}
