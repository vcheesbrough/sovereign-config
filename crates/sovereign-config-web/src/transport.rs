//! gRPC-Web transport: the
//! `Transport`/`ValueTransport`/`ManagedConnectionTransport` impls for the
//! browser, frame decoding, and proto-to-core mapping.

use async_trait::async_trait;
use js_sys::{Date, Uint8Array};
use prost::Message;
use sovereign_config_client::{
    AccessTokenProvider, Client, ManagedConnectionTransport, RpcCode, Transport, ValueTransport,
    VersionReply, map_rpc_status, timestamp,
};
use sovereign_config_core::{
    AddPathMetadata, AuthenticationStatus, ClientError, ConfigPath, ConnectionId, ConnectionUrl,
    DeleteMetadata, DisplayName, ErrorKind, ListedValue, ManagedConnectionMetadata,
    ManagedConnectionState, ManagedPermissions, MaskedSecret, PlainValue,
    ProvisionedManagedConnection, PutMetadata, ReplaceMetadata, RevealedConnectionUrl,
    RevealedSecret, Secret, SecretInput, SubTreeMutationContent, SubTreeMutationValue,
    SubTreeValue, Timestamp, ValueContent, ValueListing, ValuePaths, ValueSubTree,
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
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, Request, RequestCache, RequestInit, Response, window};

use crate::browser::{AppConfig, browser_error};
use crate::session::{
    TOKENS, clear_persisted_refresh_token, persist_refresh_token, refresh_tokens,
};

#[derive(Clone, Copy)]
pub(crate) struct BrowserTransport;

pub(crate) struct MemoryAuthentication {
    pub(crate) client_id: String,
}

#[async_trait(?Send)]
impl AccessTokenProvider for MemoryAuthentication {
    async fn access_token(&self) -> Result<Option<Secret>, ClientError> {
        let Some(tokens) = TOKENS.with_borrow_mut(Option::take) else {
            return Ok(None);
        };
        let now = Date::now();
        if now < tokens.access_expires_at_ms {
            let access_token = tokens.access_token.clone();
            TOKENS.with_borrow_mut(|slot| *slot = Some(tokens));
            return Ok(Some(access_token));
        }
        if now >= tokens.refresh_expires_at_ms {
            clear_persisted_refresh_token();
            return Ok(None);
        }
        match refresh_tokens(&self.client_id, &tokens).await {
            Ok(refreshed) => {
                let access_token = refreshed.access_token.clone();
                persist_refresh_token(&refreshed);
                TOKENS.with_borrow_mut(|slot| *slot = Some(refreshed));
                Ok(Some(access_token))
            }
            Err(error) if error.kind == ErrorKind::Unavailable => {
                TOKENS.with_borrow_mut(|slot| *slot = Some(tokens));
                Err(error)
            }
            Err(error) => {
                clear_persisted_refresh_token();
                Err(error)
            }
        }
    }
}

#[async_trait(?Send)]
impl Transport for BrowserTransport {
    async fn get_version(&self, protocol_version: &str) -> Result<VersionReply, ClientError> {
        let response: GetVersionResponse = grpc_unary(
            "/sovereign.config.v3.System/GetVersion",
            &GetVersionRequest {
                protocol_version: protocol_version.to_owned(),
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

    async fn get_identity(&self, bearer: &Secret) -> Result<AuthenticationStatus, ClientError> {
        let response: GetIdentityResponse = grpc_unary(
            "/sovereign.config.v3.System/GetIdentity",
            &GetIdentityRequest {},
            Some(bearer),
        )
        .await?;
        Ok(AuthenticationStatus {
            authenticated: response.authenticated,
        })
    }
}

#[async_trait(?Send)]
impl ValueTransport for BrowserTransport {
    async fn list_values(
        &self,
        path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<ValueListing, ClientError> {
        let response: ListValuesResponse = grpc_unary(
            "/sovereign.config.v3.Configuration/ListValues",
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
            "/sovereign.config.v3.Configuration/GetSubTree",
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
        let response: PutValueResponse = grpc_unary(
            "/sovereign.config.v3.Configuration/PutValue",
            &PutValueRequest {
                path: path.as_str().to_owned(),
                content: Some(put_value_request::Content::PlainValue(
                    value.expose().to_owned(),
                )),
            },
            Some(bearer),
        )
        .await?;
        Ok(PutMetadata {
            created_at: proto_timestamp(response.created_at)?,
            updated_at: proto_timestamp(response.updated_at)?,
        })
    }

    async fn put_secret(
        &self,
        path: &ConfigPath,
        value: &SecretInput,
        bearer: &Secret,
    ) -> Result<PutMetadata, ClientError> {
        let response: PutValueResponse = grpc_unary(
            "/sovereign.config.v3.Configuration/PutValue",
            &PutValueRequest {
                path: path.as_str().to_owned(),
                content: Some(put_value_request::Content::SecretValue(
                    value.expose().to_owned(),
                )),
            },
            Some(bearer),
        )
        .await?;
        Ok(PutMetadata {
            created_at: proto_timestamp(response.created_at)?,
            updated_at: proto_timestamp(response.updated_at)?,
        })
    }

    async fn replace_subtree(
        &self,
        path: &ConfigPath,
        values: &[SubTreeMutationValue],
        bearer: &Secret,
    ) -> Result<ReplaceMetadata, ClientError> {
        let response: ReplaceSubTreeResponse = grpc_unary(
            "/sovereign.config.v3.Configuration/ReplaceSubTree",
            &ReplaceSubTreeRequest {
                path: path.as_str().to_owned(),
                values: values
                    .iter()
                    .map(|value| ProtoSubTreeMutationValue {
                        path: value.path.as_str().to_owned(),
                        content: Some(match &value.value {
                            SubTreeMutationContent::Plain(value) => {
                                sub_tree_mutation_value::Content::PlainValue(
                                    value.expose().to_owned(),
                                )
                            }
                            SubTreeMutationContent::PreserveSecret => {
                                sub_tree_mutation_value::Content::PreserveSecret(PreserveSecret {})
                            }
                        }),
                    })
                    .collect(),
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
            "/sovereign.config.v3.Configuration/DeleteValues",
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
            "/sovereign.config.v3.Configuration/RevealSecret",
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
            "/sovereign.config.v3.Configuration/AddValuePath",
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
            "/sovereign.config.v3.Configuration/ListValuePaths",
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
impl ManagedConnectionTransport for BrowserTransport {
    async fn list_managed_connections(
        &self,
        bearer: &Secret,
    ) -> Result<Vec<ManagedConnectionMetadata>, ClientError> {
        let response: ListManagedConnectionsResponse = grpc_unary(
            "/sovereign.config.v3.ManagedConnections/ListManagedConnections",
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
            "/sovereign.config.v3.ManagedConnections/CreateManagedConnection",
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
            "/sovereign.config.v3.ManagedConnections/RotateManagedConnection",
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
            "/sovereign.config.v3.ManagedConnections/RevokeManagedConnection",
            &RevokeManagedConnectionRequest {
                connection_id: connection_id.as_str().to_owned(),
            },
            Some(bearer),
        )
        .await?;
        Ok(())
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

pub(crate) fn value_client(config: &AppConfig) -> Client<BrowserTransport, MemoryAuthentication> {
    Client::new(
        BrowserTransport,
        MemoryAuthentication {
            client_id: config.client_id.clone(),
        },
    )
}

async fn grpc_unary<M, R>(
    path: &str,
    message: &M,
    bearer: Option<&Secret>,
) -> Result<R, ClientError>
where
    M: Message,
    R: Message + Default,
{
    let encoded = message.encode_to_vec();
    let mut framed = Vec::with_capacity(encoded.len() + 5);
    framed.push(0);
    let encoded_length = u32::try_from(encoded.len()).map_err(|_| browser_error())?;
    framed.extend_from_slice(&encoded_length.to_be_bytes());
    framed.extend_from_slice(&encoded);
    let body = Uint8Array::from(framed.as_slice());
    let mut headers = vec![
        ("content-type", "application/grpc-web+proto"),
        ("x-grpc-web", "1"),
    ];
    let authorization;
    if let Some(bearer) = bearer {
        authorization = format!("Bearer {}", bearer.expose());
        headers.push(("authorization", authorization.as_str()));
    }
    let response = fetch(path, "POST", Some(body.into()), &headers).await?;
    if !response.ok() {
        return Err(map_rpc_status(RpcCode::Unavailable));
    }
    let header_status = response
        .headers()
        .get("grpc-status")
        .ok()
        .flatten()
        .and_then(|value| value.parse::<u16>().ok());
    let buffer = JsFuture::from(response.array_buffer().map_err(|_| browser_error())?)
        .await
        .map_err(|_| browser_error())?;
    decode_grpc_web_response(&Uint8Array::new(&buffer).to_vec(), header_status)
}

#[cfg(test)]
pub(crate) fn decode_grpc_web<R: Message + Default>(bytes: &[u8]) -> Result<R, ClientError> {
    decode_grpc_web_response(bytes, None)
}

pub(crate) fn decode_grpc_web_response<R: Message + Default>(
    bytes: &[u8],
    header_status: Option<u16>,
) -> Result<R, ClientError> {
    let mut offset = 0;
    let mut payload = None;
    let mut status = None;
    while offset + 5 <= bytes.len() {
        let flags = bytes[offset];
        let length = u32::from_be_bytes(bytes[offset + 1..offset + 5].try_into().unwrap()) as usize;
        offset += 5;
        if offset + length > bytes.len() {
            return Err(map_rpc_status(RpcCode::Other));
        }
        let frame = &bytes[offset..offset + length];
        if flags & 0x80 == 0 {
            payload = Some(frame);
        } else if let Ok(trailers) = std::str::from_utf8(frame) {
            status = trailers.lines().find_map(|line| {
                line.strip_prefix("grpc-status:")
                    .and_then(|value| value.trim().parse::<u16>().ok())
            });
        }
        offset += length;
    }
    let status = status
        .or(header_status)
        .ok_or_else(|| map_rpc_status(RpcCode::Other))?;
    if status != 0 {
        return Err(map_rpc_status(grpc_status_code(status)));
    }
    R::decode(payload.ok_or_else(|| map_rpc_status(RpcCode::Other))?)
        .map_err(|_| map_rpc_status(RpcCode::Other))
}

fn grpc_status_code(status: u16) -> RpcCode {
    match status {
        3 => RpcCode::InvalidArgument,
        5 => RpcCode::NotFound,
        6 => RpcCode::AlreadyExists,
        7 => RpcCode::PermissionDenied,
        9 => RpcCode::FailedPrecondition,
        10 | 14 => RpcCode::Unavailable,
        12 => RpcCode::Unimplemented,
        16 => RpcCode::Unauthenticated,
        _ => RpcCode::Other,
    }
}

pub(crate) async fn fetch(
    url: &str,
    method: &str,
    body: Option<JsValue>,
    headers: &[(&str, &str)],
) -> Result<Response, ClientError> {
    let request_headers = Headers::new().map_err(|_| browser_error())?;
    for (name, value) in headers {
        request_headers
            .append(name, value)
            .map_err(|_| browser_error())?;
    }
    let options = RequestInit::new();
    options.set_method(method);
    options.set_cache(RequestCache::NoStore);
    options.set_headers(&request_headers);
    if let Some(body) = body.as_ref() {
        options.set_body(body);
    }
    let request = Request::new_with_str_and_init(url, &options).map_err(|_| browser_error())?;
    let response = JsFuture::from(
        window()
            .ok_or_else(browser_error)?
            .fetch_with_request(&request),
    )
    .await
    .map_err(|_| map_rpc_status(RpcCode::Unavailable))?;
    response.dyn_into().map_err(|_| browser_error())
}
