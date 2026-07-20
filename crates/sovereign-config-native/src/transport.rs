use std::{net::IpAddr, time::Duration};

use async_trait::async_trait;
use http::Uri;
use sovereign_config_client::{
    ManagedConnectionTransport, RpcCode, Transport, ValueTransport, VersionReply, map_rpc_status,
    timestamp,
};
use sovereign_config_core::{
    AuthenticationStatus, ClientError, ConfigPath, ConnectionId, ConnectionUrl, DeleteMetadata,
    DisplayName, ListedValue, ManagedConnectionMetadata, ManagedConnectionState, MaskedSecret,
    PlainValue, ProvisionedManagedConnection, PutMetadata, ReplaceMetadata, RevealedConnectionUrl,
    RevealedSecret, Secret, SecretInput, SubTreeMutationContent, SubTreeMutationValue,
    SubTreeValue, ValueContent, ValueListing, ValueSubTree,
};
use sovereign_config_proto::sovereign::config::v3::{
    CreateManagedConnectionRequest, DeleteValuesRequest, GetIdentityRequest, GetSubTreeRequest,
    GetVersionRequest, ListManagedConnectionsRequest, ListValuesRequest,
    ManagedConnectionMetadata as ProtoManagedConnectionMetadata,
    ManagedConnectionState as ProtoManagedConnectionState, PreserveSecret, PutValueRequest,
    ReplaceSubTreeRequest, RevealSecretRequest, RevokeManagedConnectionRequest,
    RotateManagedConnectionRequest, SubTreeMutationValue as ProtoSubTreeMutationValue,
    ValueClassification as ProtoClassification, configuration_client::ConfigurationClient,
    listed_value, managed_connections_client::ManagedConnectionsClient, put_value_request,
    sub_tree_mutation_value, sub_tree_value, system_client::SystemClient,
};
use tonic::{
    Code, Request,
    metadata::MetadataValue,
    transport::{Channel, Endpoint},
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct TonicTransport {
    channel: Channel,
}

#[async_trait(?Send)]
impl ValueTransport for TonicTransport {
    async fn list_values(
        &self,
        path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<ValueListing, ClientError> {
        let mut client = ConfigurationClient::new(self.channel.clone());
        let response = client
            .list_values(authenticated_request(
                ListValuesRequest {
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
                Ok(ListedValue {
                    path: ConfigPath::parse(value.path).map_err(|_| invalid_response())?,
                    value: listed_content(value.classification, value.content)?,
                    created_at: timestamp(created_at.seconds, created_at.nanos)?,
                    updated_at: timestamp(updated_at.seconds, updated_at.nanos)?,
                })
            })
            .collect::<Result<Vec<_>, ClientError>>()?;
        let paths = response
            .paths
            .into_iter()
            .map(|path| ConfigPath::parse(path).map_err(|_| invalid_response()))
            .collect::<Result<Vec<_>, ClientError>>()?;
        Ok(ValueListing { values, paths })
    }

    async fn get_subtree(
        &self,
        path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<ValueSubTree, ClientError> {
        let mut client = ConfigurationClient::new(self.channel.clone());
        let response = client
            .get_sub_tree(authenticated_request(
                GetSubTreeRequest {
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
                let value_path = ConfigPath::parse(value.path).map_err(|_| invalid_response())?;
                if value_path.as_str() == "/" || !value_path.is_at_or_below(path) {
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
        let mut client = ConfigurationClient::new(self.channel.clone());
        let response = client
            .put_value(authenticated_request(
                PutValueRequest {
                    path: path.as_str().to_owned(),
                    content: Some(put_value_request::Content::PlainValue(
                        value.expose().to_owned(),
                    )),
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

    async fn put_secret(
        &self,
        path: &ConfigPath,
        value: &SecretInput,
        bearer: &Secret,
    ) -> Result<PutMetadata, ClientError> {
        let mut client = ConfigurationClient::new(self.channel.clone());
        let response = client
            .put_value(authenticated_request(
                PutValueRequest {
                    path: path.as_str().to_owned(),
                    content: Some(put_value_request::Content::SecretValue(
                        value.expose().to_owned(),
                    )),
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

    async fn replace_subtree(
        &self,
        path: &ConfigPath,
        values: &[SubTreeMutationValue],
        bearer: &Secret,
    ) -> Result<ReplaceMetadata, ClientError> {
        let mut client = ConfigurationClient::new(self.channel.clone());
        let response = client
            .replace_sub_tree(authenticated_request(
                ReplaceSubTreeRequest {
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
                                    sub_tree_mutation_value::Content::PreserveSecret(
                                        PreserveSecret {},
                                    )
                                }
                            }),
                        })
                        .collect(),
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
        let mut client = ConfigurationClient::new(self.channel.clone());
        let response = client
            .delete_values(authenticated_request(
                DeleteValuesRequest {
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
        let mut client = ConfigurationClient::new(self.channel.clone());
        let response = client
            .reveal_secret(authenticated_request(
                RevealSecretRequest {
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
}

#[async_trait(?Send)]
impl ManagedConnectionTransport for TonicTransport {
    async fn list_managed_connections(
        &self,
        bearer: &Secret,
    ) -> Result<Vec<ManagedConnectionMetadata>, ClientError> {
        let mut client = ManagedConnectionsClient::new(self.channel.clone());
        let response = client
            .list_managed_connections(authenticated_request(
                ListManagedConnectionsRequest {},
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
        bearer: &Secret,
    ) -> Result<ProvisionedManagedConnection, ClientError> {
        let mut client = ManagedConnectionsClient::new(self.channel.clone());
        let response = client
            .create_managed_connection(authenticated_request(
                CreateManagedConnectionRequest {
                    display_name: display_name.as_str().to_owned(),
                    root: root.as_str().to_owned(),
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
        let mut client = ManagedConnectionsClient::new(self.channel.clone());
        let response = client
            .rotate_managed_connection(authenticated_request(
                RotateManagedConnectionRequest {
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
        let mut client = ManagedConnectionsClient::new(self.channel.clone());
        client
            .revoke_managed_connection(authenticated_request(
                RevokeManagedConnectionRequest {
                    connection_id: connection_id.as_str().to_owned(),
                },
                bearer,
            )?)
            .await
            .map_err(|status| map_status(&status))?;
        Ok(())
    }
}

fn managed_metadata(
    metadata: ProtoManagedConnectionMetadata,
) -> Result<ManagedConnectionMetadata, ClientError> {
    let created_at = metadata.created_at.ok_or_else(invalid_response)?;
    let updated_at = metadata.updated_at.ok_or_else(invalid_response)?;
    Ok(ManagedConnectionMetadata {
        connection_id: ConnectionId::parse(metadata.connection_id)
            .map_err(|_| invalid_response())?,
        display_name: DisplayName::parse(metadata.display_name).map_err(|_| invalid_response())?,
        root: ConfigPath::parse(metadata.root).map_err(|_| invalid_response())?,
        state: managed_state(metadata.state)?,
        created_at: timestamp(created_at.seconds, created_at.nanos)?,
        updated_at: timestamp(updated_at.seconds, updated_at.nanos)?,
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
        _ => Err(invalid_response()),
    }
}

fn provisioned_connection(
    metadata: Option<ProtoManagedConnectionMetadata>,
    connection_url: &str,
) -> Result<ProvisionedManagedConnection, ClientError> {
    let metadata = managed_metadata(metadata.ok_or_else(invalid_response)?)?;
    let connection = ConnectionUrl::parse(connection_url).map_err(|_| invalid_response())?;
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
        _ => Err(invalid_response()),
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
        _ => Err(invalid_response()),
    }
}

fn authenticated_request<T>(message: T, bearer: &Secret) -> Result<Request<T>, ClientError> {
    let mut request = Request::new(message);
    let authorization = MetadataValue::try_from(format!("Bearer {}", bearer.expose()))
        .map_err(|_| map_rpc_status(RpcCode::InvalidArgument))?;
    request
        .metadata_mut()
        .insert("authorization", authorization);
    Ok(request)
}

fn invalid_response() -> ClientError {
    map_rpc_status(RpcCode::Other)
}

impl TonicTransport {
    /// Connects to a native gRPC endpoint without configuring retries.
    ///
    /// # Errors
    ///
    /// Returns a bounded invalid-request or unavailable error.
    pub async fn connect(endpoint: String) -> Result<Self, ClientError> {
        Self::connect_with_timeouts(endpoint, CONNECT_TIMEOUT, REQUEST_TIMEOUT).await
    }

    async fn connect_with_timeouts(
        endpoint: String,
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> Result<Self, ClientError> {
        validate_service_endpoint(&endpoint)?;
        let endpoint = Endpoint::new(endpoint)
            .map_err(|_| map_rpc_status(RpcCode::InvalidArgument))?
            .connect_timeout(connect_timeout)
            .timeout(request_timeout);
        let channel = tokio::time::timeout(connect_timeout, endpoint.connect())
            .await
            .map_err(|_| map_rpc_status(RpcCode::Unavailable))?
            .map_err(|_| map_rpc_status(RpcCode::Unavailable))?;
        Ok(Self { channel })
    }
}

fn validate_service_endpoint(endpoint: &str) -> Result<(), ClientError> {
    let uri = endpoint
        .parse::<Uri>()
        .map_err(|_| map_rpc_status(RpcCode::InvalidArgument))?;
    let valid = match (uri.scheme_str(), uri.host()) {
        (Some("https"), Some(_)) => true,
        (Some("http"), Some(host)) => host
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback()),
        _ => false,
    };
    if !valid {
        return Err(map_rpc_status(RpcCode::InvalidArgument));
    }
    Ok(())
}

#[async_trait(?Send)]
impl Transport for TonicTransport {
    async fn get_version(&self, protocol_version: &str) -> Result<VersionReply, ClientError> {
        let mut client = SystemClient::new(self.channel.clone());
        let response = client
            .get_version(GetVersionRequest {
                protocol_version: protocol_version.to_owned(),
            })
            .await
            .map_err(|status| map_status(&status))?
            .into_inner();
        Ok(VersionReply {
            application_version: response.application_version,
            protocol_version: response.protocol_version,
        })
    }

    async fn get_identity(&self, bearer: &Secret) -> Result<AuthenticationStatus, ClientError> {
        let mut client = SystemClient::new(self.channel.clone());
        let response = client
            .get_identity(authenticated_request(GetIdentityRequest {}, bearer)?)
            .await
            .map_err(|status| map_status(&status))?
            .into_inner();
        Ok(AuthenticationStatus {
            authenticated: response.authenticated,
        })
    }
}

fn map_status(status: &tonic::Status) -> ClientError {
    map_rpc_status(match status.code() {
        Code::Unauthenticated => RpcCode::Unauthenticated,
        Code::PermissionDenied => RpcCode::PermissionDenied,
        Code::FailedPrecondition => RpcCode::FailedPrecondition,
        Code::InvalidArgument => RpcCode::InvalidArgument,
        Code::NotFound => RpcCode::NotFound,
        Code::Aborted | Code::Cancelled | Code::DeadlineExceeded | Code::Unavailable => {
            RpcCode::Unavailable
        }
        _ => RpcCode::Other,
    })
}

#[cfg(test)]
mod tests {
    use std::{future::pending, time::Duration};

    use sovereign_config_client::Transport;
    use sovereign_config_core::{ErrorKind, Secret};
    use sovereign_config_proto::sovereign::config::v3::{
        GetIdentityRequest, GetIdentityResponse, GetVersionRequest, GetVersionResponse,
        system_server::{System, SystemServer},
    };
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::{Request, Response, Status, transport::Server};

    use super::{TonicTransport, validate_service_endpoint};

    struct HangingSystem;

    #[tonic::async_trait]
    impl System for HangingSystem {
        async fn get_version(
            &self,
            _: Request<GetVersionRequest>,
        ) -> Result<Response<GetVersionResponse>, Status> {
            pending().await
        }

        async fn get_identity(
            &self,
            _: Request<GetIdentityRequest>,
        ) -> Result<Response<GetIdentityResponse>, Status> {
            pending().await
        }
    }

    #[test]
    fn service_endpoints_require_https_except_for_loopback() {
        assert!(validate_service_endpoint("https://config.example.test").is_ok());
        assert!(validate_service_endpoint("http://127.0.0.1:50051").is_ok());
        assert!(validate_service_endpoint("http://[::1]:50051").is_ok());
        assert!(validate_service_endpoint("http://config.example.test").is_err());
        assert!(validate_service_endpoint("ftp://config.example.test").is_err());
        assert!(validate_service_endpoint("not-a-url").is_err());
    }

    #[tokio::test]
    async fn stalled_connection_is_bounded_and_unavailable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            pending::<()>().await;
        });

        let result = tokio::time::timeout(
            Duration::from_secs(1),
            TonicTransport::connect_with_timeouts(
                format!("https://{address}"),
                Duration::from_millis(25),
                Duration::from_secs(1),
            ),
        )
        .await
        .expect("connection timeout was not enforced");
        let error = result
            .err()
            .expect("stalled connection unexpectedly succeeded");

        assert_eq!(error.kind, ErrorKind::Unavailable);
        peer.abort();
    }

    #[tokio::test]
    async fn stalled_rpcs_are_bounded_and_unavailable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(
            Server::builder()
                .add_service(SystemServer::new(HangingSystem))
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );
        let transport = TonicTransport::connect_with_timeouts(
            format!("http://{address}"),
            Duration::from_secs(1),
            Duration::from_millis(25),
        )
        .await
        .unwrap();

        let version = tokio::time::timeout(Duration::from_secs(1), transport.get_version("v1"))
            .await
            .expect("version RPC timeout was not enforced")
            .unwrap_err();
        let identity = tokio::time::timeout(
            Duration::from_secs(1),
            transport.get_identity(&Secret::new("token-sentinel")),
        )
        .await
        .expect("identity RPC timeout was not enforced")
        .unwrap_err();

        assert_eq!(version.kind, ErrorKind::Unavailable);
        assert_eq!(identity.kind, ErrorKind::Unavailable);
        server.abort();
    }
}
