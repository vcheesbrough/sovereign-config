use serde::Deserialize;
use sovereign_config_client::{ManagedConnectionTransport, Transport, ValueTransport};
use sovereign_config_core::{
    ClientError, ConfigPath, ConnectionId, ConnectionUrl, DisplayName, ErrorKind,
    ManagedConnectionMetadata, ManagedConnectionState, ManagedPermission, ManagedPermissions,
    PlainValue, ProvisionedManagedConnection, Secret, SecretInput, SubTreeMutationContent,
    SubTreeMutationValue,
};
use sovereign_config_native::TonicTransport;
use sovereign_config_proto::sovereign::config::v3::{
    CreateManagedConnectionRequest, CreateManagedConnectionResponse, DeleteValuesRequest,
    DeleteValuesResponse, GetIdentityRequest, GetIdentityResponse, GetSubTreeRequest,
    GetSubTreeResponse, GetVersionRequest, GetVersionResponse, ListManagedConnectionsRequest,
    ListManagedConnectionsResponse, ListValuesRequest, ListValuesResponse, ListedValue,
    ManagedConnectionMetadata as ProtoManagedConnectionMetadata,
    ManagedConnectionState as ProtoManagedConnectionState,
    ManagedPermission as ProtoManagedPermission, PutValueRequest, PutValueResponse,
    ReplaceSubTreeRequest, ReplaceSubTreeResponse, RevealSecretRequest, RevealSecretResponse,
    RevokeManagedConnectionRequest, RevokeManagedConnectionResponse,
    RotateManagedConnectionRequest, RotateManagedConnectionResponse,
    SubTreeValue as ProtoSubTreeValue, ValueClassification,
    configuration_server::{Configuration, ConfigurationServer},
    listed_value,
    managed_connections_server::{ManagedConnections, ManagedConnectionsServer},
    put_value_request, sub_tree_mutation_value, sub_tree_value,
    system_server::{System, SystemServer},
};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Code, Request, Status, transport::Server};

const CONTRACT_CONNECTION_ID: &str = "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8";
const CONTRACT_MANAGED_ROOT: &str = "/apps/api";
const CONTRACT_URL_WITHOUT_CREDENTIAL: &str = "https://config.example.test/apps/api#v=1&issuer=https%3A%2F%2Fauth.example.test%2Fapplication%2Fo%2Fconfig%2F&client_id=sovereign-config";

#[derive(Deserialize)]
struct ContractCase {
    grpc_status: u16,
    error_kind: Option<String>,
    message: Option<String>,
}

#[derive(Default)]
struct ContractSystem;

#[derive(Default)]
struct ContractConfiguration;

#[tonic::async_trait]
impl Configuration for ContractConfiguration {
    async fn list_values(
        &self,
        request: Request<ListValuesRequest>,
    ) -> Result<tonic::Response<ListValuesResponse>, Status> {
        if request.metadata().get("authorization").is_none() {
            return Err(Status::unauthenticated("missing bearer"));
        }
        Ok(tonic::Response::new(ListValuesResponse {
            values: vec![ListedValue {
                path: "/apps/api/feature".into(),
                content: Some(listed_value::Content::PlainValue(
                    "contract-value-sentinel".into(),
                )),
                created_at: Some(prost_types::Timestamp {
                    seconds: 1_700_000_000,
                    nanos: 0,
                }),
                updated_at: Some(prost_types::Timestamp {
                    seconds: 1_700_000_001,
                    nanos: 0,
                }),
                classification: ValueClassification::Plain as i32,
            }],
            paths: vec![request.into_inner().path],
        }))
    }

    async fn get_sub_tree(
        &self,
        request: Request<GetSubTreeRequest>,
    ) -> Result<tonic::Response<GetSubTreeResponse>, Status> {
        require_bearer(&request)?;
        assert_eq!(request.into_inner().path, "/apps/api");
        Ok(tonic::Response::new(GetSubTreeResponse {
            values: vec![ProtoSubTreeValue {
                path: "/apps/api/feature".into(),
                content: Some(sub_tree_value::Content::PlainValue(
                    "contract-value-sentinel".into(),
                )),
                classification: ValueClassification::Plain as i32,
            }],
        }))
    }

    async fn put_value(
        &self,
        request: Request<PutValueRequest>,
    ) -> Result<tonic::Response<PutValueResponse>, Status> {
        require_bearer(&request)?;
        let request = request.into_inner();
        match request.path.as_str() {
            "/apps/api/feature" => assert!(matches!(
                request.content,
                Some(put_value_request::Content::PlainValue(value))
                    if value == "put-value-sentinel"
            )),
            "/apps/api/credential" => assert!(matches!(
                request.content,
                Some(put_value_request::Content::SecretValue(value))
                    if value == "contract-secret-sentinel"
            )),
            _ => panic!("unexpected put path"),
        }
        let timestamp = prost_types::Timestamp {
            seconds: 1_700_000_000,
            nanos: 0,
        };
        Ok(tonic::Response::new(PutValueResponse {
            created_at: Some(timestamp),
            updated_at: Some(timestamp),
        }))
    }

    async fn replace_sub_tree(
        &self,
        request: Request<ReplaceSubTreeRequest>,
    ) -> Result<tonic::Response<ReplaceSubTreeResponse>, Status> {
        require_bearer(&request)?;
        let request = request.into_inner();
        assert_eq!(request.path, "/apps/api");
        assert_eq!(request.values.len(), 1);
        assert_eq!(request.values[0].path, "/apps/api/new");
        assert!(matches!(
            request.values[0].content.as_ref(),
            Some(sub_tree_mutation_value::Content::PlainValue(value))
                if value == "replacement-sentinel"
        ));
        Ok(tonic::Response::new(ReplaceSubTreeResponse {
            updated_at: Some(prost_types::Timestamp {
                seconds: 1_700_000_001,
                nanos: 0,
            }),
            value_count: 1,
        }))
    }

    async fn delete_values(
        &self,
        request: Request<DeleteValuesRequest>,
    ) -> Result<tonic::Response<DeleteValuesResponse>, Status> {
        require_bearer(&request)?;
        let request = request.into_inner();
        assert_eq!(request.path, "/apps/api");
        assert!(request.recurse);
        Ok(tonic::Response::new(DeleteValuesResponse {
            deleted_at: Some(prost_types::Timestamp {
                seconds: 1_700_000_002,
                nanos: 0,
            }),
            deleted_count: 2,
        }))
    }

    async fn reveal_secret(
        &self,
        request: Request<RevealSecretRequest>,
    ) -> Result<tonic::Response<RevealSecretResponse>, Status> {
        require_bearer(&request)?;
        assert_eq!(request.into_inner().path, "/apps/api/credential");
        Ok(tonic::Response::new(RevealSecretResponse {
            value: "contract-secret-sentinel".into(),
        }))
    }
}

#[derive(Default)]
struct ContractManagedConnections;

#[tonic::async_trait]
impl ManagedConnections for ContractManagedConnections {
    async fn list_managed_connections(
        &self,
        request: Request<ListManagedConnectionsRequest>,
    ) -> Result<tonic::Response<ListManagedConnectionsResponse>, Status> {
        scripted_failure(&managed_directive(&request)?)?;
        Ok(tonic::Response::new(ListManagedConnectionsResponse {
            connections: vec![contract_managed_metadata()],
        }))
    }

    async fn create_managed_connection(
        &self,
        request: Request<CreateManagedConnectionRequest>,
    ) -> Result<tonic::Response<CreateManagedConnectionResponse>, Status> {
        let directive = managed_directive(&request)?;
        scripted_failure(&directive)?;
        let request = request.into_inner();
        assert_eq!(request.display_name, "Contract");
        assert_eq!(request.root, CONTRACT_MANAGED_ROOT);
        let response = match directive.as_str() {
            "invalid-missing-metadata" => CreateManagedConnectionResponse {
                metadata: None,
                connection_url: contract_connection_url(CONTRACT_MANAGED_ROOT),
            },
            "invalid-missing-credential" => CreateManagedConnectionResponse {
                metadata: Some(contract_managed_metadata()),
                connection_url: CONTRACT_URL_WITHOUT_CREDENTIAL.to_owned(),
            },
            "invalid-root-mismatch" => CreateManagedConnectionResponse {
                metadata: Some(contract_managed_metadata()),
                connection_url: contract_connection_url("/apps/other"),
            },
            "invalid-state" => CreateManagedConnectionResponse {
                metadata: Some(ProtoManagedConnectionMetadata {
                    state: ProtoManagedConnectionState::Unspecified as i32,
                    ..contract_managed_metadata()
                }),
                connection_url: contract_connection_url(CONTRACT_MANAGED_ROOT),
            },
            _ => CreateManagedConnectionResponse {
                metadata: Some(contract_managed_metadata()),
                connection_url: contract_connection_url(CONTRACT_MANAGED_ROOT),
            },
        };
        Ok(tonic::Response::new(response))
    }

    async fn rotate_managed_connection(
        &self,
        request: Request<RotateManagedConnectionRequest>,
    ) -> Result<tonic::Response<RotateManagedConnectionResponse>, Status> {
        scripted_failure(&managed_directive(&request)?)?;
        assert_eq!(request.into_inner().connection_id, CONTRACT_CONNECTION_ID);
        Ok(tonic::Response::new(RotateManagedConnectionResponse {
            metadata: Some(contract_managed_metadata()),
            connection_url: contract_connection_url(CONTRACT_MANAGED_ROOT),
        }))
    }

    async fn revoke_managed_connection(
        &self,
        request: Request<RevokeManagedConnectionRequest>,
    ) -> Result<tonic::Response<RevokeManagedConnectionResponse>, Status> {
        scripted_failure(&managed_directive(&request)?)?;
        assert_eq!(request.into_inner().connection_id, CONTRACT_CONNECTION_ID);
        Ok(tonic::Response::new(RevokeManagedConnectionResponse {}))
    }
}

fn contract_managed_metadata() -> ProtoManagedConnectionMetadata {
    ProtoManagedConnectionMetadata {
        connection_id: CONTRACT_CONNECTION_ID.to_owned(),
        display_name: "Contract".to_owned(),
        root: CONTRACT_MANAGED_ROOT.to_owned(),
        state: ProtoManagedConnectionState::Active as i32,
        permissions: vec![ProtoManagedPermission::Read as i32],
        created_at: Some(prost_types::Timestamp {
            seconds: 1_700_000_000,
            nanos: 0,
        }),
        updated_at: Some(prost_types::Timestamp {
            seconds: 1_700_000_001,
            nanos: 0,
        }),
    }
}

fn contract_connection_url(root: &str) -> String {
    ConnectionUrl::managed(
        "https://config.example.test",
        &ConfigPath::parse(root).unwrap(),
        "https://auth.example.test/application/o/config/",
        "sovereign-config",
        &format!("sc-managed-{CONTRACT_CONNECTION_ID}"),
        &Secret::new("contract-app-password"),
    )
    .unwrap()
    .canonical()
    .expose()
    .to_owned()
}

#[allow(clippy::result_large_err)]
fn managed_directive<T>(request: &Request<T>) -> Result<String, Status> {
    request
        .metadata()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::to_owned)
        .ok_or_else(|| Status::unauthenticated("missing bearer"))
}

#[allow(clippy::result_large_err)]
fn scripted_failure(directive: &str) -> Result<(), Status> {
    let Some(status) = directive.strip_prefix("grpc-") else {
        return Ok(());
    };
    let status = status
        .parse::<u16>()
        .map_err(|_| Status::invalid_argument("missing contract status"))?;
    if status == 0 {
        Ok(())
    } else {
        Err(Status::new(contract_code(status), "contract failure"))
    }
}

#[allow(clippy::result_large_err)]
fn require_bearer<T>(request: &Request<T>) -> Result<(), Status> {
    if request.metadata().get("authorization").is_some() {
        Ok(())
    } else {
        Err(Status::unauthenticated("missing bearer"))
    }
}

#[tonic::async_trait]
impl System for ContractSystem {
    async fn get_version(
        &self,
        _: Request<GetVersionRequest>,
    ) -> Result<tonic::Response<GetVersionResponse>, Status> {
        Ok(tonic::Response::new(GetVersionResponse {
            application_version: "contract-version".to_owned(),
            protocol_version: "v3".to_owned(),
        }))
    }

    async fn get_identity(
        &self,
        request: Request<GetIdentityRequest>,
    ) -> Result<tonic::Response<GetIdentityResponse>, Status> {
        let status = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer grpc-"))
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or_else(|| Status::invalid_argument("missing contract status"))?;
        if status == 0 {
            return Ok(tonic::Response::new(GetIdentityResponse {
                authenticated: true,
            }));
        }
        Err(Status::new(contract_code(status), "contract failure"))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn tonic_transport_satisfies_shared_contract() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(
        Server::builder()
            .add_service(SystemServer::new(ContractSystem))
            .add_service(ConfigurationServer::new(ContractConfiguration))
            .add_service(ManagedConnectionsServer::new(ContractManagedConnections))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    let transport = TonicTransport::connect(format!("http://{address}"))
        .await
        .unwrap();

    let version = transport.get_version("v3").await.unwrap();
    assert_eq!(version.application_version, "contract-version");
    assert_eq!(version.protocol_version, "v3");

    let listing = transport
        .list_values(
            &ConfigPath::parse("/apps/api").unwrap(),
            &Secret::new("contract-token-sentinel"),
        )
        .await
        .unwrap();
    assert_eq!(listing.paths, [ConfigPath::parse("/apps/api").unwrap()]);
    assert_eq!(listing.values[0].path.as_str(), "/apps/api/feature");
    assert_eq!(
        listing.values[0].value.display_text(),
        "contract-value-sentinel"
    );

    let selected = ConfigPath::parse("/apps/api").unwrap();
    let subtree = transport
        .get_subtree(&selected, &Secret::new("contract-token-sentinel"))
        .await
        .unwrap();
    assert_eq!(subtree.values[0].path.as_str(), "/apps/api/feature");
    transport
        .put_value(
            &ConfigPath::parse("/apps/api/feature").unwrap(),
            &PlainValue::new("put-value-sentinel"),
            &Secret::new("contract-token-sentinel"),
        )
        .await
        .unwrap();
    transport
        .put_secret(
            &ConfigPath::parse("/apps/api/credential").unwrap(),
            &SecretInput::new("contract-secret-sentinel"),
            &Secret::new("contract-token-sentinel"),
        )
        .await
        .unwrap();
    assert_eq!(
        transport
            .reveal_secret(
                &ConfigPath::parse("/apps/api/credential").unwrap(),
                &Secret::new("contract-token-sentinel"),
            )
            .await
            .unwrap()
            .expose(),
        "contract-secret-sentinel"
    );
    let replacement = SubTreeMutationValue {
        path: ConfigPath::parse("/apps/api/new").unwrap(),
        value: SubTreeMutationContent::Plain(PlainValue::new("replacement-sentinel")),
    };
    assert_eq!(
        transport
            .replace_subtree(
                &selected,
                &[replacement],
                &Secret::new("contract-token-sentinel"),
            )
            .await
            .unwrap()
            .value_count,
        1
    );
    assert_eq!(
        transport
            .delete_values(&selected, true, &Secret::new("contract-token-sentinel"),)
            .await
            .unwrap()
            .deleted_count,
        2
    );

    for case in contract() {
        let result = transport
            .get_identity(&Secret::new(format!("grpc-{}", case.grpc_status)))
            .await;
        assert_contract_result(result, &case);
        assert_managed_contract_case(&transport, &case).await;
    }
    assert_invalid_managed_responses_are_internal(&transport).await;
    server.abort();
}

async fn assert_managed_contract_case(transport: &TonicTransport, case: &ContractCase) {
    let bearer = Secret::new(format!("grpc-{}", case.grpc_status));
    let display_name = DisplayName::parse("Contract").unwrap();
    let root = ConfigPath::parse(CONTRACT_MANAGED_ROOT).unwrap();
    let permissions = ManagedPermissions::new([ManagedPermission::Read]).unwrap();
    let connection_id = ConnectionId::parse(CONTRACT_CONNECTION_ID).unwrap();

    let listing = transport.list_managed_connections(&bearer).await;
    let created = transport
        .create_managed_connection(&display_name, &root, &permissions, &bearer)
        .await;
    let rotated = transport
        .rotate_managed_connection(&connection_id, &bearer)
        .await;
    let revoked = transport
        .revoke_managed_connection(&connection_id, &bearer)
        .await;

    if case.grpc_status == 0 {
        let listing = listing.unwrap();
        assert_eq!(listing.len(), 1);
        assert_contract_metadata(&listing[0]);
        assert_provisioned_connection(&created.unwrap());
        assert_provisioned_connection(&rotated.unwrap());
        revoked.unwrap();
    } else {
        assert_managed_error(listing, case);
        assert_managed_error(created, case);
        assert_managed_error(rotated, case);
        assert_managed_error(revoked, case);
    }
}

fn assert_contract_metadata(metadata: &ManagedConnectionMetadata) {
    assert_eq!(metadata.connection_id.as_str(), CONTRACT_CONNECTION_ID);
    assert_eq!(metadata.display_name.as_str(), "Contract");
    assert_eq!(metadata.root.as_str(), CONTRACT_MANAGED_ROOT);
    assert_eq!(metadata.state, ManagedConnectionState::Active);
    assert_eq!(metadata.created_at.seconds, 1_700_000_000);
    assert_eq!(metadata.updated_at.seconds, 1_700_000_001);
}

fn assert_provisioned_connection(provisioned: &ProvisionedManagedConnection) {
    assert_contract_metadata(&provisioned.metadata);
    let connection = provisioned.connection_url.connection();
    assert!(connection.client_authentication().is_some());
    assert_eq!(connection.root(), &provisioned.metadata.root);
}

fn assert_managed_error<T: std::fmt::Debug>(result: Result<T, ClientError>, case: &ContractCase) {
    let error = result.unwrap_err();
    assert_eq!(
        error.kind,
        expected_kind(case.error_kind.as_deref().unwrap())
    );
    assert_eq!(error.to_string(), case.message.as_deref().unwrap());
}

async fn assert_invalid_managed_responses_are_internal(transport: &TonicTransport) {
    let display_name = DisplayName::parse("Contract").unwrap();
    let root = ConfigPath::parse(CONTRACT_MANAGED_ROOT).unwrap();
    let permissions = ManagedPermissions::new([ManagedPermission::Read]).unwrap();
    for directive in [
        "invalid-missing-metadata",
        "invalid-missing-credential",
        "invalid-root-mismatch",
        "invalid-state",
    ] {
        let error = transport
            .create_managed_connection(&display_name, &root, &permissions, &Secret::new(directive))
            .await
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Internal, "directive {directive}");
        assert_eq!(error.to_string(), "request failed", "directive {directive}");
    }
}

fn contract() -> Vec<ContractCase> {
    serde_json::from_str(include_str!("../../../test-contracts/transport.json")).unwrap()
}

fn assert_contract_result(
    result: Result<sovereign_config_core::AuthenticationStatus, ClientError>,
    case: &ContractCase,
) {
    if case.grpc_status == 0 {
        assert!(result.unwrap().authenticated);
        return;
    }
    let error = result.unwrap_err();
    assert_eq!(
        error.kind,
        expected_kind(case.error_kind.as_deref().unwrap())
    );
    assert_eq!(error.to_string(), case.message.as_deref().unwrap());
}

fn expected_kind(kind: &str) -> ErrorKind {
    match kind {
        "InvalidRequest" => ErrorKind::InvalidRequest,
        "NotFound" => ErrorKind::NotFound,
        "PermissionDenied" => ErrorKind::PermissionDenied,
        "IncompatibleProtocol" => ErrorKind::IncompatibleProtocol,
        "Unavailable" => ErrorKind::Unavailable,
        "Unauthenticated" => ErrorKind::Unauthenticated,
        "Internal" => ErrorKind::Internal,
        _ => panic!("unknown contract error kind: {kind}"),
    }
}

fn contract_code(status: u16) -> Code {
    match status {
        2 => Code::Unknown,
        3 => Code::InvalidArgument,
        5 => Code::NotFound,
        7 => Code::PermissionDenied,
        9 => Code::FailedPrecondition,
        10 => Code::Aborted,
        14 => Code::Unavailable,
        16 => Code::Unauthenticated,
        _ => panic!("unsupported contract status: {status}"),
    }
}
