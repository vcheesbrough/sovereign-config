use serde::Deserialize;
use sovereign_config_client::{Transport, ValueTransport};
use sovereign_config_core::{ClientError, ConfigPath, ErrorKind, PlainValue, Secret, SubTreeValue};
use sovereign_config_native::TonicTransport;
use sovereign_config_proto::sovereign::config::v2::{
    DeleteValuesRequest, DeleteValuesResponse, GetIdentityRequest, GetIdentityResponse,
    GetSubTreeRequest, GetSubTreeResponse, GetVersionRequest, GetVersionResponse,
    ListValuesRequest, ListValuesResponse, ListedValue, PutValueRequest, PutValueResponse,
    ReplaceSubTreeRequest, ReplaceSubTreeResponse, SubTreeValue as ProtoSubTreeValue,
    configuration_server::{Configuration, ConfigurationServer},
    system_server::{System, SystemServer},
};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Code, Request, Status, transport::Server};

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
                value: "contract-value-sentinel".into(),
                created_at: Some(prost_types::Timestamp {
                    seconds: 1_700_000_000,
                    nanos: 0,
                }),
                updated_at: Some(prost_types::Timestamp {
                    seconds: 1_700_000_001,
                    nanos: 0,
                }),
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
                value: "contract-value-sentinel".into(),
            }],
        }))
    }

    async fn put_value(
        &self,
        request: Request<PutValueRequest>,
    ) -> Result<tonic::Response<PutValueResponse>, Status> {
        require_bearer(&request)?;
        let request = request.into_inner();
        assert_eq!(request.path, "/apps/api/feature");
        assert_eq!(request.value, "put-value-sentinel");
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
        assert_eq!(request.values[0].value, "replacement-sentinel");
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
            protocol_version: "v2".to_owned(),
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
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    let transport = TonicTransport::connect(format!("http://{address}"))
        .await
        .unwrap();

    let version = transport.get_version("v2").await.unwrap();
    assert_eq!(version.application_version, "contract-version");
    assert_eq!(version.protocol_version, "v2");

    let listing = transport
        .list_values(
            &ConfigPath::parse("/apps/api").unwrap(),
            &Secret::new("contract-token-sentinel"),
        )
        .await
        .unwrap();
    assert_eq!(listing.paths, [ConfigPath::parse("/apps/api").unwrap()]);
    assert_eq!(listing.values[0].path.as_str(), "/apps/api/feature");
    assert_eq!(listing.values[0].value.expose(), "contract-value-sentinel");

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
    let replacement = SubTreeValue {
        path: ConfigPath::parse("/apps/api/new").unwrap(),
        value: PlainValue::new("replacement-sentinel"),
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
    }
    server.abort();
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
        14 => Code::Unavailable,
        16 => Code::Unauthenticated,
        _ => panic!("unsupported contract status: {status}"),
    }
}
