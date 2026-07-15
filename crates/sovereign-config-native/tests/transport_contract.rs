use serde::Deserialize;
use sovereign_config_client::{Transport, ValueTransport};
use sovereign_config_core::{ClientError, ConfigPath, ErrorKind, Secret};
use sovereign_config_native::TonicTransport;
use sovereign_config_proto::sovereign::config::v1::{
    DeleteValueRequest, DeleteValueResponse, GetIdentityRequest, GetIdentityResponse,
    GetValueRequest, GetValueResponse, GetVersionRequest, GetVersionResponse, ListValuesRequest,
    ListValuesResponse, ListedValue, PutValueRequest, PutValueResponse,
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

    async fn get_value(
        &self,
        _: Request<GetValueRequest>,
    ) -> Result<tonic::Response<GetValueResponse>, Status> {
        Err(Status::unimplemented("not used"))
    }

    async fn put_value(
        &self,
        _: Request<PutValueRequest>,
    ) -> Result<tonic::Response<PutValueResponse>, Status> {
        Err(Status::unimplemented("not used"))
    }

    async fn delete_value(
        &self,
        _: Request<DeleteValueRequest>,
    ) -> Result<tonic::Response<DeleteValueResponse>, Status> {
        Err(Status::unimplemented("not used"))
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
            protocol_version: "v1".to_owned(),
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

    let version = transport.get_version("v1").await.unwrap();
    assert_eq!(version.application_version, "contract-version");
    assert_eq!(version.protocol_version, "v1");

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
