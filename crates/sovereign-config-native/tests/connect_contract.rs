//! The shared error contract (`test-contracts/transport.json`) over Connect:
//! a session on `v6` reads each Connect error the server can send as the same
//! client error a session on a gRPC version reads the matching status as.
//!
//! The fixture answers in Connect's shape only, as a `v6` server does, and
//! takes the case to answer from the bearer, so one session walks the table.

use axum::{
    body::Body,
    extract::Request,
    response::{IntoResponse, Response},
};
use prost::Message;
use serde::Deserialize;
use sovereign_config_client::{Transport, negotiate};
use sovereign_config_core::{ErrorKind, ProtocolVersion, Secret};
use sovereign_config_native::TonicChannel;
use sovereign_config_proto::sovereign::config::{
    NegotiateResponse, ServedProtocolVersion, v6::GetIdentityResponse,
};

#[derive(Deserialize)]
struct ContractCase {
    grpc_status: u16,
    connect_code: Option<String>,
    http_status: u16,
    error_kind: Option<String>,
    message: Option<String>,
}

fn contract() -> Vec<ContractCase> {
    serde_json::from_str(include_str!("../../../test-contracts/transport.json")).unwrap()
}

fn proto(message: &impl Message) -> Response {
    Response::builder()
        .status(200)
        .header("content-type", "application/proto")
        .body(Body::from(message.encode_to_vec()))
        .unwrap()
        .into_response()
}

/// A `v6` server whose `GetIdentity` answers the case its bearer names
/// (`Bearer <grpc_status>`), and which marks the case for `9` as
/// version-not-served when the bearer says `9-retired`.
async fn serve() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = axum::Router::new().fallback(|request: Request| async move {
        assert_eq!(request.headers()["content-type"], "application/proto");
        if request.uri().path() == "/sovereign.config.Handshake/Negotiate" {
            return proto(&NegotiateResponse {
                served_protocol_versions: vec![ServedProtocolVersion {
                    protocol_version: "v6".into(),
                    deprecation_date: None,
                }],
            });
        }
        assert_eq!(
            request.uri().path(),
            "/sovereign.config.v6.System/GetIdentity"
        );
        let bearer = request.headers()["authorization"]
            .to_str()
            .unwrap()
            .trim_start_matches("Bearer ")
            .to_owned();
        let retired = bearer.ends_with("-retired");
        let status: u16 = bearer.trim_end_matches("-retired").parse().unwrap();
        let case = contract()
            .into_iter()
            .find(|case| case.grpc_status == status)
            .unwrap();
        let Some(code) = case.connect_code else {
            return proto(&GetIdentityResponse {
                authenticated: true,
            });
        };
        let mut response = Response::builder()
            .status(case.http_status)
            .header("content-type", "application/json");
        if retired {
            response = response
                .header("sovereign-config-error-kind", "version-not-served")
                .header("sovereign-config-protocol-version", "v6");
        }
        response
            .body(Body::from(format!(
                r#"{{"code":"{code}","message":"contract failure"}}"#
            )))
            .unwrap()
            .into_response()
    });
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{address}")
}

fn expected_kind(kind: &str) -> ErrorKind {
    match kind {
        "InvalidRequest" => ErrorKind::InvalidRequest,
        "NotFound" => ErrorKind::NotFound,
        "Conflict" => ErrorKind::Conflict,
        "PermissionDenied" => ErrorKind::PermissionDenied,
        "IncompatibleProtocol" => ErrorKind::IncompatibleProtocol,
        "Unavailable" => ErrorKind::Unavailable,
        "Unauthenticated" => ErrorKind::Unauthenticated,
        "Internal" => ErrorKind::Internal,
        _ => panic!("unknown contract error kind: {kind}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_v6_session_reads_every_connect_error_as_the_contract_says() {
    let channel = TonicChannel::connect(serve().await).await.unwrap();
    let service = negotiate(&channel).await.unwrap();
    assert_eq!(service.protocol_version, ProtocolVersion::V6);
    let transport = channel.speaking(service.protocol_version);

    for case in contract() {
        let result = transport
            .get_identity(&Secret::new(case.grpc_status.to_string()))
            .await;
        if case.grpc_status == 0 {
            assert!(result.unwrap().authenticated);
            continue;
        }
        let error = result.unwrap_err();
        assert_eq!(
            error.kind,
            expected_kind(case.error_kind.as_deref().unwrap()),
            "status {}",
            case.grpc_status
        );
        assert_eq!(error.to_string(), case.message.as_deref().unwrap());
    }
}

/// The marker, never the code: a `failed_precondition` carrying it is the
/// version-not-served answer a session re-handshakes on, one without it is
/// not.
#[tokio::test(flavor = "multi_thread")]
async fn the_version_not_served_marker_is_read_from_a_connect_header() {
    let channel = TonicChannel::connect(serve().await).await.unwrap();
    let transport = channel.speaking(ProtocolVersion::V6);
    let marked = transport
        .get_identity(&Secret::new("9-retired"))
        .await
        .unwrap_err();
    let unmarked = transport.get_identity(&Secret::new("9")).await.unwrap_err();
    assert_eq!(marked.kind, ErrorKind::VersionNotServed);
    assert_eq!(unmarked.kind, ErrorKind::IncompatibleProtocol);
}
