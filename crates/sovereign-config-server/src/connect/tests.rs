//! The Connect transport as a client meets it: the deployed layer order on a
//! real socket, with a stand-in for authentication, over the `v6` shims and
//! a lazy pool. Nothing here reaches storage; the behaviour suites that do
//! are in `db_tests.rs`.
//!
//! Every call is made over HTTP/1.1 with `reqwest`, as a hand-written client
//! or `curl` makes it, except where a test is about gRPC.

use std::{collections::BTreeSet, net::SocketAddr, sync::Arc, time::Duration};

use http::{HeaderMap, StatusCode};
use prost::Message;
use serde_json::{Value, json};
use sovereign_config_core::{ERROR_KIND_METADATA, VERSION_NOT_SERVED_KIND};
use sovereign_config_identity::fake::FakeIdentityProvider;
use sovereign_config_proto::sovereign::config::{
    NegotiateRequest, NegotiateResponse, handshake_server::HandshakeServer, v5, v6,
};
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use tonic::{
    Code, Status,
    body::BoxBody,
    transport::{Endpoint, Server},
};
use tower::{
    Layer, Service,
    layer::util::{Identity, Stack},
};

use super::{
    ConnectDispatchLayer, ConnectServices, ConnectShapeLayer, GrpcWebUnlessConnectLayer, service,
};
use crate::{
    audit::{AuditRecorder, AuditTrailService, v6::V6Audit},
    auth::{AuthenticatedPrincipal, Grant, Permission, is_operational_rpc},
    encryption::ValueCipher,
    handshake::HandshakeService,
    managed::{ManagedConnectionsService, ManagedSettings, V6ManagedConnections},
    metrics::ProtocolMetrics,
    protocol::{ProtocolVersionLayer, UnservedVersionLayer},
    spans::GrpcStatusLayer,
    system::{SERVED_PROTOCOL_LABELS, V5System},
    values::{ConfigurationService, V6Configuration},
};

/// A bearer the stand-in accepts as a caller who may read and write
/// everything.
pub(super) const WRITER: &str = "Bearer writer-token";
/// A bearer the stand-in accepts as a caller who may only read.
pub(super) const READER: &str = "Bearer reader-token";

fn principal(permissions: &[Permission]) -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        subject: "connect-test".into(),
        name: Some("Connect Test".into()),
        grants: vec![Grant {
            prefix: "/".into(),
            permissions: permissions.iter().copied().collect::<BTreeSet<_>>(),
        }],
    }
}

/// Authentication's shape without its tokens: the operational routes pass,
/// [`WRITER`] and [`READER`] become principals, and anything else is refused
/// `UNAUTHENTICATED` in gRPC's trailers-only shape, as the real layer does.
#[derive(Clone, Copy)]
struct StandInAuthentication;

impl<S> Layer<S> for StandInAuthentication {
    type Service = StandInAuthenticationService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        StandInAuthenticationService { inner }
    }
}

#[derive(Clone)]
struct StandInAuthenticationService<S> {
    inner: S,
}

impl<S> Service<http::Request<BoxBody>> for StandInAuthenticationService<S>
where
    S: Service<http::Request<BoxBody>, Response = http::Response<BoxBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = http::Response<BoxBody>;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, mut request: http::Request<BoxBody>) -> Self::Future {
        let replacement = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, replacement);
        let bearer = request
            .headers()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        match bearer.as_deref() {
            Some(WRITER) => {
                request.extensions_mut().insert(principal(&[
                    Permission::Read,
                    Permission::Write,
                    Permission::Manage,
                ]));
            }
            Some(READER) => {
                request
                    .extensions_mut()
                    .insert(principal(&[Permission::Read]));
            }
            _ if is_operational_rpc(request.uri().path()) => {}
            _ => {
                let refusal = Status::unauthenticated("authentication failed").into_http();
                return Box::pin(async move { Ok(refusal) });
            }
        }
        Box::pin(async move { inner.call(request).await })
    }
}

/// The shared implementations the `v6` shims run over, on `database_url`.
pub(super) fn connect_services(database_url: &str) -> ConnectServices {
    let pool = PgPoolOptions::new()
        .acquire_timeout(Duration::from_secs(30))
        .connect_lazy(database_url)
        .expect("a lazy pool must build without connecting");
    // The values suites' key, so secrets these tests seal open for every suite
    // sharing the database (`encrypt_stored_secrets` refuses a wrong key).
    let mut key = [0xA5; 32];
    ConnectServices {
        handshake: HandshakeService::new(Arc::new(ProtocolMetrics::new(SERVED_PROTOCOL_LABELS))),
        configuration: V6Configuration::new(Arc::new(ConfigurationService::new(
            pool.clone(),
            Arc::new(ValueCipher::new(&mut key)),
            AuditRecorder::for_tests(),
        ))),
        managed_connections: V6ManagedConnections::new(Arc::new(ManagedConnectionsService::new(
            pool.clone(),
            Arc::new(FakeIdentityProvider::new()),
            ManagedSettings {
                public_origin: "https://config.example.test".to_owned(),
                issuer: "https://auth.example.test/application/o/sovereign-config/".to_owned(),
                rotation_lease: Duration::from_secs(60),
            },
            Arc::new(crate::metrics::ManagedConnectionMetrics::default()),
            AuditRecorder::for_tests(),
        ))),
        audit: V6Audit::new(Arc::new(AuditTrailService::new(pool, 100))),
    }
}

/// The deployed layer order on an ephemeral port: attribution, then the gRPC
/// stack as `auth::grpc_service_layer` assembles it (with the stand-in in
/// authentication's place), then the Connect dispatch, then tonic serving
/// the handshake and `v5`'s `System`.
pub(super) struct Harness {
    pub(super) address: SocketAddr,
    pub(super) http: reqwest::Client,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Harness {
    pub(super) async fn start() -> Self {
        Self::over("postgresql://unused@127.0.0.1:1/unused").await
    }

    pub(super) async fn over(database_url: &str) -> Self {
        let metrics = Arc::new(ProtocolMetrics::new(SERVED_PROTOCOL_LABELS));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("an ephemeral port must bind");
        let address = listener.local_addr().expect("the bound address is known");
        let (shutdown, shutdown_signal) = tokio::sync::oneshot::channel();
        let router = Server::builder()
            .accept_http1(true)
            .layer(ProtocolVersionLayer::new(
                Arc::clone(&metrics),
                SERVED_PROTOCOL_LABELS,
            ))
            .layer(Stack::new(
                StandInAuthentication,
                Stack::new(
                    UnservedVersionLayer::new(SERVED_PROTOCOL_LABELS),
                    Stack::new(
                        ConnectShapeLayer,
                        Stack::new(
                            GrpcStatusLayer,
                            Stack::new(GrpcWebUnlessConnectLayer, Identity::new()),
                        ),
                    ),
                ),
            ))
            .layer(ConnectDispatchLayer::new(service(connect_services(
                database_url,
            ))))
            .add_service(HandshakeServer::new(HandshakeService::new(Arc::clone(
                &metrics,
            ))))
            .add_service(v5::system_server::SystemServer::new(V5System));
        tokio::spawn(async move {
            router
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        let _ = shutdown_signal.await;
                    },
                )
                .await
                .expect("the server must serve");
        });
        Self {
            address,
            // HTTP/1.1 only, and one connection kept alive: what a Connect
            // client behind an HTTP/1.1-only proxy uses.
            http: reqwest::Client::builder()
                .http1_only()
                .pool_max_idle_per_host(1)
                .build()
                .expect("the client must build"),
            shutdown: Some(shutdown),
        }
    }

    pub(super) fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }

    /// One Connect JSON call.
    pub(super) async fn json(
        &self,
        path: &str,
        bearer: Option<&str>,
        body: &Value,
    ) -> (StatusCode, HeaderMap, Value) {
        let mut request = self
            .http
            .post(self.url(path))
            .header("content-type", "application/json")
            .body(body.to_string());
        if let Some(bearer) = bearer {
            request = request.header("authorization", bearer);
        }
        let response = request.send().await.expect("the server must answer");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.bytes().await.expect("the body must arrive");
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("a Connect JSON answer is JSON")
        };
        (status, headers, value)
    }

    /// One Connect binary call.
    pub(super) async fn binary(
        &self,
        path: &str,
        bearer: Option<&str>,
        body: Vec<u8>,
    ) -> (StatusCode, HeaderMap, bytes::Bytes) {
        let mut request = self
            .http
            .post(self.url(path))
            .header("content-type", "application/proto")
            .body(body);
        if let Some(bearer) = bearer {
            request = request.header("authorization", bearer);
        }
        let response = request.send().await.expect("the server must answer");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.bytes().await.expect("the body must arrive");
        (status, headers, bytes)
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

fn error_code(body: &Value) -> &str {
    body["code"]
        .as_str()
        .expect("a Connect error names its code")
}

fn marker(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(ERROR_KIND_METADATA)
        .and_then(|value| value.to_str().ok())
}

fn no_store(headers: &HeaderMap) -> bool {
    headers
        .get(http::header::CACHE_CONTROL)
        .is_some_and(|value| value == "no-store")
}

const HANDSHAKE: &str = "/sovereign.config.Handshake/Negotiate";
const V6_GET_VERSION: &str = "/sovereign.config.v6.System/GetVersion";
const V6_GET_IDENTITY: &str = "/sovereign.config.v6.System/GetIdentity";
const V6_PUT_VALUE: &str = "/sovereign.config.v6.Configuration/PutValue";
const V6_LIST_VALUES: &str = "/sovereign.config.v6.Configuration/ListValues";

#[tokio::test]
async fn the_handshake_answers_over_connect_in_json_with_its_frozen_names() {
    let harness = Harness::start().await;
    let (status, headers, body) = harness
        .json(
            HANDSHAKE,
            None,
            &json!({ "clientProtocolVersions": ["v6", "v5"] }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(no_store(&headers));
    // The handshake's JSON form is frozen with its shape.
    assert_eq!(
        body,
        json!({
            "servedProtocolVersions": [
                { "protocolVersion": "v6" },
                { "protocolVersion": "v5", "deprecationDate": "2027-01-01T00:00:00Z" },
                { "protocolVersion": "v4", "deprecationDate": "2027-01-01T00:00:00Z" },
                { "protocolVersion": "v3", "deprecationDate": "2027-01-01T00:00:00Z" },
            ]
        })
    );
}

#[tokio::test]
async fn the_handshake_answers_over_connect_binary_and_over_grpc_alike() {
    let harness = Harness::start().await;
    let request = NegotiateRequest {
        client_protocol_versions: vec!["v6".into()],
    };
    let (status, headers, bytes) = harness
        .binary(HANDSHAKE, None, request.encode_to_vec())
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["content-type"], "application/proto");
    let over_connect = NegotiateResponse::decode(bytes).expect("a binary answer decodes");

    let channel = Endpoint::from_shared(harness.url(""))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let over_grpc =
        sovereign_config_proto::sovereign::config::handshake_client::HandshakeClient::new(channel)
            .negotiate(request)
            .await
            .expect("the handshake is still served over gRPC")
            .into_inner();
    assert_eq!(over_connect, over_grpc);
    assert_eq!(
        over_connect.served_protocol_versions[0].protocol_version,
        "v6"
    );
}

#[tokio::test]
async fn get_version_on_v6_is_unauthenticated_and_reports_v6_first() {
    let harness = Harness::start().await;
    let (status, _, body) = harness
        .json(V6_GET_VERSION, None, &json!({ "protocolVersion": "v6" }))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["protocolVersion"], "v6");
    assert_eq!(
        body["supportedProtocolVersions"],
        json!(["v6", "v5", "v4", "v3"])
    );
    assert_eq!(body["applicationVersion"], crate::APPLICATION_VERSION);
}

#[tokio::test]
async fn an_authentication_refusal_reaches_a_connect_client_in_connects_shape() {
    let harness = Harness::start().await;
    let (status, headers, body) = harness.json(V6_GET_IDENTITY, None, &json!({})).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(error_code(&body), "unauthenticated");
    assert!(no_store(&headers));

    let (status, _, body) = harness
        .json(V6_GET_IDENTITY, Some(READER), &json!({}))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "authenticated": true }));
}

/// A version names its transport: Connect on a gRPC version's route is
/// version-not-served, marked in a **header** — never also as a trailer.
#[tokio::test]
async fn connect_on_a_grpc_versions_route_is_version_not_served() {
    let harness = Harness::start().await;
    for (path, bearer) in [
        ("/sovereign.config.v5.System/GetVersion", None),
        (
            "/sovereign.config.v5.Configuration/GetSubTree",
            Some(WRITER),
        ),
        ("/sovereign.config.v3.Configuration/ListValues", None),
        ("/sovereign.config.v2.Configuration/ListValues", None),
    ] {
        let (status, headers, body) = harness.json(path, bearer, &json!({})).await;
        assert_eq!(error_code(&body), "failed_precondition", "{path}");
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(marker(&headers), Some(VERSION_NOT_SERVED_KIND), "{path}");
        assert!(
            !headers
                .keys()
                .any(|name| name.as_str().starts_with("trailer-")),
            "the marker is a header only: {path}"
        );
        assert!(no_store(&headers));
    }
}

/// And gRPC on `v6`'s route is version-not-served too, with the marker where
/// a gRPC client reads it.
#[tokio::test]
async fn grpc_on_v6s_route_is_version_not_served() {
    let harness = Harness::start().await;
    let channel = Endpoint::from_shared(harness.url(""))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let refused = v6::system_client::SystemClient::new(channel)
        .get_version(v6::GetVersionRequest {
            protocol_version: "v6".into(),
        })
        .await
        .expect_err("v6 is not served over gRPC");
    assert_eq!(refused.code(), Code::FailedPrecondition);
    assert_eq!(
        refused
            .metadata()
            .get(ERROR_KIND_METADATA)
            .and_then(|value| value.to_str().ok()),
        Some(VERSION_NOT_SERVED_KIND)
    );

    let web = harness
        .http
        .post(harness.url(V6_GET_VERSION))
        .header("content-type", "application/grpc-web+proto")
        .header("x-grpc-web", "1")
        .body(vec![0_u8, 0, 0, 0, 0])
        .send()
        .await
        .unwrap();
    let headers = web.headers().clone();
    let body = web.bytes().await.unwrap();
    let in_trailer = String::from_utf8_lossy(&body)
        .contains(&format!("{ERROR_KIND_METADATA}:{VERSION_NOT_SERVED_KIND}"));
    assert!(
        in_trailer || marker(&headers) == Some(VERSION_NOT_SERVED_KIND),
        "a gRPC-Web client reads the marker from the answer"
    );
}

/// `v5` over gRPC is exactly as it was.
#[tokio::test]
async fn grpc_on_v5_is_served_as_before() {
    let harness = Harness::start().await;
    let channel = Endpoint::from_shared(harness.url(""))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let reply = v5::system_client::SystemClient::new(channel)
        .get_version(v5::GetVersionRequest {
            protocol_version: "v5".into(),
        })
        .await
        .expect("v5 is served over gRPC")
        .into_inner();
    assert_eq!(reply.protocol_version, "v5");
}

#[tokio::test]
async fn a_malformed_connect_request_is_told_how_to_call() {
    let harness = Harness::start().await;
    let get = harness.http.get(harness.url(V6_LIST_VALUES)).send();
    let no_type = harness
        .http
        .post(harness.url(V6_LIST_VALUES))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("{\"path\": \"/\"}")
        .send();
    let streaming = harness
        .http
        .post(harness.url(HANDSHAKE))
        .header("content-type", "application/connect+proto")
        .body(Vec::new())
        .send();
    for response in [get.await, no_type.await, streaming.await] {
        let response = response.expect("the server must answer");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(no_store(response.headers()));
        assert_eq!(
            response.headers()["accept-post"],
            "application/proto, application/json"
        );
        let body: Value = response.json().await.expect("a Connect error is JSON");
        assert_eq!(error_code(&body), "invalid_argument");
    }
}

/// A refused call over HTTP/1.1 reads the body first, so a client still
/// writing never has the connection closed under it (#583, Q4.4). Repeated
/// on one kept-alive connection, as the spike did.
#[tokio::test]
async fn a_refused_call_over_http1_never_closes_the_connection_under_the_writer() {
    let harness = Harness::start().await;
    let body = json!({ "path": "/apps", "pad": "x".repeat(512 * 1024) });
    for attempt in 0..30 {
        let (status, _, answer) = harness.json(V6_LIST_VALUES, None, &body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "attempt {attempt}");
        assert_eq!(error_code(&answer), "unauthenticated");
    }
}

#[tokio::test]
async fn a_body_over_the_size_limit_is_resource_exhausted() {
    let harness = Harness::start().await;
    let body = json!({ "path": "/apps", "pad": "x".repeat(super::MAX_MESSAGE_BYTES) });
    let (status, headers, answer) = harness.json(V6_LIST_VALUES, Some(WRITER), &body).await;
    assert_eq!(error_code(&answer), "resource_exhausted");
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(no_store(&headers));
}

/// Two members of a `oneof` are refused in both encodings, before anything
/// reaches storage (the pool here has no server behind it).
#[tokio::test]
async fn two_members_of_a_oneof_are_refused_in_binary_and_in_json() {
    let harness = Harness::start().await;
    let (status, _, answer) = harness
        .json(
            V6_PUT_VALUE,
            Some(WRITER),
            &json!({ "path": "/apps/both", "plainValue": "a", "secretValue": "b" }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error_code(&answer), "invalid_argument");

    let one = |content| v6::PutValueRequest {
        path: "/apps/both".into(),
        content: Some(content),
    };
    let mut body = one(v6::put_value_request::Content::PlainValue("a".into())).encode_to_vec();
    body.extend(one(v6::put_value_request::Content::SecretValue("b".into())).encode_to_vec());
    let (status, headers, bytes) = harness.binary(V6_PUT_VALUE, Some(WRITER), body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(no_store(&headers));
    let answer: Value = serde_json::from_slice(&bytes).expect("a Connect error is JSON");
    assert_eq!(error_code(&answer), "invalid_argument");
}

/// The shim's own validation answers the same in both encodings, and before
/// authorization, as `v5`'s does over gRPC.
#[tokio::test]
async fn validation_answers_alike_in_both_encodings() {
    let harness = Harness::start().await;
    let (_, _, json_answer) = harness
        .json(
            V6_PUT_VALUE,
            Some(READER),
            &json!({ "path": "/apps/empty" }),
        )
        .await;
    let (_, _, bytes) = harness
        .binary(
            V6_PUT_VALUE,
            Some(READER),
            v6::PutValueRequest {
                path: "/apps/empty".into(),
                content: None,
            }
            .encode_to_vec(),
        )
        .await;
    let binary_answer: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json_answer, binary_answer);
    assert_eq!(
        json_answer,
        json!({ "code": "invalid_argument", "message": "configuration value is invalid" })
    );
}

/// `Connect-Timeout-Ms` bounds a call as a gRPC deadline does. The pool
/// points at a listener that accepts and never answers, so the call can only
/// end by its deadline.
#[tokio::test]
async fn a_connect_deadline_ends_the_call_deadline_exceeded() {
    let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let silent_address = silent.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = silent.accept().await {
            held.push(socket);
        }
    });
    let harness = Harness::over(&format!("postgresql://silent@{silent_address}/silent")).await;
    let started = std::time::Instant::now();
    let response = harness
        .http
        .post(harness.url(V6_LIST_VALUES))
        .header("content-type", "application/json")
        .header("authorization", READER)
        .header("connect-timeout-ms", "300")
        .body(json!({ "path": "/apps" }).to_string())
        .send()
        .await
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(10));
    let body: Value = response.json().await.unwrap();
    assert_eq!(error_code(&body), "deadline_exceeded");
}

/// `test-contracts/transport.json`'s Connect columns are what this server
/// sends: each gRPC status becomes that Connect code, at that HTTP status.
#[test]
fn the_transport_contracts_connect_columns_are_what_the_server_sends() {
    #[derive(serde::Deserialize)]
    struct Case {
        grpc_status: u32,
        connect_code: Option<String>,
        http_status: u16,
    }
    let cases: Vec<Case> =
        serde_json::from_str(include_str!("../../../../test-contracts/transport.json")).unwrap();
    for case in cases {
        let Some(code) = case.connect_code else {
            assert_eq!(case.grpc_status, 0);
            assert_eq!(case.http_status, 200);
            continue;
        };
        let error = connectrpc::ConnectError::new(
            connectrpc::ErrorCode::from_grpc_code(case.grpc_status).unwrap(),
            "contract",
        );
        let response = super::connect_answer(&error, &HeaderMap::new());
        assert_eq!(response.status().as_u16(), case.http_status, "{code}");
        let body = futures_body(response.into_body());
        let rendered: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(rendered["code"], code.as_str());
    }
}

fn futures_body(body: BoxBody) -> bytes::Bytes {
    use http_body_util::BodyExt;
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(body.collect())
        .unwrap()
        .to_bytes()
}

/// `v6`'s JSON field and enum value names are wire contract: renaming a
/// field, harmless to the binary encoding, breaks every JSON client. The
/// names derived from the `.proto` must be the pinned list.
#[test]
fn v6_json_names_are_pinned() {
    let source = include_str!("../../../../proto/sovereign/config/v6/service.proto");
    let mut derived = Vec::new();
    let mut blocks: Vec<(&str, &str)> = Vec::new();
    for raw in source.lines() {
        let line = raw.split("//").next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        if let ["message" | "enum" | "oneof" | "service", name, ..] = words.as_slice() {
            // `message MaskedSecret {}` opens and closes on one line.
            if !line.ends_with('}') {
                blocks.push((words[0], name.trim_end_matches('{')));
            }
            continue;
        }
        if line.starts_with('}') {
            blocks.pop();
            continue;
        }
        let Some(&(kind, _)) = blocks.last() else {
            continue;
        };
        let owner = blocks
            .iter()
            .filter(|(kind, _)| matches!(*kind, "message" | "enum"))
            .map(|(_, name)| *name)
            .collect::<Vec<_>>()
            .join(".");
        let Some((declaration, _)) = line.split_once('=') else {
            continue;
        };
        let declared: Vec<&str> = declaration.split_whitespace().collect();
        match (kind, declared.as_slice()) {
            ("enum", [value]) => derived.push(format!("enum {owner} {value}")),
            ("message" | "oneof", [.., _, name]) => {
                let mut json = String::new();
                let mut upper = false;
                for character in name.chars() {
                    if character == '_' {
                        upper = true;
                    } else if upper {
                        json.push(character.to_ascii_uppercase());
                        upper = false;
                    } else {
                        json.push(character);
                    }
                }
                derived.push(format!("field {owner} {json}"));
            }
            _ => {}
        }
    }
    let pinned: Vec<&str> = include_str!("../../../../test-contracts/v6-json-names.txt")
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .collect();
    assert_eq!(derived, pinned);
}

/// A Connect call's span and RED data point carry the status its Connect
/// answer stands for — read from the outcome the Connect layers leave, since
/// a Connect answer has no `grpc-status` — under the route's own name and
/// the protocol version it names.
#[tokio::test]
async fn a_connect_call_is_spanned_and_timed_with_its_status() {
    use http_body_util::BodyExt as _;
    use sovereign_config_telemetry::testing::Capture;
    use tower::ServiceExt as _;

    let capture = Capture::exporting();
    {
        let _guard = capture.enter();
        let fallback = tower::service_fn(|_: http::Request<BoxBody>| async {
            let mut response = http::Response::new(tonic::body::empty_body());
            *response.status_mut() = StatusCode::NOT_FOUND;
            Ok::<_, std::convert::Infallible>(response)
        });
        let service =
            crate::spans::TraceLayer::new(crate::metrics::RequestMetrics::new(&capture.meter()))
                .layer(
                    GrpcStatusLayer.layer(
                        ConnectShapeLayer.layer(
                            StandInAuthentication.layer(
                                ConnectDispatchLayer::new(service(connect_services(
                                    "postgresql://unused@127.0.0.1:1/unused",
                                )))
                                .layer(fallback),
                            ),
                        ),
                    ),
                );
        for path in [V6_GET_VERSION, V6_GET_IDENTITY] {
            let request = http::Request::builder()
                .method(http::Method::POST)
                .uri(path)
                .header("content-type", "application/json")
                .body(
                    http_body_util::Full::new(bytes::Bytes::from_static(b"{}"))
                        .map_err(|never| match never {})
                        .boxed_unsync(),
                )
                .unwrap();
            let response = service.clone().oneshot(request).await.unwrap();
            response.into_body().collect().await.unwrap();
        }
    }
    let exported = capture.finish();

    for (route, status) in [
        ("sovereign.config.v6.System/GetVersion", "OK"),
        ("sovereign.config.v6.System/GetIdentity", "UNAUTHENTICATED"),
    ] {
        let span = exported.span(route);
        assert_eq!(span.kind, "server");
        assert_eq!(
            span.attribute("rpc.response.status_code"),
            Some(status),
            "{route}"
        );
        assert_eq!(
            span.attribute("sovereign_config.protocol.version"),
            Some("v6")
        );
        let point = exported
            .metric("rpc.server.call.duration")
            .point(&[("rpc.method", route), ("rpc.response.status_code", status)]);
        assert_eq!(point.count, 1, "{route}");
    }
}
