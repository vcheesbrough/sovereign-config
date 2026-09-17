use std::{
    collections::{BTreeSet, HashMap},
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{Form, Router, extract::State, http::StatusCode, routing::post};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use http::{
    HeaderMap, HeaderValue, Method, Request, Response,
    header::{AUTHORIZATION, CONTENT_TYPE},
};
use http_body_util::BodyExt as _;
use reqwest::Url;
use serde_json::{Value, json};
use sovereign_config_core::ConfigPath;
use tokio::{net::TcpListener, task::JoinHandle, time::sleep};
use tonic::body::{BoxBody, empty_body};
use tower::{Layer, ServiceExt, service_fn};

use super::{
    AuthenticatedPrincipal, AuthenticationLayer, Authenticator, Grant, IntrospectionResponse,
    Permission, bearer_token, canonical_prefix, grpc_authentication_layer, is_operational_rpc,
    is_web_asset_request, require_rs256, validate_introspection,
};
use crate::{config::AuthenticationConfig, metrics::AuthenticationMetrics};

const TEST_CLIENT_ID: &str = "introspection-client";
const TEST_CLIENT_SECRET: &str = "introspection-secret-sentinel";

#[test]
fn permissions_are_independent_and_prefixes_stop_at_segment_boundaries() {
    let principal = AuthenticatedPrincipal {
        subject: "principal".into(),
        grants: vec![
            Grant {
                prefix: "/apps/api".into(),
                permissions: BTreeSet::from([Permission::Write]),
            },
            Grant {
                prefix: "/apps/api/private".into(),
                permissions: BTreeSet::from([Permission::Manage]),
            },
        ],
    };
    let api = ConfigPath::parse("/apps/api").unwrap();
    let child = ConfigPath::parse("/apps/api/settings").unwrap();
    let attack = ConfigPath::parse("/apps/apix").unwrap();
    let private = ConfigPath::parse("/apps/api/private/key").unwrap();

    assert!(principal.allows(&api, Permission::Write));
    assert!(principal.allows(&child, Permission::Write));
    assert!(!principal.allows(&child, Permission::Read));
    assert!(!principal.allows(&attack, Permission::Write));
    assert!(principal.allows(&private, Permission::Manage));
    assert!(!principal.allows(&private, Permission::Read));

    let global = AuthenticatedPrincipal {
        subject: "global-principal".into(),
        grants: vec![Grant {
            prefix: "/".into(),
            permissions: BTreeSet::from([Permission::Read]),
        }],
    };
    assert!(global.allows(&private, Permission::Read));
}

#[derive(Clone)]
struct FakeIntrospectionState {
    status: StatusCode,
    body: String,
    delay: Duration,
    calls: Arc<AtomicUsize>,
    basic_auth_valid: Arc<AtomicBool>,
    token_valid: Arc<AtomicBool>,
}

struct FakeIntrospectionServer {
    url: Url,
    state: FakeIntrospectionState,
    task: JoinHandle<()>,
}

impl Drop for FakeIntrospectionServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn introspect(
    State(state): State<FakeIntrospectionState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> (StatusCode, [(&'static str, &'static str); 1], String) {
    state.calls.fetch_add(1, Ordering::Relaxed);
    let expected = format!(
        "Basic {}",
        STANDARD.encode(format!("{TEST_CLIENT_ID}:{TEST_CLIENT_SECRET}"))
    );
    state.basic_auth_valid.store(
        headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            == Some(expected.as_str()),
        Ordering::Relaxed,
    );
    state.token_valid.store(
        form.get("token")
            .is_some_and(|received| received == &token("RS256")),
        Ordering::Relaxed,
    );
    sleep(state.delay).await;
    (
        state.status,
        [("content-type", "application/json")],
        state.body,
    )
}

async fn fake_server(
    status: StatusCode,
    body: impl Into<String>,
    delay: Duration,
) -> FakeIntrospectionServer {
    let state = FakeIntrospectionState {
        status,
        body: body.into(),
        delay,
        calls: Arc::new(AtomicUsize::new(0)),
        basic_auth_valid: Arc::new(AtomicBool::new(false)),
        token_valid: Arc::new(AtomicBool::new(false)),
    };
    let app = Router::new()
        .route("/application/o/introspect/", post(introspect))
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    FakeIntrospectionServer {
        url: format!("http://{address}/application/o/introspect/")
            .parse()
            .unwrap(),
        state,
        task,
    }
}

fn authenticator(url: Url, timeout: Duration) -> Authenticator {
    Authenticator::new(AuthenticationConfig {
        introspection_url: url,
        accepted_identities: vec![crate::config::AcceptedIdentity {
            issuer: "https://issuer.example/application/o/sovereign-config/".to_owned(),
            audience: "sovereign-config".to_owned(),
        }],
        introspection_client_id: TEST_CLIENT_ID.to_owned(),
        introspection_client_secret: TEST_CLIENT_SECRET.to_owned(),
        timeout,
    })
    .unwrap()
}

fn valid_response_json() -> Value {
    json!({
        "active": true,
        "iss": "https://issuer.example/application/o/sovereign-config/",
        "aud": "sovereign-config",
        "sub": "principal-id",
        "scope": "openid sovereign-config",
        "sovereign_config_grants": [
            {"prefix": "/", "permissions": ["read", "write", "manage"]}
        ]
    })
}

fn authenticated_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", token("RS256"))).unwrap(),
    );
    headers
}

fn token(algorithm: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"{algorithm}"}}"#));
    format!("{header}.payload.signature")
}

fn valid_response() -> IntrospectionResponse {
    serde_json::from_value(json!({
        "active": true,
        "iss": "https://issuer.example/application/o/sovereign-config/",
        "aud": "sovereign-config",
        "sub": "principal-id",
        "scope": "openid sovereign-config",
        "sovereign_config_grants": [
            {"prefix": "/", "permissions": ["read", "write", "manage"]},
            {"prefix": "/apps/api", "permissions": ["read"]},
            {"prefix": "/apps/api", "permissions": ["write"]}
        ]
    }))
    .unwrap()
}

#[test]
fn bearer_header_must_be_unique_and_well_formed() {
    let mut headers = HeaderMap::new();
    assert_eq!(
        bearer_token(&headers).unwrap_err().result.reason(),
        "missing_bearer"
    );

    headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer token"));
    assert_eq!(bearer_token(&headers).unwrap(), "token");

    headers.append(AUTHORIZATION, HeaderValue::from_static("Bearer second"));
    assert_eq!(
        bearer_token(&headers).unwrap_err().result.reason(),
        "malformed_bearer"
    );
}

#[test]
fn jose_header_requires_rs256() {
    assert!(require_rs256(&token("RS256")).is_ok());
    assert_eq!(
        require_rs256(&token("HS256")).unwrap_err().result.reason(),
        "wrong_algorithm"
    );
    assert_eq!(
        require_rs256("not-a-jwt").unwrap_err().result.reason(),
        "malformed_bearer"
    );
}

#[test]
fn valid_claims_merge_duplicate_prefix_permissions() {
    let principal = validate_introspection(
        valid_response(),
        "https://issuer.example/application/o/sovereign-config/",
        "sovereign-config",
    )
    .unwrap();

    assert_eq!(principal.subject, "principal-id");
    assert_eq!(principal.grants.len(), 2);
    assert_eq!(
        principal.grants[0].permissions,
        BTreeSet::from([Permission::Read, Permission::Write, Permission::Manage])
    );
    assert_eq!(
        principal.grants[1].permissions,
        BTreeSet::from([Permission::Read, Permission::Write])
    );
}

#[test]
fn inactive_and_wrong_environment_tokens_are_rejected() {
    let mut inactive = valid_response();
    inactive.active = false;
    assert_eq!(
        validate_introspection(inactive, "issuer", "audience")
            .unwrap_err()
            .result
            .reason(),
        "inactive"
    );

    assert_eq!(
        validate_introspection(valid_response(), "wrong-issuer", "sovereign-config")
            .unwrap_err()
            .result
            .reason(),
        "invalid_claims"
    );
    assert_eq!(
        validate_introspection(
            valid_response(),
            "https://issuer.example/application/o/sovereign-config/",
            "sovereign-config-dev",
        )
        .unwrap_err()
        .result
        .reason(),
        "invalid_claims"
    );
}

#[test]
fn audience_arrays_are_supported_without_partial_matches() {
    let mut response = valid_response();
    response.aud = Some(json!(["another-service", "sovereign-config"]));
    assert!(
        validate_introspection(
            response,
            "https://issuer.example/application/o/sovereign-config/",
            "sovereign-config",
        )
        .is_ok()
    );
}

#[test]
fn missing_or_malformed_required_claims_are_rejected() {
    let mut missing_scope = valid_response();
    missing_scope.scope = Some(json!("openid profile"));
    let mut empty_subject = valid_response();
    empty_subject.sub = Some(json!(""));
    let mut malformed_audience = valid_response();
    malformed_audience.aud = Some(json!(["sovereign-config", 42]));

    for response in [missing_scope, empty_subject, malformed_audience] {
        assert_eq!(
            validate_introspection(
                response,
                "https://issuer.example/application/o/sovereign-config/",
                "sovereign-config",
            )
            .unwrap_err()
            .result
            .reason(),
            "invalid_claims"
        );
    }
}

#[test]
fn grants_require_canonical_prefixes_and_known_permissions() {
    for prefix in ["/", "/apps", "/apps/my-api", "/a1/b-2"] {
        assert!(canonical_prefix(prefix).is_some());
    }
    for prefix in ["", "apps", "/apps/", "/apps//api", "/apps/."] {
        assert!(canonical_prefix(prefix).is_none());
    }

    // An uppercase prefix folds rather than being rejected — an operator
    // writing `/Apps/api` in an Authentik grant attribute gets the same
    // coverage as `/apps/api`.
    assert_eq!(canonical_prefix("/Apps/api").as_deref(), Some("/apps/api"));
    let mut response = valid_response();
    response.sovereign_config_grants =
        Some(json!([{"prefix": "/Apps/api", "permissions": ["read"]}]));
    let principal = validate_introspection(
        response,
        "https://issuer.example/application/o/sovereign-config/",
        "sovereign-config",
    )
    .unwrap();
    assert_eq!(principal.grants.len(), 1);
    assert_eq!(principal.grants[0].prefix, "/apps/api");
    let api = ConfigPath::parse("/apps/api").unwrap();
    let mixed_case_child = ConfigPath::parse_operation("/Apps/API/child").unwrap();
    assert!(principal.allows(&api, Permission::Read));
    assert!(principal.allows(&mixed_case_child, Permission::Read));

    let mut response = valid_response();
    response.sovereign_config_grants =
        Some(json!([{"prefix": "/apps/api", "permissions": ["owner"]}]));
    assert_eq!(
        validate_introspection(
            response,
            "https://issuer.example/application/o/sovereign-config/",
            "sovereign-config",
        )
        .unwrap_err()
        .result
        .reason(),
        "invalid_claims"
    );
}

#[test]
fn only_health_and_version_are_operational() {
    assert!(is_operational_rpc("/grpc.health.v1.Health/Check"));
    assert!(is_operational_rpc("/grpc.health.v1.Health/Watch"));
    assert!(is_operational_rpc("/sovereign.config.v3.System/GetVersion"));
    assert!(!is_operational_rpc("/grpc.health.v1.Health/Unknown"));
    assert!(!is_operational_rpc(
        "/sovereign.config.v3.Configuration/GetSubTree"
    ));
}

#[test]
fn browser_asset_requests_do_not_require_authentication() {
    assert!(is_web_asset_request(&Method::GET, "/"));
    assert!(is_web_asset_request(&Method::HEAD, "/app-config.js"));
    assert!(!is_web_asset_request(
        &Method::POST,
        "/sovereign.config.v3.System/GetIdentity"
    ));
    assert!(!is_web_asset_request(
        &Method::GET,
        "/sovereign.config.v3.System/GetVersion"
    ));
}

#[tokio::test]
async fn live_introspection_uses_basic_auth_for_every_request() {
    let server = fake_server(
        StatusCode::OK,
        valid_response_json().to_string(),
        Duration::ZERO,
    )
    .await;
    let authenticator = authenticator(server.url.clone(), Duration::from_secs(1));
    let headers = authenticated_headers();

    assert!(authenticator.authenticate(&headers).await.is_ok());
    assert!(authenticator.authenticate(&headers).await.is_ok());
    assert_eq!(server.state.calls.load(Ordering::Relaxed), 2);
    assert!(server.state.basic_auth_valid.load(Ordering::Relaxed));
    assert!(server.state.token_valid.load(Ordering::Relaxed));
}

#[tokio::test]
async fn dependency_failures_are_unavailable_without_retry() {
    for (status, body) in [
        (StatusCode::SERVICE_UNAVAILABLE, "{}"),
        (StatusCode::OK, "not-json"),
    ] {
        let server = fake_server(status, body, Duration::ZERO).await;
        let authenticator = authenticator(server.url.clone(), Duration::from_secs(1));
        let failure = authenticator
            .authenticate(&authenticated_headers())
            .await
            .unwrap_err();

        assert_eq!(failure.result.reason(), "dependency_unavailable");
        assert_eq!(server.state.calls.load(Ordering::Relaxed), 1);
    }

    let server = fake_server(
        StatusCode::OK,
        valid_response_json().to_string(),
        Duration::from_millis(200),
    )
    .await;
    let authenticator = authenticator(server.url.clone(), Duration::from_millis(25));
    let failure = authenticator
        .authenticate(&authenticated_headers())
        .await
        .unwrap_err();
    assert_eq!(failure.result.reason(), "dependency_unavailable");
    sleep(Duration::from_millis(225)).await;
    assert_eq!(server.state.calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn grpc_web_authentication_failures_are_framed() {
    let server = fake_server(StatusCode::SERVICE_UNAVAILABLE, "{}", Duration::ZERO).await;

    let unauthenticated = grpc_web_status(
        authenticator(server.url.clone(), Duration::from_secs(1)),
        HeaderMap::new(),
    )
    .await;
    let unavailable = grpc_web_status(
        authenticator(server.url.clone(), Duration::from_secs(1)),
        authenticated_headers(),
    )
    .await;

    assert_eq!(unauthenticated, 16);
    assert_eq!(unavailable, 14);
    assert_eq!(server.state.calls.load(Ordering::Relaxed), 1);
}

async fn grpc_web_status(authenticator: Authenticator, headers: HeaderMap) -> u16 {
    let layer =
        grpc_authentication_layer(authenticator, Arc::new(AuthenticationMetrics::default()));
    let inner = service_fn(|_: Request<BoxBody>| async {
        Ok::<_, Infallible>(Response::new(empty_body()))
    });
    let mut request = Request::builder()
        .method(Method::POST)
        .uri("/sovereign.config.v3.System/GetIdentity")
        .header(CONTENT_TYPE, "application/grpc-web+proto")
        .body(empty_body())
        .unwrap();
    request.headers_mut().extend(headers);
    let response = layer.layer(inner).oneshot(request).await.unwrap();
    assert_eq!(
        response.headers().get(CONTENT_TYPE).unwrap(),
        "application/grpc-web+proto"
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.first(), Some(&0x80));
    let length = u32::from_be_bytes(body[1..5].try_into().unwrap()) as usize;
    assert_eq!(length, body.len() - 5);
    std::str::from_utf8(&body[5..])
        .unwrap()
        .lines()
        .find_map(|line| {
            line.strip_prefix("grpc-status:")
                .and_then(|value| value.trim().parse().ok())
        })
        .expect("gRPC-Web response must contain a status trailer")
}

#[tokio::test]
async fn middleware_bypasses_only_operational_rpcs_and_propagates_principal() {
    let server = fake_server(
        StatusCode::OK,
        valid_response_json().to_string(),
        Duration::ZERO,
    )
    .await;
    let layer = AuthenticationLayer::new(
        authenticator(server.url.clone(), Duration::from_secs(1)),
        Arc::new(AuthenticationMetrics::default()),
    );
    let inner = service_fn(|request: Request<()>| async move {
        if request.uri().path() == "/protected.Service/Call" {
            let principal = request
                .extensions()
                .get::<AuthenticatedPrincipal>()
                .expect("protected request must contain its principal");
            assert_eq!(principal.subject, "principal-id");
        }
        Ok::<_, Infallible>(Response::new(empty_body()))
    });

    let version = Request::builder()
        .uri("/sovereign.config.v3.System/GetVersion")
        .body(())
        .unwrap();
    let response = layer.clone().layer(inner).oneshot(version).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(server.state.calls.load(Ordering::Relaxed), 0);

    let mut protected = Request::builder()
        .method(Method::POST)
        .uri("/protected.Service/Call")
        .body(())
        .unwrap();
    *protected.headers_mut() = authenticated_headers();
    let response = layer.clone().layer(inner).oneshot(protected).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(server.state.calls.load(Ordering::Relaxed), 1);

    let unknown = Request::builder()
        .method(Method::POST)
        .uri("/grpc.health.v1.Health/Unknown")
        .body(())
        .unwrap();
    let response = layer.layer(inner).oneshot(unknown).await.unwrap();
    let collected = response.into_body().collect().await.unwrap();
    assert_eq!(
        collected.trailers().unwrap().get("grpc-status").unwrap(),
        "16"
    );
    assert_eq!(server.state.calls.load(Ordering::Relaxed), 1);
}
