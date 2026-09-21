use std::{
    collections::{BTreeSet, HashMap},
    convert::Infallible,
    sync::{
        Arc, Mutex,
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
    AuthenticatedPrincipal, AuthenticationLayer, Authenticator, Grant, HANDSHAKE_RPC,
    IntrospectionResponse, MAX_DISPLAY_NAME_CHARACTERS, Permission, bearer_token, canonical_prefix,
    display_name, grpc_service_layer, is_operational_rpc, is_web_asset_request, require_rs256,
    validate_introspection,
};
use crate::{
    config::AuthenticationConfig,
    metrics::{AuthenticationMetrics, ProtocolMetrics},
    protocol::ProtocolVersionLayer,
    system::SERVED_PROTOCOL_VERSIONS,
};

const TEST_CLIENT_ID: &str = "introspection-client";
const TEST_CLIENT_SECRET: &str = "introspection-secret-sentinel";

#[test]
fn permissions_are_independent_and_prefixes_stop_at_segment_boundaries() {
    let principal = AuthenticatedPrincipal {
        subject: "principal".into(),
        name: None,
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
        name: None,
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

/// Waits until the fixture has recorded at least `expected` arrivals.
///
/// The counter is bumped at the top of the handler, before any configured
/// delay, so this observes arrival rather than completion — which is what lets
/// a test about retries stop guessing at scheduling latency.
async fn arrived(server: &FakeIntrospectionServer, expected: usize, within: Duration) -> bool {
    let deadline = std::time::Instant::now() + within;
    while std::time::Instant::now() < deadline {
        if server.state.calls.load(Ordering::Relaxed) >= expected {
            return true;
        }
        sleep(Duration::from_millis(5)).await;
    }
    false
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
    serde_json::from_value(valid_claims()).unwrap()
}

/// The claims of a valid introspection response, before deserialization, so a
/// test can add or replace one and see what the real `serde` path makes of it.
fn valid_claims() -> Value {
    json!({
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
    })
}

/// A valid response carrying `claims` in addition, deserialized exactly as the
/// authenticator deserializes Authentik's reply.
fn response_with(claims: &[(&str, Value)]) -> IntrospectionResponse {
    let mut body = valid_claims();
    for (name, value) in claims {
        body[*name] = value.clone();
    }
    serde_json::from_value(body).expect("any claim value must deserialize")
}

fn authenticate(response: IntrospectionResponse) -> AuthenticatedPrincipal {
    validate_introspection(
        response,
        "https://issuer.example/application/o/sovereign-config/",
        "sovereign-config",
    )
    .expect("a valid response must authenticate")
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
fn the_display_name_prefers_preferred_username_and_falls_back_to_username() {
    let name = |preferred: Option<Value>, username: Option<Value>| {
        display_name(preferred.as_ref(), username.as_ref())
    };

    assert_eq!(
        name(Some(json!("alice")), Some(json!("alice-sa"))).as_deref(),
        Some("alice")
    );
    assert_eq!(
        name(None, Some(json!("alice-sa"))).as_deref(),
        Some("alice-sa")
    );
    // A preferred name that is empty once cleaned is no name at all, so the
    // fallback is used rather than an empty label.
    for unusable in [json!(""), json!("   "), json!("\u{7}\u{1b}"), json!(42)] {
        assert_eq!(
            name(Some(unusable.clone()), Some(json!("alice-sa"))).as_deref(),
            Some("alice-sa"),
            "{unusable}"
        );
    }
    assert_eq!(name(None, None), None);
    assert_eq!(name(Some(json!(null)), Some(json!({"a": 1}))), None);
}

#[test]
fn the_display_name_is_stripped_of_control_characters_trimmed_and_bounded() {
    let name = |claim: &str| display_name(Some(&json!(claim)), None);

    assert_eq!(name("  ali\u{7}ce\n ").as_deref(), Some("alice"));
    let long = "x".repeat(MAX_DISPLAY_NAME_CHARACTERS + 50);
    assert_eq!(
        name(&long).map(|kept| kept.chars().count()),
        Some(MAX_DISPLAY_NAME_CHARACTERS)
    );
    // Bounded in characters, not bytes, so a multi-byte name is not cut
    // through the middle of a character.
    let wide = "é".repeat(MAX_DISPLAY_NAME_CHARACTERS + 1);
    assert_eq!(name(&wide), Some("é".repeat(MAX_DISPLAY_NAME_CHARACTERS)));
}

/// The name decides nothing, so no value of either claim may fail
/// authentication. Driven through `serde` deliberately: tightening a claim's
/// field to `Option<String>` would reject these at deserialization and lock
/// out every identity whose provider sends one, and only this layer sees it.
#[test]
fn no_value_of_a_name_claim_can_fail_authentication() {
    for odd in [
        json!(42),
        json!({"nested": "object"}),
        json!(["a", "b"]),
        json!(true),
        json!(null),
        json!(""),
    ] {
        for claim in ["preferred_username", "username"] {
            let principal = authenticate(response_with(&[(claim, odd.clone())]));
            assert_eq!(principal.subject, "principal-id", "{claim}: {odd}");
            assert_eq!(principal.name, None, "{claim}: {odd}");
        }
    }
}

#[test]
fn a_name_claim_reaches_the_principal_without_affecting_its_grants() {
    let principal = authenticate(response_with(&[
        ("preferred_username", json!("alice")),
        ("username", json!("alice-service")),
    ]));

    assert_eq!(principal.name.as_deref(), Some("alice"));
    assert_eq!(
        principal,
        AuthenticatedPrincipal {
            name: Some("alice".into()),
            ..authenticate(valid_response())
        }
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
fn only_health_the_handshake_and_version_are_operational() {
    assert!(is_operational_rpc("/grpc.health.v1.Health/Check"));
    assert!(is_operational_rpc("/grpc.health.v1.Health/Watch"));
    assert!(is_operational_rpc("/sovereign.config.v3.System/GetVersion"));
    // The unversioned handshake. A client calls it before it holds any token,
    // so losing this exemption breaks negotiation for the whole fleet — and
    // breaks it *silently*, because a client reads `UNAUTHENTICATED` here as
    // "this server predates the handshake" and falls back to the legacy route
    // forever. Nothing else would go red: handshake calls are counted under no
    // version.
    assert!(is_operational_rpc(HANDSHAKE_RPC));
    assert!(is_operational_rpc("/sovereign.config.Handshake/Negotiate"));
    assert!(!is_operational_rpc("/grpc.health.v1.Health/Unknown"));
    assert!(!is_operational_rpc(
        "/sovereign.config.v3.Configuration/GetSubTree"
    ));
    // Only the handshake's own method, not the whole unversioned package.
    assert!(!is_operational_rpc("/sovereign.config.Handshake/Other"));
}

/// `GetVersion` must stay unauthenticated on **every** served version, not just
/// on whichever one happened to be hardcoded.
///
/// Negotiation runs before any token exists, so a served version whose
/// `GetVersion` required authentication would fail every client at connect —
/// before it could discover which versions are served. Deriving the exemption
/// from `SERVED_PROTOCOL_VERSIONS` is what stops a newly introduced version
/// being unreachable, so this asserts the derivation rather than a literal.
#[test]
fn the_version_handshake_is_unauthenticated_on_every_served_version() {
    for served in SERVED_PROTOCOL_VERSIONS {
        let version = served.version.as_str();
        assert!(
            is_operational_rpc(&format!("/sovereign.config.{version}.System/GetVersion")),
            "GetVersion must be unauthenticated on served version {version}"
        );
    }
}

#[test]
fn only_the_version_handshake_of_a_served_version_is_exempt() {
    // An unserved version gets no exemption: it has no route to reach anyway,
    // and exempting arbitrary packages would widen the unauthenticated surface.
    assert!(!is_operational_rpc(
        "/sovereign.config.v99.System/GetVersion"
    ));
    // Only `GetVersion` is exempt, never another method on the same service.
    assert!(!is_operational_rpc(
        "/sovereign.config.v3.System/GetIdentity"
    ));
    // Near-misses must not slip through the strip-prefix/strip-suffix match.
    for path in [
        "/sovereign.config.v3.System/GetVersionExtra",
        "/sovereign.config.v3.Other.System/GetVersion",
        "/prefix/sovereign.config.v3.System/GetVersion",
        "/sovereign.config..System/GetVersion",
    ] {
        assert!(
            !is_operational_rpc(path),
            "{path} must require authentication"
        );
    }
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

    // This asserts that a timed-out introspection is **not retried**, which
    // needs the request to have *arrived* before the deadline — otherwise the
    // counter reads zero because nothing ever happened, not because nothing was
    // retried, and the test passes for the wrong reason.
    //
    // The original 25ms deadline could not establish that. It covers connection
    // setup as well as the request, so on a busy machine it expires while the
    // connection is still being made and the fixture never sees anything at
    // all — confirmed by watching this very assertion time out against a
    // ten-second poll. The deadline is therefore generous enough for the
    // request to land, while the server's delay stays far above it so the
    // timeout under test still fires. Arrival is then waited for directly,
    // using the count the fixture takes at the top of its handler before it
    // sleeps, rather than guessed at with a sleep.
    let server = fake_server(
        StatusCode::OK,
        valid_response_json().to_string(),
        Duration::from_secs(5),
    )
    .await;
    let authenticator = authenticator(server.url.clone(), Duration::from_millis(250));
    let failure = authenticator
        .authenticate(&authenticated_headers())
        .await
        .unwrap_err();
    assert_eq!(failure.result.reason(), "dependency_unavailable");

    assert!(
        arrived(&server, 1, Duration::from_secs(10)).await,
        "the introspection request never reached the fixture, so this test \
         could not have observed a retry either way"
    );
    // `authenticate` has already returned, so a retry would have been issued by
    // now; a brief settle is enough to catch one in flight.
    sleep(Duration::from_millis(50)).await;
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
    let layer = grpc_service_layer(
        authenticator,
        Arc::new(AuthenticationMetrics::default()),
        Arc::new(ProtocolMetrics::new(&["v3"])),
        &["v3"],
    );
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
        Arc::new(ProtocolMetrics::new(&["v3"])),
    );
    // Every path the inner service is actually reached on. A refusal by the
    // authentication layer is an HTTP 200 carrying a gRPC status in trailers,
    // so the response status alone cannot tell "passed through" from "refused"
    // — only whether the inner service ran can.
    let reached: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&reached);
    let inner = service_fn(move |request: Request<()>| {
        let seen = Arc::clone(&seen);
        async move {
            seen.lock()
                .expect("the reached-path log is not poisoned")
                .push(request.uri().path().to_owned());
            if request.uri().path() == "/protected.Service/Call" {
                let principal = request
                    .extensions()
                    .get::<AuthenticatedPrincipal>()
                    .expect("protected request must contain its principal");
                assert_eq!(principal.subject, "principal-id");
            }
            Ok::<_, Infallible>(Response::new(empty_body()))
        }
    });

    let version = Request::builder()
        .uri("/sovereign.config.v3.System/GetVersion")
        .body(())
        .unwrap();
    let response = layer
        .clone()
        .layer(inner.clone())
        .oneshot(version)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(server.state.calls.load(Ordering::Relaxed), 0);

    // The unversioned handshake, carrying no bearer token at all — which is how
    // every client calls it, because it runs before a token exists. It must
    // reach the service beneath, not merely come back 200.
    let handshake = Request::builder()
        .method(Method::POST)
        .uri(HANDSHAKE_RPC)
        .body(())
        .unwrap();
    let response = layer
        .clone()
        .layer(inner.clone())
        .oneshot(handshake)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        reached
            .lock()
            .expect("the reached-path log is not poisoned")
            .iter()
            .any(|path| path == HANDSHAKE_RPC),
        "an unauthenticated handshake must pass through to the service beneath"
    );
    assert_eq!(
        server.state.calls.load(Ordering::Relaxed),
        0,
        "the handshake must not reach the introspection endpoint"
    );

    let mut protected = Request::builder()
        .method(Method::POST)
        .uri("/protected.Service/Call")
        .body(())
        .unwrap();
    *protected.headers_mut() = authenticated_headers();
    let response = layer
        .clone()
        .layer(inner.clone())
        .oneshot(protected)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(server.state.calls.load(Ordering::Relaxed), 1);

    let unknown = Request::builder()
        .method(Method::POST)
        .uri("/grpc.health.v1.Health/Unknown")
        .body(())
        .unwrap();
    let response = layer.layer(inner.clone()).oneshot(unknown).await.unwrap();
    let collected = response.into_body().collect().await.unwrap();
    assert_eq!(
        collected.trailers().unwrap().get("grpc-status").unwrap(),
        "16"
    );
    assert_eq!(server.state.calls.load(Ordering::Relaxed), 1);
}

/// The `authenticated` series is the retirement gate, so it must move only for
/// traffic that actually passed authentication.
///
/// Drives the production layer order — protocol layer outside, authentication
/// inside — with one request that authenticates and one that does not. Both are
/// `attempted`; only the first is `authenticated`. The unauthenticated one
/// stands in for everything that can reach a public endpoint without being a
/// consumer: a scanner, or an application whose credentials were revoked but
/// whose process still retries. Neither would break if the version were
/// retired, so neither may hold the gate above zero.
#[tokio::test]
async fn only_authenticated_traffic_moves_the_retirement_gate() {
    let server = fake_server(
        StatusCode::OK,
        valid_response_json().to_string(),
        Duration::ZERO,
    )
    .await;
    let protocol_metrics = Arc::new(ProtocolMetrics::new(&["v3"]));
    let stack = tower::ServiceBuilder::new()
        .layer(ProtocolVersionLayer::new(
            Arc::clone(&protocol_metrics),
            &["v3"],
        ))
        .layer(AuthenticationLayer::new(
            authenticator(server.url.clone(), Duration::from_secs(1)),
            Arc::new(AuthenticationMetrics::default()),
            Arc::clone(&protocol_metrics),
        ));
    let inner =
        service_fn(|_: Request<()>| async { Ok::<_, Infallible>(Response::new(empty_body())) });

    let mut authenticated = Request::builder()
        .method(Method::POST)
        .uri("/sovereign.config.v3.Configuration/GetSubTree")
        .body(())
        .unwrap();
    *authenticated.headers_mut() = authenticated_headers();
    stack
        .clone()
        .service(inner)
        .oneshot(authenticated)
        .await
        .unwrap();

    let anonymous = Request::builder()
        .method(Method::POST)
        .uri("/sovereign.config.v3.Configuration/GetSubTree")
        .body(())
        .unwrap();
    stack
        .clone()
        .service(inner)
        .oneshot(anonymous)
        .await
        .unwrap();

    // The handshake bypasses authentication entirely, so it is attempted-only:
    // anyone may call it, and it says nothing about ongoing use.
    let handshake = Request::builder()
        .method(Method::POST)
        .uri("/sovereign.config.v3.System/GetVersion")
        .body(())
        .unwrap();
    stack.service(inner).oneshot(handshake).await.unwrap();

    let rendered = protocol_metrics.render();
    assert!(
        rendered.contains(
            "sovereign_config_protocol_requests_total{version=\"v3\",outcome=\"attempted\"} 3"
        ),
        "{rendered}"
    );
    assert!(
        rendered.contains(
            "sovereign_config_protocol_requests_total{version=\"v3\",outcome=\"authenticated\"} 1"
        ),
        "{rendered}"
    );
}
