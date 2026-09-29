use std::{
    collections::BTreeSet,
    convert::Infallible,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{Router, extract::State, http::StatusCode, routing::get};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::{
    HeaderMap, HeaderValue, Method, Request, Response,
    header::{AUTHORIZATION, CONTENT_TYPE},
};
use http_body_util::BodyExt as _;
use ring::{
    rand::SystemRandom,
    signature::{RSA_PKCS1_SHA256, RsaKeyPair, RsaPublicKeyComponents},
};
use serde_json::{Value, json};
use sovereign_config_core::ConfigPath;
use tokio::{net::TcpListener, task::JoinHandle, time::sleep};
use tonic::body::{BoxBody, empty_body};
use tower::{Layer, ServiceExt, service_fn};

use super::{
    AuthenticatedPrincipal, AuthenticationLayer, Authenticator, CLOCK_LEEWAY, Grant, HANDSHAKE_RPC,
    MAX_DISPLAY_NAME_CHARACTERS, MAX_JWKS_RESPONSE_BYTES, Permission, TokenClaims, bearer_token,
    canonical_prefix, display_name, grpc_service_layer, is_operational_rpc, is_web_asset_request,
    parse_jwt, require_current, validate_for,
};
use crate::{
    config::{AcceptedIdentity, AuthenticationConfig},
    metrics::{AuthenticationMetrics, ProtocolMetrics},
    protocol::ProtocolVersionLayer,
    system::SERVED_PROTOCOL_VERSIONS,
};

/// The issuer the claim-validation tests expect, which no test ever fetches
/// from: those tests call [`validate_for`] directly.
const ISSUER: &str = "https://issuer.example/application/o/sovereign-config/";
/// Where [`FakeJwks`] serves each issuer's key set: `<issuer>jwks/`.
const ISSUER_PATH: &str = "/application/o/sovereign-config/";
const KID_A: &str = "key-a";
const KID_B: &str = "key-b";

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

/// A throwaway RSA-2048 key, PKCS#1 DER, generated for these tests alone.
fn test_key(kid: &str) -> RsaKeyPair {
    let der: &[u8] = match kid {
        KID_A => include_bytes!("testdata/test-key-a.der"),
        KID_B => include_bytes!("testdata/test-key-b.der"),
        other => panic!("no test key {other}"),
    };
    RsaKeyPair::from_der(der).unwrap()
}

/// The public half of a test key as Authentik publishes it.
fn jwk(kid: &str) -> Value {
    let public = RsaPublicKeyComponents::<Vec<u8>>::from(test_key(kid).public());
    json!({
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "kid": kid,
        "n": URL_SAFE_NO_PAD.encode(public.n),
        "e": URL_SAFE_NO_PAD.encode(public.e),
    })
}

fn key_set(kids: &[&str]) -> String {
    json!({ "keys": kids.iter().map(|kid| jwk(kid)).collect::<Vec<_>>() }).to_string()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A JWS compact token of `header` and `claims`, signed RS256 by `signer`
/// whatever the header claims.
fn signed(header: &Value, claims: &Value, signer: &str) -> String {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let key = test_key(signer);
    let mut signature = vec![0; key.public().modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        input.as_bytes(),
        &mut signature,
    )
    .unwrap();
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

#[derive(Clone)]
struct FakeJwksState {
    status: Arc<Mutex<StatusCode>>,
    body: Arc<Mutex<String>>,
    delay: Duration,
    calls: Arc<AtomicUsize>,
}

/// An issuer serving its key set at `<issuer>jwks/`, whose answer a test can
/// change between requests — to rotate a key, or to go away.
struct FakeJwks {
    issuer: String,
    state: FakeJwksState,
    task: JoinHandle<()>,
}

impl Drop for FakeJwks {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeJwks {
    fn calls(&self) -> usize {
        self.state.calls.load(Ordering::Relaxed)
    }

    fn serve(&self, status: StatusCode, body: impl Into<String>) {
        *self.state.status.lock().unwrap() = status;
        *self.state.body.lock().unwrap() = body.into();
    }

    /// Claims a valid token of this issuer carries.
    fn claims(&self) -> Value {
        json!({
            "iss": self.issuer,
            "aud": "sovereign-config",
            "sub": "principal-id",
            "scope": "openid sovereign-config",
            "exp": now() + 300,
            "iat": now(),
            "sovereign_config_grants": [
                {"prefix": "/", "permissions": ["read", "write", "manage"]}
            ]
        })
    }

    fn token(&self) -> String {
        token_with(&self.claims())
    }

    fn headers(&self) -> HeaderMap {
        bearer(&self.token())
    }

    fn authenticator(&self, timeout: Duration) -> Authenticator {
        self.authenticator_with_refresh_interval(timeout, Duration::from_secs(60))
    }

    fn authenticator_with_refresh_interval(
        &self,
        timeout: Duration,
        min_refresh_interval: Duration,
    ) -> Authenticator {
        Authenticator::with_refresh_interval(
            AuthenticationConfig {
                accepted_identities: vec![AcceptedIdentity {
                    issuer: self.issuer.clone(),
                    audience: "sovereign-config".to_owned(),
                }],
                timeout,
            },
            min_refresh_interval,
        )
        .unwrap()
    }
}

async fn jwks(
    State(state): State<FakeJwksState>,
) -> (StatusCode, [(&'static str, &'static str); 1], String) {
    state.calls.fetch_add(1, Ordering::Relaxed);
    sleep(state.delay).await;
    let status = *state.status.lock().unwrap();
    let body = state.body.lock().unwrap().clone();
    (status, [("content-type", "application/json")], body)
}

async fn fake_jwks(status: StatusCode, body: impl Into<String>, delay: Duration) -> FakeJwks {
    let state = FakeJwksState {
        status: Arc::new(Mutex::new(status)),
        body: Arc::new(Mutex::new(body.into())),
        delay,
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let app = Router::new()
        .route(&format!("{ISSUER_PATH}jwks/"), get(jwks))
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    FakeJwks {
        issuer: format!("http://{address}{ISSUER_PATH}"),
        state,
        task,
    }
}

/// A token carrying `claims`, signed by key A and naming it.
fn token_with(claims: &Value) -> String {
    signed(&json!({"alg": "RS256", "kid": KID_A}), claims, KID_A)
}

/// An issuer publishing key A, answering at once.
async fn issuer() -> FakeJwks {
    fake_jwks(StatusCode::OK, key_set(&[KID_A]), Duration::ZERO).await
}

/// Waits until the fixture has recorded at least `expected` arrivals.
///
/// The counter is bumped at the top of the handler, before any configured
/// delay, so this observes arrival rather than completion — which is what lets
/// a test about retries stop guessing at scheduling latency.
async fn arrived(server: &FakeJwks, expected: usize, within: Duration) -> bool {
    let deadline = std::time::Instant::now() + within;
    while std::time::Instant::now() < deadline {
        if server.calls() >= expected {
            return true;
        }
        sleep(Duration::from_millis(5)).await;
    }
    false
}

fn bearer(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    headers
}

/// An unsigned token with `header`, for the checks made before any key.
fn unsigned(header: &Value) -> String {
    format!(
        "{}.{}.c2lnbmF0dXJl",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(r#"{"iss":"x"}"#)
    )
}

fn valid_response() -> TokenClaims {
    serde_json::from_value(valid_claims()).unwrap()
}

/// The claims of a valid token, before deserialization, so a test can add or
/// replace one and see what the real `serde` path makes of it.
fn valid_claims() -> Value {
    json!({
        "iss": ISSUER,
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

/// Valid claims carrying `claims` in addition, deserialized exactly as the
/// authenticator deserializes a token's payload.
fn response_with(claims: &[(&str, Value)]) -> TokenClaims {
    let mut body = valid_claims();
    for (name, value) in claims {
        body[*name] = value.clone();
    }
    serde_json::from_value(body).expect("any claim value must deserialize")
}

fn authenticate(response: TokenClaims) -> AuthenticatedPrincipal {
    validate_for(response, ISSUER, "sovereign-config").expect("valid claims must authenticate")
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
fn jose_header_requires_rs256_and_a_key_id() {
    assert!(parse_jwt(&unsigned(&json!({"alg": "RS256", "kid": KID_A}))).is_ok());
    for (header, reason) in [
        (json!({"alg": "HS256", "kid": KID_A}), "wrong_algorithm"),
        (json!({"alg": "none", "kid": KID_A}), "wrong_algorithm"),
        (json!({"alg": "RS256"}), "malformed_bearer"),
        (json!({"alg": "RS256", "kid": ""}), "malformed_bearer"),
    ] {
        assert_eq!(
            parse_jwt(&unsigned(&header)).err().unwrap().result.reason(),
            reason,
            "{header}"
        );
    }
    for malformed in [
        "not-a-jwt",
        "a.b",
        "a.b.c.d",
        "..",
        &format!(
            "{}.not-base64!.c2ln",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","kid":"k"}"#)
        ),
        &format!(
            "{}.{}.c2ln",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","kid":"k"}"#),
            URL_SAFE_NO_PAD.encode("[1]")
        ),
    ] {
        assert_eq!(
            parse_jwt(malformed).err().unwrap().result.reason(),
            "malformed_bearer",
            "{malformed}"
        );
    }
}

/// `exp` is required and `nbf`/`iat` are honoured, each with the fixed leeway
/// for clock skew and not a second more.
#[test]
fn only_a_token_inside_its_validity_window_is_current() {
    let now = SystemTime::now();
    let at = |offset: i64| {
        let seconds = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
        json!(seconds.checked_add_signed(offset).unwrap())
    };
    let leeway = i64::try_from(CLOCK_LEEWAY.as_secs()).unwrap();
    let check = |claims: &[(&str, Value)]| {
        require_current(&response_with(claims), now).map_err(|failure| failure.result.reason())
    };

    assert_eq!(check(&[("exp", at(300))]), Ok(()));
    // Expired, but within the leeway: skew, not expiry.
    assert_eq!(check(&[("exp", at(-leeway + 5))]), Ok(()));
    assert_eq!(check(&[("exp", at(-leeway - 5))]), Err("inactive"));
    assert_eq!(check(&[("exp", at(300)), ("nbf", at(leeway - 5))]), Ok(()));
    assert_eq!(
        check(&[("exp", at(300)), ("nbf", at(leeway + 60))]),
        Err("inactive")
    );
    assert_eq!(
        check(&[("exp", at(300)), ("iat", at(leeway + 60))]),
        Err("inactive")
    );
    assert_eq!(check(&[]), Err("invalid_claims"));
    assert_eq!(check(&[("exp", json!("tomorrow"))]), Err("invalid_claims"));
}

#[test]
fn valid_claims_merge_duplicate_prefix_permissions() {
    let principal = validate_for(valid_response(), ISSUER, "sovereign-config").unwrap();

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
fn wrong_environment_tokens_are_rejected() {
    assert_eq!(
        validate_for(valid_response(), "wrong-issuer", "sovereign-config")
            .unwrap_err()
            .result
            .reason(),
        "invalid_claims"
    );
    assert_eq!(
        validate_for(valid_response(), ISSUER, "sovereign-config-dev",)
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
    assert!(validate_for(response, ISSUER, "sovereign-config",).is_ok());
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
            validate_for(response, ISSUER, "sovereign-config",)
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
    let principal = validate_for(response, ISSUER, "sovereign-config").unwrap();
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
        validate_for(response, ISSUER, "sovereign-config",)
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

/// The principal is built from the verified token exactly as it was from an
/// introspection response carrying the same claims: grants folded, the
/// display name taken from `preferred_username`.
#[tokio::test]
async fn a_valid_token_authenticates_as_the_principal_its_claims_describe() {
    let server = issuer().await;
    let mut claims = server.claims();
    claims["preferred_username"] = json!("alice");
    claims["sovereign_config_grants"] = json!([
        {"prefix": "/", "permissions": ["read"]},
        {"prefix": "/Apps/api", "permissions": ["read"]},
        {"prefix": "/apps/api", "permissions": ["write"]}
    ]);

    let principal = server
        .authenticator(Duration::from_secs(1))
        .authenticate(&bearer(&token_with(&claims)))
        .await
        .unwrap();

    assert_eq!(
        principal,
        AuthenticatedPrincipal {
            subject: "principal-id".into(),
            name: Some("alice".into()),
            grants: vec![
                Grant {
                    prefix: "/".into(),
                    permissions: BTreeSet::from([Permission::Read]),
                },
                Grant {
                    prefix: "/apps/api".into(),
                    permissions: BTreeSet::from([Permission::Read, Permission::Write]),
                },
            ],
        }
    );
}

/// The keys are fetched once and every later token is verified in memory: no
/// request to the issuer per call, which is the point of the change.
#[tokio::test]
async fn keys_are_fetched_once_and_reused() {
    let server = issuer().await;
    let authenticator = server.authenticator(Duration::from_secs(1));

    for _ in 0..5 {
        authenticator.authenticate(&server.headers()).await.unwrap();
    }
    assert_eq!(server.calls(), 1);
}

/// Everything a verified signature and a validity window refuse, each with
/// the reason it is counted under, and none of them `UNAVAILABLE`.
#[tokio::test]
async fn forged_expired_and_misdirected_tokens_are_refused() {
    let server = fake_jwks(StatusCode::OK, key_set(&[KID_A, KID_B]), Duration::ZERO).await;
    let authenticator = server.authenticator(Duration::from_secs(1));
    let claims = server.claims();
    let with = |name: &str, value: Value| {
        let mut changed = claims.clone();
        changed[name] = value;
        changed
    };
    let header_a = json!({"alg": "RS256", "kid": KID_A});
    let payload_a = server.token().split('.').nth(1).unwrap().to_owned();
    let tampered = {
        let genuine = server.token();
        let signature = genuine.rsplit('.').next().unwrap().to_owned();
        let altered = with(
            "sovereign_config_grants",
            json!([{"prefix": "/", "permissions": ["manage"]}]),
        );
        format!(
            "{}.{}.{signature}",
            URL_SAFE_NO_PAD.encode(header_a.to_string()),
            URL_SAFE_NO_PAD.encode(altered.to_string())
        )
    };
    let mut cases = vec![
        // Signed by key B while naming key A.
        (signed(&header_a, &claims, KID_B), "bad_signature"),
        // Claims altered after signing.
        (tampered, "bad_signature"),
        // A signature cut from another token.
        (
            format!(
                "{}.{payload_a}.AAAA",
                URL_SAFE_NO_PAD.encode(header_a.to_string())
            ),
            "bad_signature",
        ),
        // `none` and HMAC never reach a key.
        (
            signed(&json!({"alg": "none", "kid": KID_A}), &claims, KID_A),
            "wrong_algorithm",
        ),
        (
            signed(&json!({"alg": "HS256", "kid": KID_A}), &claims, KID_A),
            "wrong_algorithm",
        ),
        // Expired beyond the leeway, and not yet valid.
        (token_with(&with("exp", json!(now() - 120))), "inactive"),
        (token_with(&with("nbf", json!(now() + 600))), "inactive"),
        // Wrong audience, missing scope, empty subject, malformed grants.
        (
            token_with(&with("aud", json!("sovereign-config-dev"))),
            "invalid_claims",
        ),
        (
            token_with(&with("scope", json!("openid profile"))),
            "invalid_claims",
        ),
        (token_with(&with("sub", json!(""))), "invalid_claims"),
        (
            token_with(&with(
                "sovereign_config_grants",
                json!([{"prefix": "/", "permissions": ["owner"]}]),
            )),
            "invalid_claims",
        ),
    ];
    // An issuer that is not configured is refused before any key is sought.
    cases.push((
        token_with(&with(
            "iss",
            json!("https://elsewhere.example/application/o/x/"),
        )),
        "invalid_claims",
    ));
    for (token, reason) in cases {
        let failure = authenticator
            .authenticate(&bearer(&token))
            .await
            .unwrap_err();
        assert_eq!(failure.result.reason(), reason, "{token}");
        assert_eq!(failure.status().code(), tonic::Code::Unauthenticated);
    }
    assert_eq!(
        server.calls(),
        1,
        "only the issuer's own key set was fetched"
    );
}

/// A token cannot supply its own key. `jku`, `x5u` and an embedded `jwk`
/// pointing at the forger's key are ignored, so a token signed with that key
/// still fails on the issuer's — and nothing is fetched from where they point.
#[tokio::test]
async fn a_token_naming_its_own_key_is_still_verified_against_the_issuer() {
    let server = issuer().await;
    let elsewhere = fake_jwks(StatusCode::OK, key_set(&[KID_B]), Duration::ZERO).await;
    let authenticator = server.authenticator(Duration::from_secs(1));
    let header = json!({
        "alg": "RS256",
        "kid": KID_A,
        "jku": format!("{}jwks/", elsewhere.issuer),
        "x5u": format!("{}jwks/", elsewhere.issuer),
        "jwk": jwk(KID_B),
    });

    let failure = authenticator
        .authenticate(&bearer(&signed(&header, &server.claims(), KID_B)))
        .await
        .unwrap_err();

    assert_eq!(failure.result.reason(), "bad_signature");
    assert_eq!(elsewhere.calls(), 0);
}

/// Authentik rotates by swapping the provider's signing key. The first token
/// naming the new key refreshes the set once and is accepted; later ones need
/// no fetch at all.
#[tokio::test]
async fn a_new_signing_key_is_picked_up_with_exactly_one_refresh() {
    let server = issuer().await;
    let authenticator =
        server.authenticator_with_refresh_interval(Duration::from_secs(1), Duration::ZERO);
    authenticator.authenticate(&server.headers()).await.unwrap();
    assert_eq!(server.calls(), 1);

    server.serve(StatusCode::OK, key_set(&[KID_B]));
    let rotated = bearer(&signed(
        &json!({"alg": "RS256", "kid": KID_B}),
        &server.claims(),
        KID_B,
    ));
    authenticator.authenticate(&rotated).await.unwrap();
    assert_eq!(server.calls(), 2);
    authenticator.authenticate(&rotated).await.unwrap();
    assert_eq!(server.calls(), 2);

    // The refresh replaced the set: the retired key verifies nothing now.
    let retired = authenticator
        .authenticate(&server.headers())
        .await
        .unwrap_err();
    assert_eq!(retired.result.reason(), "bad_signature");
}

/// Unknown `kid`s cannot be turned into requests to the issuer: within the
/// refresh interval they are refused from the cache, and concurrent misses
/// share one fetch.
#[tokio::test]
async fn a_flood_of_unknown_keys_is_bounded_by_the_refresh_interval() {
    let server = issuer().await;
    let authenticator = server.authenticator(Duration::from_secs(1));

    // A cold cache: concurrent first calls coalesce into one fetch.
    let first = futures_join_all((0..20).map(|_| {
        let authenticator = authenticator.clone();
        let headers = server.headers();
        async move { authenticator.authenticate(&headers).await.is_ok() }
    }))
    .await;
    assert!(first.into_iter().all(|accepted| accepted));
    assert_eq!(server.calls(), 1);

    let flood = futures_join_all((0..50).map(|index| {
        let authenticator = authenticator.clone();
        let headers = bearer(&signed(
            &json!({"alg": "RS256", "kid": format!("invented-{index}")}),
            &server.claims(),
            KID_A,
        ));
        async move {
            authenticator
                .authenticate(&headers)
                .await
                .unwrap_err()
                .result
                .reason()
        }
    }))
    .await;
    assert!(
        flood.iter().all(|reason| *reason == "bad_signature"),
        "{flood:?}"
    );
    assert_eq!(server.calls(), 1, "no fetch inside the refresh interval");
}

async fn futures_join_all<F: std::future::Future + Send + 'static>(
    futures: impl Iterator<Item = F>,
) -> Vec<F::Output>
where
    F::Output: Send + 'static,
{
    let handles: Vec<_> = futures.map(tokio::spawn).collect();
    let mut outputs = Vec::with_capacity(handles.len());
    for handle in handles {
        outputs.push(handle.await.unwrap());
    }
    outputs
}

/// With the issuer unreachable, a token whose key is cached still verifies;
/// one whose key is not is `UNAVAILABLE` — it may be genuine, signed by a key
/// this server cannot fetch — never `UNAUTHENTICATED`.
#[tokio::test]
async fn an_unreachable_issuer_fails_only_the_tokens_whose_key_is_not_cached() {
    let server = issuer().await;
    let authenticator =
        server.authenticator_with_refresh_interval(Duration::from_secs(1), Duration::ZERO);
    authenticator.authenticate(&server.headers()).await.unwrap();

    server.serve(StatusCode::SERVICE_UNAVAILABLE, "{}");
    authenticator.authenticate(&server.headers()).await.unwrap();
    let uncached = bearer(&signed(
        &json!({"alg": "RS256", "kid": KID_B}),
        &server.claims(),
        KID_B,
    ));
    let failure = authenticator.authenticate(&uncached).await.unwrap_err();
    assert_eq!(failure.result.reason(), "dependency_unavailable");
    assert_eq!(failure.status().code(), tonic::Code::Unavailable);

    // The failed fetch kept the last good set.
    authenticator.authenticate(&server.headers()).await.unwrap();
}

/// A key set that cannot be read is an unavailable dependency, whatever is
/// wrong with it, and none is retried within the request.
#[tokio::test]
async fn dependency_failures_are_unavailable_without_retry() {
    let oversized = json!({
        "keys": [jwk(KID_A)],
        "padding": "x".repeat(MAX_JWKS_RESPONSE_BYTES),
    })
    .to_string();
    for (status, body) in [
        (StatusCode::SERVICE_UNAVAILABLE, key_set(&[KID_A])),
        (StatusCode::OK, "not-json".to_owned()),
        (StatusCode::OK, json!({"no": "keys"}).to_string()),
        (StatusCode::OK, oversized),
        // A redirect is not followed: keys come from the issuer's own URL.
        (StatusCode::FOUND, key_set(&[KID_A])),
    ] {
        let server = fake_jwks(status, body, Duration::ZERO).await;
        let authenticator = server.authenticator(Duration::from_secs(1));
        let failure = authenticator
            .authenticate(&server.headers())
            .await
            .unwrap_err();

        assert_eq!(
            failure.result.reason(),
            "dependency_unavailable",
            "{status}"
        );
        assert_eq!(server.calls(), 1);
    }

    // This asserts that a timed-out fetch is **not retried**, which needs the
    // request to have *arrived* before the deadline — otherwise the counter
    // reads zero because nothing ever happened, not because nothing was
    // retried, and the test passes for the wrong reason. The deadline is
    // generous enough for the request to land, while the server's delay stays
    // far above it so the timeout under test still fires.
    let server = fake_jwks(StatusCode::OK, key_set(&[KID_A]), Duration::from_secs(5)).await;
    let authenticator = server.authenticator(Duration::from_millis(250));
    let failure = authenticator
        .authenticate(&server.headers())
        .await
        .unwrap_err();
    assert_eq!(failure.result.reason(), "dependency_unavailable");

    assert!(
        arrived(&server, 1, Duration::from_secs(10)).await,
        "the JWKS request never reached the fixture, so this test could not \
         have observed a retry either way"
    );
    // `authenticate` has already returned, so a retry would have been issued by
    // now; a brief settle is enough to catch one in flight.
    sleep(Duration::from_millis(50)).await;
    assert_eq!(server.calls(), 1);
}

/// The background refresh loads the keys without any request having to, and
/// retries an issuer that was unreachable at startup rather than giving up.
#[tokio::test]
async fn the_key_refresh_loads_keys_at_startup_and_retries_until_it_does() {
    let server = fake_jwks(StatusCode::SERVICE_UNAVAILABLE, "{}", Duration::ZERO).await;
    let authenticator = server.authenticator(Duration::from_secs(1));
    let refresh =
        authenticator.spawn_key_refresh_every(Duration::from_secs(3600), Duration::from_millis(50));

    assert!(arrived(&server, 1, Duration::from_secs(10)).await);
    server.serve(StatusCode::OK, key_set(&[KID_A]));
    assert!(arrived(&server, 2, Duration::from_secs(10)).await);
    // Give the loaded set a moment to be stored after the response arrived.
    sleep(Duration::from_millis(50)).await;

    authenticator.authenticate(&server.headers()).await.unwrap();
    assert_eq!(
        server.calls(),
        2,
        "the request found the keys already loaded"
    );
    // Loaded, so the loop now waits the full periodic interval: no more
    // fetches at the retry pace.
    sleep(Duration::from_millis(200)).await;
    assert_eq!(server.calls(), 2);
    refresh.abort();
}

#[tokio::test]
async fn grpc_web_authentication_failures_are_framed() {
    let server = fake_jwks(StatusCode::SERVICE_UNAVAILABLE, "{}", Duration::ZERO).await;

    let unauthenticated = grpc_web_status(
        server.authenticator(Duration::from_secs(1)),
        HeaderMap::new(),
    )
    .await;
    let unavailable = grpc_web_status(
        server.authenticator(Duration::from_secs(1)),
        server.headers(),
    )
    .await;

    assert_eq!(unauthenticated, 16);
    assert_eq!(unavailable, 14);
    assert_eq!(server.calls(), 1);
}

/// With the client-telemetry ingest stopped, the edge sends the page's
/// `POST /v1/logs` here. It is refused before authentication — no
/// token verified, nothing below reached — and with a status the page does not
/// mistake for delivery.
#[tokio::test]
async fn client_telemetry_paths_are_refused_before_authentication() {
    let server = issuer().await;
    let reached = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for (method, path) in [
        (Method::POST, "/v1/logs"),
        (Method::POST, "/v1/traces"),
        (Method::GET, "/v1/logs"),
        (Method::POST, "/v1"),
    ] {
        let layer = grpc_service_layer(
            server.authenticator(Duration::from_secs(1)),
            Arc::new(AuthenticationMetrics::default()),
            Arc::new(ProtocolMetrics::new(&["v3"])),
            &["v3"],
        );
        let counter = Arc::clone(&reached);
        let inner = service_fn(move |_: Request<BoxBody>| {
            counter.fetch_add(1, Ordering::Relaxed);
            async { Ok::<_, Infallible>(Response::new(empty_body())) }
        });
        // HTTP/2, as Traefik speaks to the server (h2c): over HTTP/1.1 the
        // gRPC-Web layer would answer 400 before authentication anyway.
        let mut request = Request::builder()
            .method(method.clone())
            .version(http::Version::HTTP_2)
            .uri(path)
            .header(CONTENT_TYPE, "application/json")
            .body(empty_body())
            .unwrap();
        request.headers_mut().extend(server.headers());
        let response = layer.layer(inner).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {path}");
    }
    assert_eq!(server.calls(), 0, "no key fetch");
    assert_eq!(
        reached.load(Ordering::Relaxed),
        0,
        "nothing below was reached"
    );
    assert!(!super::is_client_telemetry_path("/v10/logs"));
    assert!(!super::is_client_telemetry_path(
        "/sovereign.config.v4.System/GetVersion"
    ));
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
    let server = issuer().await;
    let layer = AuthenticationLayer::new(
        server.authenticator(Duration::from_secs(1)),
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
    assert_eq!(server.calls(), 0);

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
    assert_eq!(server.calls(), 0, "the handshake must not reach the issuer");

    let mut protected = Request::builder()
        .method(Method::POST)
        .uri("/protected.Service/Call")
        .body(())
        .unwrap();
    *protected.headers_mut() = server.headers();
    let response = layer
        .clone()
        .layer(inner.clone())
        .oneshot(protected)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(server.calls(), 1);

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
    assert_eq!(server.calls(), 1);
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
    let server = issuer().await;
    let protocol_metrics = Arc::new(ProtocolMetrics::new(&["v3"]));
    let stack = tower::ServiceBuilder::new()
        .layer(ProtocolVersionLayer::new(
            Arc::clone(&protocol_metrics),
            &["v3"],
        ))
        .layer(AuthenticationLayer::new(
            server.authenticator(Duration::from_secs(1)),
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
    *authenticated.headers_mut() = server.headers();
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

    let rendered = protocol_metrics.series();
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

// ---------------------------------------------------------------------------
// Spans through the authentication stack, as `main.rs` layers it
// ---------------------------------------------------------------------------

/// A native gRPC answer with its status in trailers, as a handler produces.
fn grpc_answer(code: tonic::Code) -> Response<BoxBody> {
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", HeaderValue::from(code as i32));
    let body = empty_body()
        .with_trailers(async move { Some(Ok(trailers)) })
        .boxed_unsync();
    let mut response = Response::new(body);
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/grpc"));
    response
}

/// Sends `request` through the trace layer and the gRPC stack, answering at
/// the bottom with `answer`, and reads the whole response so its trailers —
/// and the span's end — are reached.
async fn through_the_stack(
    meter: &opentelemetry::metrics::Meter,
    authenticator: Authenticator,
    request: Request<BoxBody>,
    answer: tonic::Code,
) -> Response<()> {
    let stack = grpc_service_layer(
        authenticator,
        Arc::new(AuthenticationMetrics::default()),
        Arc::new(ProtocolMetrics::new(&["v3"])),
        &["v3"],
    );
    let inner =
        service_fn(
            move |_: Request<BoxBody>| async move { Ok::<_, Infallible>(grpc_answer(answer)) },
        );
    let response = crate::spans::TraceLayer::new(crate::metrics::RequestMetrics::new(meter))
        .layer(stack.layer(inner))
        .oneshot(request)
        .await
        .unwrap();
    let (parts, body) = response.into_parts();
    body.collect().await.unwrap();
    Response::from_parts(parts, ())
}

fn grpc_request(path: &str, content_type: &'static str, headers: HeaderMap) -> Request<BoxBody> {
    // Native gRPC is HTTP/2; gRPC-Web arrives over HTTP/1.1, as from a browser.
    let version = if content_type == "application/grpc" {
        http::Version::HTTP_2
    } else {
        http::Version::HTTP_11
    };
    let mut request = Request::builder()
        .method(Method::POST)
        .version(version)
        .uri(path)
        .header(CONTENT_TYPE, content_type)
        .body(empty_body())
        .unwrap();
    request.headers_mut().extend(headers);
    request
}

/// `user.*` is the one place personal data enters a span: stamped from the
/// verified token on an authenticated call, absent from a refused one,
/// and never copied onto a log record.
#[tokio::test]
async fn an_authenticated_call_is_stamped_with_who_made_it_and_nothing_else_is() {
    let server = issuer().await;
    let mut claims = server.claims();
    claims["preferred_username"] = json!("Span Operator");
    let token = token_with(&claims);
    let capture = sovereign_config_telemetry::testing::Capture::exporting();
    let meter = capture.meter();
    {
        let _guard = capture.enter();
        through_the_stack(
            &meter,
            server.authenticator(Duration::from_secs(1)),
            grpc_request(
                "/sovereign.config.v3.System/GetIdentity",
                "application/grpc",
                bearer(&token),
            ),
            tonic::Code::Ok,
        )
        .await;
        through_the_stack(
            &meter,
            server.authenticator(Duration::from_secs(1)),
            grpc_request(
                "/sovereign.config.v3.System/GetIdentity",
                "application/grpc",
                HeaderMap::new(),
            ),
            tonic::Code::Ok,
        )
        .await;
    }
    let exported = capture.finish();

    let calls = exported.spans_named("sovereign.config.v3.System/GetIdentity");
    assert_eq!(calls.len(), 2);
    let accepted = calls
        .iter()
        .find(|span| span.attribute("rpc.response.status_code") == Some("OK"))
        .expect("the authenticated call");
    assert_eq!(accepted.attribute("user.id"), Some("principal-id"));
    assert_eq!(accepted.attribute("user.name"), Some("Span Operator"));
    // The first call on a cold cache fetches the keys, inside its own trace.
    let key_fetch = exported.span("GET");
    assert!(key_fetch.is_child_of(accepted));
    assert_eq!(key_fetch.kind, "client");

    let refused = calls
        .iter()
        .find(|span| span.attribute("rpc.response.status_code") == Some("UNAUTHENTICATED"))
        .expect("the refused call");
    assert_eq!(refused.attribute("user.id"), None);
    assert_eq!(refused.attribute("user.name"), None);
    assert!(
        !refused.is_error,
        "a refusal is the client's error, not ours"
    );

    for log in &exported.logs {
        assert!(
            !log.attributes.keys().any(|key| key.starts_with("user.")),
            "{log:?}"
        );
        assert!(
            !log.attributes
                .values()
                .any(|value| value.contains("Span Operator") || value == "principal-id"),
            "{log:?}"
        );
    }
    for value in exported.all_values() {
        assert!(!value.contains(&token), "{value}");
        let signature = token.rsplit('.').next().unwrap();
        assert!(!value.contains(signature), "{value}");
    }
}

/// The status recorder sees every answer: a handler's trailers, the
/// trailers-only refusals of the catch-all and of authentication, and a
/// browser's call — which only works because the recorder sits inside
/// gRPC-Web. Only the conventions' server-error codes fail the span.
#[tokio::test]
async fn every_grpc_status_is_recorded_and_only_server_errors_fail_the_span() {
    let unavailable = fake_jwks(StatusCode::SERVICE_UNAVAILABLE, "{}", Duration::ZERO).await;
    let capture = sovereign_config_telemetry::testing::Capture::exporting();
    let meter = capture.meter();
    let browser_content_type;
    {
        let _guard = capture.enter();
        let authenticator = || unavailable.authenticator(Duration::from_secs(1));
        // Authentication cannot reach its dependency: UNAVAILABLE, trailers-only.
        through_the_stack(
            &meter,
            authenticator(),
            grpc_request(
                "/sovereign.config.v3.System/GetIdentity",
                "application/grpc",
                unavailable.headers(),
            ),
            tonic::Code::Ok,
        )
        .await;
        // A retired version: FAILED_PRECONDITION from the catch-all.
        through_the_stack(
            &meter,
            authenticator(),
            grpc_request(
                "/sovereign.config.v99.System/GetVersion",
                "application/grpc",
                HeaderMap::new(),
            ),
            tonic::Code::Ok,
        )
        .await;
        // A handler's NOT_FOUND, in trailers.
        through_the_stack(
            &meter,
            authenticator(),
            grpc_request(
                "/sovereign.config.v3.System/GetVersion",
                "application/grpc",
                HeaderMap::new(),
            ),
            tonic::Code::NotFound,
        )
        .await;
        // A browser's call, answered INTERNAL in trailers the browser sees
        // framed into the body.
        let response = through_the_stack(
            &meter,
            authenticator(),
            grpc_request(
                "/sovereign.config.v3.System/GetVersion",
                "application/grpc-web+proto",
                HeaderMap::new(),
            ),
            tonic::Code::Internal,
        )
        .await;
        browser_content_type = response.headers().get(CONTENT_TYPE).cloned();
    }
    let exported = capture.finish();
    assert_eq!(
        browser_content_type.as_ref().map(HeaderValue::as_bytes),
        Some(&b"application/grpc-web+proto"[..])
    );

    let identity = exported.span("sovereign.config.v3.System/GetIdentity");
    assert_eq!(
        identity.attribute("rpc.response.status_code"),
        Some("UNAVAILABLE")
    );
    assert!(identity.is_error);
    assert_eq!(identity.attribute("error.type"), Some("UNAVAILABLE"));
    let key_fetch = exported.span("GET");
    assert!(key_fetch.is_error);
    assert_eq!(key_fetch.attribute("error.type"), Some("unavailable"));
    assert_eq!(
        key_fetch.attribute("http.response.status_code"),
        Some("503")
    );

    let retired = exported.span("_OTHER");
    assert_eq!(
        retired.attribute("rpc.response.status_code"),
        Some("FAILED_PRECONDITION")
    );
    assert!(!retired.is_error);

    let versions = exported.spans_named("sovereign.config.v3.System/GetVersion");
    let status = |code: &str| {
        versions
            .iter()
            .find(|span| span.attribute("rpc.response.status_code") == Some(code))
            .unwrap_or_else(|| panic!("no GetVersion span answered {code}: {versions:?}"))
    };
    assert!(!status("NOT_FOUND").is_error);
    let browser = status("INTERNAL");
    assert!(browser.is_error);
    assert_eq!(browser.attribute("error.type"), Some("INTERNAL"));

    assert_every_call_timed_with_its_status(&exported);
}

/// RED: each call's duration is recorded once, with the span's method and
/// status, and `error.type` exactly where the span failed.
fn assert_every_call_timed_with_its_status(
    exported: &sovereign_config_telemetry::testing::Exported,
) {
    let duration = exported.metric("rpc.server.call.duration");
    assert_eq!(duration.unit, "s");
    assert_eq!(duration.stored_name(), "rpc_server_call_duration_seconds");
    for (method, code, error) in [
        (
            "sovereign.config.v3.System/GetIdentity",
            "UNAVAILABLE",
            Some("UNAVAILABLE"),
        ),
        ("_OTHER", "FAILED_PRECONDITION", None),
        ("sovereign.config.v3.System/GetVersion", "NOT_FOUND", None),
        (
            "sovereign.config.v3.System/GetVersion",
            "INTERNAL",
            Some("INTERNAL"),
        ),
    ] {
        let point = duration.point(&[
            ("rpc.system.name", "grpc"),
            ("rpc.method", method),
            ("rpc.response.status_code", code),
        ]);
        assert_eq!(point.count, 1, "{method} {code}");
        assert_eq!(
            point.attributes.get("error.type").map(String::as_str),
            error,
            "{method} {code}"
        );
    }
    assert_eq!(duration.points.len(), 4, "{:?}", duration.points);
}
