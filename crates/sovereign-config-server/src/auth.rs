use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use anyhow::{Context as _, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::{
    HeaderMap, HeaderValue, Method, Request, Response,
    header::{AUTHORIZATION, CONTENT_TYPE},
};
use http_body_util::BodyExt;
use reqwest::{Client, Url};
use serde::Deserialize;
use sovereign_config_core::ConfigPath;
use tonic::{
    Status,
    body::{BoxBody, empty_body},
};
use tonic_web::GrpcWebLayer;
use tower::{
    Layer, Service,
    layer::util::{Identity, Stack},
};
use tracing::{info, warn};

use crate::{
    config::{AcceptedIdentity, AuthenticationConfig},
    metrics::{AuthenticationMetrics, AuthenticationResult},
};

const REQUIRED_SCOPE: &str = "sovereign-config";
const MAX_INTROSPECTION_RESPONSE_BYTES: usize = 64 * 1024;
const OPERATIONAL_RPCS: [&str; 3] = [
    "/grpc.health.v1.Health/Check",
    "/grpc.health.v1.Health/Watch",
    "/sovereign.config.v1.System/GetVersion",
];

#[derive(Clone)]
pub(crate) struct Authenticator {
    client: Client,
    introspection_url: Url,
    accepted_identities: Vec<AcceptedIdentity>,
    introspection_client_id: String,
    introspection_client_secret: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedPrincipal {
    pub(crate) subject: String,
    pub(crate) grants: Vec<Grant>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Grant {
    pub(crate) prefix: String,
    pub(crate) permissions: BTreeSet<Permission>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Permission {
    Read,
    Write,
    Manage,
}

#[derive(Debug)]
pub(crate) struct AuthenticationFailure {
    result: AuthenticationResult,
}

impl AuthenticationFailure {
    fn unauthenticated(result: AuthenticationResult) -> Self {
        Self { result }
    }

    fn unavailable() -> Self {
        Self {
            result: AuthenticationResult::Unavailable,
        }
    }

    fn status(&self) -> Status {
        match self.result {
            AuthenticationResult::Unavailable => {
                Status::unavailable("authentication dependency unavailable")
            }
            _ => Status::unauthenticated("authentication failed"),
        }
    }
}

impl AuthenticatedPrincipal {
    pub(crate) fn allows(&self, path: &ConfigPath, permission: Permission) -> bool {
        self.grants.iter().any(|grant| {
            grant.permissions.contains(&permission)
                && (grant.prefix.is_empty()
                    || path.as_str() == grant.prefix
                    || path
                        .as_str()
                        .strip_prefix(&grant.prefix)
                        .is_some_and(|suffix| suffix.starts_with('/')))
        })
    }
}

#[derive(Deserialize)]
struct JoseHeader {
    alg: String,
}

#[derive(Deserialize)]
struct IntrospectionResponse {
    active: bool,
    iss: Option<serde_json::Value>,
    aud: Option<serde_json::Value>,
    sub: Option<serde_json::Value>,
    scope: Option<serde_json::Value>,
    sovereign_config_grants: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct RawGrant {
    prefix: String,
    permissions: Vec<Permission>,
}

impl Authenticator {
    pub(crate) fn new(config: AuthenticationConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(config.timeout)
            .https_only(config.introspection_url.scheme() == "https")
            .build()
            .context("unable to configure Authentik introspection client")?;
        Ok(Self {
            client,
            introspection_url: config.introspection_url,
            accepted_identities: config.accepted_identities,
            introspection_client_id: config.introspection_client_id,
            introspection_client_secret: config.introspection_client_secret,
        })
    }

    async fn authenticate(
        &self,
        headers: &HeaderMap,
    ) -> Result<AuthenticatedPrincipal, AuthenticationFailure> {
        let token = bearer_token(headers)?;
        require_rs256(token)?;

        let response = self
            .client
            .post(self.introspection_url.clone())
            .basic_auth(
                &self.introspection_client_id,
                Some(&self.introspection_client_secret),
            )
            .form(&[("token", token)])
            .send()
            .await
            .map_err(|_| AuthenticationFailure::unavailable())?;
        if !response.status().is_success() {
            return Err(AuthenticationFailure::unavailable());
        }

        let response = read_bounded_response(response).await?;
        let response: IntrospectionResponse =
            serde_json::from_slice(&response).map_err(|_| AuthenticationFailure::unavailable())?;
        validate_introspection_for_any(response, &self.accepted_identities)
    }
}

async fn read_bounded_response(
    mut response: reqwest::Response,
) -> Result<Vec<u8>, AuthenticationFailure> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_INTROSPECTION_RESPONSE_BYTES as u64)
    {
        return Err(AuthenticationFailure::unavailable());
    }

    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| AuthenticationFailure::unavailable())?
    {
        if body.len() + chunk.len() > MAX_INTROSPECTION_RESPONSE_BYTES {
            return Err(AuthenticationFailure::unavailable());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, AuthenticationFailure> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Err(AuthenticationFailure::unauthenticated(
            AuthenticationResult::MissingBearer,
        ));
    };
    if values.next().is_some() {
        return Err(AuthenticationFailure::unauthenticated(
            AuthenticationResult::MalformedBearer,
        ));
    }

    let value = value.to_str().map_err(|_| {
        AuthenticationFailure::unauthenticated(AuthenticationResult::MalformedBearer)
    })?;
    let (scheme, token) = value.split_once(' ').ok_or_else(|| {
        AuthenticationFailure::unauthenticated(AuthenticationResult::MalformedBearer)
    })?;
    if !scheme.eq_ignore_ascii_case("bearer")
        || token.is_empty()
        || token.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(AuthenticationFailure::unauthenticated(
            AuthenticationResult::MalformedBearer,
        ));
    }
    Ok(token)
}

fn require_rs256(token: &str) -> Result<(), AuthenticationFailure> {
    let mut segments = token.split('.');
    let (Some(encoded_header), Some(payload), Some(signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(AuthenticationFailure::unauthenticated(
            AuthenticationResult::MalformedBearer,
        ));
    };
    if encoded_header.is_empty() || payload.is_empty() || signature.is_empty() {
        return Err(AuthenticationFailure::unauthenticated(
            AuthenticationResult::MalformedBearer,
        ));
    }
    let decoded = URL_SAFE_NO_PAD.decode(encoded_header).map_err(|_| {
        AuthenticationFailure::unauthenticated(AuthenticationResult::MalformedBearer)
    })?;
    let header: JoseHeader = serde_json::from_slice(&decoded).map_err(|_| {
        AuthenticationFailure::unauthenticated(AuthenticationResult::MalformedBearer)
    })?;
    if header.alg != "RS256" {
        return Err(AuthenticationFailure::unauthenticated(
            AuthenticationResult::WrongAlgorithm,
        ));
    }
    Ok(())
}

#[cfg(test)]
fn validate_introspection(
    response: IntrospectionResponse,
    expected_issuer: &str,
    expected_audience: &str,
) -> Result<AuthenticatedPrincipal, AuthenticationFailure> {
    validate_introspection_for_any(
        response,
        &[AcceptedIdentity {
            issuer: expected_issuer.to_owned(),
            audience: expected_audience.to_owned(),
        }],
    )
}

fn validate_introspection_for_any(
    response: IntrospectionResponse,
    accepted_identities: &[AcceptedIdentity],
) -> Result<AuthenticatedPrincipal, AuthenticationFailure> {
    if !response.active {
        return Err(AuthenticationFailure::unauthenticated(
            AuthenticationResult::Inactive,
        ));
    }
    let valid_identity = accepted_identities.iter().any(|identity| {
        response.iss.as_ref().and_then(serde_json::Value::as_str) == Some(&identity.issuer)
            && response
                .aud
                .as_ref()
                .is_some_and(|audience| audience_contains(audience, &identity.audience))
    });
    let valid_claims = valid_identity
        && response
            .scope
            .as_ref()
            .and_then(serde_json::Value::as_str)
            .is_some_and(|scopes| {
                scopes
                    .split_ascii_whitespace()
                    .any(|scope| scope == REQUIRED_SCOPE)
            })
        && response
            .sub
            .as_ref()
            .and_then(serde_json::Value::as_str)
            .is_some_and(|subject| !subject.is_empty());
    if !valid_claims {
        return Err(AuthenticationFailure::unauthenticated(
            AuthenticationResult::InvalidClaims,
        ));
    }

    let raw_grants = serde_json::from_value(response.sovereign_config_grants.ok_or_else(|| {
        AuthenticationFailure::unauthenticated(AuthenticationResult::InvalidClaims)
    })?)
    .map_err(|_| AuthenticationFailure::unauthenticated(AuthenticationResult::InvalidClaims))?;
    let grants = validate_grants(raw_grants)?;
    Ok(AuthenticatedPrincipal {
        subject: response
            .sub
            .and_then(|subject| subject.as_str().map(str::to_owned))
            .expect("subject was validated as a non-empty string"),
        grants,
    })
}

fn audience_contains(audience: &serde_json::Value, expected: &str) -> bool {
    audience.as_str() == Some(expected)
        || audience.as_array().is_some_and(|audiences| {
            audiences.iter().all(serde_json::Value::is_string)
                && audiences
                    .iter()
                    .any(|audience| audience.as_str() == Some(expected))
        })
}

fn validate_grants(raw_grants: Vec<RawGrant>) -> Result<Vec<Grant>, AuthenticationFailure> {
    let mut grants: BTreeMap<String, BTreeSet<Permission>> = BTreeMap::new();
    for raw_grant in raw_grants {
        if !is_canonical_prefix(&raw_grant.prefix) || raw_grant.permissions.is_empty() {
            return Err(AuthenticationFailure::unauthenticated(
                AuthenticationResult::InvalidClaims,
            ));
        }
        grants
            .entry(raw_grant.prefix)
            .or_default()
            .extend(raw_grant.permissions);
    }
    Ok(grants
        .into_iter()
        .map(|(prefix, permissions)| Grant {
            prefix,
            permissions,
        })
        .collect())
}

fn is_canonical_prefix(prefix: &str) -> bool {
    ConfigPath::parse(prefix).is_ok()
}

fn is_operational_rpc(path: &str) -> bool {
    OPERATIONAL_RPCS.contains(&path)
}

fn is_web_asset_request(method: &Method, path: &str) -> bool {
    matches!(*method, Method::GET | Method::HEAD) && !is_operational_rpc(path)
}

#[derive(Clone)]
pub(crate) struct AuthenticationLayer {
    authenticator: Authenticator,
    metrics: Arc<AuthenticationMetrics>,
}

impl AuthenticationLayer {
    pub(crate) fn new(authenticator: Authenticator, metrics: Arc<AuthenticationMetrics>) -> Self {
        Self {
            authenticator,
            metrics,
        }
    }
}

pub(crate) type GrpcAuthenticationLayer = Stack<AuthenticationLayer, Stack<GrpcWebLayer, Identity>>;

pub(crate) fn grpc_authentication_layer(
    authenticator: Authenticator,
    metrics: Arc<AuthenticationMetrics>,
) -> GrpcAuthenticationLayer {
    Stack::new(
        AuthenticationLayer::new(authenticator, metrics),
        Stack::new(GrpcWebLayer::new(), Identity::new()),
    )
}

impl<S> Layer<S> for AuthenticationLayer {
    type Service = AuthenticationService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthenticationService {
            inner,
            authenticator: self.authenticator.clone(),
            metrics: Arc::clone(&self.metrics),
        }
    }
}

#[derive(Clone)]
pub(crate) struct AuthenticationService<S> {
    inner: S,
    authenticator: Authenticator,
    metrics: Arc<AuthenticationMetrics>,
}

impl<S, B> Service<Request<B>> for AuthenticationService<S>
where
    S: Service<Request<B>, Response = Response<BoxBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    B: Send + 'static,
{
    type Response = Response<BoxBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        let replacement = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, replacement);
        if is_web_asset_request(request.method(), request.uri().path())
            || is_operational_rpc(request.uri().path())
        {
            return Box::pin(async move { inner.call(request).await });
        }

        let authenticator = self.authenticator.clone();
        let metrics = Arc::clone(&self.metrics);
        let rpc = request.uri().path().to_owned();
        Box::pin(async move {
            match authenticator.authenticate(request.headers()).await {
                Ok(principal) => {
                    metrics.increment(AuthenticationResult::Success);
                    info!(
                        rpc,
                        outcome = "success",
                        reason = "accepted",
                        "gRPC authentication succeeded"
                    );
                    request.extensions_mut().insert(principal);
                    inner.call(request).await
                }
                Err(failure) => {
                    metrics.increment(failure.result);
                    warn!(
                        rpc,
                        outcome = failure.result.outcome(),
                        reason = failure.result.reason(),
                        "gRPC authentication failed"
                    );
                    Ok(status_response(&failure.status()))
                }
            }
        })
    }
}

fn status_response(status: &Status) -> Response<BoxBody> {
    let mut trailers = HeaderMap::new();
    status
        .add_header(&mut trailers)
        .expect("bounded authentication status must produce valid trailers");
    let body = empty_body()
        .with_trailers(async move { Some(Ok(trailers)) })
        .boxed_unsync();
    let mut response = Response::new(body);
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/grpc"));
    response
}

#[cfg(test)]
mod tests {
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
        Permission, bearer_token, grpc_authentication_layer, is_canonical_prefix,
        is_operational_rpc, is_web_asset_request, require_rs256, validate_introspection,
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
                    prefix: "apps/api".into(),
                    permissions: BTreeSet::from([Permission::Write]),
                },
                Grant {
                    prefix: "apps/api/private".into(),
                    permissions: BTreeSet::from([Permission::Manage]),
                },
            ],
        };
        let api = ConfigPath::parse("apps/api").unwrap();
        let child = ConfigPath::parse("apps/api/settings").unwrap();
        let attack = ConfigPath::parse("apps/apix").unwrap();
        let private = ConfigPath::parse("apps/api/private/key").unwrap();

        assert!(principal.allows(&api, Permission::Write));
        assert!(principal.allows(&child, Permission::Write));
        assert!(!principal.allows(&child, Permission::Read));
        assert!(!principal.allows(&attack, Permission::Write));
        assert!(principal.allows(&private, Permission::Manage));
        assert!(!principal.allows(&private, Permission::Read));
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
                {"prefix": "", "permissions": ["read", "write", "manage"]}
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
                {"prefix": "", "permissions": ["read", "write", "manage"]},
                {"prefix": "apps/api", "permissions": ["read"]},
                {"prefix": "apps/api", "permissions": ["write"]}
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
        for prefix in ["", "apps", "apps/my-api", "a1/b-2"] {
            assert!(is_canonical_prefix(prefix));
        }
        for prefix in ["/apps", "apps/", "apps//api", "Apps/api", "apps/."] {
            assert!(!is_canonical_prefix(prefix));
        }

        let mut response = valid_response();
        response.sovereign_config_grants =
            Some(json!([{"prefix": "Apps/api", "permissions": ["read"]}]));
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

        let mut response = valid_response();
        response.sovereign_config_grants =
            Some(json!([{"prefix": "apps/api", "permissions": ["owner"]}]));
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
        assert!(is_operational_rpc("/sovereign.config.v1.System/GetVersion"));
        assert!(!is_operational_rpc("/grpc.health.v1.Health/Unknown"));
        assert!(!is_operational_rpc(
            "/sovereign.config.v1.Configuration/GetValue"
        ));
    }

    #[test]
    fn browser_asset_requests_do_not_require_authentication() {
        assert!(is_web_asset_request(&Method::GET, "/"));
        assert!(is_web_asset_request(&Method::HEAD, "/app-config.js"));
        assert!(!is_web_asset_request(
            &Method::POST,
            "/sovereign.config.v1.System/GetIdentity"
        ));
        assert!(!is_web_asset_request(
            &Method::GET,
            "/sovereign.config.v1.System/GetVersion"
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
            .uri("/sovereign.config.v1.System/GetIdentity")
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
            .uri("/sovereign.config.v1.System/GetVersion")
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
}
