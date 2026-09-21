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
    metrics::{AuthenticationMetrics, AuthenticationResult, ProtocolMetrics},
    protocol::{NegotiatedProtocolVersion, UnservedVersionLayer},
    system::served,
};

const REQUIRED_SCOPE: &str = "sovereign-config";
const MAX_INTROSPECTION_RESPONSE_BYTES: usize = 64 * 1024;
/// The unversioned handshake.
///
/// Unauthenticated by decision, recorded in `README.md`: a client has no token
/// before it has negotiated, `System.GetVersion` already publishes the same
/// list, and keeping it outside authentication leaves each protocol version
/// free to change its own scheme. The cost is that the served list and the
/// client lists sent to it are public, which the handshake service is written
/// for — it never rejects and never mints a label from a request.
const HANDSHAKE_RPC: &str = "/sovereign.config.Handshake/Negotiate";
/// Routes that bypass authentication and are not protocol-versioned.
const OPERATIONAL_RPCS: [&str; 3] = [
    "/grpc.health.v1.Health/Check",
    "/grpc.health.v1.Health/Watch",
    HANDSHAKE_RPC,
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
    /// What the identity provider calls this identity, for the audit trail to
    /// show beside the opaque subject. Never consulted for authorization.
    pub(crate) name: Option<String>,
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
        // `Grant::prefix` is always the fold key (`canonical_prefix` folds it
        // on the way in), so this must compare the fold, never `as_str()`
        // (display) — otherwise a grant stops covering any value whose
        // established case differs from how the grant itself was written.
        let fold = path.fold();
        self.grants.iter().any(|grant| {
            grant.permissions.contains(&permission)
                && (grant.prefix == "/"
                    || fold == grant.prefix
                    || fold
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
    preferred_username: Option<serde_json::Value>,
    username: Option<serde_json::Value>,
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
    let name = display_name(
        response.preferred_username.as_ref(),
        response.username.as_ref(),
    );
    Ok(AuthenticatedPrincipal {
        subject: response
            .sub
            .and_then(|subject| subject.as_str().map(str::to_owned))
            .expect("subject was validated as a non-empty string"),
        name,
        grants,
    })
}

/// The longest display name kept. It is shown in a list, not relied on.
const MAX_DISPLAY_NAME_CHARACTERS: usize = 128;

/// The name the audit trail shows for an identity: `preferred_username`, else
/// `username`, made safe to store and to print.
///
/// **It can never fail authentication.** The name decides nothing — the
/// subject is the identity and the grants are the authority — so a claim that
/// is missing, not a string, or empty once cleaned is simply no name. Control
/// characters are dropped because the value is stored and later rendered in a
/// list, and comes from the identity provider rather than from anything this
/// server validated.
fn display_name(
    preferred_username: Option<&serde_json::Value>,
    username: Option<&serde_json::Value>,
) -> Option<String> {
    [preferred_username, username]
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .map(|claim| {
            claim
                .chars()
                .filter(|character| !character.is_control())
                .take(MAX_DISPLAY_NAME_CHARACTERS)
                .collect::<String>()
                .trim()
                .to_owned()
        })
        .find(|name| !name.is_empty())
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
        let Some(prefix) = canonical_prefix(&raw_grant.prefix) else {
            return Err(AuthenticationFailure::unauthenticated(
                AuthenticationResult::InvalidClaims,
            ));
        };
        if raw_grant.permissions.is_empty() {
            return Err(AuthenticationFailure::unauthenticated(
                AuthenticationResult::InvalidClaims,
            ));
        }
        grants
            .entry(prefix)
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

/// Folds a grant prefix to its fold key, accepting any letter case so an
/// operator writing `/apps/Example` in an Authentik grant attribute gets the
/// same coverage as `/apps/example`. `Grant::prefix` is always the fold key:
/// [`AuthenticatedPrincipal::allows`] compares it byte-exact against a fold
/// key, never a display form.
fn canonical_prefix(prefix: &str) -> Option<String> {
    ConfigPath::parse_selection(prefix)
        .ok()
        .map(|path| path.fold())
}

/// `GetVersion` on any protocol version this server serves.
///
/// Kept unauthenticated for the clients that predate the handshake: every one
/// of them negotiates here, *before* any token exists — a 2.27 `Provider`
/// calls `get_version` before building its token provider. A served version
/// whose `GetVersion` required authentication would fail every such client at
/// connect with an authentication error, before it could discover which
/// versions are actually served.
///
/// Derived from the served set rather than listed, so introducing or retiring a
/// version cannot leave this behind. It is also what a current client's legacy
/// fallback reaches: a handshake refused `UNAUTHENTICATED` means a server that
/// has none, and this route is the one such a server exempts.
fn is_unauthenticated_version_handshake(path: &str) -> bool {
    path.strip_prefix("/sovereign.config.")
        .and_then(|rest| rest.strip_suffix(".System/GetVersion"))
        .is_some_and(served)
}

fn is_operational_rpc(path: &str) -> bool {
    OPERATIONAL_RPCS.contains(&path) || is_unauthenticated_version_handshake(path)
}

fn is_web_asset_request(method: &Method, path: &str) -> bool {
    matches!(*method, Method::GET | Method::HEAD) && !is_operational_rpc(path)
}

#[derive(Clone)]
pub(crate) struct AuthenticationLayer {
    authenticator: Authenticator,
    metrics: Arc<AuthenticationMetrics>,
    protocol_metrics: Arc<ProtocolMetrics>,
}

impl AuthenticationLayer {
    pub(crate) fn new(
        authenticator: Authenticator,
        metrics: Arc<AuthenticationMetrics>,
        protocol_metrics: Arc<ProtocolMetrics>,
    ) -> Self {
        Self {
            authenticator,
            metrics,
            protocol_metrics,
        }
    }
}

pub(crate) type GrpcServiceLayer =
    Stack<AuthenticationLayer, Stack<UnservedVersionLayer, Stack<GrpcWebLayer, Identity>>>;

/// The gRPC stack, outermost first: gRPC-Web, then the version-not-served
/// catch-all, then authentication.
///
/// **Both boundaries are load-bearing.**
///
/// The catch-all is *inside* `GrpcWebLayer` so that its answer is framed on the
/// way out. A browser dials the same versioned routes as any other client, and
/// a raw gRPC trailers-only response is not something a gRPC-Web client can
/// decode — a retirement would reach the browser as a transport failure with no
/// version in it. Everything the authentication layer returns already relies on
/// this same framing.
///
/// The catch-all is *outside* `AuthenticationLayer` because an unserved version
/// has no authentication scheme left to apply: its shims, and whatever rules
/// they carried, are gone. A client whose credentials also expired while it was
/// away should still be told that its protocol version is what stopped working,
/// rather than be sent to renew a token that will not help.
pub(crate) fn grpc_service_layer(
    authenticator: Authenticator,
    metrics: Arc<AuthenticationMetrics>,
    protocol_metrics: Arc<ProtocolMetrics>,
    served_versions: &'static [&'static str],
) -> GrpcServiceLayer {
    Stack::new(
        AuthenticationLayer::new(authenticator, metrics, protocol_metrics),
        Stack::new(
            UnservedVersionLayer::new(served_versions),
            Stack::new(GrpcWebLayer::new(), Identity::new()),
        ),
    )
}

impl<S> Layer<S> for AuthenticationLayer {
    type Service = AuthenticationService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthenticationService {
            inner,
            authenticator: self.authenticator.clone(),
            metrics: Arc::clone(&self.metrics),
            protocol_metrics: Arc::clone(&self.protocol_metrics),
        }
    }
}

#[derive(Clone)]
pub(crate) struct AuthenticationService<S> {
    inner: S,
    authenticator: Authenticator,
    metrics: Arc<AuthenticationMetrics>,
    protocol_metrics: Arc<ProtocolMetrics>,
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
        let protocol_metrics = Arc::clone(&self.protocol_metrics);
        let rpc = request.uri().path().to_owned();
        Box::pin(async move {
            match authenticator.authenticate(request.headers()).await {
                Ok(principal) => {
                    metrics.increment(AuthenticationResult::Success);
                    // The retirement gate counts only traffic that authenticated:
                    // a scanner or a client with revoked credentials can hold the
                    // attempted series above zero forever, but would not break if
                    // the version were retired. The version comes from the
                    // extension the protocol layer attached, so the label stays
                    // one of its compiled-in strings.
                    if let Some(NegotiatedProtocolVersion(Some(version))) =
                        request.extensions().get::<NegotiatedProtocolVersion>()
                    {
                        protocol_metrics.record_authenticated(version);
                    }
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
mod tests;
