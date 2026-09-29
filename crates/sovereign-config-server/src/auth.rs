use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::{
    HeaderMap, HeaderValue, Method, Request, Response,
    header::{AUTHORIZATION, CONTENT_TYPE},
};
use http_body_util::BodyExt;
use serde::Deserialize;
use sovereign_config_core::ConfigPath;
use tokio::task::JoinHandle;
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

use self::jwks::{KeyLookup, KeySets};
use crate::{
    config::{AcceptedIdentity, AuthenticationConfig},
    metrics::{AuthenticationMetrics, AuthenticationResult, ProtocolMetrics},
    protocol::{NegotiatedProtocolVersion, UnservedVersionLayer},
    spans::{self, GrpcStatusLayer, RequestSpan},
    system::served,
};

mod jwks;

const REQUIRED_SCOPE: &str = "sovereign-config";
/// The largest JWKS document read. Authentik's carries one key per signing
/// certificate, each with its chain, which is a few kilobytes.
const MAX_JWKS_RESPONSE_BYTES: usize = 64 * 1024;
/// How far a token's `exp`, `nbf` and `iat` may disagree with this server's
/// clock and still be accepted. Fixed, not a setting: it absorbs clock skew
/// between Authentik and this host, and nothing else.
const CLOCK_LEEWAY: Duration = Duration::from_secs(30);
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
    accepted_identities: Arc<[AcceptedIdentity]>,
    keys: Arc<KeySets>,
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
    kid: Option<String>,
}

/// A bearer token split into the parts verification needs. Nothing in it is
/// trusted until [`Authenticator::authenticate`] has checked the signature.
struct Jwt<'a> {
    kid: String,
    signing_input: &'a [u8],
    signature: Vec<u8>,
    claims: TokenClaims,
}

/// The access token's claims. Each is a raw JSON value so that a claim of an
/// unexpected type is judged by the rule that reads it — a name claim that is
/// not a string is no name, never a failed authentication.
#[derive(Deserialize)]
struct TokenClaims {
    iss: Option<serde_json::Value>,
    aud: Option<serde_json::Value>,
    sub: Option<serde_json::Value>,
    scope: Option<serde_json::Value>,
    exp: Option<serde_json::Value>,
    nbf: Option<serde_json::Value>,
    iat: Option<serde_json::Value>,
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
        Self::with_refresh_interval(config, jwks::MIN_REFRESH_INTERVAL)
    }

    fn with_refresh_interval(
        config: AuthenticationConfig,
        min_refresh_interval: Duration,
    ) -> Result<Self> {
        let keys = KeySets::new(
            config
                .accepted_identities
                .iter()
                .map(|identity| identity.issuer.as_str()),
            config.timeout,
            min_refresh_interval,
        )?;
        Ok(Self {
            accepted_identities: config.accepted_identities.into(),
            keys: Arc::new(keys),
        })
    }

    /// Loads the issuers' keys now and keeps them current for as long as the
    /// server runs. Serving does not wait for it: until the keys first load,
    /// an authenticated call fetches them itself or fails `UNAVAILABLE`, so an
    /// unreachable Authentik at startup is an outage of authenticated calls,
    /// not a crash loop.
    pub(crate) fn spawn_key_refresh(&self) -> JoinHandle<()> {
        self.spawn_key_refresh_every(jwks::PERIODIC_REFRESH, jwks::RETRY_INTERVAL)
    }

    fn spawn_key_refresh_every(&self, periodic: Duration, retry: Duration) -> JoinHandle<()> {
        let keys = Arc::clone(&self.keys);
        tokio::spawn(async move {
            loop {
                let pause = if keys.refresh().await {
                    periodic
                } else {
                    retry
                };
                tokio::time::sleep(pause).await;
            }
        })
    }

    async fn authenticate(
        &self,
        headers: &HeaderMap,
    ) -> Result<AuthenticatedPrincipal, AuthenticationFailure> {
        let token = bearer_token(headers)?;
        let jwt = parse_jwt(token)?;
        // The issuer picks the key set, so it is checked against the
        // configured issuers before any key is looked up: a token cannot make
        // this server fetch from anywhere else.
        let issuer = jwt
            .claims
            .iss
            .as_ref()
            .and_then(serde_json::Value::as_str)
            .filter(|issuer| {
                self.accepted_identities
                    .iter()
                    .any(|identity| identity.issuer == *issuer)
            })
            .ok_or_else(|| {
                AuthenticationFailure::unauthenticated(AuthenticationResult::InvalidClaims)
            })?;
        let key = match self.keys.key(issuer, &jwt.kid).await {
            KeyLookup::Found(key) => key,
            KeyLookup::Unknown => {
                return Err(AuthenticationFailure::unauthenticated(
                    AuthenticationResult::BadSignature,
                ));
            }
            KeyLookup::Unavailable => return Err(AuthenticationFailure::unavailable()),
        };
        if !key.verifies(jwt.signing_input, &jwt.signature) {
            return Err(AuthenticationFailure::unauthenticated(
                AuthenticationResult::BadSignature,
            ));
        }
        require_current(&jwt.claims, SystemTime::now())?;
        validate_claims(jwt.claims, &self.accepted_identities)
    }
}

async fn read_bounded_response(
    mut response: reqwest::Response,
) -> Result<Vec<u8>, AuthenticationFailure> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_JWKS_RESPONSE_BYTES as u64)
    {
        return Err(AuthenticationFailure::unavailable());
    }

    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| AuthenticationFailure::unavailable())?
    {
        if body.len() + chunk.len() > MAX_JWKS_RESPONSE_BYTES {
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

/// Splits a JWS compact token and decodes its parts, requiring `RS256` and a
/// `kid`. Any other header field — `jku`, `x5u`, an embedded `jwk` — is
/// ignored: the key always comes from the issuer's own key set.
fn parse_jwt(token: &str) -> Result<Jwt<'_>, AuthenticationFailure> {
    let malformed =
        || AuthenticationFailure::unauthenticated(AuthenticationResult::MalformedBearer);
    let mut segments = token.split('.');
    let (Some(encoded_header), Some(payload), Some(signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(malformed());
    };
    if encoded_header.is_empty() || payload.is_empty() || signature.is_empty() {
        return Err(malformed());
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded_header)
        .map_err(|_| malformed())?;
    let header: JoseHeader = serde_json::from_slice(&decoded).map_err(|_| malformed())?;
    if header.alg != "RS256" {
        return Err(AuthenticationFailure::unauthenticated(
            AuthenticationResult::WrongAlgorithm,
        ));
    }
    let kid = header
        .kid
        .filter(|kid| !kid.is_empty())
        .ok_or_else(malformed)?;
    let claims = URL_SAFE_NO_PAD
        .decode(payload)
        .ok()
        .and_then(|payload| serde_json::from_slice(&payload).ok())
        .ok_or_else(malformed)?;
    let signature = URL_SAFE_NO_PAD.decode(signature).map_err(|_| malformed())?;
    Ok(Jwt {
        kid,
        signing_input: &token.as_bytes()[..encoded_header.len() + 1 + payload.len()],
        signature,
        claims,
    })
}

/// Refuses a token outside its validity window, allowing [`CLOCK_LEEWAY`] of
/// skew. `exp` is required; `nbf` and `iat` are checked when present.
fn require_current(claims: &TokenClaims, now: SystemTime) -> Result<(), AuthenticationFailure> {
    let now = now
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();
    let leeway = CLOCK_LEEWAY.as_secs_f64();
    let time = |claim: &Option<serde_json::Value>| -> Result<Option<f64>, AuthenticationFailure> {
        claim
            .as_ref()
            .map(|value| {
                value.as_f64().ok_or_else(|| {
                    AuthenticationFailure::unauthenticated(AuthenticationResult::InvalidClaims)
                })
            })
            .transpose()
    };
    let expires = time(&claims.exp)?.ok_or_else(|| {
        AuthenticationFailure::unauthenticated(AuthenticationResult::InvalidClaims)
    })?;
    let not_before = time(&claims.nbf)?;
    let issued = time(&claims.iat)?;
    if now > expires + leeway
        || not_before.is_some_and(|not_before| not_before > now + leeway)
        || issued.is_some_and(|issued| issued > now + leeway)
    {
        return Err(AuthenticationFailure::unauthenticated(
            AuthenticationResult::Inactive,
        ));
    }
    Ok(())
}

#[cfg(test)]
fn validate_for(
    claims: TokenClaims,
    expected_issuer: &str,
    expected_audience: &str,
) -> Result<AuthenticatedPrincipal, AuthenticationFailure> {
    validate_claims(
        claims,
        &[AcceptedIdentity {
            issuer: expected_issuer.to_owned(),
            audience: expected_audience.to_owned(),
        }],
    )
}

/// The authorization claims of a token whose signature and validity window
/// have already been checked.
///
/// **The required `scope` claim is also what refuses an ID token.** Authentik
/// signs its ID tokens with the same key, issuer and audience as its access
/// tokens, and the grants mapping writes into both; it adds `scope` only when
/// it turns those claims into an access token. Introspection refused ID tokens
/// by not knowing them; here, a token without `scope` fails as
/// `invalid_claims`. `nonce` and `at_hash` do not tell the two apart — an
/// Authentik access token copies them from its ID token.
fn validate_claims(
    claims: TokenClaims,
    accepted_identities: &[AcceptedIdentity],
) -> Result<AuthenticatedPrincipal, AuthenticationFailure> {
    let valid_identity = accepted_identities.iter().any(|identity| {
        claims.iss.as_ref().and_then(serde_json::Value::as_str) == Some(&identity.issuer)
            && claims
                .aud
                .as_ref()
                .is_some_and(|audience| audience_contains(audience, &identity.audience))
    });
    let valid_claims = valid_identity
        && claims
            .scope
            .as_ref()
            .and_then(serde_json::Value::as_str)
            .is_some_and(|scopes| {
                scopes
                    .split_ascii_whitespace()
                    .any(|scope| scope == REQUIRED_SCOPE)
            })
        && claims
            .sub
            .as_ref()
            .and_then(serde_json::Value::as_str)
            .is_some_and(|subject| !subject.is_empty());
    if !valid_claims {
        return Err(AuthenticationFailure::unauthenticated(
            AuthenticationResult::InvalidClaims,
        ));
    }

    let raw_grants = serde_json::from_value(claims.sovereign_config_grants.ok_or_else(|| {
        AuthenticationFailure::unauthenticated(AuthenticationResult::InvalidClaims)
    })?)
    .map_err(|_| AuthenticationFailure::unauthenticated(AuthenticationResult::InvalidClaims))?;
    let grants = validate_grants(raw_grants)?;
    let name = display_name(claims.preferred_username.as_ref(), claims.username.as_ref());
    Ok(AuthenticatedPrincipal {
        subject: claims
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

/// OTLP/HTTP's own paths, which the edge routes to the client-telemetry
/// ingest on this same hostname (README "Observability").
///
/// The server never serves them. It only sees one when the ingest is not
/// running and the edge falls back to the app's router, and then it refuses
/// outright, before authentication: no token verified per telemetry batch, and
/// a `404` the page reads as "no ingest here", where the gRPC fallback's
/// HTTP `200` would read as delivered.
pub(crate) fn is_client_telemetry_path(path: &str) -> bool {
    path == "/v1" || path.starts_with("/v1/")
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

pub(crate) type GrpcServiceLayer = Stack<
    AuthenticationLayer,
    Stack<UnservedVersionLayer, Stack<GrpcStatusLayer, Stack<GrpcWebLayer, Identity>>>,
>;

/// The gRPC stack, outermost first: gRPC-Web, then the span's gRPC status
/// recorder, then the version-not-served catch-all, then authentication.
///
/// The status recorder is *inside* `GrpcWebLayer` because only there is a
/// browser's status still in trailers rather than framed into the body, and
/// *outside* the catch-all and authentication so that their refusals are
/// recorded as well.
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
            Stack::new(
                GrpcStatusLayer,
                Stack::new(GrpcWebLayer::new(), Identity::new()),
            ),
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
        if is_client_telemetry_path(request.uri().path()) {
            return Box::pin(async {
                let mut response = Response::new(empty_body());
                *response.status_mut() = http::StatusCode::NOT_FOUND;
                Ok(response)
            });
        }
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
                    if let Some(RequestSpan(span)) = request.extensions().get::<RequestSpan>() {
                        spans::stamp_user(span, &principal);
                    }
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
