//! Spans at the process boundaries (`observability` skill §1.3, §5): one
//! server span per request on the public port, and the client span and
//! context injection for every HTTP call that leaves the process. Database
//! calls are spanned at the store functions (`#[instrument]` there), and
//! detached work where it is spawned.
//!
//! Context propagation lives here, in the transport layer, and nowhere else:
//! [`TraceLayer`] adopts an inbound W3C `traceparent`; [`send`] injects the
//! current span's context into an outbound request. Business code inherits
//! the ambient span and never passes a trace id around.
//!
//! **Not spanned, deliberately:** the internal listener (`/readyz`,
//! `/metrics`) and the gRPC health service on the public port. Health is
//! separate from telemetry, and a span per probe — the container health check
//! calls `grpc.health.v1.Health/Check` every few seconds — is noise.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use http::{HeaderMap, Method, Request, Response};
use http_body_util::BodyExt;
use reqwest::Url;
use sovereign_config_telemetry::context;
use tonic::{Code, body::BoxBody};
use tower::{Layer, Service};
use tracing::{Instrument, Span, field::Empty};

use crate::auth::AuthenticatedPrincipal;

/// Every gRPC route this build serves, as `/<package>.<Service>/<Method>`:
/// the handshake, then each served protocol version's services. The set a
/// span's `rpc.method` is drawn from, so a route never becomes a span name
/// unless it is compiled in; anything else is `_OTHER`.
///
/// `every_served_rpc_has_a_route_and_nothing_else_does` compares it with the
/// `.proto` files of the served versions, so adding or retiring a version
/// cannot leave it behind.
pub(crate) const RPC_ROUTES: [&str; 30] = [
    "/sovereign.config.Handshake/Negotiate",
    "/sovereign.config.v3.System/GetVersion",
    "/sovereign.config.v3.System/GetIdentity",
    "/sovereign.config.v3.Configuration/ListValues",
    "/sovereign.config.v3.Configuration/GetSubTree",
    "/sovereign.config.v3.Configuration/PutValue",
    "/sovereign.config.v3.Configuration/ReplaceSubTree",
    "/sovereign.config.v3.Configuration/DeleteValues",
    "/sovereign.config.v3.Configuration/RevealSecret",
    "/sovereign.config.v3.Configuration/AddValuePath",
    "/sovereign.config.v3.Configuration/ListValuePaths",
    "/sovereign.config.v3.ManagedConnections/ListManagedConnections",
    "/sovereign.config.v3.ManagedConnections/CreateManagedConnection",
    "/sovereign.config.v3.ManagedConnections/RotateManagedConnection",
    "/sovereign.config.v3.ManagedConnections/RevokeManagedConnection",
    "/sovereign.config.v4.System/GetVersion",
    "/sovereign.config.v4.System/GetIdentity",
    "/sovereign.config.v4.Configuration/ListValues",
    "/sovereign.config.v4.Configuration/GetSubTree",
    "/sovereign.config.v4.Configuration/PutValue",
    "/sovereign.config.v4.Configuration/ReplaceSubTree",
    "/sovereign.config.v4.Configuration/DeleteValues",
    "/sovereign.config.v4.Configuration/RevealSecret",
    "/sovereign.config.v4.Configuration/AddValuePath",
    "/sovereign.config.v4.Configuration/ListValuePaths",
    "/sovereign.config.v4.ManagedConnections/ListManagedConnections",
    "/sovereign.config.v4.ManagedConnections/CreateManagedConnection",
    "/sovereign.config.v4.ManagedConnections/RotateManagedConnection",
    "/sovereign.config.v4.ManagedConnections/RevokeManagedConnection",
    "/sovereign.config.v4.Audit/QueryAuditTrail",
];

/// The gRPC health service's routes all start with this; see the module
/// documentation for why they carry no span.
const HEALTH_PREFIX: &str = "/grpc.health.v1.Health/";

/// `rpc.method` for a gRPC call to a route this build does not serve, and
/// `http.request.method` for a method outside the standard set, as the
/// semantic conventions spell "something else".
const OTHER: &str = "_OTHER";

/// The longest `url.path` recorded on a span. A request path is
/// request-derived; bounded, it cannot make a span arbitrarily large.
const MAX_RECORDED_PATH: usize = 256;

/// What a request is, for its span.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Route {
    /// A served gRPC route: `rpc.method` without the leading `/`, and the
    /// protocol version its package names (`None` for the handshake).
    Rpc {
        method: &'static str,
        version: Option<&'static str>,
    },
    /// A `POST` to anything else: gRPC and gRPC-Web are `POST`-only, so it is
    /// a call to a method this build does not serve.
    OtherRpc,
    /// A gRPC health probe: no span.
    Health,
    /// Anything else on the port: the web UI's static assets.
    Http,
}

fn route(method: &Method, path: &str) -> Route {
    if path.starts_with(HEALTH_PREFIX) {
        return Route::Health;
    }
    if *method != Method::POST {
        return Route::Http;
    }
    RPC_ROUTES
        .iter()
        .find(|candidate| **candidate == path)
        .map_or(Route::OtherRpc, |served| {
            let method = &served[1..];
            let version = method
                .strip_prefix("sovereign.config.")
                .and_then(|rest| rest.split_once('.'))
                .map(|(version, _)| version)
                .filter(|version| !version.contains('/'));
            Route::Rpc { method, version }
        })
}

/// The request's server span, carried on the request so that layers further
/// in — authentication, the gRPC status recorder — can add to it.
#[derive(Clone, Debug)]
pub(crate) struct RequestSpan(pub(crate) Span);

/// Opens the server span for a request, or `None` for a health probe.
pub(crate) fn server_span(method: &Method, path: &str) -> Option<Span> {
    let span = match route(method, path) {
        Route::Health => return None,
        Route::Rpc {
            method: rpc,
            version,
        } => tracing::info_span!(
            "rpc",
            otel.name = rpc,
            otel.kind = "server",
            otel.status_code = Empty,
            rpc.system.name = "grpc",
            rpc.method = rpc,
            rpc.response.status_code = Empty,
            error.type = Empty,
            sovereign_config.protocol.version = version,
            user.id = Empty,
            user.name = Empty,
        ),
        Route::OtherRpc => {
            // The route as requested, as the conventions ask of `_OTHER`: an
            // attribute, never the name, and bounded like `url.path`.
            let original = bounded_path(path);
            tracing::info_span!(
                "rpc",
                otel.name = OTHER,
                otel.kind = "server",
                otel.status_code = Empty,
                rpc.system.name = "grpc",
                rpc.method = OTHER,
                rpc.method_original = original.trim_start_matches('/'),
                rpc.response.status_code = Empty,
                error.type = Empty,
                user.id = Empty,
                user.name = Empty,
            )
        }
        Route::Http => {
            let (name, recorded) = http_method(method);
            let path = bounded_path(path);
            tracing::info_span!(
                "http",
                otel.name = name,
                otel.kind = "server",
                otel.status_code = Empty,
                http.request.method = recorded,
                url.path = path.as_str(),
                http.response.status_code = Empty,
                error.type = Empty,
            )
        }
    };
    Some(span)
}

/// A request-derived path as a span attribute may carry it: the first
/// [`MAX_RECORDED_PATH`] characters. Attributes may be as specific as the
/// request (skill §3); span *names* stay bounded.
fn bounded_path(path: &str) -> String {
    path.chars().take(MAX_RECORDED_PATH).collect()
}

/// The span name and `http.request.method` for `method`: the method itself
/// when it is a standard one, else `HTTP` and `_OTHER`, so a client cannot
/// mint span names.
fn http_method(method: &Method) -> (&'static str, &'static str) {
    let standard = match method.as_str() {
        "GET" => "GET",
        "HEAD" => "HEAD",
        "POST" => "POST",
        "PUT" => "PUT",
        "DELETE" => "DELETE",
        "CONNECT" => "CONNECT",
        "OPTIONS" => "OPTIONS",
        "TRACE" => "TRACE",
        "PATCH" => "PATCH",
        _ => return ("HTTP", OTHER),
    };
    (standard, standard)
}

/// Stamps the authenticated caller on the request's span: `user.id` is the
/// token's `sub`, `user.name` the identity provider's display name
/// (`preferred_username`, else `username`). Span attributes only — never a
/// metric label, never a log field (README `## Observability` says what
/// holding them in Tempo obliges).
pub(crate) fn stamp_user(span: &Span, principal: &AuthenticatedPrincipal) {
    span.record("user.id", principal.subject.as_str());
    if let Some(name) = &principal.name {
        span.record("user.name", name.as_str());
    }
}

/// The server span layer. **Outermost** on the public port, so the span
/// covers everything the request meets: the protocol-version layer, gRPC-Web,
/// the version-not-served catch-all, authentication (and its introspection
/// call) and the handler.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TraceLayer;

impl<S> Layer<S> for TraceLayer {
    type Service = TraceService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TraceService { inner }
    }
}

#[derive(Clone)]
pub(crate) struct TraceService<S> {
    inner: S,
}

impl<S, B> Service<Request<B>> for TraceService<S>
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
        let Some(span) = server_span(request.method(), request.uri().path()) else {
            return Box::pin(async move { inner.call(request).await });
        };
        context::adopt_parent(&span, request.headers());
        request.extensions_mut().insert(RequestSpan(span.clone()));

        let recorder = span.clone();
        Box::pin(
            async move {
                let response = inner.call(request).await?;
                // Only the HTTP span declares the field; on an RPC span this
                // is a no-op, and the gRPC status is recorded further in.
                let status = response.status().as_u16();
                recorder.record("http.response.status_code", status);
                if response.status().is_server_error() {
                    recorder.record("otel.status_code", "error");
                    recorder.record("error.type", tracing::field::display(status));
                }
                Ok(response)
            }
            .instrument(span),
        )
    }
}

/// Records a gRPC response's status on the request's span. It sits **inside**
/// the gRPC-Web layer, where every response is still native gRPC with its
/// status in trailers (or, for a trailers-only answer, in the headers) — past
/// it, a browser's status is framed into the body.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct GrpcStatusLayer;

impl<S> Layer<S> for GrpcStatusLayer {
    type Service = GrpcStatusService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        GrpcStatusService { inner }
    }
}

#[derive(Clone)]
pub(crate) struct GrpcStatusService<S> {
    inner: S,
}

impl<S, B> Service<Request<B>> for GrpcStatusService<S>
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

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let replacement = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, replacement);
        let span = request
            .extensions()
            .get::<RequestSpan>()
            .map(|RequestSpan(span)| span.clone());
        Box::pin(async move {
            let response = inner.call(request).await?;
            let Some(span) = span else {
                return Ok(response);
            };
            if let Some(code) = grpc_status(response.headers()) {
                record_grpc_status(&span, code);
                return Ok(response);
            }
            // The status arrives with the trailers, after the handler has
            // returned; the body holds the span open until then, so the span's
            // duration is the whole exchange.
            Ok(response.map(|body| {
                body.map_frame(move |frame| {
                    if let Some(code) = frame.trailers_ref().and_then(grpc_status) {
                        record_grpc_status(&span, code);
                    }
                    frame
                })
                .boxed_unsync()
            }))
        })
    }
}

fn grpc_status(headers: &HeaderMap) -> Option<Code> {
    headers
        .get("grpc-status")
        .map(|value| Code::from_bytes(value.as_bytes()))
}

/// `rpc.response.status_code` as the conventions spell it (`OK`,
/// `UNAVAILABLE`), and the span marked failed for the codes the gRPC
/// conventions count as a server error.
fn record_grpc_status(span: &Span, code: Code) {
    let name = grpc_code_name(code);
    span.record("rpc.response.status_code", name);
    if matches!(
        code,
        Code::Unknown
            | Code::DeadlineExceeded
            | Code::Unimplemented
            | Code::Internal
            | Code::Unavailable
            | Code::DataLoss
    ) {
        span.record("otel.status_code", "error");
        span.record("error.type", name);
    }
}

pub(crate) const fn grpc_code_name(code: Code) -> &'static str {
    match code {
        Code::Ok => "OK",
        Code::Cancelled => "CANCELLED",
        Code::Unknown => "UNKNOWN",
        Code::InvalidArgument => "INVALID_ARGUMENT",
        Code::DeadlineExceeded => "DEADLINE_EXCEEDED",
        Code::NotFound => "NOT_FOUND",
        Code::AlreadyExists => "ALREADY_EXISTS",
        Code::PermissionDenied => "PERMISSION_DENIED",
        Code::ResourceExhausted => "RESOURCE_EXHAUSTED",
        Code::FailedPrecondition => "FAILED_PRECONDITION",
        Code::Aborted => "ABORTED",
        Code::OutOfRange => "OUT_OF_RANGE",
        Code::Unimplemented => "UNIMPLEMENTED",
        Code::Internal => "INTERNAL",
        Code::Unavailable => "UNAVAILABLE",
        Code::DataLoss => "DATA_LOSS",
        Code::Unauthenticated => "UNAUTHENTICATED",
    }
}

/// A client span for one outbound HTTP call. `template` is the route with its
/// identifiers left as placeholders (`/api/v3/core/users/{id}/`) — never the
/// URL actually called, which would put an Authentik primary key in a span
/// name. `None` when the route is configuration rather than code (the
/// introspection endpoint), which leaves the span named by its method.
/// Records the host only: no scheme, port, path, query or credential.
pub(crate) fn client_span(method: &Method, template: Option<&'static str>, origin: &Url) -> Span {
    let (method_name, recorded) = http_method(method);
    let name = template.map_or_else(
        || method_name.to_owned(),
        |template| format!("{method_name} {template}"),
    );
    tracing::info_span!(
        "http.client",
        otel.name = name.as_str(),
        otel.kind = "client",
        otel.status_code = Empty,
        http.request.method = recorded,
        server.address = origin.host_str(),
        url.template = template,
        http.response.status_code = Empty,
        error.type = Empty,
    )
}

/// Sends `request` through `client` with the current span's trace context
/// injected, and records the response status on the current span. Call it
/// inside a [`client_span`].
///
/// # Errors
///
/// The request could not be built or sent.
pub(crate) async fn send(
    client: &reqwest::Client,
    request: reqwest::RequestBuilder,
) -> Result<reqwest::Response, reqwest::Error> {
    let mut request = request.build()?;
    context::inject_current(request.headers_mut());
    let response = client.execute(request).await?;
    Span::current().record("http.response.status_code", response.status().as_u16());
    Ok(response)
}

/// Marks the current store span failed, for a store function that returns
/// `sqlx::Error` rather than going through [`crate::rpc::storage_unavailable`].
/// Never records the error itself: its text can quote SQL or a value.
pub(crate) fn record_storage_error(_: &sqlx::Error) {
    record_error(crate::rpc::STORAGE_UNAVAILABLE_TYPE);
}

/// Marks the current span failed, with a bounded classification as its
/// `error.type`.
pub(crate) fn record_error(classification: &'static str) {
    let span = Span::current();
    span.record("otel.status_code", "error");
    span.record("error.type", classification);
}

#[cfg(test)]
mod tests;
