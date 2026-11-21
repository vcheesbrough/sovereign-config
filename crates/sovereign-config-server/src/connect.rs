//! The Connect protocol, served beside tonic on the one public port (#582).
//!
//! **A protocol version names its transport.** `v6` and the unversioned
//! handshake are served over Connect unary — binary (`application/proto`) and
//! JSON (`application/json`), over HTTP/1.1 or HTTP/2 — and `v3`–`v5` over
//! native gRPC and gRPC-Web only. A call on the wrong transport is answered
//! version-not-served by the catch-all (`protocol::UnservedVersionLayer`),
//! which asks [`request_transport`] which one a request is using.
//!
//! Four pieces, innermost first:
//!
//! - [`ConnectDispatchLayer`], innermost: a Connect unary request is answered
//!   by a `connectrpc` router; anything else (native gRPC, gRPC-Web, the web
//!   assets) goes on to tonic unchanged.
//! - the bridge handlers: each re-encodes its buffa message as protobuf bytes,
//!   decodes them as the prost type, and calls the **`v6` tonic shim**. So the
//!   behaviour is the shared implementation's, through the same shim a gRPC
//!   version uses, and only the wire differs.
//! - [`ConnectShapeLayer`], outside authentication and the catch-all: those
//!   two answer in gRPC's shape (HTTP 200, `grpc-status` in headers or
//!   trailers). For a Connect request that is re-rendered as a Connect error,
//!   with the `sovereign-config-*` metadata as plain response headers. It also
//!   reads the request body before anything can refuse it, answers a
//!   malformed Connect request with a Connect error, and marks every Connect
//!   answer `Cache-Control: no-store`.
//! - [`GrpcWebUnlessConnectLayer`], outermost: `tonic-web` answers every
//!   HTTP/1.1 request that is not gRPC-Web with a bare 400, so Connect calls
//!   and asset `GET`s go round it.
//!
//! Connect's `GET` form is never enabled: every call is a `POST`, so a path, a
//! value or a token never travels in a URL.
#![expect(
    refining_impl_trait,
    reason = "the handlers name `ServiceResult`, the concrete type the generated traits' `impl Future` returns"
)]

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use connectrpc::{
    ConnectError, ConnectRpcService, ErrorCode, Limits, RequestContext, Router, ServiceRequest,
    ServiceResult,
};
use http::{
    HeaderMap, HeaderValue, Method, Request, Response,
    header::{CACHE_CONTROL, CONTENT_TYPE},
};
use http_body_util::BodyExt;
use sovereign_config_connect::proto::sovereign::config as cproto;
use sovereign_config_proto::sovereign::config as pproto;
use tonic::{Code, Status, body::BoxBody};
use tower::{Layer, Service};

use crate::{
    audit::v6::V6Audit,
    auth::AuthenticatedPrincipal,
    handshake::HandshakeService,
    managed::V6ManagedConnections,
    protocol::NegotiatedProtocolVersion,
    system::{V6System, WireTransport},
    values::{OneofRequest, V6Configuration, sets_two_members},
};

/// The largest request or response message, and the largest request body:
/// tonic's default decode limit, so a Connect call is bounded exactly as a
/// gRPC call is.
pub(crate) const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

/// The content types a Connect **unary** call carries. Connect's streaming
/// types (`application/connect+*`) are not served: every capability is
/// reachable by a unary call.
const CONNECT_UNARY_TYPES: &str = "application/proto, application/json";

/// The outcome of a Connect call, left on the response for the span and RED
/// recorder (`spans::GrpcStatusService`), which otherwise looks for a
/// `grpc-status` that a Connect response does not carry. Without it every
/// Connect call would be recorded as having no status at all.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ConnectOutcome(pub(crate) Code);

/// Set by the dispatch layer on everything `connectrpc` answered, so the
/// shape layer knows the answer is already in Connect's shape.
#[derive(Clone, Copy, Debug)]
struct ServedByConnect;

fn content_type(headers: &HeaderMap) -> &str {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map_or("", |value| value.split(';').next().unwrap_or(value).trim())
}

/// Whether a request is a Connect unary call: a `POST` with a Connect unary
/// content type.
pub(crate) fn is_connect_unary(method: &Method, headers: &HeaderMap) -> bool {
    *method == Method::POST
        && matches!(
            content_type(headers),
            "application/proto" | "application/json"
        )
}

/// Whether a request is native gRPC or gRPC-Web, by its content type.
fn is_grpc(headers: &HeaderMap) -> bool {
    content_type(headers).starts_with("application/grpc")
}

/// The transport a request travels on, for the catch-all to judge whether
/// the version its route names is served over it. Anything that is not a
/// Connect unary call is judged as gRPC — the transport every request was
/// judged by before Connect was served, so nothing that is not Connect sees
/// a different answer.
pub(crate) fn request_transport(method: &Method, headers: &HeaderMap) -> WireTransport {
    if is_connect_unary(method, headers) {
        WireTransport::Connect
    } else {
        WireTransport::Grpc
    }
}

/// Whether `path` is a route Connect serves: the handshake, or a `v6` call.
fn is_connect_route(path: &str) -> bool {
    path == HANDSHAKE_ROUTE || path.starts_with("/sovereign.config.v6.")
}

const HANDSHAKE_ROUTE: &str = "/sovereign.config.Handshake/Negotiate";

fn code_of(error: &ConnectError) -> Code {
    Code::from_i32(i32::try_from(error.code.grpc_code()).unwrap_or(2))
}

/// A tonic status as a Connect error, carrying the `sovereign-config-*`
/// metadata — the version-not-served marker — as plain response headers.
///
/// Only as headers, never also as `trailer-` headers: a Connect unary client
/// reads it from the headers, and a client that folds both into one metadata
/// object (connect-es does) would read `version-not-served,
/// version-not-served` and match nothing (#583).
fn connect_error(status: &Status) -> ConnectError {
    let code = ErrorCode::from_grpc_code(status.code() as u32).unwrap_or(ErrorCode::Unknown);
    let mut headers = HeaderMap::new();
    for (name, value) in status.metadata().clone().into_headers() {
        if let Some(name) = name
            && name.as_str().starts_with("sovereign-config-")
        {
            headers.insert(name, value);
        }
    }
    ConnectError::new(code, status.message()).with_headers(headers)
}

fn bridge_failure(_: impl std::fmt::Debug) -> ConnectError {
    ConnectError::internal("the request could not be translated")
}

/// buffa message → protobuf bytes → prost message → the `v6` tonic shim →
/// prost → buffa. The principal and version attribution the outer layers
/// attached travel with the call, so the shim sees exactly what it would see
/// had tonic routed it.
macro_rules! bridge {
    ($inner:expr, $trait:path, $method:ident, $ctx:ident, $request:ident, $prost_req:ty, $buffa_res:ty) => {{
        let bytes = buffa::Message::encode_to_vec(&$request.to_owned_message());
        let message =
            <$prost_req as prost::Message>::decode(bytes.as_slice()).map_err(bridge_failure)?;
        let mut call = tonic::Request::new(message);
        if let Some(principal) = $ctx.extensions().get::<AuthenticatedPrincipal>() {
            call.extensions_mut().insert(principal.clone());
        }
        if let Some(version) = $ctx.extensions().get::<NegotiatedProtocolVersion>() {
            call.extensions_mut().insert(*version);
        }
        match <_ as $trait>::$method($inner, call).await {
            Ok(response) => {
                let bytes = prost::Message::encode_to_vec(response.get_ref());
                let message = <$buffa_res as buffa::Message>::decode_from_slice(&bytes)
                    .map_err(bridge_failure)?;
                connectrpc::Response::ok(message)
            }
            Err(status) => Err(connect_error(&status)),
        }
    }};
}

struct ConnectHandshake(HandshakeService);

impl cproto::Handshake for ConnectHandshake {
    async fn negotiate(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, cproto::NegotiateRequest>,
    ) -> ServiceResult<cproto::NegotiateResponse> {
        bridge!(
            &self.0,
            pproto::handshake_server::Handshake,
            negotiate,
            ctx,
            request,
            pproto::NegotiateRequest,
            cproto::NegotiateResponse
        )
    }
}

struct ConnectSystem(V6System);

impl cproto::v6::System for ConnectSystem {
    async fn get_version(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, cproto::v6::GetVersionRequest>,
    ) -> ServiceResult<cproto::v6::GetVersionResponse> {
        bridge!(
            &self.0,
            pproto::v6::system_server::System,
            get_version,
            ctx,
            request,
            pproto::v6::GetVersionRequest,
            cproto::v6::GetVersionResponse
        )
    }

    async fn get_identity(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, cproto::v6::GetIdentityRequest>,
    ) -> ServiceResult<cproto::v6::GetIdentityResponse> {
        bridge!(
            &self.0,
            pproto::v6::system_server::System,
            get_identity,
            ctx,
            request,
            pproto::v6::GetIdentityRequest,
            cproto::v6::GetIdentityResponse
        )
    }
}

/// One bridged method of a `v6` service whose tonic shim is `$trait`.
macro_rules! bridged {
    ($trait:path, $method:ident, $request:ident, $response:ident) => {
        async fn $method(
            &self,
            ctx: RequestContext,
            request: ServiceRequest<'_, cproto::v6::$request>,
        ) -> ServiceResult<cproto::v6::$response> {
            bridge!(
                &self.0,
                $trait,
                $method,
                ctx,
                request,
                pproto::v6::$request,
                cproto::v6::$response
            )
        }
    };
}

struct ConnectConfiguration(V6Configuration);

impl cproto::v6::Configuration for ConnectConfiguration {
    bridged!(
        pproto::v6::configuration_server::Configuration,
        list_values,
        ListValuesRequest,
        ListValuesResponse
    );
    bridged!(
        pproto::v6::configuration_server::Configuration,
        get_sub_tree,
        GetSubTreeRequest,
        GetSubTreeResponse
    );
    bridged!(
        pproto::v6::configuration_server::Configuration,
        put_value,
        PutValueRequest,
        PutValueResponse
    );
    bridged!(
        pproto::v6::configuration_server::Configuration,
        replace_sub_tree,
        ReplaceSubTreeRequest,
        ReplaceSubTreeResponse
    );
    bridged!(
        pproto::v6::configuration_server::Configuration,
        delete_values,
        DeleteValuesRequest,
        DeleteValuesResponse
    );
    bridged!(
        pproto::v6::configuration_server::Configuration,
        reveal_secret,
        RevealSecretRequest,
        RevealSecretResponse
    );
    bridged!(
        pproto::v6::configuration_server::Configuration,
        add_value_path,
        AddValuePathRequest,
        AddValuePathResponse
    );
    bridged!(
        pproto::v6::configuration_server::Configuration,
        list_value_paths,
        ListValuePathsRequest,
        ListValuePathsResponse
    );
}

struct ConnectManagedConnections(V6ManagedConnections);

impl cproto::v6::ManagedConnections for ConnectManagedConnections {
    bridged!(
        pproto::v6::managed_connections_server::ManagedConnections,
        list_managed_connections,
        ListManagedConnectionsRequest,
        ListManagedConnectionsResponse
    );
    bridged!(
        pproto::v6::managed_connections_server::ManagedConnections,
        create_managed_connection,
        CreateManagedConnectionRequest,
        CreateManagedConnectionResponse
    );
    bridged!(
        pproto::v6::managed_connections_server::ManagedConnections,
        rotate_managed_connection,
        RotateManagedConnectionRequest,
        RotateManagedConnectionResponse
    );
    bridged!(
        pproto::v6::managed_connections_server::ManagedConnections,
        revoke_managed_connection,
        RevokeManagedConnectionRequest,
        RevokeManagedConnectionResponse
    );
}

struct ConnectAudit(V6Audit);

impl cproto::v6::Audit for ConnectAudit {
    bridged!(
        pproto::v6::audit_server::Audit,
        query_audit_trail,
        QueryAuditTrailRequest,
        QueryAuditTrailResponse
    );
}

/// The `v6` shims and the handshake the Connect router answers with.
pub(crate) struct ConnectServices {
    pub(crate) handshake: HandshakeService,
    pub(crate) configuration: V6Configuration,
    pub(crate) managed_connections: V6ManagedConnections,
    pub(crate) audit: V6Audit,
}

/// The Connect router: the handshake and `v6`, bridged onto their shims.
pub(crate) fn service(services: ConnectServices) -> ConnectRpcService {
    let router = Router::new()
        .add_service(Arc::new(ConnectHandshake(services.handshake)))
        .add_service(Arc::new(ConnectSystem(V6System)))
        .add_service(Arc::new(ConnectConfiguration(services.configuration)))
        .add_service(Arc::new(ConnectManagedConnections(
            services.managed_connections,
        )))
        .add_service(Arc::new(ConnectAudit(services.audit)));
    ConnectRpcService::new(router).with_limits(
        Limits::default()
            .with_max_request_body_size(MAX_MESSAGE_BYTES)
            .with_max_message_size(MAX_MESSAGE_BYTES),
    )
}

/// Which `v6` request on `path`, if any, can carry two members of a `oneof`.
fn oneof_request(path: &str) -> Option<OneofRequest> {
    match path {
        "/sovereign.config.v6.Configuration/PutValue" => Some(OneofRequest::PutValue),
        "/sovereign.config.v6.Configuration/ReplaceSubTree" => Some(OneofRequest::ReplaceSubTree),
        _ => None,
    }
}

fn full(bytes: Bytes) -> BoxBody {
    http_body_util::Full::new(bytes)
        .map_err(|never| match never {})
        .boxed_unsync()
}

/// `error` as a finished Connect answer, its outcome recorded for the span.
fn connect_answer(error: &ConnectError, request_headers: &HeaderMap) -> Response<BoxBody> {
    let code = code_of(error);
    let (mut parts, body) = error
        .clone()
        .into_http_response(request_headers)
        .into_parts();
    parts.extensions.insert(ConnectOutcome(code));
    parts.extensions.insert(ServedByConnect);
    Response::from_parts(parts, body.map_err(|never| match never {}).boxed_unsync())
}

/// Answers Connect unary calls with the `connectrpc` router, and passes
/// everything else to tonic. Innermost in the stack, so authentication, the
/// catch-all, attribution, spans and RED all wrap a Connect call exactly as
/// they wrap a gRPC one.
#[derive(Clone)]
pub(crate) struct ConnectDispatchLayer {
    service: ConnectRpcService,
}

impl ConnectDispatchLayer {
    pub(crate) const fn new(service: ConnectRpcService) -> Self {
        Self { service }
    }
}

impl<S> Layer<S> for ConnectDispatchLayer {
    type Service = ConnectDispatchService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ConnectDispatchService {
            inner,
            service: self.service.clone(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct ConnectDispatchService<S> {
    inner: S,
    service: ConnectRpcService,
}

impl<S> Service<Request<BoxBody>> for ConnectDispatchService<S>
where
    S: Service<Request<BoxBody>, Response = Response<BoxBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response<BoxBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, request: Request<BoxBody>) -> Self::Future {
        if !is_connect_unary(request.method(), request.headers()) {
            let replacement = self.inner.clone();
            let mut inner = std::mem::replace(&mut self.inner, replacement);
            return Box::pin(async move { inner.call(request).await });
        }
        let mut service = self.service.clone();
        let scan = oneof_request(request.uri().path())
            .filter(|_| content_type(request.headers()) == "application/proto");
        Box::pin(async move {
            let request = match scan {
                None => request,
                Some(kind) => {
                    let headers = request.headers().clone();
                    let (parts, body) = request.into_parts();
                    // Bounded already: the shape layer read the body into
                    // memory, within the limit, before authentication ran.
                    let Ok(collected) = http_body_util::Limited::new(body, MAX_MESSAGE_BYTES)
                        .collect()
                        .await
                    else {
                        return Ok(connect_answer(
                            &ConnectError::resource_exhausted("request body size exceeds limit"),
                            &headers,
                        ));
                    };
                    let bytes = collected.to_bytes();
                    if sets_two_members(kind, &bytes) {
                        return Ok(connect_answer(
                            &ConnectError::invalid_argument(
                                "a request may set only one member of a oneof",
                            ),
                            &headers,
                        ));
                    }
                    Request::from_parts(parts, full(bytes))
                }
            };
            let response = match service.call(request).await {
                Ok(response) => response,
                Err(never) => match never {},
            };
            let (mut parts, body) = response.into_parts();
            parts.extensions.insert(ServedByConnect);
            // A unary body is small and complete, so it is read here to learn
            // the outcome for the span and RED.
            let bytes = match body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(never) => match never {},
            };
            let code = if parts.status.is_success() {
                Code::Ok
            } else {
                serde_json::from_slice::<ConnectError>(&bytes)
                    .map_or(Code::Unknown, |error| code_of(&error))
            };
            parts.extensions.insert(ConnectOutcome(code));
            Ok(Response::from_parts(parts, full(bytes)))
        })
    }
}

/// Puts Connect calls' refusals in Connect's shape, and keeps a Connect
/// connection healthy while doing it. See the module documentation.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ConnectShapeLayer;

impl<S> Layer<S> for ConnectShapeLayer {
    type Service = ConnectShapeService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ConnectShapeService { inner }
    }
}

#[derive(Clone)]
pub(crate) struct ConnectShapeService<S> {
    inner: S,
}

impl<S> Service<Request<BoxBody>> for ConnectShapeService<S>
where
    S: Service<Request<BoxBody>, Response = Response<BoxBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response<BoxBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, request: Request<BoxBody>) -> Self::Future {
        let replacement = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, replacement);
        let connect = is_connect_unary(request.method(), request.headers());
        if !connect {
            // A request on a route Connect serves that is neither a Connect
            // unary call nor gRPC: the wrong verb, a forgotten or streaming
            // content type. Told how to call, in Connect's shape, rather than
            // given a bare 400 or 404 with nothing in it.
            if is_connect_route(request.uri().path()) && !is_grpc(request.headers()) {
                // Rendered as for a unary call whatever was asked for: a
                // streaming content type would otherwise get a streaming
                // answer, which a caller who got the type wrong cannot read.
                let mut answer = connect_answer(
                    &ConnectError::invalid_argument(
                        "a Connect call is a POST with Content-Type application/proto or application/json",
                    ),
                    &HeaderMap::new(),
                );
                let headers = answer.headers_mut();
                headers.insert("accept-post", HeaderValue::from_static(CONNECT_UNARY_TYPES));
                headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
                return Box::pin(async move { Ok(answer) });
            }
            return Box::pin(async move { inner.call(request).await });
        }
        let request_headers = request.headers().clone();
        Box::pin(async move {
            // Authentication and the catch-all refuse **without reading the
            // request body**. Over HTTP/1.1 the connection then closes under
            // a client that is still writing, which connect-es reported as
            // `write EPIPE` on 4 or 5 of 30 refused calls (#583). So the body
            // is read first, bounded, before anything can refuse.
            let (parts, body) = request.into_parts();
            let Ok(collected) = http_body_util::Limited::new(body, MAX_MESSAGE_BYTES)
                .collect()
                .await
            else {
                return Ok(no_store(connect_answer(
                    &ConnectError::resource_exhausted("request body size exceeds limit"),
                    &request_headers,
                )));
            };
            let request = Request::from_parts(parts, full(collected.to_bytes()));
            let response = inner.call(request).await?;
            if response.extensions().get::<ServedByConnect>().is_some() {
                return Ok(no_store(response));
            }
            // Answered by a gRPC-shaped layer: the catch-all (status in the
            // headers) or authentication (status in the trailers). Anything
            // else — authentication's plain 404 for the client-telemetry
            // paths — is not a refusal to reshape, and passes as it is.
            if response.headers().get("grpc-status").is_none() && !is_grpc(response.headers()) {
                return Ok(no_store(response));
            }
            let (parts, body) = response.into_parts();
            let status = if let Some(status) = Status::from_header_map(&parts.headers) {
                status
            } else {
                let trailers = body
                    .collect()
                    .await
                    .ok()
                    .and_then(|collected| collected.trailers().cloned())
                    .unwrap_or_default();
                Status::from_header_map(&trailers)
                    .unwrap_or_else(|| Status::unknown("no status in a gRPC-shaped answer"))
            };
            Ok(no_store(connect_answer(
                &connect_error(&status),
                &request_headers,
            )))
        })
    }
}

fn no_store(mut response: Response<BoxBody>) -> Response<BoxBody> {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// `tonic-web`'s layer answers **every HTTP/1.1 request that is not gRPC-Web
/// with a bare 400** (it passes other content types through only on HTTP/2).
/// A Connect call over HTTP/1.1 — the point of leaving h2c behind — therefore
/// has to go round it, and so does a browser's plain `GET` of the web UI's own
/// assets, which the same 400 would otherwise meet over HTTP/1.1.
#[derive(Clone, Debug, Default)]
pub(crate) struct GrpcWebUnlessConnectLayer;

impl<S> Layer<S> for GrpcWebUnlessConnectLayer
where
    S: Service<Request<BoxBody>, Response = Response<BoxBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send,
{
    type Service = GrpcWebUnlessConnectService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        GrpcWebUnlessConnectService {
            web: tonic_web::GrpcWebLayer::new().layer(inner.clone()),
            direct: inner,
        }
    }
}

#[derive(Clone)]
pub(crate) struct GrpcWebUnlessConnectService<S> {
    web: tonic_web::GrpcWebService<S>,
    direct: S,
}

impl<S> Service<Request<BoxBody>> for GrpcWebUnlessConnectService<S>
where
    S: Service<Request<BoxBody>, Response = Response<BoxBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send + 'static,
{
    type Response = Response<BoxBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.direct.poll_ready(context)
    }

    fn call(&mut self, request: Request<BoxBody>) -> Self::Future {
        let around = matches!(*request.method(), Method::GET | Method::HEAD)
            || !is_grpc(request.headers()) && is_connect_route(request.uri().path())
            || is_connect_unary(request.method(), request.headers());
        if around {
            let replacement = self.direct.clone();
            let mut direct = std::mem::replace(&mut self.direct, replacement);
            Box::pin(async move { direct.call(request).await })
        } else {
            let mut web = self.web.clone();
            Box::pin(async move { web.call(request).await })
        }
    }
}

#[cfg(test)]
mod db_tests;
#[cfg(test)]
mod proxy_tests;
#[cfg(test)]
pub(crate) mod tests;
