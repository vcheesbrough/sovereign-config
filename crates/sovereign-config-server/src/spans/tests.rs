//! Spans asserted on what the exporter received (`observability` skill §7),
//! through the telemetry crate's production assembly around in-memory
//! exporters. Every [`Capture::finish`] also checks that each exported
//! attribute key is a semantic-convention name or `sovereign_config.`-prefixed,
//! so every test here covers the keys its spans carry.

use std::{
    collections::BTreeSet,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{Json, Router, extract::Request as AxumRequest, response::IntoResponse};
use http::{HeaderMap, HeaderValue, Method, Request, Response};
use serde_json::json;
use sovereign_config_core::Secret;
use sovereign_config_proto::sovereign::config::v3::{
    GetVersionRequest, system_client::SystemClient, system_server::SystemServer,
};
use sovereign_config_telemetry::testing::{Capture, Exported, ExportedSpan};
use sqlx::postgres::PgPoolOptions;
use tokio::{net::TcpListener, task::JoinHandle};
use tonic::{
    body::{BoxBody, empty_body},
    transport::{Endpoint, Server},
};
use tower::{Layer, ServiceExt, service_fn};
use tracing::Instrument;

use super::{GrpcStatusLayer, RPC_ROUTES, Route, TraceLayer, route, server_span};
use crate::{
    audit::AuditRecorder, authentik::AuthentikAdminClient, metrics::RequestMetrics,
    system::SERVED_PROTOCOL_LABELS, system::SystemService,
};

/// The trace layer recording its durations on `meter`.
fn timed(meter: &opentelemetry::metrics::Meter) -> TraceLayer {
    TraceLayer::new(RequestMetrics::new(meter))
}

/// The trace layer recording its durations nowhere, for tests about spans.
fn untimed() -> TraceLayer {
    use opentelemetry::metrics::MeterProvider as _;

    timed(&opentelemetry::metrics::noop::NoopMeterProvider::new().meter("untimed"))
}

/// An inbound W3C context, as a client or an edge proxy would send it.
const INBOUND_TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const INBOUND_SPAN_ID: &str = "00f067aa0ba902b7";

fn inbound_traceparent() -> String {
    format!("00-{INBOUND_TRACE_ID}-{INBOUND_SPAN_ID}-01")
}

/// The parts of a `traceparent` header: trace id and parent span id.
fn parse_traceparent(header: &str) -> (String, String) {
    let parts: Vec<&str> = header.split('-').collect();
    assert_eq!(parts.len(), 4, "malformed traceparent {header:?}");
    (parts[1].to_owned(), parts[2].to_owned())
}

fn assert_resource(span: &ExportedSpan) {
    for key in [
        "service.name",
        "service.version",
        "deployment.environment.name",
        "service.instance.id",
    ] {
        assert!(
            span.resource.contains_key(key),
            "span {:?} is missing resource attribute {key}: {:?}",
            span.name,
            span.resource
        );
    }
}

/// Resource identity is on every span a test exported.
fn assert_every_span_identified(exported: &Exported) {
    assert!(!exported.spans.is_empty(), "nothing was exported");
    for span in &exported.spans {
        assert_resource(span);
    }
}

// ---------------------------------------------------------------------------
// The route set
// ---------------------------------------------------------------------------

/// Every `rpc` in the `.proto` file at `path`, as `/<package>.<Service>/<Method>`.
fn routes_in(path: &std::path::Path) -> Vec<String> {
    let text = std::fs::read_to_string(path).expect("a served protocol's proto file is readable");
    let mut package = String::new();
    let mut service = String::new();
    let mut routes = Vec::new();
    for line in text.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("package ") {
            package = rest.trim_end_matches(';').trim().to_owned();
        } else if let Some(rest) = line.strip_prefix("service ") {
            service = rest.trim_end_matches('{').trim().to_owned();
        } else if let Some(rest) = line.strip_prefix("rpc ") {
            let method = rest.split('(').next().unwrap().trim();
            routes.push(format!("/{package}.{service}/{method}"));
        }
    }
    routes
}

/// The compiled-in route set is exactly the served protocol: the handshake
/// plus every RPC of every served version. Adding or retiring a version
/// without updating [`RPC_ROUTES`] fails here, rather than naming the new
/// version's spans `_OTHER`.
#[test]
fn every_served_rpc_has_a_route_and_nothing_else_does() {
    let proto =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../proto/sovereign/config");
    let mut expected: BTreeSet<String> = routes_in(&proto.join("handshake.proto"))
        .into_iter()
        .collect();
    for version in SERVED_PROTOCOL_LABELS {
        expected.extend(routes_in(&proto.join(version).join("service.proto")));
    }
    let compiled: BTreeSet<String> = RPC_ROUTES.iter().map(|route| (*route).to_owned()).collect();
    assert_eq!(compiled, expected);
    assert_eq!(compiled.len(), RPC_ROUTES.len(), "a route is listed twice");
}

#[test]
fn a_route_names_its_version_and_anything_unserved_is_other() {
    assert_eq!(
        route(
            &Method::POST,
            "/sovereign.config.v4.ManagedConnections/CreateManagedConnection"
        ),
        Route::Rpc {
            method: "sovereign.config.v4.ManagedConnections/CreateManagedConnection",
            version: Some("v4"),
        }
    );
    assert_eq!(
        route(&Method::POST, "/sovereign.config.Handshake/Negotiate"),
        Route::Rpc {
            method: "sovereign.config.Handshake/Negotiate",
            version: None,
        }
    );
    for junk in [
        "/sovereign.config.v99.System/GetVersion",
        "/sovereign.config.v3.System/Nonexistent",
        "/wp-login.php",
    ] {
        assert_eq!(route(&Method::POST, junk), Route::OtherRpc, "{junk}");
    }
    assert_eq!(route(&Method::GET, "/assets/app.js"), Route::Http);
    assert_eq!(
        route(&Method::POST, "/grpc.health.v1.Health/Check"),
        Route::Health
    );
    assert!(server_span(&Method::POST, "/grpc.health.v1.Health/Check").is_none());
}

#[tokio::test]
async fn an_unserved_route_is_named_other_and_keeps_its_bounded_original() {
    let capture = Capture::exporting();
    {
        let _guard = capture.enter();
        let long = format!("/sovereign.config.v99.System/{}", "x".repeat(400));
        for path in ["/sovereign.config.v99.System/GetVersion", long.as_str()] {
            let request = Request::builder()
                .method(Method::POST)
                .uri(path)
                .body(empty_body())
                .unwrap();
            serve_one(request).await;
        }
    }
    let exported = capture.finish();

    let spans = exported.spans_named("_OTHER");
    assert_eq!(spans.len(), 2);
    for span in &spans {
        assert_eq!(span.attribute("rpc.method"), Some("_OTHER"));
        let original = span.attribute("rpc.method_original").unwrap();
        assert!(original.chars().count() < 256, "{original}");
    }
    assert!(spans.iter().any(|span| {
        span.attribute("rpc.method_original") == Some("sovereign.config.v99.System/GetVersion")
    }));
}

// ---------------------------------------------------------------------------
// Inbound: the server span
// ---------------------------------------------------------------------------

/// The trace layer around a handler that logs once and answers `200`.
async fn serve_one(request: Request<BoxBody>) -> Response<BoxBody> {
    let handler = service_fn(|_request: Request<BoxBody>| async {
        tracing::info!("handled inside the request span");
        Ok::<_, std::convert::Infallible>(Response::new(empty_body()))
    });
    untimed().layer(handler).oneshot(request).await.unwrap()
}

fn get(path: &str, traceparent: Option<&str>) -> Request<BoxBody> {
    let mut request = Request::builder()
        .method(Method::GET)
        .uri(path)
        .body(empty_body())
        .unwrap();
    if let Some(traceparent) = traceparent {
        request
            .headers_mut()
            .insert("traceparent", HeaderValue::from_str(traceparent).unwrap());
    }
    request
}

#[tokio::test]
async fn a_request_with_traceparent_continues_that_trace() {
    let capture = Capture::exporting();
    {
        let _guard = capture.enter();
        serve_one(get("/index.html", Some(&inbound_traceparent()))).await;
    }
    let exported = capture.finish();

    let span = exported.span("GET");
    assert_eq!(span.kind, "server");
    assert_eq!(span.trace_id, INBOUND_TRACE_ID);
    assert_eq!(span.parent_span_id.as_deref(), Some(INBOUND_SPAN_ID));
    assert!(span.parent_is_remote);
    assert_eq!(span.attribute("http.request.method"), Some("GET"));
    assert_eq!(span.attribute("url.path"), Some("/index.html"));
    assert_eq!(span.attribute("http.response.status_code"), Some("200"));
    assert_every_span_identified(&exported);
}

#[tokio::test]
async fn a_request_without_traceparent_starts_a_new_trace() {
    let capture = Capture::exporting();
    {
        let _guard = capture.enter();
        serve_one(get("/index.html", None)).await;
        // A malformed header is no context at all, not an error.
        serve_one(get("/index.html", Some("00-not-a-trace-01"))).await;
    }
    let exported = capture.finish();

    let spans = exported.spans_named("GET");
    assert_eq!(spans.len(), 2);
    for span in spans {
        assert_eq!(span.parent_span_id, None);
        assert_ne!(span.trace_id, INBOUND_TRACE_ID);
    }
    assert_ne!(exported.spans[0].trace_id, exported.spans[1].trace_id);
}

/// The caller's "not sampled" flag is not obeyed: honouring it would let
/// anyone keep a request, and who made it, out of the trace store with one
/// header. The trace id and parent are still adopted.
#[tokio::test]
async fn a_caller_cannot_opt_a_request_out_of_tracing() {
    let capture = Capture::exporting();
    {
        let _guard = capture.enter();
        let unsampled = format!("00-{INBOUND_TRACE_ID}-{INBOUND_SPAN_ID}-00");
        serve_one(get("/index.html", Some(&unsampled))).await;
    }
    let exported = capture.finish();

    let span = exported.span("GET");
    assert_eq!(span.trace_id, INBOUND_TRACE_ID);
    assert_eq!(span.parent_span_id.as_deref(), Some(INBOUND_SPAN_ID));
}

#[tokio::test]
async fn a_server_error_on_the_web_ui_marks_its_span_failed() {
    let capture = Capture::exporting();
    {
        let _guard = capture.enter();
        let handler = service_fn(|_request: Request<BoxBody>| async {
            let mut response = Response::new(empty_body());
            *response.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
            Ok::<_, std::convert::Infallible>(response)
        });
        timed(&capture.meter())
            .layer(handler)
            .oneshot(get("/index.html", None))
            .await
            .unwrap();
        serve_one(get("/missing", None)).await;
    }
    let exported = capture.finish();

    // RED for the web UI: the request's duration, by method and status, with
    // `error.type` for a server error — and never the path.
    let duration = exported.metric("http.server.request.duration");
    assert_eq!(
        duration.stored_name(),
        "http_server_request_duration_seconds"
    );
    let point = duration.point(&[
        ("http.request.method", "GET"),
        ("http.response.status_code", "500"),
    ]);
    assert_eq!(point.count, 1);
    assert_eq!(
        point.attributes.get("error.type").map(String::as_str),
        Some("500")
    );
    assert!(point.attributes.keys().all(|key| key != "url.path"));

    let spans = exported.spans_named("GET");
    let failed = spans
        .iter()
        .find(|span| span.attribute("url.path") == Some("/index.html"))
        .unwrap();
    assert!(failed.is_error);
    assert_eq!(failed.attribute("http.response.status_code"), Some("500"));
    assert_eq!(failed.attribute("error.type"), Some("500"));
    let fine = spans
        .iter()
        .find(|span| span.attribute("url.path") == Some("/missing"))
        .unwrap();
    assert!(!fine.is_error);
}

#[tokio::test]
async fn a_log_record_inside_a_request_span_carries_its_trace_and_span_ids() {
    let capture = Capture::exporting();
    {
        let _guard = capture.enter();
        serve_one(get("/index.html", Some(&inbound_traceparent()))).await;
    }
    let exported = capture.finish();

    let span = exported.span("GET");
    let log = exported
        .log("handled inside the request span")
        .expect("the handler's log record was exported");
    assert_eq!(log.trace_id.as_deref(), Some(span.trace_id.as_str()));
    assert_eq!(log.span_id.as_deref(), Some(span.span_id.as_str()));
    // One fact, one signal: the event is a log record, not also a span event,
    // and the span's attributes are not copied onto it.
    assert!(
        !log.attributes.contains_key("url.path"),
        "{:?}",
        log.attributes
    );
}

#[tokio::test]
async fn an_unknown_method_is_bounded_to_standard_names() {
    let capture = Capture::exporting();
    {
        let _guard = capture.enter();
        let request = Request::builder()
            .method(Method::from_bytes(b"BREW").unwrap())
            .uri("/pot")
            .body(empty_body())
            .unwrap();
        serve_one(request).await;
    }
    let exported = capture.finish();
    let span = exported.span("HTTP");
    assert_eq!(span.attribute("http.request.method"), Some("_OTHER"));
}

/// A native gRPC server with the trace layer and the status recorder, as the
/// binary stacks them, serving `v3.System`.
struct GrpcHarness {
    address: SocketAddr,
    shutdown: tokio::sync::oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl GrpcHarness {
    async fn start(meter: &opentelemetry::metrics::Meter) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown, signal) = tokio::sync::oneshot::channel::<()>();
        let router = Server::builder()
            .layer(timed(meter))
            .layer(GrpcStatusLayer)
            .add_service(SystemServer::new(SystemService));
        let task = tokio::spawn(async move {
            router
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        let _ = signal.await;
                    },
                )
                .await
                .unwrap();
        });
        Self {
            address,
            shutdown,
            task,
        }
    }

    async fn get_version(&self, traceparent: Option<&str>, version: &str) {
        let channel = Endpoint::from_shared(format!("http://{}", self.address))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut request = tonic::Request::new(GetVersionRequest {
            protocol_version: version.to_owned(),
        });
        if let Some(traceparent) = traceparent {
            request
                .metadata_mut()
                .insert("traceparent", traceparent.parse().unwrap());
        }
        let _ = SystemClient::new(channel).get_version(request).await;
    }

    /// Stops the server once every connection has closed, so every span has
    /// ended before the capture is read.
    async fn stop(self) {
        let _ = self.shutdown.send(());
        tokio::time::timeout(Duration::from_secs(10), self.task)
            .await
            .expect("the harness stops")
            .unwrap();
    }
}

#[tokio::test]
async fn a_grpc_call_is_a_server_span_named_by_its_route_with_its_status() {
    let capture = Capture::exporting();
    {
        let _guard = capture.enter();
        let harness = GrpcHarness::start(&capture.meter()).await;
        harness
            .get_version(Some(&inbound_traceparent()), "v3")
            .await;
        harness.stop().await;
    }
    let exported = capture.finish();

    let span = exported.span("sovereign.config.v3.System/GetVersion");
    assert_eq!(span.kind, "server");
    assert_eq!(span.trace_id, INBOUND_TRACE_ID);
    assert_eq!(span.parent_span_id.as_deref(), Some(INBOUND_SPAN_ID));
    assert_eq!(span.attribute("rpc.system.name"), Some("grpc"));
    assert_eq!(
        span.attribute("rpc.method"),
        Some("sovereign.config.v3.System/GetVersion")
    );
    assert_eq!(
        span.attribute("sovereign_config.protocol.version"),
        Some("v3")
    );
    assert_eq!(span.attribute("rpc.response.status_code"), Some("OK"));
    assert!(!span.is_error);
    assert_every_span_identified(&exported);

    // RED: the same call, timed, under the span's own keys and values.
    let duration = exported.metric("rpc.server.call.duration");
    let point = duration.point(&[
        ("rpc.system.name", "grpc"),
        ("rpc.method", "sovereign.config.v3.System/GetVersion"),
        ("rpc.response.status_code", "OK"),
    ]);
    assert_eq!(point.count, 1);
    assert!(!point.attributes.contains_key("error.type"));
    assert!(point.value > 0.0 && point.value < 10.0, "{point:?}");
    assert_eq!(point.bounds, crate::metrics::DURATION_BOUNDARIES);
    assert!(
        point
            .attributes
            .keys()
            .all(|key| !key.starts_with("user.") && key != "sovereign_config.protocol.version"),
        "{point:?}"
    );
}

// ---------------------------------------------------------------------------
// Outbound: Authentik
// ---------------------------------------------------------------------------

/// An Authentik stand-in that records the `traceparent` of every request and
/// answers every lookup with no results.
async fn recording_authentik() -> (reqwest::Url, Arc<Mutex<Vec<Option<String>>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    let app = Router::new().fallback(move |request: AxumRequest| {
        let recorded = Arc::clone(&recorded);
        async move {
            recorded.lock().unwrap().push(
                request
                    .headers()
                    .get("traceparent")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned),
            );
            Json(json!({ "results": [] })).into_response()
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (origin, seen)
}

const ADMIN_TOKEN: &str = "span-test-admin-token-sentinel";

/// One Authentik lookup made while serving an inbound request.
async fn lookup_during_a_request(origin: reqwest::Url) {
    let client =
        AuthentikAdminClient::new(origin, Secret::new(ADMIN_TOKEN), Duration::from_secs(5))
            .unwrap();
    let span = server_span(
        &Method::POST,
        "/sovereign.config.v4.ManagedConnections/RevokeManagedConnection",
    )
    .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        "traceparent",
        HeaderValue::from_str(&inbound_traceparent()).unwrap(),
    );
    sovereign_config_telemetry::context::adopt_parent(&span, &headers);
    client
        .find_user_by_username("sc-managed-span-test")
        .instrument(span)
        .await
        .unwrap();
}

#[tokio::test]
async fn an_authentik_call_is_a_client_span_under_the_request_and_carries_its_context() {
    let (origin, seen) = recording_authentik().await;
    let capture = Capture::exporting();
    {
        let _guard = capture.enter();
        lookup_during_a_request(origin.clone()).await;
    }
    let exported = capture.finish();

    let server = exported.span("sovereign.config.v4.ManagedConnections/RevokeManagedConnection");
    let client = exported.span("GET /api/v3/core/users/");
    assert_eq!(client.kind, "client");
    assert!(client.is_child_of(server), "{client:?} under {server:?}");
    assert_eq!(client.attribute("http.request.method"), Some("GET"));
    assert_eq!(
        client.attribute("url.template"),
        Some("/api/v3/core/users/")
    );
    assert_eq!(client.attribute("server.address"), origin.host_str());
    assert_eq!(client.attribute("http.response.status_code"), Some("200"));

    // The header Authentik received names the client span as its parent.
    let seen = seen.lock().unwrap().clone();
    let header = seen[0].as_deref().expect("the request carried traceparent");
    assert_eq!(
        parse_traceparent(header),
        (client.trace_id.clone(), client.span_id.clone())
    );
    // Neither the admin token nor the username looked up is on any span.
    for value in exported.all_values() {
        assert!(!value.contains(ADMIN_TOKEN), "{value}");
        assert!(!value.contains("sc-managed-span-test"), "{value}");
    }
}

/// Propagation is the transport's, not the exporter's: with nothing exported,
/// the trace an inbound request belongs to still reaches Authentik.
#[tokio::test]
async fn with_telemetry_off_the_inbound_trace_still_reaches_authentik() {
    let (origin, seen) = recording_authentik().await;
    let capture = Capture::off();
    {
        let _guard = capture.enter();
        lookup_during_a_request(origin).await;
    }
    let exported = capture.finish();
    assert!(exported.spans.is_empty(), "telemetry off exports nothing");

    let seen = seen.lock().unwrap().clone();
    let header = seen[0]
        .as_deref()
        .expect("the request carried traceparent with telemetry off");
    let (trace_id, _) = parse_traceparent(header);
    assert_eq!(trace_id, INBOUND_TRACE_ID);
}

// ---------------------------------------------------------------------------
// Postgres, and detached work
// ---------------------------------------------------------------------------

/// A pool that never connects: every query fails fast, but the store call —
/// and so its span — still happens.
fn unreachable_pool() -> sqlx::PgPool {
    PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(500))
        .connect_lazy("postgresql://span_test:span-test-password-sentinel@127.0.0.1:1/span_test")
        .unwrap()
}

/// What no database span may carry: SQL text or a bound-parameter marker.
const FORBIDDEN_IN_DATABASE_SPANS: [&str; 5] = ["SELECT", "INSERT", "UPDATE", "DELETE", "$1"];

#[tokio::test]
async fn a_store_call_is_a_child_span_that_carries_no_sql() {
    let capture = Capture::exporting();
    {
        let _guard = capture.enter();
        let span =
            server_span(&Method::POST, "/sovereign.config.v4.Audit/QueryAuditTrail").unwrap();
        let _ = AuditRecorder::for_tests()
            .sweep_expired(&unreachable_pool(), time::OffsetDateTime::now_utc())
            .instrument(span)
            .await;
    }
    let exported = capture.finish();

    let server = exported.span("sovereign.config.v4.Audit/QueryAuditTrail");
    let store = exported.span("delete_before audit_events");
    assert!(store.is_child_of(server));
    assert_eq!(store.kind, "client");
    assert_eq!(store.attribute("db.system.name"), Some("postgresql"));
    assert_eq!(store.attribute("db.operation.name"), Some("delete_before"));
    assert_eq!(store.attribute("db.collection.name"), Some("audit_events"));
    // The unreachable database fails the call, and the span says so.
    assert!(store.is_error, "{store:?}");
    assert_eq!(store.attribute("error.type"), Some("storage_unavailable"));
    for span in &exported.spans {
        for text in span.attributes.values().chain(std::iter::once(&span.name)) {
            for forbidden in FORBIDDEN_IN_DATABASE_SPANS {
                assert!(
                    !text.contains(forbidden),
                    "span {:?} carries {forbidden:?}: {text}",
                    span.name
                );
            }
            assert!(!text.contains("span-test-password-sentinel"), "{text}");
        }
    }
}

#[tokio::test]
async fn the_audit_sweep_is_a_root_span_even_when_something_else_is_current() {
    let capture = Capture::exporting();
    {
        let _guard = capture.enter();
        let enclosing = server_span(&Method::GET, "/index.html").unwrap();
        crate::sweep_audit_trail(
            &unreachable_pool(),
            &AuditRecorder::for_tests(),
            Duration::from_hours(24),
            &crate::metrics::JobMetrics::new(&capture.meter()),
        )
        .instrument(enclosing)
        .await;
    }
    let exported = capture.finish();

    let sweep = exported.span("sovereign_config.audit.sweep");
    assert_eq!(
        sweep.parent_span_id, None,
        "the sweep must start its own trace"
    );
    assert_ne!(sweep.trace_id, exported.span("GET").trace_id);
    assert!(sweep.is_error, "the unreachable database fails the sweep");
    let store = exported.span("delete_before audit_events");
    assert!(store.is_child_of(sweep));
    assert!(store.is_error);
    // The failure is a log record in the sweep's trace, for the operator.
    let log = exported
        .log("audit retention sweep failed; retrying at the next interval")
        .expect("the failure is logged");
    assert_eq!(log.trace_id.as_deref(), Some(sweep.trace_id.as_str()));
    // RED for scheduled work: the failed sweep is timed, and marked failed.
    let duration = exported.metric("sovereign_config.audit.sweep.duration");
    assert_eq!(
        duration.stored_name(),
        "sovereign_config_audit_sweep_duration_seconds"
    );
    let point = duration.point(&[("error.type", "storage_unavailable")]);
    assert_eq!(point.count, 1);
}
