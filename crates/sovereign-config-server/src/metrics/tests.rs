//! The metrics contract, asserted on what the exporter received
//! (`observability` skill §7). Every [`Capture::finish`] also fails a test
//! whose exported series carries a forbidden label key, or build identity on
//! anything but the build-info gauge — so every test here that exports
//! checks both, for whatever instruments it touched.

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use opentelemetry::KeyValue;
use sovereign_config_telemetry::testing::{Capture, ExportedMetric, MetricKind, stored_name};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tonic::Code;

use super::{
    AuditMetrics, AuditWriteOutcome, AuthenticationMetrics, AuthenticationResult, CounterFamily,
    DURATION_BOUNDARIES, JobMetrics, ManagedConnectionMetrics, ManagedDependencyCall,
    ManagedDependencyOutcome, ManagedOperation, ManagedOperationResult, ProtocolMetrics,
    RequestMetrics, UNRECOGNISED_PROTOCOL_LABEL, names,
};
use crate::{Families, audit::EventKind, register_metrics, system::SERVED_PROTOCOL_LABELS};

/// Every instrument this server exports, and the name the platform stores
/// it under. **The source of truth** for the README's series names, the
/// retirement gate (`sovereign_config_protocol_requests_total`) and the
/// audit alert series (`sovereign_config_audit_events_total`): a rename that
/// would move a stored name fails here, not in a query.
const STORED_NAMES: [(&str, &str); 14] = [
    (
        "sovereign_config.authentication",
        "sovereign_config_authentication_total",
    ),
    (
        "sovereign_config.protocol.requests",
        "sovereign_config_protocol_requests_total",
    ),
    (
        "sovereign_config.protocol.client_versions",
        "sovereign_config_protocol_client_versions_total",
    ),
    (
        "sovereign_config.managed_connection.operations",
        "sovereign_config_managed_connection_operations_total",
    ),
    (
        "sovereign_config.managed_dependency",
        "sovereign_config_managed_dependency_total",
    ),
    (
        "sovereign_config.audit.events",
        "sovereign_config_audit_events_total",
    ),
    (
        "sovereign_config.audit.retention.swept",
        "sovereign_config_audit_retention_swept_total",
    ),
    (
        "sovereign_config.audit.retention.sweep_failures",
        "sovereign_config_audit_retention_sweep_failures_total",
    ),
    (
        "sovereign_config.audit.sweep.duration",
        "sovereign_config_audit_sweep_duration_seconds",
    ),
    ("sovereign_config.build.info", "sovereign_config_build_info"),
    (
        "rpc.server.call.duration",
        "rpc_server_call_duration_seconds",
    ),
    (
        "http.server.request.duration",
        "http_server_request_duration_seconds",
    ),
    ("db.client.connection.count", "db_client_connection_count"),
    ("db.client.connection.max", "db_client_connection_max"),
];

/// A pool that never connects: its gauges read zero, and nothing listens.
fn lazy_pool() -> PgPool {
    PgPoolOptions::new()
        .max_connections(7)
        .connect_lazy("postgresql://metrics_test@127.0.0.1:1/metrics_test")
        .expect("a lazy pool needs no connection")
}

struct Registered {
    authentication: Arc<AuthenticationMetrics>,
    managed: Arc<ManagedConnectionMetrics>,
    protocol: Arc<ProtocolMetrics>,
    audit: Arc<AuditMetrics>,
}

/// What `main` registers, exactly as `main` registers it, on `capture`'s meter.
fn register_everything(capture: &Capture, pool: &PgPool) -> Registered {
    let registered = Registered {
        authentication: Arc::new(AuthenticationMetrics::default()),
        managed: Arc::new(ManagedConnectionMetrics::default()),
        protocol: Arc::new(ProtocolMetrics::new(SERVED_PROTOCOL_LABELS)),
        audit: Arc::new(AuditMetrics::default()),
    };
    register_metrics(
        &capture.meter(),
        Families {
            authentication: &registered.authentication,
            managed: &registered.managed,
            protocol: &registered.protocol,
            audit: &registered.audit,
        },
        pool,
    );
    registered
}

#[tokio::test]
async fn every_instrument_is_exported_under_its_stored_name_with_the_resource_identity() {
    let capture = Capture::exporting();
    let pool = lazy_pool();
    let registered = register_everything(&capture, &pool);
    registered.protocol.record_attempted("v4");
    registered.protocol.record_authenticated("v4");
    registered
        .audit
        .record_write(EventKind::SecretRevealed, AuditWriteOutcome::Failed);
    let requests = RequestMetrics::new(&capture.meter());
    requests.record_rpc(
        "sovereign.config.v4.System/GetVersion",
        Code::Ok,
        Duration::from_millis(3),
    );
    requests.record_http("GET", 200, Duration::from_millis(1));
    JobMetrics::new(&capture.meter()).record_sweep(Duration::from_millis(20), None);

    let exported = capture.finish();

    let exported_names: BTreeSet<(String, String)> = exported
        .metrics
        .iter()
        .map(|metric| (metric.name.clone(), metric.stored_name()))
        .collect();
    let expected: BTreeSet<(String, String)> = STORED_NAMES
        .iter()
        .map(|(name, stored)| ((*name).to_owned(), (*stored).to_owned()))
        .collect();
    assert_eq!(exported_names, expected);

    for metric in &exported.metrics {
        for key in [
            "service.name",
            "service.version",
            "deployment.environment.name",
            "service.instance.id",
        ] {
            assert!(
                metric.resource.contains_key(key),
                "{} exported without {key}: {:?}",
                metric.name,
                metric.resource
            );
        }
    }

    // The retirement gate and the audit alert answer with the labels they
    // always had — and a series nobody has touched reads zero, not absent.
    let requests = exported.metric(names::PROTOCOL_REQUESTS);
    assert_eq!(requests.kind, MetricKind::Counter);
    assert!(
        (requests
            .point(&[("version", "v4"), ("outcome", "authenticated")])
            .value
            - 1.0)
            .abs()
            < f64::EPSILON
    );
    assert!(
        requests
            .point(&[("version", "v3"), ("outcome", "authenticated")])
            .value
            .abs()
            < f64::EPSILON
    );
    let audit = exported.metric(names::AUDIT_EVENTS);
    assert!(
        (audit
            .point(&[("kind", "secret.revealed"), ("outcome", "failed")])
            .value
            - 1.0)
            .abs()
            < f64::EPSILON
    );

    let info = exported.metric(names::BUILD_INFO);
    assert_eq!(info.kind, MetricKind::Gauge);
    assert_eq!(info.points.len(), 1, "one series, never one per version");
    let point = &info.points[0];
    assert!((point.value - 1.0).abs() < f64::EPSILON);
    assert_eq!(
        point
            .attributes
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["protocol", "revision", "version"]
    );
    assert_eq!(
        point.attributes.get("protocol").map(String::as_str),
        Some(SERVED_PROTOCOL_LABELS.join(",").as_str())
    );
    assert_eq!(
        point.attributes.get("version").map(String::as_str),
        Some(crate::APPLICATION_VERSION)
    );

    let connections = exported.metric(names::DB_CLIENT_CONNECTION_COUNT);
    assert_eq!(connections.kind, MetricKind::UpDownCounter);
    for state in ["idle", "used"] {
        let point = connections.point(&[
            ("db.client.connection.pool.name", "postgres"),
            ("db.client.connection.state", state),
        ]);
        assert!(point.value.abs() < f64::EPSILON, "a lazy pool is empty");
    }
    let max = exported.metric(names::DB_CLIENT_CONNECTION_MAX);
    assert!((max.point(&[]).value - 7.0).abs() < f64::EPSILON);
}

/// The duration histograms are in seconds, on the explicit boundaries: the
/// SDK's defaults suit milliseconds and would put every request in the first
/// bucket.
#[test]
fn every_duration_is_a_seconds_histogram_on_the_explicit_boundaries() {
    let capture = Capture::exporting();
    let requests = RequestMetrics::new(&capture.meter());
    requests.record_rpc("_OTHER", Code::Unimplemented, Duration::from_millis(40));
    requests.record_http("GET", 404, Duration::from_millis(2));
    JobMetrics::new(&capture.meter())
        .record_sweep(Duration::from_secs(2), Some("storage_unavailable"));
    let exported = capture.finish();

    let histograms: Vec<&ExportedMetric> = exported
        .metrics
        .iter()
        .filter(|metric| metric.kind == MetricKind::Histogram)
        .collect();
    assert_eq!(histograms.len(), 3);
    for histogram in histograms {
        assert_eq!(histogram.unit, "s", "{}", histogram.name);
        for point in &histogram.points {
            assert_eq!(point.bounds, DURATION_BOUNDARIES, "{}", histogram.name);
            assert!(point.value > 0.001, "recorded in seconds: {point:?}");
        }
    }
    // Only a server-error code fails a call: UNIMPLEMENTED is one.
    let unimplemented = exported
        .metric(names::RPC_SERVER_CALL_DURATION)
        .point(&[("rpc.method", "_OTHER")]);
    assert_eq!(
        unimplemented
            .attributes
            .get("error.type")
            .map(String::as_str),
        Some("UNIMPLEMENTED")
    );
    let not_found = exported
        .metric(names::HTTP_SERVER_REQUEST_DURATION)
        .point(&[("http.response.status_code", "404")]);
    assert!(!not_found.attributes.contains_key("error.type"));
}

/// The forbidden-label check runs on whatever was exported, listing keys
/// rather than metrics: an instrument nobody listed is still caught.
#[test]
#[should_panic(expected = "forbidden label key")]
fn a_series_carrying_an_identifier_fails_the_capture() {
    let capture = Capture::exporting();
    capture
        .meter()
        .u64_counter("sovereign_config.anything_new")
        .build()
        .add(1, &[KeyValue::new("user.id", "someone")]);
    let _ = capture.finish();
}

#[test]
#[should_panic(expected = "build identity")]
fn build_identity_on_a_working_metric_fails_the_capture() {
    let capture = Capture::exporting();
    super::register_build_info(&capture.meter(), "9.9.9", "abc1234", "v4,v3");
    capture
        .meter()
        .u64_counter("sovereign_config.anything_new")
        .build()
        .add(1, &[KeyValue::new("release", "9.9.9")]);
    let _ = capture.finish();
}

/// One series' labels, as `(key, value)` pairs.
type LabelSet = Vec<(String, String)>;

/// Each label set a family reports for `instrument`.
fn label_sets<F: CounterFamily>(family: &F, instrument: &'static str) -> Vec<LabelSet> {
    let mut sets = Vec::new();
    family.observe(instrument, &mut |_, attributes| {
        sets.push(
            attributes
                .iter()
                .map(|kv| (kv.key.to_string(), kv.value.to_string()))
                .collect(),
        );
    });
    sets
}

/// Asserts every instrument `family` declares reports at least one series.
fn declared<F: CounterFamily>(family: &F) {
    for instrument in F::INSTRUMENTS {
        assert!(
            !label_sets(family, instrument.name).is_empty(),
            "{} reports nothing",
            instrument.name
        );
    }
}

/// Every variant of every label enum is reported, once, with a non-empty
/// value — iterating the enums rather than listing cases, so a variant added
/// to an enum is covered without editing this test.
#[test]
fn every_variant_of_every_label_enum_is_reported_exactly_once() {
    let protocol = ProtocolMetrics::new(SERVED_PROTOCOL_LABELS);
    let cases: Vec<(&str, Vec<LabelSet>, usize)> = vec![
        (
            names::AUTHENTICATION,
            label_sets(&AuthenticationMetrics::default(), names::AUTHENTICATION),
            AuthenticationResult::ALL.len(),
        ),
        (
            names::MANAGED_OPERATIONS,
            label_sets(
                &ManagedConnectionMetrics::default(),
                names::MANAGED_OPERATIONS,
            ),
            ManagedOperation::ALL.len() * ManagedOperationResult::ALL.len(),
        ),
        (
            names::MANAGED_DEPENDENCY,
            label_sets(
                &ManagedConnectionMetrics::default(),
                names::MANAGED_DEPENDENCY,
            ),
            ManagedDependencyCall::ALL.len() * ManagedDependencyOutcome::ALL.len(),
        ),
        (
            names::AUDIT_EVENTS,
            label_sets(&AuditMetrics::default(), names::AUDIT_EVENTS),
            EventKind::ALL.len() * AuditWriteOutcome::ALL.len(),
        ),
        (
            names::PROTOCOL_REQUESTS,
            label_sets(&protocol, names::PROTOCOL_REQUESTS),
            // attempted and authenticated per version, plus unrecognised.
            SERVED_PROTOCOL_LABELS.len() * 2 + 1,
        ),
        (
            names::PROTOCOL_CLIENT_VERSIONS,
            label_sets(&protocol, names::PROTOCOL_CLIENT_VERSIONS),
            SERVED_PROTOCOL_LABELS.len() + 1,
        ),
    ];
    for (instrument, sets, expected) in cases {
        assert_eq!(sets.len(), expected, "{instrument}");
        let unique: BTreeSet<_> = sets.iter().collect();
        assert_eq!(unique.len(), sets.len(), "{instrument} repeats a label set");
        for set in &sets {
            assert!(
                set.iter().all(|(_, value)| !value.is_empty()),
                "{instrument}: {set:?}"
            );
        }
    }
    // Every instrument a family declares reports something.
    declared(&AuthenticationMetrics::default());
    declared(&ManagedConnectionMetrics::default());
    declared(&protocol);
    declared(&AuditMetrics::default());
}

#[test]
fn the_stored_name_translation_matches_the_platform() {
    assert_eq!(
        stored_name(
            "sovereign_config.protocol.requests",
            "",
            MetricKind::Counter
        ),
        "sovereign_config_protocol_requests_total"
    );
    assert_eq!(
        stored_name("rpc.server.call.duration", "s", MetricKind::Histogram),
        "rpc_server_call_duration_seconds"
    );
    assert_eq!(
        stored_name(
            "db.client.connection.count",
            "{connection}",
            MetricKind::UpDownCounter
        ),
        "db_client_connection_count"
    );
    assert_eq!(
        stored_name("sovereign_config.build.info", "", MetricKind::Gauge),
        "sovereign_config_build_info"
    );
}

#[test]
fn metrics_use_only_bounded_result_labels() {
    let metrics = AuthenticationMetrics::default();
    metrics.increment(AuthenticationResult::Success);
    metrics.increment(AuthenticationResult::InvalidClaims);
    let rendered = metrics.series();

    assert!(rendered.contains("outcome=\"success\",reason=\"accepted\"} 1"));
    assert!(rendered.contains("outcome=\"failure\",reason=\"invalid_claims\"} 1"));
    assert_eq!(
        rendered
            .matches("sovereign_config_authentication_total{")
            .count(),
        AuthenticationResult::ALL.len()
    );
    assert!(rendered.contains("outcome=\"failure\",reason=\"bad_signature\"} 0"));
}

#[test]
fn managed_metrics_use_only_bounded_fixed_labels() {
    let metrics = ManagedConnectionMetrics::default();
    metrics.record_operation(ManagedOperation::Create, ManagedOperationResult::Success);
    metrics.record_dependency(
        ManagedDependencyCall::SetCredential,
        ManagedDependencyOutcome::Ambiguous,
    );
    let rendered = metrics.series();

    assert!(rendered.contains(
        "sovereign_config_managed_connection_operations_total{operation=\"create\",result=\"success\"} 1"
    ));
    assert!(rendered.contains(
        "sovereign_config_managed_dependency_total{call=\"set_credential\",outcome=\"ambiguous\"} 1"
    ));
}

#[test]
fn an_unrecognised_version_never_becomes_a_label() {
    let metrics = ProtocolMetrics::new(SERVED_PROTOCOL_LABELS);
    metrics.record_attempted("v9000");
    metrics.record_offered("not-a-version");
    let rendered = metrics.series();
    assert!(rendered.contains(&format!(
        "sovereign_config_protocol_requests_total{{version=\"{UNRECOGNISED_PROTOCOL_LABEL}\",outcome=\"attempted\"}} 1"
    )));
    assert!(!rendered.contains("v9000") && !rendered.contains("not-a-version"));
}

/// The pool gauges against a real pool: a held connection is `used`.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn the_pool_gauges_report_a_real_pool() {
    let database_url = std::env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL")
        .expect("SOVEREIGN_CONFIG_TEST_DATABASE_URL must be configured");
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .min_connections(2)
        .connect(&database_url)
        .await
        .expect("the test database must accept connections");
    let held = pool.acquire().await.expect("a connection");
    // `min_connections` fills in the background; wait for an idle one.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while pool.num_idle() < 1 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let capture = Capture::exporting();
    super::register_pool(&capture.meter(), &pool);
    let exported = capture.finish();
    drop(held);

    let connections = exported.metric(names::DB_CLIENT_CONNECTION_COUNT);
    let value = |state| {
        connections
            .point(&[("db.client.connection.state", state)])
            .value
    };
    assert!(value("used") >= 1.0, "the held connection is in use");
    assert!(value("idle") >= 1.0, "the pool's minimum keeps one idle");
    assert!(
        value("used") + value("idle") <= 3.0,
        "never above the maximum"
    );
    let max = exported.metric(names::DB_CLIENT_CONNECTION_MAX);
    assert!((max.point(&[]).value - 3.0).abs() < f64::EPSILON);
}
