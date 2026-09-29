//! What other crates' tests assert telemetry on: the production assembly
//! around in-memory exporters, and what those exporters received, in plain
//! types (`observability` skill §7: assert on what was exported, never on
//! configuration).
//!
//! Behind the `testing` feature, which only a `[dev-dependencies]` entry
//! enables: it lets a test elsewhere see exported spans without naming an SDK
//! type, so the allowlist (`tests/allowlist.rs`) holds for tests too.
//!
//! A [`Capture`] is installed for one thread with [`Capture::enter`]. Async
//! tests use tokio's current-thread runtime (the `#[tokio::test]` default), so
//! every task the test spawns runs under it.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, Once},
    time::Duration,
};

use opentelemetry::{
    KeyValue,
    logs::AnyValue,
    metrics::Meter,
    trace::{SpanId, SpanKind, Status},
};
use opentelemetry_sdk::{
    Resource,
    error::OTelSdkResult,
    logs::{BatchConfigBuilder as LogBatch, InMemoryLogExporter, LogBatch as Records, LogExporter},
    metrics::{
        InMemoryMetricExporter,
        data::{AggregatedMetrics, MetricData, ScopeMetrics},
    },
    trace::{BatchConfigBuilder as SpanBatch, SpanData, SpanExporter},
};
use tracing::{Dispatch, dispatcher::DefaultGuard};
use tracing_subscriber::fmt::MakeWriter;

use crate::{Assembly, Exporters, Identity, InitError, OtelEnv, Telemetry, config, keys};

/// The build version every captured resource carries.
pub const VERSION: &str = "0.0.0-capture";

/// The variables of a deployment that exports every signal.
const EXPORTING: [(&str, &str); 7] = [
    ("OTEL_SERVICE_NAME", "sovereign-config"),
    (
        "OTEL_RESOURCE_ATTRIBUTES",
        "deployment.environment.name=test,telemetry_source=otlp",
    ),
    (
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "http://collector.invalid:4318",
    ),
    ("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf"),
    ("OTEL_LOGS_EXPORTER", "otlp"),
    ("OTEL_METRICS_EXPORTER", "otlp"),
    ("OTEL_TRACES_EXPORTER", "otlp"),
];

/// Keeps every span it is given, and the resource the provider set on it.
#[derive(Debug, Clone, Default)]
struct SpanRecorder {
    spans: Arc<Mutex<Vec<SpanData>>>,
    resource: Arc<Mutex<Option<Resource>>>,
}

impl SpanExporter for SpanRecorder {
    fn export(
        &self,
        batch: Vec<SpanData>,
    ) -> impl std::future::Future<Output = OTelSdkResult> + Send {
        self.spans.lock().expect("recorder lock").extend(batch);
        std::future::ready(Ok(()))
    }

    fn set_resource(&mut self, resource: &Resource) {
        *self.resource.lock().expect("recorder lock") = Some(resource.clone());
    }
}

/// The SDK's in-memory log exporter clears what it holds on shutdown; this
/// keeps it, so what shutdown flushed can still be read.
#[derive(Debug, Clone)]
struct LogRecorder(InMemoryLogExporter);

impl LogExporter for LogRecorder {
    async fn export(&self, batch: Records<'_>) -> OTelSdkResult {
        self.0.export(batch).await
    }

    fn set_resource(&mut self, resource: &Resource) {
        self.0.set_resource(resource);
    }
}

/// Discards the stdout layer's output.
#[derive(Clone, Copy)]
struct Silent;

impl std::io::Write for Silent {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Silent {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        *self
    }
}

/// Registers one inert dispatch for the life of the process, before the first
/// capture's.
///
/// While exactly one dispatch is registered, tracing-core assumes it is the
/// global default: a callsite first reached on *another* thread takes its
/// interest from that thread's default — none, in a parallel test — and
/// caches `never` for every thread. With the first capture the only
/// registered dispatch, a parallel test that reached a callsite first (the
/// Authentik introspection's `client_span`, say) switched that span off in the
/// capture too: it went missing, and `Span::current().record(..)` landed on
/// its parent instead. A second registration makes every rebuild consult each
/// live dispatch.
fn never_the_only_dispatch() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        std::mem::forget(Dispatch::new(tracing::subscriber::NoSubscriber::default()));
    });
}

/// The production assembly around recording exporters.
pub struct Capture {
    dispatch: Dispatch,
    telemetry: Telemetry,
    spans: SpanRecorder,
    logs: InMemoryLogExporter,
    metrics: InMemoryMetricExporter,
}

impl Capture {
    /// Telemetry on: every signal exports, as on a deployment.
    #[must_use]
    pub fn exporting() -> Self {
        Self::with_env(&OtelEnv::from_pairs(EXPORTING))
    }

    /// Telemetry off: no `OTEL_*` variable, so nothing is exported, but the
    /// span layer and propagation still run.
    #[must_use]
    pub fn off() -> Self {
        Self::with_env(&OtelEnv::default())
    }

    fn with_env(env: &OtelEnv) -> Self {
        never_the_only_dispatch();
        let plan = config::validate(env).expect("the capture's variables are valid");
        let spans = SpanRecorder::default();
        let logs = InMemoryLogExporter::default();
        let metrics = InMemoryMetricExporter::default();
        let (span_exporter, log_exporter, metric_exporter) =
            (spans.clone(), LogRecorder(logs.clone()), metrics.clone());
        let Assembly {
            subscriber,
            telemetry,
        } = crate::assemble(
            plan,
            &Identity {
                version: VERSION.to_owned(),
                hostname: Some("capture-host".to_owned()),
            },
            "info",
            Silent,
            Exporters {
                logs: move || Ok::<_, InitError>(log_exporter),
                // Nothing leaves before `finish`, which flushes: a test that
                // sees a span has also proved the flush.
                log_batch: LogBatch::default()
                    .with_scheduled_delay(Duration::from_secs(3600))
                    .build(),
                spans: move || Ok::<_, InitError>(span_exporter),
                span_batch: SpanBatch::default()
                    .with_scheduled_delay(Duration::from_secs(3600))
                    .build(),
                metrics: move || Ok::<_, InitError>(metric_exporter),
                // Likewise: the one collection is the one shutdown makes.
                metric_interval: Some(Duration::from_secs(3600)),
            },
        )
        .expect("the capture assembles");
        let dispatch = Dispatch::new(subscriber);
        // Never dropped. Parallel tests each install a scoped dispatch, and
        // tracing-core walks every live one under its registry's read lock
        // when a new one registers; if that walk held the last reference to
        // a finished capture, dropping it would drop the SDK providers, whose
        // `Drop` logs through a callsite registering for the first time — the
        // same read lock, re-taken behind a waiting writer: a deadlock of the
        // whole test binary. One leaked reference per capture rules it out.
        std::mem::forget(dispatch.clone());
        Self {
            dispatch,
            telemetry,
            spans,
            logs,
            metrics,
        }
    }

    /// The meter the capture's instruments are created on: its own provider,
    /// never the global one, so parallel tests do not share series. A no-op
    /// meter when the capture is [`Capture::off`].
    #[must_use]
    pub fn meter(&self) -> Meter {
        self.telemetry.meter()
    }

    /// Installs the capture as this thread's subscriber until the guard drops.
    #[must_use]
    pub fn enter(&self) -> DefaultGuard {
        let guard = tracing::dispatcher::set_default(&self.dispatch);
        // Every callsite's cached interest is recomputed now that this
        // dispatch is live. A callsite first reached by another test while
        // this one's dispatch was registering can otherwise keep the
        // `never` it computed without it, and its spans silently vanish
        // from this capture.
        tracing::callsite::rebuild_interest_cache();
        guard
    }

    /// Flushes, and returns everything exported. Every exported span's
    /// attribute keys are checked against [`keys::is_known`] here, so each
    /// test that captures spans also checks the keys it produced.
    ///
    /// # Panics
    ///
    /// When an exported span carries an unknown attribute key.
    #[must_use]
    pub fn finish(mut self) -> Exported {
        self.telemetry.shutdown();
        let resource = self
            .spans
            .resource
            .lock()
            .expect("recorder lock")
            .as_ref()
            .map(pairs_of)
            .unwrap_or_default();
        let spans = self
            .spans
            .spans
            .lock()
            .expect("recorder lock")
            .iter()
            .map(|span| ExportedSpan::from_sdk(span, &resource))
            .collect();
        let logs = self
            .logs
            .get_emitted_logs()
            .expect("the log recorder is readable")
            .iter()
            .map(|log| {
                let context = log.record.trace_context();
                ExportedLog {
                    body: log.record.body().map(any_value),
                    trace_id: context.map(|context| context.trace_id.to_string()),
                    span_id: context.map(|context| context.span_id.to_string()),
                    attributes: log
                        .record
                        .attributes_iter()
                        .map(|(key, value)| (key.to_string(), any_value(value)))
                        .collect(),
                }
            })
            .collect();
        let duplicated = self
            .spans
            .spans
            .lock()
            .expect("recorder lock")
            .iter()
            .filter_map(|span| {
                let mut keys: Vec<&str> =
                    span.attributes.iter().map(|kv| kv.key.as_str()).collect();
                keys.sort_unstable();
                let before = keys.len();
                keys.dedup();
                (keys.len() != before).then(|| span.name.to_string())
            })
            .collect::<Vec<_>>();
        // The SDK appends a re-recorded attribute rather than replacing it, so
        // a span can leave with one key twice; the plain map below would hide
        // that, so it is refused here.
        assert!(
            duplicated.is_empty(),
            "spans exported with an attribute key recorded twice: {duplicated:?}"
        );
        // Cumulative, so the last collection — the one shutdown made — holds
        // every series with its total.
        let metrics = self
            .metrics
            .get_finished_metrics()
            .expect("the metric recorder is readable")
            .last()
            .map(|collected| {
                let resource = pairs_of(collected.resource());
                collected
                    .scope_metrics()
                    .flat_map(ScopeMetrics::metrics)
                    .map(|metric| ExportedMetric::from_sdk(metric, &resource))
                    .collect()
            })
            .unwrap_or_default();
        let exported = Exported {
            spans,
            logs,
            metrics,
        };
        let unknown = exported.unknown_attribute_keys();
        assert!(
            unknown.is_empty(),
            "exported span attribute keys that are neither semantic-convention names nor \
             `{}`-prefixed: {unknown:?}",
            keys::PRODUCT_PREFIX
        );
        let forbidden = exported.forbidden_metric_keys();
        assert!(
            forbidden.is_empty(),
            "exported metric series carrying a forbidden label key: {forbidden:?}"
        );
        let misplaced = exported.misplaced_build_identity();
        assert!(
            misplaced.is_empty(),
            "build identity on a metric other than {}: {misplaced:?}",
            keys::BUILD_INFO
        );
        exported
    }
}

fn pairs_of(resource: &Resource) -> BTreeMap<String, String> {
    resource
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn pairs_of_attributes<'a>(
    attributes: impl Iterator<Item = &'a KeyValue>,
) -> BTreeMap<String, String> {
    attributes
        .map(|attribute| (attribute.key.to_string(), attribute.value.to_string()))
        .collect()
}

fn any_value(value: &AnyValue) -> String {
    match value {
        AnyValue::String(text) => text.to_string(),
        other => format!("{other:?}"),
    }
}

/// One exported span, in plain types. Ids are lowercase hex, as W3C
/// `traceparent` spells them.
#[derive(Debug, Clone)]
pub struct ExportedSpan {
    pub name: String,
    pub kind: &'static str,
    pub trace_id: String,
    pub span_id: String,
    /// `None` for a root span.
    pub parent_span_id: Option<String>,
    /// Whether the parent came from another process (an inbound
    /// `traceparent`).
    pub parent_is_remote: bool,
    pub attributes: BTreeMap<String, String>,
    /// `(trace_id, span_id)` of every linked span.
    pub links: Vec<(String, String)>,
    pub is_error: bool,
    pub resource: BTreeMap<String, String>,
}

impl ExportedSpan {
    fn from_sdk(span: &SpanData, resource: &BTreeMap<String, String>) -> Self {
        Self {
            name: span.name.to_string(),
            kind: match span.span_kind {
                SpanKind::Server => "server",
                SpanKind::Client => "client",
                SpanKind::Producer => "producer",
                SpanKind::Consumer => "consumer",
                SpanKind::Internal => "internal",
            },
            trace_id: span.span_context.trace_id().to_string(),
            span_id: span.span_context.span_id().to_string(),
            parent_span_id: (span.parent_span_id != SpanId::INVALID)
                .then(|| span.parent_span_id.to_string()),
            parent_is_remote: span.parent_span_is_remote,
            attributes: span
                .attributes
                .iter()
                .map(|attribute| (attribute.key.to_string(), attribute.value.to_string()))
                .collect(),
            links: span
                .links
                .iter()
                .map(|link| {
                    (
                        link.span_context.trace_id().to_string(),
                        link.span_context.span_id().to_string(),
                    )
                })
                .collect(),
            is_error: matches!(span.status, Status::Error { .. }),
            resource: resource.clone(),
        }
    }

    /// The value of attribute `key`, if the span carries it.
    #[must_use]
    pub fn attribute(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).map(String::as_str)
    }

    /// Whether `other` is this span's direct parent, in the same trace.
    #[must_use]
    pub fn is_child_of(&self, other: &Self) -> bool {
        self.trace_id == other.trace_id
            && self.parent_span_id.as_deref() == Some(other.span_id.as_str())
    }
}

/// One exported log record, in plain types.
#[derive(Debug, Clone)]
pub struct ExportedLog {
    pub body: Option<String>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub attributes: BTreeMap<String, String>,
}

/// What kind of instrument a metric came from, as the platform's
/// OTLP-to-Prometheus translation distinguishes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricKind {
    /// A monotonic sum: a counter, stored with `_total`.
    Counter,
    /// A non-monotonic sum: an up-down counter, stored as a gauge.
    UpDownCounter,
    Gauge,
    /// Stored as `_bucket`, `_sum` and `_count` series under one base name.
    Histogram,
}

/// One exported data point, in plain types. `value` is the sum's or the
/// gauge's value, or a histogram's sum; `count` and `bounds` are a
/// histogram's only.
#[derive(Debug, Clone)]
pub struct ExportedPoint {
    pub attributes: BTreeMap<String, String>,
    pub value: f64,
    pub count: u64,
    pub bounds: Vec<f64>,
}

impl ExportedPoint {
    /// Whether every `(key, value)` in `labels` is on this point.
    #[must_use]
    pub fn has(&self, labels: &[(&str, &str)]) -> bool {
        labels
            .iter()
            .all(|(key, value)| self.attributes.get(*key).map(String::as_str) == Some(*value))
    }
}

/// One exported metric, in plain types.
#[derive(Debug, Clone)]
pub struct ExportedMetric {
    pub name: String,
    pub unit: String,
    pub kind: MetricKind,
    pub points: Vec<ExportedPoint>,
    pub resource: BTreeMap<String, String>,
}

impl ExportedMetric {
    #[allow(clippy::cast_precision_loss)] // test counts, far below 2^52
    fn from_sdk(
        metric: &opentelemetry_sdk::metrics::data::Metric,
        resource: &BTreeMap<String, String>,
    ) -> Self {
        fn points<T: Copy>(
            data: &MetricData<T>,
            value: impl Fn(T) -> f64,
        ) -> (MetricKind, Vec<ExportedPoint>) {
            let point = |attributes, value, count, bounds| ExportedPoint {
                attributes,
                value,
                count,
                bounds,
            };
            match data {
                MetricData::Sum(sum) => (
                    if sum.is_monotonic() {
                        MetricKind::Counter
                    } else {
                        MetricKind::UpDownCounter
                    },
                    sum.data_points()
                        .map(|p| {
                            point(
                                pairs_of_attributes(p.attributes()),
                                value(p.value()),
                                0,
                                Vec::new(),
                            )
                        })
                        .collect(),
                ),
                MetricData::Gauge(gauge) => (
                    MetricKind::Gauge,
                    gauge
                        .data_points()
                        .map(|p| {
                            point(
                                pairs_of_attributes(p.attributes()),
                                value(p.value()),
                                0,
                                Vec::new(),
                            )
                        })
                        .collect(),
                ),
                MetricData::Histogram(histogram) => (
                    MetricKind::Histogram,
                    histogram
                        .data_points()
                        .map(|p| {
                            point(
                                pairs_of_attributes(p.attributes()),
                                value(p.sum()),
                                p.count(),
                                p.bounds().collect(),
                            )
                        })
                        .collect(),
                ),
                MetricData::ExponentialHistogram(_) => {
                    panic!("this product records no exponential histogram")
                }
            }
        }
        let (kind, points) = match metric.data() {
            AggregatedMetrics::F64(data) => points(data, |v| v),
            AggregatedMetrics::U64(data) => points(data, |v| v as f64),
            AggregatedMetrics::I64(data) => points(data, |v| v as f64),
        };
        Self {
            name: metric.name().to_owned(),
            unit: metric.unit().to_owned(),
            kind,
            points,
            resource: resource.clone(),
        }
    }

    /// The name the platform stores this metric under (see [`stored_name`]).
    #[must_use]
    pub fn stored_name(&self) -> String {
        stored_name(&self.name, &self.unit, self.kind)
    }

    /// The one point carrying every `(key, value)` in `labels`.
    ///
    /// # Panics
    ///
    /// When there is not exactly one.
    #[must_use]
    pub fn point(&self, labels: &[(&str, &str)]) -> &ExportedPoint {
        let matching: Vec<_> = self.points.iter().filter(|p| p.has(labels)).collect();
        assert_eq!(
            matching.len(),
            1,
            "expected one {} point with {labels:?}; exported: {:?}",
            self.name,
            self.points
        );
        matching[0]
    }
}

/// The name the estate's collector stores a metric under: its OTLP-to-
/// Prometheus translation (`otelcol.exporter.prometheus` in `monitor-alloy`,
/// suffixes on) — every character outside `[A-Za-z0-9_:]` becomes `_`, the
/// unit is appended as a word unless it is an annotation in braces, and a
/// counter gains `_total`. A histogram's name is the base of its `_bucket`,
/// `_sum` and `_count` series.
///
/// A mirror, for tests: a rename that would move a stored name fails the
/// test comparing against it, rather than the README's queries.
///
/// # Panics
///
/// On a unit the table below does not know: extend it deliberately.
#[must_use]
pub fn stored_name(name: &str, unit: &str, kind: MetricKind) -> String {
    let mut stored: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == ':' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let unit = match unit {
        "" => None,
        annotation if annotation.starts_with('{') && annotation.ends_with('}') => None,
        "s" => Some("seconds"),
        "ms" => Some("milliseconds"),
        "By" => Some("bytes"),
        "1" if kind == MetricKind::Gauge => Some("ratio"),
        "1" => None,
        other => panic!("no Prometheus word for unit {other:?}: extend `stored_name`"),
    };
    if let Some(word) = unit
        && !stored.ends_with(&format!("_{word}"))
    {
        stored.push('_');
        stored.push_str(word);
    }
    if kind == MetricKind::Counter && !stored.ends_with("_total") {
        stored.push_str("_total");
    }
    stored
}

/// Everything a [`Capture`] exported.
#[derive(Debug, Clone)]
pub struct Exported {
    pub spans: Vec<ExportedSpan>,
    pub logs: Vec<ExportedLog>,
    pub metrics: Vec<ExportedMetric>,
}

impl Exported {
    /// The only metric named `name`.
    ///
    /// # Panics
    ///
    /// When there is not exactly one.
    #[must_use]
    pub fn metric(&self, name: &str) -> &ExportedMetric {
        let matching: Vec<_> = self.metrics.iter().filter(|m| m.name == name).collect();
        assert_eq!(
            matching.len(),
            1,
            "expected exactly one metric named {name:?}; exported: {:?}",
            self.metrics.iter().map(|m| &m.name).collect::<Vec<_>>()
        );
        matching[0]
    }

    /// `(metric, key)` for every exported series carrying a key from
    /// [`keys::FORBIDDEN_METRIC_KEYS`].
    #[must_use]
    pub fn forbidden_metric_keys(&self) -> Vec<(String, String)> {
        let mut found: Vec<(String, String)> = self
            .metrics
            .iter()
            .flat_map(|metric| {
                metric.points.iter().flat_map(move |point| {
                    point
                        .attributes
                        .keys()
                        .filter(|key| keys::FORBIDDEN_METRIC_KEYS.contains(&key.as_str()))
                        .map(move |key| (metric.name.clone(), key.clone()))
                })
            })
            .collect();
        found.sort();
        found.dedup();
        found
    }

    /// `(metric, key)` for build identity found anywhere but
    /// [`keys::BUILD_INFO`]: a `revision` or `protocol` key, or any attribute
    /// whose value is the build's version (which is how the build's version
    /// is caught while the protocol-version label keeps the key `version`).
    #[must_use]
    pub fn misplaced_build_identity(&self) -> Vec<(String, String)> {
        let build_versions: Vec<&str> = self
            .metrics
            .iter()
            .filter(|metric| metric.name == keys::BUILD_INFO)
            .flat_map(|metric| &metric.points)
            .filter_map(|point| point.attributes.get("version").map(String::as_str))
            .collect();
        let mut found: Vec<(String, String)> = self
            .metrics
            .iter()
            .filter(|metric| metric.name != keys::BUILD_INFO)
            .flat_map(|metric| {
                let build_versions = &build_versions;
                metric.points.iter().flat_map(move |point| {
                    point
                        .attributes
                        .iter()
                        .filter(|(key, value)| {
                            keys::BUILD_IDENTITY[1..].contains(&key.as_str())
                                || build_versions.contains(&value.as_str())
                        })
                        .map(move |(key, _)| (metric.name.clone(), key.clone()))
                })
            })
            .collect();
        found.sort();
        found.dedup();
        found
    }

    /// The only span named `name`.
    ///
    /// # Panics
    ///
    /// When there is not exactly one.
    #[must_use]
    pub fn span(&self, name: &str) -> &ExportedSpan {
        let matching: Vec<_> = self.spans.iter().filter(|span| span.name == name).collect();
        assert_eq!(
            matching.len(),
            1,
            "expected exactly one span named {name:?}; exported: {:?}",
            self.span_names()
        );
        matching[0]
    }

    /// Every span named `name`.
    #[must_use]
    pub fn spans_named(&self, name: &str) -> Vec<&ExportedSpan> {
        self.spans.iter().filter(|span| span.name == name).collect()
    }

    #[must_use]
    pub fn span_names(&self) -> Vec<&str> {
        self.spans.iter().map(|span| span.name.as_str()).collect()
    }

    /// The first log record whose body is `body`.
    #[must_use]
    pub fn log(&self, body: &str) -> Option<&ExportedLog> {
        self.logs
            .iter()
            .find(|log| log.body.as_deref() == Some(body))
    }

    /// Exported span attribute keys that [`keys::is_known`] rejects.
    #[must_use]
    pub fn unknown_attribute_keys(&self) -> Vec<String> {
        let mut unknown: Vec<String> = self
            .spans
            .iter()
            .flat_map(|span| span.attributes.keys())
            .filter(|key| !keys::is_known(key))
            .cloned()
            .collect();
        unknown.sort();
        unknown.dedup();
        unknown
    }

    /// Every attribute value and log body exported, for a search for what
    /// must never be there.
    #[must_use]
    pub fn all_values(&self) -> Vec<&str> {
        self.spans
            .iter()
            .flat_map(|span| {
                span.attributes
                    .values()
                    .map(String::as_str)
                    .chain(std::iter::once(span.name.as_str()))
            })
            .chain(self.logs.iter().flat_map(|log| {
                log.attributes
                    .values()
                    .map(String::as_str)
                    .chain(log.body.as_deref())
            }))
            .collect()
    }
}
