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
    sync::{Arc, Mutex},
    time::Duration,
};

use opentelemetry::{
    logs::AnyValue,
    trace::{SpanId, SpanKind, Status},
};
use opentelemetry_sdk::{
    Resource,
    error::OTelSdkResult,
    logs::{BatchConfigBuilder as LogBatch, InMemoryLogExporter, LogBatch as Records, LogExporter},
    trace::{BatchConfigBuilder as SpanBatch, SpanData, SpanExporter},
};
use tracing::{Dispatch, dispatcher::DefaultGuard};
use tracing_subscriber::fmt::MakeWriter;

use crate::{Assembly, Exporters, Identity, InitError, OtelEnv, Telemetry, config, keys};

/// The build version every captured resource carries.
pub const VERSION: &str = "0.0.0-capture";

/// The variables of a deployment that exports logs and traces.
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
    ("OTEL_METRICS_EXPORTER", "none"),
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

/// The production assembly around recording exporters.
pub struct Capture {
    dispatch: Dispatch,
    telemetry: Telemetry,
    spans: SpanRecorder,
    logs: InMemoryLogExporter,
}

impl Capture {
    /// Telemetry on: logs and traces export, as on a deployment.
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
        let plan = config::validate(env).expect("the capture's variables are valid");
        let spans = SpanRecorder::default();
        let logs = InMemoryLogExporter::default();
        let (span_exporter, log_exporter) = (spans.clone(), LogRecorder(logs.clone()));
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
        }
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
        let exported = Exported { spans, logs };
        let unknown = exported.unknown_attribute_keys();
        assert!(
            unknown.is_empty(),
            "exported span attribute keys that are neither semantic-convention names nor \
             `{}`-prefixed: {unknown:?}",
            keys::PRODUCT_PREFIX
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

/// Everything a [`Capture`] exported.
#[derive(Debug, Clone)]
pub struct Exported {
    pub spans: Vec<ExportedSpan>,
    pub logs: Vec<ExportedLog>,
}

impl Exported {
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
