//! What actually leaves the process, asserted on what an exporter received —
//! the SDK's in-memory one, or the real OTLP one pointed at nothing — rather
//! than on configuration (`observability` skill §7).

use std::{
    io::Write,
    net::TcpListener,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use opentelemetry::{Key, logs::AnyValue};
use opentelemetry_sdk::{
    Resource,
    error::OTelSdkResult,
    logs::{BatchConfig, BatchConfigBuilder, InMemoryLogExporter, LogBatch, LogExporter},
    trace::{self, InMemorySpanExporter},
};
use sovereign_config_telemetry::{
    Assembly, Exporters, Identity, InitError, OtelEnv, Plan, SHUTDOWN_TIMEOUT, assemble,
    config::validate,
};
use tracing_subscriber::fmt::MakeWriter;

const VERSION: &str = "2.36.0-test";

/// The variables a deployment that exports logs only carries, with a stale
/// version planted in the attribute list to prove the build's wins. Spans
/// are covered by the server's tests, through `testing::Capture`.
const DEPLOYED: [(&str, &str); 7] = [
    ("OTEL_SERVICE_NAME", "sovereign-config"),
    (
        "OTEL_RESOURCE_ATTRIBUTES",
        "deployment.environment.name=dev,telemetry_source=otlp,service.version=0.0.1-stale",
    ),
    ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://monitor-alloy:4318"),
    ("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf"),
    ("OTEL_LOGS_EXPORTER", "otlp"),
    ("OTEL_METRICS_EXPORTER", "none"),
    ("OTEL_TRACES_EXPORTER", "none"),
];

/// Captures what the `fmt` layer writes, in place of stdout.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Captured {
    fn lines(&self) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Captured {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// The in-memory exporter clears what it holds when shut down; this keeps
/// it, so a test can read what shutdown flushed.
#[derive(Debug, Clone)]
struct Kept(InMemoryLogExporter);

impl LogExporter for Kept {
    async fn export(&self, batch: LogBatch<'_>) -> OTelSdkResult {
        self.0.export(batch).await
    }
    fn set_resource(&mut self, resource: &Resource) {
        self.0.set_resource(resource);
    }
}

/// A dispatch for one test that is never dropped.
///
/// Parallel tests each install their own scoped dispatch, and tracing-core
/// holds its dispatcher registry's read lock while it walks every live
/// dispatch to rebuild callsite interest. If that walk holds the *last*
/// reference to another test's finished subscriber, dropping it drops the
/// SDK providers, whose `Drop` logs through a callsite registering for the
/// first time — which takes the same read lock again behind a waiting
/// writer, and every test deadlocks. Keeping one reference forever means no
/// subscriber is ever dropped there. Production installs one global
/// subscriber for the life of the process, so it cannot meet this.
fn kept(subscriber: Box<dyn tracing::Subscriber + Send + Sync>) -> tracing::Dispatch {
    let dispatch = tracing::Dispatch::new(subscriber);
    std::mem::forget(dispatch.clone());
    dispatch
}

fn identity(hostname: Option<&str>) -> Identity {
    Identity {
        version: VERSION.to_owned(),
        hostname: hostname.map(str::to_owned),
    }
}

/// A batch delay long enough that nothing is exported until shutdown flushes
/// it, so a test that sees records has proved the flush.
fn slow_batches() -> BatchConfig {
    BatchConfigBuilder::default()
        .with_scheduled_delay(Duration::from_secs(3600))
        .build()
}

/// Exporters around `logs`, and a span exporter that must never be built
/// (these tests' deployment has `OTEL_TRACES_EXPORTER=none`).
fn exporters<L>(
    logs: impl FnOnce() -> Result<L, InitError>,
    log_batch: BatchConfig,
) -> Exporters<
    impl FnOnce() -> Result<L, InitError>,
    impl FnOnce() -> Result<InMemorySpanExporter, InitError>,
> {
    Exporters {
        logs,
        log_batch,
        spans: || -> Result<InMemorySpanExporter, InitError> {
            panic!("no span exporter may be built while traces are off")
        },
        span_batch: trace::BatchConfigBuilder::default().build(),
    }
}

fn assemble_with(
    plan: Plan,
    exporter: &InMemoryLogExporter,
    stdout: &Captured,
    hostname: Option<&str>,
) -> Assembly {
    let exporter = Kept(exporter.clone());
    assemble(
        plan,
        &identity(hostname),
        "info",
        stdout.clone(),
        exporters(move || Ok::<_, InitError>(exporter), slow_batches()),
    )
    .expect("assembly must succeed")
}

fn attribute(value: &opentelemetry::Value) -> String {
    value.to_string()
}

#[test]
fn every_exported_record_carries_the_resource_identity() {
    let exporter = InMemoryLogExporter::default();
    let stdout = Captured::default();
    let plan = validate(&OtelEnv::from_pairs(DEPLOYED)).unwrap();
    let Assembly {
        subscriber,
        mut telemetry,
    } = assemble_with(plan, &exporter, &stdout, Some("sovereign-config-dev"));

    tracing::dispatcher::with_default(&kept(subscriber), || {
        telemetry.announce();
        tracing::info!(answer = 42, "first");
        tracing::warn!("second");
        telemetry.shutdown();
    });

    let records = exporter.get_emitted_logs().unwrap();
    assert_eq!(records.len(), 3, "the announcement and both events");
    for record in &records {
        let resource = &record.resource;
        let get = |key: &'static str| {
            resource
                .get(&Key::from_static_str(key))
                .map(|value| attribute(&value))
        };
        assert_eq!(get("service.name").as_deref(), Some("sovereign-config"));
        assert_eq!(get("deployment.environment.name").as_deref(), Some("dev"));
        assert_eq!(get("telemetry_source").as_deref(), Some("otlp"));
        assert_eq!(
            get("service.version").as_deref(),
            Some(VERSION),
            "the build's version must win over OTEL_RESOURCE_ATTRIBUTES"
        );
        assert!(get("service.instance.id").is_some());
    }
    // The records are structured, not preformatted lines.
    let first = records
        .iter()
        .find(|r| r.record.body() == Some(&AnyValue::from("first")))
        .expect("the first event was exported");
    assert!(
        first
            .record
            .attributes_iter()
            .any(|(key, value)| key.as_str() == "answer" && *value == AnyValue::Int(42))
    );
    // stdout still gets every line: `docker logs` keeps working.
    assert_eq!(stdout.lines().len(), 3, "{:?}", stdout.lines());
}

#[test]
fn the_instance_id_is_identical_across_two_inits_on_one_hostname() {
    let ids: Vec<String> = (0..2)
        .map(|_| {
            let exporter = InMemoryLogExporter::default();
            let plan = validate(&OtelEnv::from_pairs(DEPLOYED)).unwrap();
            let Assembly {
                subscriber,
                mut telemetry,
            } = assemble_with(plan, &exporter, &Captured::default(), Some("host-a"));
            tracing::dispatcher::with_default(&kept(subscriber), || {
                tracing::info!("one");
                telemetry.shutdown();
            });
            let records = exporter.get_emitted_logs().unwrap();
            attribute(
                &records[0]
                    .resource
                    .get(&Key::from_static_str("service.instance.id"))
                    .expect("an instance id"),
            )
        })
        .collect();
    assert_eq!(ids[0], ids[1]);
}

#[test]
fn off_builds_no_provider_and_says_so_once() {
    for plan in [
        validate(&OtelEnv::default()).unwrap(),
        validate(&OtelEnv::from_pairs(
            DEPLOYED.into_iter().chain([("OTEL_SDK_DISABLED", "true")]),
        ))
        .unwrap(),
    ] {
        let exporter = InMemoryLogExporter::default();
        let stdout = Captured::default();
        let built = Arc::new(Mutex::new(false));
        let flag = Arc::clone(&built);
        let Assembly {
            subscriber,
            mut telemetry,
        } = assemble(
            plan,
            &identity(Some("host")),
            "",
            stdout.clone(),
            exporters(
                move || {
                    *flag.lock().unwrap() = true;
                    Ok::<_, InitError>(exporter)
                },
                slow_batches(),
            ),
        )
        .unwrap();

        assert!(!telemetry.is_exporting());
        assert!(!*built.lock().unwrap(), "no exporter may be built when off");
        tracing::dispatcher::with_default(&kept(subscriber), || {
            telemetry.announce();
            tracing::info!("served");
            telemetry.shutdown();
        });
        let lines = stdout.lines();
        assert_eq!(
            lines
                .iter()
                .filter(|line| line.contains("telemetry off"))
                .count(),
            1,
            "{lines:?}"
        );
        assert!(lines.iter().any(|line| line.contains("served")));
    }
}

#[test]
fn shutdown_flushes_pending_records_within_its_timeout() {
    let exporter = InMemoryLogExporter::default();
    let plan = validate(&OtelEnv::from_pairs(DEPLOYED)).unwrap();
    let Assembly {
        subscriber,
        mut telemetry,
    } = assemble_with(plan, &exporter, &Captured::default(), None);

    tracing::dispatcher::with_default(&kept(subscriber), || {
        for n in 0..100 {
            tracing::info!(n, "pending");
        }
    });
    assert!(
        exporter.get_emitted_logs().unwrap().is_empty(),
        "nothing is exported before the hour-long batch delay"
    );
    let started = Instant::now();
    telemetry.shutdown();
    assert!(started.elapsed() < SHUTDOWN_TIMEOUT);
    assert_eq!(exporter.get_emitted_logs().unwrap().len(), 100);
}

#[test]
fn the_sdk_s_own_diagnostics_never_reach_the_log_bridge() {
    let exporter = InMemoryLogExporter::default();
    let stdout = Captured::default();
    let plan = validate(&OtelEnv::from_pairs(DEPLOYED)).unwrap();
    let Assembly {
        subscriber,
        mut telemetry,
    } = assemble_with(plan, &exporter, &stdout, None);

    tracing::dispatcher::with_default(&kept(subscriber), || {
        tracing::warn!(target: "opentelemetry_sdk", "export failed");
        tracing::debug!(target: "opentelemetry_otlp", url = "http://collector", "detail");
        tracing::warn!(target: "reqwest::blocking", "connection refused");
        tracing::warn!(target: "hyper_util::client::legacy::connect::http", "dial failed");
        // The server's own gRPC stack is not the exporter's, and is bridged.
        tracing::warn!(target: "tonic::transport::server", "h2c protocol error");
        telemetry.shutdown();
    });

    let bridged_targets: Vec<String> = exporter
        .get_emitted_logs()
        .unwrap()
        .iter()
        .map(|log| {
            log.record
                .target()
                .map(ToString::to_string)
                .unwrap_or_default()
        })
        .collect();
    assert_eq!(bridged_targets, ["tonic::transport::server"]);
    let lines = stdout.lines();
    // The warning is the failure signal on stdout; the debug detail, which
    // names the endpoint, is not written at all.
    assert!(lines.iter().any(|line| line.contains("export failed")));
    assert!(!lines.iter().any(|line| line.contains("http://collector")));
}

#[test]
fn an_unreachable_collector_costs_nothing_and_shutdown_stays_bounded() {
    use opentelemetry_otlp::{Protocol, WithExportConfig};

    // A port that was free a moment ago: nothing listens on it.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let endpoint = format!("http://127.0.0.1:{port}/v1/logs");
    let plan = validate(&OtelEnv::from_pairs(DEPLOYED)).unwrap();
    let stdout = Captured::default();
    let Assembly {
        subscriber,
        mut telemetry,
    } = assemble(
        plan,
        &identity(Some("host")),
        "info",
        stdout.clone(),
        exporters(
            move || {
                opentelemetry_otlp::LogExporter::builder()
                    .with_http()
                    .with_protocol(Protocol::HttpBinary)
                    .with_endpoint(endpoint)
                    .with_timeout(Duration::from_secs(2))
                    .build()
                    .map_err(|_| InitError::Exporter("log"))
            },
            BatchConfigBuilder::default()
                .with_scheduled_delay(Duration::from_millis(50))
                .build(),
        ),
    )
    .unwrap();

    let started = Instant::now();
    tracing::dispatcher::with_default(&kept(subscriber), || {
        for n in 0..50 {
            tracing::info!(n, "served while the collector is down");
        }
        // Emitting never waits on the export.
        assert!(started.elapsed() < Duration::from_secs(1));
        std::thread::sleep(Duration::from_millis(300));
        telemetry.shutdown();
    });
    assert!(started.elapsed() < SHUTDOWN_TIMEOUT + Duration::from_secs(1));
    // The SDK reports the failure from its own batch thread, which sees the
    // global subscriber rather than this test's scoped one, so what reaches
    // stdout in production is asserted by the server's process tests. Here:
    // nothing written on this thread names the endpoint.
    let lines = stdout.lines();
    assert!(
        !lines
            .iter()
            .any(|line| line.contains(&format!("127.0.0.1:{port}"))),
        "{lines:?}"
    );
}

/// A span's attributes are the span's: stdout lines carry no span fields,
/// so `user.*` recorded on a request span never reaches `docker logs`.
#[test]
fn stdout_lines_carry_no_span_fields() {
    let exporter = InMemoryLogExporter::default();
    let stdout = Captured::default();
    let plan = validate(&OtelEnv::from_pairs(DEPLOYED)).unwrap();
    let Assembly {
        subscriber,
        mut telemetry,
    } = assemble_with(plan, &exporter, &stdout, None);

    tracing::dispatcher::with_default(&kept(subscriber), || {
        let span = tracing::info_span!(
            target: "sovereign_config_server::spans",
            "rpc",
            user.id = "subject-sentinel",
            user.name = "name-sentinel",
        );
        let _entered = span.enter();
        tracing::info!("inside the span");
        telemetry.shutdown();
    });

    let lines = stdout.lines();
    let line = lines
        .iter()
        .find(|line| line.contains("inside the span"))
        .expect("the event reached stdout");
    for absent in ["subject-sentinel", "name-sentinel", "\"span\"", "\"spans\""] {
        assert!(!line.contains(absent), "{absent} on stdout: {line}");
    }
    // Nor on the exported record: the bridge copies no span attributes.
    for record in exporter.get_emitted_logs().unwrap() {
        assert!(
            !record
                .record
                .attributes_iter()
                .any(|(key, _)| key.as_str().starts_with("user.")),
        );
    }
}

/// A collector that accepts connections and never answers — the worst case
/// for a flush — costs one shutdown bound, not one per signal: both signals
/// flush at once, inside Docker's default stop grace.
#[test]
fn a_hung_collector_costs_one_shutdown_bound_for_both_signals() {
    use opentelemetry_otlp::{Protocol, WithExportConfig};

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let held = Arc::new(Mutex::new(Vec::new()));
    let holder = Arc::clone(&held);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            holder.lock().unwrap().push(stream);
        }
    });
    let plan = validate(&OtelEnv::from_pairs(
        DEPLOYED
            .into_iter()
            .chain([("OTEL_TRACES_EXPORTER", "otlp")]),
    ))
    .unwrap();
    let Assembly {
        subscriber,
        mut telemetry,
    } = assemble(
        plan,
        &identity(Some("host")),
        "info",
        Captured::default(),
        Exporters {
            logs: move || {
                opentelemetry_otlp::LogExporter::builder()
                    .with_http()
                    .with_protocol(Protocol::HttpBinary)
                    .with_endpoint(format!("http://{address}/v1/logs"))
                    .with_timeout(Duration::from_secs(30))
                    .build()
                    .map_err(|_| InitError::Exporter("log"))
            },
            log_batch: slow_batches(),
            spans: move || {
                opentelemetry_otlp::SpanExporter::builder()
                    .with_http()
                    .with_protocol(Protocol::HttpBinary)
                    .with_endpoint(format!("http://{address}/v1/traces"))
                    .with_timeout(Duration::from_secs(30))
                    .build()
                    .map_err(|_| InitError::Exporter("span"))
            },
            span_batch: trace::BatchConfigBuilder::default()
                .with_scheduled_delay(Duration::from_secs(3600))
                .build(),
        },
    )
    .unwrap();

    tracing::dispatcher::with_default(&kept(subscriber), || {
        let span = tracing::info_span!(target: "sovereign_config_test", "work");
        let _entered = span.enter();
        tracing::info!("pending");
    });
    let started = Instant::now();
    telemetry.shutdown();
    let elapsed = started.elapsed();
    assert!(
        elapsed < SHUTDOWN_TIMEOUT + Duration::from_millis(1500),
        "shutdown took {elapsed:?}"
    );
}
