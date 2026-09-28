//! The server's telemetry module — the only crate in the workspace that names
//! an OpenTelemetry SDK or exporter type (`observability` skill §5; the
//! allowlist test in `tests/allowlist.rs` enforces it).
//!
//! Product code logs through `tracing` and never knows this crate exists
//! beyond two calls in `main`: [`init`] before anything else, and
//! [`Telemetry::shutdown`] once the server has stopped.
//!
//! Three states, chosen by the `OTEL_*` variables alone ([`config`]):
//!
//! - **none set** — JSON logs to stdout and the W3C propagator, nothing else:
//!   no provider, no exporter, no background thread. `cargo run`, `cargo test`
//!   and CI all run this way.
//! - **`OTEL_SDK_DISABLED=true`** — the same, for a deployment that carries
//!   the variables and wants them silent.
//! - **anything else** — the whole set is validated first, then log records
//!   leave over OTLP (`http/protobuf`) to the one configured collector, as
//!   well as reaching stdout.
//!
//! Spans (#420) and metrics (#421) will be added here, as further layers and
//! providers on the same [`resource`]; nothing outside this crate changes when
//! they are.

pub mod config;
pub mod resource;

use std::time::Duration;

use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_sdk::{
    logs::{BatchConfig, BatchConfigBuilder, BatchLogProcessor, LogExporter, SdkLoggerProvider},
    propagation::TraceContextPropagator,
};
use tracing::{Subscriber, info, warn};
use tracing_subscriber::{
    EnvFilter, Layer, fmt::MakeWriter, layer::SubscriberExt, registry::Registry,
};

pub use config::{ConfigError, Off, OtelEnv, Plan};

/// How long [`Telemetry::shutdown`] may take to flush. It bounds the wait,
/// not the exporter: records still unsent when it passes are lost, which is
/// preferable to a process that will not stop.
pub const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// The target of this module's own lifecycle messages that are written after
/// the log provider has gone, and so must not reach the log bridge.
const SHUTDOWN_TARGET: &str = "sovereign_config_telemetry::shutdown";

/// Targets kept out of the log bridge, whatever `RUST_LOG` says, so that
/// exporting can never produce a record that itself needs exporting: the SDK's
/// own diagnostics (every `opentelemetry*` crate logs under its crate name)
/// and the HTTP client the exporter sends through (`reqwest` over
/// `hyper_util`'s client, which also names the host it dials). These reach
/// stdout only — the server's own outbound `reqwest` calls included, a loss
/// recorded in `AGENTS.md`. The server's gRPC stack (`tonic`, `h2`, `hyper`)
/// is deliberately bridged: its transport errors are worth exporting.
/// `hyper`'s shared HTTP/1 codec also serves the exporter, but logs only at
/// `trace`, a deliberate debugging level.
const NEVER_BRIDGED: [&str; 4] = [
    "opentelemetry",
    "reqwest",
    "hyper_util::client",
    SHUTDOWN_TARGET,
];

/// Why telemetry could not start.
#[derive(Debug, thiserror::Error)]
pub enum InitError {
    /// Not a `#[source]`: the message already carries it, and `anyhow` would
    /// print it a second time as the cause.
    #[error("invalid telemetry configuration: {0}")]
    Config(ConfigError),
    /// The exporter's own message is deliberately not carried: the SDK quotes
    /// the endpoint in it.
    #[error("the OTLP log exporter could not be built")]
    Exporter,
    #[error("a global tracing subscriber is already installed")]
    AlreadyInstalled,
}

impl From<ConfigError> for InitError {
    fn from(error: ConfigError) -> Self {
        Self::Config(error)
    }
}

/// The facts about this process that are not the deployment's to state.
#[derive(Debug, Clone)]
pub struct Identity {
    /// `service.version`: the build's release, never overridable.
    pub version: String,
    /// The source of `service.instance.id`.
    pub hostname: Option<String>,
}

/// The running telemetry. Hold it for the life of the process and call
/// [`Telemetry::shutdown`] inside the async runtime once serving stops, so the
/// last records — the ones most worth having — are flushed. Dropping it
/// shuts down too, with the same bound, for the error paths that return early.
#[derive(Debug)]
pub struct Telemetry {
    plan: Plan,
    logs: Option<SdkLoggerProvider>,
}

impl Telemetry {
    /// Whether anything leaves the process. `false` means no provider, no
    /// exporter and no background thread exist.
    #[must_use]
    pub fn is_exporting(&self) -> bool {
        self.logs.is_some()
    }

    /// Says once, at startup, which state telemetry is in — so "why are there
    /// no logs in Loki" has an answer in `docker logs`. Never names the
    /// endpoint or any other value.
    pub fn announce(&self) {
        match &self.plan {
            Plan::Off(Off::NoVariables) => {
                info!("telemetry off: no OTEL_* variable is set; logging to stdout only");
            }
            Plan::Off(Off::Disabled) => {
                info!("telemetry off: OTEL_SDK_DISABLED is true; logging to stdout only");
            }
            Plan::Off(Off::NothingExported) => {
                info!("telemetry off: every signal this server exports is set to none");
            }
            Plan::ExportLogs { .. } => info!(
                signals = "logs",
                protocol = config::HTTP_PROTOBUF,
                "telemetry on: exporting over OTLP to the configured collector"
            ),
        }
    }

    /// Flushes and stops every provider, waiting at most [`SHUTDOWN_TIMEOUT`].
    /// Idempotent. A failure is reported on stdout only: the provider it would
    /// be exported through is the thing that just stopped.
    pub fn shutdown(&mut self) {
        if let Some(logs) = self.logs.take()
            && let Err(error) = logs.shutdown_with_timeout(SHUTDOWN_TIMEOUT)
        {
            warn!(target: SHUTDOWN_TARGET, error = %error, "telemetry did not flush cleanly");
        }
    }
}

impl Drop for Telemetry {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// A subscriber and the telemetry behind it, not yet installed. [`init`]
/// installs it globally; tests install it for a scope.
pub struct Assembly {
    pub subscriber: Box<dyn Subscriber + Send + Sync>,
    pub telemetry: Telemetry,
}

/// Builds the layers for `plan`. The exporter and batch settings are
/// parameters so that tests assemble exactly what production does around an
/// in-memory exporter; `exporter` is called only when logs export.
///
/// Layers:
/// - `fmt`, JSON to `writer`, filtered by `log_filter` (`RUST_LOG`), with the
///   SDK's own targets held at `warn` — that is where a failing export shows,
///   once per batch interval (skill §6);
/// - the log bridge, when exporting, filtered by the same `log_filter` minus
///   [`NEVER_BRIDGED`]. It copies no span attributes onto records (skill §3).
///
/// # Errors
///
/// The exporter could not be built.
pub fn assemble<E, W>(
    plan: Plan,
    identity: &Identity,
    log_filter: &str,
    writer: W,
    exporter: impl FnOnce() -> Result<E, InitError>,
    batch: BatchConfig,
) -> Result<Assembly, InitError>
where
    E: LogExporter + 'static,
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    let stdout = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(writer)
        .with_filter(stdout_filter(log_filter));

    let logs = match &plan {
        Plan::ExportLogs { attributes } => Some(
            SdkLoggerProvider::builder()
                .with_resource(resource::build(
                    attributes,
                    &identity.version,
                    identity.hostname.as_deref(),
                ))
                .with_log_processor(
                    BatchLogProcessor::builder(exporter()?)
                        .with_batch_config(batch)
                        .build(),
                )
                .build(),
        ),
        Plan::Off(_) => None,
    };
    let bridge = logs.as_ref().map(|provider| {
        OpenTelemetryTracingBridge::new(provider).with_filter(bridge_filter(log_filter))
    });

    let subscriber = Registry::default().with(stdout).with(bridge);
    Ok(Assembly {
        subscriber: Box::new(subscriber),
        telemetry: Telemetry { plan, logs },
    })
}

/// `RUST_LOG`, or `info` when it is unset or does not parse.
fn base_filter(log_filter: &str) -> EnvFilter {
    EnvFilter::try_new(log_filter)
        .ok()
        .filter(|_| !log_filter.trim().is_empty())
        .unwrap_or_else(|| EnvFilter::new("info"))
}

fn stdout_filter(log_filter: &str) -> EnvFilter {
    base_filter(log_filter).add_directive(
        "opentelemetry=warn"
            .parse()
            .expect("a static directive must parse"),
    )
}

fn bridge_filter(log_filter: &str) -> EnvFilter {
    NEVER_BRIDGED
        .iter()
        .fold(base_filter(log_filter), |filter, target| {
            filter.add_directive(
                format!("{target}=off")
                    .parse()
                    .expect("a static directive must parse"),
            )
        })
}

/// Validates the process's `OTEL_*` variables, builds what they ask for,
/// installs the global subscriber and the W3C propagator, and announces the
/// state once. Call it first, before anything logs.
///
/// # Errors
///
/// The variables are invalid (the message names the variable, never its
/// value), the exporter could not be built, or a subscriber is already set.
pub fn init(version: &str) -> Result<Telemetry, InitError> {
    let plan = config::validate(&OtelEnv::from_process()?)?;
    let identity = Identity {
        version: version.to_owned(),
        hostname: resource::hostname(),
    };
    let log_filter = std::env::var("RUST_LOG").unwrap_or_default();
    let assembly = assemble(
        plan,
        &identity,
        &log_filter,
        std::io::stdout,
        otlp_log_exporter,
        // Reads the OTEL_BLRP_* variables, which config validated.
        BatchConfigBuilder::default().build(),
    )?;

    // Propagation runs whether or not anything exports: a silent service
    // must still pass a trace through (skill §2).
    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
    tracing::subscriber::set_global_default(assembly.subscriber)
        .map_err(|_| InitError::AlreadyInstalled)?;
    assembly.telemetry.announce();
    Ok(assembly.telemetry)
}

/// The OTLP log exporter over `http/protobuf`. The endpoint, headers and
/// timeout are read by the SDK from the `OTEL_EXPORTER_OTLP_*` variables that
/// [`config::validate`] has already checked.
fn otlp_log_exporter() -> Result<opentelemetry_otlp::LogExporter, InitError> {
    use opentelemetry_otlp::{Protocol, WithExportConfig};

    opentelemetry_otlp::LogExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .build()
        .map_err(|_| InitError::Exporter)
}
