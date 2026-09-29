//! The `OTEL_*` variables, validated as one set before anything starts.
//!
//! This is the whole configuration interface (`observability` skill §2): the
//! product has no telemetry section of its own. The SDK reads some variables
//! and silently ignores the rest, so this module reads the ones the SDK does
//! not (`OTEL_SDK_DISABLED`, the three `*_EXPORTER`s, the protocol, the
//! propagators, the endpoint-absent check) and checks the shape of the ones it
//! does, so a value the SDK would have shrugged at fails the deploy instead.
//!
//! Every error names the variable and describes the expected shape. None of
//! them quotes the value: `OTEL_EXPORTER_OTLP_HEADERS` can carry a credential,
//! and a message that echoes one variable is a message that will one day echo
//! that one.

use std::collections::BTreeMap;

use url::Url;

pub const OTEL_SDK_DISABLED: &str = "OTEL_SDK_DISABLED";
pub const OTEL_SERVICE_NAME: &str = "OTEL_SERVICE_NAME";
pub const OTEL_RESOURCE_ATTRIBUTES: &str = "OTEL_RESOURCE_ATTRIBUTES";
pub const OTEL_EXPORTER_OTLP_ENDPOINT: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";
pub const OTEL_EXPORTER_OTLP_PROTOCOL: &str = "OTEL_EXPORTER_OTLP_PROTOCOL";
pub const OTEL_PROPAGATORS: &str = "OTEL_PROPAGATORS";
pub const OTEL_TRACES_SAMPLER: &str = "OTEL_TRACES_SAMPLER";
pub const OTEL_TRACES_SAMPLER_ARG: &str = "OTEL_TRACES_SAMPLER_ARG";

/// The only protocol this build carries. `grpc` is a valid contract value,
/// but the tonic transport is not compiled in (see the workspace
/// `Cargo.toml`), so a deployment that asks for it fails loudly rather than
/// silently getting HTTP.
pub const HTTP_PROTOBUF: &str = "http/protobuf";

/// The samplers a deployment may choose. `traceidratio` is left out on
/// purpose: it decides from the trace id alone, and an inbound `traceparent`
/// lets the caller pick that id — so it would let any caller keep its own
/// requests, and the `user.*` they carry, out of the trace store. The
/// `parentbased_*` samplers are safe because the transport adopts an inbound
/// parent as sampled (`crate::context::adopt_parent`).
const SAMPLERS: [&str; 5] = [
    "always_on",
    "always_off",
    "parentbased_always_on",
    "parentbased_always_off",
    "parentbased_traceidratio",
];

/// Variables the SDK reads as whole numbers of milliseconds or items. The SDK
/// ignores a malformed one and keeps its default; this module refuses it.
const WHOLE_NUMBERS: [&str; 14] = [
    "OTEL_BSP_MAX_QUEUE_SIZE",
    "OTEL_BSP_SCHEDULE_DELAY",
    "OTEL_BSP_EXPORT_TIMEOUT",
    "OTEL_BSP_MAX_EXPORT_BATCH_SIZE",
    "OTEL_BLRP_MAX_QUEUE_SIZE",
    "OTEL_BLRP_SCHEDULE_DELAY",
    "OTEL_BLRP_EXPORT_TIMEOUT",
    "OTEL_BLRP_MAX_EXPORT_BATCH_SIZE",
    "OTEL_METRIC_EXPORT_INTERVAL",
    "OTEL_METRIC_EXPORT_TIMEOUT",
    "OTEL_EXPORTER_OTLP_TIMEOUT",
    "OTEL_EXPORTER_OTLP_TRACES_TIMEOUT",
    "OTEL_EXPORTER_OTLP_METRICS_TIMEOUT",
    "OTEL_EXPORTER_OTLP_LOGS_TIMEOUT",
];

/// A telemetry variable that is present but unusable. Displays as the
/// variable's name and the shape it must have — never its value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{variable} {problem}")]
pub struct ConfigError {
    pub variable: String,
    pub problem: &'static str,
}

impl ConfigError {
    fn new(variable: impl Into<String>, problem: &'static str) -> Self {
        Self {
            variable: variable.into(),
            problem,
        }
    }
}

/// A snapshot of every `OTEL_*` variable, taken once so that what is validated
/// is exactly what is used.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OtelEnv(BTreeMap<String, String>);

impl OtelEnv {
    /// The process environment's `OTEL_*` variables.
    ///
    /// # Errors
    ///
    /// A variable whose value is not UTF-8.
    pub fn from_process() -> Result<Self, ConfigError> {
        let mut variables = BTreeMap::new();
        for (name, value) in std::env::vars_os() {
            let name = name.to_string_lossy().into_owned();
            if !name.starts_with("OTEL_") {
                continue;
            }
            let value = value
                .into_string()
                .map_err(|_| ConfigError::new(name.clone(), "is not valid UTF-8"))?;
            // The spec treats an empty value as unset, so a variable that is
            // present but empty does not switch telemetry on.
            if !value.is_empty() {
                variables.insert(name, value);
            }
        }
        Ok(Self(variables))
    }

    /// A snapshot from explicit pairs; anything not named `OTEL_*` is ignored.
    #[must_use]
    pub fn from_pairs<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        Self(
            pairs
                .into_iter()
                .filter(|(name, value)| name.starts_with("OTEL_") && !value.is_empty())
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
        )
    }

    /// The value of `name`, treating an empty value as unset, as the spec does.
    fn get(&self, name: &str) -> Option<&str> {
        self.0
            .get(name)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    }
}

/// One telemetry signal, as its `OTEL_<SIGNAL>_EXPORTER` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    Traces,
    Metrics,
    Logs,
}

impl Signal {
    pub const ALL: [Self; 3] = [Self::Traces, Self::Metrics, Self::Logs];

    fn exporter_variable(self) -> &'static str {
        match self {
            Self::Traces => "OTEL_TRACES_EXPORTER",
            Self::Metrics => "OTEL_METRICS_EXPORTER",
            Self::Logs => "OTEL_LOGS_EXPORTER",
        }
    }

    fn endpoint_variable(self) -> &'static str {
        match self {
            Self::Traces => "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
            Self::Metrics => "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
            Self::Logs => "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
        }
    }

    fn protocol_variable(self) -> &'static str {
        match self {
            Self::Traces => "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
            Self::Metrics => "OTEL_EXPORTER_OTLP_METRICS_PROTOCOL",
            Self::Logs => "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL",
        }
    }
}

/// Why telemetry is off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Off {
    /// No `OTEL_*` variable at all: a laptop, a test, CI.
    NoVariables,
    /// `OTEL_SDK_DISABLED=true`: a deployment that carries the variables and
    /// wants them silent.
    Disabled,
    /// Validated, but every signal is set to `none`.
    NothingExported,
}

/// Which signals are exported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // one flag per signal, named as the variables name them
pub struct Exported {
    pub logs: bool,
    pub metrics: bool,
    pub traces: bool,
}

impl Exported {
    /// Nothing exported.
    pub const NONE: Self = Self {
        logs: false,
        metrics: false,
        traces: false,
    };

    /// Whether any signal is exported.
    #[must_use]
    pub const fn any(self) -> bool {
        self.logs || self.metrics || self.traces
    }

    /// The exported signals, as the startup line names them.
    #[must_use]
    pub fn names(self) -> String {
        [
            (self.logs, "logs"),
            (self.metrics, "metrics"),
            (self.traces, "traces"),
        ]
        .into_iter()
        .filter_map(|(on, name)| on.then_some(name))
        .collect::<Vec<_>>()
        .join(",")
    }
}

/// What the validated set asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    Off(Off),
    /// Export the named signals over OTLP, identified by these resource
    /// attributes (as the deployment stated them; the build's own facts are
    /// added by [`crate::resource`]). At least one signal is on.
    Export {
        attributes: Vec<(String, String)>,
        signals: Exported,
    },
}

/// Validates the whole set and says what to build.
///
/// # Errors
///
/// The first variable, in a fixed order, that is present and unusable; or a
/// required variable that is absent while telemetry is on.
pub fn validate(env: &OtelEnv) -> Result<Plan, ConfigError> {
    if env.0.is_empty() {
        return Ok(Plan::Off(Off::NoVariables));
    }
    if sdk_disabled(env)? {
        return Ok(Plan::Off(Off::Disabled));
    }

    let mut exporting = Vec::new();
    for signal in Signal::ALL {
        if exports(env, signal)? {
            exporting.push(signal);
        }
    }
    validate_protocols(env)?;
    validate_endpoints(env, &exporting)?;
    validate_propagators(env)?;
    validate_sampler(env)?;
    for name in WHOLE_NUMBERS {
        if let Some(value) = env.get(name)
            && value.trim().parse::<u64>().is_err()
        {
            return Err(ConfigError::new(name, "must be a whole number"));
        }
    }
    if exporting.is_empty() {
        return Ok(Plan::Off(Off::NothingExported));
    }
    // Identity is required of anything that exports, whichever signal it is.
    let attributes = resource_attributes(env)?;

    Ok(Plan::Export {
        attributes,
        signals: Exported {
            logs: exporting.contains(&Signal::Logs),
            metrics: exporting.contains(&Signal::Metrics),
            traces: exporting.contains(&Signal::Traces),
        },
    })
}

fn sdk_disabled(env: &OtelEnv) -> Result<bool, ConfigError> {
    match env.get(OTEL_SDK_DISABLED).map(str::trim) {
        None => Ok(false),
        Some(value) if value.eq_ignore_ascii_case("true") => Ok(true),
        Some(value) if value.eq_ignore_ascii_case("false") => Ok(false),
        Some(_) => Err(ConfigError::new(OTEL_SDK_DISABLED, "must be true or false")),
    }
}

fn exports(env: &OtelEnv, signal: Signal) -> Result<bool, ConfigError> {
    // Unset means the spec's default, `otlp`.
    match env.get(signal.exporter_variable()).map(str::trim) {
        None | Some("otlp") => Ok(true),
        Some("none") => Ok(false),
        Some(_) => Err(ConfigError::new(
            signal.exporter_variable(),
            "must be otlp or none",
        )),
    }
}

fn validate_protocols(env: &OtelEnv) -> Result<(), ConfigError> {
    let names = std::iter::once(OTEL_EXPORTER_OTLP_PROTOCOL)
        .chain(Signal::ALL.map(Signal::protocol_variable));
    for name in names {
        match env.get(name).map(str::trim) {
            None | Some(HTTP_PROTOBUF) => {}
            Some("grpc") => {
                return Err(ConfigError::new(
                    name,
                    "selects grpc, which this server is not built with; use http/protobuf",
                ));
            }
            Some(_) => return Err(ConfigError::new(name, "must be http/protobuf or grpc")),
        }
    }
    Ok(())
}

fn validate_endpoints(env: &OtelEnv, exporting: &[Signal]) -> Result<(), ConfigError> {
    let names = std::iter::once(OTEL_EXPORTER_OTLP_ENDPOINT)
        .chain(Signal::ALL.map(Signal::endpoint_variable));
    for name in names {
        if let Some(value) = env.get(name)
            && !is_collector_url(value)
        {
            return Err(ConfigError::new(
                name,
                "must be an absolute http or https URL",
            ));
        }
    }
    // Never the SDK's localhost default: that is a compiled-in address by
    // another name, and a deployment that forgot its endpoint should fail
    // here rather than export into nothing.
    for signal in exporting {
        if env.get(OTEL_EXPORTER_OTLP_ENDPOINT).is_none()
            && env.get(signal.endpoint_variable()).is_none()
        {
            return Err(ConfigError::new(
                OTEL_EXPORTER_OTLP_ENDPOINT,
                "must be set while any signal exports over OTLP (set that signal's OTEL_*_EXPORTER to none to silence it)",
            ));
        }
    }
    Ok(())
}

fn is_collector_url(value: &str) -> bool {
    Url::parse(value.trim())
        .is_ok_and(|url| matches!(url.scheme(), "http" | "https") && url.host().is_some())
}

fn validate_propagators(env: &OtelEnv) -> Result<(), ConfigError> {
    match env.get(OTEL_PROPAGATORS).map(str::trim) {
        None | Some("tracecontext") => Ok(()),
        Some(_) => Err(ConfigError::new(
            OTEL_PROPAGATORS,
            "must be tracecontext (W3C trace context is the only propagator)",
        )),
    }
}

fn validate_sampler(env: &OtelEnv) -> Result<(), ConfigError> {
    if let Some(sampler) = env.get(OTEL_TRACES_SAMPLER)
        && !SAMPLERS.contains(&sampler.trim())
    {
        return Err(ConfigError::new(
            OTEL_TRACES_SAMPLER,
            "must be always_on, always_off or a parentbased_* sampler (traceidratio lets a caller choose, through its trace id, whether its request is recorded)",
        ));
    }
    if let Some(argument) = env.get(OTEL_TRACES_SAMPLER_ARG)
        && !argument
            .trim()
            .parse::<f64>()
            .is_ok_and(|ratio| (0.0..=1.0).contains(&ratio))
    {
        return Err(ConfigError::new(
            OTEL_TRACES_SAMPLER_ARG,
            "must be a number from 0 to 1",
        ));
    }
    Ok(())
}

/// `OTEL_RESOURCE_ATTRIBUTES` parsed as the SDK's own detector parses it
/// (comma-separated `key=value`, each side trimmed), then `OTEL_SERVICE_NAME`
/// applied over `service.name` as the spec orders. Unlike the SDK, which
/// drops a malformed entry, a malformed entry is an error.
fn resource_attributes(env: &OtelEnv) -> Result<Vec<(String, String)>, ConfigError> {
    use opentelemetry_semantic_conventions::resource::{DEPLOYMENT_ENVIRONMENT_NAME, SERVICE_NAME};

    let mut attributes = BTreeMap::new();
    if let Some(list) = env.get(OTEL_RESOURCE_ATTRIBUTES) {
        for entry in list.split_terminator(',') {
            let (key, value) = entry
                .split_once('=')
                .map(|(key, value)| (key.trim(), value.trim()))
                .filter(|(key, _)| !key.is_empty())
                .ok_or_else(|| {
                    ConfigError::new(
                        OTEL_RESOURCE_ATTRIBUTES,
                        "must be a comma-separated list of key=value pairs",
                    )
                })?;
            attributes.insert(key.to_owned(), value.to_owned());
        }
    }
    if let Some(name) = env.get(OTEL_SERVICE_NAME) {
        attributes.insert(SERVICE_NAME.to_owned(), name.trim().to_owned());
    }

    if attributes.get(SERVICE_NAME).is_none_or(String::is_empty) {
        return Err(ConfigError::new(
            OTEL_SERVICE_NAME,
            "must be set while telemetry is on",
        ));
    }
    if attributes
        .get(DEPLOYMENT_ENVIRONMENT_NAME)
        .is_none_or(String::is_empty)
    {
        return Err(ConfigError::new(
            OTEL_RESOURCE_ATTRIBUTES,
            "must carry deployment.environment.name while telemetry is on",
        ));
    }
    Ok(attributes.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The set a deployment of this server actually carries.
    const DEPLOYED: [(&str, &str); 7] = [
        ("OTEL_SERVICE_NAME", "sovereign-config"),
        (
            "OTEL_RESOURCE_ATTRIBUTES",
            "deployment.environment.name=dev,telemetry_source=otlp",
        ),
        ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://monitor-alloy:4318"),
        ("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf"),
        ("OTEL_LOGS_EXPORTER", "otlp"),
        ("OTEL_METRICS_EXPORTER", "otlp"),
        ("OTEL_TRACES_EXPORTER", "otlp"),
    ];

    fn deployed_with(overrides: &[(&'static str, &'static str)]) -> OtelEnv {
        let mut pairs: BTreeMap<&str, &str> = DEPLOYED.into_iter().collect();
        for (name, value) in overrides {
            pairs.insert(name, value);
        }
        OtelEnv::from_pairs(pairs)
    }

    fn deployed_without(name: &str) -> OtelEnv {
        OtelEnv::from_pairs(DEPLOYED.into_iter().filter(|(n, _)| *n != name))
    }

    /// Asserts the error names `variable` and does not quote `value`.
    fn assert_rejects(env: &OtelEnv, variable: &str, value: &str) {
        let error = validate(env).expect_err("the set must be rejected");
        assert_eq!(error.variable, variable);
        let message = error.to_string();
        assert!(message.contains(variable), "{message}");
        assert!(
            !message.contains(value),
            "the message quoted the value: {message}"
        );
    }

    #[test]
    fn no_variables_is_off() {
        assert_eq!(
            validate(&OtelEnv::default()),
            Ok(Plan::Off(Off::NoVariables))
        );
        // Present but empty is unset, so it does not switch telemetry on.
        let env = OtelEnv::from_pairs([("OTEL_SERVICE_NAME", ""), ("PATH", "/usr/bin")]);
        assert_eq!(validate(&env), Ok(Plan::Off(Off::NoVariables)));
    }

    #[test]
    fn sdk_disabled_is_off_whatever_else_is_set() {
        for value in ["true", "TRUE", " True "] {
            let env =
                deployed_with(&[("OTEL_SDK_DISABLED", value), ("OTEL_LOGS_EXPORTER", "junk")]);
            assert_eq!(validate(&env), Ok(Plan::Off(Off::Disabled)));
        }
        let env = deployed_with(&[("OTEL_SDK_DISABLED", "false")]);
        assert!(matches!(validate(&env), Ok(Plan::Export { .. })));
        assert_rejects(
            &deployed_with(&[("OTEL_SDK_DISABLED", "yes-please")]),
            "OTEL_SDK_DISABLED",
            "yes-please",
        );
    }

    #[test]
    fn the_deployed_set_exports_every_signal_with_its_attributes() {
        let Ok(Plan::Export {
            attributes,
            signals,
        }) = validate(&deployed_with(&[]))
        else {
            panic!("the deployed set must export");
        };
        assert_eq!(
            signals,
            Exported {
                logs: true,
                metrics: true,
                traces: true
            }
        );
        assert_eq!(signals.names(), "logs,metrics,traces");
        assert_eq!(
            attributes,
            [
                ("deployment.environment.name", "dev"),
                ("service.name", "sovereign-config"),
                ("telemetry_source", "otlp"),
            ]
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
        );
    }

    #[test]
    fn a_signal_exporting_without_an_endpoint_fails_rather_than_defaulting_to_localhost() {
        let env = deployed_without("OTEL_EXPORTER_OTLP_ENDPOINT");
        assert_eq!(
            validate(&env).unwrap_err().variable,
            "OTEL_EXPORTER_OTLP_ENDPOINT"
        );
        // A default exporter is `otlp`, so a set that only names the service
        // still has three signals exporting, and still needs an endpoint.
        let env = OtelEnv::from_pairs([("OTEL_SERVICE_NAME", "sovereign-config")]);
        assert_eq!(
            validate(&env).unwrap_err().variable,
            "OTEL_EXPORTER_OTLP_ENDPOINT"
        );
        // A per-signal endpoint satisfies its own signal.
        let env = OtelEnv::from_pairs(
            DEPLOYED
                .into_iter()
                .filter(|(n, _)| *n != "OTEL_EXPORTER_OTLP_ENDPOINT")
                .chain([(
                    "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
                    "http://collector:4318/v1/logs",
                )]),
        );
        // ...but not another signal's: traces still export, with nowhere to go.
        assert_eq!(
            validate(&env).unwrap_err().variable,
            "OTEL_EXPORTER_OTLP_ENDPOINT"
        );
        let env = OtelEnv::from_pairs(
            DEPLOYED
                .into_iter()
                .filter(|(n, _)| *n != "OTEL_EXPORTER_OTLP_ENDPOINT")
                .chain([
                    (
                        "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
                        "http://collector:4318/v1/logs",
                    ),
                    ("OTEL_TRACES_EXPORTER", "none"),
                    ("OTEL_METRICS_EXPORTER", "none"),
                ]),
        );
        assert!(matches!(validate(&env), Ok(Plan::Export { .. })));
    }

    #[test]
    fn each_signal_is_silenced_on_its_own() {
        let Ok(Plan::Export { signals, .. }) =
            validate(&deployed_with(&[("OTEL_TRACES_EXPORTER", "none")]))
        else {
            panic!("logs still export");
        };
        assert_eq!(
            signals,
            Exported {
                logs: true,
                metrics: true,
                traces: false
            }
        );
        let Ok(Plan::Export { signals, .. }) =
            validate(&deployed_with(&[("OTEL_LOGS_EXPORTER", "none")]))
        else {
            panic!("traces still export");
        };
        assert_eq!(signals.names(), "metrics,traces");
        let Ok(Plan::Export { signals, .. }) =
            validate(&deployed_with(&[("OTEL_METRICS_EXPORTER", "none")]))
        else {
            panic!("logs and traces still export");
        };
        assert_eq!(signals.names(), "logs,traces");
        // Metrics alone are a reason to start: they have a provider now.
        let Ok(Plan::Export { signals, .. }) = validate(&deployed_with(&[
            ("OTEL_LOGS_EXPORTER", "none"),
            ("OTEL_TRACES_EXPORTER", "none"),
        ])) else {
            panic!("metrics still export");
        };
        assert_eq!(signals.names(), "metrics");
        assert_eq!(
            validate(&deployed_with(&[
                ("OTEL_LOGS_EXPORTER", "none"),
                ("OTEL_METRICS_EXPORTER", "none"),
                ("OTEL_TRACES_EXPORTER", "none"),
            ])),
            Ok(Plan::Off(Off::NothingExported))
        );
    }

    #[test]
    fn no_endpoint_is_needed_when_nothing_exports() {
        let env = OtelEnv::from_pairs([
            ("OTEL_TRACES_EXPORTER", "none"),
            ("OTEL_METRICS_EXPORTER", "none"),
            ("OTEL_LOGS_EXPORTER", "none"),
        ]);
        assert_eq!(validate(&env), Ok(Plan::Off(Off::NothingExported)));
    }

    #[test]
    fn a_malformed_endpoint_is_rejected_without_being_quoted() {
        for value in ["monitor-alloy:4318", "ftp://collector", "not a url"] {
            assert_rejects(
                &deployed_with(&[("OTEL_EXPORTER_OTLP_ENDPOINT", value)]),
                "OTEL_EXPORTER_OTLP_ENDPOINT",
                value,
            );
        }
    }

    #[test]
    fn protocol_must_be_http_protobuf_and_grpc_is_refused_by_name() {
        assert_rejects(
            &deployed_with(&[("OTEL_EXPORTER_OTLP_PROTOCOL", "http/json")]),
            "OTEL_EXPORTER_OTLP_PROTOCOL",
            "http/json",
        );
        let error = validate(&deployed_with(&[(
            "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL",
            "grpc",
        )]))
        .unwrap_err();
        assert_eq!(error.variable, "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL");
        assert!(error.to_string().contains("not built with"), "{error}");
    }

    #[test]
    fn exporter_must_be_otlp_or_none() {
        for signal in Signal::ALL {
            assert_rejects(
                &deployed_with(&[(signal.exporter_variable(), "console")]),
                signal.exporter_variable(),
                "console",
            );
        }
    }

    #[test]
    fn propagators_must_be_w3c_trace_context() {
        assert!(validate(&deployed_with(&[("OTEL_PROPAGATORS", "tracecontext")])).is_ok());
        assert_rejects(
            &deployed_with(&[("OTEL_PROPAGATORS", "b3multi")]),
            "OTEL_PROPAGATORS",
            "b3multi",
        );
    }

    #[test]
    fn sampler_and_its_argument_are_checked() {
        assert!(
            validate(&deployed_with(&[
                ("OTEL_TRACES_SAMPLER", "parentbased_traceidratio"),
                ("OTEL_TRACES_SAMPLER_ARG", "0.25"),
            ]))
            .is_ok()
        );
        assert_rejects(
            &deployed_with(&[("OTEL_TRACES_SAMPLER", "sometimes")]),
            "OTEL_TRACES_SAMPLER",
            "sometimes",
        );
        // A caller picks its trace id, so a sampler that decides from the
        // trace id alone would let it opt out of tracing.
        assert_eq!(
            validate(&deployed_with(&[("OTEL_TRACES_SAMPLER", "traceidratio")]))
                .unwrap_err()
                .variable,
            "OTEL_TRACES_SAMPLER"
        );
        for value in ["1.5", "-0.1", "half"] {
            assert_rejects(
                &deployed_with(&[("OTEL_TRACES_SAMPLER_ARG", value)]),
                "OTEL_TRACES_SAMPLER_ARG",
                value,
            );
        }
    }

    #[test]
    fn numeric_knobs_must_be_whole_numbers() {
        assert_rejects(
            &deployed_with(&[("OTEL_BLRP_SCHEDULE_DELAY", "soon")]),
            "OTEL_BLRP_SCHEDULE_DELAY",
            "soon",
        );
    }

    #[test]
    fn required_resource_attributes_must_be_present() {
        assert_eq!(
            validate(&deployed_without("OTEL_SERVICE_NAME"))
                .unwrap_err()
                .variable,
            "OTEL_SERVICE_NAME"
        );
        // service.name inside the attribute list is as good as the variable.
        let env = OtelEnv::from_pairs(
            DEPLOYED
                .into_iter()
                .filter(|(n, _)| !matches!(*n, "OTEL_SERVICE_NAME" | "OTEL_RESOURCE_ATTRIBUTES"))
                .chain([(
                    "OTEL_RESOURCE_ATTRIBUTES",
                    "service.name=sovereign-config,deployment.environment.name=dev",
                )]),
        );
        assert!(matches!(validate(&env), Ok(Plan::Export { .. })));

        assert_eq!(
            validate(&deployed_with(&[(
                "OTEL_RESOURCE_ATTRIBUTES",
                "telemetry_source=otlp"
            )]))
            .unwrap_err()
            .variable,
            "OTEL_RESOURCE_ATTRIBUTES"
        );
        assert_rejects(
            &deployed_with(&[(
                "OTEL_RESOURCE_ATTRIBUTES",
                "deployment.environment.name=dev,secret-token",
            )]),
            "OTEL_RESOURCE_ATTRIBUTES",
            "secret-token",
        );
    }

    #[test]
    fn otel_service_name_wins_over_the_attribute_list() {
        let env = deployed_with(&[(
            "OTEL_RESOURCE_ATTRIBUTES",
            "service.name=stale,deployment.environment.name=dev",
        )]);
        let Ok(Plan::Export { attributes, .. }) = validate(&env) else {
            panic!("must export");
        };
        assert!(attributes.contains(&("service.name".to_owned(), "sovereign-config".to_owned())));
    }

    #[test]
    fn empty_values_count_as_unset() {
        // Compose passes a name with no value as an empty string in some
        // setups; an empty exporter is the default, not an invalid value.
        let env = deployed_with(&[("OTEL_TRACES_EXPORTER", ""), ("OTEL_PROPAGATORS", "")]);
        assert!(matches!(validate(&env), Ok(Plan::Export { .. })));
    }
}
