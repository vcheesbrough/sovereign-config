//! The server's metrics (`observability` skill §1.5–1.6, §4), pushed over
//! OTLP by `sovereign-config-telemetry` — nothing here scrapes, renders or
//! names an SDK type.
//!
//! Every instrument is created **once**, at startup, on the meter
//! `sovereign_config_telemetry::Telemetry::meter` hands out, and held by what
//! records it: the counter families below by their `Arc`, the request
//! histograms by the transport layer ([`RequestMetrics`]), the sweep
//! histogram by the sweep ([`JobMetrics`]). Not in statics: every test
//! assembles its own capture, and a static would make parallel tests share
//! series.
//!
//! **Counters are atomics, reported by observable counters.** Each family
//! counts in its own atomics and an observable counter reads them at every
//! collection, reporting **every** label combination its enums allow —
//! including those still at zero. That keeps what the scrape exposition
//! gave: every series exists from startup, so `rate()` sees a series' first
//! increment and the retirement gate can read a real zero rather than an
//! absent series. The label sets come from exhaustive matches over enums, so
//! no request can mint a label value.
//!
//! **Names survive the platform's translation.** An instrument named
//! `sovereign_config.protocol.requests` is stored as
//! `sovereign_config_protocol_requests_total` (dots to underscores, `_total`
//! for a counter, a unit word for a unit), so every series the README and the
//! retirement gate name keeps its stored name and labels. The table in this
//! module's tests is the source of truth.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use opentelemetry::{
    KeyValue,
    metrics::{AsyncInstrument, Histogram, Meter},
};
use sovereign_config_telemetry::keys;
use sqlx::PgPool;
use tonic::Code;

use crate::{audit::EventKind, spans};

/// The bucket a request counts against when its route names a `sovereign.config`
/// protocol version this server does not serve.
///
/// Routes outside `/sovereign.config.` — health probes, gRPC reflection, web
/// assets — are not protocol traffic and are counted nowhere in this family.
/// Folding them in here would bury the one signal the bucket exists to give:
/// that something is addressing a protocol version this build does not know.
pub(crate) const UNRECOGNISED_PROTOCOL_LABEL: &str = "unrecognised";

/// Explicit histogram boundaries, in **seconds**: the semantic conventions'
/// recommendation for `http.server.request.duration`, used for every duration
/// here. The SDK's defaults suit milliseconds and would put every request in
/// the first bucket.
pub(crate) const DURATION_BOUNDARIES: [f64; 14] = [
    0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0,
];

/// Instrument names. Each is stored under the name its comment gives.
pub(crate) mod names {
    /// `sovereign_config_authentication_total`
    pub(crate) const AUTHENTICATION: &str = "sovereign_config.authentication";
    /// `sovereign_config_protocol_requests_total`
    pub(crate) const PROTOCOL_REQUESTS: &str = "sovereign_config.protocol.requests";
    /// `sovereign_config_protocol_client_versions_total`
    pub(crate) const PROTOCOL_CLIENT_VERSIONS: &str = "sovereign_config.protocol.client_versions";
    /// `sovereign_config_managed_connection_operations_total`
    pub(crate) const MANAGED_OPERATIONS: &str = "sovereign_config.managed_connection.operations";
    /// `sovereign_config_managed_dependency_total`
    pub(crate) const MANAGED_DEPENDENCY: &str = "sovereign_config.managed_dependency";
    /// `sovereign_config_audit_events_total`
    pub(crate) const AUDIT_EVENTS: &str = "sovereign_config.audit.events";
    /// `sovereign_config_audit_retention_swept_total`
    pub(crate) const AUDIT_SWEPT: &str = "sovereign_config.audit.retention.swept";
    /// `sovereign_config_audit_retention_sweep_failures_total`
    pub(crate) const AUDIT_SWEEP_FAILURES: &str = "sovereign_config.audit.retention.sweep_failures";
    /// `sovereign_config_audit_sweep_duration_seconds`
    pub(crate) const AUDIT_SWEEP_DURATION: &str = "sovereign_config.audit.sweep.duration";
    /// `sovereign_config_build_info`
    pub(crate) use sovereign_config_telemetry::keys::BUILD_INFO;
    /// `rpc_server_call_duration_seconds`, `http_server_request_duration_seconds`,
    /// `db_client_connection_count`, `db_client_connection_max`
    pub(crate) use sovereign_config_telemetry::keys::{
        DB_CLIENT_CONNECTION_COUNT, DB_CLIENT_CONNECTION_MAX, HTTP_SERVER_REQUEST_DURATION,
        RPC_SERVER_CALL_DURATION,
    };
}

/// One observable counter of a [`CounterFamily`].
pub(crate) struct Instrument {
    pub(crate) name: &'static str,
    pub(crate) description: &'static str,
}

/// Counters kept as atomics and reported, every label combination at every
/// collection, by one observable counter per [`Instrument`].
pub(crate) trait CounterFamily: Send + Sync + 'static {
    const INSTRUMENTS: &'static [Instrument];

    /// Reports every series of `instrument`, zeros included.
    fn observe(&self, instrument: &'static str, emit: &mut dyn FnMut(u64, &[KeyValue]));
}

/// Registers one observable counter per instrument of `family`. The callbacks
/// live as long as the meter provider; nothing needs holding.
pub(crate) fn register<F: CounterFamily>(meter: &Meter, family: &Arc<F>) {
    for instrument in F::INSTRUMENTS {
        let family = Arc::clone(family);
        let name = instrument.name;
        let _ = meter
            .u64_observable_counter(name)
            .with_description(instrument.description)
            .with_callback(move |observer: &dyn AsyncInstrument<u64>| {
                family.observe(name, &mut |value, attributes| {
                    observer.observe(value, attributes);
                });
            })
            .build();
    }
}

/// Every series a family reports, one `stored_name{label="value",…} value`
/// line each — what the family's observable counters hand the exporter,
/// under the names the platform stores. For tests; nothing serves it.
#[cfg(test)]
pub(crate) fn series<F: CounterFamily>(family: &F) -> String {
    use std::fmt::Write as _;

    use sovereign_config_telemetry::testing::{MetricKind, stored_name};

    let mut output = String::new();
    for instrument in F::INSTRUMENTS {
        let stored = stored_name(instrument.name, "", MetricKind::Counter);
        family.observe(instrument.name, &mut |value, attributes| {
            let labels = attributes
                .iter()
                .map(|attribute| format!("{}=\"{}\"", attribute.key, attribute.value))
                .collect::<Vec<_>>()
                .join(",");
            if labels.is_empty() {
                writeln!(output, "{stored} {value}")
            } else {
                writeln!(output, "{stored}{{{labels}}} {value}")
            }
            .expect("writing to a String cannot fail");
        });
    }
    output
}

/// The build identity of the running process, as the estate's
/// `<app>.build.info` convention: a gauge pinned at `1` whose attributes carry
/// the facts, stored as `sovereign_config_build_info`, so a query joins it
/// onto any other series with
/// `… * on(job, instance) group_left(version, revision, protocol)` instead of
/// stamping build identity onto every series — which would start a fresh
/// series set on every deploy. Under push, `job` is the platform's copy of
/// `service.name` and `instance` of `service.instance.id`, which is stable
/// across redeploys.
///
/// **One series, never one per served version.** `protocol` carries the whole
/// served set most-preferred-first (`v4,v3`), the same string startup logs as
/// `protocol_versions`. A series per version would match an instance more than
/// once and break exactly the `group_left` join this metric exists for, and a
/// single most-preferred value would claim the server had dropped the older
/// versions it is still serving. Per-version traffic — and the retirement gate
/// — is `sovereign_config_protocol_requests_total`; this label is descriptive.
///
/// These are the only attributes that carry build identity; the capture's
/// `finish` fails a test that exports them on anything else.
pub(crate) fn register_build_info(meter: &Meter, version: &str, revision: &str, protocol: &str) {
    let attributes = [
        KeyValue::new("version", version.to_owned()),
        KeyValue::new("revision", revision.to_owned()),
        KeyValue::new("protocol", protocol.to_owned()),
    ];
    let _ = meter
        .u64_observable_gauge(names::BUILD_INFO)
        .with_description("Build identity of the running server: always 1.")
        .with_callback(move |observer| observer.observe(1, &attributes))
        .build();
}

/// `db.client.connection.state`: whether a pooled connection is in use.
#[derive(Clone, Copy, Debug)]
enum ConnectionState {
    Idle,
    Used,
}

impl ConnectionState {
    const ALL: [Self; 2] = [Self::Idle, Self::Used];

    const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Used => "used",
        }
    }
}

/// `db.client.connection.pool.name`: the server has one pool, the store's.
const POOL_NAME: &str = "postgres";

/// The Postgres pool's saturation (skill §1.5), from the pool itself at each
/// collection: `db.client.connection.count` by state, and
/// `db.client.connection.max`. Both are up-down counters in the semantic
/// conventions, stored as gauges (`db_client_connection_count`,
/// `db_client_connection_max`; the `{connection}` unit is an annotation and
/// adds no suffix). Used over max is how close the store is to making a
/// request wait for a connection.
pub(crate) fn register_pool(meter: &Meter, pool: &PgPool) {
    let counted = pool.clone();
    let _ = meter
        .i64_observable_up_down_counter(names::DB_CLIENT_CONNECTION_COUNT)
        .with_description("Connections in the Postgres pool, by state.")
        .with_unit("{connection}")
        .with_callback(move |observer| {
            let size = i64::from(counted.size());
            let idle = i64::try_from(counted.num_idle()).unwrap_or(i64::MAX);
            for state in ConnectionState::ALL {
                let value = match state {
                    ConnectionState::Idle => idle,
                    ConnectionState::Used => (size - idle).max(0),
                };
                observer.observe(
                    value,
                    &[
                        KeyValue::new(keys::DB_CLIENT_CONNECTION_POOL_NAME, POOL_NAME),
                        KeyValue::new(keys::DB_CLIENT_CONNECTION_STATE, state.as_str()),
                    ],
                );
            }
        })
        .build();
    let max = i64::from(pool.options().get_max_connections());
    let _ = meter
        .i64_observable_up_down_counter(names::DB_CLIENT_CONNECTION_MAX)
        .with_description("The most connections the Postgres pool will open.")
        .with_unit("{connection}")
        .with_callback(move |observer| {
            observer.observe(
                max,
                &[KeyValue::new(
                    keys::DB_CLIENT_CONNECTION_POOL_NAME,
                    POOL_NAME,
                )],
            );
        })
        .build();
}

fn duration_histogram(
    meter: &Meter,
    name: &'static str,
    description: &'static str,
) -> Histogram<f64> {
    meter
        .f64_histogram(name)
        .with_description(description)
        .with_unit("s")
        .with_boundaries(DURATION_BOUNDARIES.to_vec())
        .build()
}

/// RED for the public port's entry points (skill §1.5): one duration
/// histogram per protocol, whose count is the rate and whose non-OK share is
/// the errors. Recorded by the transport layer (`spans`), with the same
/// attribute keys and values as the request's span, so a metric and a span
/// agree. Health probes are not recorded, as they are not spanned.
#[derive(Clone)]
pub(crate) struct RequestMetrics {
    rpc: Histogram<f64>,
    http: Histogram<f64>,
}

impl RequestMetrics {
    pub(crate) fn new(meter: &Meter) -> Self {
        Self {
            rpc: duration_histogram(
                meter,
                names::RPC_SERVER_CALL_DURATION,
                "Duration of gRPC and gRPC-Web calls, by method and status.",
            ),
            http: duration_histogram(
                meter,
                names::HTTP_SERVER_REQUEST_DURATION,
                "Duration of web UI asset requests.",
            ),
        }
    }

    /// One gRPC call on `method` — a compiled-in route or `_OTHER` — ending
    /// with `code`. `error.type` is the status name for the codes the gRPC
    /// conventions count as a server error, as on the span.
    pub(crate) fn record_rpc(&self, method: &'static str, code: Code, elapsed: Duration) {
        let status = spans::grpc_code_name(code);
        let mut attributes = vec![
            KeyValue::new(keys::RPC_SYSTEM_NAME, "grpc"),
            KeyValue::new(keys::RPC_METHOD, method),
            KeyValue::new(keys::RPC_RESPONSE_STATUS_CODE, status),
        ];
        if spans::is_server_error(code) {
            attributes.push(KeyValue::new(keys::ERROR_TYPE, status));
        }
        self.rpc.record(elapsed.as_secs_f64(), &attributes);
    }

    /// One web asset request: `method` is already bounded to the standard
    /// set or `_OTHER`, and a status code is a bounded number.
    pub(crate) fn record_http(&self, method: &'static str, status: u16, elapsed: Duration) {
        let mut attributes = vec![
            KeyValue::new(keys::HTTP_REQUEST_METHOD, method),
            KeyValue::new(keys::HTTP_RESPONSE_STATUS_CODE, i64::from(status)),
        ];
        if status >= 500 {
            attributes.push(KeyValue::new(keys::ERROR_TYPE, status.to_string()));
        }
        self.http.record(elapsed.as_secs_f64(), &attributes);
    }
}

/// RED for scheduled work: the audit retention sweep's duration, whose count
/// is its rate and whose `error.type` marks a failed sweep.
#[derive(Clone)]
pub(crate) struct JobMetrics {
    sweep: Histogram<f64>,
}

impl JobMetrics {
    pub(crate) fn new(meter: &Meter) -> Self {
        Self {
            sweep: duration_histogram(
                meter,
                names::AUDIT_SWEEP_DURATION,
                "Duration of audit retention sweeps.",
            ),
        }
    }

    /// One sweep; `failure` is its bounded classification, if it failed.
    pub(crate) fn record_sweep(&self, elapsed: Duration, failure: Option<&'static str>) {
        let attributes: Vec<KeyValue> = failure
            .map(|classification| KeyValue::new(keys::ERROR_TYPE, classification))
            .into_iter()
            .collect();
        self.sweep.record(elapsed.as_secs_f64(), &attributes);
    }
}

/// Per-protocol-version request counts, in two series.
///
/// - `outcome="attempted"` counts every `POST` whose route names the version,
///   before authentication runs. Other methods are never counted: gRPC and
///   gRPC-Web are `POST`-only, and this port also serves web assets. It answers "is anything still *trying* to
///   speak this version?", and includes traffic that is not a consumer at all —
///   an internet scanner, a decommissioned application whose credentials were
///   revoked but whose process still retries.
/// - `outcome="authenticated"` counts the subset that then passed
///   authentication. It answers "is any **real consumer** still speaking this
///   version?" and is the input to the retirement decision.
///
/// The split exists because the gate has to be reachable. The gRPC endpoint is
/// public, so the attempted series can be held above zero indefinitely by
/// traffic that would not break on retirement; gating on it would mean either
/// never retiring a version or learning to ignore a counter documented as
/// authoritative. Nothing unauthenticated can move the authenticated series.
///
/// `attempted >= authenticated` always holds, and the difference is refused
/// traffic. The unauthenticated `GetVersion` handshake is attempted-only by
/// construction, which is right: anyone may call it, and negotiation happens
/// once at connect, so a long-lived provider would otherwise register a single
/// connect and then go quiet while its traffic continued.
///
/// The label domain is fixed at construction from compiled-in strings and is
/// never taken from a request, so no route path can widen it. Anything outside
/// that domain lands in [`UNRECOGNISED_PROTOCOL_LABEL`].
pub(crate) struct ProtocolMetrics {
    versions: Vec<VersionCounters>,
    unrecognised: AtomicU64,
    offered_unrecognised: AtomicU64,
}

struct VersionCounters {
    label: &'static str,
    attempted: AtomicU64,
    authenticated: AtomicU64,
    /// How many times a handshake named this version in its client list.
    offered: AtomicU64,
}

impl ProtocolMetrics {
    /// Counters for exactly `versions`, which must be compiled-in labels.
    pub(crate) fn new(versions: &[&'static str]) -> Self {
        Self {
            versions: versions
                .iter()
                .map(|label| VersionCounters {
                    label,
                    attempted: AtomicU64::new(0),
                    authenticated: AtomicU64::new(0),
                    offered: AtomicU64::new(0),
                })
                .collect(),
            unrecognised: AtomicU64::new(0),
            offered_unrecognised: AtomicU64::new(0),
        }
    }

    fn counters(&self, version: &str) -> Option<&VersionCounters> {
        self.versions
            .iter()
            .find(|counters| counters.label == version)
    }

    /// Counts one request arriving on `version`, before authentication, or
    /// against the unrecognised bucket when it is not a label this instance was
    /// built with.
    pub(crate) fn record_attempted(&self, version: &str) {
        match self.counters(version) {
            Some(counters) => counters.attempted.fetch_add(1, Ordering::Relaxed),
            None => self.unrecognised.fetch_add(1, Ordering::Relaxed),
        };
    }

    /// Counts one request on `version` that passed authentication. A version
    /// outside the label domain is ignored rather than bucketed: it was already
    /// counted as unrecognised on arrival, and has no service to reach.
    pub(crate) fn record_authenticated(&self, version: &str) {
        if let Some(counters) = self.counters(version) {
            counters.authenticated.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Counts one version a handshake's client list named.
    ///
    /// This is the record of **what clients in the field can speak**, which the
    /// per-request series cannot show: a client that speaks `v3` and `v4` sends
    /// both, but its traffic only ever names the one it selected. Retirement
    /// reads the request series; this one is how an operator sees a fleet
    /// becoming ready for a retirement before making it.
    ///
    /// The list is untrusted input on a public endpoint, so a version outside
    /// the compiled-in label domain lands in the unrecognised bucket. Nothing
    /// from the request can ever become a label.
    pub(crate) fn record_offered(&self, version: &str) {
        match self.counters(version) {
            Some(counters) => counters.offered.fetch_add(1, Ordering::Relaxed),
            None => self.offered_unrecognised.fetch_add(1, Ordering::Relaxed),
        };
    }

    #[cfg(test)]
    pub(crate) fn series(&self) -> String {
        series(self)
    }
}

impl CounterFamily for ProtocolMetrics {
    const INSTRUMENTS: &'static [Instrument] = &[
        Instrument {
            name: names::PROTOCOL_REQUESTS,
            description: "gRPC requests by protocol version and outcome.",
        },
        Instrument {
            name: names::PROTOCOL_CLIENT_VERSIONS,
            description: "Protocol versions named in handshake client lists.",
        },
    ];

    fn observe(&self, instrument: &'static str, emit: &mut dyn FnMut(u64, &[KeyValue])) {
        match instrument {
            names::PROTOCOL_REQUESTS => {
                for counters in &self.versions {
                    for (outcome, counter) in [
                        ("attempted", &counters.attempted),
                        ("authenticated", &counters.authenticated),
                    ] {
                        emit(
                            counter.load(Ordering::Relaxed),
                            &[
                                KeyValue::new("version", counters.label),
                                KeyValue::new("outcome", outcome),
                            ],
                        );
                    }
                }
                emit(
                    self.unrecognised.load(Ordering::Relaxed),
                    &[
                        KeyValue::new("version", UNRECOGNISED_PROTOCOL_LABEL),
                        KeyValue::new("outcome", "attempted"),
                    ],
                );
            }
            names::PROTOCOL_CLIENT_VERSIONS => {
                for counters in &self.versions {
                    emit(
                        counters.offered.load(Ordering::Relaxed),
                        &[KeyValue::new("version", counters.label)],
                    );
                }
                emit(
                    self.offered_unrecognised.load(Ordering::Relaxed),
                    &[KeyValue::new("version", UNRECOGNISED_PROTOCOL_LABEL)],
                );
            }
            _ => {}
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum AuthenticationResult {
    Success,
    MissingBearer,
    MalformedBearer,
    WrongAlgorithm,
    /// Signed by no key the issuer publishes: a forged or altered token, or
    /// one naming a key the issuer's current key set does not hold.
    BadSignature,
    /// Genuine, but outside its validity window: expired, or not yet valid.
    Inactive,
    InvalidClaims,
    Unavailable,
}

impl AuthenticationResult {
    pub(crate) const ALL: [Self; 8] = [
        Self::Success,
        Self::MissingBearer,
        Self::MalformedBearer,
        Self::WrongAlgorithm,
        Self::BadSignature,
        Self::Inactive,
        Self::InvalidClaims,
        Self::Unavailable,
    ];

    const fn index(self) -> usize {
        self as usize
    }

    pub(crate) const fn outcome(self) -> &'static str {
        match self {
            Self::Success => "success",
            _ => "failure",
        }
    }

    pub(crate) const fn reason(self) -> &'static str {
        match self {
            Self::Success => "accepted",
            Self::MissingBearer => "missing_bearer",
            Self::MalformedBearer => "malformed_bearer",
            Self::WrongAlgorithm => "wrong_algorithm",
            Self::BadSignature => "bad_signature",
            Self::Inactive => "inactive",
            Self::InvalidClaims => "invalid_claims",
            Self::Unavailable => "dependency_unavailable",
        }
    }
}

#[derive(Default)]
pub(crate) struct AuthenticationMetrics {
    counters: [AtomicU64; AuthenticationResult::ALL.len()],
}

impl AuthenticationMetrics {
    pub(crate) fn increment(&self, result: AuthenticationResult) {
        self.counters[result.index()].fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn series(&self) -> String {
        series(self)
    }
}

impl CounterFamily for AuthenticationMetrics {
    const INSTRUMENTS: &'static [Instrument] = &[Instrument {
        name: names::AUTHENTICATION,
        description: "Protected gRPC authentication results.",
    }];

    fn observe(&self, instrument: &'static str, emit: &mut dyn FnMut(u64, &[KeyValue])) {
        if instrument != names::AUTHENTICATION {
            return;
        }
        for result in AuthenticationResult::ALL {
            emit(
                self.counters[result.index()].load(Ordering::Relaxed),
                &[
                    KeyValue::new("outcome", result.outcome()),
                    KeyValue::new("reason", result.reason()),
                ],
            );
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ManagedOperation {
    List,
    Create,
    Rotate,
    Revoke,
}

impl ManagedOperation {
    pub(crate) const ALL: [Self; 4] = [Self::List, Self::Create, Self::Rotate, Self::Revoke];

    const fn index(self) -> usize {
        self as usize
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::List => "list",
            Self::Create => "create",
            Self::Rotate => "rotate",
            Self::Revoke => "revoke",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ManagedOperationResult {
    Success,
    InvalidRequest,
    Unauthenticated,
    PermissionDenied,
    NotFound,
    Conflict,
    Storage,
    Dependency,
    CleanupRequired,
    Internal,
}

impl ManagedOperationResult {
    pub(crate) const ALL: [Self; 10] = [
        Self::Success,
        Self::InvalidRequest,
        Self::Unauthenticated,
        Self::PermissionDenied,
        Self::NotFound,
        Self::Conflict,
        Self::Storage,
        Self::Dependency,
        Self::CleanupRequired,
        Self::Internal,
    ];

    const fn index(self) -> usize {
        self as usize
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::InvalidRequest => "invalid_request",
            Self::Unauthenticated => "unauthenticated",
            Self::PermissionDenied => "permission_denied",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::Storage => "storage_unavailable",
            Self::Dependency => "dependency_failed",
            Self::CleanupRequired => "cleanup_required",
            Self::Internal => "internal",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ManagedDependencyCall {
    CreateAccount,
    SetAttributes,
    FindUser,
    FindCredentials,
    SetCredential,
    DeleteUser,
    /// Best-effort: never fails or rolls back connection creation.
    AssignGroup,
}

impl ManagedDependencyCall {
    pub(crate) const ALL: [Self; 7] = [
        Self::CreateAccount,
        Self::SetAttributes,
        Self::FindUser,
        Self::FindCredentials,
        Self::SetCredential,
        Self::DeleteUser,
        Self::AssignGroup,
    ];

    const fn index(self) -> usize {
        self as usize
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::CreateAccount => "create_account",
            Self::SetAttributes => "set_attributes",
            Self::FindUser => "find_user",
            Self::FindCredentials => "find_credentials",
            Self::SetCredential => "set_credential",
            Self::DeleteUser => "delete_user",
            Self::AssignGroup => "assign_group",
        }
    }
}

/// Fixed dependency outcomes: `ok` plus the bounded [`crate::authentik::AdminError`] kinds.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ManagedDependencyOutcome {
    Ok,
    NotFound,
    Rejected,
    Unavailable,
    Ambiguous,
    Invalid,
}

impl ManagedDependencyOutcome {
    pub(crate) const ALL: [Self; 6] = [
        Self::Ok,
        Self::NotFound,
        Self::Rejected,
        Self::Unavailable,
        Self::Ambiguous,
        Self::Invalid,
    ];

    const fn index(self) -> usize {
        self as usize
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::NotFound => "not_found",
            Self::Rejected => "rejected",
            Self::Unavailable => "unavailable",
            Self::Ambiguous => "ambiguous",
            Self::Invalid => "invalid",
        }
    }
}

/// Bounded managed-connection operation and dependency counters.
///
/// Labels are fixed enums only: no connection identifier, name, root, username,
/// credential, URL, or provider response detail can reach a label value.
#[derive(Default)]
pub(crate) struct ManagedConnectionMetrics {
    operations: [[AtomicU64; ManagedOperationResult::ALL.len()]; ManagedOperation::ALL.len()],
    dependencies:
        [[AtomicU64; ManagedDependencyOutcome::ALL.len()]; ManagedDependencyCall::ALL.len()],
}

impl ManagedConnectionMetrics {
    pub(crate) fn record_operation(
        &self,
        operation: ManagedOperation,
        result: ManagedOperationResult,
    ) {
        self.operations[operation.index()][result.index()].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_dependency(
        &self,
        call: ManagedDependencyCall,
        outcome: ManagedDependencyOutcome,
    ) {
        self.dependencies[call.index()][outcome.index()].fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn series(&self) -> String {
        series(self)
    }
}

impl CounterFamily for ManagedConnectionMetrics {
    const INSTRUMENTS: &'static [Instrument] = &[
        Instrument {
            name: names::MANAGED_OPERATIONS,
            description: "Managed connection operation results.",
        },
        Instrument {
            name: names::MANAGED_DEPENDENCY,
            description: "Managed connection Authentik dependency outcomes.",
        },
    ];

    fn observe(&self, instrument: &'static str, emit: &mut dyn FnMut(u64, &[KeyValue])) {
        match instrument {
            names::MANAGED_OPERATIONS => {
                for operation in ManagedOperation::ALL {
                    for result in ManagedOperationResult::ALL {
                        emit(
                            self.operations[operation.index()][result.index()]
                                .load(Ordering::Relaxed),
                            &[
                                KeyValue::new("operation", operation.as_str()),
                                KeyValue::new("result", result.as_str()),
                            ],
                        );
                    }
                }
            }
            names::MANAGED_DEPENDENCY => {
                for call in ManagedDependencyCall::ALL {
                    for outcome in ManagedDependencyOutcome::ALL {
                        emit(
                            self.dependencies[call.index()][outcome.index()]
                                .load(Ordering::Relaxed),
                            &[
                                KeyValue::new("call", call.as_str()),
                                KeyValue::new("outcome", outcome.as_str()),
                            ],
                        );
                    }
                }
            }
            _ => {}
        }
    }
}

/// Whether an audit event reached the trail.
#[derive(Clone, Copy, Debug)]
pub(crate) enum AuditWriteOutcome {
    Recorded,
    Failed,
}

impl AuditWriteOutcome {
    pub(crate) const ALL: [Self; 2] = [Self::Recorded, Self::Failed];

    const fn index(self) -> usize {
        self as usize
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Failed => "failed",
        }
    }
}

/// Audit trail writes by event kind and outcome, and the retention sweep.
///
/// `outcome="failed"` is the series to alert on. A failed write either failed
/// the operation it belonged to — a change, a secret access — or, for a plain
/// read, was dropped while the read was served; in both cases the trail and
/// reality have parted, and this counter is the only place that shows.
#[derive(Default)]
pub(crate) struct AuditMetrics {
    writes: [[AtomicU64; AuditWriteOutcome::ALL.len()]; EventKind::ALL.len()],
    swept: AtomicU64,
    sweep_failures: AtomicU64,
}

impl AuditMetrics {
    pub(crate) fn record_write(&self, kind: EventKind, outcome: AuditWriteOutcome) {
        self.writes[kind.index()][outcome.index()].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_swept(&self, rows: u64) {
        self.swept.fetch_add(rows, Ordering::Relaxed);
    }

    pub(crate) fn record_sweep_failure(&self) {
        self.sweep_failures.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn series(&self) -> String {
        series(self)
    }
}

impl CounterFamily for AuditMetrics {
    const INSTRUMENTS: &'static [Instrument] = &[
        Instrument {
            name: names::AUDIT_EVENTS,
            description: "Audit trail writes by event kind and outcome.",
        },
        Instrument {
            name: names::AUDIT_SWEPT,
            description: "Audit events deleted by the retention sweep.",
        },
        Instrument {
            name: names::AUDIT_SWEEP_FAILURES,
            description: "Retention sweeps that failed.",
        },
    ];

    fn observe(&self, instrument: &'static str, emit: &mut dyn FnMut(u64, &[KeyValue])) {
        match instrument {
            names::AUDIT_EVENTS => {
                for kind in EventKind::ALL {
                    for outcome in AuditWriteOutcome::ALL {
                        emit(
                            self.writes[kind.index()][outcome.index()].load(Ordering::Relaxed),
                            &[
                                KeyValue::new("kind", kind.as_str()),
                                KeyValue::new("outcome", outcome.as_str()),
                            ],
                        );
                    }
                }
            }
            names::AUDIT_SWEPT => emit(self.swept.load(Ordering::Relaxed), &[]),
            names::AUDIT_SWEEP_FAILURES => emit(self.sweep_failures.load(Ordering::Relaxed), &[]),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests;
