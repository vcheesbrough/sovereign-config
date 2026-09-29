mod audit;
mod auth;
mod authentik;
mod config;
mod encryption;
mod handshake;
mod managed;
mod metrics;
mod protocol;
mod rpc;
mod spans;
mod system;
mod values;
mod web;

use std::{
    env,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tokio::{net::TcpListener, signal};
use tonic::{
    Request,
    transport::{Endpoint, Server},
};
use tonic_health::pb::{
    HealthCheckRequest, health_check_response,
    health_client::HealthClient,
    health_server::{Health, HealthServer},
};
use tonic_health::server::HealthReporter;
use tracing::{Instrument, error, info};

use audit::{AuditRecorder, AuditTrailService, v4::V4Audit};
use auth::{Authenticator, grpc_service_layer};
use authentik::AuthentikAdminClient;
use config::{Config, ManagedConnectionConfig, required_env};
use handshake::HandshakeService;
use managed::{
    ManagedConnectionsService, ManagedSettings, V3ManagedConnections, V4ManagedConnections,
};
use metrics::{
    AuditMetrics, AuthenticationMetrics, JobMetrics, ManagedConnectionMetrics, ProtocolMetrics,
    RequestMetrics,
};
use opentelemetry::metrics::Meter;
use protocol::ProtocolVersionLayer;
use sovereign_config_core::Secret;
use sovereign_config_proto::sovereign::config::{
    handshake_server::HandshakeServer,
    v3::{
        configuration_server::ConfigurationServer,
        managed_connections_server::ManagedConnectionsServer, system_server::SystemServer,
    },
    v4,
};
use spans::TraceLayer;
use system::{SERVED_PROTOCOL_LABELS, SystemService, V4System};
use values::{ConfigurationService, V3Configuration, V4Configuration, encrypt_stored_secrets};
use web::WebAssetsLayer;

const SYSTEM_SERVICE_NAME: &str = "sovereign.config.v3.System";
const APPLICATION_VERSION: &str = application_version(option_env!("SOVEREIGN_CONFIG_RELEASE"));
const APPLICATION_REVISION: &str = application_revision(option_env!("SOVEREIGN_CONFIG_REVISION"));

const fn application_version(release_version: Option<&str>) -> &str {
    match release_version {
        Some(version) if !version.is_empty() => version,
        _ => env!("CARGO_PKG_VERSION"),
    }
}

/// The commit this binary was built from, or `unknown`.
///
/// Unlike the version there is no source-tree fallback: a local `cargo build`
/// has no commit stamped into it, and reporting the *checkout's* HEAD would
/// claim an identity the binary may not have — a dirty tree, or a build kept
/// across commits. `unknown` says plainly that nothing stamped it.
const fn application_revision(revision: Option<&str>) -> &str {
    match revision {
        Some(revision) if !revision.is_empty() => revision,
        _ => "unknown",
    }
}

async fn ready(State(database): State<PgPool>) -> impl IntoResponse {
    match sqlx::query("SELECT 1").execute(&database).await {
        Ok(_) => StatusCode::OK,
        Err(error) => {
            error!(error = %error, "database readiness probe failed");
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    if env::args().nth(1).as_deref() == Some("healthcheck") {
        return healthcheck().await;
    }
    // First, before anything logs: it installs the subscriber, and it fails
    // startup on a half-configured OTEL_* set rather than exporting nowhere.
    let mut telemetry = sovereign_config_telemetry::init(APPLICATION_VERSION)?;
    let served = serve(&telemetry.meter()).await;
    // Inside the runtime and after serving has stopped, so the records of the
    // shutdown itself are flushed. Bounded, and never able to fail the exit.
    telemetry.shutdown();
    served
}

async fn serve(meter: &Meter) -> Result<()> {
    let config = Config::from_env()?;
    let web_assets = WebAssetsLayer::new(&config.web);
    let authenticator = Authenticator::new(config.authentication)?;
    authenticator.spawn_key_refresh();
    let authentication_metrics = Arc::new(AuthenticationMetrics::default());
    let managed_metrics = Arc::new(ManagedConnectionMetrics::default());
    let protocol_metrics = Arc::new(ProtocolMetrics::new(SERVED_PROTOCOL_LABELS));
    let audit_metrics = Arc::new(AuditMetrics::default());
    let audit = AuditRecorder::new(Arc::clone(&audit_metrics), config.audit.coalesce_window);
    let (managed_admin, managed_settings) = managed_dependencies(config.managed)?;
    let database = connect_database(&config.database_url).await?;
    let value_cipher = Arc::new(config.value_cipher);
    encrypt_stored_secrets(&database, &value_cipher).await?;

    register_metrics(
        meter,
        Families {
            authentication: &authentication_metrics,
            managed: &managed_metrics,
            protocol: &protocol_metrics,
            audit: &audit_metrics,
        },
        &database,
    );
    spawn_health_server(config.metrics_addr, database.clone()).await?;
    spawn_audit_retention_sweep(
        database.clone(),
        audit.clone(),
        config.audit.retention,
        JobMetrics::new(meter),
    );
    let (_health_reporter, health_service) = serving_health_service().await;
    // One implementation of each service, whatever the number of protocol
    // versions served: every version registered below is a shim over these.
    let configuration = Arc::new(ConfigurationService::new(
        database.clone(),
        Arc::clone(&value_cipher),
        audit.clone(),
    ));
    let managed_connections = Arc::new(ManagedConnectionsService::new(
        database.clone(),
        managed_admin,
        managed_settings,
        managed_metrics,
        audit,
    ));
    let audit_trail = Arc::new(AuditTrailService::new(database, config.audit.page_size));

    info!(
        grpc_addr = %config.grpc_addr,
        metrics_addr = %config.metrics_addr,
        protocol_versions = SERVED_PROTOCOL_LABELS.join(","),
        "sovereign-config started"
    );
    Server::builder()
        .accept_http1(true)
        // Outermost of all: the request's span covers every layer below, and
        // adopts an inbound `traceparent` before anything else runs. It
        // starts the request's clock for RED as well.
        .layer(TraceLayer::new(RequestMetrics::new(meter)))
        // Outermost of the rest, so every request is attributed to the protocol version its
        // route names — including one rejected by authentication, which still
        // counts as `attempted`. It must also stay outside the authentication
        // layer because that layer reads the version extension this one
        // attaches in order to record the `authenticated` series.
        .layer(ProtocolVersionLayer::new(
            Arc::clone(&protocol_metrics),
            SERVED_PROTOCOL_LABELS,
        ))
        .layer(grpc_service_layer(
            authenticator,
            authentication_metrics,
            Arc::clone(&protocol_metrics),
            SERVED_PROTOCOL_LABELS,
        ))
        .layer(web_assets)
        .add_service(health_service)
        // Unversioned, and registered first: it is the operation every
        // version's clients call before any of them. It has no shim, because
        // it belongs to no version.
        .add_service(HandshakeServer::new(HandshakeService::new(
            protocol_metrics,
        )))
        .add_service(SystemServer::new(SystemService))
        .add_service(ConfigurationServer::new(V3Configuration::new(Arc::clone(
            &configuration,
        ))))
        .add_service(ManagedConnectionsServer::new(V3ManagedConnections::new(
            Arc::clone(&managed_connections),
        )))
        // `v4`: the same implementations again, plus the audit trail, which
        // `v3` has no service for.
        .add_service(v4::system_server::SystemServer::new(V4System))
        .add_service(v4::configuration_server::ConfigurationServer::new(
            V4Configuration::new(Arc::clone(&configuration)),
        ))
        .add_service(
            v4::managed_connections_server::ManagedConnectionsServer::new(
                V4ManagedConnections::new(Arc::clone(&managed_connections)),
            ),
        )
        .add_service(v4::audit_server::AuditServer::new(V4Audit::new(
            audit_trail,
        )))
        .serve_with_shutdown(config.grpc_addr, shutdown_signal())
        .await
        .context("gRPC server terminated")
}

/// The Authentik admin client and the non-secret settings the managed
/// connection service builds URLs and grants from.
fn managed_dependencies(
    managed: ManagedConnectionConfig,
) -> Result<(AuthentikAdminClient, ManagedSettings)> {
    let admin = AuthentikAdminClient::new(
        managed.api_origin.clone(),
        Secret::new(managed.api_token),
        managed.timeout,
    )?;
    let settings = ManagedSettings {
        public_origin: managed.public_origin,
        issuer: managed.issuer,
        client_id: managed.client_id,
        grants_attribute: managed.grants_attribute,
        managed_group: managed.managed_group,
        // Comfortably longer than the bounded Authentik call, so an expired
        // lease proves the previous rotation attempt has ended.
        rotation_lease: managed.timeout * 6,
    };
    Ok((admin, settings))
}

/// Connects to the required `PostgreSQL` dependency and applies the
/// forward-only migrations before anything can serve — as one root span,
/// since startup is part of no request.
async fn connect_database(database_url: &str) -> Result<PgPool> {
    async {
        let database = PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(5))
            .connect(database_url)
            .await
            .map_err(|_| {
                spans::record_error("unavailable");
                anyhow::anyhow!("unable to connect to required PostgreSQL dependency")
            })?;
        sqlx::migrate!("./migrations")
            .run(&database)
            .await
            .inspect_err(|_| spans::record_error("migration_failed"))
            .context("database migration failed")?;
        Ok(database)
    }
    .instrument(tracing::info_span!(
        parent: None,
        "migrate",
        otel.kind = "client",
        otel.status_code = tracing::field::Empty,
        error.type = tracing::field::Empty,
        db.system.name = "postgresql",
        db.operation.name = "migrate",
    ))
    .await
}

/// The counter families whose observable counters [`register_metrics`]
/// registers.
#[derive(Clone, Copy)]
struct Families<'a> {
    authentication: &'a Arc<AuthenticationMetrics>,
    managed: &'a Arc<ManagedConnectionMetrics>,
    protocol: &'a Arc<ProtocolMetrics>,
    audit: &'a Arc<AuditMetrics>,
}

/// Registers every observable instrument on `meter`, once: the counter
/// families, build identity and the pool's saturation. The request and sweep
/// histograms are created by what records them.
fn register_metrics(meter: &Meter, families: Families<'_>, database: &PgPool) {
    metrics::register(meter, families.authentication);
    metrics::register(meter, families.managed);
    metrics::register(meter, families.protocol);
    metrics::register(meter, families.audit);
    metrics::register_build_info(
        meter,
        APPLICATION_VERSION,
        APPLICATION_REVISION,
        &SERVED_PROTOCOL_LABELS.join(","),
    );
    metrics::register_pool(meter, database);
}

/// The internal listener's routes: `/readyz` and nothing else. Metrics leave
/// over OTLP, so there is no `/metrics` to scrape; the listener keeps its
/// `SOVEREIGN_CONFIG_METRICS_ADDR` name because renaming an operator's
/// variable would be churn for no gain.
fn health_router(database: PgPool) -> Router {
    Router::new()
        .route("/readyz", get(ready))
        .with_state(database)
}

/// Serves `/readyz` on the internal listener in the background. Binding
/// happens before this returns, so a taken port fails startup.
async fn spawn_health_server(address: SocketAddr, database: PgPool) -> Result<()> {
    let listener = TcpListener::bind(address)
        .await
        .context("unable to bind the internal health listener")?;
    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, health_router(database)).await {
            error!(error = %error, "internal health listener terminated");
        }
    });
    Ok(())
}

/// How often the audit trail is swept. Retention is measured in days, so an
/// hour's slack on when an expired event actually goes is immaterial, and each
/// sweep finds at most an hour's worth of expiries to delete.
const AUDIT_SWEEP_INTERVAL: Duration = Duration::from_hours(1);

/// Deletes expired audit events in the background, for as long as the server
/// runs. The first sweep is immediate, so a server that is restarted often
/// still sweeps. A failed sweep is counted, logged and retried at the next
/// interval: it must never take the server down, and nothing is lost by
/// keeping an event an hour longer.
fn spawn_audit_retention_sweep(
    database: PgPool,
    audit: AuditRecorder,
    retention: Duration,
    metrics: JobMetrics,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(AUDIT_SWEEP_INTERVAL);
        loop {
            interval.tick().await;
            sweep_audit_trail(&database, &audit, retention, &metrics).await;
        }
    });
}

/// One retention sweep, as a **root** span of its own: it is scheduled work,
/// part of no request, and a child of whatever happened to be current would
/// hang it off a trace it has nothing to do with.
async fn sweep_audit_trail(
    database: &PgPool,
    audit: &AuditRecorder,
    retention: Duration,
    metrics: &JobMetrics,
) {
    async {
        let started = Instant::now();
        let cutoff = time::OffsetDateTime::now_utc() - retention;
        let failure = match audit.sweep_expired(database, cutoff).await {
            Ok(swept) => {
                tracing::Span::current().record("sovereign_config.audit.swept", swept);
                if swept > 0 {
                    info!(swept, "expired audit events deleted");
                }
                None
            }
            Err(error) => {
                spans::record_error("storage_unavailable");
                error!(error = %error, "audit retention sweep failed; retrying at the next interval");
                Some("storage_unavailable")
            }
        };
        metrics.record_sweep(started.elapsed(), failure);
    }
    .instrument(tracing::info_span!(
        parent: None,
        "sovereign_config.audit.sweep",
        otel.kind = "internal",
        otel.status_code = tracing::field::Empty,
        error.type = tracing::field::Empty,
        sovereign_config.audit.swept = tracing::field::Empty,
    ))
    .await;
}

/// The gRPC health service with every served service marked serving. The
/// reporter is returned so the caller decides how long it lives.
async fn serving_health_service() -> (HealthReporter, HealthServer<impl Health>) {
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<SystemServer<SystemService>>()
        .await;
    health_reporter
        .set_serving::<ConfigurationServer<ConfigurationService>>()
        .await;
    health_reporter
        .set_serving::<ManagedConnectionsServer<ManagedConnectionsService>>()
        .await;
    health_reporter
        .set_serving::<v4::system_server::SystemServer<V4System>>()
        .await;
    health_reporter
        .set_serving::<v4::configuration_server::ConfigurationServer<V4Configuration>>()
        .await;
    health_reporter
        .set_serving::<v4::managed_connections_server::ManagedConnectionsServer<V4ManagedConnections>>()
        .await;
    health_reporter
        .set_serving::<v4::audit_server::AuditServer<V4Audit>>()
        .await;
    (health_reporter, health_service)
}

async fn healthcheck() -> Result<()> {
    let mut address: SocketAddr = required_env("SOVEREIGN_CONFIG_GRPC_ADDR")?
        .parse()
        .context("SOVEREIGN_CONFIG_GRPC_ADDR must be a socket address")?;
    if address.ip().is_unspecified() {
        address.set_ip(if address.is_ipv4() {
            "127.0.0.1".parse().expect("IPv4 loopback must parse")
        } else {
            "::1".parse().expect("IPv6 loopback must parse")
        });
    }

    let channel = Endpoint::from_shared(format!("http://{address}"))
        .context("unable to configure local gRPC health endpoint")?
        .connect()
        .await
        .context("unable to connect to local gRPC health service")?;
    let mut client = HealthClient::new(channel);
    let response = client
        .check(Request::new(HealthCheckRequest {
            service: SYSTEM_SERVICE_NAME.to_owned(),
        }))
        .await
        .context("local gRPC health check failed")?
        .into_inner();

    if response.status != health_check_response::ServingStatus::Serving as i32 {
        bail!("local gRPC service is not serving");
    }
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    let received_signal = {
        let mut terminate = signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler must install");
        tokio::select! {
            _ = signal::ctrl_c() => "SIGINT",
            _ = terminate.recv() => "SIGTERM",
        }
    };

    #[cfg(not(unix))]
    let received_signal = {
        let _ = signal::ctrl_c().await;
        "SIGINT"
    };

    info!(signal = received_signal, "shutdown signal received");
}

#[cfg(test)]
mod tests {
    use super::{
        APPLICATION_VERSION, SYSTEM_SERVICE_NAME, application_revision, application_version,
        health_router,
    };
    use crate::system::SERVED_PROTOCOL_VERSIONS;

    #[test]
    fn configured_release_version_overrides_cargo_version() {
        assert_eq!(application_version(Some("1.3.42")), "1.3.42");
        assert_eq!(application_version(None), env!("CARGO_PKG_VERSION"));
        assert_eq!(application_version(Some("")), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn an_unstamped_build_reports_an_unknown_revision() {
        assert_eq!(application_revision(Some("a1b2c3d")), "a1b2c3d");
        assert_eq!(application_revision(None), "unknown");
        assert_eq!(application_revision(Some("")), "unknown");
    }

    /// The scrape endpoint is gone — metrics are pushed over OTLP — and the
    /// internal listener keeps only `/readyz`, which still probes the database:
    /// a pool that cannot reach Postgres is not ready.
    #[tokio::test]
    async fn the_internal_listener_serves_readyz_and_no_metrics() {
        use axum::{body::Body, http::Request, http::StatusCode};
        use tower::ServiceExt as _;

        // Lazy: nothing listens on port 1, so every probe fails fast.
        let database = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(200))
            .connect_lazy("postgresql://sovereign_config@127.0.0.1:1/sovereign_config")
            .expect("a lazy pool needs no connection");

        let metrics = health_router(database.clone())
            .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(metrics.status(), StatusCode::NOT_FOUND);

        let ready = health_router(database)
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn compiled_application_version_uses_the_build_release() {
        let expected = option_env!("SOVEREIGN_CONFIG_RELEASE").unwrap_or(env!("CARGO_PKG_VERSION"));
        assert_eq!(APPLICATION_VERSION, expected);
    }

    #[test]
    fn the_health_probe_names_a_served_protocol_package() {
        // The local healthcheck binary asks for this service by name; a
        // retirement that left it naming a deleted package would break the
        // container health probe rather than fail a test.
        assert!(
            SERVED_PROTOCOL_VERSIONS
                .iter()
                .any(|version| SYSTEM_SERVICE_NAME
                    == format!("sovereign.config.{}.System", version.version.as_str())),
            "{SYSTEM_SERVICE_NAME} must name a served protocol version"
        );
    }
}
