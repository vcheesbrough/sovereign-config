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
mod system;
mod values;
mod web;

use std::{env, net::SocketAddr, sync::Arc, time::Duration};

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
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, fmt};

use audit::{AuditRecorder, AuditTrailService, v4::V4Audit};
use auth::{Authenticator, grpc_service_layer};
use authentik::AuthentikAdminClient;
use config::{Config, ManagedConnectionConfig, required_env};
use handshake::HandshakeService;
use managed::{
    ManagedConnectionsService, ManagedSettings, V3ManagedConnections, V4ManagedConnections,
};
use metrics::{AuditMetrics, AuthenticationMetrics, ManagedConnectionMetrics, ProtocolMetrics};
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
use system::{SERVED_PROTOCOL_LABELS, SystemService, V4System};
use values::{ConfigurationService, V3Configuration, V4Configuration, encrypt_stored_secrets};
use web::WebAssetsLayer;

const SYSTEM_SERVICE_NAME: &str = "sovereign.config.v3.System";
const APPLICATION_VERSION: &str = application_version(option_env!("SOVEREIGN_CONFIG_RELEASE"));

const fn application_version(release_version: Option<&str>) -> &str {
    match release_version {
        Some(version) if !version.is_empty() => version,
        _ => env!("CARGO_PKG_VERSION"),
    }
}

#[derive(Clone)]
struct AppState {
    database: PgPool,
    authentication_metrics: Arc<AuthenticationMetrics>,
    managed_metrics: Arc<ManagedConnectionMetrics>,
    protocol_metrics: Arc<ProtocolMetrics>,
    audit_metrics: Arc<AuditMetrics>,
}

impl AppState {
    fn render_metrics(&self, up: u8) -> String {
        format!(
            "sovereign_config_up {up}\n{}{}{}{}",
            self.authentication_metrics.render(),
            self.managed_metrics.render(),
            self.protocol_metrics.render(),
            self.audit_metrics.render(),
        )
    }
}

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    match sqlx::query("SELECT 1").execute(&state.database).await {
        Ok(_) => (StatusCode::OK, state.render_metrics(1)),
        Err(error) => {
            error!(error = %error, "database health probe failed");
            (StatusCode::SERVICE_UNAVAILABLE, state.render_metrics(0))
        }
    }
}

async fn ready(State(state): State<AppState>) -> impl IntoResponse {
    match sqlx::query("SELECT 1").execute(&state.database).await {
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
    init_logging();

    let config = Config::from_env()?;
    let web_assets = WebAssetsLayer::new(&config.web);
    let authenticator = Authenticator::new(config.authentication)?;
    let authentication_metrics = Arc::new(AuthenticationMetrics::default());
    let managed_metrics = Arc::new(ManagedConnectionMetrics::default());
    let protocol_metrics = Arc::new(ProtocolMetrics::new(SERVED_PROTOCOL_LABELS));
    let audit_metrics = Arc::new(AuditMetrics::default());
    let audit = AuditRecorder::new(Arc::clone(&audit_metrics), config.audit.coalesce_window);
    let (managed_admin, managed_settings) = managed_dependencies(config.managed)?;
    let database = connect_database(&config.database_url).await?;
    let value_cipher = Arc::new(config.value_cipher);
    encrypt_stored_secrets(&database, &value_cipher).await?;

    let state = AppState {
        database,
        authentication_metrics: Arc::clone(&authentication_metrics),
        managed_metrics: Arc::clone(&managed_metrics),
        protocol_metrics: Arc::clone(&protocol_metrics),
        audit_metrics,
    };
    spawn_metrics_server(config.metrics_addr, state.clone()).await?;
    spawn_audit_retention_sweep(
        state.database.clone(),
        audit.clone(),
        config.audit.retention,
    );
    let (_health_reporter, health_service) = serving_health_service().await;
    // One implementation of each service, whatever the number of protocol
    // versions served: every version registered below is a shim over these.
    let configuration = Arc::new(ConfigurationService::new(
        state.database.clone(),
        Arc::clone(&value_cipher),
        audit.clone(),
    ));
    let managed_connections = Arc::new(ManagedConnectionsService::new(
        state.database.clone(),
        managed_admin,
        managed_settings,
        managed_metrics,
        audit,
    ));
    let audit_trail = Arc::new(AuditTrailService::new(
        state.database.clone(),
        config.audit.page_size,
    ));

    info!(
        grpc_addr = %config.grpc_addr,
        metrics_addr = %config.metrics_addr,
        protocol_versions = SERVED_PROTOCOL_LABELS.join(","),
        "sovereign-config started"
    );
    Server::builder()
        .accept_http1(true)
        // Outermost, so every request is attributed to the protocol version its
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

/// Structured JSON logs to stdout, filtered by `RUST_LOG`-style environment
/// configuration and defaulting to `info`.
fn init_logging() {
    fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
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
/// forward-only migrations before anything can serve.
async fn connect_database(database_url: &str) -> Result<PgPool> {
    let database = PgPoolOptions::new()
        .acquire_timeout(Duration::from_secs(5))
        .connect(database_url)
        .await
        .map_err(|_| anyhow::anyhow!("unable to connect to required PostgreSQL dependency"))?;
    sqlx::migrate!("./migrations")
        .run(&database)
        .await
        .context("database migration failed")?;
    Ok(database)
}

/// Serves `/metrics` and `/readyz` on the internal metrics listener in the
/// background. Binding happens before this returns, so a taken port fails
/// startup.
async fn spawn_metrics_server(address: SocketAddr, state: AppState) -> Result<()> {
    let metrics_app = Router::new()
        .route("/metrics", get(metrics))
        .route("/readyz", get(ready))
        .with_state(state);
    let metrics_listener = TcpListener::bind(address)
        .await
        .context("unable to bind metrics listener")?;
    tokio::spawn(async move {
        if let Err(error) = axum::serve(metrics_listener, metrics_app).await {
            error!(error = %error, "metrics server terminated");
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
fn spawn_audit_retention_sweep(database: PgPool, audit: AuditRecorder, retention: Duration) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(AUDIT_SWEEP_INTERVAL);
        loop {
            interval.tick().await;
            let cutoff = time::OffsetDateTime::now_utc() - retention;
            match audit.sweep_expired(&database, cutoff).await {
                Ok(0) => {}
                Ok(swept) => info!(swept, "expired audit events deleted"),
                Err(error) => error!(error = %error, "audit retention sweep failed"),
            }
        }
    });
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
    use super::{APPLICATION_VERSION, SYSTEM_SERVICE_NAME, application_version};
    use crate::system::SERVED_PROTOCOL_VERSIONS;

    #[test]
    fn configured_release_version_overrides_cargo_version() {
        assert_eq!(application_version(Some("1.3.42")), "1.3.42");
        assert_eq!(application_version(None), env!("CARGO_PKG_VERSION"));
        assert_eq!(application_version(Some("")), env!("CARGO_PKG_VERSION"));
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
