mod auth;
mod config;
mod metrics;
mod values;
mod web;

use std::{env, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tokio::{net::TcpListener, signal};
use tonic::{
    Request, Response, Status,
    transport::{Endpoint, Server},
};
use tonic_health::pb::{HealthCheckRequest, health_check_response, health_client::HealthClient};
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, fmt};

use auth::{Authenticator, grpc_authentication_layer};
use config::{Config, required_env};
use metrics::AuthenticationMetrics;
use sovereign_config_core::PROTOCOL_VERSION;
use sovereign_config_proto::sovereign::config::v3::{
    GetIdentityRequest, GetIdentityResponse, GetVersionRequest, GetVersionResponse,
    configuration_server::ConfigurationServer,
    system_server::{System, SystemServer},
};
use values::ConfigurationService;
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
}

#[derive(Clone, Default)]
struct SystemService;

#[tonic::async_trait]
impl System for SystemService {
    async fn get_version(
        &self,
        request: Request<GetVersionRequest>,
    ) -> Result<Response<GetVersionResponse>, Status> {
        let requested = request.into_inner().protocol_version;
        if requested != PROTOCOL_VERSION {
            return Err(Status::failed_precondition(format!(
                "protocol mismatch: client requested {requested:?}, server requires {PROTOCOL_VERSION}"
            )));
        }

        Ok(Response::new(GetVersionResponse {
            application_version: APPLICATION_VERSION.to_owned(),
            protocol_version: PROTOCOL_VERSION.to_owned(),
        }))
    }

    async fn get_identity(
        &self,
        request: Request<GetIdentityRequest>,
    ) -> Result<Response<GetIdentityResponse>, Status> {
        if request
            .extensions()
            .get::<auth::AuthenticatedPrincipal>()
            .is_none()
        {
            return Err(Status::unauthenticated("authentication required"));
        }
        Ok(Response::new(GetIdentityResponse {
            authenticated: true,
        }))
    }
}

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    match sqlx::query("SELECT 1").execute(&state.database).await {
        Ok(_) => (
            StatusCode::OK,
            format!(
                "sovereign_config_up 1\n{}",
                state.authentication_metrics.render()
            ),
        ),
        Err(error) => {
            error!(error = %error, "database health probe failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                format!(
                    "sovereign_config_up 0\n{}",
                    state.authentication_metrics.render()
                ),
            )
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

    fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Config::from_env()?;
    let web_assets = WebAssetsLayer::new(&config.web);
    let authenticator = Authenticator::new(config.authentication)?;
    let authentication_metrics = Arc::new(AuthenticationMetrics::default());
    let database = PgPoolOptions::new()
        .acquire_timeout(Duration::from_secs(5))
        .connect(&config.database_url)
        .await
        .map_err(|_| anyhow::anyhow!("unable to connect to required PostgreSQL dependency"))?;
    sqlx::migrate!("./migrations")
        .run(&database)
        .await
        .context("database migration failed")?;

    let state = AppState {
        database,
        authentication_metrics: Arc::clone(&authentication_metrics),
    };
    let metrics_app = Router::new()
        .route("/metrics", get(metrics))
        .route("/readyz", get(ready))
        .with_state(state.clone());
    let metrics_listener = TcpListener::bind(config.metrics_addr)
        .await
        .context("unable to bind metrics listener")?;
    tokio::spawn(async move {
        if let Err(error) = axum::serve(metrics_listener, metrics_app).await {
            error!(error = %error, "metrics server terminated");
        }
    });

    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<SystemServer<SystemService>>()
        .await;
    health_reporter
        .set_serving::<ConfigurationServer<ConfigurationService>>()
        .await;

    info!(grpc_addr = %config.grpc_addr, metrics_addr = %config.metrics_addr, protocol_version = PROTOCOL_VERSION, "sovereign-config started");
    Server::builder()
        .accept_http1(true)
        .layer(grpc_authentication_layer(
            authenticator,
            authentication_metrics,
        ))
        .layer(web_assets)
        .add_service(health_service)
        .add_service(SystemServer::new(SystemService))
        .add_service(ConfigurationServer::new(ConfigurationService::new(
            state.database.clone(),
        )))
        .serve_with_shutdown(config.grpc_addr, shutdown_signal())
        .await
        .context("gRPC server terminated")
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
    use tonic::Code;

    use super::{
        APPLICATION_VERSION, PROTOCOL_VERSION, System, SystemService, application_version,
    };
    use sovereign_config_proto::sovereign::config::v3::GetVersionRequest;
    use tonic::Request;

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

    #[tokio::test]
    async fn version_rejects_protocol_mismatch() {
        let result = SystemService
            .get_version(Request::new(GetVersionRequest {
                protocol_version: "v999".to_owned(),
            }))
            .await;

        let status = result.expect_err("mismatched protocol must be rejected");
        assert_eq!(status.code(), Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn version_returns_the_current_protocol() {
        let response = SystemService
            .get_version(Request::new(GetVersionRequest {
                protocol_version: PROTOCOL_VERSION.to_owned(),
            }))
            .await
            .expect("matching protocol must succeed")
            .into_inner();

        assert_eq!(response.protocol_version, PROTOCOL_VERSION);
        assert_eq!(response.application_version, APPLICATION_VERSION);
    }
}
