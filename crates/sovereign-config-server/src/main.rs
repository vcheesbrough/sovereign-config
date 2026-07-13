use std::{env, fs, net::SocketAddr, time::Duration};

use anyhow::{Context, Result, bail};
use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tokio::{net::TcpListener, signal};
use tonic::{Request, Response, Status, transport::Server};
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, fmt};

use sovereign_config_proto::sovereign::config::v1::{
    GetVersionRequest, GetVersionResponse,
    system_server::{System, SystemServer},
};

const PROTOCOL_VERSION: &str = "v1";
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
}

#[derive(Clone)]
struct Config {
    database_url: String,
    grpc_addr: SocketAddr,
    metrics_addr: SocketAddr,
}

impl Config {
    fn from_env() -> Result<Self> {
        let database_url = required_secret("SOVEREIGN_CONFIG_DATABASE_URL")?;
        let grpc_addr = required_env("SOVEREIGN_CONFIG_GRPC_ADDR")?
            .parse()
            .context("SOVEREIGN_CONFIG_GRPC_ADDR must be a socket address")?;
        let metrics_addr = required_env("SOVEREIGN_CONFIG_METRICS_ADDR")?
            .parse()
            .context("SOVEREIGN_CONFIG_METRICS_ADDR must be a socket address")?;

        if grpc_addr == metrics_addr {
            bail!("gRPC and metrics listeners must use different addresses");
        }

        Ok(Self {
            database_url,
            grpc_addr,
            metrics_addr,
        })
    }
}

fn required_env(name: &str) -> Result<String> {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        _ => bail!("required configuration {name} is missing or empty"),
    }
}

fn required_secret(name: &str) -> Result<String> {
    if let Ok(value) = env::var(name)
        && !value.trim().is_empty()
    {
        return Ok(value);
    }

    let file_name = format!("{name}_FILE");
    let path = required_env(&file_name)?;
    let value = fs::read_to_string(&path).with_context(|| format!("unable to read {file_name}"))?;
    if value.trim().is_empty() {
        bail!("{file_name} points to an empty secret file");
    }
    Ok(value.trim().to_owned())
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
}

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    match sqlx::query("SELECT 1").execute(&state.database).await {
        Ok(_) => (StatusCode::OK, "sovereign_config_up 1\n"),
        Err(error) => {
            error!(error = %error, "database health probe failed");
            (StatusCode::SERVICE_UNAVAILABLE, "sovereign_config_up 0\n")
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
    fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Config::from_env()?;
    let database = PgPoolOptions::new()
        .acquire_timeout(Duration::from_secs(5))
        .connect(&config.database_url)
        .await
        .map_err(|_| anyhow::anyhow!("unable to connect to required PostgreSQL dependency"))?;
    sqlx::migrate!("./migrations")
        .run(&database)
        .await
        .context("database migration failed")?;

    let state = AppState { database };
    let metrics_app = Router::new()
        .route("/metrics", get(metrics))
        .route("/readyz", get(ready))
        .with_state(state);
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

    info!(grpc_addr = %config.grpc_addr, metrics_addr = %config.metrics_addr, protocol_version = PROTOCOL_VERSION, "sovereign-config started");
    Server::builder()
        .add_service(health_service)
        .add_service(SystemServer::new(SystemService))
        .serve_with_shutdown(config.grpc_addr, shutdown_signal())
        .await
        .context("gRPC server terminated")
}

async fn shutdown_signal() {
    let _ = signal::ctrl_c().await;
    info!("shutdown signal received");
}

#[cfg(test)]
mod tests {
    use tonic::Code;

    use super::{
        APPLICATION_VERSION, PROTOCOL_VERSION, System, SystemService, application_version,
        required_env,
    };
    use sovereign_config_proto::sovereign::config::v1::GetVersionRequest;
    use tonic::Request;

    #[test]
    fn required_env_rejects_missing_values() {
        assert!(required_env("SOVEREIGN_CONFIG_TEST_UNSET_6F63A8D9").is_err());
    }

    #[test]
    fn configured_release_version_overrides_cargo_version() {
        assert_eq!(application_version(Some("1.1.42")), "1.1.42");
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
