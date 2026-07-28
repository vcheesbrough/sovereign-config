//! Woodpecker CI external secrets extension backed by Sovereign Config.
//!
//! Woodpecker resolves pipeline secrets by `POSTing` signed repository and
//! pipeline metadata to a single configured extension endpoint. This binary is
//! that endpoint: it verifies the signature, renders the configured layers for
//! the repository being built, reads them through a read-only managed
//! connection, and returns the merged result in Woodpecker's secret format.
//!
//! It replaces `woodpecker-openbao-broker` and is wire-compatible with it, so
//! no pipeline YAML changes at the cutover. See `README.md` in this crate for
//! the environment surface, the threat model, and the cutover runbook.

mod config;
mod error;
mod handler;
mod layers;
mod metrics;
mod model;
mod pubkey;
mod signature;
mod sovereign;
#[cfg(test)]
mod tests;

use std::{env, process::ExitCode, sync::Arc, time::Duration};

use tracing_subscriber::{EnvFilter, fmt};

use crate::{
    config::Config,
    handler::AppState,
    metrics::{Metrics, ObservabilityState},
};

const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(3);

#[tokio::main]
async fn main() -> ExitCode {
    match env::args().nth(1).as_deref() {
        Some("healthcheck") => healthcheck().await,
        Some("--version") => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        _ => match serve().await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                // Startup failures are reported as bounded text: a
                // misconfiguration must be diagnosable without any value,
                // token, or URL reaching the log.
                tracing::error!(error = %error, "broker failed to start");
                ExitCode::FAILURE
            }
        },
    }
}

async fn serve() -> Result<(), Box<dyn std::error::Error>> {
    fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Config::from_env()?;
    let verifier = pubkey::load(&config.public_key).await?;

    // Connecting here, before the listeners bind, means a bad connection URL or
    // a protocol mismatch fails the container rather than every pipeline.
    let sovereign = sovereign::spawn(config.connection_url, config.queue_depth, config.token_ttl)?;
    tracing::info!(
        root = %sovereign.root().as_str(),
        layers = ?config.layers.specs(),
        "connected to the configuration service"
    );

    let metrics = Arc::new(Metrics::default());
    let requests = handler::router(AppState {
        verifier: Arc::new(verifier),
        layers: Arc::new(config.layers),
        sovereign: sovereign.clone(),
        metrics: Arc::clone(&metrics),
    });
    let observability = metrics::router(ObservabilityState { metrics, sovereign });

    let request_listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    let observability_listener = tokio::net::TcpListener::bind(config.metrics_addr).await?;
    tracing::info!(
        listen = %config.listen_addr,
        metrics = %config.metrics_addr,
        "broker listening"
    );

    tokio::select! {
        result = axum::serve(request_listener, requests).with_graceful_shutdown(shutdown()) => result?,
        result = axum::serve(observability_listener, observability) => result?,
    }
    Ok(())
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
}

/// In-process liveness probe for the container `HEALTHCHECK`.
///
/// Calls the broker's own `/health` over loopback so the runtime image needs no
/// `curl`.
async fn healthcheck() -> ExitCode {
    // Resolved through the same function the server uses, so an address the
    // server accepts is never one the healthcheck rejects. An address that
    // fails here would also have failed startup.
    let Ok(mut address) = config::listen_addr(&config::ProcessEnv) else {
        return ExitCode::FAILURE;
    };
    if address.ip().is_unspecified() {
        address.set_ip(if address.is_ipv4() {
            "127.0.0.1".parse().expect("IPv4 loopback must parse")
        } else {
            "::1".parse().expect("IPv6 loopback must parse")
        });
    }
    probe(&address.to_string()).await
}

async fn probe(address: &str) -> ExitCode {
    let Ok(client) = reqwest::Client::builder()
        .timeout(HEALTHCHECK_TIMEOUT)
        .build()
    else {
        return ExitCode::FAILURE;
    };
    match client.get(format!("http://{address}/health")).send().await {
        Ok(response) if response.status().is_success() => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}
