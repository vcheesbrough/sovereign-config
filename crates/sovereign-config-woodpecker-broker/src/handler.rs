//! The two HTTP endpoints Woodpecker talks to.

use std::{sync::Arc, time::SystemTime};

use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Uri},
    response::IntoResponse,
    routing::{get, post},
};
use serde_json::json;

use crate::{
    error::BrokerError,
    layers::LayerTemplates,
    metrics::Metrics,
    model::{SecretsRequest, SecretsResponse},
    signature::SignatureVerifier,
    sovereign::SovereignHandle,
};

/// A pipeline payload with `changed_files` can be sizeable, but nowhere near
/// this; the cap keeps an unauthenticated POST from buffering without bound.
const MAX_BODY_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) verifier: Arc<SignatureVerifier>,
    pub(crate) layers: Arc<LayerTemplates>,
    pub(crate) sovereign: SovereignHandle,
    pub(crate) metrics: Arc<Metrics>,
}

pub(crate) fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/secrets", post(secrets))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

/// Unauthenticated liveness, matching the Go broker's `/health`.
async fn health() -> impl IntoResponse {
    Json(json!({"status": "ok"}))
}

/// Resolves the secrets for one pipeline.
///
/// Order matters: the signature is verified over the **raw bytes** before the
/// body is parsed, so an unsigned request is rejected 401 without the broker
/// ever interpreting its content — and a malformed body from an authentic
/// Woodpecker is still reported as 400 rather than hidden behind the 401.
async fn secrets(
    State(state): State<AppState>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<SecretsResponse>, BrokerError> {
    let outcome = resolve(&state, &uri, &headers, &body).await;
    match &outcome {
        Ok(response) => state.metrics.request("ok", response.secrets.len()),
        Err(error) => {
            if let BrokerError::Unauthorized(reason) = error {
                state.metrics.signature_failure(reason.reason());
            }
            state.metrics.request(error.outcome(), 0);
        }
    }
    outcome.map(Json)
}

async fn resolve(
    state: &AppState,
    uri: &Uri,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<SecretsResponse, BrokerError> {
    let request_target = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_owned(), ToString::to_string);
    state
        .verifier
        .verify(&request_target, headers, body, SystemTime::now())
        .map_err(BrokerError::Unauthorized)?;

    // Serde rejects a body whose `repo` or `pipeline` is absent or null, which
    // is the same condition the Go broker reports separately; distinguish them
    // so the operator-visible message matches.
    let request: SecretsRequest = serde_json::from_slice(body).map_err(|_| {
        match serde_json::from_slice::<serde_json::Value>(body) {
            Ok(value) => {
                if value.get("repo").is_none_or(serde_json::Value::is_null)
                    || value.get("pipeline").is_none_or(serde_json::Value::is_null)
                {
                    BrokerError::MissingFields
                } else {
                    BrokerError::InvalidBody
                }
            }
            Err(_) => BrokerError::InvalidBody,
        }
    })?;

    let layers = state.layers.render(state.sovereign.root(), &request);
    let values = state.sovereign.fetch(layers).await?;
    Ok(SecretsResponse::build(values))
}
