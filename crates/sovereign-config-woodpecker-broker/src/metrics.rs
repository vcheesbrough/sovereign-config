//! Prometheus metrics and readiness, on a listener separate from `/secrets`.
//!
//! Every label is drawn from a closed set defined here. Nothing derived from a
//! request — repository, branch, path, secret name — is ever a label value:
//! that would make cardinality unbounded and leak the shape of the
//! configuration into the metrics store.

use std::{
    fmt::Write as _,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use axum::{Router, http::StatusCode, response::IntoResponse, routing::get};

use crate::sovereign::SovereignHandle;

/// Request outcomes, matching [`crate::error::BrokerError::outcome`] plus `ok`.
const OUTCOMES: [&str; 6] = [
    "ok",
    "unauthorized",
    "invalid",
    "unavailable",
    "overloaded",
    "reader_gone",
];

const SIGNATURE_REASONS: [&str; 11] = [
    "missing_headers",
    "not_ascii",
    "unknown_label",
    "malformed_input",
    "unexpected_components",
    "unsupported_algorithm",
    "created_out_of_range",
    "missing_digest",
    "malformed_digest",
    "digest_mismatch",
    "bad_signature",
];

#[derive(Default)]
pub(crate) struct Metrics {
    requests: [AtomicU64; OUTCOMES.len()],
    signature_failures: [AtomicU64; SIGNATURE_REASONS.len()],
    secrets_returned: AtomicU64,
}

impl Metrics {
    pub(crate) fn request(&self, outcome: &str, secrets: usize) {
        if let Some(index) = OUTCOMES.iter().position(|known| *known == outcome) {
            self.requests[index].fetch_add(1, Ordering::Relaxed);
        }
        if secrets > 0 {
            self.secrets_returned
                .store(secrets as u64, Ordering::Relaxed);
        }
    }

    pub(crate) fn signature_failure(&self, reason: &str) {
        if let Some(index) = SIGNATURE_REASONS.iter().position(|known| *known == reason) {
            self.signature_failures[index].fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn render(&self) -> String {
        let mut output = String::from(
            "# HELP sovereign_config_broker_up Broker liveness.\n\
             # TYPE sovereign_config_broker_up gauge\n\
             sovereign_config_broker_up 1\n\
             # HELP sovereign_config_broker_requests_total Secret requests by outcome.\n\
             # TYPE sovereign_config_broker_requests_total counter\n",
        );
        for (index, outcome) in OUTCOMES.iter().enumerate() {
            let value = self.requests[index].load(Ordering::Relaxed);
            writeln!(
                output,
                "sovereign_config_broker_requests_total{{outcome=\"{outcome}\"}} {value}"
            )
            .expect("writing metrics to a String cannot fail");
        }

        output.push_str(
            "# HELP sovereign_config_broker_signature_failures_total Rejected signatures by reason.\n\
             # TYPE sovereign_config_broker_signature_failures_total counter\n",
        );
        for (index, reason) in SIGNATURE_REASONS.iter().enumerate() {
            let value = self.signature_failures[index].load(Ordering::Relaxed);
            writeln!(
                output,
                "sovereign_config_broker_signature_failures_total{{reason=\"{reason}\"}} {value}"
            )
            .expect("writing metrics to a String cannot fail");
        }

        writeln!(
            output,
            "# HELP sovereign_config_broker_secrets_returned Secrets returned by the most recent successful request.\n\
             # TYPE sovereign_config_broker_secrets_returned gauge\n\
             sovereign_config_broker_secrets_returned {}",
            self.secrets_returned.load(Ordering::Relaxed)
        )
        .expect("writing metrics to a String cannot fail");
        output
    }
}

#[derive(Clone)]
pub(crate) struct ObservabilityState {
    pub(crate) metrics: Arc<Metrics>,
    pub(crate) sovereign: SovereignHandle,
}

pub(crate) fn router(state: ObservabilityState) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .route("/readyz", get(readyz))
        .with_state(state)
}

async fn metrics(
    axum::extract::State(state): axum::extract::State<ObservabilityState>,
) -> impl IntoResponse {
    (
        [("content-type", "text/plain; version=0.0.4")],
        state.metrics.render(),
    )
}

/// Ready only while the reader thread is alive. A dead reader means every
/// request would 503, and Woodpecker silently falls back to its own store, so
/// this is the signal that must alert.
async fn readyz(
    axum::extract::State(state): axum::extract::State<ObservabilityState>,
) -> impl IntoResponse {
    if state.sovereign.is_live() {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "reader unavailable")
    }
}

#[cfg(test)]
mod tests {
    use super::{Metrics, OUTCOMES, SIGNATURE_REASONS};
    use crate::signature::SignatureError;

    #[test]
    fn every_outcome_and_reason_renders_even_at_zero() {
        let rendered = Metrics::default().render();
        for outcome in OUTCOMES {
            assert!(
                rendered.contains(&format!(
                    "sovereign_config_broker_requests_total{{outcome=\"{outcome}\"}} 0"
                )),
                "missing outcome {outcome}"
            );
        }
        for reason in SIGNATURE_REASONS {
            assert!(
                rendered.contains(&format!(
                    "sovereign_config_broker_signature_failures_total{{reason=\"{reason}\"}} 0"
                )),
                "missing reason {reason}"
            );
        }
    }

    // The reason set here must stay in step with the error enum, or a failure
    // mode becomes invisible exactly when it starts happening.
    #[test]
    fn the_reason_set_covers_every_signature_error() {
        for error in [
            SignatureError::MissingHeaders,
            SignatureError::NotAscii,
            SignatureError::UnknownLabel,
            SignatureError::MalformedInput,
            SignatureError::UnexpectedComponents,
            SignatureError::UnsupportedAlgorithm,
            SignatureError::CreatedOutOfRange,
            SignatureError::MissingDigest,
            SignatureError::MalformedDigest,
            SignatureError::DigestMismatch,
            SignatureError::BadSignature,
        ] {
            assert!(
                SIGNATURE_REASONS.contains(&error.reason()),
                "unlabelled signature error {error:?}"
            );
        }
    }

    #[test]
    fn counters_increment_only_for_known_labels() {
        let metrics = Metrics::default();
        metrics.request("ok", 3);
        metrics.request("ok", 0);
        metrics.request("not-a-known-outcome", 0);
        metrics.signature_failure(SignatureError::DigestMismatch.reason());

        let rendered = metrics.render();
        assert!(rendered.contains("sovereign_config_broker_requests_total{outcome=\"ok\"} 2"));
        assert!(rendered.contains(
            "sovereign_config_broker_signature_failures_total{reason=\"digest_mismatch\"} 1"
        ));
        assert!(rendered.contains("sovereign_config_broker_secrets_returned 3"));
    }
}
