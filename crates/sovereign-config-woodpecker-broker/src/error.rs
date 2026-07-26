//! The broker's error surface and its HTTP status mapping.
//!
//! Response bodies match the Go broker's strings exactly, so operators reading
//! Woodpecker's logs see the same text across the cutover.
//!
//! Nothing here carries a configuration value, a path, a token, or any part of
//! the request. Diagnostics that need more detail are logged, not returned.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use sovereign_config_core::{ClientError, ErrorKind};

use crate::signature::SignatureError;

#[derive(Debug, thiserror::Error)]
pub(crate) enum BrokerError {
    #[error("signature verification failed")]
    Unauthorized(SignatureError),
    #[error("invalid request body")]
    InvalidBody,
    #[error("repo and pipeline are required")]
    MissingFields,
    #[error("secret store unavailable")]
    Unavailable,
    #[error("auth unavailable")]
    AuthUnavailable,
    #[error("broker is overloaded")]
    Overloaded,
}

impl BrokerError {
    pub(crate) fn status(&self) -> StatusCode {
        match self {
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::InvalidBody | Self::MissingFields => StatusCode::BAD_REQUEST,
            Self::Unavailable | Self::AuthUnavailable | Self::Overloaded => {
                StatusCode::SERVICE_UNAVAILABLE
            }
        }
    }

    /// A bounded label for the request metric. Never derived from request data.
    pub(crate) fn outcome(&self) -> &'static str {
        match self {
            Self::Unauthorized(_) => "unauthorized",
            Self::InvalidBody | Self::MissingFields => "invalid",
            Self::Unavailable | Self::AuthUnavailable => "unavailable",
            Self::Overloaded => "overloaded",
        }
    }
}

impl IntoResponse for BrokerError {
    fn into_response(self) -> Response {
        let status = self.status();
        // `Overloaded` reports the store's message: from Woodpecker's side a
        // shed request is indistinguishable from an unreachable store, and the
        // distinction is already in the metric.
        let message = match self {
            Self::Overloaded => "secret store unavailable".to_owned(),
            other => other.to_string(),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}

/// Maps a Sovereign Config client error onto the broker's surface.
///
/// `PermissionDenied` and `NotFound` are deliberately absent: a layer the
/// connection may not read, or that does not exist, is skipped by the reader
/// rather than failing the request — matching the Go broker's treatment of
/// `OpenBao` 403 and 404.
impl From<ClientError> for BrokerError {
    fn from(error: ClientError) -> Self {
        match error.kind {
            ErrorKind::Unauthenticated => Self::AuthUnavailable,
            _ => Self::Unavailable,
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::{body::to_bytes, http::StatusCode, response::IntoResponse};
    use sovereign_config_core::{ClientError, ErrorKind};

    use super::BrokerError;
    use crate::signature::SignatureError;

    #[tokio::test]
    async fn every_variant_maps_to_a_status_and_the_go_broker_body() {
        for (error, status, body) in [
            (
                BrokerError::Unauthorized(SignatureError::BadSignature),
                StatusCode::UNAUTHORIZED,
                "signature verification failed",
            ),
            (
                BrokerError::InvalidBody,
                StatusCode::BAD_REQUEST,
                "invalid request body",
            ),
            (
                BrokerError::MissingFields,
                StatusCode::BAD_REQUEST,
                "repo and pipeline are required",
            ),
            (
                BrokerError::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "secret store unavailable",
            ),
            (
                BrokerError::AuthUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "auth unavailable",
            ),
            (
                BrokerError::Overloaded,
                StatusCode::SERVICE_UNAVAILABLE,
                "secret store unavailable",
            ),
        ] {
            let response = error.into_response();
            assert_eq!(response.status(), status);
            let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(json["error"], body);
        }
    }

    #[test]
    fn only_unauthenticated_maps_to_the_auth_surface() {
        for (kind, expected) in [
            (ErrorKind::Unauthenticated, "auth unavailable"),
            (ErrorKind::Unavailable, "secret store unavailable"),
            (ErrorKind::Internal, "secret store unavailable"),
            (ErrorKind::IncompatibleProtocol, "secret store unavailable"),
            (ErrorKind::InvalidRequest, "secret store unavailable"),
            (ErrorKind::Conflict, "secret store unavailable"),
        ] {
            let error: BrokerError = ClientError::new(kind, "bounded").into();
            assert_eq!(error.to_string(), expected);
            assert_eq!(error.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
    }
}
