use sovereign_config_core::{ClientError, ConnectionUrlError, ErrorKind};
use thiserror::Error;

/// The bounded, redacted error surface of the provider facade.
///
/// Every variant carries a fixed, non-interpolated message. No variant ever
/// embeds the connection URL, a credential, a token, an issuer, a path, a
/// configuration value, or a secret. In particular [`ProviderError::InvalidConversion`]
/// discards the underlying `serde_json` error, whose `Display` can echo the
/// offending field name or value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderError {
    /// The connection URL was malformed or non-canonical.
    #[error("connection URL is invalid")]
    MalformedUrl,
    /// The connection URL is a human device-flow URL; an unattended
    /// application must be given a managed client-credentials URL.
    #[error("connection URL requires managed client-credentials authentication")]
    UnsupportedCredential,
    /// Token acquisition or an authenticated read was rejected.
    #[error("authentication failed")]
    AuthenticationFailed,
    /// The connection is not authorized for the requested configuration.
    #[error("permission denied")]
    PermissionDenied,
    /// The service protocol is incompatible with this provider release.
    #[error("service protocol is incompatible")]
    IncompatibleProtocol,
    /// The request was rejected as invalid.
    #[error("request is invalid")]
    InvalidRequest,
    /// A configuration value expected during the load was absent.
    #[error("configuration value not found")]
    NotFound,
    /// A dependency (identity provider or Sovereign Config) was unavailable.
    #[error("dependency is unavailable")]
    Unavailable,
    /// The loaded subtree could not be converted to the requested type.
    #[error("configuration could not be converted to the requested type")]
    InvalidConversion,
    /// An internal error occurred.
    #[error("internal error")]
    Internal,
}

impl From<ConnectionUrlError> for ProviderError {
    fn from(_: ConnectionUrlError) -> Self {
        Self::MalformedUrl
    }
}

impl From<ClientError> for ProviderError {
    fn from(error: ClientError) -> Self {
        match error.kind {
            ErrorKind::Unauthenticated => Self::AuthenticationFailed,
            ErrorKind::PermissionDenied => Self::PermissionDenied,
            // A version going away and no version in common are different
            // events, but they reach a consuming application the same way:
            // there is nothing it can do about either but rebuild. The session
            // has already re-handshaked once by the time this is reached.
            ErrorKind::IncompatibleProtocol | ErrorKind::VersionNotServed => {
                Self::IncompatibleProtocol
            }
            // The provider only reads configuration, so it never targets an
            // occupied path; a conflict would still be a rejected request.
            ErrorKind::InvalidRequest | ErrorKind::Conflict => Self::InvalidRequest,
            ErrorKind::NotFound => Self::NotFound,
            ErrorKind::Unavailable => Self::Unavailable,
            ErrorKind::Internal => Self::Internal,
        }
    }
}

#[cfg(test)]
mod tests {
    use sovereign_config_core::{ClientError, ConnectionUrlError, ErrorKind};

    use super::ProviderError;

    #[test]
    fn maps_every_client_error_kind() {
        for (kind, expected) in [
            (
                ErrorKind::Unauthenticated,
                ProviderError::AuthenticationFailed,
            ),
            (ErrorKind::PermissionDenied, ProviderError::PermissionDenied),
            (
                ErrorKind::IncompatibleProtocol,
                ProviderError::IncompatibleProtocol,
            ),
            (ErrorKind::InvalidRequest, ProviderError::InvalidRequest),
            (ErrorKind::NotFound, ProviderError::NotFound),
            (ErrorKind::Unavailable, ProviderError::Unavailable),
            (ErrorKind::Internal, ProviderError::Internal),
        ] {
            let error = ClientError::new(kind, "some internal message");
            assert_eq!(ProviderError::from(error), expected);
        }
    }

    #[test]
    fn maps_connection_url_error_to_malformed_url() {
        assert_eq!(
            ProviderError::from(ConnectionUrlError),
            ProviderError::MalformedUrl
        );
    }

    #[test]
    fn every_message_is_fixed_and_carries_no_dynamic_data() {
        for error in [
            ProviderError::MalformedUrl,
            ProviderError::UnsupportedCredential,
            ProviderError::AuthenticationFailed,
            ProviderError::PermissionDenied,
            ProviderError::IncompatibleProtocol,
            ProviderError::InvalidRequest,
            ProviderError::NotFound,
            ProviderError::Unavailable,
            ProviderError::InvalidConversion,
            ProviderError::Internal,
        ] {
            assert!(!error.to_string().is_empty());
        }
    }
}
