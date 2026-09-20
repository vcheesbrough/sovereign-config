//! Bounded error surface for tool execution.
//!
//! A [`ToolFailure`] carries a stable machine label and a bounded message. It
//! is built exclusively from caller-independent sources — the client library's
//! own error messages and this crate's fixed validation strings — so a failure
//! can never echo a path, value, secret, subject, grant, or provider URL back
//! to the caller or into diagnostics.
//!
//! A few of the library's messages are assembled at run time rather than being
//! `&'static`: the incompatible-version one names the version lists both ends
//! offered, which cannot be known at compile time. Those are bounded and
//! stripped in `sovereign-config-core` before they get here, and they carry no
//! caller input — a version identifier is not something a tool call supplies.

use sovereign_config_core::{ClientError, ErrorKind};

/// A recoverable tool-execution failure surfaced to the MCP caller as an
/// `isError` tool result rather than a transport-level JSON-RPC error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolFailure {
    /// Stable machine-readable category, safe to branch on.
    pub code: &'static str,
    /// Bounded, caller-independent human message.
    pub message: String,
}

impl ToolFailure {
    #[must_use]
    pub fn new(code: &'static str, message: &str) -> Self {
        Self {
            code,
            message: message.to_owned(),
        }
    }

    /// Maps a client/gRPC error to a bounded tool failure. The label mirrors the
    /// originating status class; the message is the library's own bounded
    /// string, never a formatted argument of this crate's own.
    #[must_use]
    pub fn from_client(error: &ClientError) -> Self {
        let code = match error.kind {
            ErrorKind::Unauthenticated => "unauthenticated",
            ErrorKind::PermissionDenied => "permission_denied",
            ErrorKind::IncompatibleProtocol => "incompatible_protocol",
            ErrorKind::VersionNotServed => "version_not_served",
            ErrorKind::InvalidRequest => "invalid_request",
            ErrorKind::NotFound => "not_found",
            ErrorKind::Conflict => "conflict",
            ErrorKind::Unavailable => "unavailable",
            ErrorKind::Internal => "internal",
        };
        Self {
            code,
            message: error.message().to_owned(),
        }
    }
}

impl From<ClientError> for ToolFailure {
    fn from(error: ClientError) -> Self {
        Self::from_client(&error)
    }
}

#[cfg(test)]
mod tests {
    use sovereign_config_core::{ClientError, ErrorKind};

    use super::ToolFailure;

    #[test]
    fn every_error_kind_maps_to_a_stable_bounded_label() {
        for (kind, code) in [
            (ErrorKind::Unauthenticated, "unauthenticated"),
            (ErrorKind::PermissionDenied, "permission_denied"),
            (ErrorKind::IncompatibleProtocol, "incompatible_protocol"),
            (ErrorKind::InvalidRequest, "invalid_request"),
            (ErrorKind::NotFound, "not_found"),
            (ErrorKind::Unavailable, "unavailable"),
            (ErrorKind::Internal, "internal"),
        ] {
            let failure = ToolFailure::from(ClientError::new(kind, "bounded message"));
            assert_eq!(failure.code, code);
            assert_eq!(failure.message, "bounded message");
        }
    }
}
