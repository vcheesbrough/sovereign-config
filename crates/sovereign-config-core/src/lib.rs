#![forbid(unsafe_code)]

mod connection;

use core::fmt;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROTOCOL_VERSION: &str = "v1";

pub use connection::{ConnectionUrl, ConnectionUrlError};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PathError {
    #[error("path must be canonical")]
    NonCanonical,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ConfigPath(String);

impl ConfigPath {
    #[must_use]
    pub fn root() -> Self {
        Self(String::new())
    }

    /// Parses an empty root path or a slash-separated lowercase path.
    ///
    /// # Errors
    ///
    /// Returns [`PathError::NonCanonical`] when a segment is empty or contains
    /// characters outside lowercase ASCII letters, digits, and `-`.
    pub fn parse(value: impl Into<String>) -> Result<Self, PathError> {
        let value = value.into();
        if value.is_empty()
            || value.split('/').all(|segment| {
                !segment.is_empty()
                    && segment.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
        {
            Ok(Self(value))
        } else {
            Err(PathError::NonCanonical)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ConfigPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ConfigValue {
    Null,
    Boolean(bool),
    Integer(i64),
    String(String),
    Sequence(Vec<ConfigValue>),
    Object(BTreeMap<String, ConfigValue>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceStatus {
    pub application_version: String,
    pub protocol_version: String,
    pub compatible: bool,
}

impl ServiceStatus {
    #[must_use]
    pub fn negotiate(application_version: String, protocol_version: String) -> Self {
        let compatible = protocol_version == PROTOCOL_VERSION;
        Self {
            application_version,
            protocol_version,
            compatible,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticationStatus {
    pub authenticated: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    Unauthenticated,
    PermissionDenied,
    IncompatibleProtocol,
    InvalidRequest,
    Unavailable,
    Internal,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{message}")]
pub struct ClientError {
    pub kind: ErrorKind,
    message: &'static str,
}

impl ClientError {
    #[must_use]
    pub const fn new(kind: ErrorKind, message: &'static str) -> Self {
        Self { kind, message }
    }

    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret([REDACTED])")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

#[cfg(test)]
mod tests {
    use super::{ConfigPath, ErrorKind, PROTOCOL_VERSION, Secret, ServiceStatus};

    #[test]
    fn paths_are_canonical_and_root_is_explicit() {
        assert_eq!(ConfigPath::root().as_str(), "");
        assert!(ConfigPath::parse("apps/api-v2").is_ok());
        for invalid in ["/apps", "apps/", "apps//api", "Apps", "apps_api"] {
            assert!(ConfigPath::parse(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn protocol_negotiation_is_exact() {
        assert!(ServiceStatus::negotiate("1.3.0".into(), PROTOCOL_VERSION.into()).compatible);
        assert!(!ServiceStatus::negotiate("1.3.0".into(), "v2".into()).compatible);
    }

    #[test]
    fn secrets_are_redacted_in_all_formatters() {
        let secret = Secret::new("credential-sentinel");
        assert_eq!(secret.to_string(), "[REDACTED]");
        assert_eq!(format!("{secret:?}"), "Secret([REDACTED])");
        assert_eq!(secret.expose(), "credential-sentinel");
    }

    #[test]
    fn errors_expose_only_bounded_messages() {
        let error = super::ClientError::new(ErrorKind::Unavailable, "service unavailable");
        assert_eq!(error.to_string(), "service unavailable");
    }
}
