#![forbid(unsafe_code)]

mod connection;

use core::fmt;
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
        Self("/".into())
    }

    /// Parses a rooted lowercase path, including the `/` root path.
    ///
    /// # Errors
    ///
    /// Returns [`PathError::NonCanonical`] when the path is not rooted, a segment
    /// is empty, or it contains characters outside lowercase ASCII letters,
    /// digits, and `-`.
    pub fn parse(value: impl Into<String>) -> Result<Self, PathError> {
        let value = value.into();
        if value == "/"
            || value.strip_prefix('/').is_some_and(|relative| {
                !relative.is_empty()
                    && relative.split('/').all(|segment| {
                        !segment.is_empty()
                            && segment.bytes().all(|byte| {
                                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                            })
                    })
            })
        {
            Ok(Self(value))
        } else {
            Err(PathError::NonCanonical)
        }
    }

    /// Parses a non-root absolute operation path and normalizes ASCII letters to lowercase.
    ///
    /// # Errors
    ///
    /// Returns [`PathError::NonCanonical`] for root or unrooted paths, empty
    /// segments, non-ASCII text, percent encoding, or characters other than
    /// ASCII letters, digits, and `-`.
    pub fn parse_operation(value: impl AsRef<str>) -> Result<Self, PathError> {
        let value = value.as_ref();
        let Some(relative) = value.strip_prefix('/') else {
            return Err(PathError::NonCanonical);
        };
        if relative.is_empty()
            || !relative.split('/').all(|segment| {
                !segment.is_empty()
                    && segment.bytes().all(|byte| {
                        byte.is_ascii_alphabetic() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
        {
            return Err(PathError::NonCanonical);
        }
        Self::parse(value.to_ascii_lowercase())
    }

    /// Appends one value name to a canonical rooted namespace.
    ///
    /// # Errors
    ///
    /// Returns [`PathError::NonCanonical`] when `name` is not one valid path
    /// segment.
    pub fn join_name(&self, name: impl AsRef<str>) -> Result<Self, PathError> {
        let name = name.as_ref();
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphabetic() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(PathError::NonCanonical);
        }
        let name = name.to_ascii_lowercase();
        if self.0 == "/" {
            Self::parse(format!("/{name}"))
        } else {
            Self::parse(format!("{}/{name}", self.0))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Plain configuration text that must be exposed explicitly.
#[derive(Clone, Default, Deserialize, Eq, PartialEq)]
#[serde(transparent)]
pub struct PlainValue(String);

impl PlainValue {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Debug for PlainValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PlainValue([REDACTED])")
    }
}

impl fmt::Display for PlainValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanos: i32,
}

impl Timestamp {
    /// Converts a system timestamp into the protocol-neutral representation.
    ///
    /// # Errors
    ///
    /// Returns an error for times before the Unix epoch or values outside the
    /// representable range.
    pub fn from_system_time(value: SystemTime) -> Result<Self, ClientError> {
        let duration = value.duration_since(UNIX_EPOCH).map_err(|_| {
            ClientError::new(ErrorKind::Internal, "service returned an invalid timestamp")
        })?;
        Ok(Self {
            seconds: i64::try_from(duration.as_secs()).map_err(|_| {
                ClientError::new(ErrorKind::Internal, "service returned an invalid timestamp")
            })?,
            nanos: i32::try_from(duration.subsec_nanos()).map_err(|_| invalid_timestamp())?,
        })
    }

    /// Converts this timestamp to [`SystemTime`].
    ///
    /// # Errors
    ///
    /// Returns an error when seconds or nanoseconds are negative or overflow.
    pub fn to_system_time(self) -> Result<SystemTime, ClientError> {
        let seconds = u64::try_from(self.seconds).map_err(|_| invalid_timestamp())?;
        let nanos = u32::try_from(self.nanos).map_err(|_| invalid_timestamp())?;
        if nanos >= 1_000_000_000 {
            return Err(invalid_timestamp());
        }
        UNIX_EPOCH
            .checked_add(Duration::new(seconds, nanos))
            .ok_or_else(invalid_timestamp)
    }
}

fn invalid_timestamp() -> ClientError {
    ClientError::new(ErrorKind::Internal, "service returned an invalid timestamp")
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExactValue {
    pub value: PlainValue,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListedValue {
    pub path: ConfigPath,
    pub value: PlainValue,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValueListing {
    pub values: Vec<ListedValue>,
    pub paths: Vec<ConfigPath>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PutMetadata {
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteMetadata {
    pub deleted_at: Timestamp,
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
    NotFound,
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

/// An authentication or connection credential that requires explicit exposure.
///
/// Secrets deliberately do not implement Serde's serialization traits.
///
/// ```compile_fail
/// use serde::Serialize;
/// use sovereign_config_core::Secret;
///
/// fn assert_serializable<T: Serialize>() {}
/// assert_serializable::<Secret>();
/// ```
///
/// ```compile_fail
/// use serde::Deserialize;
/// use sovereign_config_core::Secret;
///
/// fn assert_deserializable<T: for<'de> Deserialize<'de>>() {}
/// assert_deserializable::<Secret>();
/// ```
#[derive(Clone)]
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
    use super::{ConfigPath, ErrorKind, PROTOCOL_VERSION, PlainValue, Secret, ServiceStatus};

    #[test]
    fn paths_are_canonical_and_root_is_explicit() {
        assert_eq!(ConfigPath::root().as_str(), "/");
        assert!(ConfigPath::parse("/apps/api-v2").is_ok());
        for invalid in ["", "apps", "/apps/", "/apps//api", "/Apps", "/apps_api"] {
            assert!(ConfigPath::parse(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn operation_paths_normalize_ascii_case_and_join_to_roots() {
        let root = ConfigPath::parse("/teams/platform").unwrap();
        assert_eq!(
            root.join_name("Apps-API-V2").unwrap().as_str(),
            "/teams/platform/apps-api-v2"
        );
        for invalid in [
            "",
            "/",
            "apps",
            "apps/",
            "apps//api",
            ".",
            "..",
            "a%2fb",
            "caf\u{e9}",
        ] {
            assert!(
                ConfigPath::parse_operation(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
        assert!(root.join_name("apps/api").is_err());
    }

    #[test]
    fn plain_values_are_redacted_in_formatters() {
        let value = PlainValue::new("value-sentinel");
        assert_eq!(value.expose(), "value-sentinel");
        assert_eq!(value.to_string(), "[REDACTED]");
        assert_eq!(format!("{value:?}"), "PlainValue([REDACTED])");
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
