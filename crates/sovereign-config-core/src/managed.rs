use core::fmt;

use crate::{ClientError, ConfigPath, ConnectionUrl, ErrorKind, Timestamp};

/// Maximum accepted length for an opaque managed connection identifier.
pub const MAX_CONNECTION_ID_CHARS: usize = 64;
/// Minimum accepted length for an opaque managed connection identifier.
pub const MIN_CONNECTION_ID_CHARS: usize = 16;
/// Maximum accepted length for a managed connection display name.
pub const MAX_DISPLAY_NAME_CHARS: usize = 100;

const fn invalid_connection() -> ClientError {
    ClientError::new(ErrorKind::InvalidRequest, "managed connection is invalid")
}

/// Opaque bounded identifier for one managed connection.
///
/// The identifier is random, discloses neither display name nor root, and is
/// the only external name for the connection.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConnectionId(String);

impl ConnectionId {
    /// Parses a bounded opaque connection identifier.
    ///
    /// # Errors
    ///
    /// Returns a bounded error when the identifier is empty, out of bounds, or
    /// contains anything but lowercase ASCII letters and digits.
    pub fn parse(value: impl Into<String>) -> Result<Self, ClientError> {
        let value = value.into();
        if (MIN_CONNECTION_ID_CHARS..=MAX_CONNECTION_ID_CHARS).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        {
            Ok(Self(value))
        } else {
            Err(invalid_connection())
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Bounded user-supplied display name for a managed connection.
///
/// Display names are presentation only: identity and authorization always use
/// the opaque [`ConnectionId`] and canonical root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayName(String);

impl DisplayName {
    /// Parses a bounded display name.
    ///
    /// # Errors
    ///
    /// Returns a bounded error when the name is empty, untrimmed, longer than
    /// [`MAX_DISPLAY_NAME_CHARS`] characters, or contains control characters.
    pub fn parse(value: impl Into<String>) -> Result<Self, ClientError> {
        let value = value.into();
        if !value.is_empty()
            && value.trim() == value
            && value.chars().count() <= MAX_DISPLAY_NAME_CHARS
            && !value.chars().any(char::is_control)
        {
            Ok(Self(value))
        } else {
            Err(invalid_connection())
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DisplayName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Bounded operational lifecycle state of a managed connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedConnectionState {
    Provisioning,
    Active,
    RotationUnknown,
    Revoking,
    CleanupRequired,
}

impl ManagedConnectionState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Provisioning => "provisioning",
            Self::Active => "active",
            Self::RotationUnknown => "rotation_unknown",
            Self::Revoking => "revoking",
            Self::CleanupRequired => "cleanup_required",
        }
    }

    /// Parses a bounded lifecycle state.
    ///
    /// # Errors
    ///
    /// Returns a bounded error when the value is not a known lifecycle state.
    pub fn parse(value: &str) -> Result<Self, ClientError> {
        match value {
            "provisioning" => Ok(Self::Provisioning),
            "active" => Ok(Self::Active),
            "rotation_unknown" => Ok(Self::RotationUnknown),
            "revoking" => Ok(Self::Revoking),
            "cleanup_required" => Ok(Self::CleanupRequired),
            _ => Err(invalid_connection()),
        }
    }
}

impl fmt::Display for ManagedConnectionState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Safe listable metadata for one managed connection.
///
/// Contains no credential, provider identity, or external identifier.
#[derive(Clone, Debug)]
pub struct ManagedConnectionMetadata {
    pub connection_id: ConnectionId,
    pub display_name: DisplayName,
    pub root: ConfigPath,
    pub state: ManagedConnectionState,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

/// Result of creating or rotating a managed connection.
///
/// Carries the safe metadata plus the only copy of the one-time revealed
/// connection URL. The type cannot be serialized and redacts by construction.
#[derive(Clone, Debug)]
pub struct ProvisionedManagedConnection {
    pub metadata: ManagedConnectionMetadata,
    pub connection_url: RevealedConnectionUrl,
}

/// One-time revealed managed connection URL.
///
/// Returned only by creation and successful rotation; the URL cannot be read
/// again and must be replaced by rotation when lost. Formatting is redacted by
/// construction and the type cannot be serialized.
///
/// ```compile_fail
/// fn assert_serialize<T: serde::Serialize>() {}
/// assert_serialize::<sovereign_config_core::RevealedConnectionUrl>();
/// ```
#[derive(Clone)]
pub struct RevealedConnectionUrl(ConnectionUrl);

impl RevealedConnectionUrl {
    #[must_use]
    pub const fn new(connection: ConnectionUrl) -> Self {
        Self(connection)
    }

    #[must_use]
    pub const fn connection(&self) -> &ConnectionUrl {
        &self.0
    }
}

impl fmt::Debug for RevealedConnectionUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("RevealedConnectionUrl")
            .field(&"[REDACTED]")
            .finish()
    }
}

impl fmt::Display for RevealedConnectionUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

#[cfg(test)]
mod tests {
    use super::{ConnectionId, DisplayName, ManagedConnectionState, RevealedConnectionUrl};
    use crate::{ConfigPath, ConnectionUrl, Secret};

    #[test]
    fn connection_ids_are_bounded_opaque_lowercase() {
        assert!(ConnectionId::parse("a".repeat(16)).is_ok());
        assert!(ConnectionId::parse("a1b2c3d4e5f6a7b8".to_owned()).is_ok());
        for invalid in [
            String::new(),
            "a".repeat(15),
            "a".repeat(65),
            "A".repeat(16),
            "a-b".repeat(8),
            format!("{}\u{0}", "a".repeat(16)),
        ] {
            assert!(ConnectionId::parse(invalid.clone()).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn display_names_are_bounded_and_trimmed() {
        assert!(DisplayName::parse("Pipeline reader").is_ok());
        assert!(DisplayName::parse("x".repeat(100)).is_ok());
        for invalid in [
            String::new(),
            " padded".to_owned(),
            "padded ".to_owned(),
            "x".repeat(101),
            "line\nbreak".to_owned(),
        ] {
            assert!(DisplayName::parse(invalid.clone()).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn lifecycle_states_round_trip_bounded_values() {
        for state in [
            ManagedConnectionState::Provisioning,
            ManagedConnectionState::Active,
            ManagedConnectionState::RotationUnknown,
            ManagedConnectionState::Revoking,
            ManagedConnectionState::CleanupRequired,
        ] {
            assert_eq!(ManagedConnectionState::parse(state.as_str()), Ok(state));
        }
        assert!(ManagedConnectionState::parse("revoked").is_err());
        assert!(ManagedConnectionState::parse("").is_err());
    }

    #[test]
    fn revealed_connection_urls_redact_all_formatters() {
        let connection = ConnectionUrl::managed(
            "https://config.example.test",
            &ConfigPath::parse("/apps/api").unwrap(),
            "https://auth.example.test/application/o/config/",
            "sovereign-config",
            "generated-username",
            &Secret::new("app-password-sentinel"),
        )
        .unwrap();
        let revealed = RevealedConnectionUrl::new(connection);
        assert_eq!(revealed.to_string(), "[REDACTED]");
        assert!(!format!("{revealed:?}").contains("app-password-sentinel"));
        assert!(
            revealed
                .connection()
                .canonical()
                .expose()
                .contains("client_secret=")
        );
    }
}
