use core::fmt;
use std::collections::BTreeSet;

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

const fn invalid_permissions() -> ClientError {
    ClientError::new(
        ErrorKind::InvalidRequest,
        "managed connection permissions are invalid",
    )
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

/// One permission a managed connection's grant may carry on its root.
///
/// The variant order is canonical: `Read` < `Write` < `Manage`, so a
/// [`ManagedPermissions`] set always renders in the same order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ManagedPermission {
    Read,
    Write,
    Manage,
}

impl ManagedPermission {
    /// The lowercase token written into the Authentik grant JSON and the
    /// database, e.g. `"read"`.
    #[must_use]
    pub const fn as_grant_token(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Manage => "manage",
        }
    }

    /// The proto enum tag for this permission (matches `ManagedPermission` in
    /// the v3 contract: `READ=1`, `WRITE=2`, `MANAGE=3`).
    #[must_use]
    pub const fn as_proto(self) -> i32 {
        match self {
            Self::Read => 1,
            Self::Write => 2,
            Self::Manage => 3,
        }
    }

    /// Parses a proto enum tag.
    ///
    /// # Errors
    ///
    /// Returns a bounded error for `UNSPECIFIED` (0) or any unknown tag.
    pub fn from_proto(value: i32) -> Result<Self, ClientError> {
        match value {
            1 => Ok(Self::Read),
            2 => Ok(Self::Write),
            3 => Ok(Self::Manage),
            _ => Err(invalid_permissions()),
        }
    }

    /// Parses a lowercase grant token.
    ///
    /// # Errors
    ///
    /// Returns a bounded error when the token is not a known permission.
    pub fn parse(value: &str) -> Result<Self, ClientError> {
        match value {
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            "manage" => Ok(Self::Manage),
            _ => Err(invalid_permissions()),
        }
    }
}

impl fmt::Display for ManagedPermission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_grant_token())
    }
}

/// An ordered, deduplicated, non-empty set of [`ManagedPermission`]s.
///
/// This is the grant an operator selects at creation time. Storage,
/// wire, and grant-JSON forms are all canonically ordered
/// (`Read` < `Write` < `Manage`), so equal sets always serialize identically.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedPermissions(BTreeSet<ManagedPermission>);

impl ManagedPermissions {
    /// Builds a non-empty permission set from an iterator, deduplicating and
    /// ordering its members.
    ///
    /// # Errors
    ///
    /// Returns a bounded error when the iterator yields no permissions.
    pub fn new(
        permissions: impl IntoIterator<Item = ManagedPermission>,
    ) -> Result<Self, ClientError> {
        let set: BTreeSet<ManagedPermission> = permissions.into_iter().collect();
        if set.is_empty() {
            Err(invalid_permissions())
        } else {
            Ok(Self(set))
        }
    }

    /// Builds a permission set from proto enum tags.
    ///
    /// # Errors
    ///
    /// Returns a bounded error when the slice is empty or contains an unknown
    /// or `UNSPECIFIED` tag.
    pub fn from_proto(values: &[i32]) -> Result<Self, ClientError> {
        let mut set = BTreeSet::new();
        for &value in values {
            set.insert(ManagedPermission::from_proto(value)?);
        }
        Self::new(set)
    }

    /// Parses the canonical comma-separated storage form, e.g. `"read,write"`.
    ///
    /// # Errors
    ///
    /// Returns a bounded error when the string is empty or names an unknown
    /// permission.
    pub fn parse(value: &str) -> Result<Self, ClientError> {
        let mut set = BTreeSet::new();
        for token in value.split(',') {
            set.insert(ManagedPermission::parse(token)?);
        }
        Self::new(set)
    }

    /// The proto enum tags for the set, in canonical order.
    #[must_use]
    pub fn to_proto(&self) -> Vec<i32> {
        self.0
            .iter()
            .map(|permission| permission.as_proto())
            .collect()
    }

    /// The lowercase grant tokens for the set, in canonical order.
    #[must_use]
    pub fn grant_tokens(&self) -> Vec<&'static str> {
        self.0
            .iter()
            .map(|permission| permission.as_grant_token())
            .collect()
    }

    /// The canonical comma-separated storage form, e.g. `"read,write"`.
    #[must_use]
    pub fn as_storage(&self) -> String {
        self.grant_tokens().join(",")
    }

    /// Iterates the set in canonical order.
    pub fn iter(&self) -> impl Iterator<Item = ManagedPermission> + '_ {
        self.0.iter().copied()
    }

    /// Whether the set contains a given permission.
    #[must_use]
    pub fn contains(&self, permission: ManagedPermission) -> bool {
        self.0.contains(&permission)
    }
}

impl fmt::Display for ManagedPermissions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.as_storage())
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
    pub permissions: ManagedPermissions,
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
    use super::{
        ConnectionId, DisplayName, ManagedConnectionState, ManagedPermission, ManagedPermissions,
        RevealedConnectionUrl,
    };
    use crate::{ConfigPath, ConnectionUrl, Secret};

    #[test]
    fn single_permission_round_trips_every_form() {
        for (permission, token, proto) in [
            (ManagedPermission::Read, "read", 1),
            (ManagedPermission::Write, "write", 2),
            (ManagedPermission::Manage, "manage", 3),
        ] {
            assert_eq!(permission.as_grant_token(), token);
            assert_eq!(permission.as_proto(), proto);
            assert_eq!(ManagedPermission::parse(token), Ok(permission));
            assert_eq!(ManagedPermission::from_proto(proto), Ok(permission));
        }
        assert!(ManagedPermission::parse("admin").is_err());
        assert!(ManagedPermission::parse("").is_err());
        assert!(ManagedPermission::from_proto(0).is_err());
        assert!(ManagedPermission::from_proto(4).is_err());
    }

    #[test]
    fn permission_sets_order_and_deduplicate() {
        let set = ManagedPermissions::new([
            ManagedPermission::Manage,
            ManagedPermission::Read,
            ManagedPermission::Read,
            ManagedPermission::Write,
        ])
        .expect("non-empty");
        assert_eq!(set.as_storage(), "read,write,manage");
        assert_eq!(set.grant_tokens(), ["read", "write", "manage"]);
        assert_eq!(set.to_proto(), [1, 2, 3]);
        assert!(set.contains(ManagedPermission::Write));
        assert_eq!(
            set.iter().collect::<Vec<_>>(),
            [
                ManagedPermission::Read,
                ManagedPermission::Write,
                ManagedPermission::Manage,
            ]
        );
    }

    #[test]
    fn empty_permission_sets_are_rejected() {
        assert!(ManagedPermissions::new([]).is_err());
        assert!(ManagedPermissions::from_proto(&[]).is_err());
        assert!(ManagedPermissions::parse("").is_err());
    }

    #[test]
    fn permission_sets_round_trip_storage_and_proto() {
        let set = ManagedPermissions::new([ManagedPermission::Read, ManagedPermission::Manage])
            .expect("non-empty");
        assert_eq!(
            ManagedPermissions::parse(&set.as_storage()),
            Ok(set.clone())
        );
        assert_eq!(ManagedPermissions::from_proto(&set.to_proto()), Ok(set));

        // Non-canonical input order normalizes to canonical storage.
        assert_eq!(
            ManagedPermissions::parse("write,read")
                .unwrap()
                .as_storage(),
            "read,write"
        );
        assert_eq!(
            ManagedPermissions::from_proto(&[3, 1])
                .unwrap()
                .as_storage(),
            "read,manage"
        );
    }

    #[test]
    fn permission_sets_reject_unknown_members() {
        assert!(ManagedPermissions::parse("read,admin").is_err());
        assert!(ManagedPermissions::from_proto(&[1, 0]).is_err());
        assert!(ManagedPermissions::from_proto(&[1, 9]).is_err());
    }

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
