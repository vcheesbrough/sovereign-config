#![forbid(unsafe_code)]

mod connection;
mod managed;

use core::fmt;
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROTOCOL_VERSION: &str = "v3";
pub const MASKED_SECRET_TEXT: &str = "********";

pub use connection::{ConnectionUrl, ConnectionUrlError};
pub use managed::{
    ConnectionId, DisplayName, MAX_CONNECTION_ID_CHARS, MAX_DISPLAY_NAME_CHARS,
    MIN_CONNECTION_ID_CHARS, ManagedConnectionMetadata, ManagedConnectionState, ManagedPermission,
    ManagedPermissions, ProvisionedManagedConnection, RevealedConnectionUrl,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PathError {
    #[error("path must be canonical")]
    NonCanonical,
}

/// A canonical absolute configuration path.
///
/// The grammar is `/` (the tree root) or `^/[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$`.
/// Every path carries two forms:
///
/// - The **fold key** ([`ConfigPath::as_str`]) — ASCII letters lowercased.
///   This is what resolution, uniqueness, authorization, and every other
///   comparison uses; `/x/FOO` and `/x/foo` share one fold key and are the
///   same value.
/// - The **display form** ([`ConfigPath::display_str`]) — the path exactly as
///   written. Returned in reads and listings and shown in the UI, but never
///   compared or used for lookup.
///
/// This is case-**retentive**, not case-sensitive: the service stores and
/// reports the letter case it was given, but two paths differing only in case
/// remain one value. Case retention was added in release 2.18.0; a client
/// built before that release assumes every response path is already
/// lowercase and fails the whole response it arrived in once one is not. See
/// the `Upgrade` section of the repository README.
///
/// `_` was added to the segment character set in release 2.15.0. It is a
/// widening of the `v3` protocol's canonical path grammar: a client built before
/// that release rejects a path containing `_` and fails the whole response it
/// arrived in. See the `Upgrade` section of the repository README.
#[derive(Clone, Debug)]
pub struct ConfigPath {
    fold: String,
    display: String,
}

impl ConfigPath {
    #[must_use]
    pub fn root() -> Self {
        Self {
            fold: "/".into(),
            display: "/".into(),
        }
    }

    /// Parses a rooted, already fold-cased (lowercase) path, including the `/`
    /// root path.
    ///
    /// The display form equals the fold key. Use this only for input already
    /// known to be canonical — round-tripping a stored fold key, a literal in
    /// code, a connection root — never for text a caller typed, which should
    /// go through [`ConfigPath::parse_operation`] or
    /// [`ConfigPath::parse_selection`] to retain its case.
    ///
    /// # Errors
    ///
    /// Returns [`PathError::NonCanonical`] when the path is not rooted, a segment
    /// is empty, or it contains characters outside lowercase ASCII letters,
    /// digits, `-`, and `_`.
    pub fn parse(value: impl Into<String>) -> Result<Self, PathError> {
        let value = value.into();
        if value == "/"
            || value.strip_prefix('/').is_some_and(|relative| {
                !relative.is_empty()
                    && relative.split('/').all(|segment| {
                        !segment.is_empty()
                            && segment.bytes().all(|byte| {
                                byte.is_ascii_lowercase()
                                    || byte.is_ascii_digit()
                                    || byte == b'-'
                                    || byte == b'_'
                            })
                    })
            })
        {
            Ok(Self {
                fold: value.clone(),
                display: value,
            })
        } else {
            Err(PathError::NonCanonical)
        }
    }

    /// Parses a non-root absolute operation path, retaining the case it was
    /// written with as the display form while folding ASCII letters for the
    /// fold key.
    ///
    /// # Errors
    ///
    /// Returns [`PathError::NonCanonical`] for root or unrooted paths, empty
    /// segments, non-ASCII text, percent encoding, or characters other than
    /// ASCII letters, digits, `-`, and `_`.
    pub fn parse_operation(value: impl AsRef<str>) -> Result<Self, PathError> {
        let value = value.as_ref();
        let Some(relative) = value.strip_prefix('/') else {
            return Err(PathError::NonCanonical);
        };
        if relative.is_empty()
            || !relative.split('/').all(|segment| {
                !segment.is_empty()
                    && segment.bytes().all(|byte| {
                        byte.is_ascii_alphabetic()
                            || byte.is_ascii_digit()
                            || byte == b'-'
                            || byte == b'_'
                    })
            })
        {
            return Err(PathError::NonCanonical);
        }
        Ok(Self {
            fold: value.to_ascii_lowercase(),
            display: value.to_owned(),
        })
    }

    /// Parses an absolute operation selection, including the tree root,
    /// retaining case as [`ConfigPath::parse_operation`] does.
    ///
    /// # Errors
    ///
    /// Returns [`PathError::NonCanonical`] for unrooted paths, empty segments,
    /// non-ASCII text, percent encoding, or unsupported characters.
    pub fn parse_selection(value: impl AsRef<str>) -> Result<Self, PathError> {
        if value.as_ref() == "/" {
            return Ok(Self::root());
        }
        Self::parse_operation(value)
    }

    /// Appends one value name to a canonical rooted namespace, retaining the
    /// case `name` was given as that segment's display form.
    ///
    /// # Errors
    ///
    /// Returns [`PathError::NonCanonical`] when `name` is not one valid path
    /// segment.
    pub fn join_name(&self, name: impl AsRef<str>) -> Result<Self, PathError> {
        let name = name.as_ref();
        if name.is_empty()
            || !name.bytes().all(|byte| {
                byte.is_ascii_alphabetic() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
            })
        {
            return Err(PathError::NonCanonical);
        }
        let fold_name = name.to_ascii_lowercase();
        let fold = if self.fold == "/" {
            format!("/{fold_name}")
        } else {
            format!("{}/{fold_name}", self.fold)
        };
        let display = if self.display == "/" {
            format!("/{name}")
        } else {
            format!("{}/{name}", self.display)
        };
        Ok(Self { fold, display })
    }

    /// The fold key: ASCII letters lowercased. Used for comparison, lookup,
    /// and every other match — never for display.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.fold
    }

    /// The display form: exactly the case this path was written with.
    #[must_use]
    pub fn display_str(&self) -> &str {
        &self.display
    }

    #[must_use]
    pub fn is_at_or_below(&self, root: &Self) -> bool {
        root.fold == "/"
            || self.fold == root.fold
            || self
                .fold
                .strip_prefix(root.fold.as_str())
                .is_some_and(|suffix| suffix.starts_with('/'))
    }

    /// The final segment's fold key.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.fold.rsplit('/').next().filter(|name| !name.is_empty())
    }

    /// The final segment's display form.
    #[must_use]
    pub fn display_name(&self) -> Option<&str> {
        self.display
            .rsplit('/')
            .next()
            .filter(|name| !name.is_empty())
    }
}

impl PartialEq for ConfigPath {
    fn eq(&self, other: &Self) -> bool {
        self.fold == other.fold
    }
}

impl Eq for ConfigPath {}

impl PartialOrd for ConfigPath {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ConfigPath {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.fold.cmp(&other.fold)
    }
}

/// Serializes to the fold key, matching this type's historical
/// `#[serde(transparent)]` wire shape.
impl Serialize for ConfigPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.fold)
    }
}

/// Deserializes without validation, matching this type's historical
/// `#[serde(transparent)]` behavior — round-trips only, never for untrusted
/// text. Untrusted input must go through [`ConfigPath::parse_operation`] or
/// [`ConfigPath::parse_selection`].
impl<'de> Deserialize<'de> for ConfigPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(Self {
            fold: value.clone(),
            display: value,
        })
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueClassification {
    Plain,
    Secret,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MaskedSecret;

impl MaskedSecret {
    #[must_use]
    pub const fn text(self) -> &'static str {
        MASKED_SECRET_TEXT
    }
}

impl fmt::Display for MaskedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(MASKED_SECRET_TEXT)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValueContent {
    Plain(PlainValue),
    Secret(MaskedSecret),
}

impl ValueContent {
    #[must_use]
    pub const fn classification(&self) -> ValueClassification {
        match self {
            Self::Plain(_) => ValueClassification::Plain,
            Self::Secret(_) => ValueClassification::Secret,
        }
    }

    #[must_use]
    pub fn display_text(&self) -> &str {
        match self {
            Self::Plain(value) => value.expose(),
            Self::Secret(_) => MASKED_SECRET_TEXT,
        }
    }

    #[must_use]
    pub const fn plain(&self) -> Option<&PlainValue> {
        match self {
            Self::Plain(value) => Some(value),
            Self::Secret(_) => None,
        }
    }
}

/// A secret accepted only as write input. It is never serializable and all
/// formatting is redacted.
///
/// ```compile_fail
/// use serde::Serialize;
/// use sovereign_config_core::SecretInput;
///
/// fn assert_serializable<T: Serialize>() {}
/// assert_serializable::<SecretInput>();
/// ```
#[derive(Clone)]
pub struct SecretInput(String);

impl SecretInput {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretInput([REDACTED])")
    }
}

impl fmt::Display for SecretInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

/// Plaintext returned only by the explicit reveal operation.
///
/// ```compile_fail
/// use serde::Serialize;
/// use sovereign_config_core::RevealedSecret;
///
/// fn assert_serializable<T: Serialize>() {}
/// assert_serializable::<RevealedSecret>();
/// ```
#[derive(Clone)]
pub struct RevealedSecret(String);

impl RevealedSecret {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RevealedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RevealedSecret([REDACTED])")
    }
}

impl fmt::Display for RevealedSecret {
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
pub struct ListedValue {
    pub path: ConfigPath,
    pub value: ValueContent,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    /// Other canonical paths resolving to the same value that the caller may
    /// read. Excludes this value's own `path`.
    pub alias_paths: Vec<ConfigPath>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValueListing {
    pub values: Vec<ListedValue>,
    pub paths: Vec<ConfigPath>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubTreeValue {
    pub path: ConfigPath,
    pub value: ValueContent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubTreeMutationContent {
    Plain(PlainValue),
    PreserveSecret,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubTreeMutationValue {
    pub path: ConfigPath,
    pub value: SubTreeMutationContent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValueSubTree {
    pub values: Vec<SubTreeValue>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PutMetadata {
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteMetadata {
    pub deleted_at: Timestamp,
    pub deleted_count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplaceMetadata {
    pub updated_at: Timestamp,
    pub value_count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddPathMetadata {
    pub created_at: Timestamp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValuePaths {
    pub paths: Vec<ConfigPath>,
}

impl fmt::Display for ConfigPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.fold)
    }
}

/// A JSON object key, ordered and deduplicated by its fold (ASCII-lowercased)
/// form but rendered in its display form — exactly the [`ConfigPath`] split,
/// so a JSON object's key order follows the same fold ordering as everything
/// else, regardless of which segments happen to carry mixed case.
#[derive(Clone, Debug, Eq, PartialEq)]
struct JsonKey {
    fold: String,
    display: String,
}

impl JsonKey {
    fn new(display: impl Into<String>) -> Self {
        let display = display.into();
        let fold = display.to_ascii_lowercase();
        Self { fold, display }
    }
}

impl Ord for JsonKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.fold.cmp(&other.fold)
    }
}

impl PartialOrd for JsonKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum JsonNode {
    String(String),
    Object(BTreeMap<JsonKey, Self>),
}

impl Serialize for JsonNode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        match self {
            Self::String(value) => serializer.serialize_str(value),
            Self::Object(values) => {
                let mut map = serializer.serialize_map(Some(values.len()))?;
                for (key, value) in values {
                    map.serialize_entry(&key.display, value)?;
                }
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for JsonNode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = JsonNode;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object or string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(JsonNode::String(value.to_owned()))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(JsonNode::String(value))
            }

            fn visit_map<A>(self, mut values: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut object = BTreeMap::new();
                while let Some((key, value)) = values.next_entry::<String, JsonNode>()? {
                    // Two keys differing only by case fold to the same path,
                    // so this rejects them exactly as a byte-identical
                    // duplicate would have been rejected before — a JSON
                    // object cannot express which case should win.
                    if object.insert(JsonKey::new(key), value).is_some() {
                        return Err(serde::de::Error::custom("duplicate JSON object key"));
                    }
                }
                Ok(JsonNode::Object(object))
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

/// Renders a flat absolute-path collection as deterministic, pretty JSON.
///
/// # Errors
///
/// Returns a bounded validation error when a path is outside the selection or
/// when a value and an object would occupy the same JSON node.
pub fn render_subtree_json(
    root: &ConfigPath,
    values: &[SubTreeValue],
) -> Result<String, ClientError> {
    let mut object = BTreeMap::new();
    let mut exact = None;
    for value in values {
        if value.path.as_str() == "/" || !value.path.is_at_or_below(root) {
            return Err(invalid_subtree());
        }
        if value.path == *root {
            if exact.replace(value.value.display_text()).is_some() {
                return Err(invalid_subtree());
            }
            continue;
        }
        let segments = json_segments(root, &value.path)?;
        insert_json_value(&mut object, &segments, value.value.display_text())?;
    }
    let node = match exact {
        Some(value) if object.is_empty() => JsonNode::String(value.to_owned()),
        Some(_) => return Err(invalid_subtree()),
        None => JsonNode::Object(object),
    };
    serde_json::to_string_pretty(&node)
        .map(|json| format!("{json}\n"))
        .map_err(|_| invalid_subtree())
}

/// Parses strict subtree JSON into canonical absolute paths and plain strings.
///
/// # Errors
///
/// Returns a bounded validation error for malformed JSON, duplicate keys,
/// invalid path segments, or non-string leaves below an object.
pub fn parse_subtree_json(
    root: &ConfigPath,
    json: &str,
) -> Result<Vec<SubTreeMutationValue>, ClientError> {
    let mut deserializer = serde_json::Deserializer::from_str(json);
    let node = JsonNode::deserialize(&mut deserializer).map_err(|_| invalid_json())?;
    deserializer.end().map_err(|_| invalid_json())?;
    let mut values = Vec::new();
    if root.as_str() == "/" {
        let JsonNode::Object(object) = node else {
            return Err(invalid_json());
        };
        flatten_json_object(root, object, &mut values)?;
    } else {
        flatten_json_node(root, node, &mut values)?;
    }
    Ok(values)
}

/// Splits `path`'s segments below `root`, in their **display** case.
///
/// The boundary between `root` and the relative segments is found on the fold
/// keys (case never changes a segment's byte length), then the same byte
/// offset slices `path`'s display form — so JSON object keys carry whatever
/// case the value's path was stored with.
fn json_segments(root: &ConfigPath, path: &ConfigPath) -> Result<Vec<String>, ClientError> {
    if root.as_str() == "/" {
        return Ok(path
            .display_str()
            .trim_start_matches('/')
            .split('/')
            .map(str::to_owned)
            .collect());
    }
    let relative_fold = path
        .as_str()
        .strip_prefix(root.as_str())
        .and_then(|suffix| suffix.strip_prefix('/'))
        .ok_or_else(invalid_subtree)?;
    let boundary = path.as_str().len() - relative_fold.len();
    let relative_display = &path.display_str()[boundary..];
    Ok(relative_display.split('/').map(str::to_owned).collect())
}

fn insert_json_value(
    object: &mut BTreeMap<JsonKey, JsonNode>,
    segments: &[String],
    value: &str,
) -> Result<(), ClientError> {
    let Some((segment, remaining)) = segments.split_first() else {
        return Err(invalid_subtree());
    };
    let key = JsonKey::new(segment.clone());
    if remaining.is_empty() {
        if object
            .insert(key, JsonNode::String(value.to_owned()))
            .is_some()
        {
            return Err(invalid_subtree());
        }
        return Ok(());
    }
    // If an ancestor at this fold key already exists (two leaves disagreeing
    // on that ancestor's established case), `entry` matches by fold and keeps
    // whichever display form got here first — deterministic because `values`
    // arrives fold-ordered.
    let node = object
        .entry(key)
        .or_insert_with(|| JsonNode::Object(BTreeMap::new()));
    let JsonNode::Object(child) = node else {
        return Err(invalid_subtree());
    };
    insert_json_value(child, remaining, value)
}

fn flatten_json_object(
    root: &ConfigPath,
    object: BTreeMap<JsonKey, JsonNode>,
    values: &mut Vec<SubTreeMutationValue>,
) -> Result<(), ClientError> {
    for (key, node) in object {
        let path = root.join_name(key.display).map_err(|_| invalid_json())?;
        flatten_json_node(&path, node, values)?;
    }
    Ok(())
}

fn flatten_json_node(
    path: &ConfigPath,
    node: JsonNode,
    values: &mut Vec<SubTreeMutationValue>,
) -> Result<(), ClientError> {
    match node {
        JsonNode::String(value) => {
            if value.contains('\0') {
                return Err(invalid_json());
            }
            let value = if value == MASKED_SECRET_TEXT {
                SubTreeMutationContent::PreserveSecret
            } else {
                SubTreeMutationContent::Plain(PlainValue::new(value))
            };
            values.push(SubTreeMutationValue {
                path: path.clone(),
                value,
            });
            Ok(())
        }
        JsonNode::Object(object) => flatten_json_object(path, object, values),
    }
}

fn invalid_json() -> ClientError {
    ClientError::new(ErrorKind::InvalidRequest, "configuration JSON is invalid")
}

fn invalid_subtree() -> ClientError {
    ClientError::new(
        ErrorKind::InvalidRequest,
        "configuration subtree cannot be represented as JSON",
    )
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
    /// The request cannot apply because the target is already taken, such as
    /// aliasing a value onto an occupied path.
    Conflict,
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
    use super::{
        ConfigPath, ErrorKind, MASKED_SECRET_TEXT, MaskedSecret, PROTOCOL_VERSION, PlainValue,
        RevealedSecret, Secret, SecretInput, ServiceStatus, SubTreeMutationContent,
        SubTreeMutationValue, SubTreeValue, ValueContent, parse_subtree_json, render_subtree_json,
    };

    #[test]
    fn paths_are_canonical_and_root_is_explicit() {
        assert_eq!(ConfigPath::root().as_str(), "/");
        assert!(ConfigPath::parse("/apps/api-v2").is_ok());
        for valid in [
            "/apps_api",
            "/woodpecker/global/github_token",
            "/apps/_leading",
            "/apps/trailing_",
            "/apps/__",
        ] {
            assert!(ConfigPath::parse(valid).is_ok(), "rejected {valid:?}");
        }
        for invalid in [
            "",
            "apps",
            "/apps/",
            "/apps//api",
            "/Apps",
            "/apps.api",
            "/apps+api",
            "/apps api",
        ] {
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
        assert_eq!(
            root.join_name("Zot_CI_User").unwrap().as_str(),
            "/teams/platform/zot_ci_user"
        );
        assert_eq!(
            ConfigPath::parse_operation("/Woodpecker/Global/GitHub_Token")
                .unwrap()
                .as_str(),
            "/woodpecker/global/github_token"
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
            "/apps.api",
        ] {
            assert!(
                ConfigPath::parse_operation(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
        assert!(root.join_name("apps/api").is_err());
        assert_eq!(
            ConfigPath::parse_selection("/").unwrap(),
            ConfigPath::root()
        );
        assert_eq!(
            ConfigPath::parse_selection("/Apps/API").unwrap().as_str(),
            "/apps/api"
        );
        assert!(
            ConfigPath::parse("/apps/api/key")
                .unwrap()
                .is_at_or_below(&ConfigPath::parse("/apps/api").unwrap())
        );
        assert!(
            !ConfigPath::parse("/apps/api-v2/key")
                .unwrap()
                .is_at_or_below(&ConfigPath::parse("/apps/api").unwrap())
        );
        assert!(
            !ConfigPath::parse("/foo/second/abc")
                .unwrap()
                .is_at_or_below(&ConfigPath::parse("/foo/s").unwrap())
        );
    }

    #[test]
    fn paths_retain_display_case_while_folding_for_comparison() {
        let mixed = ConfigPath::parse_operation("/Apps/serverIP").unwrap();
        assert_eq!(mixed.as_str(), "/apps/serverip");
        assert_eq!(mixed.display_str(), "/Apps/serverIP");
        assert_eq!(mixed.name(), Some("serverip"));
        assert_eq!(mixed.display_name(), Some("serverIP"));

        let lower = ConfigPath::parse_operation("/apps/serverip").unwrap();
        assert_eq!(mixed, lower, "fold-equal paths must compare equal");
        assert_eq!(lower.display_str(), "/apps/serverip");

        let root_selection = ConfigPath::parse_selection("/Apps").unwrap();
        assert_eq!(root_selection.as_str(), "/apps");
        assert_eq!(root_selection.display_str(), "/Apps");

        let joined = root_selection.join_name("Server_IP").unwrap();
        assert_eq!(joined.as_str(), "/apps/server_ip");
        assert_eq!(joined.display_str(), "/Apps/Server_IP");

        let mut ordered = [
            ConfigPath::parse_operation("/b").unwrap(),
            ConfigPath::parse_operation("/A").unwrap(),
        ];
        ordered.sort();
        assert_eq!(
            ordered.iter().map(ConfigPath::as_str).collect::<Vec<_>>(),
            ["/a", "/b"],
            "ordering must follow the fold key, not the display form"
        );
    }

    fn subtree_value(path: &str, value: &str) -> SubTreeValue {
        SubTreeValue {
            path: ConfigPath::parse(path).unwrap(),
            value: ValueContent::Plain(PlainValue::new(value)),
        }
    }

    fn mutation_value(path: &str, value: &str) -> SubTreeMutationValue {
        SubTreeMutationValue {
            path: ConfigPath::parse(path).unwrap(),
            value: SubTreeMutationContent::Plain(PlainValue::new(value)),
        }
    }

    #[test]
    fn subtree_json_round_trips_exact_nested_root_and_empty_values() {
        let selected = ConfigPath::parse("/apps/api").unwrap();
        let values = vec![
            subtree_value("/apps/api/enabled", "true"),
            subtree_value("/apps/api/nested/message", "line one\nline two"),
        ];
        let json = render_subtree_json(&selected, &values).unwrap();
        assert_eq!(
            json,
            "{\n  \"enabled\": \"true\",\n  \"nested\": {\n    \"message\": \"line one\\nline two\"\n  }\n}\n"
        );
        assert_eq!(
            parse_subtree_json(&selected, &json).unwrap(),
            vec![
                mutation_value("/apps/api/enabled", "true"),
                mutation_value("/apps/api/nested/message", "line one\nline two"),
            ]
        );

        let exact = vec![subtree_value("/apps/api", "value")];
        assert_eq!(
            render_subtree_json(&selected, &exact).unwrap(),
            "\"value\"\n"
        );
        assert_eq!(
            parse_subtree_json(&selected, "\"value\"").unwrap(),
            vec![mutation_value("/apps/api", "value")]
        );

        let same_name_child = vec![subtree_value("/apps/api/api", "child")];
        assert_eq!(
            render_subtree_json(&selected, &same_name_child).unwrap(),
            "{\n  \"api\": \"child\"\n}\n"
        );
        assert_eq!(
            parse_subtree_json(&selected, "{\"api\":\"child\"}").unwrap(),
            vec![mutation_value("/apps/api/api", "child")]
        );

        // Underscore keys round-trip: Woodpecker `from_secret:` names such as
        // `github_token` are stored verbatim as path segments.
        let underscored = vec![subtree_value("/apps/api/github_token", "value")];
        assert_eq!(
            render_subtree_json(&selected, &underscored).unwrap(),
            "{\n  \"github_token\": \"value\"\n}\n"
        );
        assert_eq!(
            parse_subtree_json(&selected, "{\"github_token\":\"value\"}").unwrap(),
            vec![mutation_value("/apps/api/github_token", "value")]
        );

        let root = ConfigPath::root();
        assert_eq!(
            parse_subtree_json(&root, "{\"apps\":{\"enabled\":\"yes\"}}").unwrap(),
            vec![mutation_value("/apps/enabled", "yes")]
        );
        assert_eq!(render_subtree_json(&selected, &[]).unwrap(), "{}\n");
        assert!(parse_subtree_json(&selected, "{}").unwrap().is_empty());
    }

    #[test]
    fn subtree_json_keys_retain_display_case() {
        let selected = ConfigPath::parse_operation("/Apps/API").unwrap();
        let leaf = selected.join_name("serverIP").unwrap();
        let values = vec![SubTreeValue {
            path: leaf,
            value: ValueContent::Plain(PlainValue::new("value")),
        }];
        let json = render_subtree_json(&selected, &values).unwrap();
        assert_eq!(json, "{\n  \"serverIP\": \"value\"\n}\n");

        let parsed = parse_subtree_json(&selected, &json).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].path.display_str(), "/Apps/API/serverIP");
        assert_eq!(parsed[0].path.as_str(), "/apps/api/serverip");

        // A lowercase key still resolves to the same established fold key.
        let refolded = parse_subtree_json(&selected, "{\"serverip\":\"value\"}").unwrap();
        assert_eq!(refolded[0].path, parsed[0].path);
    }

    #[test]
    fn subtree_json_object_keys_order_by_fold_not_display_bytes() {
        // Byte order would put "Signing-Key" (uppercase 'S') before
        // "api-token" (lowercase 'a'); fold order — what every other JSON key
        // comparison in this system uses — puts it after, matching the order
        // an operator actually expects.
        let selected = ConfigPath::parse_operation("/apps/api").unwrap();
        let values = vec![
            SubTreeValue {
                path: ConfigPath::parse_operation("/apps/api/Signing-Key").unwrap(),
                value: ValueContent::Plain(PlainValue::new("one")),
            },
            SubTreeValue {
                path: ConfigPath::parse_operation("/apps/api/api-token").unwrap(),
                value: ValueContent::Plain(PlainValue::new("two")),
            },
        ];
        let json = render_subtree_json(&selected, &values).unwrap();
        assert_eq!(
            json,
            "{\n  \"api-token\": \"two\",\n  \"Signing-Key\": \"one\"\n}\n"
        );
    }

    #[test]
    fn subtree_json_rejects_case_variant_duplicate_keys() {
        let selected = ConfigPath::parse("/apps/api").unwrap();
        assert!(parse_subtree_json(&selected, "{\"Foo\":\"a\",\"foo\":\"b\"}").is_err());
    }

    #[test]
    fn subtree_json_rejects_lossy_or_invalid_shapes() {
        let selected = ConfigPath::parse("/apps/api").unwrap();
        let collisions = vec![
            subtree_value("/apps/api", "parent"),
            subtree_value("/apps/api/child", "child"),
        ];
        assert!(render_subtree_json(&selected, &collisions).is_err());
        assert!(
            render_subtree_json(&selected, &[subtree_value("/apps/api-v2/child", "outside")])
                .is_err()
        );
        assert!(
            render_subtree_json(
                &ConfigPath::root(),
                &[SubTreeValue {
                    path: ConfigPath::root(),
                    value: ValueContent::Plain(PlainValue::new("invalid-root-value")),
                }]
            )
            .is_err()
        );
        for invalid in [
            "[]",
            "true",
            "null",
            "{\"enabled\":true}",
            "{\"enabled\":null}",
            "{\"enabled\":[\"value\"]}",
            "{\"nested\":{\"bad.key\":\"value\"}}",
            "{\"enabled\":\"first\",\"enabled\":\"second\"}",
            "{\"enabled\":\"bad\\u0000value\"}",
        ] {
            assert!(
                parse_subtree_json(&selected, invalid).is_err(),
                "accepted {invalid}"
            );
        }
        assert!(parse_subtree_json(&ConfigPath::root(), "\"root-value\"").is_err());
    }

    #[test]
    fn plain_values_are_redacted_in_formatters() {
        let value = PlainValue::new("value-sentinel");
        assert_eq!(value.expose(), "value-sentinel");
        assert_eq!(value.to_string(), "[REDACTED]");
        assert_eq!(format!("{value:?}"), "PlainValue([REDACTED])");
    }

    #[test]
    fn secret_types_and_json_masks_are_safe_by_construction() {
        let input = SecretInput::new("secret-sentinel");
        let revealed = RevealedSecret::new("secret-sentinel");
        assert_eq!(input.expose(), "secret-sentinel");
        assert_eq!(revealed.expose(), "secret-sentinel");
        assert_eq!(format!("{input:?}"), "SecretInput([REDACTED])");
        assert_eq!(format!("{revealed:?}"), "RevealedSecret([REDACTED])");
        assert_eq!(MaskedSecret.to_string(), MASKED_SECRET_TEXT);

        let selected = ConfigPath::parse("/apps/api").unwrap();
        let masked = SubTreeValue {
            path: ConfigPath::parse("/apps/api/credential").unwrap(),
            value: ValueContent::Secret(MaskedSecret),
        };
        let json = render_subtree_json(&selected, &[masked]).unwrap();
        assert!(!json.contains("secret-sentinel"));
        assert_eq!(
            parse_subtree_json(&selected, &json).unwrap(),
            vec![SubTreeMutationValue {
                path: ConfigPath::parse("/apps/api/credential").unwrap(),
                value: SubTreeMutationContent::PreserveSecret,
            }]
        );
    }

    #[test]
    fn protocol_negotiation_is_exact() {
        assert!(ServiceStatus::negotiate("1.5.0".into(), PROTOCOL_VERSION.into()).compatible);
        assert!(!ServiceStatus::negotiate("1.5.0".into(), "v1".into()).compatible);
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
