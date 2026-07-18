#![forbid(unsafe_code)]

mod connection;

use core::fmt;
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROTOCOL_VERSION: &str = "v2";

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

    /// Parses an absolute operation selection, including the tree root, and
    /// normalizes ASCII letters to lowercase.
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

    #[must_use]
    pub fn is_at_or_below(&self, root: &Self) -> bool {
        root.as_str() == "/"
            || self == root
            || self
                .as_str()
                .strip_prefix(root.as_str())
                .is_some_and(|suffix| suffix.starts_with('/'))
    }

    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.0.rsplit('/').next().filter(|name| !name.is_empty())
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubTreeValue {
    pub path: ConfigPath,
    pub value: PlainValue,
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

impl fmt::Display for ConfigPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum JsonNode {
    String(String),
    Object(BTreeMap<String, Self>),
}

impl Serialize for JsonNode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::String(value) => serializer.serialize_str(value),
            Self::Object(values) => values.serialize(serializer),
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
                    if object.insert(key, value).is_some() {
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
            if exact.replace(value.value.expose()).is_some() {
                return Err(invalid_subtree());
            }
            continue;
        }
        let segments = json_segments(root, &value.path)?;
        insert_json_value(&mut object, &segments, value.value.expose())?;
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
pub fn parse_subtree_json(root: &ConfigPath, json: &str) -> Result<Vec<SubTreeValue>, ClientError> {
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

fn json_segments(root: &ConfigPath, path: &ConfigPath) -> Result<Vec<String>, ClientError> {
    if root.as_str() == "/" {
        return Ok(path
            .as_str()
            .trim_start_matches('/')
            .split('/')
            .map(str::to_owned)
            .collect());
    }
    let relative = path
        .as_str()
        .strip_prefix(root.as_str())
        .and_then(|suffix| suffix.strip_prefix('/'))
        .ok_or_else(invalid_subtree)?;
    Ok(relative.split('/').map(str::to_owned).collect())
}

fn insert_json_value(
    object: &mut BTreeMap<String, JsonNode>,
    segments: &[String],
    value: &str,
) -> Result<(), ClientError> {
    let Some((segment, remaining)) = segments.split_first() else {
        return Err(invalid_subtree());
    };
    if remaining.is_empty() {
        if object
            .insert(segment.clone(), JsonNode::String(value.to_owned()))
            .is_some()
        {
            return Err(invalid_subtree());
        }
        return Ok(());
    }
    let node = object
        .entry(segment.clone())
        .or_insert_with(|| JsonNode::Object(BTreeMap::new()));
    let JsonNode::Object(child) = node else {
        return Err(invalid_subtree());
    };
    insert_json_value(child, remaining, value)
}

fn flatten_json_object(
    root: &ConfigPath,
    object: BTreeMap<String, JsonNode>,
    values: &mut Vec<SubTreeValue>,
) -> Result<(), ClientError> {
    for (name, node) in object {
        let path = root.join_name(name).map_err(|_| invalid_json())?;
        flatten_json_node(&path, node, values)?;
    }
    Ok(())
}

fn flatten_json_node(
    path: &ConfigPath,
    node: JsonNode,
    values: &mut Vec<SubTreeValue>,
) -> Result<(), ClientError> {
    match node {
        JsonNode::String(value) => {
            if value.contains('\0') {
                return Err(invalid_json());
            }
            values.push(SubTreeValue {
                path: path.clone(),
                value: PlainValue::new(value),
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
        ConfigPath, ErrorKind, PROTOCOL_VERSION, PlainValue, Secret, ServiceStatus, SubTreeValue,
        parse_subtree_json, render_subtree_json,
    };

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

    fn subtree_value(path: &str, value: &str) -> SubTreeValue {
        SubTreeValue {
            path: ConfigPath::parse(path).unwrap(),
            value: PlainValue::new(value),
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
        assert_eq!(parse_subtree_json(&selected, &json).unwrap(), values);

        let exact = vec![subtree_value("/apps/api", "value")];
        assert_eq!(
            render_subtree_json(&selected, &exact).unwrap(),
            "\"value\"\n"
        );
        assert_eq!(parse_subtree_json(&selected, "\"value\"").unwrap(), exact);

        let same_name_child = vec![subtree_value("/apps/api/api", "child")];
        assert_eq!(
            render_subtree_json(&selected, &same_name_child).unwrap(),
            "{\n  \"api\": \"child\"\n}\n"
        );
        assert_eq!(
            parse_subtree_json(&selected, "{\"api\":\"child\"}").unwrap(),
            same_name_child
        );

        let root = ConfigPath::root();
        assert_eq!(
            parse_subtree_json(&root, "{\"apps\":{\"enabled\":\"yes\"}}").unwrap(),
            vec![subtree_value("/apps/enabled", "yes")]
        );
        assert_eq!(render_subtree_json(&selected, &[]).unwrap(), "{}\n");
        assert!(parse_subtree_json(&selected, "{}").unwrap().is_empty());
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
                    value: PlainValue::new("invalid-root-value"),
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
            "{\"nested\":{\"bad_key\":\"value\"}}",
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
    fn protocol_negotiation_is_exact() {
        assert!(ServiceStatus::negotiate("1.4.0".into(), PROTOCOL_VERSION.into()).compatible);
        assert!(!ServiceStatus::negotiate("1.4.0".into(), "v1".into()).compatible);
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
