//! The JSON subtree codec: rendering a subtree as nested JSON and parsing it
//! back into mutations.

use core::fmt;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    ClientError, ConfigPath, ErrorKind, MASKED_SECRET_TEXT, PlainValue, SubTreeMutationContent,
    SubTreeMutationValue, SubTreeValue,
};

/// A JSON object key, ordered and deduplicated by its fold (ASCII-lowercased)
/// form but rendered exactly as written — the same single-field, derive-not-store
/// split as [`ConfigPath`], so a JSON object's key order follows the same fold
/// ordering as everything else, regardless of which segments happen to carry
/// mixed case. `Eq`/`Ord` are both derived from `path` inline, so — unlike a
/// stored-fold-plus-derived-`PartialEq` design — they cannot disagree.
#[derive(Clone, Debug)]
struct JsonKey {
    path: String,
}

impl JsonKey {
    fn new(path: impl Into<String>) -> Self {
        Self { path: path.into() }
    }
}

impl PartialEq for JsonKey {
    fn eq(&self, other: &Self) -> bool {
        self.path.eq_ignore_ascii_case(&other.path)
    }
}

impl Eq for JsonKey {}

impl Ord for JsonKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.path
            .bytes()
            .map(|byte| byte.to_ascii_lowercase())
            .cmp(other.path.bytes().map(|byte| byte.to_ascii_lowercase()))
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
                    map.serialize_entry(&key.path, value)?;
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

/// Splits `path`'s segments below `root`, exactly as written.
///
/// The boundary between `root` and the relative segments is found
/// case-insensitively (case never changes a segment's byte length, so plain
/// byte slicing stays valid), then that same byte offset slices `path` as
/// written — so JSON object keys carry whatever case the value's path was
/// stored with, even when it differs from how `root` itself was cased.
fn json_segments(root: &ConfigPath, path: &ConfigPath) -> Result<Vec<String>, ClientError> {
    if root.as_str() == "/" {
        return Ok(path
            .as_str()
            .trim_start_matches('/')
            .split('/')
            .map(str::to_owned)
            .collect());
    }
    let prefix_len = root.as_str().len();
    let path_str = path.as_str();
    let matches_root = path_str.len() > prefix_len
        && path_str.as_bytes()[..prefix_len].eq_ignore_ascii_case(root.as_str().as_bytes())
        && path_str.as_bytes()[prefix_len] == b'/';
    if !matches_root {
        return Err(invalid_subtree());
    }
    let relative = &path_str[prefix_len + 1..];
    Ok(relative.split('/').map(str::to_owned).collect())
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
        let path = root.join_name(key.path).map_err(|_| invalid_json())?;
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

pub(crate) fn invalid_subtree() -> ClientError {
    ClientError::new(
        ErrorKind::InvalidRequest,
        "configuration subtree cannot be represented as JSON",
    )
}
