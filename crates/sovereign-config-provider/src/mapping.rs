use std::collections::BTreeMap;

use serde_json::{Map, Value};
use sovereign_config_core::{ConfigPath, RevealedSecret, SubTreeValue, ValueContent};

use crate::error::ProviderError;

/// Builds a nested JSON tree keyed by path segments relative to `root`, using
/// each leaf's real text.
///
/// `Plain` leaves use their exposed text; `Secret` leaves use the caller-supplied
/// revealed plaintext keyed by exact path. Every secret leaf in `values` must
/// have a matching entry in `revealed`.
///
/// This is deliberately distinct from `sovereign_config_core::render_subtree_json`,
/// which masks secrets via `ValueContent::display_text()` for CLI/UI display. A
/// facade assembling real application configuration needs the unmasked values.
///
/// # Errors
///
/// Returns [`ProviderError::InvalidConversion`] for a path outside `root`, a
/// value/object collision on one JSON node, or a secret leaf missing its
/// revealed plaintext. The error never names the offending path or value.
pub(crate) fn subtree_to_json(
    root: &ConfigPath,
    values: &[SubTreeValue],
    revealed: &BTreeMap<ConfigPath, RevealedSecret>,
) -> Result<Value, ProviderError> {
    let mut object = Map::new();
    let mut exact = None;
    for value in values {
        if value.path.as_str() == "/" || !value.path.is_at_or_below(root) {
            return Err(ProviderError::InvalidConversion);
        }
        let text = leaf_text(value, revealed)?;
        if value.path == *root {
            if exact.replace(text).is_some() {
                return Err(ProviderError::InvalidConversion);
            }
            continue;
        }
        let segments = relative_segments(root, &value.path)?;
        insert(&mut object, &segments, text)?;
    }
    match exact {
        Some(text) if object.is_empty() => Ok(Value::String(text)),
        Some(_) => Err(ProviderError::InvalidConversion),
        None => Ok(Value::Object(object)),
    }
}

fn leaf_text(
    value: &SubTreeValue,
    revealed: &BTreeMap<ConfigPath, RevealedSecret>,
) -> Result<String, ProviderError> {
    match &value.value {
        ValueContent::Plain(plain) => Ok(plain.expose().to_owned()),
        ValueContent::Secret(_) => revealed
            .get(&value.path)
            .map(|secret| secret.expose().to_owned())
            .ok_or(ProviderError::InvalidConversion),
    }
}

fn relative_segments(root: &ConfigPath, path: &ConfigPath) -> Result<Vec<String>, ProviderError> {
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
        .ok_or(ProviderError::InvalidConversion)?;
    Ok(relative.split('/').map(str::to_owned).collect())
}

fn insert(
    object: &mut Map<String, Value>,
    segments: &[String],
    value: String,
) -> Result<(), ProviderError> {
    let Some((segment, remaining)) = segments.split_first() else {
        return Err(ProviderError::InvalidConversion);
    };
    if remaining.is_empty() {
        if object
            .insert(segment.clone(), Value::String(value))
            .is_some()
        {
            return Err(ProviderError::InvalidConversion);
        }
        return Ok(());
    }
    let entry = object
        .entry(segment.clone())
        .or_insert_with(|| Value::Object(Map::new()));
    let Value::Object(child) = entry else {
        return Err(ProviderError::InvalidConversion);
    };
    insert(child, remaining, value)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde::Deserialize;
    use serde_json::{Value, json};
    use sovereign_config_core::{
        ConfigPath, MaskedSecret, PlainValue, RevealedSecret, SubTreeValue, ValueContent,
    };

    use super::{ProviderError, subtree_to_json};

    fn path(value: &str) -> ConfigPath {
        ConfigPath::parse(value).unwrap()
    }

    fn plain(path_value: &str, text: &str) -> SubTreeValue {
        SubTreeValue {
            path: path(path_value),
            value: ValueContent::Plain(PlainValue::new(text)),
        }
    }

    fn secret(path_value: &str) -> SubTreeValue {
        SubTreeValue {
            path: path(path_value),
            value: ValueContent::Secret(MaskedSecret),
        }
    }

    #[test]
    fn maps_nested_plain_values_relative_to_root() {
        let root = path("/apps/api");
        let values = [
            plain("/apps/api/database/url", "postgres://localhost"),
            plain("/apps/api/feature", "on"),
        ];
        let json = subtree_to_json(&root, &values, &BTreeMap::new()).unwrap();
        assert_eq!(
            json,
            json!({"database": {"url": "postgres://localhost"}, "feature": "on"})
        );
    }

    #[test]
    fn maps_exact_root_selection_as_scalar_string() {
        let root = path("/apps/api/feature");
        let values = [plain("/apps/api/feature", "on")];
        let json = subtree_to_json(&root, &values, &BTreeMap::new()).unwrap();
        assert_eq!(json, Value::String("on".to_owned()));
    }

    #[test]
    fn maps_empty_subtree_as_empty_object() {
        let root = path("/apps/api");
        let json = subtree_to_json(&root, &[], &BTreeMap::new()).unwrap();
        assert_eq!(json, json!({}));
    }

    #[test]
    fn maps_root_slash_selection() {
        let root = ConfigPath::root();
        let values = [plain("/apps/api/feature", "on")];
        let json = subtree_to_json(&root, &values, &BTreeMap::new()).unwrap();
        assert_eq!(json, json!({"apps": {"api": {"feature": "on"}}}));
    }

    #[test]
    fn reveals_secret_leaves_with_real_text() {
        let root = path("/apps/api");
        let values = [
            plain("/apps/api/feature", "on"),
            secret("/apps/api/database/password"),
        ];
        let mut revealed = BTreeMap::new();
        revealed.insert(
            path("/apps/api/database/password"),
            RevealedSecret::new("hunter2-sentinel"),
        );
        let json = subtree_to_json(&root, &values, &revealed).unwrap();
        assert_eq!(
            json,
            json!({"feature": "on", "database": {"password": "hunter2-sentinel"}})
        );
    }

    #[test]
    fn missing_revealed_secret_is_invalid_conversion() {
        let root = path("/apps/api");
        let values = [secret("/apps/api/password")];
        let error = subtree_to_json(&root, &values, &BTreeMap::new()).unwrap_err();
        assert_eq!(error, ProviderError::InvalidConversion);
    }

    #[test]
    fn value_and_object_collision_is_invalid_conversion() {
        let root = path("/apps/api");
        for values in [
            [
                plain("/apps/api/a", "leaf"),
                plain("/apps/api/a/b", "child"),
            ],
            [
                plain("/apps/api/a/b", "child"),
                plain("/apps/api/a", "leaf"),
            ],
        ] {
            let error = subtree_to_json(&root, &values, &BTreeMap::new()).unwrap_err();
            assert_eq!(error, ProviderError::InvalidConversion);
        }
    }

    #[test]
    fn path_outside_root_is_invalid_conversion() {
        let root = path("/apps/api");
        let values = [plain("/apps/other/feature", "on")];
        let error = subtree_to_json(&root, &values, &BTreeMap::new()).unwrap_err();
        assert_eq!(error, ProviderError::InvalidConversion);
    }

    #[test]
    fn invalid_conversion_error_names_no_value() {
        assert_eq!(
            ProviderError::InvalidConversion.to_string(),
            "configuration could not be converted to the requested type"
        );
    }

    #[test]
    fn maps_into_a_typed_struct() {
        #[derive(Debug, Deserialize, Eq, PartialEq)]
        struct Database {
            url: String,
            password: String,
        }
        #[derive(Debug, Deserialize, Eq, PartialEq)]
        struct AppConfig {
            feature: String,
            database: Database,
        }

        let root = path("/apps/api");
        let values = [
            plain("/apps/api/feature", "on"),
            plain("/apps/api/database/url", "postgres://localhost"),
            secret("/apps/api/database/password"),
        ];
        let mut revealed = BTreeMap::new();
        revealed.insert(
            path("/apps/api/database/password"),
            RevealedSecret::new("hunter2-sentinel"),
        );
        let json = subtree_to_json(&root, &values, &revealed).unwrap();
        let config: AppConfig = serde_json::from_value(json).unwrap();
        assert_eq!(
            config,
            AppConfig {
                feature: "on".to_owned(),
                database: Database {
                    url: "postgres://localhost".to_owned(),
                    password: "hunter2-sentinel".to_owned(),
                },
            }
        );
    }
}
