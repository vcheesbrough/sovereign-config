//! Tool catalogue: names, JSON-Schema declarations, and bounded argument
//! parsing.
//!
//! Parsing is total and defensive: every argument is validated and bounded here
//! before any backend call, and the parsed [`ToolCall`] carries only canonical
//! domain types. A rejected argument yields a bounded [`ToolFailure`] that never
//! echoes the offending input.

use serde_json::{Value, json};
use sovereign_config_core::{
    ConfigPath, ConnectionId, DisplayName, ManagedPermission, ManagedPermissions, PlainValue,
    SecretInput, SubTreeMutationValue, parse_subtree_json,
};

use crate::errors::ToolFailure;

/// Upper bound on a single plain value, secret, or JSON document accepted as an
/// argument. Large enough for real configuration, small enough to reject abuse
/// before it reaches the server.
pub const MAX_VALUE_BYTES: usize = 1 << 20;
/// Upper bound on the number of permissions accepted for one connection.
pub const MAX_PERMISSIONS: usize = 16;

/// A fully validated tool invocation ready to run against a [`crate::backend::Backend`].
///
/// Not comparable or cloneable: it can carry a [`SecretInput`], which
/// deliberately implements neither `Eq` nor `Clone`.
#[derive(Debug)]
pub enum ToolCall {
    Status,
    Login,
    Logout,
    Get {
        path: ConfigPath,
        reveal: bool,
    },
    List {
        path: ConfigPath,
    },
    PutValue {
        path: ConfigPath,
        value: PlainValue,
    },
    PutSecret {
        path: ConfigPath,
        value: SecretInput,
    },
    ReplaceSubtree {
        path: ConfigPath,
        values: Vec<SubTreeMutationValue>,
    },
    Delete {
        path: ConfigPath,
        recurse: bool,
    },
    RevealSecret {
        path: ConfigPath,
    },
    ListConnections,
    CreateConnection {
        display_name: DisplayName,
        root: ConfigPath,
        permissions: ManagedPermissions,
    },
    RotateConnection {
        connection_id: ConnectionId,
    },
    RevokeConnection {
        connection_id: ConnectionId,
    },
}

const INVALID: &str = "invalid_request";

fn invalid(message: &'static str) -> ToolFailure {
    ToolFailure::new(INVALID, message)
}

fn require_str<'a>(arguments: &'a Value, key: &str) -> Result<&'a str, ToolFailure> {
    arguments
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("a required string argument is missing or not a string"))
}

fn optional_bool(arguments: &Value, key: &str) -> Result<bool, ToolFailure> {
    match arguments.get(key) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(invalid("a boolean argument has the wrong type")),
    }
}

fn bounded(value: &str) -> Result<&str, ToolFailure> {
    if value.len() > MAX_VALUE_BYTES {
        return Err(invalid("value exceeds the maximum accepted size"));
    }
    Ok(value)
}

fn operation_path(arguments: &Value) -> Result<ConfigPath, ToolFailure> {
    ConfigPath::parse_operation(require_str(arguments, "path")?)
        .map_err(|_| invalid("path must name a configuration value"))
}

fn selection_path(arguments: &Value) -> Result<ConfigPath, ToolFailure> {
    selection_at(arguments, "path")
}

fn selection_at(arguments: &Value, key: &str) -> Result<ConfigPath, ToolFailure> {
    ConfigPath::parse_selection(require_str(arguments, key)?)
        .map_err(|_| invalid("path must name a configuration subtree"))
}

/// Parses `(name, arguments)` into a validated [`ToolCall`].
///
/// # Errors
///
/// Returns a bounded [`ToolFailure`] when the tool is unknown or an argument is
/// missing, mistyped, out of bounds, or not canonical.
pub fn parse_call(name: &str, arguments: &Value) -> Result<ToolCall, ToolFailure> {
    let arguments = if arguments.is_null() {
        &json!({})
    } else if arguments.is_object() {
        arguments
    } else {
        return Err(invalid("tool arguments must be a JSON object"));
    };
    match name {
        "status" => Ok(ToolCall::Status),
        "login" => Ok(ToolCall::Login),
        "logout" => Ok(ToolCall::Logout),
        "get" => Ok(ToolCall::Get {
            path: selection_path(arguments)?,
            reveal: optional_bool(arguments, "reveal")?,
        }),
        "list" => Ok(ToolCall::List {
            path: selection_path(arguments)?,
        }),
        "put_value" => Ok(ToolCall::PutValue {
            path: operation_path(arguments)?,
            value: PlainValue::new(bounded(require_str(arguments, "value")?)?),
        }),
        "put_secret" => Ok(ToolCall::PutSecret {
            path: operation_path(arguments)?,
            value: SecretInput::new(bounded(require_str(arguments, "value")?)?),
        }),
        "replace_subtree" => {
            let path = selection_path(arguments)?;
            let json = bounded(require_str(arguments, "json")?)?;
            let values = parse_subtree_json(&path, json)
                .map_err(|_| invalid("json is not a valid configuration subtree document"))?;
            Ok(ToolCall::ReplaceSubtree { path, values })
        }
        "delete" => {
            let recurse = optional_bool(arguments, "recurse")?;
            let path = if recurse {
                selection_path(arguments)?
            } else {
                operation_path(arguments)?
            };
            Ok(ToolCall::Delete { path, recurse })
        }
        "reveal_secret" => Ok(ToolCall::RevealSecret {
            path: operation_path(arguments)?,
        }),
        "list_connections" => Ok(ToolCall::ListConnections),
        "create_connection" => Ok(ToolCall::CreateConnection {
            display_name: DisplayName::parse(require_str(arguments, "display_name")?)
                .map_err(|_| invalid("display_name is not a valid connection name"))?,
            root: selection_at(arguments, "root")?,
            permissions: parse_permissions(arguments)?,
        }),
        "rotate_connection" => Ok(ToolCall::RotateConnection {
            connection_id: connection_id(arguments)?,
        }),
        "revoke_connection" => Ok(ToolCall::RevokeConnection {
            connection_id: connection_id(arguments)?,
        }),
        _ => Err(ToolFailure::new("unknown_tool", "unknown tool")),
    }
}

fn connection_id(arguments: &Value) -> Result<ConnectionId, ToolFailure> {
    ConnectionId::parse(require_str(arguments, "connection_id")?)
        .map_err(|_| invalid("connection_id is not a valid connection identifier"))
}

fn parse_permissions(arguments: &Value) -> Result<ManagedPermissions, ToolFailure> {
    let Some(entries) = arguments.get("permissions").and_then(Value::as_array) else {
        return Err(invalid("permissions must be an array of permission names"));
    };
    if entries.len() > MAX_PERMISSIONS {
        return Err(invalid("too many permissions were requested"));
    }
    let mut parsed = Vec::with_capacity(entries.len());
    for entry in entries {
        let name = entry
            .as_str()
            .ok_or_else(|| invalid("each permission must be a string"))?;
        parsed.push(
            ManagedPermission::parse(name)
                .map_err(|_| invalid("an unknown permission name was requested"))?,
        );
    }
    ManagedPermissions::new(parsed).map_err(|_| invalid("the requested permission set is invalid"))
}

/// The complete tool catalogue as the `tools/list` result payload.
///
/// Schemas are intentionally strict (`additionalProperties: false`) so callers
/// cannot smuggle unexpected fields, and the surface is additive: later slices
/// (e.g. alias tools from card #243) append entries without reshaping these.
#[must_use]
pub fn catalogue() -> Value {
    let path_property = json!({
        "type": "string",
        "description": "Absolute configuration path beginning with '/'.",
    });
    json!([
        tool(
            "status",
            "Report the service version and whether the current profile is authenticated. Takes no arguments.",
            json!({})
        ),
        tool(
            "login",
            "Begin an explicit device-authorization login. Surfaces the verification URL and user code as a log notification, then polls the provider to completion and stores the refresh credential. Takes no arguments.",
            json!({})
        ),
        tool(
            "logout",
            "Delete the stored refresh credential for the current profile. Takes no arguments.",
            json!({})
        ),
        tool_with(
            "get",
            "Read the configuration value or subtree at an absolute path, rendered as JSON. Secrets are masked unless 'reveal' is true, in which case each secret is revealed through an explicit authorized reveal.",
            json!({ "path": path_property, "reveal": { "type": "boolean", "description": "Reveal secret values via explicit authorized reveals (default false)." } }),
            &["path"],
        ),
        tool_with(
            "list",
            "List the readable values and child paths directly beneath an absolute path.",
            json!({ "path": path_property }),
            &["path"],
        ),
        tool_with(
            "put_value",
            "Create or replace one exact plain configuration value.",
            json!({ "path": path_property, "value": { "type": "string", "description": "Plain value to store." } }),
            &["path", "value"],
        ),
        tool_with(
            "put_secret",
            "Create or replace one exact secret configuration value. The value is never echoed back.",
            json!({ "path": path_property, "value": { "type": "string", "description": "Secret value to store." } }),
            &["path", "value"],
        ),
        tool_with(
            "replace_subtree",
            "Atomically replace every value at or below an absolute path from a strict JSON document (JSON merge).",
            json!({ "path": path_property, "json": { "type": "string", "description": "Strict JSON subtree document." } }),
            &["path", "json"],
        ),
        tool_with(
            "delete",
            "Permanently delete one exact value, or an entire subtree when 'recurse' is true.",
            json!({ "path": path_property, "recurse": { "type": "boolean", "description": "Delete the whole subtree at the path (default false)." } }),
            &["path"],
        ),
        tool_with(
            "reveal_secret",
            "Reveal the plaintext of one exact secret value through an explicit authorized reveal.",
            json!({ "path": path_property }),
            &["path"],
        ),
        tool(
            "list_connections",
            "List metadata for managed application connections rooted in manageable paths. Takes no arguments.",
            json!({})
        ),
        tool_with(
            "create_connection",
            "Create one managed application connection with the given permissions (grants) on its root path, returning its one-time connection URL.",
            json!({
                "display_name": { "type": "string", "description": "Human-readable connection name." },
                "root": { "type": "string", "description": "Absolute root path the connection is scoped to." },
                "permissions": {
                    "type": "array",
                    "description": "Permission (grant) names to delegate to the connection.",
                    "items": { "type": "string" },
                    "maxItems": MAX_PERMISSIONS,
                },
            }),
            &["display_name", "root", "permissions"],
        ),
        tool_with(
            "rotate_connection",
            "Rotate one managed connection's credential, returning a new one-time connection URL.",
            json!({ "connection_id": { "type": "string", "description": "Identifier of the connection to rotate." } }),
            &["connection_id"],
        ),
        tool_with(
            "revoke_connection",
            "Permanently revoke one managed connection. Returns no credential.",
            json!({ "connection_id": { "type": "string", "description": "Identifier of the connection to revoke." } }),
            &["connection_id"],
        ),
    ])
}

fn tool(name: &str, description: &str, properties: Value) -> Value {
    tool_with(name, description, properties, &[])
}

fn tool_with(name: &str, description: &str, properties: Value, required: &[&str]) -> Value {
    let mut schema = serde_json::Map::new();
    schema.insert("type".to_owned(), Value::from("object"));
    schema.insert("properties".to_owned(), properties);
    schema.insert("required".to_owned(), json!(required));
    schema.insert("additionalProperties".to_owned(), Value::Bool(false));
    let mut tool = serde_json::Map::new();
    tool.insert("name".to_owned(), Value::from(name));
    tool.insert("description".to_owned(), Value::from(description));
    tool.insert("inputSchema".to_owned(), Value::Object(schema));
    Value::Object(tool)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{ToolCall, catalogue, parse_call};

    #[test]
    fn catalogue_lists_every_implemented_tool_with_object_schemas() {
        let listed = catalogue();
        let names: Vec<&str> = listed
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        for expected in [
            "status",
            "login",
            "logout",
            "get",
            "list",
            "put_value",
            "put_secret",
            "replace_subtree",
            "delete",
            "reveal_secret",
            "list_connections",
            "create_connection",
            "rotate_connection",
            "revoke_connection",
        ] {
            assert!(names.contains(&expected), "missing tool {expected}");
        }
        for tool in listed.as_array().unwrap() {
            assert_eq!(tool["inputSchema"]["type"], "object");
            assert_eq!(tool["inputSchema"]["additionalProperties"], false);
        }
        // Aliases are deferred to card #243 and must not appear yet.
        assert!(!names.iter().any(|name| name.contains("alias")));
    }

    #[test]
    fn parses_bounded_and_canonical_arguments() {
        assert!(matches!(
            parse_call("status", &json!({})).unwrap(),
            ToolCall::Status
        ));
        match parse_call("get", &json!({ "path": "/apps/api", "reveal": true })).unwrap() {
            ToolCall::Get { path, reveal } => {
                assert_eq!(path.as_str(), "/apps/api");
                assert!(reveal);
            }
            _ => panic!("expected get"),
        }
    }

    #[test]
    fn rejects_unknown_tool_and_bad_arguments() {
        assert_eq!(
            parse_call("nope", &json!({})).unwrap_err().code,
            "unknown_tool"
        );
        assert!(parse_call("get", &json!({})).is_err());
        assert!(parse_call("get", &json!({ "path": "not-rooted" })).is_err());
        assert!(parse_call("put_value", &json!({ "path": "/a", "value": 1 })).is_err());
        assert!(parse_call("delete", &json!({ "path": "/a", "recurse": "yes" })).is_err());
    }

    #[test]
    fn rejects_oversized_values() {
        let big = "x".repeat(super::MAX_VALUE_BYTES + 1);
        assert!(parse_call("put_value", &json!({ "path": "/a", "value": big })).is_err());
    }

    #[test]
    fn create_connection_requires_known_permissions() {
        assert!(
            parse_call(
                "create_connection",
                &json!({ "display_name": "App", "root": "/apps", "permissions": ["bogus"] }),
            )
            .is_err()
        );
        assert!(
            parse_call(
                "create_connection",
                &json!({ "display_name": "App", "root": "/apps", "permissions": ["read"] }),
            )
            .is_ok()
        );
    }
}
