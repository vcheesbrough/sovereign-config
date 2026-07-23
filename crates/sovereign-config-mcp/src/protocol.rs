//! Minimal JSON-RPC 2.0 envelope handling for the MCP stdio transport.
//!
//! The MCP stdio transport frames every message as a single line of JSON
//! terminated by a newline, with no embedded newlines. This module parses
//! incoming lines into requests or notifications and builds the response and
//! notification envelopes. It deliberately owns only the transport envelope —
//! method dispatch and tool semantics live in [`crate::server`].

use serde_json::{Map, Value};

/// JSON-RPC standard error codes used by the server.
pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;

/// A parsed inbound JSON-RPC message.
pub enum Incoming {
    /// A request carrying an `id`; the peer expects exactly one response.
    Request {
        id: Value,
        method: String,
        params: Value,
    },
    /// A notification (no `id`); no response may be produced.
    Notification { method: String },
    /// The line was not a well-formed JSON-RPC message. The parse outcome
    /// records whether an `id` was recoverable so the caller can decide whether
    /// a response is owed.
    Invalid { id: Option<Value>, code: i64 },
}

/// Parses one framing line into an [`Incoming`] message.
///
/// A line that is not a JSON object, or that omits `method`, is reported as
/// [`Incoming::Invalid`]. The `id` is surfaced when present so the caller can
/// address an error response to a malformed request.
#[must_use]
pub fn parse_incoming(line: &str) -> Incoming {
    let Ok(value) = serde_json::from_str::<Value>(line) else {
        return Incoming::Invalid {
            id: None,
            code: PARSE_ERROR,
        };
    };
    let Some(object) = value.as_object() else {
        return Incoming::Invalid {
            id: None,
            code: INVALID_REQUEST,
        };
    };
    let id = object.get("id").cloned();
    let params = object.get("params").cloned().unwrap_or(Value::Null);
    let Some(method) = object.get("method").and_then(Value::as_str) else {
        return Incoming::Invalid {
            id,
            code: INVALID_REQUEST,
        };
    };
    let method = method.to_owned();
    match id {
        Some(id) => Incoming::Request { id, method, params },
        None => Incoming::Notification { method },
    }
}

/// Builds a successful response envelope for the given request `id`.
#[must_use]
pub fn success(id: Value, result: Value) -> Value {
    let mut envelope = Map::new();
    envelope.insert("jsonrpc".to_owned(), Value::from("2.0"));
    envelope.insert("id".to_owned(), id);
    envelope.insert("result".to_owned(), result);
    Value::Object(envelope)
}

/// Builds an error response envelope for the given request `id`.
///
/// `message` is always a bounded, caller-independent string; this function
/// never embeds request arguments, so error envelopes cannot leak inputs.
#[must_use]
pub fn error(id: Value, code: i64, message: &str) -> Value {
    let mut detail = Map::new();
    detail.insert("code".to_owned(), Value::from(code));
    detail.insert("message".to_owned(), Value::from(message));
    let mut envelope = Map::new();
    envelope.insert("jsonrpc".to_owned(), Value::from("2.0"));
    envelope.insert("id".to_owned(), id);
    envelope.insert("error".to_owned(), Value::Object(detail));
    Value::Object(envelope)
}

/// Builds a server-to-client notification envelope.
#[must_use]
pub fn notification(method: &str, params: Value) -> Value {
    let mut envelope = Map::new();
    envelope.insert("jsonrpc".to_owned(), Value::from("2.0"));
    envelope.insert("method".to_owned(), Value::from(method));
    envelope.insert("params".to_owned(), params);
    Value::Object(envelope)
}

#[cfg(test)]
mod tests {
    use super::{Incoming, parse_incoming};

    #[test]
    fn parses_a_request_with_id_and_params() {
        match parse_incoming(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#) {
            Incoming::Request { id, method, .. } => {
                assert_eq!(id, serde_json::json!(1));
                assert_eq!(method, "tools/list");
            }
            _ => panic!("expected a request"),
        }
    }

    #[test]
    fn parses_a_notification_without_id() {
        match parse_incoming(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#) {
            Incoming::Notification { method } => {
                assert_eq!(method, "notifications/initialized");
            }
            _ => panic!("expected a notification"),
        }
    }

    #[test]
    fn rejects_non_json_and_non_object_and_methodless() {
        assert!(matches!(
            parse_incoming("not json"),
            Incoming::Invalid { .. }
        ));
        assert!(matches!(
            parse_incoming("[1,2,3]"),
            Incoming::Invalid { .. }
        ));
        match parse_incoming(r#"{"jsonrpc":"2.0","id":7}"#) {
            Incoming::Invalid { id, .. } => assert_eq!(id, Some(serde_json::json!(7))),
            _ => panic!("expected invalid with recoverable id"),
        }
    }
}
