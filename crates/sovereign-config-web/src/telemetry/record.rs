//! What the page may say, and its OTLP/JSON form.
//!
//! **Nothing dynamic reaches a record.** The body and every attribute value
//! are `&'static str` or a number, and every key is a [`Key`]: a record can
//! only ever carry text compiled into this build. That is what keeps a token,
//! a secret the page is showing, a configuration value or a path out of
//! telemetry — not a review of each call site, but the types. The one
//! runtime string, `service.version`, is on the resource and comes from the
//! product's own configuration document.
//!
//! No `user.*` attribute is set here: the ingest stamps identity from the
//! token and discards whatever a client claims.

use serde_json::{Value, json};
use sovereign_config_core::ErrorKind;

use super::context::TraceContext;

pub(crate) const SERVICE_NAME: &str = "sovereign-config-web";

/// Every attribute key the page emits. Semantic-convention names where the
/// conventions have one, `sovereign_config.`-prefixed otherwise (AGENTS.md
/// §4), and a test walks [`Key::ALL`] against the forbidden names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Key {
    RpcSystem,
    RpcService,
    RpcMethod,
    ErrorType,
    DurationMs,
}

impl Key {
    #[cfg(test)]
    pub(crate) const ALL: &'static [Self] = &[
        Self::RpcSystem,
        Self::RpcService,
        Self::RpcMethod,
        Self::ErrorType,
        Self::DurationMs,
    ];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::RpcSystem => "rpc.system",
            Self::RpcService => "rpc.service",
            Self::RpcMethod => "rpc.method",
            Self::ErrorType => "error.type",
            Self::DurationMs => "sovereign_config.client.duration_ms",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AttributeValue {
    Text(&'static str),
    Integer(i64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Severity {
    Info,
    Warn,
}

impl Severity {
    const fn number(self) -> u8 {
        match self {
            Self::Info => 9,
            Self::Warn => 13,
        }
    }

    const fn text(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Warn => "WARN",
        }
    }
}

/// One log record, with the action it belongs to.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Record {
    pub(crate) time_unix_ms: f64,
    pub(crate) severity: Severity,
    pub(crate) body: &'static str,
    pub(crate) attributes: Vec<(Key, AttributeValue)>,
    pub(crate) context: Option<TraceContext>,
}

impl Record {
    /// The outcome of one gRPC-Web call. `route` is the call's compiled-in
    /// path, `/<service>/<method>`; the error, when there was one, is named by
    /// its kind and never by its message.
    pub(crate) fn rpc(
        time_unix_ms: f64,
        route: &'static str,
        duration_ms: f64,
        error: Option<ErrorKind>,
        context: Option<TraceContext>,
    ) -> Self {
        let (service, method) = route
            .trim_start_matches('/')
            .split_once('/')
            .unwrap_or((route, ""));
        let mut attributes = vec![
            (Key::RpcSystem, AttributeValue::Text("grpc")),
            (Key::RpcService, AttributeValue::Text(service)),
            (Key::RpcMethod, AttributeValue::Text(method)),
            (
                Key::DurationMs,
                // Saturating: a clock that jumped is not worth a panic.
                #[allow(clippy::cast_possible_truncation)]
                AttributeValue::Integer(duration_ms.max(0.0).round() as i64),
            ),
        ];
        if let Some(kind) = error {
            attributes.push((Key::ErrorType, AttributeValue::Text(error_type(kind))));
        }
        Self {
            time_unix_ms,
            severity: if error.is_some() {
                Severity::Warn
            } else {
                Severity::Info
            },
            body: if error.is_some() {
                "gRPC-Web call failed"
            } else {
                "gRPC-Web call completed"
            },
            attributes,
            context,
        }
    }

    /// The OTLP/JSON `LogRecord`. Ids are hex, as OTLP/JSON specifies, and
    /// the 64-bit timestamps are strings.
    pub(crate) fn to_otlp(&self) -> Value {
        let nanos = unix_nanos(self.time_unix_ms);
        let mut record = json!({
            "timeUnixNano": nanos,
            "observedTimeUnixNano": nanos,
            "severityNumber": self.severity.number(),
            "severityText": self.severity.text(),
            "body": { "stringValue": self.body },
            "attributes": self.attributes.iter().map(|(key, value)| attribute(key.as_str(), *value)).collect::<Vec<_>>(),
        });
        if let Some(context) = self.context {
            record["traceId"] = Value::String(context.trace_id_hex());
            record["spanId"] = Value::String(context.span_id_hex());
            record["flags"] = json!(1);
        }
        record
    }
}

/// The request body for a batch of already-encoded records: one resource
/// (this service and its build), one scope.
pub(crate) fn logs_request(service_version: &str, encoded_records: &[String]) -> String {
    let resource = json!({
        "attributes": [
            {"key": "service.name", "value": {"stringValue": SERVICE_NAME}},
            {"key": "service.version", "value": {"stringValue": service_version}},
        ],
    });
    let scope = json!({ "name": SERVICE_NAME, "version": service_version });
    format!(
        "{{\"resourceLogs\":[{{\"resource\":{resource},\"scopeLogs\":[{{\"scope\":{scope},\"logRecords\":[{}]}}]}}]}}",
        encoded_records.join(",")
    )
}

fn attribute(key: &str, value: AttributeValue) -> Value {
    let value = match value {
        AttributeValue::Text(text) => json!({ "stringValue": text }),
        // OTLP/JSON carries 64-bit integers as strings.
        AttributeValue::Integer(number) => json!({ "intValue": number.to_string() }),
    };
    json!({ "key": key, "value": value })
}

fn unix_nanos(unix_ms: f64) -> String {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let millis = unix_ms.max(0.0).round() as u64;
    format!("{millis}000000")
}

/// The bounded name of an error kind, for `error.type`.
///
/// Exhaustive, so a new kind fails to compile until it has a name here.
pub(crate) const fn error_type(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::Unauthenticated => "unauthenticated",
        ErrorKind::PermissionDenied => "permission_denied",
        ErrorKind::IncompatibleProtocol => "incompatible_protocol",
        ErrorKind::VersionNotServed => "version_not_served",
        ErrorKind::InvalidRequest => "invalid_request",
        ErrorKind::NotFound => "not_found",
        ErrorKind::Conflict => "conflict",
        ErrorKind::Unavailable => "unavailable",
        ErrorKind::Internal => "internal",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use sovereign_config_core::ErrorKind;

    use super::{Key, Record, logs_request};
    use crate::telemetry::context::TraceContext;

    const FORBIDDEN: [&str; 4] = ["token", "password", "secret", "value"];

    fn context() -> TraceContext {
        TraceContext::from_random([0xab; 24])
    }

    /// Every key the page can emit, walked from the enumeration so a key
    /// added later is covered without editing this test.
    #[test]
    fn no_attribute_key_names_a_forbidden_field() {
        for key in Key::ALL {
            let name = key.as_str();
            for forbidden in FORBIDDEN {
                assert!(!name.contains(forbidden), "{name} names {forbidden}");
            }
            assert!(
                !name.starts_with("user.") && !name.starts_with("session."),
                "{name}: identity is the ingest's to stamp"
            );
            assert!(
                name.starts_with("rpc.")
                    || name.starts_with("error.")
                    || name.starts_with("sovereign_config."),
                "{name} is neither a semantic-convention name nor product-prefixed"
            );
        }
    }

    /// Every record the page builds, encoded exactly as it is sent: no key
    /// anywhere in it names a forbidden field, and none claims an identity.
    #[test]
    fn no_encoded_record_carries_a_forbidden_field_name() {
        let records = [
            Record::rpc(
                1.0,
                "/sovereign.config.v4.Configuration/RevealSecret",
                3.0,
                None,
                Some(context()),
            ),
            Record::rpc(
                1.0,
                "/sovereign.config.v4.Configuration/PutValue",
                3.0,
                Some(ErrorKind::PermissionDenied),
                None,
            ),
        ];
        let encoded: Vec<String> = records
            .iter()
            .map(|record| record.to_otlp().to_string())
            .collect();
        let request: Value = serde_json::from_str(&logs_request("2.38.0", &encoded)).unwrap();
        let mut keys = Vec::new();
        collect_attribute_keys(&request, &mut keys);
        assert!(keys.contains(&"rpc.method".to_owned()));
        for key in keys {
            for forbidden in FORBIDDEN {
                assert!(!key.contains(forbidden), "{key} names {forbidden}");
            }
            assert!(
                !key.starts_with("user."),
                "{key}: the client claims no identity"
            );
        }
    }

    fn collect_attribute_keys(value: &Value, keys: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                if let Some(Value::Array(attributes)) = map.get("attributes") {
                    keys.extend(
                        attributes
                            .iter()
                            .filter_map(|attribute| attribute["key"].as_str().map(str::to_owned)),
                    );
                }
                map.values()
                    .for_each(|nested| collect_attribute_keys(nested, keys));
            }
            Value::Array(items) => items
                .iter()
                .for_each(|nested| collect_attribute_keys(nested, keys)),
            _ => {}
        }
    }

    #[test]
    fn a_record_carries_its_actions_trace_and_span_ids() {
        let record = Record::rpc(
            1_700_000_000_123.0,
            "/sovereign.config.v4.System/GetIdentity",
            12.4,
            None,
            Some(context()),
        )
        .to_otlp();
        assert_eq!(record["traceId"], "ab".repeat(16));
        assert_eq!(record["spanId"], "ab".repeat(8));
        assert_eq!(record["flags"], 1);
        assert_eq!(record["timeUnixNano"], "1700000000123000000");
        assert_eq!(record["severityText"], "INFO");
        let attributes = record["attributes"].as_array().unwrap();
        let find = |key: &str| {
            attributes
                .iter()
                .find(|attribute| attribute["key"] == key)
                .map(|attribute| attribute["value"].clone())
        };
        assert_eq!(
            find("rpc.service").unwrap()["stringValue"],
            "sovereign.config.v4.System"
        );
        assert_eq!(find("rpc.method").unwrap()["stringValue"], "GetIdentity");
        assert_eq!(
            find("sovereign_config.client.duration_ms").unwrap()["intValue"],
            "12"
        );
        assert!(find("error.type").is_none());
    }

    #[test]
    fn a_failed_call_is_a_warning_named_by_its_kind() {
        let record = Record::rpc(
            1.0,
            "/sovereign.config.v4.System/GetIdentity",
            1.0,
            Some(ErrorKind::Unavailable),
            None,
        )
        .to_otlp();
        assert_eq!(record["severityText"], "WARN");
        assert!(record.get("traceId").is_none());
        assert!(record.to_string().contains("\"unavailable\""));
    }

    #[test]
    fn the_request_names_the_service_and_its_build_only() {
        let request: Value = serde_json::from_str(&logs_request("2.38.4", &[])).unwrap();
        let resource = &request["resourceLogs"][0]["resource"]["attributes"];
        assert_eq!(
            resource,
            &serde_json::json!([
                {"key": "service.name", "value": {"stringValue": "sovereign-config-web"}},
                {"key": "service.version", "value": {"stringValue": "2.38.4"}},
            ])
        );
        assert_eq!(
            request["resourceLogs"][0]["scopeLogs"][0]["logRecords"],
            serde_json::json!([])
        );
    }
}
