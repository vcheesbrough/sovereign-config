//! The page's spans, and their OTLP/JSON form.
//!
//! One **action** span per user action — the root of its trace — and one
//! **client** span per gRPC-Web call that action made, whose id is the
//! parent the call's `traceparent` names, so the server's request span hangs
//! beneath it (#420).
//!
//! As with records (`record.rs`), **nothing dynamic reaches a span**: the name
//! is an [`ActionKind`] or a compiled-in route, every key is a [`Key`] and
//! every text value is `&'static str`. The keys on a call span are the ones
//! the server's own request span carries (`spans.rs` in the server crate), so
//! the two halves of a call read alike in Tempo.

use serde_json::{Value, json};
use sovereign_config_core::ErrorKind;

use super::{
    context::TraceContext,
    record::{self, AttributeValue, Key},
};

/// What a user did, as the name of its root span.
///
/// A bounded, compiled-in set: never a path, a value or a screen's content.
/// Exhaustive, so a new action fails to compile until it has a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ActionKind {
    /// The page loading: configuration, login callback, the first views.
    PageLoad,
    /// The Downloads view's own load, which needs no session.
    LoadDownloads,
    /// An in-app route change.
    Navigate,
    /// Back or Forward.
    HistoryNavigate,
    LogIn,
    ToggleJsonMode,
    SaveJson,
    CreateValue,
    SaveValue,
    SaveSecret,
    RevealSecret,
    DeleteValue,
    AddPath,
    RefreshPathOptions,
    CopyCommand,
    CreateConnection,
    RotateConnection,
    RevokeConnection,
    CopyConnectionUrl,
    FilterAudit,
    RetryAudit,
    NextAuditPage,
}

impl ActionKind {
    #[cfg(test)]
    pub(crate) const ALL: &'static [Self] = &[
        Self::PageLoad,
        Self::LoadDownloads,
        Self::Navigate,
        Self::HistoryNavigate,
        Self::LogIn,
        Self::ToggleJsonMode,
        Self::SaveJson,
        Self::CreateValue,
        Self::SaveValue,
        Self::SaveSecret,
        Self::RevealSecret,
        Self::DeleteValue,
        Self::AddPath,
        Self::RefreshPathOptions,
        Self::CopyCommand,
        Self::CreateConnection,
        Self::RotateConnection,
        Self::RevokeConnection,
        Self::CopyConnectionUrl,
        Self::FilterAudit,
        Self::RetryAudit,
        Self::NextAuditPage,
    ];

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::PageLoad => "page_load",
            Self::LoadDownloads => "load_downloads",
            Self::Navigate => "navigate",
            Self::HistoryNavigate => "history_navigate",
            Self::LogIn => "log_in",
            Self::ToggleJsonMode => "toggle_json_mode",
            Self::SaveJson => "save_json",
            Self::CreateValue => "create_value",
            Self::SaveValue => "save_value",
            Self::SaveSecret => "save_secret",
            Self::RevealSecret => "reveal_secret",
            Self::DeleteValue => "delete_value",
            Self::AddPath => "add_path",
            Self::RefreshPathOptions => "refresh_path_options",
            Self::CopyCommand => "copy_command",
            Self::CreateConnection => "create_connection",
            Self::RotateConnection => "rotate_connection",
            Self::RevokeConnection => "revoke_connection",
            Self::CopyConnectionUrl => "copy_connection_url",
            Self::FilterAudit => "filter_audit",
            Self::RetryAudit => "retry_audit",
            Self::NextAuditPage => "next_audit_page",
        }
    }
}

/// OTLP's span kinds, as far as the page uses them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SpanKind {
    Internal,
    Client,
}

impl SpanKind {
    const fn number(self) -> u8 {
        match self {
            Self::Internal => 1,
            Self::Client => 3,
        }
    }
}

/// One finished span.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Span {
    pub(crate) name: &'static str,
    pub(crate) kind: SpanKind,
    /// This span's trace and id.
    pub(crate) context: TraceContext,
    /// The span it hangs under, in the same trace; `None` for a root.
    pub(crate) parent: Option<TraceContext>,
    pub(crate) start_unix_ms: f64,
    pub(crate) end_unix_ms: f64,
    pub(crate) attributes: Vec<(Key, AttributeValue)>,
    pub(crate) failed: bool,
}

impl Span {
    /// The root span of one action, with how many calls it made and whether
    /// any of them failed.
    pub(crate) fn action(
        kind: ActionKind,
        context: TraceContext,
        start_unix_ms: f64,
        end_unix_ms: f64,
        calls: u32,
        failed_calls: u32,
    ) -> Self {
        Self {
            name: kind.name(),
            kind: SpanKind::Internal,
            context,
            parent: None,
            start_unix_ms,
            end_unix_ms: end_unix_ms.max(start_unix_ms),
            attributes: vec![(Key::RpcCount, AttributeValue::Integer(i64::from(calls)))],
            failed: failed_calls > 0,
        }
    }

    /// One gRPC-Web call. `route` is the compiled-in `/<service>/<method>`;
    /// `status` the gRPC status the server answered with, when it answered
    /// with one; `error` the call's outcome as the page saw it.
    ///
    /// A client span is failed for **every** non-`OK` outcome — the gRPC
    /// conventions ask that of the client side, where the server marks only
    /// its own faults — and names it by the status or, where no status came
    /// back, by the error's kind.
    pub(crate) fn rpc(
        route: &'static str,
        context: TraceContext,
        parent: TraceContext,
        start_unix_ms: f64,
        end_unix_ms: f64,
        status: Option<u16>,
        error: Option<ErrorKind>,
    ) -> Self {
        let method = route.strip_prefix('/').unwrap_or(route);
        let mut attributes = vec![
            (Key::RpcSystemName, AttributeValue::Text("grpc")),
            (Key::RpcMethod, AttributeValue::Text(method)),
        ];
        if let Some(version) = protocol_version(method) {
            attributes.push((Key::ProtocolVersion, AttributeValue::Text(version)));
        }
        let status_name = status.and_then(grpc_code_name);
        if let Some(name) = status_name {
            attributes.push((Key::RpcResponseStatusCode, AttributeValue::Text(name)));
        }
        let failed = error.is_some() || status.is_some_and(|code| code != 0);
        if failed {
            let error_type = match (status, status_name, error) {
                (Some(code), Some(name), _) if code != 0 => name,
                (_, _, Some(kind)) => record::error_type(kind),
                _ => "_OTHER",
            };
            attributes.push((Key::ErrorType, AttributeValue::Text(error_type)));
        }
        Self {
            name: method,
            kind: SpanKind::Client,
            context,
            parent: Some(parent),
            start_unix_ms,
            end_unix_ms: end_unix_ms.max(start_unix_ms),
            attributes,
            failed,
        }
    }

    /// The OTLP/JSON `Span`: ids in hex, 64-bit times as strings, and the
    /// status set only when failed (unset is OTLP's "nothing to say").
    pub(crate) fn to_otlp(&self) -> Value {
        let mut span = json!({
            "traceId": self.context.trace_id_hex(),
            "spanId": self.context.span_id_hex(),
            "flags": 1,
            "name": self.name,
            "kind": self.kind.number(),
            "startTimeUnixNano": record::unix_nanos(self.start_unix_ms),
            "endTimeUnixNano": record::unix_nanos(self.end_unix_ms),
            "attributes": self.attributes.iter().map(|(key, value)| record::attribute(key.as_str(), *value)).collect::<Vec<_>>(),
        });
        if let Some(parent) = self.parent {
            span["parentSpanId"] = Value::String(parent.span_id_hex());
        }
        if self.failed {
            span["status"] = json!({ "code": 2 });
        }
        span
    }
}

/// The request body for a batch of already-encoded spans: the same one
/// resource and scope as the page's logs.
pub(crate) fn traces_request(service_version: &str, encoded_spans: &[String]) -> String {
    let (resource, scope) = record::resource_and_scope(service_version);
    format!(
        "{{\"resourceSpans\":[{{\"resource\":{resource},\"scopeSpans\":[{{\"scope\":{scope},\"spans\":[{}]}}]}}]}}",
        encoded_spans.join(",")
    )
}

/// The protocol version a route's package names — `v4` for
/// `sovereign.config.v4.System/GetIdentity` — or `None` for the unversioned
/// handshake. The same derivation as the server's span.
fn protocol_version(method: &'static str) -> Option<&'static str> {
    method
        .strip_prefix("sovereign.config.")
        .and_then(|rest| rest.split_once('.'))
        .map(|(version, _)| version)
        .filter(|version| !version.contains('/'))
}

/// `rpc.response.status_code` as the conventions spell it, for the codes
/// gRPC defines; `None` for anything else, which is left unrecorded.
pub(crate) const fn grpc_code_name(code: u16) -> Option<&'static str> {
    Some(match code {
        0 => "OK",
        1 => "CANCELLED",
        2 => "UNKNOWN",
        3 => "INVALID_ARGUMENT",
        4 => "DEADLINE_EXCEEDED",
        5 => "NOT_FOUND",
        6 => "ALREADY_EXISTS",
        7 => "PERMISSION_DENIED",
        8 => "RESOURCE_EXHAUSTED",
        9 => "FAILED_PRECONDITION",
        10 => "ABORTED",
        11 => "OUT_OF_RANGE",
        12 => "UNIMPLEMENTED",
        13 => "INTERNAL",
        14 => "UNAVAILABLE",
        15 => "DATA_LOSS",
        16 => "UNAUTHENTICATED",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use sovereign_config_core::ErrorKind;

    use super::{ActionKind, Span, grpc_code_name, traces_request};
    use crate::telemetry::context::TraceContext;

    const FORBIDDEN: [&str; 4] = ["token", "password", "secret", "value"];

    fn action() -> TraceContext {
        TraceContext::from_random([0xab; 24])
    }

    fn call() -> TraceContext {
        action().child([0xcd; 8])
    }

    fn attribute(span: &Value, key: &str) -> Option<Value> {
        span["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|attribute| attribute["key"] == key)
            .map(|attribute| attribute["value"].clone())
    }

    /// Every action has a bounded, `snake_case` name, and no two share one.
    #[test]
    fn every_action_has_its_own_bounded_name() {
        let mut names = std::collections::BTreeSet::new();
        for kind in ActionKind::ALL {
            let name = kind.name();
            assert!(
                name.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{name}"
            );
            assert!(names.insert(name), "{name} is used twice");
        }
    }

    /// The call span is a child of the action span, in the same trace, and
    /// its id is the parent the call's `traceparent` names — so the server's
    /// request span hangs under it.
    #[test]
    fn a_call_span_hangs_under_its_action_and_is_the_traceparents_parent() {
        let root = Span::action(ActionKind::Navigate, action(), 10.0, 50.0, 1, 0).to_otlp();
        let child = Span::rpc(
            "/sovereign.config.v4.Configuration/ListValues",
            call(),
            action(),
            12.0,
            40.0,
            Some(0),
            None,
        )
        .to_otlp();
        assert_eq!(root["name"], "navigate");
        assert_eq!(root["kind"], 1);
        assert!(root.get("parentSpanId").is_none(), "the action is the root");
        assert_eq!(child["traceId"], root["traceId"]);
        assert_eq!(child["parentSpanId"], root["spanId"]);
        assert_ne!(child["spanId"], root["spanId"]);
        assert_eq!(child["kind"], 3);
        assert_eq!(
            child["name"],
            "sovereign.config.v4.Configuration/ListValues"
        );
        let traceparent = call().traceparent();
        let [_, trace, parent, _]: [&str; 4] = traceparent
            .split('-')
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        assert_eq!(child["traceId"], trace);
        assert_eq!(child["spanId"], parent);
        assert_eq!(child["startTimeUnixNano"], "12000000");
        assert_eq!(child["endTimeUnixNano"], "40000000");
        assert!(child.get("status").is_none());
        assert_eq!(
            attribute(&root, "sovereign_config.client.rpc_count").unwrap()["intValue"],
            "1"
        );
    }

    /// The keys the server's request span carries, with its values.
    #[test]
    fn a_call_span_carries_the_servers_semantic_convention_keys() {
        let span = Span::rpc(
            "/sovereign.config.v4.System/GetIdentity",
            call(),
            action(),
            1.0,
            2.0,
            Some(0),
            None,
        )
        .to_otlp();
        assert_eq!(
            attribute(&span, "rpc.system.name").unwrap()["stringValue"],
            "grpc"
        );
        assert_eq!(
            attribute(&span, "rpc.method").unwrap()["stringValue"],
            "sovereign.config.v4.System/GetIdentity"
        );
        assert_eq!(
            attribute(&span, "rpc.response.status_code").unwrap()["stringValue"],
            "OK"
        );
        assert_eq!(
            attribute(&span, "sovereign_config.protocol.version").unwrap()["stringValue"],
            "v4"
        );
        assert!(attribute(&span, "error.type").is_none());
        let handshake = Span::rpc(
            "/sovereign.config.Handshake/Negotiate",
            call(),
            action(),
            1.0,
            2.0,
            Some(0),
            None,
        )
        .to_otlp();
        assert!(attribute(&handshake, "sovereign_config.protocol.version").is_none());
    }

    #[test]
    fn a_failed_call_is_an_error_named_by_its_status_or_its_kind() {
        let refused = Span::rpc(
            "/sovereign.config.v4.Configuration/PutValue",
            call(),
            action(),
            1.0,
            2.0,
            Some(7),
            Some(ErrorKind::PermissionDenied),
        )
        .to_otlp();
        assert_eq!(refused["status"]["code"], 2);
        assert_eq!(
            attribute(&refused, "rpc.response.status_code").unwrap()["stringValue"],
            "PERMISSION_DENIED"
        );
        assert_eq!(
            attribute(&refused, "error.type").unwrap()["stringValue"],
            "PERMISSION_DENIED"
        );
        // No answer at all: no status to record, and the kind names it.
        let unreachable = Span::rpc(
            "/sovereign.config.v4.Configuration/PutValue",
            call(),
            action(),
            1.0,
            2.0,
            None,
            Some(ErrorKind::Unavailable),
        )
        .to_otlp();
        assert_eq!(unreachable["status"]["code"], 2);
        assert!(attribute(&unreachable, "rpc.response.status_code").is_none());
        assert_eq!(
            attribute(&unreachable, "error.type").unwrap()["stringValue"],
            "unavailable"
        );
        // An action with a failed call is failed too.
        let root = Span::action(ActionKind::SaveValue, action(), 1.0, 2.0, 2, 1).to_otlp();
        assert_eq!(root["status"]["code"], 2);
    }

    #[test]
    fn every_grpc_code_has_its_conventional_name() {
        assert_eq!(grpc_code_name(0), Some("OK"));
        assert_eq!(grpc_code_name(14), Some("UNAVAILABLE"));
        assert_eq!(grpc_code_name(16), Some("UNAUTHENTICATED"));
        assert_eq!(grpc_code_name(17), None);
        assert!((0..=16).all(|code| grpc_code_name(code).is_some()));
    }

    /// A clock that ran backwards does not produce a span that ends before
    /// it starts.
    #[test]
    fn a_span_never_ends_before_it_starts() {
        let span = Span::action(ActionKind::PageLoad, action(), 100.0, 90.0, 0, 0).to_otlp();
        assert_eq!(span["startTimeUnixNano"], span["endTimeUnixNano"]);
    }

    /// Every span the page can build, encoded as sent: no key names a
    /// forbidden field or claims an identity, and every key is a
    /// semantic-convention name or product-prefixed.
    #[test]
    fn no_encoded_span_carries_a_forbidden_field_name() {
        let mut spans: Vec<String> = ActionKind::ALL
            .iter()
            .map(|kind| {
                Span::action(*kind, action(), 1.0, 2.0, 3, 1)
                    .to_otlp()
                    .to_string()
            })
            .collect();
        spans.push(
            Span::rpc(
                "/sovereign.config.v4.Configuration/RevealSecret",
                call(),
                action(),
                1.0,
                2.0,
                Some(0),
                None,
            )
            .to_otlp()
            .to_string(),
        );
        spans.push(
            Span::rpc(
                "/sovereign.config.v4.Configuration/PutValue",
                call(),
                action(),
                1.0,
                2.0,
                None,
                Some(ErrorKind::Internal),
            )
            .to_otlp()
            .to_string(),
        );
        let request: Value = serde_json::from_str(&traces_request("2.39.0", &spans)).unwrap();
        let resource = &request["resourceSpans"][0]["resource"]["attributes"];
        assert_eq!(
            resource,
            &serde_json::json!([
                {"key": "service.name", "value": {"stringValue": "sovereign-config-web"}},
                {"key": "service.version", "value": {"stringValue": "2.39.0"}},
            ])
        );
        let encoded = &request["resourceSpans"][0]["scopeSpans"][0]["spans"];
        assert_eq!(encoded.as_array().unwrap().len(), ActionKind::ALL.len() + 2);
        for span in encoded.as_array().unwrap() {
            for attribute in span["attributes"].as_array().unwrap() {
                let key = attribute["key"].as_str().unwrap();
                for forbidden in FORBIDDEN {
                    assert!(!key.contains(forbidden), "{key} names {forbidden}");
                }
                assert!(
                    !key.starts_with("user.") && !key.starts_with("session."),
                    "{key}"
                );
                assert!(
                    key.starts_with("rpc.")
                        || key.starts_with("error.")
                        || key.starts_with("sovereign_config."),
                    "{key}"
                );
            }
        }
    }
}
