//! Span attribute keys: the shared constants product code sets attributes
//! with, and the list every exported key is checked against
//! (`observability` skill §4, §7).
//!
//! `tracing` macros take field names as literals, so a key at a span's
//! creation site cannot be one of these constants. The check therefore runs
//! on what an exporter received ([`is_known`]), not on the source: a typo in
//! a macro literal is an unknown key, and fails the test that exported it.

pub use opentelemetry_semantic_conventions::attribute::{
    CODE_FILE_PATH, CODE_LINE_NUMBER, DB_COLLECTION_NAME, DB_OPERATION_NAME, DB_SYSTEM_NAME,
    ERROR_TYPE, EXCEPTION_MESSAGE, EXCEPTION_STACKTRACE, HTTP_REQUEST_METHOD,
    HTTP_RESPONSE_STATUS_CODE, RPC_METHOD, RPC_METHOD_ORIGINAL, RPC_RESPONSE_STATUS_CODE,
    RPC_SYSTEM_NAME, SERVER_ADDRESS, URL_PATH, URL_TEMPLATE, USER_ID, USER_NAME,
};

/// The prefix of every key this product names for itself.
pub const PRODUCT_PREFIX: &str = "sovereign_config.";

/// The protocol version a request's route names (`v3`, `v4`), from the
/// compiled-in served set.
pub const PROTOCOL_VERSION: &str = "sovereign_config.protocol.version";

/// The span bridge's name for the module a span was created in. It is not a
/// semantic-convention key (the conventions have `code.function.name`, which
/// `tracing` cannot supply), and it is the one key this product exports that
/// is neither the conventions' nor its own; it is kept because it is the
/// quickest way from a span to the code that opened it.
pub const CODE_MODULE_NAME: &str = "code.module.name";

/// Every semantic-convention key a span of this product may carry: the ones
/// product code sets, and the ones the span bridge adds itself (code location,
/// and `exception.*` for a field named `error`).
///
/// The RPC keys are the conventions' current ones (`rpc.system.name`, a
/// fully-qualified `rpc.method`, `rpc.response.status_code`), not the
/// deprecated `rpc.system` / `rpc.service` / `rpc.grpc.status_code`.
pub const SEMANTIC_CONVENTION: [&str; 19] = [
    CODE_FILE_PATH,
    CODE_LINE_NUMBER,
    DB_COLLECTION_NAME,
    DB_OPERATION_NAME,
    DB_SYSTEM_NAME,
    ERROR_TYPE,
    EXCEPTION_MESSAGE,
    EXCEPTION_STACKTRACE,
    HTTP_REQUEST_METHOD,
    HTTP_RESPONSE_STATUS_CODE,
    RPC_METHOD,
    RPC_METHOD_ORIGINAL,
    RPC_RESPONSE_STATUS_CODE,
    RPC_SYSTEM_NAME,
    SERVER_ADDRESS,
    URL_PATH,
    URL_TEMPLATE,
    USER_ID,
    USER_NAME,
];

/// Whether `key` may appear on an exported span: a semantic-convention key
/// from [`SEMANTIC_CONVENTION`], [`CODE_MODULE_NAME`], or one of the product's
/// own under [`PRODUCT_PREFIX`].
#[must_use]
pub fn is_known(key: &str) -> bool {
    SEMANTIC_CONVENTION.contains(&key)
        || key == CODE_MODULE_NAME
        || key
            .strip_prefix(PRODUCT_PREFIX)
            .is_some_and(|rest| !rest.is_empty())
}

/// Metric attribute keys from the semantic conventions, for the pool gauges.
pub use opentelemetry_semantic_conventions::attribute::{
    DB_CLIENT_CONNECTION_POOL_NAME, DB_CLIENT_CONNECTION_STATE,
};

/// Semantic-convention instrument names this product records.
pub use opentelemetry_semantic_conventions::metric::{
    DB_CLIENT_CONNECTION_COUNT, DB_CLIENT_CONNECTION_MAX, HTTP_SERVER_REQUEST_DURATION,
    RPC_SERVER_CALL_DURATION,
};

/// The build-identity info metric (`observability` skill §1.6): a gauge at
/// `1` whose attributes are the build's facts. The only instrument that may
/// carry them.
pub const BUILD_INFO: &str = "sovereign_config.build.info";

/// The attribute keys that carry build identity on [`BUILD_INFO`], and on
/// nothing else. `version` is also the key of the protocol-version label on
/// `sovereign_config.protocol.*` — a name kept because the retirement gate
/// is written against it — so for that key the check is on values: no other
/// metric may carry the build's own version string.
pub const BUILD_IDENTITY: [&str; 3] = ["version", "revision", "protocol"];

/// Keys no metric series may carry (skill §4): identifiers, request-derived
/// values and build identity as a resource fact. Listed as keys, not per
/// metric, so a new instrument is checked without being named here. Each is
/// unbounded, or changes on every deploy; any of them on a series is a
/// cardinality incident, and the ids are personal data besides.
pub const FORBIDDEN_METRIC_KEYS: [&str; 22] = [
    USER_ID,
    USER_NAME,
    "user.email",
    "enduser.id",
    "session.id",
    "client.address",
    "connection_id",
    "content_id",
    "path",
    URL_PATH,
    "url.full",
    "url.query",
    RPC_METHOD_ORIGINAL,
    SERVER_ADDRESS,
    "trace_id",
    "span_id",
    "request_id",
    "correlation_id",
    "service.version",
    "service.instance.id",
    "sovereign_config.connection.id",
    "sovereign_config.path",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_typo_is_unknown_and_the_product_prefix_is_known() {
        assert!(is_known("rpc.system.name"));
        assert!(is_known(PROTOCOL_VERSION));
        assert!(is_known(CODE_MODULE_NAME));
        for typo in [
            "rpc.sytem.name",
            "rpc.system",
            "user_id",
            "sovereign_config.",
            "sovereign-config.x",
            "busy_ns",
            "target",
        ] {
            assert!(!is_known(typo), "{typo}");
        }
    }
}
