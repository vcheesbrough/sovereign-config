//! `v6` over Connect on storage: each JSON fix in the form a `curl` user sees
//! it, binary and JSON reaching the same outcome, and `v6` answering as `v5`
//! does over gRPC — the same shared implementation behind both.
//!
//! Each test writes under a root of its own, so the suites can share one
//! database and be run again.

use std::{
    collections::BTreeSet,
    env,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use prost::Message;
use serde_json::{Value, json};
use sovereign_config_proto::sovereign::config::{v5, v6};
use sqlx::postgres::PgPoolOptions;
use tonic::Request;

use super::tests::{Harness, READER, WRITER};
use crate::{
    audit::AuditRecorder,
    auth::{AuthenticatedPrincipal, Grant, Permission},
    encryption::ValueCipher,
    values::{ConfigurationService, V5Configuration},
};

fn database_url() -> String {
    env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL")
        .expect("SOVEREIGN_CONFIG_TEST_DATABASE_URL must be configured")
}

pub(super) async fn migrate(database_url: &str) {
    let pool = PgPoolOptions::new().connect(database_url).await.unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
}

/// A root no other run has written under.
pub(super) fn fresh_root(name: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("/connect-tests/{name}-{nanos}")
}

/// How many digits follow the second in an RFC 3339 timestamp.
fn fraction_digits(timestamp: &Value) -> usize {
    let text = timestamp.as_str().expect("a timestamp is a JSON string");
    text.split_once('.')
        .map_or(0, |(_, rest)| rest.trim_end_matches('Z').len())
}

/// Every timestamp `v6` writes carries microseconds at most.
fn microseconds(timestamp: &Value) -> bool {
    fraction_digits(timestamp) <= 6
}

const PUT: &str = "/sovereign.config.v6.Configuration/PutValue";
const SUBTREE: &str = "/sovereign.config.v6.Configuration/GetSubTree";
const LIST: &str = "/sovereign.config.v6.Configuration/ListValues";
const REPLACE: &str = "/sovereign.config.v6.Configuration/ReplaceSubTree";
const DELETE: &str = "/sovereign.config.v6.Configuration/DeleteValues";
const REVEAL: &str = "/sovereign.config.v6.Configuration/RevealSecret";
const AUDIT: &str = "/sovereign.config.v6.Audit/QueryAuditTrail";

/// Each JSON fix, as a stranger with `curl` meets it.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn each_json_fix_is_on_the_wire() {
    let url = database_url();
    migrate(&url).await;
    let harness = Harness::over(&url).await;
    let root = fresh_root("fixes");

    let (status, _, put) = harness
        .json(
            PUT,
            Some(WRITER),
            &json!({ "path": format!("{root}/plain"), "plainValue": "v" }),
        )
        .await;
    assert!(status.is_success(), "{put}");
    assert!(microseconds(&put["createdAt"]), "{put}");
    assert!(microseconds(&put["updatedAt"]), "{put}");
    harness
        .json(
            PUT,
            Some(WRITER),
            &json!({ "path": format!("{root}/secret"), "secretValue": "s3cr3t" }),
        )
        .await;

    // A secret is the `maskedSecret` member, the enum keeps its prefix.
    let (_, _, subtree) = harness
        .json(SUBTREE, Some(READER), &json!({ "path": root }))
        .await;
    assert_eq!(
        subtree,
        json!({ "values": [
            { "path": format!("{root}/plain"), "plainValue": "v", "classification": "VALUE_CLASSIFICATION_PLAIN" },
            { "path": format!("{root}/secret"), "maskedSecret": {}, "classification": "VALUE_CLASSIFICATION_SECRET" },
        ]})
    );
    let (_, _, listed) = harness
        .json(LIST, Some(READER), &json!({ "path": root }))
        .await;
    for value in listed["values"].as_array().unwrap() {
        assert!(microseconds(&value["createdAt"]), "{value}");
    }

    // Counts are JSON numbers.
    let (_, _, replaced) = harness
        .json(
            REPLACE,
            Some(WRITER),
            &json!({ "path": format!("{root}/tree"), "values": [
                { "path": format!("{root}/tree/a"), "plainValue": "1" },
                { "path": format!("{root}/tree/b"), "plainValue": "2" },
            ]}),
        )
        .await;
    assert_eq!(replaced["valueCount"], json!(2), "{replaced}");
    let (_, _, deleted) = harness
        .json(
            DELETE,
            Some(WRITER),
            &json!({ "path": format!("{root}/tree"), "recurse": true }),
        )
        .await;
    assert_eq!(deleted["deletedCount"], json!(2), "{deleted}");
    // `v5` carried nanoseconds here: the one timestamp not from Postgres.
    assert!(microseconds(&deleted["deletedAt"]), "{deleted}");

    // An event's identifier is an opaque string; the counts are numbers.
    let (_, _, page) = harness
        .json(AUDIT, Some(READER), &json!({ "pathFilter": root }))
        .await;
    let events = page["events"].as_array().unwrap();
    assert!(!events.is_empty(), "{page}");
    for event in events {
        assert!(event["id"].is_string(), "{event}");
        assert!(microseconds(&event["occurredAt"]), "{event}");
        assert!(microseconds(&event["firstOccurredAt"]), "{event}");
    }
    assert!(page["totalCount"].is_u64(), "{page}");
    assert!(page["matchCount"].is_u64(), "{page}");
    assert_eq!(
        page["matchCount"],
        json!(events.len()),
        "every event under a fresh root matches"
    );
}

/// The same requests in binary and in JSON reach the same outcome.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn binary_and_json_reach_the_same_outcome() {
    let url = database_url();
    migrate(&url).await;
    let harness = Harness::over(&url).await;
    let root = fresh_root("parity");

    let (status, _, bytes) = harness
        .binary(
            PUT,
            Some(WRITER),
            v6::PutValueRequest {
                path: format!("{root}/plain"),
                content: Some(v6::put_value_request::Content::PlainValue("v".into())),
            }
            .encode_to_vec(),
        )
        .await;
    assert!(status.is_success());
    v6::PutValueResponse::decode(bytes).unwrap();

    let (_, _, bytes) = harness
        .binary(
            SUBTREE,
            Some(READER),
            v6::GetSubTreeRequest { path: root.clone() }.encode_to_vec(),
        )
        .await;
    let binary = v6::GetSubTreeResponse::decode(bytes).unwrap();
    let (_, _, json) = harness
        .json(SUBTREE, Some(READER), &json!({ "path": root }))
        .await;
    assert_eq!(binary.values.len(), 1);
    assert_eq!(json["values"][0]["path"], binary.values[0].path);
    assert_eq!(json["values"][0]["plainValue"], "v");

    // Each refusal, both ways.
    for (route, bearer, body, binary_body, code) in [
        (
            PUT,
            READER,
            json!({ "path": format!("{root}/denied"), "plainValue": "x" }),
            v6::PutValueRequest {
                path: format!("{root}/denied"),
                content: Some(v6::put_value_request::Content::PlainValue("x".into())),
            }
            .encode_to_vec(),
            "permission_denied",
        ),
        (
            REVEAL,
            READER,
            json!({ "path": format!("{root}/missing") }),
            v6::RevealSecretRequest {
                path: format!("{root}/missing"),
            }
            .encode_to_vec(),
            "not_found",
        ),
        (
            SUBTREE,
            READER,
            json!({ "path": "no-leading-slash" }),
            v6::GetSubTreeRequest {
                path: "no-leading-slash".into(),
            }
            .encode_to_vec(),
            "invalid_argument",
        ),
    ] {
        let (json_status, _, json_answer) = harness.json(route, Some(bearer), &body).await;
        let (binary_status, _, bytes) = harness.binary(route, Some(bearer), binary_body).await;
        let binary_answer: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json_status, binary_status, "{route}");
        assert_eq!(json_answer, binary_answer, "{route}");
        assert_eq!(json_answer["code"], code, "{route}");
    }
}

/// `v6` over Connect answers as `v5` over gRPC: one shared implementation
/// behind both, so the same stored subtree comes back byte for byte.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn v6_over_connect_answers_as_v5_over_grpc() {
    use v5::configuration_server::Configuration as _;

    let url = database_url();
    migrate(&url).await;
    let harness = Harness::over(&url).await;
    let root = fresh_root("v5");
    harness
        .json(
            PUT,
            Some(WRITER),
            &json!({ "path": format!("{root}/plain"), "plainValue": "v" }),
        )
        .await;
    harness
        .json(
            PUT,
            Some(WRITER),
            &json!({ "path": format!("{root}/secret"), "secretValue": "s" }),
        )
        .await;

    let pool = PgPoolOptions::new().connect(&url).await.unwrap();
    // The values suites' key, so secrets these tests seal open for every suite
    // sharing the database (`encrypt_stored_secrets` refuses a wrong key).
    let mut key = [0xA5; 32];
    let v5_shim = V5Configuration::new(Arc::new(ConfigurationService::new(
        pool,
        Arc::new(ValueCipher::new(&mut key)),
        AuditRecorder::for_tests(),
    )));
    let mut request = Request::new(v5::GetSubTreeRequest { path: root.clone() });
    request.extensions_mut().insert(AuthenticatedPrincipal {
        subject: "connect-test".into(),
        name: None,
        grants: vec![Grant {
            prefix: "/".into(),
            permissions: [Permission::Read].into_iter().collect::<BTreeSet<_>>(),
        }],
    });
    let over_grpc = v5_shim
        .get_sub_tree(request)
        .await
        .unwrap()
        .into_inner()
        .encode_to_vec();
    let (_, _, over_connect) = harness
        .binary(
            SUBTREE,
            Some(READER),
            v6::GetSubTreeRequest { path: root }.encode_to_vec(),
        )
        .await;
    assert_eq!(over_connect.as_ref(), over_grpc.as_slice());
}
