use std::{collections::BTreeSet, env, sync::Arc, time::Duration};

use crate::encryption::ValueCipher;
use sovereign_config_proto::sovereign::config::v3::{
    PreserveSecret, RevealSecretRequest, SubTreeMutationValue, ValueClassification,
    configuration_server::Configuration, listed_value, put_value_request, sub_tree_mutation_value,
    sub_tree_value,
};
use sqlx::postgres::PgPoolOptions;
use tokio::time::{sleep, timeout};
use tonic::{Code, Request};

use super::{
    AddValuePathRequest, ConfigurationService, DeleteValuesRequest, GetSubTreeRequest,
    ListValuePathsRequest, ListValuesRequest, MASKED_SECRET_TEXT, PutValueRequest,
    ReplaceSubTreeRequest, encrypt_stored_secrets, wrong_key,
};
use crate::auth::{AuthenticatedPrincipal, Grant, Permission};

fn request_with_grants<T>(message: T, grants: &[(&str, &[Permission])]) -> Request<T> {
    let mut request = Request::new(message);
    request.extensions_mut().insert(AuthenticatedPrincipal {
        subject: "integration-principal".into(),
        grants: grants
            .iter()
            .map(|(prefix, permissions)| Grant {
                prefix: (*prefix).into(),
                permissions: permissions.iter().copied().collect::<BTreeSet<_>>(),
            })
            .collect(),
    });
    request
}

fn request<T>(message: T, permissions: &[Permission]) -> Request<T> {
    request_for_prefix(message, "/tests/exact", permissions)
}

fn request_for_prefix<T>(message: T, prefix: &str, permissions: &[Permission]) -> Request<T> {
    let mut request = Request::new(message);
    request.extensions_mut().insert(AuthenticatedPrincipal {
        subject: "integration-principal".into(),
        grants: vec![Grant {
            prefix: prefix.into(),
            permissions: permissions.iter().copied().collect::<BTreeSet<_>>(),
        }],
    });
    request
}

fn plain_put(path: &str, value: &str) -> PutValueRequest {
    PutValueRequest {
        path: path.into(),
        content: Some(put_value_request::Content::PlainValue(value.into())),
    }
}

fn secret_put(path: &str, value: &str) -> PutValueRequest {
    PutValueRequest {
        path: path.into(),
        content: Some(put_value_request::Content::SecretValue(value.into())),
    }
}

fn plain_mutation(path: &str, value: &str) -> SubTreeMutationValue {
    SubTreeMutationValue {
        path: path.into(),
        content: Some(sub_tree_mutation_value::Content::PlainValue(value.into())),
    }
}

fn preserve_secret(path: &str) -> SubTreeMutationValue {
    SubTreeMutationValue {
        path: path.into(),
        content: Some(sub_tree_mutation_value::Content::PreserveSecret(
            PreserveSecret {},
        )),
    }
}

// A fixed key, so a test can seal a value with one cipher and open it with
// another. Test data is disposable; nothing here needs a real key.
fn test_cipher() -> Arc<ValueCipher> {
    cipher_seeded(0xA5)
}

fn cipher_seeded(seed: u8) -> Arc<ValueCipher> {
    let mut key = [seed; 32];
    Arc::new(ValueCipher::new(&mut key))
}

// Reads what is physically stored for a path, bypassing the service, so a
// test can assert on the representation rather than on what a client sees.
async fn stored_value(pool: &sqlx::PgPool, path: &str) -> (i64, String, String) {
    sqlx::query_as::<_, (i64, String, String)>(
        r"
        SELECT p.content_id, c.value, c.classification
        FROM configuration_paths p
        JOIN configuration_value_contents c ON c.id = p.content_id
        WHERE p.lowercase_path = $1
        ",
    )
    .bind(path)
    .fetch_one(pool)
    .await
    .unwrap()
}

// Remove every path at or below the given prefixes and drop any content
// left without a path, scoped to the affected contents so parallel tests
// under other prefixes are untouched.
async fn clear_test_paths(pool: &sqlx::PgPool, prefixes: &[&str]) {
    let mut ids: Vec<i64> = Vec::new();
    for prefix in prefixes {
        let mut removed = sqlx::query_scalar::<_, i64>(
            "DELETE FROM configuration_paths WHERE lowercase_path = $1 OR starts_with(lowercase_path, $1 || '/') RETURNING content_id",
        )
        .bind(prefix)
        .fetch_all(pool)
        .await
        .unwrap();
        ids.append(&mut removed);
    }
    if !ids.is_empty() {
        sqlx::query(
            r"
            DELETE FROM configuration_value_contents c
            WHERE c.id = ANY($1::BIGINT[])
              AND NOT EXISTS (
                    SELECT 1 FROM configuration_paths p WHERE p.content_id = c.id
                  )
            ",
        )
        .bind(&ids)
        .execute(pool)
        .await
        .unwrap();
    }
}

async fn seed_plain(pool: &sqlx::PgPool, path: &str, value: &str) {
    sqlx::query(
        r"
        WITH inserted AS (
            INSERT INTO configuration_value_contents (value, classification, created_at, updated_at)
            VALUES ($2, 'plain', NOW(), NOW())
            RETURNING id
        )
        INSERT INTO configuration_paths (path, content_id, created_at, updated_at)
        SELECT $1, id, NOW(), NOW() FROM inserted
        ",
    )
    .bind(path)
    .bind(value)
    .execute(pool)
    .await
    .unwrap();
}

// Writes a secret the way a server that predates encryption would have:
// classified as secret, stored in the clear. This is what the startup pass
// has to find and seal.
async fn seed_legacy_plaintext_secret(pool: &sqlx::PgPool, path: &str, value: &str) {
    sqlx::query(
        r"
        WITH inserted AS (
            INSERT INTO configuration_value_contents (value, classification, created_at, updated_at)
            VALUES ($2, 'secret', NOW(), NOW())
            RETURNING id
        )
        INSERT INTO configuration_paths (path, content_id, created_at, updated_at)
        SELECT $1, id, NOW(), NOW() FROM inserted
        ",
    )
    .bind(path)
    .bind(value)
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn postgres_service_enforces_atomic_v3_value_lifecycle() {
    let database_url = env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL")
        .expect("SOVEREIGN_CONFIG_TEST_DATABASE_URL must be configured");
    let pool = PgPoolOptions::new().connect(&database_url).await.unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    clear_test_paths(&pool, &["/tests/exact", "/tests/exactly"]).await;
    let service = ConfigurationService::new(pool.clone(), test_cipher());

    let invalid_list = service
        .list_values(request(
            ListValuesRequest {
                path: "/tests//exact".into(),
            },
            &[Permission::Read],
        ))
        .await
        .unwrap_err();
    assert_eq!(invalid_list.code(), Code::InvalidArgument);
    let unrooted_value = service
        .get_sub_tree(request(
            GetSubTreeRequest {
                path: "tests/exact/key".into(),
            },
            &[Permission::Read],
        ))
        .await
        .unwrap_err();
    assert_eq!(unrooted_value.code(), Code::InvalidArgument);
    let invalid_value = service
        .put_value(request(
            plain_put("/tests/exact/invalid", "invalid\0value"),
            &[Permission::Write],
        ))
        .await
        .unwrap_err();
    assert_eq!(invalid_value.code(), Code::InvalidArgument);

    service
        .put_value(request(
            plain_put("/Tests/Exact/Key", "value-sentinel-one"),
            &[Permission::Write],
        ))
        .await
        .unwrap();
    service
        .put_value(request_for_prefix(
            plain_put("/tests/exactly/outside", "boundary-value-sentinel"),
            "/",
            &[Permission::Write],
        ))
        .await
        .unwrap();
    service
        .put_value(request(
            plain_put("/tests/exact/nested/child", "nested-value-sentinel"),
            &[Permission::Write],
        ))
        .await
        .unwrap();
    let listing = service
        .list_values(request(
            ListValuesRequest {
                path: "/tests/exact".into(),
            },
            &[Permission::Read],
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listing.values.len(), 1);
    // The stored value's path keeps the case it was written with, even
    // though it resolves and lists under a lowercase-typed query path.
    assert_eq!(listing.values[0].path, "/Tests/Exact/Key");
    // "/tests" and "/tests/exact" take the display case established by
    // "/Tests/Exact/Key" — the only readable row under either ancestor,
    // written before "/tests/exact/nested/child". "/tests/exact/nested"
    // has only the latter as a contributor, so it stays lowercase.
    assert_eq!(
        listing.paths,
        ["/", "/Tests", "/Tests/Exact", "/tests/exact/nested"]
    );
    let nested_only = service
        .list_values(request_for_prefix(
            ListValuesRequest {
                path: "/tests/exact".into(),
            },
            "/tests/exact/nested",
            &[Permission::Read],
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(nested_only.values.is_empty());
    assert_eq!(
        nested_only.paths,
        ["/", "/tests", "/tests/exact", "/tests/exact/nested"]
    );
    let write_only = service
        .list_values(request(
            ListValuesRequest {
                path: "/tests/exact".into(),
            },
            &[Permission::Write],
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(write_only.values.is_empty());
    assert!(write_only.paths.is_empty());
    let denied = service
        .get_sub_tree(request(
            GetSubTreeRequest {
                path: "/tests/exact".into(),
            },
            &[Permission::Write],
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), Code::PermissionDenied);
    assert!(!denied.message().contains("value-sentinel"));

    let stored = service
        .get_sub_tree(request(
            GetSubTreeRequest {
                path: "/TESTS/EXACT".into(),
            },
            &[Permission::Read],
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(stored.values.len(), 2);
    assert_eq!(stored.values[0].path, "/Tests/Exact/Key");
    assert!(matches!(
        stored.values[0].content.as_ref(),
        Some(sub_tree_value::Content::PlainValue(value)) if value == "value-sentinel-one"
    ));
    assert_eq!(stored.values[1].path, "/tests/exact/nested/child");

    let narrower_read = service
        .get_sub_tree(request_for_prefix(
            GetSubTreeRequest {
                path: "/tests/exact".into(),
            },
            "/tests/exact/nested",
            &[Permission::Read],
        ))
        .await
        .unwrap_err();
    assert_eq!(narrower_read.code(), Code::PermissionDenied);

    let boundary = service
        .get_sub_tree(request(
            GetSubTreeRequest {
                path: "/tests/exactly".into(),
            },
            &[Permission::Read],
        ))
        .await
        .unwrap_err();
    assert_eq!(boundary.code(), Code::PermissionDenied);

    let write_only_replace = service
        .replace_sub_tree(request(
            ReplaceSubTreeRequest {
                path: "/tests/exact".into(),
                values: vec![],
            },
            &[Permission::Write],
        ))
        .await
        .unwrap_err();
    assert_eq!(write_only_replace.code(), Code::PermissionDenied);

    let invalid_replace = service
        .replace_sub_tree(request(
            ReplaceSubTreeRequest {
                path: "/tests/exact".into(),
                values: vec![
                    plain_mutation("/tests/exact/collision/child", "child"),
                    plain_mutation("/tests/exact/collision-sibling", "sibling"),
                    plain_mutation("/tests/exact/collision", "parent"),
                ],
            },
            &[Permission::Write, Permission::Manage],
        ))
        .await
        .unwrap_err();
    assert_eq!(invalid_replace.code(), Code::InvalidArgument);
    let invalid_root_value = service
        .replace_sub_tree(request_for_prefix(
            ReplaceSubTreeRequest {
                path: "/".into(),
                values: vec![plain_mutation("/", "invalid-root-value")],
            },
            "/",
            &[Permission::Write, Permission::Manage],
        ))
        .await
        .unwrap_err();
    assert_eq!(invalid_root_value.code(), Code::InvalidArgument);
    assert_eq!(
        service
            .get_sub_tree(request(
                GetSubTreeRequest {
                    path: "/tests/exact".into()
                },
                &[Permission::Read]
            ))
            .await
            .unwrap()
            .into_inner()
            .values
            .len(),
        2
    );

    let replacement = service
        .replace_sub_tree(request(
            ReplaceSubTreeRequest {
                path: "/tests/exact".into(),
                values: vec![
                    plain_mutation("/tests/exact/alpha", "one"),
                    plain_mutation("/tests/exact/nested/beta", "two"),
                ],
            },
            &[Permission::Write, Permission::Manage],
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(replacement.value_count, 2);
    let replaced = service
        .get_sub_tree(request(
            GetSubTreeRequest {
                path: "/tests/exact".into(),
            },
            &[Permission::Read],
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        replaced
            .values
            .iter()
            .map(|value| value.path.as_str())
            .collect::<Vec<_>>(),
        ["/tests/exact/alpha", "/tests/exact/nested/beta"]
    );

    let manage_only_exact_delete_denied = service
        .delete_values(request(
            DeleteValuesRequest {
                path: "/tests/exact/alpha".into(),
                recurse: false,
            },
            &[Permission::Manage],
        ))
        .await
        .unwrap_err();
    assert_eq!(
        manage_only_exact_delete_denied.code(),
        Code::PermissionDenied
    );
    let read_only_exact_delete_denied = service
        .delete_values(request(
            DeleteValuesRequest {
                path: "/tests/exact/alpha".into(),
                recurse: false,
            },
            &[Permission::Read],
        ))
        .await
        .unwrap_err();
    assert_eq!(read_only_exact_delete_denied.code(), Code::PermissionDenied);
    let manage_only_recursive_delete_denied = service
        .delete_values(request(
            DeleteValuesRequest {
                path: "/tests/exact".into(),
                recurse: true,
            },
            &[Permission::Manage],
        ))
        .await
        .unwrap_err();
    assert_eq!(
        manage_only_recursive_delete_denied.code(),
        Code::PermissionDenied
    );

    let exact_delete = service
        .delete_values(request(
            DeleteValuesRequest {
                path: "/tests/exact/alpha".into(),
                recurse: false,
            },
            &[Permission::Write],
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(exact_delete.deleted_count, 1);
    let recursive_delete = service
        .delete_values(request(
            DeleteValuesRequest {
                path: "/tests/exact".into(),
                recurse: true,
            },
            &[Permission::Write],
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(recursive_delete.deleted_count, 1);
    let preserved_boundary = service
        .get_sub_tree(request_for_prefix(
            GetSubTreeRequest {
                path: "/tests/exactly".into(),
            },
            "/",
            &[Permission::Read],
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(preserved_boundary.values.len(), 1);
    assert_eq!(preserved_boundary.values[0].path, "/tests/exactly/outside");
    let missing_delete = service
        .delete_values(request(
            DeleteValuesRequest {
                path: "/tests/exact".into(),
                recurse: true,
            },
            &[Permission::Write],
        ))
        .await
        .unwrap_err();
    assert_eq!(missing_delete.code(), Code::NotFound);
    assert!(
        service
            .get_sub_tree(request(
                GetSubTreeRequest {
                    path: "/tests/exact".into()
                },
                &[Permission::Read]
            ))
            .await
            .unwrap()
            .into_inner()
            .values
            .is_empty()
    );

    pool.close().await;
    let unavailable = service
        .get_sub_tree(request(
            GetSubTreeRequest {
                path: "/tests/exact".into(),
            },
            &[Permission::Read],
        ))
        .await
        .unwrap_err();
    assert_eq!(unavailable.code(), Code::Unavailable);
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn postgres_retains_established_display_case_across_writes_and_folds_uniqueness() {
    let database_url = env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL")
        .expect("SOVEREIGN_CONFIG_TEST_DATABASE_URL must be configured");
    let pool = PgPoolOptions::new().connect(&database_url).await.unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    clear_test_paths(&pool, &["/tests/case"]).await;
    let service = ConfigurationService::new(pool.clone(), test_cipher());
    let read_write = [Permission::Read, Permission::Write];

    // The first write of a fold key establishes its display form.
    service
        .put_value(request_for_prefix(
            plain_put("/tests/case/serverIP", "value-one"),
            "/tests/case",
            &read_write,
        ))
        .await
        .unwrap();
    let (_, stored_value, _) = stored_value(&pool, "/tests/case/serverip").await;
    assert_eq!(stored_value, "value-one");
    let established = service
        .get_sub_tree(request_for_prefix(
            GetSubTreeRequest {
                path: "/tests/case/serverip".into(),
            },
            "/tests/case",
            &[Permission::Read],
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(established.values[0].path, "/tests/case/serverIP");

    // A later write through a differently-cased spelling of the same fold
    // key updates the value but leaves the established display form.
    service
        .put_value(request_for_prefix(
            plain_put("/TESTS/CASE/SERVERIP", "value-two"),
            "/tests/case",
            &read_write,
        ))
        .await
        .unwrap();
    let unchanged_case = service
        .get_sub_tree(request_for_prefix(
            GetSubTreeRequest {
                path: "/tests/case/serverip".into(),
            },
            "/tests/case",
            &[Permission::Read],
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(unchanged_case.values[0].path, "/tests/case/serverIP");
    assert!(matches!(
        unchanged_case.values[0].content.as_ref(),
        Some(sub_tree_value::Content::PlainValue(value)) if value == "value-two"
    ));

    // A fold-colliding alias — even spelled in yet another case — is
    // rejected as an existing path, not created as a second value.
    service
        .put_value(request_for_prefix(
            plain_put("/tests/case/other", "other-value"),
            "/tests/case",
            &read_write,
        ))
        .await
        .unwrap();
    let aliasing_collision = service
        .add_value_path(request_for_prefix(
            AddValuePathRequest {
                source_path: "/tests/case/other".into(),
                new_path: "/TESTS/case/ServerIp".into(),
            },
            "/tests/case",
            &read_write,
        ))
        .await
        .unwrap_err();
    assert_eq!(aliasing_collision.code(), Code::AlreadyExists);

    // Delete then recreate is the only way to change established case.
    service
        .delete_values(request_for_prefix(
            DeleteValuesRequest {
                path: "/tests/case/serverip".into(),
                recurse: false,
            },
            "/tests/case",
            &[Permission::Write],
        ))
        .await
        .unwrap();
    service
        .put_value(request_for_prefix(
            plain_put("/tests/case/SERVERIP", "value-three"),
            "/tests/case",
            &read_write,
        ))
        .await
        .unwrap();
    let recreated = service
        .get_sub_tree(request_for_prefix(
            GetSubTreeRequest {
                path: "/tests/case/serverip".into(),
            },
            "/tests/case",
            &[Permission::Read],
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(recreated.values[0].path, "/tests/case/SERVERIP");

    pool.close().await;
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn postgres_masks_rotates_reveals_and_preserves_secrets() {
    let database_url = env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL")
        .expect("SOVEREIGN_CONFIG_TEST_DATABASE_URL must be configured");
    let pool = PgPoolOptions::new().connect(&database_url).await.unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    clear_test_paths(&pool, &["/tests/secrets"]).await;
    let service = ConfigurationService::new(pool.clone(), test_cipher());

    for sentinel in ["secret-sentinel-one", "secret-sentinel-two"] {
        service
            .put_value(request_for_prefix(
                secret_put("/tests/secrets/credential", sentinel),
                "/tests/secrets",
                &[Permission::Write],
            ))
            .await
            .unwrap();
    }

    let listing = service
        .list_values(request_for_prefix(
            ListValuesRequest {
                path: "/tests/secrets".into(),
            },
            "/tests/secrets",
            &[Permission::Read],
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        listing.values[0].classification,
        ValueClassification::Secret as i32
    );
    assert!(matches!(
        listing.values[0].content,
        Some(listed_value::Content::MaskedSecret(_))
    ));

    // A plain value that happens to equal the JSON mask token must still
    // round-trip as plain when the marker is resolved against stored
    // classifications.
    service
        .replace_sub_tree(request_for_prefix(
            ReplaceSubTreeRequest {
                path: "/tests/secrets".into(),
                values: vec![
                    preserve_secret("/tests/secrets/credential"),
                    preserve_secret("/tests/secrets/plain-mask"),
                ],
            },
            "/tests/secrets",
            &[Permission::Write, Permission::Manage],
        ))
        .await
        .unwrap();
    let round_tripped = service
        .get_sub_tree(request_for_prefix(
            GetSubTreeRequest {
                path: "/tests/secrets".into(),
            },
            "/tests/secrets",
            &[Permission::Read],
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(round_tripped.values.iter().any(|value| {
        value.path == "/tests/secrets/plain-mask"
            && value.classification == ValueClassification::Plain as i32
            && matches!(
                value.content.as_ref(),
                Some(sub_tree_value::Content::PlainValue(content))
                    if content == MASKED_SECRET_TEXT
            )
    }));

    service
        .put_value(request_for_prefix(
            secret_put(
                "/tests/secrets/collision-parent",
                "collision-parent-sentinel",
            ),
            "/tests/secrets",
            &[Permission::Write],
        ))
        .await
        .unwrap();
    let rejected_child = service
        .put_value(request_for_prefix(
            plain_put(
                "/tests/secrets/collision-parent/child",
                "collision-child-sentinel",
            ),
            "/tests/secrets",
            &[Permission::Write],
        ))
        .await
        .unwrap_err();
    assert_eq!(rejected_child.code(), Code::InvalidArgument);
    assert!(
        !rejected_child
            .message()
            .contains("collision-child-sentinel")
    );

    service
        .put_value(request_for_prefix(
            secret_put(
                "/tests/secrets/collision-child/leaf",
                "collision-leaf-sentinel",
            ),
            "/tests/secrets",
            &[Permission::Write],
        ))
        .await
        .unwrap();
    let rejected_parent = service
        .put_value(request_for_prefix(
            plain_put(
                "/tests/secrets/collision-child",
                "collision-parent-sentinel",
            ),
            "/tests/secrets",
            &[Permission::Write],
        ))
        .await
        .unwrap_err();
    assert_eq!(rejected_parent.code(), Code::InvalidArgument);
    assert!(
        !rejected_parent
            .message()
            .contains("collision-parent-sentinel")
    );

    service
        .put_value(request_for_prefix(
            secret_put("/tests/secrets/subtree-secret", "subtree-secret-sentinel"),
            "/tests/secrets",
            &[Permission::Write],
        ))
        .await
        .unwrap();
    let rejected_subtree = service
        .replace_sub_tree(request_for_prefix(
            ReplaceSubTreeRequest {
                path: "/tests/secrets/subtree-secret/child-area".into(),
                values: vec![plain_mutation(
                    "/tests/secrets/subtree-secret/child-area/key",
                    "subtree-child-sentinel",
                )],
            },
            "/tests/secrets",
            &[Permission::Write, Permission::Manage],
        ))
        .await
        .unwrap_err();
    assert_eq!(rejected_subtree.code(), Code::InvalidArgument);
    assert!(
        !rejected_subtree
            .message()
            .contains("subtree-child-sentinel")
    );

    let revealed = service
        .reveal_secret(request_for_prefix(
            RevealSecretRequest {
                path: "/tests/secrets/credential".into(),
            },
            "/tests/secrets",
            &[Permission::Read],
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(revealed.value, "secret-sentinel-two");
    let denied = service
        .reveal_secret(request_for_prefix(
            RevealSecretRequest {
                path: "/tests/secrets/credential".into(),
            },
            "/tests/secrets",
            &[Permission::Write],
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), Code::PermissionDenied);
    assert!(!denied.message().contains("secret-sentinel"));

    service
        .replace_sub_tree(request_for_prefix(
            ReplaceSubTreeRequest {
                path: "/tests/secrets".into(),
                values: vec![
                    preserve_secret("/tests/secrets/credential"),
                    plain_mutation("/tests/secrets/enabled", "true"),
                ],
            },
            "/tests/secrets",
            &[Permission::Write, Permission::Manage],
        ))
        .await
        .unwrap();
    service
        .replace_sub_tree(request_for_prefix(
            ReplaceSubTreeRequest {
                path: "/tests/secrets".into(),
                values: vec![plain_mutation("/tests/secrets/enabled", "false")],
            },
            "/tests/secrets",
            &[Permission::Write, Permission::Manage],
        ))
        .await
        .unwrap();
    let rejected = service
        .replace_sub_tree(request_for_prefix(
            ReplaceSubTreeRequest {
                path: "/tests/secrets".into(),
                values: vec![plain_mutation(
                    "/tests/secrets/credential",
                    "attempted-overwrite-sentinel",
                )],
            },
            "/tests/secrets",
            &[Permission::Write, Permission::Manage],
        ))
        .await
        .unwrap_err();
    assert_eq!(rejected.code(), Code::InvalidArgument);
    assert!(!rejected.message().contains("attempted-overwrite-sentinel"));
    let rejected_child = service
        .replace_sub_tree(request_for_prefix(
            ReplaceSubTreeRequest {
                path: "/tests/secrets".into(),
                values: vec![plain_mutation(
                    "/tests/secrets/credential/child",
                    "attempted-child-sentinel",
                )],
            },
            "/tests/secrets",
            &[Permission::Write, Permission::Manage],
        ))
        .await
        .unwrap_err();
    assert_eq!(rejected_child.code(), Code::InvalidArgument);
    assert!(
        !rejected_child
            .message()
            .contains("attempted-child-sentinel")
    );
    assert_eq!(
        service
            .reveal_secret(request_for_prefix(
                RevealSecretRequest {
                    path: "/tests/secrets/credential".into(),
                },
                "/tests/secrets",
                &[Permission::Read],
            ))
            .await
            .unwrap()
            .into_inner()
            .value,
        "secret-sentinel-two"
    );

    service
        .put_value(request_for_prefix(
            plain_put("/tests/secrets/credential", "now-plain"),
            "/tests/secrets",
            &[Permission::Write],
        ))
        .await
        .unwrap();
    let not_secret = service
        .reveal_secret(request_for_prefix(
            RevealSecretRequest {
                path: "/tests/secrets/credential".into(),
            },
            "/tests/secrets",
            &[Permission::Read],
        ))
        .await
        .unwrap_err();
    assert_eq!(not_secret.code(), Code::InvalidArgument);

    service
        .put_value(request_for_prefix(
            secret_put("/tests/secrets/credential", "secret-sentinel-three"),
            "/tests/secrets",
            &[Permission::Write],
        ))
        .await
        .unwrap();
    service
        .delete_values(request_for_prefix(
            DeleteValuesRequest {
                path: "/tests/secrets/credential".into(),
                recurse: false,
            },
            "/tests/secrets",
            &[Permission::Write],
        ))
        .await
        .unwrap();
    let retained: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM configuration_paths WHERE lowercase_path = '/tests/secrets/credential'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(retained, 0);
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn postgres_serializes_overlapping_subtree_replacements() {
    let database_url = env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL")
        .expect("SOVEREIGN_CONFIG_TEST_DATABASE_URL must be configured");
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&database_url)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    clear_test_paths(&pool, &["/tests/concurrent"]).await;
    seed_plain(&pool, "/tests/concurrent/existing", "seed").await;

    let mut blocker = pool.begin().await.unwrap();
    sqlx::query(
        "SELECT path FROM configuration_paths WHERE lowercase_path = '/tests/concurrent/existing' FOR UPDATE",
    )
    .fetch_one(&mut *blocker)
    .await
    .unwrap();

    let service = ConfigurationService::new(pool.clone(), test_cipher());
    let first_service = service.clone();
    let first = tokio::spawn(async move {
        first_service
            .replace_sub_tree(request_for_prefix(
                ReplaceSubTreeRequest {
                    path: "/tests/concurrent".into(),
                    values: vec![
                        plain_mutation("/tests/concurrent/alpha-one", "one"),
                        plain_mutation("/tests/concurrent/alpha-two", "two"),
                    ],
                },
                "/tests/concurrent",
                &[Permission::Write, Permission::Manage],
            ))
            .await
    });
    let second = tokio::spawn(async move {
        service
            .replace_sub_tree(request_for_prefix(
                ReplaceSubTreeRequest {
                    path: "/tests/concurrent".into(),
                    values: vec![
                        plain_mutation("/tests/concurrent/beta-one", "one"),
                        plain_mutation("/tests/concurrent/beta-two", "two"),
                    ],
                },
                "/tests/concurrent",
                &[Permission::Write, Permission::Manage],
            ))
            .await
    });

    let both_waiting = timeout(Duration::from_secs(5), async {
        loop {
            let waiting: i64 = sqlx::query_scalar(
                r"
                SELECT COUNT(*)
                FROM pg_stat_activity
                WHERE datname = current_database()
                  AND pid <> pg_backend_pid()
                  AND wait_event_type = 'Lock'
                  AND (
                    query LIKE '%DELETE FROM configuration_paths%'
                    OR query LIKE '%pg_advisory_xact_lock%'
                  )
                ",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            if waiting >= 2 {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    blocker.commit().await.unwrap();
    assert!(
        both_waiting.is_ok(),
        "concurrent replacements did not both reach their lock waits"
    );
    for replacement in [first, second] {
        timeout(Duration::from_secs(5), replacement)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    let paths = sqlx::query_scalar::<_, String>(
        "SELECT path FROM configuration_paths WHERE lowercase_path LIKE '/tests/concurrent/%' ORDER BY lowercase_path",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(
        paths == ["/tests/concurrent/alpha-one", "/tests/concurrent/alpha-two",]
            || paths == ["/tests/concurrent/beta-one", "/tests/concurrent/beta-two",],
        "final subtree was not one complete replacement: {paths:?}"
    );

    clear_test_paths(&pool, &["/tests/concurrent"]).await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn postgres_service_exposes_one_value_at_multiple_paths() {
    let database_url = env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL")
        .expect("SOVEREIGN_CONFIG_TEST_DATABASE_URL must be configured");
    let pool = PgPoolOptions::new().connect(&database_url).await.unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    clear_test_paths(&pool, &["/tests/alias"]).await;
    let service = ConfigurationService::new(pool.clone(), test_cipher());
    let read_write = [Permission::Read, Permission::Write];

    service
        .put_value(request_for_prefix(
            plain_put("/tests/alias/primary", "one"),
            "/tests/alias",
            &read_write,
        ))
        .await
        .unwrap();
    service
        .add_value_path(request_for_prefix(
            AddValuePathRequest {
                source_path: "/tests/alias/primary".into(),
                new_path: "/tests/alias/mirror".into(),
            },
            "/tests/alias",
            &read_write,
        ))
        .await
        .unwrap();

    let both = service
        .list_value_paths(request_for_prefix(
            ListValuePathsRequest {
                path: "/tests/alias/primary".into(),
            },
            "/tests/alias",
            &[Permission::Read],
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(both.paths, ["/tests/alias/mirror", "/tests/alias/primary"]);

    // Writing through either path updates the shared content.
    service
        .put_value(request_for_prefix(
            plain_put("/tests/alias/mirror", "two"),
            "/tests/alias",
            &read_write,
        ))
        .await
        .unwrap();
    let primary = service
        .get_sub_tree(request_for_prefix(
            GetSubTreeRequest {
                path: "/tests/alias/primary".into(),
            },
            "/tests/alias",
            &[Permission::Read],
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(matches!(
        primary.values[0].content.as_ref(),
        Some(sub_tree_value::Content::PlainValue(value)) if value == "two"
    ));

    // Deleting one path keeps the value reachable via the other.
    let content_id: i64 =
        sqlx::query_scalar("SELECT content_id FROM configuration_paths WHERE lowercase_path = $1")
            .bind("/tests/alias/primary")
            .fetch_one(&pool)
            .await
            .unwrap();
    service
        .delete_values(request_for_prefix(
            DeleteValuesRequest {
                path: "/tests/alias/mirror".into(),
                recurse: false,
            },
            "/tests/alias",
            &[Permission::Write],
        ))
        .await
        .unwrap();
    let survivors = service
        .list_value_paths(request_for_prefix(
            ListValuePathsRequest {
                path: "/tests/alias/primary".into(),
            },
            "/tests/alias",
            &[Permission::Read],
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(survivors.paths, ["/tests/alias/primary"]);
    let content_alive: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM configuration_value_contents WHERE id = $1")
            .bind(content_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(content_alive, 1);

    // Deleting the last path removes the value for good.
    service
        .delete_values(request_for_prefix(
            DeleteValuesRequest {
                path: "/tests/alias/primary".into(),
                recurse: false,
            },
            "/tests/alias",
            &[Permission::Write],
        ))
        .await
        .unwrap();
    let orphaned: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM configuration_value_contents WHERE id = $1")
            .bind(content_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(orphaned, 0);

    clear_test_paths(&pool, &["/tests/alias"]).await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn postgres_refuses_to_reclassify_a_value_with_multiple_paths() {
    let database_url = env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL")
        .expect("SOVEREIGN_CONFIG_TEST_DATABASE_URL must be configured");
    let pool = PgPoolOptions::new().connect(&database_url).await.unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    clear_test_paths(&pool, &["/tests/aliasclass"]).await;
    let service = ConfigurationService::new(pool.clone(), test_cipher());
    let read_write = [Permission::Read, Permission::Write];

    service
        .put_value(request_for_prefix(
            secret_put("/tests/aliasclass/credential", "secret-sentinel"),
            "/tests/aliasclass",
            &read_write,
        ))
        .await
        .unwrap();
    service
        .add_value_path(request_for_prefix(
            AddValuePathRequest {
                source_path: "/tests/aliasclass/credential".into(),
                new_path: "/tests/aliasclass/mirror".into(),
            },
            "/tests/aliasclass",
            &read_write,
        ))
        .await
        .unwrap();

    // Demoting the secret through either alias would change how the value is
    // exposed at the other path, so it is refused while both exist.
    for path in ["/tests/aliasclass/credential", "/tests/aliasclass/mirror"] {
        let refused = service
            .put_value(request_for_prefix(
                plain_put(path, "demoted"),
                "/tests/aliasclass",
                &read_write,
            ))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), Code::InvalidArgument);
    }
    let classification = sqlx::query_scalar::<_, String>(
        r"
        SELECT c.classification
        FROM configuration_paths p
        JOIN configuration_value_contents c ON c.id = p.content_id
        WHERE p.lowercase_path = '/tests/aliasclass/credential'
        ",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(classification, "secret");

    // Rotating the secret in place is unaffected by the alias.
    service
        .put_value(request_for_prefix(
            secret_put("/tests/aliasclass/credential", "rotated-sentinel"),
            "/tests/aliasclass",
            &read_write,
        ))
        .await
        .unwrap();
    assert_eq!(
        service
            .reveal_secret(request_for_prefix(
                RevealSecretRequest {
                    path: "/tests/aliasclass/mirror".into(),
                },
                "/tests/aliasclass",
                &[Permission::Read],
            ))
            .await
            .unwrap()
            .into_inner()
            .value,
        "rotated-sentinel"
    );

    // Once a single path remains, classification can change again.
    service
        .delete_values(request_for_prefix(
            DeleteValuesRequest {
                path: "/tests/aliasclass/mirror".into(),
                recurse: false,
            },
            "/tests/aliasclass",
            &[Permission::Write],
        ))
        .await
        .unwrap();
    service
        .put_value(request_for_prefix(
            plain_put("/tests/aliasclass/credential", "now-plain"),
            "/tests/aliasclass",
            &read_write,
        ))
        .await
        .unwrap();

    clear_test_paths(&pool, &["/tests/aliasclass"]).await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn postgres_replaces_cross_aliased_subtrees_without_deadlock() {
    let database_url = env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL")
        .expect("SOVEREIGN_CONFIG_TEST_DATABASE_URL must be configured");
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&database_url)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    let service = ConfigurationService::new(pool.clone(), test_cipher());
    let read_write = [Permission::Read, Permission::Write];
    let replace = [Permission::Write, Permission::Manage];

    // Two values, each aliased across both subtrees in opposite positions:
    // updating by path order would lock them in opposite orders.
    for round in 0..6 {
        clear_test_paths(&pool, &["/tests/crossleft", "/tests/crossright"]).await;
        let left_first = format!("/tests/crossleft/one-{round}");
        let left_second = format!("/tests/crossleft/two-{round}");
        let right_first = format!("/tests/crossright/one-{round}");
        let right_second = format!("/tests/crossright/two-{round}");
        for (source, alias) in [(&left_first, &right_second), (&left_second, &right_first)] {
            service
                .put_value(request_with_grants(
                    plain_put(source, "seed"),
                    &[("/", &read_write)],
                ))
                .await
                .unwrap();
            service
                .add_value_path(request_with_grants(
                    AddValuePathRequest {
                        source_path: source.clone(),
                        new_path: alias.clone(),
                    },
                    &[("/", &read_write)],
                ))
                .await
                .unwrap();
        }

        let left_service = service.clone();
        let right_service = service.clone();
        let left_values = vec![
            plain_mutation(&left_first, "left"),
            plain_mutation(&left_second, "left"),
        ];
        let right_values = vec![
            plain_mutation(&right_first, "right"),
            plain_mutation(&right_second, "right"),
        ];
        let left_task = tokio::spawn(async move {
            left_service
                .replace_sub_tree(request_with_grants(
                    ReplaceSubTreeRequest {
                        path: "/tests/crossleft".into(),
                        values: left_values,
                    },
                    &[("/", &replace)],
                ))
                .await
        });
        let right_task = tokio::spawn(async move {
            right_service
                .replace_sub_tree(request_with_grants(
                    ReplaceSubTreeRequest {
                        path: "/tests/crossright".into(),
                        values: right_values,
                    },
                    &[("/", &replace)],
                ))
                .await
        });

        // A deadlock would abort one transaction; both must commit.
        for task in [left_task, right_task] {
            timeout(Duration::from_secs(5), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap_or_else(|error| {
                    panic!("cross-aliased replacement failed in round {round}: {error:?}")
                });
        }
    }

    clear_test_paths(&pool, &["/tests/crossleft", "/tests/crossright"]).await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn postgres_prunes_content_when_last_aliases_are_deleted_concurrently() {
    let database_url = env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL")
        .expect("SOVEREIGN_CONFIG_TEST_DATABASE_URL must be configured");
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&database_url)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    let service = ConfigurationService::new(pool.clone(), test_cipher());
    let read_write = [Permission::Read, Permission::Write];

    // The two aliases sit under unrelated hierarchies, so the path locks
    // deliberately do not serialize these deletions. Repeat the race to make
    // an unsynchronized prune overwhelmingly likely to be observed.
    for round in 0..8 {
        clear_test_paths(&pool, &["/tests/aliasrace-left", "/tests/aliasrace-right"]).await;
        let left = format!("/tests/aliasrace-left/value-{round}");
        let right = format!("/tests/aliasrace-right/value-{round}");
        service
            .put_value(request_with_grants(
                plain_put(&left, "shared"),
                &[("/", &read_write)],
            ))
            .await
            .unwrap();
        service
            .add_value_path(request_with_grants(
                AddValuePathRequest {
                    source_path: left.clone(),
                    new_path: right.clone(),
                },
                &[("/", &read_write)],
            ))
            .await
            .unwrap();
        let content_id: i64 = sqlx::query_scalar(
            "SELECT content_id FROM configuration_paths WHERE lowercase_path = $1",
        )
        .bind(&left)
        .fetch_one(&pool)
        .await
        .unwrap();

        let first = service.clone();
        let second = service.clone();
        let left_task = tokio::spawn(async move {
            first
                .delete_values(request_with_grants(
                    DeleteValuesRequest {
                        path: left,
                        recurse: false,
                    },
                    &[("/", &[Permission::Write])],
                ))
                .await
        });
        let right_task = tokio::spawn(async move {
            second
                .delete_values(request_with_grants(
                    DeleteValuesRequest {
                        path: right,
                        recurse: false,
                    },
                    &[("/", &[Permission::Write])],
                ))
                .await
        });
        for task in [left_task, right_task] {
            timeout(Duration::from_secs(5), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }

        // Every path is gone, so the value must be gone with it: an
        // unreachable content row would retain secret plaintext forever.
        let orphaned: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM configuration_value_contents WHERE id = $1")
                .bind(content_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            orphaned, 0,
            "content survived its last paths in round {round}"
        );
    }

    clear_test_paths(&pool, &["/tests/aliasrace-left", "/tests/aliasrace-right"]).await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn postgres_subtree_replacement_writes_a_shared_value_once() {
    let database_url = env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL")
        .expect("SOVEREIGN_CONFIG_TEST_DATABASE_URL must be configured");
    let pool = PgPoolOptions::new().connect(&database_url).await.unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    clear_test_paths(&pool, &["/tests/aliasreplace"]).await;
    let service = ConfigurationService::new(pool.clone(), test_cipher());
    let read_write = [Permission::Read, Permission::Write];
    let replace = [Permission::Write, Permission::Manage];

    service
        .put_value(request_for_prefix(
            plain_put("/tests/aliasreplace/first", "original"),
            "/tests/aliasreplace",
            &read_write,
        ))
        .await
        .unwrap();
    service
        .add_value_path(request_for_prefix(
            AddValuePathRequest {
                source_path: "/tests/aliasreplace/first".into(),
                new_path: "/tests/aliasreplace/second".into(),
            },
            "/tests/aliasreplace",
            &read_write,
        ))
        .await
        .unwrap();

    // Editing one alias while the other still carries the old value is
    // ambiguous: rejected rather than silently resolved by sort order.
    let conflicting = service
        .replace_sub_tree(request_for_prefix(
            ReplaceSubTreeRequest {
                path: "/tests/aliasreplace".into(),
                values: vec![
                    plain_mutation("/tests/aliasreplace/first", "edited"),
                    plain_mutation("/tests/aliasreplace/second", "original"),
                ],
            },
            "/tests/aliasreplace",
            &replace,
        ))
        .await
        .unwrap_err();
    assert_eq!(conflicting.code(), Code::InvalidArgument);
    let unchanged = sqlx::query_scalar::<_, String>(
        r"
        SELECT c.value
        FROM configuration_paths p
        JOIN configuration_value_contents c ON c.id = p.content_id
        WHERE p.lowercase_path = '/tests/aliasreplace/first'
        ",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(unchanged, "original");

    // Agreeing aliases collapse to a single write, and both paths survive.
    service
        .replace_sub_tree(request_for_prefix(
            ReplaceSubTreeRequest {
                path: "/tests/aliasreplace".into(),
                values: vec![
                    plain_mutation("/tests/aliasreplace/first", "edited"),
                    plain_mutation("/tests/aliasreplace/second", "edited"),
                ],
            },
            "/tests/aliasreplace",
            &replace,
        ))
        .await
        .unwrap();
    let stored = sqlx::query_scalar::<_, String>(
        r"
        SELECT c.value
        FROM configuration_paths p
        JOIN configuration_value_contents c ON c.id = p.content_id
        WHERE p.lowercase_path = ANY(ARRAY['/tests/aliasreplace/first', '/tests/aliasreplace/second'])
        GROUP BY c.value
        ",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(stored, ["edited"]);
    let contents: i64 = sqlx::query_scalar(
        r"
        SELECT COUNT(DISTINCT p.content_id)
        FROM configuration_paths p
        WHERE p.lowercase_path LIKE '/tests/aliasreplace/%'
        ",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(contents, 1);

    clear_test_paths(&pool, &["/tests/aliasreplace"]).await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn postgres_service_scopes_alias_permissions() {
    let database_url = env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL")
        .expect("SOVEREIGN_CONFIG_TEST_DATABASE_URL must be configured");
    let pool = PgPoolOptions::new().connect(&database_url).await.unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    clear_test_paths(&pool, &["/tests/aliasauth"]).await;
    let service = ConfigurationService::new(pool.clone(), test_cipher());
    let read_write = [Permission::Read, Permission::Write];

    service
        .put_value(request_for_prefix(
            plain_put("/tests/aliasauth/visible", "one"),
            "/tests/aliasauth",
            &read_write,
        ))
        .await
        .unwrap();
    service
        .add_value_path(request_for_prefix(
            AddValuePathRequest {
                source_path: "/tests/aliasauth/visible".into(),
                new_path: "/tests/aliasauth/hidden".into(),
            },
            "/tests/aliasauth",
            &read_write,
        ))
        .await
        .unwrap();

    // A caller who can only read one path sees only that path.
    let scoped = service
        .list_value_paths(request_with_grants(
            ListValuePathsRequest {
                path: "/tests/aliasauth/visible".into(),
            },
            &[("/tests/aliasauth/visible", &[Permission::Read])],
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(scoped.paths, ["/tests/aliasauth/visible"]);

    // Aliasing requires write on the new path, not just the source.
    let denied = service
        .add_value_path(request_with_grants(
            AddValuePathRequest {
                source_path: "/tests/aliasauth/visible".into(),
                new_path: "/tests/aliasauth/another".into(),
            },
            &[(
                "/tests/aliasauth/visible",
                &[Permission::Read, Permission::Write],
            )],
        ))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), Code::PermissionDenied);

    // A new path nesting under an existing path collides.
    let collision = service
        .add_value_path(request_for_prefix(
            AddValuePathRequest {
                source_path: "/tests/aliasauth/visible".into(),
                new_path: "/tests/aliasauth/visible/child".into(),
            },
            "/tests/aliasauth",
            &read_write,
        ))
        .await
        .unwrap_err();
    assert_eq!(collision.code(), Code::InvalidArgument);

    // Re-aliasing an occupied path is rejected.
    let duplicate = service
        .add_value_path(request_for_prefix(
            AddValuePathRequest {
                source_path: "/tests/aliasauth/visible".into(),
                new_path: "/tests/aliasauth/hidden".into(),
            },
            "/tests/aliasauth",
            &read_write,
        ))
        .await
        .unwrap_err();
    assert_eq!(duplicate.code(), Code::AlreadyExists);

    clear_test_paths(&pool, &["/tests/aliasauth"]).await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn postgres_stores_secrets_as_ciphertext_and_reveals_them() {
    let database_url = env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL")
        .expect("SOVEREIGN_CONFIG_TEST_DATABASE_URL must be configured");
    let pool = PgPoolOptions::new().connect(&database_url).await.unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    clear_test_paths(&pool, &["/tests/encryption"]).await;
    let service = ConfigurationService::new(pool.clone(), test_cipher());
    let permissions = [Permission::Read, Permission::Write];

    service
        .put_value(request_for_prefix(
            secret_put("/tests/encryption/token", "hunter2"),
            "/tests/encryption",
            &permissions,
        ))
        .await
        .unwrap();

    // The point of the whole change: anyone reading the table directly —
    // a dump, a backup, a replica — sees no plaintext.
    let (_, stored, classification) = stored_value(&pool, "/tests/encryption/token").await;
    assert_eq!(classification, "secret");
    assert!(stored.starts_with("enc:v1:"));
    assert!(!stored.contains("hunter2"));

    let revealed = service
        .reveal_secret(request_for_prefix(
            RevealSecretRequest {
                path: "/tests/encryption/token".into(),
            },
            "/tests/encryption",
            &permissions,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(revealed.value, "hunter2");

    // Listings mask secrets, so they must not carry the ciphertext either.
    let listing = service
        .list_values(request_for_prefix(
            ListValuesRequest {
                path: "/tests/encryption".into(),
            },
            "/tests/encryption",
            &permissions,
        ))
        .await
        .unwrap()
        .into_inner();
    let listed = listing
        .values
        .iter()
        .find(|value| value.path == "/tests/encryption/token")
        .expect("the stored secret must be listed");
    assert!(matches!(
        listed.content,
        Some(listed_value::Content::MaskedSecret(_))
    ));

    clear_test_paths(&pool, &["/tests/encryption"]).await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn postgres_leaves_plain_values_readable() {
    let database_url = env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL")
        .expect("SOVEREIGN_CONFIG_TEST_DATABASE_URL must be configured");
    let pool = PgPoolOptions::new().connect(&database_url).await.unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    clear_test_paths(&pool, &["/tests/encryptionplain"]).await;
    let service = ConfigurationService::new(pool.clone(), test_cipher());
    let permissions = [Permission::Read, Permission::Write];

    service
        .put_value(request_for_prefix(
            plain_put("/tests/encryptionplain/host", "db.internal"),
            "/tests/encryptionplain",
            &permissions,
        ))
        .await
        .unwrap();

    let (_, stored, classification) = stored_value(&pool, "/tests/encryptionplain/host").await;
    assert_eq!(classification, "plain");
    assert_eq!(stored, "db.internal");

    clear_test_paths(&pool, &["/tests/encryptionplain"]).await;
    pool.close().await;
}

// `_` is a single-character wildcard in SQL LIKE. Every subtree match in
// this file must therefore use starts_with, or a path containing `_` would
// reach across into a sibling subtree that authorize() never checked —
// silently widening reads and, worse, recursive deletes.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn postgres_treats_underscore_as_a_literal_not_a_wildcard() {
    let database_url = env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL")
        .expect("SOVEREIGN_CONFIG_TEST_DATABASE_URL must be configured");
    let pool = PgPoolOptions::new().connect(&database_url).await.unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    clear_test_paths(&pool, &["/tests/underscore"]).await;
    let service = ConfigurationService::new(pool.clone(), test_cipher());
    let permissions = [Permission::Read, Permission::Write, Permission::Manage];

    // `a_b` and `axb` are distinct subtrees that `LIKE '/…/a_b/%'` conflates.
    for (path, value) in [
        ("/tests/underscore/a_b/github_token", "under"),
        ("/tests/underscore/axb/sibling", "sibling"),
    ] {
        service
            .put_value(request_for_prefix(
                plain_put(path, value),
                "/tests/underscore",
                &permissions,
            ))
            .await
            .unwrap();
    }

    let subtree = service
        .get_sub_tree(request_for_prefix(
            GetSubTreeRequest {
                path: "/tests/underscore/a_b".into(),
            },
            "/tests/underscore",
            &permissions,
        ))
        .await
        .unwrap()
        .into_inner();
    let read: Vec<String> = subtree.values.into_iter().map(|value| value.path).collect();
    assert_eq!(read, vec!["/tests/underscore/a_b/github_token".to_owned()]);

    // The recursive delete is where the wildcard would destroy data.
    service
        .delete_values(request_for_prefix(
            DeleteValuesRequest {
                path: "/tests/underscore/a_b".into(),
                recurse: true,
            },
            "/tests/underscore",
            &permissions,
        ))
        .await
        .unwrap();

    let survivors = service
        .get_sub_tree(request_for_prefix(
            GetSubTreeRequest {
                path: "/tests/underscore".into(),
            },
            "/tests/underscore",
            &permissions,
        ))
        .await
        .unwrap()
        .into_inner();
    let remaining: Vec<String> = survivors
        .values
        .into_iter()
        .map(|value| value.path)
        .collect();
    assert_eq!(remaining, vec!["/tests/underscore/axb/sibling".to_owned()]);

    clear_test_paths(&pool, &["/tests/underscore"]).await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn postgres_rejects_ciphertext_moved_between_values() {
    let database_url = env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL")
        .expect("SOVEREIGN_CONFIG_TEST_DATABASE_URL must be configured");
    let pool = PgPoolOptions::new().connect(&database_url).await.unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    clear_test_paths(&pool, &["/tests/encryptionswap"]).await;
    let service = ConfigurationService::new(pool.clone(), test_cipher());
    let permissions = [Permission::Read, Permission::Write];

    for (path, value) in [("first", "alpha-secret"), ("second", "beta-secret")] {
        service
            .put_value(request_for_prefix(
                secret_put(&format!("/tests/encryptionswap/{path}"), value),
                "/tests/encryptionswap",
                &permissions,
            ))
            .await
            .unwrap();
    }

    // Someone with SQL write access copies one value's ciphertext over
    // another's. Without the row binding this would silently reveal the
    // first secret under the second path.
    let (_, first_stored, _) = stored_value(&pool, "/tests/encryptionswap/first").await;
    let (second_id, _, _) = stored_value(&pool, "/tests/encryptionswap/second").await;
    sqlx::query("UPDATE configuration_value_contents SET value = $2 WHERE id = $1")
        .bind(second_id)
        .bind(&first_stored)
        .execute(&pool)
        .await
        .unwrap();

    let error = service
        .reveal_secret(request_for_prefix(
            RevealSecretRequest {
                path: "/tests/encryptionswap/second".into(),
            },
            "/tests/encryptionswap",
            &permissions,
        ))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::Internal);
    assert!(!error.message().contains("alpha-secret"));
    assert!(!error.message().contains("enc:v1:"));

    clear_test_paths(&pool, &["/tests/encryptionswap"]).await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn postgres_reclassification_switches_the_stored_representation() {
    let database_url = env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL")
        .expect("SOVEREIGN_CONFIG_TEST_DATABASE_URL must be configured");
    let pool = PgPoolOptions::new().connect(&database_url).await.unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    clear_test_paths(&pool, &["/tests/encryptionclass"]).await;
    let service = ConfigurationService::new(pool.clone(), test_cipher());
    let permissions = [Permission::Read, Permission::Write];
    let path = "/tests/encryptionclass/value";

    service
        .put_value(request_for_prefix(
            plain_put(path, "not-yet-sensitive"),
            "/tests/encryptionclass",
            &permissions,
        ))
        .await
        .unwrap();
    let (_, stored, classification) = stored_value(&pool, path).await;
    assert_eq!(
        (stored.as_str(), classification.as_str()),
        ("not-yet-sensitive", "plain")
    );

    // plain -> secret seals the new value.
    service
        .put_value(request_for_prefix(
            secret_put(path, "now-sensitive"),
            "/tests/encryptionclass",
            &permissions,
        ))
        .await
        .unwrap();
    let (_, stored, classification) = stored_value(&pool, path).await;
    assert_eq!(classification, "secret");
    assert!(stored.starts_with("enc:v1:"));
    assert!(!stored.contains("now-sensitive"));
    let revealed = service
        .reveal_secret(request_for_prefix(
            RevealSecretRequest { path: path.into() },
            "/tests/encryptionclass",
            &permissions,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(revealed.value, "now-sensitive");

    // secret -> plain stores the new value in the clear, and it is no
    // longer revealable.
    service
        .put_value(request_for_prefix(
            plain_put(path, "public-again"),
            "/tests/encryptionclass",
            &permissions,
        ))
        .await
        .unwrap();
    let (_, stored, classification) = stored_value(&pool, path).await;
    assert_eq!(
        (stored.as_str(), classification.as_str()),
        ("public-again", "plain")
    );
    let error = service
        .reveal_secret(request_for_prefix(
            RevealSecretRequest { path: path.into() },
            "/tests/encryptionclass",
            &permissions,
        ))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);

    clear_test_paths(&pool, &["/tests/encryptionclass"]).await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn postgres_encrypts_legacy_plaintext_secrets_once() {
    let database_url = env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL")
        .expect("SOVEREIGN_CONFIG_TEST_DATABASE_URL must be configured");
    let pool = PgPoolOptions::new().connect(&database_url).await.unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    clear_test_paths(&pool, &["/tests/encryptionbackfill"]).await;
    let cipher = test_cipher();
    let path = "/tests/encryptionbackfill/legacy";
    seed_legacy_plaintext_secret(&pool, path, "legacy-secret").await;

    encrypt_stored_secrets(&pool, &cipher).await.unwrap();

    let (_, sealed, classification) = stored_value(&pool, path).await;
    assert_eq!(classification, "secret");
    assert!(sealed.starts_with("enc:v1:"));
    assert!(!sealed.contains("legacy-secret"));

    let service = ConfigurationService::new(pool.clone(), Arc::clone(&cipher));
    let permissions = [Permission::Read, Permission::Write];
    let revealed = service
        .reveal_secret(request_for_prefix(
            RevealSecretRequest { path: path.into() },
            "/tests/encryptionbackfill",
            &permissions,
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(revealed.value, "legacy-secret");

    // Running again must not re-seal what is already sealed: a second
    // layer would make the value unreadable.
    encrypt_stored_secrets(&pool, &cipher).await.unwrap();
    let (_, after, _) = stored_value(&pool, path).await;
    assert_eq!(after, sealed);

    clear_test_paths(&pool, &["/tests/encryptionbackfill"]).await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn postgres_survives_one_damaged_secret_and_fails_closed_on_reading_it() {
    let database_url = env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL")
        .expect("SOVEREIGN_CONFIG_TEST_DATABASE_URL must be configured");
    let pool = PgPoolOptions::new().connect(&database_url).await.unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    clear_test_paths(&pool, &["/tests/encryptiondamaged"]).await;
    let damaged_path = "/tests/encryptiondamaged/token";
    let healthy_path = "/tests/encryptiondamaged/legacy";
    seed_legacy_plaintext_secret(&pool, damaged_path, "placeholder").await;
    seed_legacy_plaintext_secret(&pool, healthy_path, "still-fine").await;
    let (damaged_id, _, _) = stored_value(&pool, damaged_path).await;

    // One row sealed under a key this server does not have — a torn write
    // or a partial restore looks the same from here.
    let foreign = cipher_seeded(0x11)
        .encrypt(damaged_id, "secret", "sealed-under-another-key")
        .unwrap();
    sqlx::query("UPDATE configuration_value_contents SET value = $2 WHERE id = $1")
        .bind(damaged_id)
        .bind(&foreign)
        .execute(&pool)
        .await
        .unwrap();

    // Restore the database before asserting. A panic below would otherwise
    // leave a foreign envelope in the shared test database, and this pass
    // is global rather than prefix-scoped, so every later run — and any
    // developer server pointed at it — would inherit the damage.
    let outcome = encrypt_stored_secrets(&pool, &test_cipher()).await;
    let sealed_healthy = stored_value(&pool, healthy_path).await.1;
    let damaged_after = stored_value(&pool, damaged_path).await.1;
    clear_test_paths(&pool, &["/tests/encryptiondamaged"]).await;

    // Damage to one secret must not deny the service to everything else,
    // including every plain value, none of which needs a key at all.
    outcome.expect("one damaged secret must not prevent startup");
    assert!(sealed_healthy.starts_with("enc:v1:"));
    assert!(!sealed_healthy.contains("still-fine"));
    // The damaged row is left exactly as found, never re-sealed.
    assert_eq!(damaged_after, foreign);

    pool.close().await;
}

#[test]
fn a_key_that_opens_nothing_is_reported_as_the_wrong_key() {
    // Every sealed row failing points at the key; one key opens all of
    // them. A mix means the key is right and those rows are damaged.
    assert!(wrong_key(3, 3));
    assert!(!wrong_key(1, 3));
    assert!(!wrong_key(0, 3));
    // Nothing sealed yet cannot condemn the key.
    assert!(!wrong_key(0, 0));
    // A lone sealed secret that fails is ambiguous, and resolved as the
    // wrong key: refusing to start is easier to diagnose than quietly
    // serving a secret the server cannot read.
    assert!(wrong_key(1, 1));
}
