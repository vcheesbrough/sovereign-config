use std::{borrow::Cow, env, time::Duration};

use sovereign_config_core::ConfigPath;
use sqlx::{PgPool, migrate::Migrator, postgres::PgPoolOptions};
use tokio::time::{Instant, sleep};

async fn connect_when_ready(database_url: &str) -> PgPool {
    let deadline = Instant::now() + Duration::from_secs(30);

    loop {
        if let Ok(pool) = PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(2))
            .connect(database_url)
            .await
        {
            return pool;
        }

        assert!(
            Instant::now() < deadline,
            "PostgreSQL migration test service did not become ready"
        );
        sleep(Duration::from_millis(500)).await;
    }
}

async fn reset_schema(pool: &PgPool, context: &str) {
    sqlx::query(
        // Every table the migrations create, so a reset leaves nothing for the
        // next `run` to collide with. A new migration adds its table here.
        "DROP TABLE IF EXISTS audit_events, configuration_paths, configuration_value_contents, configuration_values, managed_connections, schema_metadata, _sqlx_migrations CASCADE",
    )
    .execute(pool)
    .await
    .unwrap_or_else(|_| panic!("test schema must reset {context}"));
}

// Insert one content row and return its id, so path-constraint fixtures can
// satisfy the foreign key.
async fn seed_content(pool: &PgPool, classification: &str) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO configuration_value_contents (value, classification, created_at, updated_at) VALUES ('', $1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) RETURNING id",
    )
    .bind(classification)
    .fetch_one(pool)
    .await
    .expect("content fixture must be insertable")
}

async fn rooted_path_constraint_accepts_only_rooted_values(pool: &PgPool) {
    let content_id = seed_content(pool, "plain").await;
    let invalid_path = sqlx::query(
        "INSERT INTO configuration_paths (path, content_id, created_at, updated_at) VALUES ('Invalid/Path', $1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
    )
    .bind(content_id)
    .execute(pool)
    .await;
    let rooted_path = sqlx::query(
        "INSERT INTO configuration_paths (path, content_id, created_at, updated_at) VALUES ('/valid/path', $1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
    )
    .bind(content_id)
    .execute(pool)
    .await;
    // 0008 widened the segment grammar to permit `_` while still rejecting
    // everything outside [a-z0-9_-].
    let underscored_path = sqlx::query(
        "INSERT INTO configuration_paths (path, content_id, created_at, updated_at) VALUES ('/woodpecker/global/github_token', $1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
    )
    .bind(content_id)
    .execute(pool)
    .await;
    let dotted_path = sqlx::query(
        "INSERT INTO configuration_paths (path, content_id, created_at, updated_at) VALUES ('/woodpecker/global/github.token', $1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
    )
    .bind(content_id)
    .execute(pool)
    .await;
    let retained_values: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM configuration_paths")
        .fetch_one(pool)
        .await
        .expect("configuration path inventory must be readable");

    assert!(invalid_path.is_err());
    assert!(rooted_path.is_ok());
    assert!(underscored_path.is_ok());
    assert!(dotted_path.is_err());
    assert_eq!(retained_values, 2);
}

/// Paths that probe every edge of the grammar: each character class at a
/// segment boundary, every way of being unrooted or empty, the separators and
/// encodings a caller might try, and the two places a regex and a byte scan
/// most often part ways — a trailing newline and a non-ASCII letter.
const PATH_GRAMMAR_CORPUS: [&str; 34] = [
    "/a",
    "/a/b",
    "/A/b",
    "/Mixed/Case_and-dash",
    "/0",
    "/a_b",
    "/a-b",
    "/-",
    "/_",
    "/a/B/c9",
    "",
    "/",
    "a",
    "a/b",
    "/a/",
    "//a",
    "/a//b",
    "/a b",
    " /a",
    "/a ",
    "/a\tb",
    "/a.b",
    "/a:b",
    "/a@b",
    "/a+b",
    "/a~b",
    "/a\\b",
    "/a%2fb",
    "/a\n",
    "\n/a",
    "/a/b\n",
    "/\u{e9}",
    "/\u{ff41}",
    "/a/\u{c5}",
];

/// The `configuration_paths.path` constraint and `ConfigPath::parse_operation`
/// must admit exactly the same strings.
///
/// The server relies on it: reads hand each stored path to `parse_operation`
/// to carry it as a `ConfigPath`, and fail the whole response if that parse
/// fails. That is only safe while no row the database accepts can fail it. The
/// two live in different files and different languages, and migration 0008 is
/// precedent for the constraint being widened — so whoever next widens either
/// one alone finds out here, not from a listing that answers `UNAVAILABLE`.
async fn path_constraint_and_parser_admit_the_same_grammar(pool: &PgPool) {
    let content_id = seed_content(pool, "plain").await;
    for path in PATH_GRAMMAR_CORPUS {
        let mut transaction = pool.begin().await.expect("transaction must begin");
        let inserted = sqlx::query(
            "INSERT INTO configuration_paths (path, content_id, created_at, updated_at) VALUES ($1, $2, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
        )
        .bind(path)
        .bind(content_id)
        .execute(&mut *transaction)
        .await;
        transaction
            .rollback()
            .await
            .expect("probe must leave no row behind");

        // Only the grammar constraint may refuse a probe: any other failure
        // would otherwise pass for a rejection and prove nothing.
        let database_accepts = match inserted {
            Ok(_) => true,
            Err(error) => {
                let refused_by = error
                    .as_database_error()
                    .and_then(sqlx::error::DatabaseError::constraint)
                    .map(str::to_owned);
                assert_eq!(
                    refused_by.as_deref(),
                    Some("configuration_paths_path_check"),
                    "{path:?} was refused by something other than the grammar: {error}"
                );
                false
            }
        };
        assert_eq!(
            database_accepts,
            ConfigPath::parse_operation(path).is_ok(),
            "the path constraint and ConfigPath::parse_operation disagree on {path:?}"
        );
    }
}

async fn classification_is_explicit_and_constrained(pool: &PgPool) {
    let invalid = sqlx::query(
        "INSERT INTO configuration_value_contents (value, classification, created_at, updated_at) VALUES ('', 'unknown', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
    )
    .execute(pool)
    .await;
    let omitted = sqlx::query(
        "INSERT INTO configuration_value_contents (value, created_at, updated_at) VALUES ('', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
    )
    .execute(pool)
    .await;

    assert!(invalid.is_err());
    assert!(omitted.is_err());
}

async fn managed_connection_constraints_are_enforced(pool: &PgPool) {
    let valid = sqlx::query(
        "INSERT INTO managed_connections (connection_id, display_name, root, state, created_at, updated_at) VALUES ('abcdefghij0123456789abcdefghij01', 'Pipeline reader', '/apps/api', 'provisioning', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
    )
    .execute(pool)
    .await;
    let global_root = sqlx::query(
        "INSERT INTO managed_connections (connection_id, display_name, root, state, created_at, updated_at) VALUES ('abcdefghij0123456789abcdefghij02', 'Global reader', '/', 'active', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
    )
    .execute(pool)
    .await;
    let invalid_id = sqlx::query(
        "INSERT INTO managed_connections (connection_id, display_name, root, state, created_at, updated_at) VALUES ('UPPER', 'name', '/', 'active', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
    )
    .execute(pool)
    .await;
    let invalid_state = sqlx::query(
        "INSERT INTO managed_connections (connection_id, display_name, root, state, created_at, updated_at) VALUES ('abcdefghij0123456789abcdefghij03', 'name', '/', 'revoked', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
    )
    .execute(pool)
    .await;
    let invalid_root = sqlx::query(
        "INSERT INTO managed_connections (connection_id, display_name, root, state, created_at, updated_at) VALUES ('abcdefghij0123456789abcdefghij04', 'name', 'unrooted', 'active', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
    )
    .execute(pool)
    .await;
    let padded_name = sqlx::query(
        "INSERT INTO managed_connections (connection_id, display_name, root, state, created_at, updated_at) VALUES ('abcdefghij0123456789abcdefghij05', ' padded', '/', 'active', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
    )
    .execute(pool)
    .await;
    // 0008: a connection may be rooted at an underscored path.
    let underscored_root = sqlx::query(
        "INSERT INTO managed_connections (connection_id, display_name, root, state, created_at, updated_at) VALUES ('abcdefghij0123456789abcdefghij06', 'Woodpecker broker', '/woodpecker/repos/vcheesbrough/sovereign_config', 'active', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
    )
    .execute(pool)
    .await;

    assert!(valid.is_ok());
    assert!(global_root.is_ok());
    assert!(invalid_id.is_err());
    assert!(invalid_state.is_err());
    assert!(invalid_root.is_err());
    assert!(padded_name.is_err());
    assert!(underscored_root.is_ok());

    // A row inserted without the permissions column defaults to read-only.
    let backfilled: String = sqlx::query_scalar(
        "SELECT permissions FROM managed_connections WHERE connection_id = 'abcdefghij0123456789abcdefghij01'",
    )
    .fetch_one(pool)
    .await
    .expect("default permissions must be readable");
    assert_eq!(backfilled, "read");

    // Every canonical non-empty subset is accepted.
    for permissions in [
        "read",
        "write",
        "manage",
        "read,write",
        "read,manage",
        "write,manage",
        "read,write,manage",
    ] {
        let accepted = sqlx::query(
            "INSERT INTO managed_connections (connection_id, display_name, root, state, permissions, created_at, updated_at) VALUES ('permsaccepted0123456789abcdefghi', 'name', '/', 'active', $1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
        )
        .bind(permissions)
        .execute(pool)
        .await;
        assert!(accepted.is_ok(), "{permissions} must be accepted");
        sqlx::query("DELETE FROM managed_connections WHERE connection_id = 'permsaccepted0123456789abcdefghi'")
            .execute(pool)
            .await
            .expect("permission fixture cleanup must succeed");
    }

    // An unknown permission, an empty set, and a non-canonical order are all
    // rejected by the CHECK constraint.
    for permissions in ["", "admin", "write,read", "read,read"] {
        let rejected = sqlx::query(
            "INSERT INTO managed_connections (connection_id, display_name, root, state, permissions, created_at, updated_at) VALUES ('permsrejected0123456789abcdefghi', 'name', '/', 'active', $1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
        )
        .bind(permissions)
        .execute(pool)
        .await;
        assert!(rejected.is_err(), "{permissions:?} must be rejected");
    }

    sqlx::query("DELETE FROM managed_connections")
        .execute(pool)
        .await
        .expect("managed connection cleanup must succeed");
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn migrations_are_repeatable_against_postgresql() {
    let database_url = env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL")
        .expect("SOVEREIGN_CONFIG_TEST_DATABASE_URL must be configured");
    let pool = connect_when_ready(&database_url).await;
    let migrator = sqlx::migrate!("./migrations");
    reset_schema(&pool, "before upgrade validation").await;

    let prior_release = Migrator {
        migrations: Cow::Owned(vec![migrator.migrations[0].clone()]),
        ..Migrator::DEFAULT
    };
    prior_release
        .run(&pool)
        .await
        .expect("prior release migration must succeed");
    let value_table_before_upgrade: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('configuration_values')::text")
            .fetch_one(&pool)
            .await
            .expect("prior schema inventory must be readable");
    assert!(value_table_before_upgrade.is_none());
    let legacy_values = Migrator {
        migrations: Cow::Owned(vec![
            migrator.migrations[0].clone(),
            migrator.migrations[1].clone(),
        ]),
        ..Migrator::DEFAULT
    };
    legacy_values
        .run(&pool)
        .await
        .expect("legacy value schema migration must succeed");
    sqlx::query(
        "INSERT INTO configuration_values (path, value, created_at, updated_at) VALUES ('legacy/path', '', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
    )
    .execute(&pool)
    .await
    .expect("legacy value must be insertable before the rooted migration");
    migrator
        .run(&pool)
        .await
        .expect("upgrade from the prior release must succeed");
    // The rooted migration (0003) purges legacy rows; the alias migration
    // (0007) then leaves no paths to back-fill.
    let values_after_rooted_upgrade: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM configuration_paths")
            .fetch_one(&pool)
            .await
            .expect("upgraded configuration path inventory must be readable");
    assert_eq!(values_after_rooted_upgrade, 0);

    reset_schema(&pool, "after upgrade validation").await;

    let v2_release = Migrator {
        migrations: Cow::Owned(migrator.migrations[..3].to_vec()),
        ..Migrator::DEFAULT
    };
    v2_release
        .run(&pool)
        .await
        .expect("v2 schema migration must succeed");
    sqlx::query(
        "INSERT INTO configuration_values (path, value, created_at, updated_at) VALUES ('/existing/value', 'plain-sentinel', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
    )
    .execute(&pool)
    .await
    .expect("v2 value must be insertable");
    migrator
        .run(&pool)
        .await
        .expect("v2 classification upgrade must succeed");
    // After the alias split (0007) the value is reached through a path row
    // joined to its content, preserving the sentinel and default classification.
    let migrated: (String, String) = sqlx::query_as(
        r"
        SELECT c.value, c.classification
        FROM configuration_paths p
        JOIN configuration_value_contents c ON c.id = p.content_id
        WHERE p.path = '/existing/value'
        ",
    )
    .fetch_one(&pool)
    .await
    .expect("migrated value must be readable");
    assert_eq!(migrated, ("plain-sentinel".into(), "plain".into()));

    reset_schema(&pool, "after v2 classification validation").await;

    migrator
        .run(&pool)
        .await
        .expect("first migration run must succeed");
    migrator
        .run(&pool)
        .await
        .expect("repeated migration run must succeed");

    let applied_migrations: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations WHERE success")
            .fetch_one(&pool)
            .await
            .expect("migration history must be readable");
    let metadata_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM schema_metadata")
        .fetch_one(&pool)
        .await
        .expect("migrated schema must be readable");
    let authorization_tables: i64 = sqlx::query_scalar(
        r"
        SELECT COUNT(*)
        FROM information_schema.tables
        WHERE table_schema = current_schema()
          AND (
            table_name LIKE '%acl%'
            OR table_name LIKE '%grant%'
            OR table_name LIKE '%token%'
            OR table_name LIKE '%session%'
            OR table_name LIKE '%history%'
            OR table_name LIKE '%tombstone%'
            OR table_name LIKE '%key%'
          )
        ",
    )
    .fetch_one(&pool)
    .await
    .expect("authorization table inventory must be readable");
    // Audit storage was forbidden outright until the audit trail (card #373)
    // introduced exactly one table. It is named here so that a *second* one,
    // or a differently named one, still fails: the trail is a deliberate,
    // singular exception, not an opening for storing authorization state.
    let audit_tables: Vec<String> = sqlx::query_scalar(
        r"
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = current_schema() AND table_name LIKE '%audit%'
        ORDER BY table_name
        ",
    )
    .fetch_all(&pool)
    .await
    .expect("audit table inventory must be readable");

    // The alias split replaces configuration_values with a content table and a
    // path table referencing it.
    let legacy_value_table: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('configuration_values')::text")
            .fetch_one(&pool)
            .await
            .expect("legacy value table inventory must be readable");
    let content_columns: i64 = sqlx::query_scalar(
        r"
        SELECT COUNT(*)
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'configuration_value_contents'
          AND column_name IN ('id', 'value', 'classification', 'created_at', 'updated_at')
        ",
    )
    .fetch_one(&pool)
    .await
    .expect("configuration content schema must be readable");
    let path_columns: i64 = sqlx::query_scalar(
        r"
        SELECT COUNT(*)
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'configuration_paths'
          AND column_name IN ('path', 'content_id', 'created_at', 'updated_at')
        ",
    )
    .fetch_one(&pool)
    .await
    .expect("configuration path schema must be readable");
    let managed_connection_columns: Vec<String> = sqlx::query_scalar(
        r"
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'managed_connections'
        ORDER BY column_name
        ",
    )
    .fetch_all(&pool)
    .await
    .expect("managed connection schema must be readable");
    // The metadata table must never gain a credential, secret, or URL column.
    assert_eq!(
        managed_connection_columns,
        [
            "connection_id",
            "created_at",
            "credential_identifier",
            "display_name",
            "permissions",
            "provider_user_id",
            "provider_user_uid",
            "root",
            "state",
            "updated_at",
        ]
    );
    let credential_columns: i64 = sqlx::query_scalar(
        r"
        SELECT COUNT(*)
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND (
            column_name LIKE '%url%'
            OR column_name LIKE '%password%'
            OR column_name LIKE '%secret%'
            OR column_name LIKE '%key%'
            OR column_name LIKE '%token%'
          )
        ",
    )
    .fetch_one(&pool)
    .await
    .expect("credential column inventory must be readable");
    // The audit query's filters are served by indexes, not by scanning a
    // year of history (card #407).
    let audit_indexes: Vec<String> = sqlx::query_scalar(
        r"
        SELECT indexname::text
        FROM pg_indexes
        WHERE schemaname = current_schema() AND tablename = 'audit_events'
        ORDER BY indexname
        ",
    )
    .fetch_all(&pool)
    .await
    .expect("audit index inventory must be readable");
    assert_eq!(applied_migrations, 12);
    assert_eq!(
        audit_indexes,
        [
            "audit_events_coalesce_digest_key",
            "audit_events_first_occurred_idx",
            "audit_events_narrative_trgm_idx",
            "audit_events_occurred_idx",
            "audit_events_path_fold_trgm_idx",
            "audit_events_pkey",
        ]
    );
    assert_eq!(metadata_rows, 1);
    assert_eq!(authorization_tables, 0);
    assert_eq!(audit_tables, ["audit_events"]);
    assert!(legacy_value_table.is_none());
    assert_eq!(content_columns, 5);
    assert_eq!(path_columns, 4);
    assert_eq!(credential_columns, 0);
    rooted_path_constraint_accepts_only_rooted_values(&pool).await;
    path_constraint_and_parser_admit_the_same_grammar(&pool).await;
    classification_is_explicit_and_constrained(&pool).await;
    managed_connection_constraints_are_enforced(&pool).await;
}
