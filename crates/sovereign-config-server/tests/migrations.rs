use std::{borrow::Cow, env, time::Duration};

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
        "DROP TABLE IF EXISTS configuration_values, managed_connections, schema_metadata, _sqlx_migrations CASCADE",
    )
    .execute(pool)
    .await
    .unwrap_or_else(|_| panic!("test schema must reset {context}"));
}

async fn rooted_path_constraint_accepts_only_rooted_values(pool: &PgPool) {
    let invalid_path = sqlx::query(
        "INSERT INTO configuration_values (path, value, classification, created_at, updated_at) VALUES ('Invalid/Path', '', 'plain', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
    )
    .execute(pool)
    .await;
    let rooted_path = sqlx::query(
        "INSERT INTO configuration_values (path, value, classification, created_at, updated_at) VALUES ('/valid/path', '', 'plain', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
    )
    .execute(pool)
    .await;
    let retained_values: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM configuration_values")
        .fetch_one(pool)
        .await
        .expect("configuration value inventory must be readable");

    assert!(invalid_path.is_err());
    assert!(rooted_path.is_ok());
    assert_eq!(retained_values, 1);
}

async fn classification_is_explicit_and_constrained(pool: &PgPool) {
    let invalid = sqlx::query(
        "INSERT INTO configuration_values (path, value, classification, created_at, updated_at) VALUES ('/invalid/classification', '', 'unknown', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
    )
    .execute(pool)
    .await;
    let omitted = sqlx::query(
        "INSERT INTO configuration_values (path, value, created_at, updated_at) VALUES ('/missing/classification', '', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
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

    assert!(valid.is_ok());
    assert!(global_root.is_ok());
    assert!(invalid_id.is_err());
    assert!(invalid_state.is_err());
    assert!(invalid_root.is_err());
    assert!(padded_name.is_err());

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
    let values_after_rooted_upgrade: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM configuration_values")
            .fetch_one(&pool)
            .await
            .expect("upgraded configuration value inventory must be readable");
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
    let migrated: (String, String) = sqlx::query_as(
        "SELECT value, classification FROM configuration_values WHERE path = '/existing/value'",
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
            OR table_name LIKE '%audit%'
            OR table_name LIKE '%history%'
            OR table_name LIKE '%tombstone%'
            OR table_name LIKE '%key%'
          )
        ",
    )
    .fetch_one(&pool)
    .await
    .expect("authorization table inventory must be readable");

    let value_columns: i64 = sqlx::query_scalar(
        r"
        SELECT COUNT(*)
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'configuration_values'
          AND column_name IN ('path', 'value', 'classification', 'created_at', 'updated_at')
        ",
    )
    .fetch_one(&pool)
    .await
    .expect("configuration value schema must be readable");
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
    assert_eq!(applied_migrations, 5);
    assert_eq!(metadata_rows, 1);
    assert_eq!(authorization_tables, 0);
    assert_eq!(value_columns, 5);
    assert_eq!(credential_columns, 0);
    rooted_path_constraint_accepts_only_rooted_values(&pool).await;
    classification_is_explicit_and_constrained(&pool).await;
    managed_connection_constraints_are_enforced(&pool).await;
}
