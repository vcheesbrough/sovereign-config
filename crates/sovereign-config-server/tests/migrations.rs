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

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn migrations_are_repeatable_against_postgresql() {
    let database_url = env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL")
        .expect("SOVEREIGN_CONFIG_TEST_DATABASE_URL must be configured");
    let pool = connect_when_ready(&database_url).await;
    let migrator = sqlx::migrate!("./migrations");
    sqlx::query(
        "DROP TABLE IF EXISTS configuration_values, schema_metadata, _sqlx_migrations CASCADE",
    )
    .execute(&pool)
    .await
    .expect("test schema must reset");

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
    migrator
        .run(&pool)
        .await
        .expect("upgrade from the prior release must succeed");

    sqlx::query(
        "DROP TABLE IF EXISTS configuration_values, schema_metadata, _sqlx_migrations CASCADE",
    )
    .execute(&pool)
    .await
    .expect("test schema must reset after upgrade validation");

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
          AND column_name IN ('path', 'value', 'created_at', 'updated_at')
        ",
    )
    .fetch_one(&pool)
    .await
    .expect("configuration value schema must be readable");
    let invalid_path = sqlx::query(
        "INSERT INTO configuration_values (path, value, created_at, updated_at) VALUES ('Invalid/Path', '', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
    )
    .execute(&pool)
    .await;

    assert_eq!(applied_migrations, 2);
    assert_eq!(metadata_rows, 1);
    assert_eq!(authorization_tables, 0);
    assert_eq!(value_columns, 4);
    assert!(invalid_path.is_err());
}
