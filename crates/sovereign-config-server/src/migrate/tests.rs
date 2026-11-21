//! `migrate` and the server's checks of it, against `PostgreSQL`.
//!
//! Each test works in a schema of its own on the search path, so a fresh,
//! empty database is cheap and the shared test database is never left
//! half-migrated.

use sqlx::{Connection as _, PgConnection, PgPool};

use super::{MIGRATOR, apply_schema, connect, run, verify_schema};
use crate::config::MigrateConfig;
use crate::encryption::ValueCipher;
use crate::identity::{self, ExternalSetup};
use crate::values::verify_stored_secrets;

/// A pool on an empty schema named `schema`, first on the search path.
async fn empty_schema(schema: &str) -> Option<(PgPool, String)> {
    let database_url = std::env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL").ok()?;
    let mut connection = PgConnection::connect(&database_url)
        .await
        .expect("the test database must accept connections");
    // Installed where every schema finds it: a migration that creates it
    // would otherwise put it in whichever schema ran first.
    for statement in [
        "CREATE EXTENSION IF NOT EXISTS pg_trgm SCHEMA public".to_owned(),
        format!("DROP SCHEMA IF EXISTS {schema} CASCADE"),
        format!("CREATE SCHEMA {schema}"),
    ] {
        sqlx::query(&statement)
            .execute(&mut connection)
            .await
            .expect("schema setup must succeed");
    }
    let separator = if database_url.contains('?') { '&' } else { '?' };
    let url = format!("{database_url}{separator}options=-c%20search_path%3D{schema}%2Cpublic");
    let pool = connect(&url).await.expect("the schema must be reachable");
    Some((pool, url))
}

fn cipher(seed: u8) -> ValueCipher {
    ValueCipher::new(&mut [seed; 32])
}

fn config(url: &str, seed: u8) -> MigrateConfig {
    MigrateConfig {
        database_url: url.to_owned(),
        identity_provider: "test-provider",
        external_setup: ExternalSetup::None,
        value_cipher: cipher(seed),
    }
}

fn classification(error: &anyhow::Error) -> Option<&'static str> {
    sovereign_config_telemetry::error::classification(error.as_ref())
}

async fn applied_migrations(pool: &PgPool) -> Vec<(i64, Vec<u8>)> {
    sqlx::query_as("SELECT version, checksum FROM _sqlx_migrations ORDER BY version")
        .fetch_all(pool)
        .await
        .unwrap()
}

async fn secrets(pool: &PgPool) -> Vec<(i64, String)> {
    sqlx::query_as(
        "SELECT id, value FROM configuration_value_contents WHERE classification = 'secret' \
         ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn seed_plaintext_secret(pool: &PgPool, path: &str, value: &str) {
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

/// The server refuses a database with pending migrations, naming `migrate`,
/// and starts on one that also carries migrations it does not know: that is
/// a rollback to this release from a newer one.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn the_server_refuses_pending_migrations_and_tolerates_unknown_ones() {
    let Some((pool, _)) = empty_schema("migrate_verify_schema").await else {
        return;
    };

    let refused = verify_schema(&pool).await.unwrap_err();
    assert_eq!(classification(&refused), Some("migration_pending"));
    let message = format!("{refused:#}");
    assert_eq!(
        message,
        format!(
            "the database schema is not current ({} migrations pending); run \
             `sovereign-config-server migrate` before starting the server",
            MIGRATOR.iter().count()
        )
    );

    assert_eq!(apply_schema(&pool).await.unwrap(), MIGRATOR.iter().count());
    verify_schema(&pool)
        .await
        .expect("a migrated database passes");

    // What a newer release's `migrate` leaves behind.
    sqlx::query(
        "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) \
         VALUES (999999, 'from a newer release', TRUE, '\\x00', 0)",
    )
    .execute(&pool)
    .await
    .unwrap();
    verify_schema(&pool)
        .await
        .expect("an unknown applied migration is a rollback, and tolerated");
    // And this release's `migrate`, run again as the rollback's deploy runs
    // it, applies nothing and refuses nothing.
    assert_eq!(apply_schema(&pool).await.unwrap(), 0);

    // A migration this release carries, applied by someone else's build.
    sqlx::query("UPDATE _sqlx_migrations SET checksum = '\\x00' WHERE version = 1")
        .execute(&pool)
        .await
        .unwrap();
    let diverged = verify_schema(&pool).await.unwrap_err();
    assert_eq!(classification(&diverged), Some("migration_diverged"));
    pool.close().await;
}

/// Running `migrate` twice against current state changes nothing: the
/// schema, the identity claim and the sealed secrets are exactly as the
/// first run left them. The first run sealed the plaintext it found.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn migrate_twice_changes_nothing_the_second_time() {
    let Some((pool, url)) = empty_schema("migrate_twice").await else {
        return;
    };
    apply_schema(&pool).await.unwrap();
    seed_plaintext_secret(&pool, "/tests/migrate/legacy", "legacy-secret").await;

    run(config(&url, 0x5A)).await.expect("the first run");
    let schema = applied_migrations(&pool).await;
    let sealed = secrets(&pool).await;
    assert_eq!(sealed.len(), 1);
    assert!(sealed[0].1.starts_with("enc:v1:"), "the first run seals");

    run(config(&url, 0x5A)).await.expect("the second run");
    assert_eq!(applied_migrations(&pool).await, schema);
    assert_eq!(secrets(&pool).await, sealed);
    let recorded: Vec<String> = sqlx::query_scalar("SELECT name FROM identity_provider")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(recorded, ["test-provider"]);

    // The state `migrate` leaves is the state the server accepts.
    verify_schema(&pool).await.unwrap();
    identity::verify_deployment(&pool, "test-provider")
        .await
        .unwrap();
    verify_stored_secrets(&pool, &cipher(0x5A)).await.unwrap();
    pool.close().await;
}

/// A key that opens none of the sealed secrets stops `migrate` before it
/// seals anything more, and stops the server from serving.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn the_wrong_key_stops_both_migrate_and_the_server() {
    let Some((pool, url)) = empty_schema("migrate_wrong_key").await else {
        return;
    };
    apply_schema(&pool).await.unwrap();
    seed_plaintext_secret(&pool, "/tests/migrate/sealed", "sealed-secret").await;
    run(config(&url, 0x5A)).await.unwrap();
    seed_plaintext_secret(&pool, "/tests/migrate/later", "later-secret").await;
    let before = secrets(&pool).await;

    let refused = run(config(&url, 0x11)).await.unwrap_err();
    assert_eq!(classification(&refused), Some("wrong_key"));
    assert!(
        format!("{refused:#}").starts_with("migrate step `reseal` failed: "),
        "{refused:#}"
    );
    assert_eq!(secrets(&pool).await, before, "nothing is half-converted");

    // The server checks with the right key first: the plaintext row is
    // `migrate`'s to seal, not the server's to serve.
    let unsealed = verify_stored_secrets(&pool, &cipher(0x5A))
        .await
        .unwrap_err();
    assert_eq!(classification(&unsealed), Some("unsealed_secrets"));
    assert_eq!(
        format!("{unsealed:#}"),
        "1 stored configuration secrets are not encrypted yet; run \
         `sovereign-config-server migrate` before starting the server"
    );
    run(config(&url, 0x5A)).await.unwrap();
    let wrong = verify_stored_secrets(&pool, &cipher(0x11))
        .await
        .unwrap_err();
    assert_eq!(classification(&wrong), Some("wrong_key"));
    verify_stored_secrets(&pool, &cipher(0x5A)).await.unwrap();
    pool.close().await;
}

/// A database no `migrate` has claimed is refused by the server, which never
/// claims it itself.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn the_server_refuses_an_unclaimed_deployment() {
    let Some((pool, _)) = empty_schema("migrate_unclaimed").await else {
        return;
    };
    apply_schema(&pool).await.unwrap();

    let refused = identity::verify_deployment(&pool, "test-provider")
        .await
        .unwrap_err();
    assert_eq!(classification(&refused), Some("unclaimed"));
    let recorded: Vec<String> = sqlx::query_scalar("SELECT name FROM identity_provider")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert!(recorded.is_empty(), "the check wrote nothing");

    identity::claim_deployment(&pool, "test-provider")
        .await
        .unwrap();
    identity::verify_deployment(&pool, "test-provider")
        .await
        .unwrap();
    let other = identity::verify_deployment(&pool, "other")
        .await
        .unwrap_err();
    assert_eq!(classification(&other), Some("provider_mismatch"));
    pool.close().await;
}
