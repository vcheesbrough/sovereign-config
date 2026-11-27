//! `migrate` and the server's checks of it, against `PostgreSQL`.
//!
//! Each test works in a schema of its own on the search path, so a fresh,
//! empty database is cheap and the shared test database is never left
//! half-migrated.

use sqlx::{Connection as _, PgConnection, PgPool};

use super::runtime_role::{self, PasswordChange, RoleChange, RuntimeLogin};
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

/// The runtime login the tests that do not look at it share. Roles are
/// cluster-wide, so a test that does gets one of its own.
const SHARED_ROLE: &str = "sc_test_migrate_runtime";
const RUNTIME_PASSWORD: &str = "runtime-password-for-tests";

fn config(url: &str, seed: u8) -> MigrateConfig {
    config_for(url, seed, SHARED_ROLE)
}

fn config_for(url: &str, seed: u8, role: &str) -> MigrateConfig {
    MigrateConfig {
        database_url: url.to_owned(),
        runtime_login: RuntimeLogin::named(role, RUNTIME_PASSWORD.to_owned()).unwrap(),
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

    let role = runtime_state(&pool, SHARED_ROLE).await;
    run(config(&url, 0x5A)).await.expect("the second run");
    assert_eq!(applied_migrations(&pool).await, schema);
    assert_eq!(secrets(&pool).await, sealed);
    assert_eq!(
        runtime_state(&pool, SHARED_ROLE).await,
        role,
        "the runtime role, its password's salt and its grants are as the first run left them"
    );
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

/// The runtime role's stored password verifier and attributes, the grants on
/// every table and sequence in the schema, and the schema's default
/// privileges: everything the `runtime_role` step writes.
async fn runtime_state(pool: &PgPool, role: &str) -> Vec<String> {
    sqlx::query_scalar(
        r"
        SELECT format('%s %s %s %s %s %s %s', rolname, rolpassword, rolsuper, rolcreatedb,
                      rolcreaterole, rolinherit, rolcanlogin)
        FROM pg_authid WHERE rolname = $1
        UNION ALL
        SELECT format('%s %s', relname, relacl::TEXT) FROM pg_class
        WHERE relnamespace = current_schema()::regnamespace AND relkind IN ('r', 'S')
        UNION ALL
        SELECT format('default %s %s', defaclobjtype, defaclacl::TEXT) FROM pg_default_acl
        WHERE defaclnamespace = current_schema()::regnamespace
        ORDER BY 1
        ",
    )
    .bind(role)
    .fetch_all(pool)
    .await
    .unwrap()
}

/// `url` logged in as `role` with `password` instead, its search path kept.
fn login_url(url: &str, role: &str, password: &str) -> String {
    let mut url = reqwest::Url::parse(url).expect("the test URL parses");
    url.set_username(role).unwrap();
    url.set_password(Some(password)).unwrap();
    url.to_string()
}

/// The SQLSTATE a statement failed with, or `None` if it succeeded.
async fn sqlstate(pool: &PgPool, statement: &str) -> Option<String> {
    match sqlx::raw_sql(statement).execute(pool).await {
        Ok(_) => None,
        Err(sqlx::Error::Database(error)) => Some(error.code().unwrap_or_default().into_owned()),
        Err(other) => panic!("{statement}: {other}"),
    }
}

/// The server's login can read and write every row and pass every startup
/// check, and cannot create, alter, drop or truncate anything, nor touch the
/// migration record, nor become the owner.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn the_runtime_login_writes_rows_and_cannot_change_the_schema() {
    const ROLE: &str = "sc_test_runtime_confined";
    let Some((pool, url)) = empty_schema("migrate_runtime_confined").await else {
        return;
    };
    run(config_for(&url, 0x5A, ROLE)).await.unwrap();
    let owner: String = sqlx::query_scalar("SELECT current_user::TEXT")
        .fetch_one(&pool)
        .await
        .unwrap();
    let runtime = connect(&login_url(&url, ROLE, RUNTIME_PASSWORD))
        .await
        .expect("the runtime login connects with the password migrate was given");

    // What the server checks before it serves, on its own login.
    verify_schema(&runtime).await.unwrap();
    identity::verify_deployment(&runtime, "test-provider")
        .await
        .unwrap();
    verify_stored_secrets(&runtime, &cipher(0x5A))
        .await
        .unwrap();

    // Rows, through every privilege it holds, sequences included.
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO configuration_value_contents (value, classification, created_at, updated_at) \
         VALUES ('v', 'plain', NOW(), NOW()) RETURNING id",
    )
    .fetch_one(&runtime)
    .await
    .unwrap();
    sqlx::query("UPDATE configuration_value_contents SET value = 'w' WHERE id = $1")
        .bind(id)
        .execute(&runtime)
        .await
        .unwrap();
    let value: String =
        sqlx::query_scalar("SELECT value FROM configuration_value_contents WHERE id = $1")
            .bind(id)
            .fetch_one(&runtime)
            .await
            .unwrap();
    assert_eq!(value, "w");
    sqlx::query("DELETE FROM configuration_value_contents WHERE id = $1")
        .bind(id)
        .execute(&runtime)
        .await
        .unwrap();

    for statement in [
        "CREATE TABLE intruder (id BIGINT)".to_owned(),
        "CREATE INDEX intruder ON configuration_paths (path)".to_owned(),
        "CREATE SCHEMA intruder".to_owned(),
        "CREATE ROLE intruder".to_owned(),
        "ALTER TABLE configuration_paths ADD COLUMN intruder TEXT".to_owned(),
        "ALTER TABLE configuration_paths RENAME TO intruder".to_owned(),
        "DROP TABLE configuration_paths".to_owned(),
        "DROP TABLE _sqlx_migrations".to_owned(),
        "TRUNCATE configuration_paths".to_owned(),
        "TRUNCATE audit_events".to_owned(),
        "DELETE FROM _sqlx_migrations".to_owned(),
        "UPDATE _sqlx_migrations SET success = FALSE".to_owned(),
        "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) \
         VALUES (999999, 'intruder', TRUE, '\\x00', 0)"
            .to_owned(),
        format!("SET ROLE \"{owner}\""),
    ] {
        assert_eq!(
            sqlstate(&runtime, &statement).await.as_deref(),
            Some("42501"),
            "the runtime login must be refused: {statement}"
        );
    }
    runtime.close().await;
    pool.close().await;
}

/// A table a later migration adds is the runtime login's to read and write
/// the moment the owner creates it, with no grant of its own and no second
/// run of `migrate`: the schema's default privileges carry it. It is still
/// not the runtime login's to drop.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn a_table_a_later_migration_adds_needs_no_grant() {
    const ROLE: &str = "sc_test_runtime_later_table";
    let Some((pool, url)) = empty_schema("migrate_runtime_later_table").await else {
        return;
    };
    run(config_for(&url, 0x5A, ROLE)).await.unwrap();
    // What a later release's migration does, as the owner `migrate` is.
    sqlx::raw_sql("CREATE TABLE later_feature (id BIGSERIAL PRIMARY KEY, note TEXT NOT NULL)")
        .execute(&pool)
        .await
        .unwrap();

    let runtime = connect(&login_url(&url, ROLE, RUNTIME_PASSWORD))
        .await
        .unwrap();
    let id: i64 =
        sqlx::query_scalar("INSERT INTO later_feature (note) VALUES ('first') RETURNING id")
            .fetch_one(&runtime)
            .await
            .expect("insert, and the new sequence");
    sqlx::query("UPDATE later_feature SET note = 'second' WHERE id = $1")
        .bind(id)
        .execute(&runtime)
        .await
        .unwrap();
    let note: String = sqlx::query_scalar("SELECT note FROM later_feature WHERE id = $1")
        .bind(id)
        .fetch_one(&runtime)
        .await
        .unwrap();
    assert_eq!(note, "second");
    sqlx::query("DELETE FROM later_feature")
        .execute(&runtime)
        .await
        .unwrap();
    for statement in ["DROP TABLE later_feature", "TRUNCATE later_feature"] {
        assert_eq!(
            sqlstate(&runtime, statement).await.as_deref(),
            Some("42501"),
            "{statement}"
        );
    }
    runtime.close().await;
    pool.close().await;
}

/// A password set by Postgres itself is recognised, so `migrate` leaves it
/// alone; a new one replaces it, and only the new one logs in. That is how
/// the runtime password is rotated: change the secret and redeploy.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn the_runtime_password_is_kept_when_current_and_rotated_when_not() {
    const ROLE: &str = "sc_test_runtime_rotation";
    let Some((pool, url)) = empty_schema("migrate_runtime_rotation").await else {
        return;
    };
    apply_schema(&pool).await.unwrap();
    let login = |password: &str| RuntimeLogin::named(ROLE, password.to_owned()).unwrap();
    // Created, or left from an earlier run of this test: roles outlive the
    // schemas they were granted in.
    runtime_role::ensure(&pool, &login("first-password"))
        .await
        .unwrap();

    // An existing role keeps its password through `ensure`: the running
    // server may be using it.
    sqlx::raw_sql(&format!("ALTER ROLE {ROLE} PASSWORD 'set-by-postgres'"))
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        runtime_role::ensure(&pool, &login("rotated-password"))
            .await
            .unwrap(),
        RoleChange::Existing
    );
    // PostgreSQL's own verifier, from a plaintext password, is recognised.
    assert_eq!(
        runtime_role::set_password(&pool, &login("set-by-postgres"))
            .await
            .unwrap(),
        PasswordChange::Unchanged
    );
    assert_eq!(
        runtime_role::set_password(&pool, &login("rotated-password"))
            .await
            .unwrap(),
        PasswordChange::Set
    );
    assert_eq!(
        runtime_role::set_password(&pool, &login("rotated-password"))
            .await
            .unwrap(),
        PasswordChange::Unchanged
    );
    assert!(
        connect(&login_url(&url, ROLE, "set-by-postgres"))
            .await
            .is_err(),
        "the old password no longer logs in"
    );
    connect(&login_url(&url, ROLE, "rotated-password"))
        .await
        .expect("the new one does")
        .close()
        .await;
    pool.close().await;
}

/// Whatever was done to the runtime role by hand, the next `migrate` puts
/// back: its attributes, its grants, its default privileges, and `CREATE`
/// on the schema. A membership in another role, or an object it owns, it
/// refuses rather than dismantles.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn migrate_restores_a_widened_runtime_role_and_refuses_what_it_cannot() {
    const ROLE: &str = "sc_test_runtime_widened";
    const SCHEMA: &str = "migrate_runtime_widened";
    const GROUP: &str = "sc_test_runtime_widened_group";
    let Some((pool, url)) = empty_schema(SCHEMA).await else {
        return;
    };
    run(config_for(&url, 0x5A, ROLE)).await.unwrap();
    let current = runtime_state(&pool, ROLE).await;
    for widening in [
        format!("ALTER ROLE {ROLE} CREATEDB CREATEROLE INHERIT"),
        format!("GRANT TRUNCATE, TRIGGER, REFERENCES ON ALL TABLES IN SCHEMA {SCHEMA} TO {ROLE}"),
        format!("GRANT INSERT, DELETE ON {SCHEMA}._sqlx_migrations TO {ROLE}"),
        format!("GRANT UPDATE ON ALL SEQUENCES IN SCHEMA {SCHEMA} TO {ROLE}"),
        format!("ALTER DEFAULT PRIVILEGES IN SCHEMA {SCHEMA} GRANT ALL ON TABLES TO {ROLE}"),
        format!("ALTER DEFAULT PRIVILEGES IN SCHEMA {SCHEMA} GRANT ALL ON SEQUENCES TO {ROLE}"),
    ] {
        sqlx::raw_sql(&widening).execute(&pool).await.unwrap();
    }
    assert_ne!(runtime_state(&pool, ROLE).await, current);
    run(config_for(&url, 0x5A, ROLE)).await.unwrap();
    assert_eq!(runtime_state(&pool, ROLE).await, current);

    // `CREATE` on the schema through `PUBLIC`, as a cluster first
    // initialised before PostgreSQL 15 keeps it: taken back.
    sqlx::raw_sql(&format!(
        "GRANT CREATE ON SCHEMA {SCHEMA} TO PUBLIC; \
         GRANT CREATE ON SCHEMA {SCHEMA} TO {ROLE}"
    ))
    .execute(&pool)
    .await
    .unwrap();
    run(config_for(&url, 0x5A, ROLE)).await.unwrap();
    let creates: bool = sqlx::query_scalar("SELECT has_schema_privilege($1, $2, 'CREATE')")
        .bind(ROLE)
        .bind(SCHEMA)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        !creates,
        "the runtime role can no longer create in the schema"
    );

    // A role it could act as is not `migrate`'s to dismantle: refused.
    sqlx::raw_sql(&format!(
        "DO $$ BEGIN CREATE ROLE {GROUP}; EXCEPTION WHEN duplicate_object THEN NULL; END $$; \
         GRANT {GROUP} TO {ROLE}"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let refused = run(config_for(&url, 0x5A, ROLE)).await.unwrap_err();
    assert_eq!(classification(&refused), Some("runtime_role_is_member"));
    assert!(
        format!("{refused:#}").starts_with("migrate step `runtime_role` failed: "),
        "{refused:#}"
    );
    sqlx::raw_sql(&format!("REVOKE {GROUP} FROM {ROLE}"))
        .execute(&pool)
        .await
        .unwrap();
    run(config_for(&url, 0x5A, ROLE)).await.unwrap();

    // Nor is an object it owns, which it could drop whatever it was granted.
    sqlx::raw_sql(&format!(
        "CREATE TABLE {SCHEMA}.handed_over (id BIGINT); \
         ALTER TABLE {SCHEMA}.handed_over OWNER TO {ROLE}"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let refused = run(config_for(&url, 0x5A, ROLE)).await.unwrap_err();
    assert_eq!(classification(&refused), Some("runtime_role_owns"));
    sqlx::raw_sql(&format!("DROP TABLE {SCHEMA}.handed_over"))
        .execute(&pool)
        .await
        .unwrap();
    run(config_for(&url, 0x5A, ROLE)).await.unwrap();
    assert_eq!(runtime_state(&pool, ROLE).await, current);

    // The owner itself is never made the runtime role.
    let owner: String = sqlx::query_scalar("SELECT current_user::TEXT")
        .fetch_one(&pool)
        .await
        .unwrap();
    let refused = runtime_role::ensure(
        &pool,
        &RuntimeLogin::named(&owner, RUNTIME_PASSWORD.to_owned()).unwrap(),
    )
    .await
    .unwrap_err();
    assert_eq!(classification(&refused), Some("runtime_role_is_owner"));
    pool.close().await;
}

/// A `migrate` that fails after `runtime_role` leaves the running server's
/// password working: a rotated one is set only by the last step, once
/// everything before it has succeeded, so the previous release keeps
/// opening connections.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn a_failed_migrate_leaves_the_running_servers_password_working() {
    const ROLE: &str = "sc_test_runtime_failed_rotation";
    let Some((pool, url)) = empty_schema("migrate_runtime_failed_rotation").await else {
        return;
    };
    let rotating = |seed: u8, password: &str| {
        let mut config = config_for(&url, seed, ROLE);
        config.runtime_login = RuntimeLogin::named(ROLE, password.to_owned()).unwrap();
        config
    };
    apply_schema(&pool).await.unwrap();
    seed_plaintext_secret(&pool, "/tests/migrate/rotation", "rotation-secret").await;
    run(rotating(0x5A, "running-password")).await.unwrap();

    // `reseal` refuses the wrong key, after `runtime_role` has run.
    let refused = run(rotating(0x11, "rotated-password")).await.unwrap_err();
    assert_eq!(classification(&refused), Some("wrong_key"));
    connect(&login_url(&url, ROLE, "running-password"))
        .await
        .expect("the running server still logs in")
        .close()
        .await;
    assert!(
        connect(&login_url(&url, ROLE, "rotated-password"))
            .await
            .is_err(),
        "the new password is not set yet"
    );

    run(rotating(0x5A, "rotated-password")).await.unwrap();
    connect(&login_url(&url, ROLE, "rotated-password"))
        .await
        .expect("a successful migrate sets it")
        .close()
        .await;
    pool.close().await;
}
