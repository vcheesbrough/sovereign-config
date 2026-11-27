//! `sovereign-config-server migrate`: everything a release changes outside
//! its image, run as a one-shot step before the server is replaced (#615,
//! the `migrations` skill).
//!
//! The steps run in this order, each idempotent, each its own root span:
//!
//! 1. **`schema`** — the SQL migrations embedded in the binary. Applied
//!    migrations this binary does not know are tolerated: that is a rollback
//!    to an older image, and nothing is ever un-applied.
//! 2. **`runtime_role`** — the login the server connects with is created,
//!    or brought back to its exact attributes and grants (`runtime_role`,
//!    #616). The owner login every step runs as stays with `migrate`.
//! 3. **`identity_claim`** — the deployment's identity provider is recorded
//!    the first time, and any other refused (`identity::claim_deployment`).
//! 4. **`reseal`** — every stored secret is brought up to the current
//!    encrypted representation (`values::encrypt_stored_secrets`), and a key
//!    that opens none of them aborts.
//! 5. **`identity_provider`** — what the release configures in the identity
//!    provider itself (`identity::ExternalSetup`), which the provider's crate
//!    describes.
//! 6. **`runtime_password`** — the runtime login gets the password
//!    `migrate` was given, if it has another. Last, so a `migrate` failing
//!    at any step above leaves the running server's password working.
//!
//! The server applies none of this. At startup it checks that each step has
//! run ([`verify_schema`], `identity::verify_deployment`,
//! `values::verify_stored_secrets`) and refuses to serve otherwise. Every
//! migration must work with the release before it, because `migrate` runs
//! while that release still serves.

use std::time::Duration;

use anyhow::{Context, Result};
use sqlx::{PgPool, migrate::Migrator, postgres::PgPoolOptions};
use tracing::info;

use crate::config::MigrateConfig;
use crate::spans::{classified, in_root_span};
use crate::{identity, values};

pub(crate) mod runtime_role;

/// The migrations this binary carries.
static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// A step's root span: `sovereign_config.migrate.<step>`.
macro_rules! step_span {
    ($step:literal) => {
        tracing::info_span!(
            parent: None,
            concat!("sovereign_config.migrate.", $step),
            otel.kind = "internal",
            otel.status_code = tracing::field::Empty,
            error.type = tracing::field::Empty,
        )
    };
}

/// Runs every step in order, stopping at the first that fails.
///
/// # Errors
///
/// A step fails; the steps after it do not run.
pub(crate) async fn run(config: MigrateConfig) -> Result<()> {
    let database = in_root_span(step_span!("schema"), "schema_failed", async {
        let database = connect(&config.database_url).await?;
        let applied = apply_schema(&database).await?;
        info!(applied, "schema is current");
        Ok(database)
    })
    .await
    .context("migrate step `schema` failed")?;
    in_root_span(step_span!("runtime_role"), "runtime_role_failed", async {
        runtime_role::ensure(&database, &config.runtime_login).await?;
        Ok(())
    })
    .await
    .context("migrate step `runtime_role` failed")?;
    in_root_span(
        step_span!("identity_claim"),
        "identity_claim_failed",
        identity::claim_deployment(&database, config.identity_provider),
    )
    .await
    .context("migrate step `identity_claim` failed")?;
    in_root_span(
        step_span!("reseal"),
        "reseal_failed",
        values::encrypt_stored_secrets(&database, &config.value_cipher),
    )
    .await
    .context("migrate step `reseal` failed")?;
    in_root_span(
        step_span!("identity_provider"),
        "identity_provider_failed",
        config.external_setup.apply(),
    )
    .await
    .context("migrate step `identity_provider` failed")?;
    // Last, so a failure anywhere above leaves the running server's password
    // working.
    in_root_span(
        step_span!("runtime_password"),
        "runtime_password_failed",
        async {
            runtime_role::set_password(&database, &config.runtime_login).await?;
            Ok(())
        },
    )
    .await
    .context("migrate step `runtime_password` failed")?;
    database.close().await;
    info!("migrations complete");
    Ok(())
}

/// Connects to the required `PostgreSQL` dependency, never quoting the URL.
pub(crate) async fn connect(database_url: &str) -> Result<PgPool> {
    PgPoolOptions::new()
        .acquire_timeout(Duration::from_secs(5))
        .connect(database_url)
        .await
        .map_err(|_| {
            classified(
                "unavailable",
                "unable to connect to required PostgreSQL dependency",
            )
        })
}

/// Applies every pending migration and returns how many there were.
async fn apply_schema(database: &PgPool) -> Result<usize> {
    let pending = schema_status(database).await?.pending;
    let mut migrator = sqlx::migrate!("./migrations");
    // A database migrated by a newer release: this binary is the rollback.
    migrator.set_ignore_missing(true);
    migrator.run(database).await.map_err(|error| {
        classified(
            "migration_failed",
            format!("database migration failed: {error}"),
        )
    })?;
    Ok(pending)
}

/// How the database's applied migrations compare with this binary's.
struct SchemaStatus {
    /// Embedded and not applied.
    pending: usize,
    /// Applied, but under a different checksum, or left failed.
    diverged: usize,
}

async fn schema_status(database: &PgPool) -> Result<SchemaStatus> {
    let unavailable = |_| {
        classified(
            "unavailable",
            "unable to read the database's applied migrations",
        )
    };
    // Where sqlx creates the table: the first schema on the search path.
    let tracked: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_tables \
         WHERE schemaname = current_schema() AND tablename = '_sqlx_migrations')",
    )
    .fetch_one(database)
    .await
    .map_err(unavailable)?;
    let applied: Vec<(i64, Vec<u8>, bool)> = if tracked {
        sqlx::query_as("SELECT version, checksum, success FROM _sqlx_migrations")
            .fetch_all(database)
            .await
            .map_err(unavailable)?
    } else {
        Vec::new()
    };
    let mut status = SchemaStatus {
        pending: 0,
        diverged: 0,
    };
    for migration in MIGRATOR
        .iter()
        .filter(|migration| !migration.migration_type.is_down_migration())
    {
        match applied
            .iter()
            .find(|(version, _, _)| *version == migration.version)
        {
            None => status.pending += 1,
            Some((_, checksum, success)) => {
                if !success || checksum.as_slice() != &*migration.checksum {
                    status.diverged += 1;
                }
            }
        }
    }
    Ok(status)
}

/// The server's half of the schema step: every migration this binary embeds
/// is applied, unchanged. Applied migrations it does not know are a rollback
/// and are tolerated. It changes nothing.
///
/// # Errors
///
/// The database cannot be read, a migration is pending, or one was applied
/// under a different checksum or left failed.
pub(crate) async fn verify_schema(database: &PgPool) -> Result<()> {
    let status = schema_status(database).await?;
    if status.diverged > 0 {
        return Err(classified(
            "migration_diverged",
            format!(
                "{} applied migrations differ from the ones this release carries; \
                 the database was migrated by another build",
                status.diverged
            ),
        ));
    }
    if status.pending > 0 {
        return Err(classified(
            "migration_pending",
            format!(
                "the database schema is not current ({} migrations pending); \
                 run `sovereign-config-server migrate` before starting the server",
                status.pending
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
