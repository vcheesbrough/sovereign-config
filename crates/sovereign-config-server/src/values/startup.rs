use anyhow::Context as _;
use sqlx::{FromRow, PgPool};
use tracing::{error, info};

use super::SECRET;
use crate::encryption::{ValueCipher, is_envelope};

#[derive(FromRow)]
struct StoredSecretRow {
    id: i64,
    value: String,
}

/// Brings every stored secret up to the current encrypted representation.
///
/// Runs at startup, after migrations, because encrypting is something only the
/// server can do — a SQL migration has no access to the key. Rows already
/// sealed are verified and left alone, so a second run changes nothing; rows
/// still in plaintext, written before this server encrypted anything, are
/// sealed in place. Running on every start rather than once behind a marker
/// also repairs a deployment that was rolled back, wrote plaintext, and rolled
/// forward again.
///
/// Rows that will not open are judged together rather than one at a time,
/// because the same symptom has two very different causes. If *every* sealed
/// row fails, the key does not match this database: startup aborts, since
/// running on would mean serving errors for secrets that are perfectly intact
/// under the right key — or, worse, sealing a second layer over them. If only
/// some fail among healthy ones, that is damage to those rows — a torn write, a
/// partial restore — and taking the whole service down with them would deny
/// every `plain` value too, none of which needs a key at all. Those rows are
/// logged and left exactly as found, and [`ConfigurationService::reveal_secret`]
/// still fails closed for their paths.
pub(crate) async fn encrypt_stored_secrets(
    database: &PgPool,
    cipher: &ValueCipher,
) -> anyhow::Result<()> {
    let mut transaction = database
        .begin()
        .await
        .context("unable to begin the configuration secret encryption pass")?;
    // Replicas start concurrently, and two of them rewriting the same row would
    // race. The lock is held for the transaction, so it is released either way.
    //
    // It excludes other encryption passes, not live traffic: this assumes no
    // other instance is already serving. The deployment runs one container, so
    // the pass completes before anything can write. Anyone adding a replica or
    // a rolling deploy must revisit this — a `put_value` landing between the
    // SELECT below and its UPDATE would be overwritten by the sealed older
    // value. Locking the rows (`FOR UPDATE`) is the fix at that point.
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('sovereign-config:encrypt-stored-secrets', 0))",
    )
    .execute(&mut *transaction)
    .await
    .context("unable to lock configuration secrets for encryption")?;

    let stored = sqlx::query_as::<_, StoredSecretRow>(
        r"
        SELECT id, value
        FROM configuration_value_contents
        WHERE classification = 'secret'
        ORDER BY id
        ",
    )
    .fetch_all(&mut *transaction)
    .await
    .context("unable to read configuration secrets for encryption")?;

    let mut encrypted = 0usize;
    let mut sealed_on_entry = 0usize;
    let mut unreadable = Vec::new();
    for row in stored {
        if is_envelope(&row.value) {
            sealed_on_entry += 1;
            if let Err(error) = cipher.decrypt(row.id, SECRET, &row.value) {
                error!(
                    content_id = row.id,
                    reason = %error,
                    "stored configuration secret is unreadable"
                );
                unreadable.push(row.id);
            }
            continue;
        }
        let sealed = cipher
            .encrypt(row.id, SECRET, &row.value)
            .map_err(|error| anyhow::anyhow!("configuration secret {}: {error}", row.id))?;
        // `updated_at` deliberately stays put: how a value is stored changed,
        // the value itself did not, and moving the timestamp would misreport a
        // rotation to every client watching it.
        sqlx::query("UPDATE configuration_value_contents SET value = $2 WHERE id = $1")
            .bind(row.id)
            .bind(&sealed)
            .execute(&mut *transaction)
            .await
            .context("unable to encrypt a stored configuration secret")?;
        encrypted += 1;
    }

    if wrong_key(unreadable.len(), sealed_on_entry) {
        // Nothing is committed: the rows encrypted above roll back with the
        // transaction, so a mistaken key cannot half-convert the database.
        anyhow::bail!(
            "every stored configuration secret is unreadable ({sealed_on_entry} rows); \
             the configured value encryption key does not match this database"
        );
    }

    transaction
        .commit()
        .await
        .context("unable to commit encrypted configuration secrets")?;
    if encrypted > 0 {
        info!(count = encrypted, "encrypted stored configuration secrets");
    }
    if !unreadable.is_empty() {
        error!(
            count = unreadable.len(),
            content_ids = ?unreadable,
            "some stored configuration secrets are unreadable and will fail when revealed; \
             every other value is unaffected"
        );
    }
    Ok(())
}

/// Decides whether unreadable secrets mean the key is wrong or the rows are.
///
/// Every sealed row failing points at the key, because one key opens all of
/// them. A mix means the key is right and those particular rows are damaged.
///
/// The two are genuinely indistinguishable when the database holds exactly one
/// sealed secret and it fails, so that case is treated as the wrong key: a
/// server that refuses to start is easier to diagnose and safer than one
/// quietly serving a secret it cannot read.
pub(super) fn wrong_key(unreadable: usize, sealed_on_entry: usize) -> bool {
    unreadable > 0 && unreadable == sealed_on_entry
}
