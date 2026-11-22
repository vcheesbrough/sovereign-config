use anyhow::Context as _;
use sqlx::PgPool;
use tracing::{error, info};

use super::SECRET;
use super::store::{StoredSecretRow, lock_encryption_pass, reseal_secret, stored_secrets};
use crate::encryption::{ValueCipher, is_envelope};

/// Brings every stored secret up to the current encrypted representation:
/// `migrate`'s stored-data step (`crate::migrate`).
///
/// Runs after the schema step, because encrypting is something only this
/// binary can do — a SQL migration has no access to the key. Rows already
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
///
/// Returns how many rows it sealed. The step's span is `migrate`'s.
pub(crate) async fn encrypt_stored_secrets(
    database: &PgPool,
    cipher: &ValueCipher,
) -> anyhow::Result<usize> {
    let mut transaction = database
        .begin()
        .await
        .context("unable to begin the configuration secret encryption pass")?;
    // Replicas start concurrently, and two of them rewriting the same row would
    // race. The lock is held for the transaction, so it is released either way.
    //
    // It excludes other encryption passes, not live traffic, and from #615
    // the pass runs while the previous release still serves. That is safe
    // only because a serving release never writes plaintext: every release
    // since encryption seals on write, so the rows this pass rewrites are
    // ones no live writer produces. A `put_value` landing between the SELECT
    // below and its UPDATE on such a row would be overwritten by the sealed
    // older value; were plaintext writers ever to serve again, locking the
    // rows (`FOR UPDATE`) is the fix.
    lock_encryption_pass(&mut transaction)
        .await
        .context("unable to lock configuration secrets for encryption")?;

    let stored = stored_secrets(&mut transaction)
        .await
        .context("unable to read configuration secrets for encryption")?;

    let mut encrypted = 0usize;
    let survey = survey(&stored, cipher);
    for row in stored.iter().filter(|row| !is_envelope(&row.value)) {
        let sealed = cipher
            .encrypt(row.id, SECRET, &row.value)
            .map_err(|error| anyhow::anyhow!("configuration secret {}: {error}", row.id))?;
        // `updated_at` deliberately stays put: how a value is stored changed,
        // the value itself did not, and moving the timestamp would misreport a
        // rotation to every client watching it.
        reseal_secret(&mut transaction, row.id, &sealed)
            .await
            .context("unable to encrypt a stored configuration secret")?;
        encrypted += 1;
    }

    // Nothing is committed on failure: the rows encrypted above roll back
    // with the transaction, so a mistaken key cannot half-convert the
    // database.
    survey.refuse_wrong_key()?;

    transaction
        .commit()
        .await
        .context("unable to commit encrypted configuration secrets")?;
    if encrypted > 0 {
        info!(count = encrypted, "encrypted stored configuration secrets");
    }
    survey.report_unreadable();
    Ok(encrypted)
}

/// The server's half of the stored-data step: it checks, and changes nothing.
///
/// The server never serves under the wrong key (#615 keeps the rule the pass
/// above applies), and never with a secret still in plaintext, which would
/// mean `migrate` has not run for this release. Damaged rows among healthy
/// ones are reported and tolerated, exactly as the pass tolerates them.
///
/// # Errors
///
/// The rows cannot be read, a secret is still in plaintext, or the key opens
/// none of them.
pub(crate) async fn verify_stored_secrets(
    database: &PgPool,
    cipher: &ValueCipher,
) -> anyhow::Result<()> {
    // A transaction only because the store's reads take one; nothing is
    // written, and it is rolled back on drop.
    let mut transaction = database
        .begin()
        .await
        .context("unable to read configuration secrets")?;
    let stored = stored_secrets(&mut transaction)
        .await
        .context("unable to read configuration secrets")?;
    drop(transaction);
    let survey = survey(&stored, cipher);
    if survey.plaintext > 0 {
        return Err(crate::spans::classified(
            "unsealed_secrets",
            format!(
                "{} stored configuration secrets are not encrypted yet; \
                 run `sovereign-config-server migrate` before starting the server",
                survey.plaintext
            ),
        ));
    }
    survey.refuse_wrong_key()?;
    survey.report_unreadable();
    Ok(())
}

/// What the stored secrets look like under `cipher`.
struct Survey {
    plaintext: usize,
    sealed: usize,
    unreadable: Vec<i64>,
}

fn survey(stored: &[StoredSecretRow], cipher: &ValueCipher) -> Survey {
    let mut survey = Survey {
        plaintext: 0,
        sealed: 0,
        unreadable: Vec::new(),
    };
    for row in stored {
        if !is_envelope(&row.value) {
            survey.plaintext += 1;
            continue;
        }
        survey.sealed += 1;
        if let Err(error) = cipher.decrypt(row.id, SECRET, &row.value) {
            error!(
                content_id = row.id,
                reason = %error,
                "stored configuration secret is unreadable"
            );
            survey.unreadable.push(row.id);
        }
    }
    survey
}

impl Survey {
    fn refuse_wrong_key(&self) -> anyhow::Result<()> {
        if wrong_key(self.unreadable.len(), self.sealed) {
            return Err(crate::spans::classified(
                "wrong_key",
                format!(
                    "every stored configuration secret is unreadable ({} rows); \
                     the configured value encryption key does not match this database",
                    self.sealed
                ),
            ));
        }
        Ok(())
    }

    fn report_unreadable(&self) {
        if !self.unreadable.is_empty() {
            error!(
                count = self.unreadable.len(),
                content_ids = ?self.unreadable,
                "some stored configuration secrets are unreadable and will fail when revealed; \
                 every other value is unaffected"
            );
        }
    }
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
