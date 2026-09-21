//! Every `PostgreSQL` row type and query behind the `Configuration` service.
//! Nothing outside this module writes SQL; callers see typed rows and a
//! bounded `Status` (or, for the startup pass, the raw `sqlx::Error`).
//!
//! Subtree matching uses `starts_with`, never `LIKE`: `_` is a legal path
//! segment character (since 2.15.0) and a single-character `LIKE` wildcard,
//! so `LIKE '/a/b_c/%'` would also match the sibling subtree `/a/bXc/` that
//! authorization never checked. This applies to every prefix match here. Do
//! not "optimize" it back to `LIKE` for the btree prefix scan.

use std::collections::BTreeSet;

use sovereign_config_core::ConfigPath;
use sqlx::{FromRow, PgExecutor, PgPool, Postgres, Transaction};
use time::OffsetDateTime;
use tonic::Status;

use super::paths::parent_path;
use crate::rpc::storage_unavailable;

#[derive(FromRow)]
pub(super) struct ListedValueRow {
    pub(super) path: String,
    pub(super) lowercase_path: String,
    pub(super) content_id: i64,
    pub(super) value: String,
    pub(super) classification: String,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

#[derive(FromRow)]
pub(super) struct SubTreeRow {
    pub(super) path: String,
    pub(super) value: String,
    pub(super) classification: String,
}

/// A row's fold key, selected under the name `path` — the result is only
/// ever an opaque fold-key string (a collision probe, a secret-path set),
/// never anything meant for display.
#[derive(FromRow)]
struct PathRow {
    path: String,
}

#[derive(FromRow)]
pub(super) struct PathWithFoldRow {
    pub(super) path: String,
    pub(super) lowercase_path: String,
}

#[derive(FromRow)]
pub(super) struct RevealedRow {
    pub(super) content_id: i64,
    pub(super) value: String,
    pub(super) classification: String,
}

#[derive(FromRow)]
pub(super) struct PathContentRow {
    pub(super) path: String,
    pub(super) lowercase_path: String,
    pub(super) content_id: i64,
    pub(super) created_at: OffsetDateTime,
}

#[derive(FromRow)]
pub(super) struct PathContentClassRow {
    pub(super) content_id: i64,
    /// The stored representation being overwritten — ciphertext when
    /// `classification` is secret. Selected for the audit trail, which keeps
    /// it only when it is plain.
    pub(super) value: String,
    pub(super) classification: String,
    pub(super) path_count: i64,
}

/// A path row a statement deleted, with the content it pointed at as it stood
/// when it was deleted. `value` and `classification` exist for the audit trail
/// and must be read before orphaned contents are pruned — which they are,
/// because the `DELETE … RETURNING` that produces this row captures them.
#[derive(FromRow)]
pub(super) struct DeletedPathRow {
    pub(super) path: String,
    pub(super) content_id: i64,
    pub(super) value: String,
    pub(super) classification: String,
}

#[derive(FromRow)]
pub(super) struct MutationRow {
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

#[derive(FromRow)]
pub(super) struct StoredSecretRow {
    pub(super) id: i64,
    pub(super) value: String,
}

#[derive(FromRow)]
pub(super) struct ContentRow {
    pub(super) id: i64,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

// True if `path` is an ancestor or descendant of an existing path; values form
// a tree of leaves, so nesting is never allowed.
pub(super) async fn path_collides(
    transaction: &mut Transaction<'_, Postgres>,
    path: &str,
) -> Result<bool, Status> {
    let collision = sqlx::query_scalar::<_, String>(
        r"
        SELECT path
        FROM configuration_paths
        WHERE lowercase_path <> $1
          AND (starts_with(lowercase_path, $1 || '/') OR starts_with($1, lowercase_path || '/'))
        LIMIT 1
        ",
    )
    .bind(path)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| storage_unavailable())?;
    Ok(collision.is_some())
}

/// Claims the identity a new content row will be inserted under.
///
/// A secret's ciphertext is bound to the row that stores it, so the identity
/// has to be known before the value is encrypted — which rules out letting the
/// INSERT generate it. Taking it from the sequence up front means the row is
/// written once, already sealed: no plaintext is ever handed to `PostgreSQL`,
/// not even briefly inside the transaction, where it would still reach the
/// write-ahead log.
pub(super) async fn reserve_content_id(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<i64, Status> {
    sqlx::query_scalar::<_, i64>(
        "SELECT nextval(pg_get_serial_sequence('configuration_value_contents', 'id'))",
    )
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| storage_unavailable())
}

/// Inserts a content row under a previously reserved identity.
///
/// `value` is the stored representation, already encrypted when the
/// classification calls for it — this function does no encoding of its own.
pub(super) async fn insert_content(
    transaction: &mut Transaction<'_, Postgres>,
    content_id: i64,
    value: &str,
    classification: &str,
    now: OffsetDateTime,
) -> Result<ContentRow, Status> {
    sqlx::query_as::<_, ContentRow>(
        r"
        INSERT INTO configuration_value_contents (id, value, classification, created_at, updated_at)
        OVERRIDING SYSTEM VALUE
        VALUES ($1, $2, $3, $4, $4)
        RETURNING id, created_at, updated_at
        ",
    )
    .bind(content_id)
    .bind(value)
    .bind(classification)
    .bind(now)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| storage_unavailable())
}

/// Inserts a path row. `path` is the exact case it was written with;
/// `lowercase_path` is computed by Postgres and must never appear here — the
/// generated column rejects any attempt to write it directly.
pub(super) async fn insert_path(
    transaction: &mut Transaction<'_, Postgres>,
    path: &str,
    content_id: i64,
    now: OffsetDateTime,
) -> Result<(), Status> {
    sqlx::query(
        r"
        INSERT INTO configuration_paths (path, content_id, created_at, updated_at)
        VALUES ($1, $2, $3, $3)
        ",
    )
    .bind(path)
    .bind(content_id)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|_| storage_unavailable())?;
    Ok(())
}

pub(super) fn content_ids(rows: &[DeletedPathRow]) -> Vec<i64> {
    let mut ids = rows.iter().map(|row| row.content_id).collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    ids
}

// Delete any of the given contents that no longer have a path referencing them.
// Runs inline in the mutation transaction so the last path removal is what
// deletes the value — no background reconciliation.
pub(super) async fn prune_orphan_contents(
    transaction: &mut Transaction<'_, Postgres>,
    content_ids: &[i64],
) -> Result<(), Status> {
    if content_ids.is_empty() {
        return Ok(());
    }
    // Path locks do not serialize deletions of aliases under unrelated
    // hierarchies, so two transactions each removing one of a value's last two
    // paths would both still see the other's uncommitted path row and skip
    // pruning, orphaning the content permanently. Lock each affected content
    // first. `content_ids` arrives sorted and deduplicated, so concurrent
    // pruners take these in a common order and cannot deadlock; every path lock
    // in a transaction is already held before any content lock.
    for content_id in content_ids {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('content:' || $1::TEXT, 0))")
            .bind(content_id)
            .execute(&mut **transaction)
            .await
            .map_err(|_| storage_unavailable())?;
    }
    sqlx::query(
        r"
        DELETE FROM configuration_value_contents c
        WHERE c.id = ANY($1::BIGINT[])
          AND NOT EXISTS (
                SELECT 1 FROM configuration_paths p WHERE p.content_id = c.id
              )
        ",
    )
    .bind(content_ids)
    .execute(&mut **transaction)
    .await
    .map_err(|_| storage_unavailable())?;
    Ok(())
}

// Shared ancestor locks and an exclusive target lock form a hierarchy: sibling
// subtrees can proceed together, while identical or parent/descendant mutations
// serialize. A hash collision can only add serialization, never remove it.
pub(super) async fn lock_mutation_path(
    transaction: &mut Transaction<'_, Postgres>,
    path: &ConfigPath,
) -> Result<(), Status> {
    // Locks are hashed by this string, so two concurrent writes to the same
    // fold key — spelled differently — must hash to the same lock or they
    // would never serialize against each other. Always the fold, never
    // `path.as_str()` (display).
    let fold = path.fold();
    if fold != "/" {
        lock_path(transaction, "/", false).await?;
        let parent = parent_path(&fold);
        if parent != "/" {
            let mut prefix = String::new();
            for segment in parent.trim_start_matches('/').split('/') {
                prefix.push('/');
                prefix.push_str(segment);
                lock_path(transaction, &prefix, false).await?;
            }
        }
    }
    lock_path(transaction, &fold, true).await
}

pub(super) async fn lock_path(
    transaction: &mut Transaction<'_, Postgres>,
    path: &str,
    exclusive: bool,
) -> Result<(), Status> {
    let query = if exclusive {
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))"
    } else {
        "SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))"
    };
    sqlx::query(query)
        .bind(path)
        .execute(&mut **transaction)
        .await
        .map_err(|_| storage_unavailable())?;
    Ok(())
}

pub(super) async fn begin(database: &PgPool) -> Result<Transaction<'static, Postgres>, Status> {
    database.begin().await.map_err(|_| storage_unavailable())
}

pub(super) async fn commit(transaction: Transaction<'_, Postgres>) -> Result<(), Status> {
    transaction
        .commit()
        .await
        .map_err(|_| storage_unavailable())
}

/// Every stored path with its content, in fold order — the candidate set a
/// listing filters through the caller's grants.
pub(super) async fn path_candidates(database: &PgPool) -> Result<Vec<PathContentRow>, Status> {
    sqlx::query_as::<_, PathContentRow>(
        "SELECT path, lowercase_path, content_id, created_at FROM configuration_paths ORDER BY lowercase_path",
    )
    .fetch_all(database)
    .await
    .map_err(|_| storage_unavailable())
}

/// The listed values stored at exactly the given fold paths.
pub(super) async fn listed_values(
    database: &PgPool,
    fold_paths: &[String],
) -> Result<Vec<ListedValueRow>, Status> {
    sqlx::query_as::<_, ListedValueRow>(
        r"
                SELECT p.path, p.lowercase_path, p.content_id, c.value, c.classification, c.created_at, c.updated_at
                FROM configuration_paths p
                JOIN configuration_value_contents c ON c.id = p.content_id
                WHERE p.lowercase_path = ANY($1::TEXT[])
                ORDER BY p.lowercase_path
                ",
    )
    .bind(fold_paths)
    .fetch_all(database)
    .await
    .map_err(|_| storage_unavailable())
}

/// Every value at or below `fold`, in fold order.
pub(super) async fn sub_tree_rows(
    database: &PgPool,
    fold: &str,
) -> Result<Vec<SubTreeRow>, Status> {
    sqlx::query_as::<_, SubTreeRow>(
        r"
            SELECT p.path, c.value, c.classification
            FROM configuration_paths p
            JOIN configuration_value_contents c ON c.id = p.content_id
            WHERE $1 = '/' OR p.lowercase_path = $1 OR starts_with(p.lowercase_path, $1 || '/')
            ORDER BY p.lowercase_path
            ",
    )
    .bind(fold)
    .fetch_all(database)
    .await
    .map_err(|_| storage_unavailable())
}

/// The content, classification and alias count behind one fold path.
pub(super) async fn path_content_class(
    transaction: &mut Transaction<'_, Postgres>,
    fold: &str,
) -> Result<Option<PathContentClassRow>, Status> {
    sqlx::query_as::<_, PathContentClassRow>(
        r"
            SELECT
                p.content_id,
                c.value,
                c.classification,
                (
                    SELECT COUNT(*)
                    FROM configuration_paths siblings
                    WHERE siblings.content_id = p.content_id
                ) AS path_count
            FROM configuration_paths p
            JOIN configuration_value_contents c ON c.id = p.content_id
            WHERE p.lowercase_path = $1
            ",
    )
    .bind(fold)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| storage_unavailable())
}

/// Overwrites a content row's stored representation and classification.
/// Every path aliasing the content observes the new value.
pub(super) async fn update_content(
    transaction: &mut Transaction<'_, Postgres>,
    content_id: i64,
    stored: &str,
    classification: &str,
    now: OffsetDateTime,
) -> Result<MutationRow, Status> {
    sqlx::query_as::<_, MutationRow>(
        r"
                UPDATE configuration_value_contents
                SET value = $2, classification = $3, updated_at = $4
                WHERE id = $1
                RETURNING created_at, updated_at
                ",
    )
    .bind(content_id)
    .bind(stored)
    .bind(classification)
    .bind(now)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| storage_unavailable())
}

/// Fold keys of every secret at, below, or above `fold`.
pub(super) async fn secret_paths_touching(
    transaction: &mut Transaction<'_, Postgres>,
    fold: &str,
) -> Result<BTreeSet<String>, Status> {
    let rows = sqlx::query_as::<_, PathRow>(
        r"
            SELECT p.lowercase_path AS path
            FROM configuration_paths p
            JOIN configuration_value_contents c ON c.id = p.content_id
            WHERE c.classification = 'secret'
              AND (
                    $1 = '/'
                    OR p.lowercase_path = $1
                    OR starts_with(p.lowercase_path, $1 || '/')
                    OR starts_with($1, p.lowercase_path || '/')
                  )
            ORDER BY p.lowercase_path
            ",
    )
    .bind(fold)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| storage_unavailable())?;
    Ok(rows.into_iter().map(|row| row.path).collect())
}

/// Deletes every plain path at or below `fold` that is not in `keep`,
/// returning the content each deleted path referenced.
pub(super) async fn delete_plain_paths_except(
    transaction: &mut Transaction<'_, Postgres>,
    fold: &str,
    keep: &[String],
) -> Result<Vec<DeletedPathRow>, Status> {
    let mut deleted = sqlx::query_as::<_, DeletedPathRow>(
        r"
            DELETE FROM configuration_paths p
            USING configuration_value_contents c
            WHERE p.content_id = c.id
              AND ($1 = '/' OR p.lowercase_path = $1 OR starts_with(p.lowercase_path, $1 || '/'))
              AND c.classification = 'plain'
              AND NOT (p.lowercase_path = ANY($2::TEXT[]))
            RETURNING p.path, p.content_id, c.value, c.classification
            ",
    )
    .bind(fold)
    .bind(keep)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|_| storage_unavailable())?;
    // See `delete_paths`: the audit trail itemizes a bounded prefix.
    deleted.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(deleted)
}

/// The content a fold path resolves to, if any.
pub(super) async fn content_id_at<'e, E>(executor: E, fold: &str) -> Result<Option<i64>, Status>
where
    E: PgExecutor<'e>,
{
    sqlx::query_scalar::<_, i64>(
        "SELECT content_id FROM configuration_paths WHERE lowercase_path = $1",
    )
    .bind(fold)
    .fetch_optional(executor)
    .await
    .map_err(|_| storage_unavailable())
}

/// What a content row held before it was overwritten.
#[derive(FromRow)]
pub(super) struct PreviousContentRow {
    pub(super) value: String,
    pub(super) classification: String,
}

/// Overwrites a content row with a plain value, returning what it held before.
///
/// Subtree replacement never reaches a secret, so the previous content is
/// plain in practice; its classification is returned anyway so the audit trail
/// decides what it may keep from the row itself rather than from that promise.
pub(super) async fn update_plain_content(
    transaction: &mut Transaction<'_, Postgres>,
    content_id: i64,
    value: &str,
    now: OffsetDateTime,
) -> Result<PreviousContentRow, Status> {
    // `UPDATE … RETURNING` yields the new row, so the old one is read by a
    // locking CTE in the same statement rather than by a second round trip.
    sqlx::query_as::<_, PreviousContentRow>(
        r"
                WITH previous AS (
                    SELECT value, classification
                    FROM configuration_value_contents
                    WHERE id = $1
                    FOR UPDATE
                )
                UPDATE configuration_value_contents c
                SET value = $2, classification = 'plain', updated_at = $3
                FROM previous
                WHERE c.id = $1
                RETURNING previous.value, previous.classification
                ",
    )
    .bind(content_id)
    .bind(value)
    .bind(now)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| storage_unavailable())
}

/// Deletes the path at `fold`, or with `recurse` every path at or below it,
/// returning each deleted path and the content it referenced, in path order.
pub(super) async fn delete_paths(
    transaction: &mut Transaction<'_, Postgres>,
    fold: &str,
    recurse: bool,
) -> Result<Vec<DeletedPathRow>, Status> {
    let statement = if recurse {
        r"
            DELETE FROM configuration_paths p
            USING configuration_value_contents c
            WHERE p.content_id = c.id
              AND ($1 = '/' OR p.lowercase_path = $1 OR starts_with(p.lowercase_path, $1 || '/'))
            RETURNING p.path, p.content_id, c.value, c.classification
            "
    } else {
        r"
            DELETE FROM configuration_paths p
            USING configuration_value_contents c
            WHERE p.content_id = c.id AND p.lowercase_path = $1
            RETURNING p.path, p.content_id, c.value, c.classification
            "
    };
    let mut deleted = sqlx::query_as::<_, DeletedPathRow>(statement)
        .bind(fold)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|_| storage_unavailable())?;
    // `RETURNING` promises no order, and the audit trail itemizes a bounded
    // prefix of these — which must be the same prefix every time.
    deleted.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(deleted)
}

/// The stored representation behind one fold path, for a reveal.
pub(super) async fn revealed_row(
    database: &PgPool,
    fold: &str,
) -> Result<Option<RevealedRow>, Status> {
    sqlx::query_as::<_, RevealedRow>(
        r"
            SELECT p.content_id, c.value, c.classification
            FROM configuration_paths p
            JOIN configuration_value_contents c ON c.id = p.content_id
            WHERE p.lowercase_path = $1
            ",
    )
    .bind(fold)
    .fetch_optional(database)
    .await
    .map_err(|_| storage_unavailable())
}

/// Whether a path row already exists at exactly `fold`.
pub(super) async fn path_is_occupied(
    transaction: &mut Transaction<'_, Postgres>,
    fold: &str,
) -> Result<bool, Status> {
    let occupied = sqlx::query_scalar::<_, String>(
        "SELECT path FROM configuration_paths WHERE lowercase_path = $1",
    )
    .bind(fold)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| storage_unavailable())?;
    Ok(occupied.is_some())
}

/// Every path resolving to one content, in fold order.
pub(super) async fn paths_of_content(
    database: &PgPool,
    content_id: i64,
) -> Result<Vec<PathWithFoldRow>, Status> {
    sqlx::query_as::<_, PathWithFoldRow>(
        "SELECT path, lowercase_path FROM configuration_paths WHERE content_id = $1 ORDER BY lowercase_path",
    )
    .bind(content_id)
    .fetch_all(database)
    .await
    .map_err(|_| storage_unavailable())
}

/// Serializes concurrent start-of-day encryption passes for the transaction.
pub(super) async fn lock_encryption_pass(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('sovereign-config:encrypt-stored-secrets', 0))",
    )
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// Every secret's stored representation, in id order.
pub(super) async fn stored_secrets(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<Vec<StoredSecretRow>, sqlx::Error> {
    sqlx::query_as::<_, StoredSecretRow>(
        r"
        SELECT id, value
        FROM configuration_value_contents
        WHERE classification = 'secret'
        ORDER BY id
        ",
    )
    .fetch_all(&mut **transaction)
    .await
}

/// Replaces a secret's stored representation without touching `updated_at`.
pub(super) async fn reseal_secret(
    transaction: &mut Transaction<'_, Postgres>,
    content_id: i64,
    sealed: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE configuration_value_contents SET value = $2 WHERE id = $1")
        .bind(content_id)
        .bind(sealed)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}
