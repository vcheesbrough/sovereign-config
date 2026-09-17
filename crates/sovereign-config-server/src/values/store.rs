use sovereign_config_core::ConfigPath;
use sqlx::{FromRow, Postgres, Transaction};
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

/// A row's fold key, selected under the name `path` — the caller already
/// treats the result as an opaque fold-key string (a collision probe, a
/// secret-path set), never as anything meant for display.
#[derive(FromRow)]
pub(super) struct PathRow {
    pub(super) path: String,
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
    pub(super) classification: String,
    pub(super) path_count: i64,
}

#[derive(FromRow)]
pub(super) struct DeletedPathRow {
    pub(super) content_id: i64,
}

#[derive(FromRow)]
pub(super) struct MutationRow {
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
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
