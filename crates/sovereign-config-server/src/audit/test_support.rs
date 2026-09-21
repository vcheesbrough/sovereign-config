//! What the database-backed suites share for asserting on the trail: reading
//! it back, clearing it, and forcing a write to fail.
//!
//! Everything is scoped to a path prefix, because the suites share one
//! database and one `audit_events` table.

use sqlx::{FromRow, PgPool};
use time::OffsetDateTime;

/// One stored event, every column a test may assert on.
#[derive(Debug, FromRow)]
pub(crate) struct TrailRow {
    pub(crate) kind: String,
    pub(crate) display_path: String,
    pub(crate) path_fold: String,
    pub(crate) actor_subject: String,
    pub(crate) actor_name: Option<String>,
    pub(crate) protocol_version: String,
    pub(crate) old_value: Option<String>,
    pub(crate) new_value: Option<String>,
    pub(crate) narrative: String,
    pub(crate) event_count: i32,
    pub(crate) occurred_at: OffsetDateTime,
    pub(crate) first_occurred_at: OffsetDateTime,
}

impl TrailRow {
    /// Every text column in one string, for asserting that something appears
    /// nowhere in the row rather than in no column the test remembered.
    pub(crate) fn everything(&self) -> String {
        format!("{self:?}")
    }
}

/// Every event at or below `prefix`, oldest first.
pub(crate) async fn trail(pool: &PgPool, prefix: &str) -> Vec<TrailRow> {
    sqlx::query_as::<_, TrailRow>(
        r"
        SELECT kind, display_path, path_fold, actor_subject, actor_name, protocol_version,
               old_value, new_value, narrative, event_count, occurred_at, first_occurred_at
        FROM audit_events
        WHERE path_fold = $1 OR starts_with(path_fold, $1 || '/')
        ORDER BY id
        ",
    )
    .bind(prefix)
    .fetch_all(pool)
    .await
    .expect("the audit trail must be readable")
}

/// The kinds of `rows`, in order — the shape most assertions start from.
pub(crate) fn kinds(rows: &[TrailRow]) -> Vec<&str> {
    rows.iter().map(|row| row.kind.as_str()).collect()
}

pub(crate) async fn clear_trail(pool: &PgPool, prefix: &str) {
    sqlx::query(
        "DELETE FROM audit_events WHERE path_fold = $1 OR starts_with(path_fold, $1 || '/')",
    )
    .bind(prefix)
    .execute(pool)
    .await
    .expect("the audit trail must be clearable");
}

/// Makes every audit write at or below `prefix` fail, until
/// [`restore_audit_writes`] is called with the same `tag`.
///
/// A trigger rather than an injected failing recorder, so that what is tested
/// is the real statement failing inside the real transaction. `tag` names the
/// trigger and `prefix` scopes it, so a test that panics before restoring
/// breaks only its own paths. Both are test constants: they are formatted into
/// the statement because DDL takes no bind parameters.
pub(crate) async fn break_audit_writes(pool: &PgPool, tag: &str, prefix: &str) {
    restore_audit_writes(pool, tag).await;
    sqlx::query(&format!(
        r"
        CREATE FUNCTION audit_test_refuse_{tag}() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF lower(NEW.display_path) = '{prefix}'
               OR starts_with(lower(NEW.display_path), '{prefix}/') THEN
                RAISE EXCEPTION 'audit write refused by test';
            END IF;
            RETURN NEW;
        END $$
        "
    ))
    .execute(pool)
    .await
    .expect("the refusing function must be creatable");
    sqlx::query(&format!(
        "CREATE TRIGGER audit_test_refuse_{tag} BEFORE INSERT ON audit_events \
         FOR EACH ROW EXECUTE FUNCTION audit_test_refuse_{tag}()"
    ))
    .execute(pool)
    .await
    .expect("the refusing trigger must be creatable");
}

pub(crate) async fn restore_audit_writes(pool: &PgPool, tag: &str) {
    sqlx::query(&format!(
        "DROP TRIGGER IF EXISTS audit_test_refuse_{tag} ON audit_events"
    ))
    .execute(pool)
    .await
    .expect("the refusing trigger must be droppable");
    sqlx::query(&format!(
        "DROP FUNCTION IF EXISTS audit_test_refuse_{tag}()"
    ))
    .execute(pool)
    .await
    .expect("the refusing function must be droppable");
}
