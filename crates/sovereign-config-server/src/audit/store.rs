//! Every `PostgreSQL` statement behind the audit trail. Nothing outside this
//! module writes SQL against `audit_events`.
//!
//! Errors are returned raw rather than as a bounded `Status`, because what a
//! failure means is the caller's policy: a mutation fails closed on it, a plain
//! read carries on.

use std::borrow::Cow;

use sqlx::{PgExecutor, PgPool};
use time::OffsetDateTime;

use super::Actor;

/// One event's columns. The actor and the time are shared by every event of a
/// call, so they are bound once rather than repeated per row.
pub(super) struct EventRow<'a> {
    pub(super) kind: &'static str,
    pub(super) display_path: &'a str,
    pub(super) old_value: Option<&'a str>,
    pub(super) new_value: Option<&'a str>,
    pub(super) narrative: &'a str,
    pub(super) coalesce_digest: Option<String>,
}

/// `text` as `PostgreSQL` can store it. A `TEXT` cannot hold NUL, and an actor
/// subject or name comes from the identity provider rather than from anything
/// this server validated — so without this, one odd claim would fail every
/// audit write for that identity, and with them every secret access.
fn storable(text: &str) -> Cow<'_, str> {
    if text.contains('\0') {
        Cow::Owned(text.replace('\0', ""))
    } else {
        Cow::Borrowed(text)
    }
}

/// Inserts `rows` in one statement, however many there are.
///
/// A row with a `coalesce_digest` that already exists bumps that window instead:
/// the count goes up, the time moves to the latest occurrence, and the wording
/// follows it, so a coalesced row always describes its most recent access. It
/// is one statement either way — nothing is read back to be rewritten. A NULL
/// key never conflicts, so an ordinary change is always its own row.
///
/// Two rows of one call must not share a key, which holds because only single
/// accesses coalesce and they are recorded one at a time.
pub(super) async fn insert_events<'e, E>(
    executor: E,
    actor: &Actor<'_>,
    at: OffsetDateTime,
    rows: &[EventRow<'_>],
) -> Result<(), sqlx::Error>
where
    E: PgExecutor<'e>,
{
    if rows.is_empty() {
        return Ok(());
    }
    let kinds: Vec<&str> = rows.iter().map(|row| row.kind).collect();
    let paths: Vec<&str> = rows.iter().map(|row| row.display_path).collect();
    let old_values: Vec<Option<&str>> = rows.iter().map(|row| row.old_value).collect();
    let new_values: Vec<Option<&str>> = rows.iter().map(|row| row.new_value).collect();
    let narratives: Vec<Cow<'_, str>> = rows.iter().map(|row| storable(row.narrative)).collect();
    let coalesce_digests: Vec<Option<&str>> = rows
        .iter()
        .map(|row| row.coalesce_digest.as_deref())
        .collect();

    sqlx::query(
        r"
        INSERT INTO audit_events (
            occurred_at, first_occurred_at, kind, display_path, actor_subject, actor_name,
            protocol_version, old_value, new_value, narrative, coalesce_digest
        )
        SELECT $1, $1, event.kind, event.display_path, $2, $3, $4,
               event.old_value, event.new_value, event.narrative, event.coalesce_digest
        FROM UNNEST($5::TEXT[], $6::TEXT[], $7::TEXT[], $8::TEXT[], $9::TEXT[], $10::TEXT[])
            AS event(kind, display_path, old_value, new_value, narrative, coalesce_digest)
        ON CONFLICT (coalesce_digest) DO UPDATE
        SET event_count = audit_events.event_count + 1,
            occurred_at = GREATEST(audit_events.occurred_at, EXCLUDED.occurred_at),
            display_path = EXCLUDED.display_path,
            actor_name = COALESCE(EXCLUDED.actor_name, audit_events.actor_name),
            narrative = EXCLUDED.narrative
        ",
    )
    .bind(at)
    .bind(storable(actor.subject))
    .bind(actor.name.map(storable))
    .bind(actor.protocol_version)
    .bind(kinds)
    .bind(paths)
    .bind(old_values)
    .bind(new_values)
    .bind(narratives)
    .bind(coalesce_digests)
    .execute(executor)
    .await?;
    Ok(())
}

/// Deletes every event last seen before `cutoff`. A coalesced row goes by its
/// most recent occurrence, so a window still being bumped is never swept.
pub(super) async fn delete_before(
    database: &PgPool,
    cutoff: OffsetDateTime,
) -> Result<u64, sqlx::Error> {
    let swept = sqlx::query("DELETE FROM audit_events WHERE occurred_at < $1")
        .bind(cutoff)
        .execute(database)
        .await?;
    Ok(swept.rows_affected())
}
