//! Every `PostgreSQL` statement behind the audit trail. Nothing outside this
//! module writes SQL against `audit_events`.
//!
//! Errors are returned raw rather than as a bounded `Status`, because what a
//! failure means is the caller's policy: a mutation fails closed on it, a plain
//! read carries on.

use std::borrow::Cow;

use sqlx::{FromRow, PgExecutor, PgPool, Postgres, QueryBuilder};
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

/// One stored event, as the audit query reads it back.
#[derive(Debug, FromRow)]
pub(super) struct StoredEvent {
    pub(super) id: i64,
    pub(super) kind: String,
    pub(super) display_path: String,
    pub(super) occurred_at: OffsetDateTime,
    pub(super) first_occurred_at: OffsetDateTime,
    pub(super) event_count: i32,
    pub(super) actor_subject: String,
    pub(super) actor_name: Option<String>,
    pub(super) protocol_version: String,
    pub(super) old_value: Option<String>,
    pub(super) new_value: Option<String>,
    pub(super) narrative: String,
}

/// The events one value's history is made of: its own, subtree reads of any
/// ancestor, and listings of its parent. All three are fold keys.
pub(super) struct ElementScope {
    pub(super) path: String,
    pub(super) ancestors: Vec<String>,
    pub(super) parent: String,
}

/// Every filter of one audit query, already validated and folded. Nothing in
/// here is raw request text: fragments are matched literally, never as
/// patterns, whatever they contain.
pub(super) struct EventFilter<'a> {
    /// The fold keys the caller holds `read` under; `/` covers everything.
    /// Applied in the query rather than to the page, so a page is never
    /// short because rows the caller may not see were dropped from it.
    pub(super) readable_prefixes: &'a [String],
    pub(super) path_fragment: Option<&'a str>,
    pub(super) element: Option<&'a ElementScope>,
    pub(super) text_fragment: Option<&'a str>,
    pub(super) from: Option<OffsetDateTime>,
    pub(super) until: Option<OffsetDateTime>,
    pub(super) protocol_version: Option<&'a str>,
    pub(super) kinds: &'a [&'static str],
    /// The last row of the previous page, as `(first_occurred_at, id)`.
    pub(super) after: Option<(OffsetDateTime, i64)>,
    pub(super) limit: i64,
}

/// A `LIKE` pattern matching `fragment` anywhere, with every wildcard in the
/// fragment itself escaped: `_` is a legal path character and must match only
/// an underscore.
fn contains_pattern(fragment: &str) -> String {
    let mut pattern = String::with_capacity(fragment.len() + 2);
    pattern.push('%');
    for character in fragment.chars() {
        if matches!(character, '\\' | '%' | '_') {
            pattern.push('\\');
        }
        pattern.push(character);
    }
    pattern.push('%');
    pattern
}

/// One page of events matching `filter`, newest first.
///
/// Built clause by clause so each filter that is unset costs nothing and each
/// that is set can use its index: a fixed statement of `$n IS NULL OR …`
/// clauses would leave the planner a generic plan that uses none of them.
pub(super) async fn query_events(
    database: &PgPool,
    filter: &EventFilter<'_>,
) -> Result<Vec<StoredEvent>, sqlx::Error> {
    let mut query = QueryBuilder::<Postgres>::new(
        "SELECT id, kind, display_path, occurred_at, first_occurred_at, event_count, \
         actor_subject, actor_name, protocol_version, old_value, new_value, narrative \
         FROM audit_events WHERE EXISTS (SELECT 1 FROM UNNEST(",
    );
    query.push_bind(filter.readable_prefixes).push(
        "::TEXT[]) AS readable(prefix) WHERE readable.prefix = '/' \
             OR path_fold = readable.prefix \
             OR starts_with(path_fold, readable.prefix || '/'))",
    );
    if let Some(fragment) = filter.path_fragment {
        query
            .push(" AND path_fold LIKE ")
            .push_bind(contains_pattern(fragment))
            .push(" ESCAPE '\\'");
    }
    if let Some(element) = filter.element {
        query
            .push(" AND (path_fold = ")
            .push_bind(&element.path)
            .push(" OR (kind = 'subtree.read' AND path_fold = ANY(")
            .push_bind(&element.ancestors)
            .push(")) OR (kind = 'values.listed' AND path_fold = ")
            .push_bind(&element.parent)
            .push("))");
    }
    if let Some(fragment) = filter.text_fragment {
        query
            .push(" AND narrative ILIKE ")
            .push_bind(contains_pattern(fragment))
            .push(" ESCAPE '\\'");
    }
    if let Some(from) = filter.from {
        query.push(" AND occurred_at >= ").push_bind(from);
    }
    if let Some(until) = filter.until {
        query.push(" AND first_occurred_at <= ").push_bind(until);
    }
    if let Some(version) = filter.protocol_version {
        query.push(" AND protocol_version = ").push_bind(version);
    }
    if !filter.kinds.is_empty() {
        query
            .push(" AND kind = ANY(")
            .push_bind(filter.kinds)
            .push(")");
    }
    if let Some((first_occurred_at, id)) = filter.after {
        query
            .push(" AND (first_occurred_at, id) < (")
            .push_bind(first_occurred_at)
            .push(", ")
            .push_bind(id)
            .push(")");
    }
    query
        .push(" ORDER BY first_occurred_at DESC, id DESC LIMIT ")
        .push_bind(filter.limit);
    query.build_query_as().fetch_all(database).await
}

#[cfg(test)]
mod tests {
    use super::contains_pattern;

    #[test]
    fn a_fragment_matches_literally_whatever_it_contains() {
        assert_eq!(contains_pattern("api"), "%api%");
        assert_eq!(contains_pattern("db_url"), "%db\\_url%");
        assert_eq!(contains_pattern("100%"), "%100\\%%");
        assert_eq!(contains_pattern("a\\b"), "%a\\\\b%");
    }
}
