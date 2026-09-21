//! Reading the audit trail back, in no protocol version's terms.
//!
//! Inputs arrive unvalidated — raw strings, and a kind selection that is `None`
//! when it had no version-free form — and are validated here. Nothing here may
//! import the proto crate: a version is a shim over this file, never a branch
//! in it.
//!
//! **Visibility is the existing grant check.** An event is returned only where
//! the caller holds `read` on its path, exactly as `list_value_paths` filters —
//! and, for an alias event, on the other path its narrative names too, which is
//! what `list_value_paths` hides. A managed-connection event needs `manage` on
//! its root instead, the grant that lists the connection at all. Every
//! condition is part of the query rather than applied to its result:
//! filtering a page after reading it would return short pages, or empty ones,
//! for as long as the newest events belonged to someone else's namespace.
//!
//! A query is not itself recorded in the trail: it returns no configuration
//! content, and recording it would make every scroll of the trail a new entry
//! in it.

use sovereign_config_core::{AuditEntry, AuditEventKind, AuditPage, ConfigPath, Timestamp};
use sqlx::PgPool;
use time::OffsetDateTime;
use tonic::Status;

use super::narrative;
use super::store::{self, ElementScope, EventFilter, StoredEvent};
use crate::auth::{AuthenticatedPrincipal, Permission};
use crate::rpc::{CallContext, storage_unavailable, to_timestamp};

/// The longest path fragment a query may carry: comfortably past any real
/// path, short enough that a request cannot make the trigram match costly.
const MAX_PATH_FILTER_CHARACTERS: usize = 512;
/// The longest narrative fragment a query may carry.
const MAX_TEXT_FILTER_CHARACTERS: usize = 256;
/// The longest protocol version label the trail stores; see the table's own
/// `protocol_version` constraint.
const MAX_PROTOCOL_VERSION_CHARACTERS: usize = 32;

pub(crate) struct AuditTrailService {
    database: PgPool,
    /// The configured page size: what a query gets when it names none, and
    /// the most it gets when it names more.
    page_size: u32,
}

/// One query exactly as a caller sent it, before any of it is validated.
pub(super) struct TrailQuery<'a> {
    pub(super) path_filter: &'a str,
    pub(super) element_path: &'a str,
    pub(super) text_filter: &'a str,
    pub(super) from: Option<Timestamp>,
    pub(super) until: Option<Timestamp>,
    pub(super) protocol_version: &'a str,
    /// `None` when a requested kind had no version-free form.
    pub(super) kinds: Option<Vec<AuditEventKind>>,
    pub(super) page_size: u32,
    pub(super) cursor: &'a str,
}

/// A query whose every filter has been validated and folded.
struct ValidQuery<'a> {
    path_fragment: Option<String>,
    element: Option<ElementScope>,
    text_fragment: Option<&'a str>,
    from: Option<OffsetDateTime>,
    until: Option<OffsetDateTime>,
    protocol_version: Option<&'a str>,
    kinds: Vec<&'static str>,
    after: Option<(OffsetDateTime, i64)>,
}

impl AuditTrailService {
    pub(crate) const fn new(database: PgPool, page_size: u32) -> Self {
        Self {
            database,
            page_size,
        }
    }

    pub(super) async fn query_audit_trail(
        &self,
        context: &CallContext<'_>,
        query: TrailQuery<'_>,
    ) -> Result<AuditPage, Status> {
        let valid = validate(&query)?;
        let principal = context.principal()?;
        let readable_prefixes = granted_prefixes(principal, Permission::Read);
        let manageable_prefixes = granted_prefixes(principal, Permission::Manage);
        if readable_prefixes.is_empty() && manageable_prefixes.is_empty() {
            return Ok(AuditPage::default());
        }
        let page_size = match query.page_size {
            0 => self.page_size,
            requested => requested.min(self.page_size),
        };
        let rows = store::query_events(
            &self.database,
            &EventFilter {
                readable_prefixes: &readable_prefixes,
                manageable_prefixes: &manageable_prefixes,
                path_fragment: valid.path_fragment.as_deref(),
                element: valid.element.as_ref(),
                text_fragment: valid.text_fragment,
                from: valid.from,
                until: valid.until,
                protocol_version: valid.protocol_version,
                kinds: &valid.kinds,
                after: valid.after,
                // One row past the page says whether there is another page,
                // without a cursor that leads to an empty one.
                limit: i64::from(page_size) + 1,
            },
        )
        .await
        .map_err(|_| storage_unavailable())?;
        page(rows, page_size)
    }
}

/// The fold keys `principal` holds `permission` under. Grant prefixes are
/// already fold keys, which is what `path_fold` is matched against.
fn granted_prefixes(principal: &AuthenticatedPrincipal, permission: Permission) -> Vec<String> {
    principal
        .grants
        .iter()
        .filter(|grant| grant.permissions.contains(&permission))
        .map(|grant| grant.prefix.clone())
        .collect()
}

fn invalid_query() -> Status {
    Status::invalid_argument("audit query is invalid")
}

#[expect(
    clippy::result_large_err,
    reason = "tonic::Status is the crate's RPC error type and is returned by value"
)]
fn validate<'a>(query: &'a TrailQuery<'a>) -> Result<ValidQuery<'a>, Status> {
    let path_fragment = non_empty(query.path_filter)
        .map(|fragment| {
            let path_characters = fragment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'/'));
            (path_characters && fragment.len() <= MAX_PATH_FILTER_CHARACTERS)
                .then(|| fragment.to_ascii_lowercase())
                .ok_or_else(invalid_query)
        })
        .transpose()?;
    let element = non_empty(query.element_path)
        .map(|path| {
            ConfigPath::parse_operation(path)
                .map(|path| element_scope(&path))
                .map_err(|_| invalid_query())
        })
        .transpose()?;
    if path_fragment.is_some() && element.is_some() {
        return Err(invalid_query());
    }
    let text_fragment = non_empty(query.text_filter)
        .map(|fragment| {
            (fragment.chars().count() <= MAX_TEXT_FILTER_CHARACTERS && !fragment.contains('\0'))
                .then_some(fragment)
                .ok_or_else(invalid_query)
        })
        .transpose()?;
    let protocol_version = non_empty(query.protocol_version)
        .map(|version| {
            (version.len() <= MAX_PROTOCOL_VERSION_CHARACTERS
                && version
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()))
            .then_some(version)
            .ok_or_else(invalid_query)
        })
        .transpose()?;
    let from = query.from.map(instant).transpose()?;
    let until = query.until.map(instant).transpose()?;
    if from.zip(until).is_some_and(|(from, until)| from > until) {
        return Err(invalid_query());
    }
    let kinds = query
        .kinds
        .as_ref()
        .ok_or_else(invalid_query)?
        .iter()
        .map(|kind| kind.as_str())
        .collect();
    let after = non_empty(query.cursor).map(parse_cursor).transpose()?;
    Ok(ValidQuery {
        path_fragment,
        element,
        text_fragment,
        from,
        until,
        protocol_version,
        kinds,
        after,
    })
}

fn non_empty(text: &str) -> Option<&str> {
    (!text.is_empty()).then_some(text)
}

/// Everything that can have read `path` without naming it: a subtree read of
/// any ancestor, the root included, and a listing of its direct parent.
fn element_scope(path: &ConfigPath) -> ElementScope {
    let fold = path.fold();
    let mut ancestors = vec!["/".to_owned()];
    let mut end = 0;
    while let Some(next) = fold[end + 1..].find('/') {
        end += 1 + next;
        ancestors.push(fold[..end].to_owned());
    }
    let parent = ancestors.last().cloned().unwrap_or_else(|| "/".to_owned());
    ElementScope {
        path: fold,
        ancestors,
        parent,
    }
}

#[expect(
    clippy::result_large_err,
    reason = "tonic::Status is the crate's RPC error type and is returned by value"
)]
fn instant(timestamp: Timestamp) -> Result<OffsetDateTime, Status> {
    let nanos = u32::try_from(timestamp.nanos)
        .ok()
        .filter(|nanos| *nanos < 1_000_000_000)
        .ok_or_else(invalid_query)?;
    OffsetDateTime::from_unix_timestamp(timestamp.seconds)
        .ok()
        .and_then(|at| at.replace_nanosecond(nanos).ok())
        .ok_or_else(invalid_query)
}

/// The cursor after `row`. Opaque to a client; to this server it is the row's
/// position in the page order, `(first_occurred_at, id)`, which is fixed for
/// the row's life — so a row inserted or bumped mid-scroll can neither be
/// returned twice nor push an unseen one past the cursor.
fn cursor_after(row: &StoredEvent) -> String {
    let micros = row.first_occurred_at.unix_timestamp_nanos() / 1_000;
    format!("{micros}.{}", row.id)
}

#[expect(
    clippy::result_large_err,
    reason = "tonic::Status is the crate's RPC error type and is returned by value"
)]
fn parse_cursor(cursor: &str) -> Result<(OffsetDateTime, i64), Status> {
    let (micros, id) = cursor.split_once('.').ok_or_else(invalid_query)?;
    let micros: i64 = micros.parse().map_err(|_| invalid_query())?;
    let id: i64 = id.parse().map_err(|_| invalid_query())?;
    let at = OffsetDateTime::from_unix_timestamp_nanos(i128::from(micros) * 1_000)
        .map_err(|_| invalid_query())?;
    if id < 1 {
        return Err(invalid_query());
    }
    Ok((at, id))
}

#[expect(
    clippy::result_large_err,
    reason = "tonic::Status is the crate's RPC error type and is returned by value"
)]
fn page(mut rows: Vec<StoredEvent>, page_size: u32) -> Result<AuditPage, Status> {
    let page_size = usize::try_from(page_size).map_err(|_| storage_unavailable())?;
    let more = rows.len() > page_size;
    rows.truncate(page_size);
    let next_cursor = more.then(|| rows.last().map(cursor_after)).flatten();
    let events = rows
        .into_iter()
        .map(entry)
        .collect::<Result<Vec<_>, Status>>()?;
    Ok(AuditPage {
        events,
        next_cursor,
    })
}

/// A stored row as a client sees it. The table's own constraints admit only
/// what this accepts, so a failure here is storage misbehaving, not a request
/// the caller could fix.
#[expect(
    clippy::result_large_err,
    reason = "tonic::Status is the crate's RPC error type and is returned by value"
)]
fn entry(row: StoredEvent) -> Result<AuditEntry, Status> {
    let event_count = u32::try_from(row.event_count).map_err(|_| storage_unavailable())?;
    Ok(AuditEntry {
        id: u64::try_from(row.id).map_err(|_| storage_unavailable())?,
        kind: AuditEventKind::parse(&row.kind).ok_or_else(storage_unavailable)?,
        path: ConfigPath::parse_selection(&row.display_path).map_err(|_| storage_unavailable())?,
        narrative: narrative::served(
            &row.narrative,
            event_count,
            row.first_occurred_at,
            row.occurred_at,
        ),
        occurred_at: to_timestamp(row.occurred_at)?,
        first_occurred_at: to_timestamp(row.first_occurred_at)?,
        event_count,
        actor_subject: row.actor_subject,
        actor_name: row.actor_name,
        protocol_version: row.protocol_version,
        old_value: row.old_value,
        new_value: row.new_value,
    })
}

#[cfg(test)]
mod tests {
    use sovereign_config_core::{AuditEventKind, ConfigPath, Timestamp};

    use super::{TrailQuery, element_scope, parse_cursor, validate};

    fn query() -> TrailQuery<'static> {
        TrailQuery {
            path_filter: "",
            element_path: "",
            text_filter: "",
            from: None,
            until: None,
            protocol_version: "",
            kinds: Some(Vec::new()),
            page_size: 0,
            cursor: "",
        }
    }

    #[test]
    fn an_empty_query_is_valid_and_filters_nothing() {
        let empty = query();
        let valid = validate(&empty).unwrap();
        assert!(valid.path_fragment.is_none() && valid.element.is_none());
        assert!(valid.kinds.is_empty() && valid.after.is_none());
    }

    #[test]
    fn the_path_filter_is_folded_and_limited_to_path_characters() {
        let folded = TrailQuery {
            path_filter: "Apps/DB_url",
            ..query()
        };
        assert_eq!(
            validate(&folded).unwrap().path_fragment.as_deref(),
            Some("apps/db_url")
        );
        for invalid in ["a%b", "a b", "ü", &"a".repeat(513)] {
            let query = TrailQuery {
                path_filter: invalid,
                ..query()
            };
            assert!(validate(&query).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn an_element_query_cannot_be_combined_with_a_path_filter() {
        let both = TrailQuery {
            path_filter: "apps",
            element_path: "/apps/api/url",
            ..query()
        };
        assert!(validate(&both).is_err());
        let root = TrailQuery {
            element_path: "/",
            ..query()
        };
        assert!(
            validate(&root).is_err(),
            "an element is one value, not the root"
        );
    }

    #[test]
    fn an_element_is_read_through_its_ancestors_and_listed_through_its_parent() {
        let scope = element_scope(&ConfigPath::parse_operation("/Apps/Api/URL").unwrap());
        assert_eq!(scope.path, "/apps/api/url");
        assert_eq!(scope.ancestors, ["/", "/apps", "/apps/api"]);
        assert_eq!(scope.parent, "/apps/api");

        let top = element_scope(&ConfigPath::parse("/flag").unwrap());
        assert_eq!(top.ancestors, ["/"]);
        assert_eq!(top.parent, "/");
    }

    #[test]
    fn an_untranslatable_kind_a_bad_range_or_version_is_refused() {
        assert!(
            validate(&TrailQuery {
                kinds: None,
                ..query()
            })
            .is_err()
        );
        let backwards = TrailQuery {
            from: Some(Timestamp {
                seconds: 20,
                nanos: 0,
            }),
            until: Some(Timestamp {
                seconds: 10,
                nanos: 0,
            }),
            ..query()
        };
        assert!(validate(&backwards).is_err());
        let bad_nanos = TrailQuery {
            from: Some(Timestamp {
                seconds: 0,
                nanos: 1_000_000_000,
            }),
            ..query()
        };
        assert!(validate(&bad_nanos).is_err());
        for version in ["V4", "v4 ", "v-4", &"v".repeat(33)] {
            let query = TrailQuery {
                protocol_version: version,
                ..query()
            };
            assert!(validate(&query).is_err(), "{version:?}");
        }
        let kinds = TrailQuery {
            kinds: Some(vec![AuditEventKind::SecretRevealed]),
            protocol_version: "v4",
            ..query()
        };
        let valid = validate(&kinds).unwrap();
        assert_eq!(valid.kinds, ["secret.revealed"]);
        assert_eq!(valid.protocol_version, Some("v4"));
    }

    #[test]
    fn a_cursor_round_trips_and_garbage_is_refused() {
        let (at, id) = parse_cursor("1789981323000001.42").unwrap();
        assert_eq!(at.unix_timestamp_nanos(), 1_789_981_323_000_001_000);
        assert_eq!(id, 42);
        for garbage in [
            "",
            "42",
            "a.b",
            "1.0",
            "1.-3",
            "1.2.3",
            "99999999999999999999.1",
        ] {
            assert!(parse_cursor(garbage).is_err(), "{garbage:?}");
        }
    }
}
