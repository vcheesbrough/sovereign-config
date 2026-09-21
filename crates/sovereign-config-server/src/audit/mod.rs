//! The audit trail: every configuration change, secret access and
//! configuration read, attributed to who caused it and the protocol version it
//! arrived on.
//!
//! - `narrative` — the sentence each event is stored with, and how it is
//!   served. Pure.
//! - `store` — every `PostgreSQL` statement behind the trail.
//! - `service` — reading the trail back, in no protocol version's terms.
//! - `v4` — the `v4` tonic impl of the `Audit` service: a translation shim
//!   over `service`. `v3` has no `Audit` service.
//!
//! **No secret value is ever recorded.** A value reaches an event only as a
//! [`Recorded`], whose constructor discards anything not classified plain, so
//! the rule does not depend on each call site remembering it. The table
//! enforces the same rule a second time.
//!
//! Recording is called from the shared service implementations, never from a
//! protocol shim. If it lived in a version's shim, speaking another version
//! would be a way around the trail.

mod narrative;
mod service;
mod store;
pub(crate) mod v4;

use std::{sync::Arc, time::Duration};

use sha2::{Digest, Sha256};
use sovereign_config_core::ConfigPath;
use sqlx::{PgPool, Postgres, Transaction};
use time::OffsetDateTime;
use tonic::Status;
use tracing::error;

use crate::metrics::{AuditMetrics, AuditWriteOutcome};
use crate::rpc::storage_unavailable;
use crate::values::PLAIN;

pub(crate) use service::AuditTrailService;

/// How many individual value events one bulk operation records. A recursive
/// delete or a subtree replacement can touch an unbounded number of values
/// inside one transaction; beyond this the operation's summary event says how
/// many changes it did not itemize.
pub(crate) const BULK_EVENT_CAP: usize = 1000;

/// What happened. The label is stored, filtered on, and is a metric label, so
/// the domain is closed here and again by the table's own constraint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EventKind {
    ValueCreated,
    ValueUpdated,
    ValueDeleted,
    ValuePathAdded,
    SubtreeReplaced,
    SubtreeDeleted,
    SecretRevealed,
    SubtreeRead,
    ValuesListed,
    ConnectionCreated,
    ConnectionRotated,
    ConnectionRevoked,
}

impl EventKind {
    pub(crate) const ALL: [Self; 12] = [
        Self::ValueCreated,
        Self::ValueUpdated,
        Self::ValueDeleted,
        Self::ValuePathAdded,
        Self::SubtreeReplaced,
        Self::SubtreeDeleted,
        Self::SecretRevealed,
        Self::SubtreeRead,
        Self::ValuesListed,
        Self::ConnectionCreated,
        Self::ConnectionRotated,
        Self::ConnectionRevoked,
    ];

    pub(crate) const fn index(self) -> usize {
        self as usize
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ValueCreated => "value.created",
            Self::ValueUpdated => "value.updated",
            Self::ValueDeleted => "value.deleted",
            Self::ValuePathAdded => "value.path_added",
            Self::SubtreeReplaced => "subtree.replaced",
            Self::SubtreeDeleted => "subtree.deleted",
            Self::SecretRevealed => "secret.revealed",
            Self::SubtreeRead => "subtree.read",
            Self::ValuesListed => "values.listed",
            Self::ConnectionCreated => "connection.created",
            Self::ConnectionRotated => "connection.rotated",
            Self::ConnectionRevoked => "connection.revoked",
        }
    }

    /// Whether repeats inside one window collapse into a single row. Accesses
    /// do — a provider that does not cache reveals every secret on every load —
    /// and changes never do: each one is its own fact.
    const fn coalesces(self) -> bool {
        matches!(
            self,
            Self::SecretRevealed | Self::SubtreeRead | Self::ValuesListed
        )
    }
}

/// A value as the trail may hold it: the text when it is plain, and nothing at
/// all when it is not.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Recorded<'a> {
    Plain(&'a str),
    Secret,
}

impl<'a> Recorded<'a> {
    /// Anything not classified exactly plain is withheld, so an unknown or
    /// future classification fails towards recording too little.
    pub(crate) fn of(classification: &str, value: &'a str) -> Self {
        if classification == PLAIN {
            Self::Plain(value)
        } else {
            Self::Secret
        }
    }

    const fn plain(self) -> Option<&'a str> {
        match self {
            Self::Plain(value) => Some(value),
            Self::Secret => None,
        }
    }
}

/// Who an event is attributed to, and the protocol version they spoke.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Actor<'a> {
    pub(crate) subject: &'a str,
    /// The name the identity went by when the event happened.
    pub(crate) name: Option<&'a str>,
    pub(crate) protocol_version: &'static str,
}

impl Actor<'_> {
    /// How a narrative refers to the actor: by name when the identity provider
    /// gave one, because a year-old trail of opaque subjects tells an operator
    /// nothing. The subject is always stored beside it.
    fn shown(&self) -> &str {
        self.name.unwrap_or(self.subject)
    }
}

/// One thing that happened, ready to store.
pub(crate) struct AuditEvent<'a> {
    kind: EventKind,
    path: &'a str,
    /// The other path of an alias event, which its narrative names. Stored so
    /// the query can require `read` on it too.
    counterpart: Option<&'a str>,
    old_value: Option<&'a str>,
    new_value: Option<&'a str>,
    narrative: String,
}

/// A managed connection as an event describes it. None of it is secret: the
/// trail never sees a connection URL or a credential.
#[derive(Clone, Copy)]
pub(crate) struct ConnectionSubject<'a> {
    pub(crate) root: &'a str,
    pub(crate) display_name: &'a str,
    pub(crate) connection_id: &'a str,
}

impl<'a> AuditEvent<'a> {
    pub(crate) fn value_created(actor: &Actor<'_>, path: &'a str, new: Recorded<'a>) -> Self {
        Self {
            kind: EventKind::ValueCreated,
            path,
            counterpart: None,
            old_value: None,
            new_value: new.plain(),
            narrative: narrative::value_created(actor.shown(), path, new),
        }
    }

    pub(crate) fn value_updated(
        actor: &Actor<'_>,
        path: &'a str,
        old: Recorded<'a>,
        new: Recorded<'a>,
    ) -> Self {
        Self {
            kind: EventKind::ValueUpdated,
            path,
            counterpart: None,
            old_value: old.plain(),
            new_value: new.plain(),
            narrative: narrative::value_updated(actor.shown(), path, old, new),
        }
    }

    pub(crate) fn value_deleted(actor: &Actor<'_>, path: &'a str, old: Recorded<'a>) -> Self {
        Self {
            kind: EventKind::ValueDeleted,
            path,
            counterpart: None,
            old_value: old.plain(),
            new_value: None,
            narrative: narrative::value_deleted(actor.shown(), path, old),
        }
    }

    /// The two events of one alias: the new path gaining a value, and the
    /// source being exposed somewhere else. Both, because someone looking at
    /// either path is owed the fact.
    pub(crate) fn path_added(
        actor: &Actor<'_>,
        source: &'a ConfigPath,
        new_path: &'a ConfigPath,
    ) -> [Self; 2] {
        [
            Self {
                counterpart: Some(source.as_str()),
                ..Self::bare(
                    EventKind::ValuePathAdded,
                    new_path.as_str(),
                    narrative::path_added(actor.shown(), new_path.as_str(), source.as_str()),
                )
            },
            Self {
                counterpart: Some(new_path.as_str()),
                ..Self::bare(
                    EventKind::ValuePathAdded,
                    source.as_str(),
                    narrative::path_exposed(actor.shown(), source.as_str(), new_path.as_str()),
                )
            },
        ]
    }

    pub(crate) fn subtree_replaced(
        actor: &Actor<'_>,
        root: &'a str,
        created: usize,
        updated: usize,
        deleted: usize,
        unrecorded: usize,
    ) -> Self {
        Self::bare(
            EventKind::SubtreeReplaced,
            root,
            narrative::subtree_replaced(actor.shown(), root, created, updated, deleted, unrecorded),
        )
    }

    pub(crate) fn subtree_deleted(
        actor: &Actor<'_>,
        root: &'a str,
        deleted: usize,
        unrecorded: usize,
    ) -> Self {
        Self::bare(
            EventKind::SubtreeDeleted,
            root,
            narrative::subtree_deleted(actor.shown(), root, deleted, unrecorded),
        )
    }

    pub(crate) fn secret_revealed(actor: &Actor<'_>, path: &'a str) -> Self {
        Self::bare(
            EventKind::SecretRevealed,
            path,
            narrative::secret_revealed(actor.shown(), path),
        )
    }

    /// A read is recorded as it was requested — one event on the root, with
    /// how many values came back — and never per value, and never with any
    /// value: a subtree can hold secrets, and the trail has no business copying
    /// content it was only asked to witness.
    pub(crate) fn subtree_read(actor: &Actor<'_>, root: &'a str, value_count: usize) -> Self {
        Self::bare(
            EventKind::SubtreeRead,
            root,
            narrative::subtree_read(actor.shown(), root, value_count),
        )
    }

    pub(crate) fn values_listed(actor: &Actor<'_>, namespace: &'a str, value_count: usize) -> Self {
        Self::bare(
            EventKind::ValuesListed,
            namespace,
            narrative::values_listed(actor.shown(), namespace, value_count),
        )
    }

    pub(crate) fn connection_created(
        actor: &Actor<'_>,
        connection: ConnectionSubject<'a>,
        permissions: &str,
    ) -> Self {
        Self::bare(
            EventKind::ConnectionCreated,
            connection.root,
            narrative::connection_created(
                actor.shown(),
                connection.root,
                connection.display_name,
                connection.connection_id,
                permissions,
            ),
        )
    }

    pub(crate) fn connection_rotated(actor: &Actor<'_>, connection: ConnectionSubject<'a>) -> Self {
        Self::bare(
            EventKind::ConnectionRotated,
            connection.root,
            narrative::connection_rotated(
                actor.shown(),
                connection.root,
                connection.display_name,
                connection.connection_id,
            ),
        )
    }

    pub(crate) fn connection_revoked(actor: &Actor<'_>, connection: ConnectionSubject<'a>) -> Self {
        Self::bare(
            EventKind::ConnectionRevoked,
            connection.root,
            narrative::connection_revoked(
                actor.shown(),
                connection.root,
                connection.display_name,
                connection.connection_id,
            ),
        )
    }

    /// An event that carries no value, which is every kind but a single
    /// value's creation, change or deletion.
    fn bare(kind: EventKind, path: &'a str, narrative: String) -> Self {
        Self {
            kind,
            path,
            counterpart: None,
            old_value: None,
            new_value: None,
            narrative,
        }
    }
}

/// Writes events, applying the failure policy its caller chose by which method
/// it called, and counting every outcome.
#[derive(Clone)]
pub(crate) struct AuditRecorder {
    metrics: Arc<AuditMetrics>,
    coalesce_window: Duration,
}

impl AuditRecorder {
    pub(crate) const fn new(metrics: Arc<AuditMetrics>, coalesce_window: Duration) -> Self {
        Self {
            metrics,
            coalesce_window,
        }
    }

    /// **Fail closed, atomically.** Records `events` inside the caller's
    /// transaction, so a change and its record commit together or not at all.
    pub(crate) async fn record_in(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        actor: &Actor<'_>,
        at: OffsetDateTime,
        events: &[AuditEvent<'_>],
    ) -> Result<(), Status> {
        let rows = self.rows(actor, at, events);
        let result = store::insert_events(&mut **transaction, actor, at, &rows).await;
        self.settle(events, result)
    }

    /// **Fail closed.** For an operation with no transaction of its own to
    /// join: the caller must not complete if this fails.
    ///
    /// The failure is the storage fault every RPC already reports, so a caller
    /// on any protocol version sees a status it already handles.
    pub(crate) async fn record(
        &self,
        database: &PgPool,
        actor: &Actor<'_>,
        at: OffsetDateTime,
        event: AuditEvent<'_>,
    ) -> Result<(), Status> {
        let events = [event];
        let rows = self.rows(actor, at, &events);
        let result = store::insert_events(database, actor, at, &rows).await;
        self.settle(&events, result)
    }

    /// **Best effort.** A failure is counted and logged and the caller carries
    /// on. For plain reads only: they perform no other write, so failing them
    /// would make every configuration read depend on the database accepting
    /// writes — a failure mode they do not have today.
    pub(crate) async fn record_best_effort(
        &self,
        database: &PgPool,
        actor: &Actor<'_>,
        at: OffsetDateTime,
        event: AuditEvent<'_>,
    ) {
        // Already counted and logged; the read is served regardless.
        let _ = self.record(database, actor, at, event).await;
    }

    /// Deletes every event last seen before `cutoff`, returning how many.
    pub(crate) async fn sweep_expired(
        &self,
        database: &PgPool,
        cutoff: OffsetDateTime,
    ) -> Result<u64, sqlx::Error> {
        match store::delete_before(database, cutoff).await {
            Ok(swept) => {
                self.metrics.record_swept(swept);
                Ok(swept)
            }
            Err(error) => {
                self.metrics.record_sweep_failure();
                Err(error)
            }
        }
    }

    fn rows<'e>(
        &self,
        actor: &Actor<'_>,
        at: OffsetDateTime,
        events: &'e [AuditEvent<'_>],
    ) -> Vec<store::EventRow<'e>> {
        events
            .iter()
            .map(|event| store::EventRow {
                kind: event.kind.as_str(),
                display_path: event.path,
                counterpart_display_path: event.counterpart,
                old_value: event.old_value,
                new_value: event.new_value,
                narrative: &event.narrative,
                coalesce_digest: event.kind.coalesces().then(|| {
                    coalesce_digest(event.kind, actor, event.path, at, self.coalesce_window)
                }),
            })
            .collect()
    }

    #[expect(
        clippy::result_large_err,
        reason = "tonic::Status is the crate's RPC error type and is returned by value"
    )]
    fn settle(
        &self,
        events: &[AuditEvent<'_>],
        result: Result<(), sqlx::Error>,
    ) -> Result<(), Status> {
        let outcome = if result.is_ok() {
            AuditWriteOutcome::Recorded
        } else {
            AuditWriteOutcome::Failed
        };
        for event in events {
            self.metrics.record_write(event.kind, outcome);
        }
        result.map_err(|failure| {
            // Kinds and a count only. An event's path, values and narrative
            // are exactly what the log must not become a second copy of.
            error!(
                error = %failure,
                events = events.len(),
                first_kind = events.first().map(|event| event.kind.as_str()),
                "audit events could not be recorded"
            );
            storage_unavailable()
        })
    }
}

/// The identity of one coalescing window: who, on which protocol version,
/// did what, to which path, in which window.
///
/// **The protocol version is part of the key on purpose.** During a rolling
/// deploy one identity is seen on two versions inside a single window; keyed
/// without it those accesses would collapse into one row carrying whichever
/// version wrote first, misreporting the very thing the column exists to show.
///
/// Hashed so its length is fixed whatever the subject or path, and built so the
/// only unbounded component comes last: `kind`, the version label, the bucket
/// and a fold path cannot contain the separator, so no two distinct windows can
/// spell the same input.
fn coalesce_digest(
    kind: EventKind,
    actor: &Actor<'_>,
    path: &str,
    at: OffsetDateTime,
    window: Duration,
) -> String {
    let window_seconds = i64::try_from(window.as_secs()).unwrap_or(i64::MAX).max(1);
    let bucket = at.unix_timestamp().div_euclid(window_seconds);
    // A path's grammar is ASCII, so this is exactly the fold the table
    // generates for `path_fold`.
    let fold = path.to_ascii_lowercase();
    let digest = Sha256::digest(format!(
        "{}|{}|{bucket}|{fold}|{}",
        kind.as_str(),
        actor.protocol_version,
        actor.subject,
    ));
    digest
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            use std::fmt::Write as _;
            write!(hex, "{byte:02x}").expect("writing a digest to a String cannot fail");
            hex
        })
}

#[cfg(test)]
impl AuditRecorder {
    /// A recorder with a day's window whose metrics nobody reads.
    pub(crate) fn for_tests() -> Self {
        Self::with_metrics(Arc::new(AuditMetrics::default()))
    }

    pub(crate) fn with_metrics(metrics: Arc<AuditMetrics>) -> Self {
        Self::new(metrics, Duration::from_hours(24))
    }
}

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod query_tests;

#[cfg(test)]
mod tests;
