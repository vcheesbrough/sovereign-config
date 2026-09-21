//! The audit trail as a client reads it back, in no protocol version's terms.

use crate::{ConfigPath, Timestamp};

/// What happened. The label is the one the trail stores and filters on.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AuditEventKind {
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

impl AuditEventKind {
    pub const ALL: [Self; 12] = [
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

    #[must_use]
    pub const fn as_str(self) -> &'static str {
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

    /// The kind stored as `label`, or `None` for a label this build does not
    /// know.
    #[must_use]
    pub fn parse(label: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == label)
    }

    /// Whether this kind is a plain read of configuration — the events a view
    /// of changes and secret accesses leaves out by default, because they
    /// outnumber everything else.
    #[must_use]
    pub const fn is_plain_read(self) -> bool {
        matches!(self, Self::SubtreeRead | Self::ValuesListed)
    }
}

/// One page's worth of filters. Every filter that is set must match; an unset
/// one matches everything.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuditQuery {
    /// A case-insensitive fragment of the event's path.
    pub path_filter: Option<String>,
    /// One value's path: its own events, plus subtree reads of its ancestors
    /// and listings of its parent. Cannot be combined with `path_filter`.
    pub element_path: Option<ConfigPath>,
    /// A case-insensitive fragment of the event's narrative.
    pub text_filter: Option<String>,
    /// Events whose period overlaps [`from`, `until`].
    pub from: Option<Timestamp>,
    pub until: Option<Timestamp>,
    /// The protocol version label an event arrived on, matched exactly.
    pub protocol_version: Option<String>,
    /// The kinds to return; empty returns every kind.
    pub kinds: Vec<AuditEventKind>,
    /// Zero asks for the service's page size.
    pub page_size: u32,
    /// The previous page's [`AuditPage::next_cursor`], verbatim.
    pub cursor: Option<String>,
}

/// One event in the trail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEntry {
    pub id: u64,
    pub kind: AuditEventKind,
    /// The path as written when the event happened; `/` for a read of the
    /// whole tree.
    pub path: ConfigPath,
    /// The most recent occurrence.
    pub occurred_at: Timestamp,
    pub first_occurred_at: Timestamp,
    /// How many accesses this event stands for.
    pub event_count: u32,
    pub actor_subject: String,
    pub actor_name: Option<String>,
    pub protocol_version: String,
    /// A plain value's previous and new text; never set for a secret.
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    /// One sentence, including a coalesced event's count and period.
    pub narrative: String,
}

/// One page of the trail, newest first.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuditPage {
    pub events: Vec<AuditEntry>,
    /// Pass as [`AuditQuery::cursor`] for the next page; `None` at the end.
    pub next_cursor: Option<String>,
}
