//! The audit mapping every version with an `Audit` service shares: event
//! kinds and events, which no version since `v4` has changed. A version's
//! `vN.rs` imports its generated package as `proto` and invokes
//! [`audit_wire`]; its request and response mapping is its own, because that
//! is what versions change.

/// `wire_kind`, `audit_kind` and `audit_entry`, over whichever `proto` is in
/// scope.
macro_rules! audit_wire {
    () => {
        const fn wire_kind(kind: AuditEventKind) -> proto::AuditEventKind {
            use proto::AuditEventKind as Wire;
            match kind {
                AuditEventKind::ValueCreated => Wire::ValueCreated,
                AuditEventKind::ValueUpdated => Wire::ValueUpdated,
                AuditEventKind::ValueDeleted => Wire::ValueDeleted,
                AuditEventKind::ValuePathAdded => Wire::ValuePathAdded,
                AuditEventKind::SubtreeReplaced => Wire::SubtreeReplaced,
                AuditEventKind::SubtreeDeleted => Wire::SubtreeDeleted,
                AuditEventKind::SecretRevealed => Wire::SecretRevealed,
                AuditEventKind::SubtreeRead => Wire::SubtreeRead,
                AuditEventKind::ValuesListed => Wire::ValuesListed,
                AuditEventKind::ConnectionCreated => Wire::ConnectionCreated,
                AuditEventKind::ConnectionRotated => Wire::ConnectionRotated,
                AuditEventKind::ConnectionRevoked => Wire::ConnectionRevoked,
            }
        }

        fn audit_kind(tag: i32) -> Result<AuditEventKind, ClientError> {
            use proto::AuditEventKind as Wire;
            Ok(match Wire::try_from(tag).map_err(|_| browser_error())? {
                Wire::Unspecified => return Err(browser_error()),
                Wire::ValueCreated => AuditEventKind::ValueCreated,
                Wire::ValueUpdated => AuditEventKind::ValueUpdated,
                Wire::ValueDeleted => AuditEventKind::ValueDeleted,
                Wire::ValuePathAdded => AuditEventKind::ValuePathAdded,
                Wire::SubtreeReplaced => AuditEventKind::SubtreeReplaced,
                Wire::SubtreeDeleted => AuditEventKind::SubtreeDeleted,
                Wire::SecretRevealed => AuditEventKind::SecretRevealed,
                Wire::SubtreeRead => AuditEventKind::SubtreeRead,
                Wire::ValuesListed => AuditEventKind::ValuesListed,
                Wire::ConnectionCreated => AuditEventKind::ConnectionCreated,
                Wire::ConnectionRotated => AuditEventKind::ConnectionRotated,
                Wire::ConnectionRevoked => AuditEventKind::ConnectionRevoked,
            })
        }

        fn audit_entry(event: proto::AuditEvent) -> Result<AuditEntry, ClientError> {
            Ok(AuditEntry {
                id: super::audit_wire::WireId::into_id(event.id).ok_or_else(browser_error)?,
                kind: audit_kind(event.kind)?,
                path: ConfigPath::parse_selection(event.path).map_err(|_| browser_error())?,
                occurred_at: proto_timestamp(event.occurred_at)?,
                first_occurred_at: proto_timestamp(event.first_occurred_at)?,
                event_count: event.event_count,
                actor_subject: event.actor_subject,
                actor_name: event.actor_name,
                protocol_version: event.protocol_version,
                old_value: event.old_value,
                new_value: event.new_value,
                narrative: event.narrative,
            })
        }
    };
}

pub(super) use audit_wire;

/// An audit event's identifier as a version carries it: a `uint64` up to
/// `v5`, an opaque string from `v6`. This workspace's server writes the
/// string as the decimal of the same number, which is what this client reads
/// it back as; a string that is not one is a broken response.
pub(super) trait WireId {
    fn into_id(self) -> Option<u64>;
}

impl WireId for u64 {
    fn into_id(self) -> Option<u64> {
        Some(self)
    }
}

impl WireId for String {
    fn into_id(self) -> Option<u64> {
        self.parse().ok()
    }
}
