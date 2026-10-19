//! The wire mapping every version's `Audit` shim shares: event kinds and
//! events, which no version since `v4` has changed. A version's `vN.rs`
//! imports its generated package as `proto` and invokes [`audit_wire`]; the
//! `QueryAuditTrail` adapter itself is per version, because its shape is what
//! versions change.

/// The kind and event translations, over whichever `proto` is in scope.
macro_rules! audit_wire {
    () => {
        const fn kind(kind: proto::AuditEventKind) -> Option<AuditEventKind> {
            use proto::AuditEventKind as Wire;
            Some(match kind {
                Wire::Unspecified => return None,
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

        fn kinds(tags: &[i32]) -> Option<Vec<AuditEventKind>> {
            tags.iter()
                .map(|tag| proto::AuditEventKind::try_from(*tag).ok().and_then(kind))
                .collect()
        }

        const fn timestamp(value: &prost_types::Timestamp) -> Timestamp {
            Timestamp {
                seconds: value.seconds,
                nanos: value.nanos,
            }
        }

        fn event(entry: AuditEntry) -> proto::AuditEvent {
            proto::AuditEvent {
                id: entry.id,
                kind: wire_kind(entry.kind) as i32,
                path: entry.path.as_str().to_owned(),
                occurred_at: Some(to_proto_timestamp(entry.occurred_at)),
                first_occurred_at: Some(to_proto_timestamp(entry.first_occurred_at)),
                event_count: entry.event_count,
                actor_subject: entry.actor_subject,
                actor_name: entry.actor_name,
                protocol_version: entry.protocol_version,
                old_value: entry.old_value,
                new_value: entry.new_value,
                narrative: entry.narrative,
            }
        }
    };
}

pub(super) use audit_wire;
