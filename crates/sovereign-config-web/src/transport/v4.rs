//! The `sovereign.config.v4` dialer for the browser: the shared dialer in
//! [`super::adapter`] pointed at `v4`'s messages and routes, plus `v4`'s
//! `Audit` service.
//!
//! Every route here names `sovereign.config.v4`. Retiring `v4` is deleting this
//! file and its arm of [`super::dialer`].

use sovereign_config_core::{AuditEntry, AuditEventKind};
use sovereign_config_proto::sovereign::config::v4 as proto;

use super::adapter::version_dialer;

version_dialer!(ProtocolVersion::V4, "v4");

const QUERY_AUDIT_TRAIL: &str = "/sovereign.config.v4.Audit/QueryAuditTrail";

/// The routes `v4` dials beyond the surface every version shares.
#[cfg(test)]
pub(super) const AUDIT_ROUTES: &[&str] = &[QUERY_AUDIT_TRAIL];

#[async_trait(?Send)]
impl AuditTransport for Dialer {
    async fn query_audit_trail(
        &self,
        query: &AuditQuery,
        bearer: &Secret,
    ) -> Result<AuditPage, ClientError> {
        let response: proto::QueryAuditTrailResponse =
            grpc_unary(QUERY_AUDIT_TRAIL, &audit_request(query), Some(bearer)).await?;
        Ok(AuditPage {
            events: response
                .events
                .into_iter()
                .map(audit_entry)
                .collect::<Result<Vec<_>, ClientError>>()?,
            next_cursor: (!response.next_cursor.is_empty()).then_some(response.next_cursor),
        })
    }
}

fn audit_request(query: &AuditQuery) -> proto::QueryAuditTrailRequest {
    let wire_time = |at: &Timestamp| prost_types::Timestamp {
        seconds: at.seconds,
        nanos: at.nanos,
    };
    proto::QueryAuditTrailRequest {
        path_filter: query.path_filter.clone().unwrap_or_default(),
        element_path: query
            .element_path
            .as_ref()
            .map(|path| path.as_str().to_owned())
            .unwrap_or_default(),
        text_filter: query.text_filter.clone().unwrap_or_default(),
        from: query.from.as_ref().map(wire_time),
        until: query.until.as_ref().map(wire_time),
        protocol_version: query.protocol_version.clone().unwrap_or_default(),
        kinds: query
            .kinds
            .iter()
            .map(|kind| wire_kind(*kind) as i32)
            .collect(),
        page_size: query.page_size,
        cursor: query.cursor.clone().unwrap_or_default(),
    }
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
        id: event.id,
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
