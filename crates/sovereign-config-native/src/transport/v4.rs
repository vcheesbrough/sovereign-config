//! The `sovereign.config.v4` dialer: the shared dialer in [`super::adapter`]
//! pointed at `v4`'s generated stubs, plus `v4`'s `Audit` service.
//!
//! Every route this module dials names `sovereign.config.v4`. Retiring `v4` is
//! deleting this file and its arm of [`super::dialer`].

use sovereign_config_core::{AuditEntry, AuditEventKind, Timestamp};
use sovereign_config_proto::sovereign::config::v4 as proto;

use super::adapter::version_dialer;

version_dialer!(ProtocolVersion::V4);

impl Dialer {
    fn audit(&self) -> proto::audit_client::AuditClient<Channel> {
        proto::audit_client::AuditClient::new(self.channel.clone())
    }
}

#[async_trait(?Send)]
impl AuditTransport for Dialer {
    async fn query_audit_trail(
        &self,
        query: &AuditQuery,
        bearer: &Secret,
    ) -> Result<AuditPage, ClientError> {
        let response = self
            .audit()
            .query_audit_trail(authenticated_request(audit_request(query), bearer)?)
            .await
            .map_err(|status| map_status(&status))?
            .into_inner();
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
    Ok(match Wire::try_from(tag).map_err(|_| invalid_response())? {
        Wire::Unspecified => return Err(invalid_response()),
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
    let occurred_at = event.occurred_at.ok_or_else(invalid_response)?;
    let first_occurred_at = event.first_occurred_at.ok_or_else(invalid_response)?;
    Ok(AuditEntry {
        id: event.id,
        kind: audit_kind(event.kind)?,
        path: ConfigPath::parse_selection(event.path).map_err(|_| invalid_response())?,
        occurred_at: timestamp(occurred_at.seconds, occurred_at.nanos)?,
        first_occurred_at: timestamp(first_occurred_at.seconds, first_occurred_at.nanos)?,
        event_count: event.event_count,
        actor_subject: event.actor_subject,
        actor_name: event.actor_name,
        protocol_version: event.protocol_version,
        old_value: event.old_value,
        new_value: event.new_value,
        narrative: event.narrative,
    })
}
