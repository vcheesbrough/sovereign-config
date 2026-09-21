//! The `v4` wire shim over [`AuditTrailService`]: translation only.
//!
//! `v4` is the first version with an `Audit` service, so there is nothing yet to
//! share with another version's shim. A kind this build cannot name — an
//! unknown or `UNSPECIFIED` tag — makes the whole selection `None`, which the
//! shared implementation refuses before it asks who is calling.

use std::sync::Arc;

use sovereign_config_core::{AuditEntry, AuditEventKind, Timestamp};
use sovereign_config_proto::sovereign::config::v4::{
    self as proto, QueryAuditTrailRequest, QueryAuditTrailResponse, audit_server::Audit,
};
use tonic::{Request, Response, Status};

use super::service::{AuditTrailService, TrailQuery};
use crate::rpc::{CallContext, to_proto_timestamp};

pub(crate) struct V4Audit {
    shared: Arc<AuditTrailService>,
}

impl V4Audit {
    pub(crate) const fn new(shared: Arc<AuditTrailService>) -> Self {
        Self { shared }
    }
}

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

#[tonic::async_trait]
impl Audit for V4Audit {
    async fn query_audit_trail(
        &self,
        request: Request<QueryAuditTrailRequest>,
    ) -> Result<Response<QueryAuditTrailResponse>, Status> {
        let context = CallContext::from_request(&request);
        let message = request.get_ref();
        let page = self
            .shared
            .query_audit_trail(
                &context,
                TrailQuery {
                    path_filter: &message.path_filter,
                    element_path: &message.element_path,
                    text_filter: &message.text_filter,
                    from: message.from.as_ref().map(timestamp),
                    until: message.until.as_ref().map(timestamp),
                    protocol_version: &message.protocol_version,
                    kinds: kinds(&message.kinds),
                    page_size: message.page_size,
                    cursor: &message.cursor,
                },
            )
            .await?;
        Ok(Response::new(QueryAuditTrailResponse {
            events: page.events.into_iter().map(event).collect(),
            next_cursor: page.next_cursor.unwrap_or_default(),
        }))
    }
}
