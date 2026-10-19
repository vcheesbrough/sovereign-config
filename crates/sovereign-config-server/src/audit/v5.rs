//! The `v5` wire shim over [`AuditTrailService`]: translation only.
//!
//! `v5`'s request adds `actor_filter` and its response the first page's
//! counts; the kind and event mapping is the one `v4` uses ([`super::shim`]).

use std::sync::Arc;

use sovereign_config_core::{AuditEntry, AuditEventKind, Timestamp};
use sovereign_config_proto::sovereign::config::v5::{
    self as proto, QueryAuditTrailRequest, QueryAuditTrailResponse, audit_server::Audit,
};
use tonic::{Request, Response, Status};

use super::service::{AuditTrailService, TrailQuery};
use super::shim::audit_wire;
use crate::rpc::{CallContext, to_proto_timestamp};

pub(crate) struct V5Audit {
    shared: Arc<AuditTrailService>,
}

impl V5Audit {
    pub(crate) const fn new(shared: Arc<AuditTrailService>) -> Self {
        Self { shared }
    }
}

audit_wire!();

#[tonic::async_trait]
impl Audit for V5Audit {
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
                    actor_filter: &message.actor_filter,
                    counts: true,
                },
            )
            .await?;
        Ok(Response::new(QueryAuditTrailResponse {
            events: page.events.into_iter().map(event).collect(),
            next_cursor: page.next_cursor.unwrap_or_default(),
            total_count: page.counts.map(|counts| counts.total),
            match_count: page.counts.map(|counts| counts.matching),
        }))
    }
}
