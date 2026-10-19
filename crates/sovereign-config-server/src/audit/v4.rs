//! The `v4` wire shim over [`AuditTrailService`]: translation only.
//!
//! The kind and event mapping is shared with later versions ([`super::shim`]);
//! the request and response are `v4`'s own, which carry no actor filter and no
//! counts. A kind this build cannot name — an unknown or `UNSPECIFIED` tag —
//! makes the whole selection `None`, which the shared implementation refuses
//! before it asks who is calling.

use std::sync::Arc;

use sovereign_config_core::{AuditEntry, AuditEventKind, Timestamp};
use sovereign_config_proto::sovereign::config::v4::{
    self as proto, QueryAuditTrailRequest, QueryAuditTrailResponse, audit_server::Audit,
};
use tonic::{Request, Response, Status};

use super::service::{AuditTrailService, TrailQuery};
use super::shim::audit_wire;
use crate::rpc::{CallContext, to_proto_timestamp};

pub(crate) struct V4Audit {
    shared: Arc<AuditTrailService>,
}

impl V4Audit {
    pub(crate) const fn new(shared: Arc<AuditTrailService>) -> Self {
        Self { shared }
    }
}

audit_wire!();

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
                    actor_filter: "",
                    counts: false,
                },
            )
            .await?;
        Ok(Response::new(QueryAuditTrailResponse {
            events: page.events.into_iter().map(event).collect(),
            next_cursor: page.next_cursor.unwrap_or_default(),
        }))
    }
}
