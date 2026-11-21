//! The `sovereign.config.v6` dialer for the browser: the shared dialer in
//! [`super::adapter`] pointed at `v6`'s messages and routes and dialling
//! Connect unary ([`super::connect_unary`]), plus `v6`'s `Audit` service —
//! `v5`'s shape, with 32-bit counts and a string event id.
//!
//! Every route here names `sovereign.config.v6`. Retiring `v6` is deleting this
//! file and its arm of [`super::dialer`].

use sovereign_config_core::{AuditCounts, AuditEntry, AuditEventKind};
use sovereign_config_proto::sovereign::config::v6 as proto;

use super::adapter::version_dialer;
use super::audit_wire::audit_wire;

version_dialer!(ProtocolVersion::V6, "v6", connect_unary);

const QUERY_AUDIT_TRAIL: &str = "/sovereign.config.v6.Audit/QueryAuditTrail";

/// The routes `v6` dials beyond the surface every version shares.
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
            unary(QUERY_AUDIT_TRAIL, &audit_request(query), Some(bearer)).await?;
        Ok(AuditPage {
            events: response
                .events
                .into_iter()
                .map(audit_entry)
                .collect::<Result<Vec<_>, ClientError>>()?,
            next_cursor: (!response.next_cursor.is_empty()).then_some(response.next_cursor),
            counts: audit_counts(
                response.total_count.map(u64::from),
                response.match_count.map(u64::from),
            )?,
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
        actor_filter: query.actor_filter.clone().unwrap_or_default(),
    }
}

/// The counts a first page carries. They come as a pair or not at all; one
/// without the other, or more matches than events, is a broken response.
fn audit_counts(
    total: Option<u64>,
    matching: Option<u64>,
) -> Result<Option<AuditCounts>, ClientError> {
    match (total, matching) {
        (None, None) => Ok(None),
        (Some(total), Some(matching)) if matching <= total => {
            Ok(Some(AuditCounts { total, matching }))
        }
        _ => Err(browser_error()),
    }
}

audit_wire!();
