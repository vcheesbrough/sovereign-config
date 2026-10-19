//! The `sovereign.config.v5` dialer: the shared dialer in [`super::adapter`]
//! pointed at `v5`'s generated stubs, plus `v5`'s `Audit` service, whose
//! request carries an actor filter and whose first page carries the query's
//! counts.
//!
//! Every route this module dials names `sovereign.config.v5`. Retiring `v5` is
//! deleting this file and its arm of [`super::dialer`].

use sovereign_config_core::{AuditCounts, AuditEntry, AuditEventKind, Timestamp};
use sovereign_config_proto::sovereign::config::v5 as proto;

use super::adapter::version_dialer;
use super::audit_wire::audit_wire;

version_dialer!(ProtocolVersion::V5);

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
            counts: audit_counts(response.total_count, response.match_count)?,
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
        _ => Err(invalid_response()),
    }
}

audit_wire!();

#[cfg(test)]
mod tests {
    use sovereign_config_core::{AuditCounts, AuditQuery};

    use super::{audit_counts, audit_request};

    #[test]
    fn the_actor_filter_reaches_the_wire() {
        let request = audit_request(&AuditQuery {
            actor_filter: Some("ops".into()),
            text_filter: Some("revealed".into()),
            cursor: Some("cursor-sentinel".into()),
            ..AuditQuery::default()
        });
        assert_eq!(request.actor_filter, "ops");
        assert_eq!(request.text_filter, "revealed");
        assert_eq!(request.cursor, "cursor-sentinel");
        assert_eq!(audit_request(&AuditQuery::default()).actor_filter, "");
    }

    #[test]
    fn counts_arrive_as_a_pair_or_not_at_all() {
        assert_eq!(audit_counts(None, None).unwrap(), None);
        assert_eq!(
            audit_counts(Some(120), Some(7)).unwrap(),
            Some(AuditCounts {
                total: 120,
                matching: 7
            })
        );
        assert!(audit_counts(Some(1), None).is_err());
        assert!(audit_counts(None, Some(1)).is_err());
        assert!(
            audit_counts(Some(1), Some(2)).is_err(),
            "more matches than events"
        );
    }
}
