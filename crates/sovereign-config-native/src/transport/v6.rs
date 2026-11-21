//! The `sovereign.config.v6` dialer: the shared dialer in [`super::adapter`]
//! over Connect unary ([`super::connect`]) rather than tonic, plus `v6`'s
//! `Audit` service — `v5`'s shape, with 32-bit counts and a string event id.
//!
//! `v6` is served over Connect only, so its "stubs" are the hand-written
//! clients in [`proto`], shaped like tonic's so the shared dialer calls them
//! unchanged; the messages are `v6`'s prost types.
//!
//! Every route this module dials names `sovereign.config.v6`. Retiring `v6` is
//! deleting this file and its arm of [`super::dialer`].

use super::connect::ConnectChannel;
use sovereign_config_core::{AuditCounts, AuditEntry, AuditEventKind, Timestamp};

use super::adapter::version_dialer;
use super::audit_wire::audit_wire;

/// `v6`'s messages, and Connect clients standing where tonic's would.
mod proto {
    pub(super) use sovereign_config_proto::sovereign::config::v6::*;

    use crate::transport::connect::connect_client;

    connect_client!(system_client, SystemClient, "System", {
        get_version => "GetVersion" (GetVersionRequest) -> GetVersionResponse,
        get_identity => "GetIdentity" (GetIdentityRequest) -> GetIdentityResponse,
    });

    connect_client!(configuration_client, ConfigurationClient, "Configuration", {
        list_values => "ListValues" (ListValuesRequest) -> ListValuesResponse,
        get_sub_tree => "GetSubTree" (GetSubTreeRequest) -> GetSubTreeResponse,
        put_value => "PutValue" (PutValueRequest) -> PutValueResponse,
        replace_sub_tree => "ReplaceSubTree" (ReplaceSubTreeRequest) -> ReplaceSubTreeResponse,
        delete_values => "DeleteValues" (DeleteValuesRequest) -> DeleteValuesResponse,
        reveal_secret => "RevealSecret" (RevealSecretRequest) -> RevealSecretResponse,
        add_value_path => "AddValuePath" (AddValuePathRequest) -> AddValuePathResponse,
        list_value_paths => "ListValuePaths" (ListValuePathsRequest) -> ListValuePathsResponse,
    });

    connect_client!(managed_connections_client, ManagedConnectionsClient, "ManagedConnections", {
        list_managed_connections => "ListManagedConnections" (ListManagedConnectionsRequest) -> ListManagedConnectionsResponse,
        create_managed_connection => "CreateManagedConnection" (CreateManagedConnectionRequest) -> CreateManagedConnectionResponse,
        rotate_managed_connection => "RotateManagedConnection" (RotateManagedConnectionRequest) -> RotateManagedConnectionResponse,
        revoke_managed_connection => "RevokeManagedConnection" (RevokeManagedConnectionRequest) -> RevokeManagedConnectionResponse,
    });

    connect_client!(audit_client, AuditClient, "Audit", {
        query_audit_trail => "QueryAuditTrail" (QueryAuditTrailRequest) -> QueryAuditTrailResponse,
    });
}

version_dialer!(ProtocolVersion::V6, ConnectChannel);

impl Dialer {
    fn audit(&self) -> proto::audit_client::AuditClient<ConnectChannel> {
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
        _ => Err(invalid_response()),
    }
}

audit_wire!();
