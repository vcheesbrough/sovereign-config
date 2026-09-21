//! The `sovereign.config.v3` dialer: the shared dialer in [`super::adapter`]
//! pointed at `v3`'s generated stubs.
//!
//! Every route this module dials names `sovereign.config.v3`, because tonic
//! builds each route path from the package its stubs were generated for. That
//! is what makes a version's dispatch deletable: retiring `v3` is deleting this
//! file and its arm of [`super::dialer`].
//!
//! `v3` has no `Audit` service, so an audit query is answered here, bounded,
//! and dials nothing.

use sovereign_config_client::audit_not_available;
use sovereign_config_proto::sovereign::config::v3 as proto;

use super::adapter::version_dialer;

version_dialer!(ProtocolVersion::V3);

#[async_trait(?Send)]
impl AuditTransport for Dialer {
    async fn query_audit_trail(
        &self,
        _: &AuditQuery,
        _: &Secret,
    ) -> Result<AuditPage, ClientError> {
        Err(audit_not_available(VERSION))
    }
}
