//! The `sovereign.config.v3` dialer for the browser: the shared dialer in
//! [`super::adapter`] pointed at `v3`'s messages and routes.
//!
//! Every route here names `sovereign.config.v3`, because the gRPC route path
//! embeds the package name. That is what makes a version's dispatch deletable:
//! retiring `v3` is deleting this file and its arm of [`super::dialer`].
//!
//! `v3` has no `Audit` service, so an audit query is answered here, bounded,
//! and posts nothing.

use sovereign_config_client::audit_not_available;
use sovereign_config_proto::sovereign::config::v3 as proto;

use super::adapter::version_dialer;

version_dialer!(ProtocolVersion::V3, "v3");

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
