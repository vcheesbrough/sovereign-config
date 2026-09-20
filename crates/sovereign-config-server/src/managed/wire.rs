//! A stored connection as every protocol version reports it, and the bounded
//! `Status` values every managed-connection operation returns.

use sovereign_config_core::{ConnectionUrl, ManagedConnectionState, ManagedPermissions, Timestamp};
use tonic::Status;

use super::store::ConnectionRow;
use crate::rpc::to_timestamp;

/// A stored connection's metadata, in no protocol version's terms.
///
/// `connection_id`, `display_name` and `root` stay the stored strings rather
/// than core's validated types, because they have always been reported
/// verbatim. `display_name` is the one the schema cannot prove re-parses: its
/// constraint is a POSIX character class under the database collation, not
/// [`sovereign_config_core::DisplayName`]'s Unicode rule, so parsing it here
/// could let a row that lists today start failing the whole listing. The other
/// two stay strings beside it rather than leave the struct half-validated.
pub(super) struct ConnectionMetadata {
    pub(super) connection_id: String,
    pub(super) display_name: String,
    pub(super) root: String,
    pub(super) state: ManagedConnectionState,
    pub(super) permissions: ManagedPermissions,
    pub(super) created_at: Timestamp,
    pub(super) updated_at: Timestamp,
}

/// A connection together with the URL that is returned exactly once, by the
/// create or rotate that minted its credential.
pub(super) struct ProvisionedConnection {
    pub(super) metadata: ConnectionMetadata,
    pub(super) connection_url: ConnectionUrl,
}

#[expect(
    clippy::result_large_err,
    reason = "tonic::Status is the crate's RPC error type and is returned by value"
)]
pub(super) fn metadata(row: &ConnectionRow) -> Result<ConnectionMetadata, Status> {
    let state = ManagedConnectionState::parse(&row.state).map_err(|_| internal_error())?;
    let permissions = ManagedPermissions::parse(&row.permissions).map_err(|_| internal_error())?;
    Ok(ConnectionMetadata {
        connection_id: row.connection_id.clone(),
        display_name: row.display_name.clone(),
        root: row.root.clone(),
        state,
        permissions,
        created_at: to_timestamp(row.created_at)?,
        updated_at: to_timestamp(row.updated_at)?,
    })
}

pub(super) fn invalid_request() -> Status {
    Status::invalid_argument("managed connection request is invalid")
}

pub(super) fn not_found() -> Status {
    Status::not_found("managed connection not found")
}

pub(super) fn conflict_error() -> Status {
    Status::aborted("managed connection operation is already in progress")
}

pub(super) fn dependency_error() -> Status {
    Status::unavailable("managed connection dependency is unavailable")
}

pub(super) fn internal_error() -> Status {
    Status::internal("managed connection state is invalid")
}
