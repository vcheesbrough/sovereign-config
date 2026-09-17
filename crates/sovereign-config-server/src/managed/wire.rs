//! Mapping a stored connection onto its wire metadata, and the bounded
//! `Status` values every managed-connection RPC returns.

use sovereign_config_core::{ManagedConnectionState, ManagedPermissions};
use sovereign_config_proto::sovereign::config::v3::{
    ManagedConnectionMetadata as ProtoManagedConnectionMetadata,
    ManagedConnectionState as ProtoManagedConnectionState,
};
use tonic::Status;

use super::store::ConnectionRow;
use crate::rpc::to_proto_timestamp;

#[expect(
    clippy::result_large_err,
    reason = "tonic::Status is the crate's RPC error type and is returned by value"
)]
pub(super) fn proto_metadata(
    row: &ConnectionRow,
) -> Result<ProtoManagedConnectionMetadata, Status> {
    let state = ManagedConnectionState::parse(&row.state).map_err(|_| internal_error())?;
    let permissions = ManagedPermissions::parse(&row.permissions).map_err(|_| internal_error())?;
    Ok(ProtoManagedConnectionMetadata {
        connection_id: row.connection_id.clone(),
        display_name: row.display_name.clone(),
        root: row.root.clone(),
        state: proto_state(state) as i32,
        permissions: permissions.to_proto(),
        created_at: Some(to_proto_timestamp(row.created_at)?),
        updated_at: Some(to_proto_timestamp(row.updated_at)?),
    })
}

pub(super) const fn proto_state(state: ManagedConnectionState) -> ProtoManagedConnectionState {
    match state {
        ManagedConnectionState::Provisioning => ProtoManagedConnectionState::Provisioning,
        ManagedConnectionState::Active => ProtoManagedConnectionState::Active,
        ManagedConnectionState::RotationUnknown => ProtoManagedConnectionState::RotationUnknown,
        ManagedConnectionState::Revoking => ProtoManagedConnectionState::Revoking,
        ManagedConnectionState::CleanupRequired => ProtoManagedConnectionState::CleanupRequired,
    }
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
