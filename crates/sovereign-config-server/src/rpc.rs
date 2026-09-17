//! Helpers shared by every tonic service in this crate: the authenticated
//! principal a request carries, timestamp mapping, and the one `Status` whose
//! wording is common to all services.

use time::OffsetDateTime;
use tonic::{Request, Status};

use crate::auth::AuthenticatedPrincipal;

/// The principal the authentication layer attached to `request`.
#[expect(
    clippy::result_large_err,
    reason = "tonic::Status is the crate's RPC error type and is returned by value"
)]
pub(crate) fn principal<T>(request: &Request<T>) -> Result<&AuthenticatedPrincipal, Status> {
    request
        .extensions()
        .get::<AuthenticatedPrincipal>()
        .ok_or_else(|| Status::unauthenticated("authentication required"))
}

#[expect(
    clippy::result_large_err,
    reason = "tonic::Status is the crate's RPC error type and is returned by value"
)]
pub(crate) fn to_proto_timestamp(value: OffsetDateTime) -> Result<prost_types::Timestamp, Status> {
    Ok(prost_types::Timestamp {
        seconds: value.unix_timestamp(),
        nanos: i32::try_from(value.nanosecond()).map_err(|_| invalid_timestamp())?,
    })
}

/// Message of [`storage_unavailable`]; exported so metrics can classify the
/// outcome by matching it, exactly as before the helper was shared.
pub(crate) const STORAGE_UNAVAILABLE_MESSAGE: &str = "configuration storage is unavailable";

pub(crate) fn storage_unavailable() -> Status {
    Status::unavailable(STORAGE_UNAVAILABLE_MESSAGE)
}

fn invalid_timestamp() -> Status {
    Status::internal("configuration timestamp is invalid")
}
