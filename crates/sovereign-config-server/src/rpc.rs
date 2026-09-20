//! Helpers shared by every service in this crate: the call context a request
//! carries, timestamp mapping, and the one `Status` whose wording is common to
//! all services.

use sovereign_config_core::Timestamp;
use time::OffsetDateTime;
use tonic::{Extensions, Request, Status};

use crate::auth::AuthenticatedPrincipal;

/// Who is calling, as a protocol-version-free service implementation sees it.
///
/// Every shared implementation takes the caller as this one parameter, so a
/// later field is added here rather than to every method signature. Whatever
/// is added is data to record, never something to branch on: an implementation
/// that behaves differently per protocol version is a forked server.
pub(crate) struct CallContext<'a> {
    principal: Option<&'a AuthenticatedPrincipal>,
}

impl<'a> CallContext<'a> {
    pub(crate) fn from_request<T>(request: &'a Request<T>) -> Self {
        Self::from_extensions(request.extensions())
    }

    /// For a shim that takes its request apart to move the message rather than
    /// clone it.
    pub(crate) fn from_extensions(extensions: &'a Extensions) -> Self {
        Self {
            principal: extensions.get::<AuthenticatedPrincipal>(),
        }
    }

    /// The principal the authentication layer attached to the request.
    ///
    /// A missing principal is reported here, when it is first needed, rather
    /// than when the context is built. Each RPC has always validated some of
    /// its input before asking who is calling, and which error a doubly-wrong
    /// request receives is part of the behaviour a protocol version promises.
    #[expect(
        clippy::result_large_err,
        reason = "tonic::Status is the crate's RPC error type and is returned by value"
    )]
    pub(crate) fn principal(&self) -> Result<&'a AuthenticatedPrincipal, Status> {
        self.principal
            .ok_or_else(|| Status::unauthenticated("authentication required"))
    }
}

/// The version-free timestamp every shared implementation reports.
#[expect(
    clippy::result_large_err,
    reason = "tonic::Status is the crate's RPC error type and is returned by value"
)]
pub(crate) fn to_timestamp(value: OffsetDateTime) -> Result<Timestamp, Status> {
    Ok(Timestamp {
        seconds: value.unix_timestamp(),
        nanos: i32::try_from(value.nanosecond()).map_err(|_| invalid_timestamp())?,
    })
}

/// The well-known protobuf timestamp, which every protocol version shares.
pub(crate) const fn to_proto_timestamp(value: Timestamp) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: value.seconds,
        nanos: value.nanos,
    }
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
