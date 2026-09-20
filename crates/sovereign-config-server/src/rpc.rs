//! Helpers shared by every service in this crate: the call context a request
//! carries, timestamp mapping, and the one `Status` whose wording is common to
//! all services.

use sovereign_config_core::Timestamp;
use time::OffsetDateTime;
use tonic::{Extensions, Request, Status};

use crate::audit::Actor;
use crate::auth::AuthenticatedPrincipal;
use crate::protocol::NegotiatedProtocolVersion;

/// The protocol version recorded for a call that carries no version extension.
///
/// Unreachable in a running server: a handler is only reachable on a served
/// route, and [`crate::protocol::ProtocolVersionLayer`] attaches the served
/// label to every one. It exists for a service driven directly, without the
/// layer stack — and it is a label rather than an error because the version is
/// data to record, never something a call may succeed or fail on.
pub(crate) const UNATTRIBUTED_PROTOCOL_LABEL: &str = "unattributed";

/// Who is calling, as a protocol-version-free service implementation sees it.
///
/// Every shared implementation takes the caller as this one parameter, so a
/// later field is added here rather than to every method signature. Whatever
/// is added is data to record, never something to branch on: an implementation
/// that behaves differently per protocol version is a forked server.
pub(crate) struct CallContext<'a> {
    principal: Option<&'a AuthenticatedPrincipal>,
    protocol_version: Option<&'static str>,
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
            // The label of the route actually dialled, so a shim cannot state
            // it wrongly: shims are made by copying the previous version's,
            // and a constant copied and left unchanged would attribute every
            // call on the new version to the old one.
            protocol_version: extensions
                .get::<NegotiatedProtocolVersion>()
                .and_then(|negotiated| negotiated.0),
        }
    }

    /// The principal the authentication layer attached to the request.
    ///
    /// A missing principal is reported here, when it is first needed, rather
    /// than when the context is built. RPCs differ in whether they validate
    /// their input or ask who is calling first, and reporting it lazily keeps
    /// each one's order as it was. This is a fail-closed backstop rather than a
    /// client-visible contract: the authentication layer never lets a request
    /// without a principal reach a handler. The order is kept because keeping
    /// it is free, and `values/tests.rs` pins it against an eager rewrite.
    #[expect(
        clippy::result_large_err,
        reason = "tonic::Status is the crate's RPC error type and is returned by value"
    )]
    pub(crate) fn principal(&self) -> Result<&'a AuthenticatedPrincipal, Status> {
        self.principal
            .ok_or_else(|| Status::unauthenticated("authentication required"))
    }

    /// Who the audit trail attributes this call to, and the protocol version
    /// they spoke. Reports a missing principal exactly as [`Self::principal`]
    /// does; every caller has already authorized by the time it records.
    #[expect(
        clippy::result_large_err,
        reason = "tonic::Status is the crate's RPC error type and is returned by value"
    )]
    pub(crate) fn actor(&self) -> Result<Actor<'a>, Status> {
        let principal = self.principal()?;
        Ok(Actor {
            subject: &principal.subject,
            name: principal.name.as_deref(),
            protocol_version: self.protocol_version.unwrap_or(UNATTRIBUTED_PROTOCOL_LABEL),
        })
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
