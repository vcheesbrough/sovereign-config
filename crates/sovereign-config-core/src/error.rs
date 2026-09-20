//! The bounded client error surface.

use std::borrow::Cow;

use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    Unauthenticated,
    PermissionDenied,
    /// This build and the service share no protocol version at all.
    ///
    /// Terminal: there is nothing to renegotiate to. Distinct from
    /// [`ErrorKind::VersionNotServed`], which is one version going away while
    /// others may remain.
    IncompatibleProtocol,
    /// The service does not serve the protocol version the request named.
    ///
    /// Raised by the service's version-not-served answer, never by the
    /// transport's generic not-found, so a retired version cannot be mistaken
    /// for a mistyped route. A client that sees it re-handshakes **once** and
    /// retries the call, which never executed.
    VersionNotServed,
    InvalidRequest,
    NotFound,
    /// The request cannot apply because the target is already taken, such as
    /// aliasing a value onto an occupied path.
    Conflict,
    Unavailable,
    Internal,
}

/// A bounded error, carrying a message safe to show an operator.
///
/// The message is usually one of a fixed set of compiled-in strings. A few
/// errors — the incompatible-version one above all — have to name what the two
/// ends actually offered, which cannot be known at compile time, so the message
/// is a [`Cow`]: borrowed for the fixed cases, owned for those. Anything built
/// from a service's answer is sanitised and length-bounded before it gets here;
/// nothing derived from a request or response reaches an operator verbatim.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{message}")]
pub struct ClientError {
    pub kind: ErrorKind,
    message: Cow<'static, str>,
}

impl ClientError {
    #[must_use]
    pub const fn new(kind: ErrorKind, message: &'static str) -> Self {
        Self {
            kind,
            message: Cow::Borrowed(message),
        }
    }

    /// An error whose message had to be assembled at run time.
    ///
    /// The caller is responsible for bounding and sanitising anything the
    /// message carries from the wire.
    #[must_use]
    pub const fn described(kind: ErrorKind, message: String) -> Self {
        Self {
            kind,
            message: Cow::Owned(message),
        }
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}
