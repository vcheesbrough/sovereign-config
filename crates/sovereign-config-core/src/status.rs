//! Service and authentication status reported to clients.
//!
//! Compatibility is a **range**, not an equality. A client speaks the set of
//! versions in [`ProtocolVersion::ALL`]; a server answers with the set it
//! serves; the session speaks the highest version in both. Clients are deployed
//! independently of the server and are expected to lag it, so a server upgrade
//! that adds a version must leave every already-deployed client negotiating
//! exactly as before. See `## Protocol versioning` in `README.md`.

use crate::{ClientError, ErrorKind};

/// A protocol version this build speaks.
///
/// Ordering is **declaration order**, not lexicographic: `"v10" < "v3"` as
/// strings, so comparing version strings would rank a tenth version below a
/// third one and negotiate the wrong session. Declare variants oldest-first and
/// keep [`ProtocolVersion::ALL`] in the same order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProtocolVersion {
    V3,
}

impl ProtocolVersion {
    /// Every version this build speaks, oldest first.
    pub const ALL: &'static [Self] = &[Self::V3];

    /// The version a client asks for when it has no reason to ask for an older
    /// one: the newest it speaks.
    pub const PREFERRED: Self = Self::V3;

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V3 => "v3",
        }
    }

    /// The version named by `text`, or `None` when this build does not speak it.
    ///
    /// A version this build has never heard of is not an error — a newer server
    /// may offer versions from the future, and they are simply not candidates.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|version| version.as_str() == text)
    }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The highest version both this build and `server_supported` speak.
///
/// `echoed` is the server's `protocol_version` field and is used alone when
/// `server_supported` is empty, which is how a server older than 2.25.0 answers.
fn select(echoed: &str, server_supported: &[String]) -> Option<ProtocolVersion> {
    if server_supported.is_empty() {
        return ProtocolVersion::parse(echoed);
    }
    // `rev()`: `ALL` is oldest-first, so the first match walking backwards is
    // the highest version both ends speak. A version only the server speaks is
    // never a candidate, because it is not in `ALL`.
    ProtocolVersion::ALL.iter().rev().copied().find(|version| {
        server_supported
            .iter()
            .any(|offered| offered == version.as_str())
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceStatus {
    pub application_version: String,
    /// The version the session speaks, already known to be one this build
    /// supports.
    pub protocol_version: ProtocolVersion,
}

impl ServiceStatus {
    /// Negotiates the session version against the set a server advertises.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::IncompatibleProtocol`] when no version is common to
    /// this build and the server.
    pub fn negotiate(
        application_version: String,
        echoed_protocol_version: &str,
        server_supported: &[String],
    ) -> Result<Self, ClientError> {
        let protocol_version =
            select(echoed_protocol_version, server_supported).ok_or(ClientError::new(
                ErrorKind::IncompatibleProtocol,
                "service protocol is incompatible",
            ))?;
        Ok(Self {
            application_version,
            protocol_version,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticationStatus {
    pub authenticated: bool,
}
