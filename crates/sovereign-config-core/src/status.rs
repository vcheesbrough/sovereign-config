//! Service and authentication status reported to clients.
//!
//! Compatibility is a **range**, not an equality, and it is settled on one
//! unversioned handshake: the client sends every version it speaks, the server
//! answers with every version it serves — most preferred first — and the client
//! selects from the server's order. Clients are deployed independently of the
//! server and are expected to lag it, so a server upgrade that adds a version
//! must leave every already-deployed client negotiating exactly as before. See
//! `## Protocol versioning` in `README.md`.

use crate::{ClientError, ErrorKind};

/// The gRPC metadata key naming *which* bounded failure a status is.
///
/// **Frozen, like the handshake's message shape.** It is returned outside every
/// protocol version — a request for a version the server does not serve has no
/// version whose rules could apply to it — so no version can ever redefine it,
/// and every client from 2.28 on reads it.
///
/// It lives here, with the version-free protocol vocabulary, rather than in the
/// generated-types crate: it is a fact about the wire that belongs to no
/// package, and the server's shared implementation must be able to name it
/// without naming a protocol version's generated types.
pub const ERROR_KIND_METADATA: &str = "sovereign-config-error-kind";

/// The [`ERROR_KIND_METADATA`] value marking the version-not-served answer.
///
/// A client identifies that answer by this marker, never by the status code
/// alone: the code is shared with failures that are not about versions at all.
pub const VERSION_NOT_SERVED_KIND: &str = "version-not-served";

/// The gRPC metadata key echoing the protocol version a refused request named.
///
/// Request-derived, so a server bounds and strips it before sending and a
/// client treats it as untrusted text.
pub const REQUESTED_VERSION_METADATA: &str = "sovereign-config-protocol-version";

/// A protocol version this build speaks.
///
/// Declaration order is **preference order, most preferred first** — not
/// lexicographic, and not numeric. Nothing compares two versions: selection
/// follows the *server's* order, and this enum only answers "do we speak it?".
/// That is why there is no `Ord`; a derived one would rank `v10` below `v3` as
/// a string and invite exactly the comparison this design removed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolVersion {
    V3,
}

impl ProtocolVersion {
    /// Every version this build speaks, **most preferred first**.
    ///
    /// **A version may only appear here once a transport can actually dial it.**
    /// Negotiation selects from this list and the result is reported to
    /// operators, but the transports dispatch on compiled-in route paths — so a
    /// version listed here without matching route support would be negotiated,
    /// displayed, and then never used: every RPC would travel on the older
    /// version's routes while the client believed otherwise. That silently
    /// inverts `sovereign_config_protocol_requests_total`, which is the gate for
    /// retiring a version, so it would report the live version as dead.
    ///
    /// That cannot be reached by accident. Adding a variant to this enum is a
    /// **compile error** in `sovereign-config-native` and `sovereign-config-web`
    /// until each has a dialer for it: both select their route set with an
    /// exhaustive `match` over [`ProtocolVersion`]. Write the dialer, and the
    /// build goes green; there is nothing to remember and no test to silence.
    pub const ALL: &'static [Self] = &[Self::V3];

    /// The version a client prefers when the server expresses no preference:
    /// the first of [`ProtocolVersion::ALL`].
    pub const PREFERRED: Self = Self::V3;

    /// The one version a server that has **no handshake** serves.
    ///
    /// Every server up to 2.27 routes `GetVersion` by version and serves
    /// exactly `v3`, so a client that finds no handshake speaks this and
    /// nothing else. Naming it once means that retiring `V3` from the
    /// enumeration fails to compile here, rather than leaving the fallback
    /// pointing at a version no dialer exists for.
    pub const LEGACY: Self = Self::V3;

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

/// One protocol version a service serves, as the handshake reported it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServedVersion {
    /// The version's identifier, exactly as the service spelled it. Untrusted:
    /// it is compared against compiled-in strings and never used as a label.
    pub version: String,
    /// An RFC 3339 UTC timestamp before which the service does not expect to
    /// retire this version, when it named one.
    ///
    /// Advisory. A client warns its operator and **never fails** because of it.
    pub deprecation_date: Option<String>,
}

impl ServedVersion {
    /// A version served with no announced retirement date.
    #[must_use]
    pub fn new(version: &str) -> Self {
        Self {
            version: version.to_owned(),
            deprecation_date: None,
        }
    }
}

/// How many served versions an error message will name, and how long each may
/// be.
///
/// The served list arrives from a public endpoint over the network, and its
/// only use in an error is to tell an operator what the two ends offered. These
/// bounds are what stop a hostile or broken service turning that into an
/// unbounded string in a log, a terminal, or a browser.
const NAMED_VERSION_LIMIT: usize = 8;
const NAMED_VERSION_LENGTH: usize = 16;

/// `version` reduced to something safe to put in an operator-facing message.
///
/// Anything outside the character set a version identifier may use becomes `?`,
/// so no control character, quote or newline from the wire can reach a log line
/// or a terminal, and the result is truncated.
fn sanitise(version: &str) -> String {
    version
        .chars()
        .take(NAMED_VERSION_LENGTH)
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                character
            } else {
                '?'
            }
        })
        .collect()
}

/// How much of a deprecation date is kept before it is truncated.
///
/// An RFC 3339 timestamp with a numeric offset and fractional seconds is
/// comfortably shorter than this.
const DEPRECATION_DATE_LENGTH: usize = 40;

/// `date` reduced to something safe to show an operator.
///
/// The same reasoning as [`sanitise`], for a timestamp's character set: RFC
/// 3339 also needs `:` and `+`. This matters because a deprecation date is the
/// one piece of handshake text that is *shown* rather than compared — it
/// reaches a structured log, a terminal, an MCP tool result and the page — so
/// without this a hostile or broken service could put a control character, an
/// ANSI escape or a megabyte of text into all four.
fn sanitise_date(date: &str) -> String {
    date.chars()
        .take(DEPRECATION_DATE_LENGTH)
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, ':' | '+' | '-' | '.') {
                character
            } else {
                '?'
            }
        })
        .collect()
}

/// The served list rendered for an error message: bounded in both directions.
fn describe_served(served: &[ServedVersion]) -> String {
    if served.is_empty() {
        return "none".to_owned();
    }
    let named: Vec<String> = served
        .iter()
        .take(NAMED_VERSION_LIMIT)
        .map(|entry| sanitise(&entry.version))
        .collect();
    let mut description = named.join(", ");
    if served.len() > NAMED_VERSION_LIMIT {
        description.push_str(", …");
    }
    description
}

/// Every version this build speaks, rendered for an error message.
fn describe_spoken() -> String {
    ProtocolVersion::ALL
        .iter()
        .map(|version| version.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The error raised when this build and a service share no protocol version.
///
/// It names **both** lists. A bare "incompatible" tells an operator nothing
/// they can act on; which versions each end offered tells them whether to
/// upgrade the client or the server.
fn incompatible(served: &[ServedVersion]) -> ClientError {
    ClientError::described(
        ErrorKind::IncompatibleProtocol,
        format!(
            "service protocol is incompatible: this client speaks {}, the service serves {}",
            describe_spoken(),
            describe_served(served),
        ),
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceStatus {
    /// The version the session speaks, already known to be one this build
    /// supports.
    pub protocol_version: ProtocolVersion,
    /// Set when the selected version carries an announced retirement date,
    /// which every client surfaces to its operator as a warning.
    pub deprecation_date: Option<String>,
}

impl ServiceStatus {
    /// Selects the session's version from the set a service serves.
    ///
    /// Follows the **service's** preference order, not this build's: the first
    /// entry both ends speak wins, except that a version carrying a deprecation
    /// date is passed over while a version without one is still to come. A
    /// version only the service speaks is never a candidate — there is no
    /// dialer for it.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::IncompatibleProtocol`], naming both lists, when no
    /// version is common to this build and the service.
    pub fn select(served: &[ServedVersion]) -> Result<Self, ClientError> {
        let mut deprecated: Option<&ServedVersion> = None;
        for entry in served {
            let Some(version) = ProtocolVersion::parse(&entry.version) else {
                continue;
            };
            if entry.deprecation_date.is_none() {
                return Ok(Self {
                    protocol_version: version,
                    deprecation_date: None,
                });
            }
            // Keep the first deprecated candidate, but keep looking: a
            // non-deprecated version further down the service's order is the
            // better choice, even though the service prefers this one.
            deprecated.get_or_insert(entry);
        }

        deprecated
            .and_then(|entry| {
                ProtocolVersion::parse(&entry.version).map(|version| Self {
                    protocol_version: version,
                    // Sanitised here, at the one seam every client passes
                    // through, so none of them has to remember to do it.
                    deprecation_date: entry.deprecation_date.as_deref().map(sanitise_date),
                })
            })
            .ok_or_else(|| incompatible(served))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticationStatus {
    pub authenticated: bool,
}
