//! The `System` service: protocol negotiation and authenticated identity, once
//! per protocol version — [`SystemService`] for `v3` and [`V4System`] for `v4`.
//! It stays per-version, unlike every other service, because `GetVersion` is
//! version-specific by nature: each version answers on its own route, in its
//! own message, with its own promised ordering.
//!
//! `GetVersion` is **`v3`'s** view of the served set, not the handshake. The
//! handshake ([`crate::handshake`]) is unversioned and is what a current client
//! negotiates on; this RPC predates it, and every rule below exists because a
//! client compiled before 2.28 is still reading it. Its behaviour — the echo,
//! the fallback, the ordering — is `v3` behaviour and cannot change without a
//! new protocol version.
//!
//! The served list itself lives here because this is where it has always lived,
//! and both readers — this RPC and the handshake — take it from one place.
//! See `## Protocol versioning` in `README.md`.

use sovereign_config_core::ProtocolVersion;
use sovereign_config_proto::sovereign::config::{
    v3::{
        GetIdentityRequest, GetIdentityResponse, GetVersionRequest, GetVersionResponse,
        system_server::System,
    },
    v4,
};
use tonic::{Extensions, Request, Response, Status};

use crate::{APPLICATION_VERSION, auth::AuthenticatedPrincipal};

/// One protocol version this binary routes, and when it is expected to go.
pub(crate) struct ServedProtocol {
    pub(crate) version: ProtocolVersion,
    /// Where this version falls in **age** order: lower is older.
    ///
    /// Deliberately its own field rather than inferred from this list's order,
    /// which is *preference* — a free compile-time choice. A developer will
    /// usually prefer the newest version, but is not required to: preferring an
    /// established version while a newer one soaks is a legitimate thing to
    /// want, and then preference is no longer reverse-age.
    ///
    /// `v3`'s advertised set is contractually **oldest first**, and that is
    /// `v3` behaviour which cannot change without a new protocol version. It is
    /// therefore derived from this field and never from preference, so that
    /// reordering preference cannot silently rewrite a released version's
    /// contract.
    pub(crate) age: u8,
    /// An RFC 3339 UTC timestamp before which this version is not expected to
    /// be retired, or `None` when no retirement has been announced.
    ///
    /// **Compiled in, not configured.** The routes it describes are compiled in
    /// too, and a date that could drift from the binary serving it would
    /// announce a retirement the running server had not made — or hide one it
    /// had. Announcing a date is a release, like every other change to what is
    /// served.
    pub(crate) deprecation_date: Option<&'static str>,
}

/// Every protocol version **this binary routes**, **most preferred first**.
///
/// Deliberately its own list rather than an alias of [`ProtocolVersion::ALL`],
/// which is the set the *client* crates can speak. The two are different facts
/// and must move independently: declaring a variant in core says "a client in
/// this workspace can speak it", while naming it here says "this server has a
/// service registered for it". Aliasing them would make those one edit, and a
/// version declared but not yet registered would be advertised immediately —
/// negotiation would succeed and then every RPC on it would return the
/// version-not-served error.
///
/// Adding a version here is therefore the *last* step of introducing one: the
/// `add_service` call for it must already be on the router. Removing one is the
/// last step of retiring it, gated on the `outcome="authenticated"` series of
/// `sovereign_config_protocol_requests_total` reading zero for that version —
/// see the README.
pub(crate) const SERVED_PROTOCOL_VERSIONS: &[ServedProtocol] = &[
    ServedProtocol {
        version: ProtocolVersion::V4,
        age: 4,
        deprecation_date: None,
    },
    ServedProtocol {
        version: ProtocolVersion::V3,
        age: 3,
        deprecation_date: None,
    },
];

/// The metric label for every version in [`SERVED_PROTOCOL_VERSIONS`], in the
/// same order.
///
/// Spelled out rather than derived, because a `const` cannot map a slice; the
/// test below is what keeps the two in step. Compiled-in labels are what keep
/// `sovereign_config_protocol_requests_total` bounded.
pub(crate) const SERVED_PROTOCOL_LABELS: &[&str] =
    &[ProtocolVersion::V4.as_str(), ProtocolVersion::V3.as_str()];

/// The version a request that names no version this server serves is told about:
/// the most preferred served version.
fn preferred_served() -> &'static str {
    SERVED_PROTOCOL_VERSIONS
        .first()
        .expect("the server must serve at least one protocol version")
        .version
        .as_str()
}

pub(crate) fn served(requested: &str) -> bool {
    SERVED_PROTOCOL_VERSIONS
        .iter()
        .any(|served| served.version.as_str() == requested)
}

/// The served set as **`v3`** reports it: oldest first.
///
/// `v3` advertised this list oldest-first from the day the field was added, and
/// a `v3` client reading it is entitled to that order. The handshake reports
/// the same versions most-preferred-first; the difference is not an
/// inconsistency but the point — each contract keeps its own promise.
///
/// Sorted by [`ServedProtocol::age`], never by reversing the list. The list's
/// own order is preference, which is free to be anything, so recovering age
/// from it would make a preference change silently alter what `v3` advertises.
fn advertised_to_v3(served: &[ServedProtocol]) -> Vec<String> {
    oldest_first(served)
        .into_iter()
        .map(|entry| entry.version.as_str().to_owned())
        .collect()
}

/// `served` in age order, oldest first.
///
/// Split out from [`advertised_to_v3`] so the ordering can be asserted on its
/// own. `ProtocolVersion` has a single variant today, so every entry of any
/// test fixture renders to the same string — which would make an assertion on
/// the advertised names pass no matter what this did. Returning the entries
/// lets a test check the order that was actually chosen.
fn oldest_first(served: &[ServedProtocol]) -> Vec<&ServedProtocol> {
    let mut sorted: Vec<&ServedProtocol> = served.iter().collect();
    sorted.sort_by_key(|entry| entry.age);
    sorted
}

fn v3_supported_protocol_versions() -> Vec<String> {
    advertised_to_v3(SERVED_PROTOCOL_VERSIONS)
}

/// The served set as **`v4`** reports it: most preferred first, the order the
/// handshake reports. `v4` is free to choose, because it is a new contract;
/// `v3` is not, and keeps its own order.
fn v4_supported_protocol_versions() -> Vec<String> {
    SERVED_PROTOCOL_VERSIONS
        .iter()
        .map(|entry| entry.version.as_str().to_owned())
        .collect()
}

/// The version a session is told it will speak: the one it asked for whenever
/// that is served. Shared by every version's `GetVersion`, because the echo is
/// the one rule no version may change — see [`SystemService::get_version`].
fn echoed(requested: String) -> String {
    if served(&requested) {
        requested
    } else {
        preferred_served().to_owned()
    }
}

#[expect(
    clippy::result_large_err,
    reason = "tonic::Status is the crate's RPC error type and is returned by value"
)]
fn require_principal(extensions: &Extensions) -> Result<(), Status> {
    if extensions.get::<AuthenticatedPrincipal>().is_none() {
        return Err(Status::unauthenticated("authentication required"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemService;

#[tonic::async_trait]
impl System for SystemService {
    async fn get_version(
        &self,
        request: Request<GetVersionRequest>,
    ) -> Result<Response<GetVersionResponse>, Status> {
        let requested = request.into_inner().protocol_version;

        // Echo the *requested* version whenever it is served. Clients compiled
        // before `supported_protocol_versions` existed compare this field
        // against the single version they know, so echoing this server's
        // preferred version instead would fail every deployed client the day a
        // newer version ships. Only a request for a version this server does
        // not serve at all falls back — a client that asks for a version it
        // speaks can never see that, so the guarantee holds.
        Ok(Response::new(GetVersionResponse {
            application_version: APPLICATION_VERSION.to_owned(),
            protocol_version: echoed(requested),
            supported_protocol_versions: v3_supported_protocol_versions(),
        }))
    }

    async fn get_identity(
        &self,
        request: Request<GetIdentityRequest>,
    ) -> Result<Response<GetIdentityResponse>, Status> {
        require_principal(request.extensions())?;
        Ok(Response::new(GetIdentityResponse {
            authenticated: true,
        }))
    }
}

/// `v4`'s `System`: the same echo as `v3`, and the served set most preferred
/// first.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct V4System;

#[tonic::async_trait]
impl v4::system_server::System for V4System {
    async fn get_version(
        &self,
        request: Request<v4::GetVersionRequest>,
    ) -> Result<Response<v4::GetVersionResponse>, Status> {
        Ok(Response::new(v4::GetVersionResponse {
            application_version: APPLICATION_VERSION.to_owned(),
            protocol_version: echoed(request.into_inner().protocol_version),
            supported_protocol_versions: v4_supported_protocol_versions(),
        }))
    }

    async fn get_identity(
        &self,
        request: Request<v4::GetIdentityRequest>,
    ) -> Result<Response<v4::GetIdentityResponse>, Status> {
        require_principal(request.extensions())?;
        Ok(Response::new(v4::GetIdentityResponse {
            authenticated: true,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SERVED_PROTOCOL_LABELS, SERVED_PROTOCOL_VERSIONS, ServedProtocol, System, SystemService,
        V4System, advertised_to_v3, oldest_first, v3_supported_protocol_versions,
    };
    use crate::APPLICATION_VERSION;
    use sovereign_config_core::ProtocolVersion;
    use sovereign_config_proto::sovereign::config::{v3::GetVersionRequest, v4};
    use tonic::Request;

    async fn get_version(
        requested: &str,
    ) -> sovereign_config_proto::sovereign::config::v3::GetVersionResponse {
        SystemService
            .get_version(Request::new(GetVersionRequest {
                protocol_version: requested.to_owned(),
            }))
            .await
            .expect("GetVersion never rejects a requested version")
            .into_inner()
    }

    #[tokio::test]
    async fn version_echoes_the_requested_version_and_advertises_the_served_set() {
        let response = get_version(ProtocolVersion::V3.as_str()).await;

        assert_eq!(response.protocol_version, ProtocolVersion::V3.as_str());
        assert_eq!(response.application_version, APPLICATION_VERSION);
        assert_eq!(response.supported_protocol_versions, ["v3", "v4"]);
    }

    #[tokio::test]
    async fn version_advertises_every_served_version_in_order() {
        let response = get_version(ProtocolVersion::PREFERRED.as_str()).await;

        assert_eq!(
            response.supported_protocol_versions,
            v3_supported_protocol_versions()
        );
    }

    /// `v3` advertises oldest-first; the served list is most-preferred-first.
    ///
    /// The two orders are opposite on purpose. `v3` has advertised its set
    /// oldest-first since the field was added and a `v3` client is entitled to
    /// that order, so the reversal is what keeps that promise now the server's
    /// own list has flipped. Changing it would be a `v3` behaviour change, and
    /// therefore a new protocol version.
    ///
    /// With one served version the two orders coincide and nothing could fail,
    /// so this drives a second version through the same function — the same
    /// trick `vtest` plays for concurrent serving.
    /// `v3` advertises oldest-first; the served list is in **preference**
    /// order, which is a free compile-time choice.
    ///
    /// The two are independent, and this drives the case that proves it: a
    /// fixture whose preference order is **not** reverse-age, standing for a
    /// server that deliberately prefers an established version while a newer
    /// one soaks. Recovering age by reversing preference would emit the wrong
    /// order here — and would do it in a commit that only touched the served
    /// list, silently changing a released version's contract.
    ///
    /// With one variant in `ProtocolVersion` a synthetic fixture is the only
    /// way this contract can be tested at all.
    #[test]
    fn the_v3_advertised_set_is_oldest_first_whatever_the_preference_order() {
        // Preference: v9 first, then v3, then v5 — nothing like reverse-age.
        let preference_is_not_reverse_age = [
            ServedProtocol {
                version: ProtocolVersion::V3,
                age: 9,
                deprecation_date: None,
            },
            ServedProtocol {
                version: ProtocolVersion::V3,
                age: 3,
                deprecation_date: None,
            },
            ServedProtocol {
                version: ProtocolVersion::V3,
                age: 5,
                deprecation_date: Some("2027-01-01T00:00:00Z"),
            },
        ];

        // Asserted on the ages the ordering actually chose: every entry here
        // renders to the same name, so an assertion on the advertised strings
        // would hold whatever this did.
        let chosen: Vec<u8> = oldest_first(&preference_is_not_reverse_age)
            .into_iter()
            .map(|entry| entry.age)
            .collect();

        assert_eq!(
            chosen,
            [3, 5, 9],
            "v3 must be advertised oldest-first regardless of preference order"
        );
        assert_ne!(
            preference_is_not_reverse_age
                .iter()
                .map(|entry| entry.age)
                .collect::<Vec<_>>(),
            chosen,
            "the fixture must not already be in age order, or this proves nothing"
        );
        assert_eq!(
            advertised_to_v3(&preference_is_not_reverse_age).len(),
            preference_is_not_reverse_age.len()
        );
        assert_eq!(
            v3_supported_protocol_versions(),
            advertised_to_v3(SERVED_PROTOCOL_VERSIONS)
        );
    }

    /// The served list's ages must be distinct, or "oldest first" is ambiguous
    /// and the advertised order depends on sort stability rather than on the
    /// contract.
    #[test]
    fn every_served_version_has_a_distinct_age() {
        let mut ages: Vec<u8> = SERVED_PROTOCOL_VERSIONS
            .iter()
            .map(|entry| entry.age)
            .collect();
        ages.sort_unstable();
        let distinct = ages.len();
        ages.dedup();
        assert_eq!(ages.len(), distinct, "two served versions share an age");
    }

    #[test]
    fn metric_labels_cover_exactly_the_served_protocol_versions() {
        // A version served but unlabelled would be invisible to the retirement
        // check; a version labelled but not served would read a permanent zero
        // and invite retiring something that is still registered.
        let served: Vec<&str> = SERVED_PROTOCOL_VERSIONS
            .iter()
            .map(|served| served.version.as_str())
            .collect();
        assert_eq!(served, SERVED_PROTOCOL_LABELS);
    }

    #[tokio::test]
    async fn version_answers_an_unserved_request_instead_of_rejecting_it() {
        // The lockstep gate this replaced returned FAILED_PRECONDITION here,
        // which left a range-aware client no way to discover what is served.
        // The catch-all in `protocol.rs` now returns FAILED_PRECONDITION for a
        // route naming an unserved version — but this RPC is reached only on a
        // *served* version's route, so the two never meet.
        for requested in ["v1", "v999", ""] {
            let response = get_version(requested).await;

            assert_eq!(
                response.protocol_version,
                ProtocolVersion::PREFERRED.as_str(),
                "an unserved request falls back to the preferred served version"
            );
            assert_eq!(response.supported_protocol_versions, ["v3", "v4"]);
        }
    }

    async fn get_version_on_v4(requested: &str) -> v4::GetVersionResponse {
        v4::system_server::System::get_version(
            &V4System,
            Request::new(v4::GetVersionRequest {
                protocol_version: requested.to_owned(),
            }),
        )
        .await
        .expect("GetVersion never rejects a requested version")
        .into_inner()
    }

    /// `v4` keeps the echo every version must keep: the version asked for,
    /// whenever it is served — including an *older* one, which is what a
    /// client that dialled `v4`'s route to ask about `v3` is owed.
    #[tokio::test]
    async fn v4_echoes_the_requested_version_and_advertises_preference_order() {
        for requested in ["v4", "v3"] {
            let response = get_version_on_v4(requested).await;

            assert_eq!(response.protocol_version, requested);
            assert_eq!(response.application_version, APPLICATION_VERSION);
            assert_eq!(response.supported_protocol_versions, ["v4", "v3"]);
        }
        let unserved = get_version_on_v4("v1").await;
        assert_eq!(unserved.protocol_version, ProtocolVersion::V4.as_str());
    }

    #[tokio::test]
    async fn v4_identity_requires_a_principal() {
        let refused = v4::system_server::System::get_identity(
            &V4System,
            Request::new(v4::GetIdentityRequest {}),
        )
        .await
        .expect_err("no principal is attached");
        assert_eq!(refused.code(), tonic::Code::Unauthenticated);
    }
}
