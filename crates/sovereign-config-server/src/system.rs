//! The `System` service: protocol negotiation and authenticated identity.
//!
//! Negotiation is a **supported range**, not an equality. Clients are deployed
//! independently of this server and are expected to lag it, so `GetVersion`
//! never rejects a version it does not recognise — it answers with the set it
//! serves and lets the client choose. See `## Protocol versioning` in
//! `README.md` for the introduction and retirement procedure.

use sovereign_config_core::ProtocolVersion;
use sovereign_config_proto::sovereign::config::v3::{
    GetIdentityRequest, GetIdentityResponse, GetVersionRequest, GetVersionResponse,
    system_server::System,
};
use tonic::{Request, Response, Status};

use crate::{APPLICATION_VERSION, auth::AuthenticatedPrincipal};

/// Every protocol version **this binary routes**, oldest first.
///
/// Deliberately its own list rather than an alias of [`ProtocolVersion::ALL`],
/// which is the set the *client* crates can speak. The two are different facts
/// and must move independently: declaring a variant in core says "a client in
/// this workspace can speak it", while naming it here says "this server has a
/// service registered for it". Aliasing them would make those one edit, and a
/// version declared but not yet registered would be advertised immediately —
/// negotiation would succeed and then every RPC on it would return
/// `Unimplemented`.
///
/// Adding a version here is therefore the *last* step of introducing one: the
/// `add_service` call for it must already be on the router. Removing one is the
/// last step of retiring it, gated on the `outcome="authenticated"` series of
/// `sovereign_config_protocol_requests_total` reading zero for that version —
/// see the README.
pub(crate) const SERVED_PROTOCOL_VERSIONS: &[ProtocolVersion] = &[ProtocolVersion::V3];

/// The metric label for every version in [`SERVED_PROTOCOL_VERSIONS`].
///
/// Spelled out rather than derived, because a `const` cannot map a slice; the
/// test below is what keeps the two in step. Compiled-in labels are what keep
/// `sovereign_config_protocol_requests_total` bounded.
pub(crate) const SERVED_PROTOCOL_LABELS: &[&str] = &[ProtocolVersion::V3.as_str()];

/// The version a request that names no version this server serves is told about:
/// the newest served.
fn newest_served() -> &'static str {
    SERVED_PROTOCOL_VERSIONS
        .last()
        .expect("the server must serve at least one protocol version")
        .as_str()
}

fn served(requested: &str) -> bool {
    SERVED_PROTOCOL_VERSIONS
        .iter()
        .any(|version| version.as_str() == requested)
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
        // against the single version they know, so echoing this server's newest
        // version instead would fail every deployed client the day a newer
        // version ships. Only a request for a version this server does not
        // serve at all falls back to the newest — a client that asks for a
        // version it speaks can never see that, so the guarantee holds.
        let protocol_version = if served(&requested) {
            requested
        } else {
            newest_served().to_owned()
        };

        Ok(Response::new(GetVersionResponse {
            application_version: APPLICATION_VERSION.to_owned(),
            protocol_version,
            supported_protocol_versions: SERVED_PROTOCOL_VERSIONS
                .iter()
                .map(|version| version.as_str().to_owned())
                .collect(),
        }))
    }

    async fn get_identity(
        &self,
        request: Request<GetIdentityRequest>,
    ) -> Result<Response<GetIdentityResponse>, Status> {
        if request
            .extensions()
            .get::<AuthenticatedPrincipal>()
            .is_none()
        {
            return Err(Status::unauthenticated("authentication required"));
        }
        Ok(Response::new(GetIdentityResponse {
            authenticated: true,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::{SERVED_PROTOCOL_LABELS, SERVED_PROTOCOL_VERSIONS, System, SystemService};
    use crate::APPLICATION_VERSION;
    use sovereign_config_core::ProtocolVersion;
    use sovereign_config_proto::sovereign::config::v3::GetVersionRequest;
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
        assert_eq!(response.supported_protocol_versions, ["v3"]);
    }

    #[tokio::test]
    async fn version_advertises_every_served_version_in_order() {
        let response = get_version(ProtocolVersion::PREFERRED.as_str()).await;

        let expected: Vec<String> = SERVED_PROTOCOL_VERSIONS
            .iter()
            .map(|version| version.as_str().to_owned())
            .collect();
        assert_eq!(response.supported_protocol_versions, expected);
    }

    /// The served set is advertised verbatim and documented oldest-first, which
    /// clients rely on when picking the highest mutually supported version.
    ///
    /// This was previously free because the list aliased `ProtocolVersion::ALL`,
    /// whose own ordering is already pinned in core. Now that the two are
    /// separate facts — what this binary routes versus what a client can speak —
    /// the server's own list needs its own guard.
    #[test]
    fn the_served_set_is_ordered_oldest_first() {
        assert!(
            SERVED_PROTOCOL_VERSIONS
                .windows(2)
                .all(|pair| pair[0] < pair[1]),
            "SERVED_PROTOCOL_VERSIONS must be ascending: {SERVED_PROTOCOL_VERSIONS:?}"
        );
    }

    #[test]
    fn metric_labels_cover_exactly_the_served_protocol_versions() {
        // A version served but unlabelled would be invisible to the retirement
        // check; a version labelled but not served would read a permanent zero
        // and invite retiring something that is still registered.
        let served: Vec<&str> = SERVED_PROTOCOL_VERSIONS
            .iter()
            .map(|version| version.as_str())
            .collect();
        assert_eq!(served, SERVED_PROTOCOL_LABELS);
    }

    #[tokio::test]
    async fn version_answers_an_unserved_request_instead_of_rejecting_it() {
        // The lockstep gate this replaced returned FAILED_PRECONDITION here,
        // which left a range-aware client no way to discover what is served.
        for requested in ["v1", "v999", ""] {
            let response = get_version(requested).await;

            assert_eq!(
                response.protocol_version,
                ProtocolVersion::PREFERRED.as_str(),
                "an unserved request falls back to the newest served version"
            );
            assert_eq!(response.supported_protocol_versions, ["v3"]);
        }
    }
}
