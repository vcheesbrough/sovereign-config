//! The unversioned handshake: `/sovereign.config.Handshake/Negotiate`.
//!
//! This module sits **outside** the protocol seam. It has no shim and no
//! per-version form, because it is the one operation a client calls before it
//! knows which versions exist — the operation that tells it. Everything else
//! the server does lives behind a `vN` shim; this does not.
//!
//! It reports one list, [`SERVED_PROTOCOL_VERSIONS`], most preferred first, and
//! nothing else. It never rejects, whatever the client sends: rejecting here
//! would be rejecting a client for the versions it speaks, which is exactly the
//! flag-day coupling negotiation exists to remove.
//!
//! The endpoint is unauthenticated and therefore public. The client's version
//! list is untrusted input: it is counted under compiled-in labels only, with
//! a bound on how much of it is looked at, and it never influences the answer.
//! See `## Protocol versioning` in `README.md`.

use std::sync::Arc;

use sovereign_config_proto::sovereign::config::{
    NegotiateRequest, NegotiateResponse, ServedProtocolVersion, handshake_server::Handshake,
};
use tonic::{Request, Response, Status};

use crate::{metrics::ProtocolMetrics, system::SERVED_PROTOCOL_VERSIONS};

/// How many entries of a client's list are looked at, and how many bytes of
/// each.
///
/// Nothing is rejected for exceeding these — §1.3 of the contract is that the
/// handshake never rejects — but anything past them is not examined. A client
/// speaking more than this many versions is not a thing that exists; a request
/// carrying more is someone probing a public endpoint, and the cost of reading
/// it is bounded here rather than left to the metric to absorb.
const CLIENT_LIST_LIMIT: usize = 32;
const CLIENT_VERSION_LENGTH: usize = 16;

#[derive(Clone)]
pub(crate) struct HandshakeService {
    metrics: Arc<ProtocolMetrics>,
}

impl HandshakeService {
    pub(crate) const fn new(metrics: Arc<ProtocolMetrics>) -> Self {
        Self { metrics }
    }

    /// Records what the client said it speaks, under compiled-in labels.
    ///
    /// An entry longer than [`CLIENT_VERSION_LENGTH`] cannot be a version this
    /// server serves, so it is counted as unrecognised without being compared
    /// against every label.
    fn record(&self, client_versions: &[String]) {
        for offered in client_versions.iter().take(CLIENT_LIST_LIMIT) {
            if offered.len() > CLIENT_VERSION_LENGTH {
                self.metrics
                    .record_offered(crate::metrics::UNRECOGNISED_PROTOCOL_LABEL);
            } else {
                self.metrics.record_offered(offered);
            }
        }
    }
}

#[tonic::async_trait]
impl Handshake for HandshakeService {
    async fn negotiate(
        &self,
        request: Request<NegotiateRequest>,
    ) -> Result<Response<NegotiateResponse>, Status> {
        self.record(&request.into_inner().client_protocol_versions);

        // The whole served set, in this server's preference order, whatever the
        // client asked for. Never filtered and never reordered by the request:
        // the client selects, the server only reports.
        Ok(Response::new(NegotiateResponse {
            served_protocol_versions: SERVED_PROTOCOL_VERSIONS
                .iter()
                .map(|served| ServedProtocolVersion {
                    protocol_version: served.version.as_str().to_owned(),
                    deprecation_date: served.deprecation_date.map(str::to_owned),
                })
                .collect(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use sovereign_config_core::ProtocolVersion;
    use sovereign_config_proto::sovereign::config::{
        NegotiateRequest, NegotiateResponse, handshake_server::Handshake as _,
    };
    use tonic::Request;

    use super::{CLIENT_LIST_LIMIT, HandshakeService};
    use crate::{metrics::ProtocolMetrics, system::SERVED_PROTOCOL_LABELS};

    fn service() -> (HandshakeService, Arc<ProtocolMetrics>) {
        let metrics = Arc::new(ProtocolMetrics::new(SERVED_PROTOCOL_LABELS));
        (HandshakeService::new(Arc::clone(&metrics)), metrics)
    }

    async fn negotiate(client_versions: &[&str]) -> NegotiateResponse {
        let (service, _) = service();
        negotiate_with(&service, client_versions).await
    }

    async fn negotiate_with(
        service: &HandshakeService,
        client_versions: &[&str],
    ) -> NegotiateResponse {
        service
            .negotiate(Request::new(NegotiateRequest {
                client_protocol_versions: client_versions
                    .iter()
                    .map(|version| (*version).to_owned())
                    .collect(),
            }))
            .await
            .expect("the handshake never rejects")
            .into_inner()
    }

    fn versions(response: &NegotiateResponse) -> Vec<String> {
        response
            .served_protocol_versions
            .iter()
            .map(|served| served.protocol_version.clone())
            .collect()
    }

    #[tokio::test]
    async fn the_handshake_reports_every_served_version_most_preferred_first() {
        let response = negotiate(&[ProtocolVersion::PREFERRED.as_str()]).await;

        assert_eq!(versions(&response), SERVED_PROTOCOL_LABELS);
    }

    /// §1.3: the answer is the server's whole set, independent of the request.
    /// A server that filtered by the client's list would hand a client a view of
    /// the world shaped by what it already believed — and could never tell it
    /// about a version it does not yet speak.
    #[tokio::test]
    async fn the_answer_is_identical_whatever_the_client_sends() {
        let expected = versions(&negotiate(&["v3"]).await);
        let oversized: Vec<&str> = std::iter::repeat_n("v999", CLIENT_LIST_LIMIT * 4).collect();

        for client_versions in [
            vec![],
            vec![""],
            vec!["v1"],
            vec!["v9000", "v3"],
            vec!["v3", "v9000"],
            // Not a version identifier at all: quotes, newlines, a label
            // injection attempt, and something far past every bound.
            vec!["v3\" injected=\"", "\n\n", &"v".repeat(4096)],
            oversized,
        ] {
            let response = negotiate_with(&service().0, &client_versions).await;

            assert_eq!(
                versions(&response),
                expected,
                "the served set must not depend on {client_versions:?}"
            );
        }
    }

    /// The label-injection guard. The endpoint is public and the list is
    /// attacker-controlled, so a version outside the compiled-in domain must
    /// land in the fixed bucket rather than mint a series of its own.
    #[tokio::test]
    async fn a_client_list_is_counted_under_compiled_in_labels_only() {
        let (service, metrics) = service();

        negotiate_with(&service, &["v3", "v9000", "not-a-version", "v3"]).await;

        let rendered = metrics.render();
        assert!(
            rendered.contains("sovereign_config_protocol_client_versions_total{version=\"v3\"} 2"),
            "{rendered}"
        );
        assert!(
            rendered.contains(
                "sovereign_config_protocol_client_versions_total{version=\"unrecognised\"} 2"
            ),
            "{rendered}"
        );
        assert!(
            !rendered.contains("v9000") && !rendered.contains("not-a-version"),
            "a request must never introduce a label of its own: {rendered}"
        );
    }

    /// Reading an unbounded list is work an anonymous caller can ask for. The
    /// bound is on what is examined, not on what is accepted — the request
    /// still succeeds, which is what §1.3 requires.
    #[tokio::test]
    async fn only_a_bounded_prefix_of_a_client_list_is_examined() {
        let (service, metrics) = service();
        let flood: Vec<&str> = std::iter::repeat_n("v3", CLIENT_LIST_LIMIT + 100).collect();

        negotiate_with(&service, &flood).await;

        assert!(
            metrics.render().contains(&format!(
                "sovereign_config_protocol_client_versions_total{{version=\"v3\"}} {CLIENT_LIST_LIMIT}"
            )),
            "{}",
            metrics.render()
        );
    }
}
