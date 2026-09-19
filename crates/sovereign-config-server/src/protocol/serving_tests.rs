//! Proof that two protocol versions serve concurrently on one router.
//!
//! These tests register `sovereign.config.v3` alongside the dev-only
//! `sovereign.config.vtest` package and drive both over a real channel. They
//! exist because the dual-registration mechanism would otherwise ship having
//! never concurrently served: a flaw in it would first surface during a genuine
//! v4 migration, which is the worst possible moment to discover one.
//!
//! `vtest` is a `[dev-dependency]` and never reaches the release binary. It
//! commits to no wire contract — see its `service.proto`.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use sovereign_config_proto::sovereign::config::v3::{
    GetVersionRequest as V3Request, system_client::SystemClient as V3Client,
    system_server::SystemServer as V3Server,
};
use sovereign_config_proto_testversion::sovereign::config::vtest::{
    GetVersionRequest as TestRequest, GetVersionResponse as TestResponse, LegacyGetVersionResponse,
    system_client::SystemClient as TestClient,
    system_server::{System as TestSystem, SystemServer as TestServer},
};
use tokio::net::TcpListener;
use tonic::{
    Request, Response, Status,
    body::BoxBody,
    transport::{Channel, Endpoint, Server},
};
use tower::{Layer, Service};

use crate::{
    metrics::ProtocolMetrics,
    protocol::{NegotiatedProtocolVersion, ProtocolVersionLayer},
    system::{SERVED_PROTOCOL_LABELS, SystemService},
};

const TEST_VERSION: &str = "vtest";

/// Every label the harness recognises: the shipped versions plus `vtest`.
///
/// `vtest` appears here and nowhere in the binary, which is exactly how a real
/// second version would be added — one more compiled-in label.
const HARNESS_LABELS: &[&str] = &["v3", TEST_VERSION];

/// The `vtest` package's own service. Answers distinguishably from v3 so a test
/// can tell which implementation handled a request, and reports back the
/// [`NegotiatedProtocolVersion`] extension it was handed so the extension is
/// proven to survive the layer rather than merely being attached.
#[derive(Clone, Copy, Default)]
struct TestVersionService;

#[tonic::async_trait]
impl TestSystem for TestVersionService {
    async fn get_version(
        &self,
        request: Request<TestRequest>,
    ) -> Result<Response<TestResponse>, Status> {
        let seen = request
            .extensions()
            .get::<NegotiatedProtocolVersion>()
            .map(|version| version.0.unwrap_or("none").to_owned());
        Ok(Response::new(TestResponse {
            application_version: "testversion-service".to_owned(),
            protocol_version: request.into_inner().protocol_version,
            supported_protocol_versions: seen.into_iter().collect(),
        }))
    }
}

/// Rejects every request without calling the service beneath it, standing in
/// for the authentication layer refusing a request.
#[derive(Clone, Copy)]
struct RejectingLayer;

impl<S> Layer<S> for RejectingLayer {
    type Service = RejectingService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RejectingService(inner)
    }
}

#[derive(Clone)]
struct RejectingService<S>(S);

impl<S, B> Service<http::Request<B>> for RejectingService<S>
where
    S: Service<http::Request<B>, Response = http::Response<BoxBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    B: Send + 'static,
{
    type Response = http::Response<BoxBody>;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.0.poll_ready(context)
    }

    fn call(&mut self, _: http::Request<B>) -> Self::Future {
        let refusal = Status::unauthenticated("authentication required").into_http();
        Box::pin(async move { Ok(refusal) })
    }
}

struct Harness {
    address: SocketAddr,
    metrics: Arc<ProtocolMetrics>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Harness {
    /// Serves both protocol packages on one router, behind the same layer the
    /// binary uses.
    async fn start() -> Self {
        let metrics = Arc::new(ProtocolMetrics::new(HARNESS_LABELS));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("an ephemeral port must bind");
        let address = listener.local_addr().expect("the bound address is known");
        let (shutdown, shutdown_signal) = tokio::sync::oneshot::channel();

        let router = Server::builder()
            .layer(ProtocolVersionLayer::new(
                Arc::clone(&metrics),
                HARNESS_LABELS,
            ))
            .add_service(V3Server::new(SystemService))
            .add_service(TestServer::new(TestVersionService));

        tokio::spawn(async move {
            router
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        let _ = shutdown_signal.await;
                    },
                )
                .await
                .expect("the dual-protocol server must serve");
        });

        Self {
            address,
            metrics,
            shutdown: Some(shutdown),
        }
    }

    async fn channel(&self) -> Channel {
        Endpoint::from_shared(format!("http://{}", self.address))
            .expect("the harness endpoint must parse")
            .connect_timeout(Duration::from_secs(5))
            .connect()
            .await
            .expect("the harness must accept a connection")
    }

    /// The `attempted` series of `sovereign_config_protocol_requests_total` for
    /// `version`. The harness has no authentication layer, so nothing here can
    /// move the `authenticated` series; that is covered in `auth/tests.rs`.
    fn requests(&self, version: &str) -> u64 {
        let needle = format!(
            "sovereign_config_protocol_requests_total{{version=\"{version}\",outcome=\"attempted\"}} "
        );
        self.metrics
            .render()
            .lines()
            .find_map(|line| line.strip_prefix(needle.as_str()))
            .unwrap_or_else(|| panic!("no counter rendered for {version}"))
            .parse()
            .expect("a counter renders as an integer")
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

#[tokio::test]
async fn both_protocol_packages_answer_on_their_own_routes() {
    let harness = Harness::start().await;

    let v3 = V3Client::new(harness.channel().await)
        .get_version(V3Request {
            protocol_version: "v3".to_owned(),
        })
        .await
        .expect("the v3 route must answer")
        .into_inner();
    let test = TestClient::new(harness.channel().await)
        .get_version(TestRequest {
            protocol_version: TEST_VERSION.to_owned(),
        })
        .await
        .expect("the vtest route must answer")
        .into_inner();

    // Neither shadows the other: each route reached its own implementation,
    // which the distinct application versions prove.
    assert_eq!(v3.protocol_version, "v3");
    assert_eq!(v3.supported_protocol_versions, SERVED_PROTOCOL_LABELS);
    assert_eq!(test.application_version, "testversion-service");
    assert_eq!(test.protocol_version, TEST_VERSION);
    assert_ne!(v3.application_version, test.application_version);

    // The layer's version extension reaches the handler, which is what a future
    // version's shim reads to tell which protocol called it.
    assert_eq!(test.supported_protocol_versions, [TEST_VERSION]);
}

#[tokio::test]
async fn each_version_is_counted_against_its_own_label() {
    let harness = Harness::start().await;
    let mut v3 = V3Client::new(harness.channel().await);
    let mut test = TestClient::new(harness.channel().await);

    for _ in 0..3 {
        v3.get_version(V3Request {
            protocol_version: "v3".to_owned(),
        })
        .await
        .expect("the v3 route must answer");
    }
    test.get_version(TestRequest {
        protocol_version: TEST_VERSION.to_owned(),
    })
    .await
    .expect("the vtest route must answer");

    // Real RPC traffic, not connect counts: three v3 calls over one channel
    // register three times. This is what makes the counter usable as the
    // retirement precondition — a long-lived client negotiates once but keeps
    // generating traffic.
    assert_eq!(harness.requests("v3"), 3);
    assert_eq!(harness.requests(TEST_VERSION), 1);
    assert_eq!(harness.requests("unrecognised"), 0);
}

/// The guarantee that already deployed applications need no rebuild.
///
/// `supported_protocol_versions` was added to a released message. A client
/// compiled before it existed must still decode a current server's response and
/// still pass the exact-equality check it was built with — prost skips unknown
/// fields, and the echo is still the version it asked for. If this ever fails,
/// every deployed provider fails on every configuration load.
#[tokio::test]
async fn a_client_compiled_without_the_supported_set_still_decodes_and_negotiates() {
    use prost::Message as _;

    let harness = Harness::start().await;
    let current = V3Client::new(harness.channel().await)
        .get_version(V3Request {
            protocol_version: "v3".to_owned(),
        })
        .await
        .expect("the v3 route must answer")
        .into_inner();
    assert!(
        !current.supported_protocol_versions.is_empty(),
        "the response under test must actually carry the new field"
    );

    // Decode the current wire bytes with a pre-2.25.0 client's compiled view.
    let legacy = LegacyGetVersionResponse::decode(current.encode_to_vec().as_slice())
        .expect("an older client must decode a response carrying an unknown field");

    assert_eq!(legacy.application_version, current.application_version);
    // The exact-equality gate such a client performs, verbatim.
    assert_eq!(legacy.protocol_version, "v3");
}

/// Pins the layer ordering that `main.rs` depends on.
///
/// `ProtocolVersionLayer` must sit **outside** the authentication layer, so a
/// request that authentication refuses is still counted as traffic on its
/// protocol version. Tower documents that the first layer added is called
/// first, and tonic's `Server::layer` delegates to `ServiceBuilder::layer`, so
/// this holds today — but nothing else would catch it changing.
///
/// The failure mode is silent and expensive: an under-counting metric reads
/// zero for a version that is still in use, which is exactly the signal the
/// README makes the precondition for deleting that version's package. The
/// resulting outage would have no failing test behind it.
#[tokio::test]
async fn a_request_refused_beneath_the_layer_is_still_counted() {
    let metrics = Arc::new(ProtocolMetrics::new(&["v3"]));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("an ephemeral port must bind");
    let address = listener.local_addr().expect("the bound address is known");

    let layer_metrics = Arc::clone(&metrics);
    tokio::spawn(async move {
        let _ = Server::builder()
            // Same order as `main.rs`: the protocol layer first, the refusing
            // layer (standing in for authentication) beneath it.
            .layer(ProtocolVersionLayer::new(layer_metrics, &["v3"]))
            .layer(RejectingLayer)
            .add_service(V3Server::new(SystemService))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await;
    });

    let channel = Endpoint::from_shared(format!("http://{address}"))
        .expect("the endpoint must parse")
        .connect_timeout(Duration::from_secs(5))
        .connect()
        .await
        .expect("the server must accept a connection");
    let refused = V3Client::new(channel)
        .get_version(V3Request {
            protocol_version: "v3".to_owned(),
        })
        .await
        .expect_err("the rejecting layer must refuse the request");
    assert_eq!(refused.code(), tonic::Code::Unauthenticated);

    let rendered = metrics.render();
    assert!(
        rendered.contains(
            "sovereign_config_protocol_requests_total{version=\"v3\",outcome=\"attempted\"} 1"
        ),
        "a refused request is still an attempt on its protocol version: {rendered}"
    );
    // And it is *only* an attempt. A refused request must never reach the
    // series that gates retirement, or anything able to reach the public
    // endpoint could hold a version open indefinitely.
    assert!(
        rendered.contains(
            "sovereign_config_protocol_requests_total{version=\"v3\",outcome=\"authenticated\"} 0"
        ),
        "a refused request must not count as authenticated: {rendered}"
    );
}

#[tokio::test]
async fn a_versioned_route_this_build_does_not_serve_is_counted_as_unrecognised() {
    let harness = Harness::start().await;
    let metrics = Arc::new(ProtocolMetrics::new(&["v3"]));

    // The same layer, built without the `vtest` label — the state a server is in
    // when a client calls a version it does not serve.
    let layer_metrics = Arc::clone(&metrics);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("an ephemeral port must bind");
    let address = listener.local_addr().expect("the bound address is known");
    tokio::spawn(async move {
        let _ = Server::builder()
            .layer(ProtocolVersionLayer::new(layer_metrics, &["v3"]))
            .add_service(V3Server::new(SystemService))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await;
    });

    let channel = Endpoint::from_shared(format!("http://{address}"))
        .expect("the endpoint must parse")
        .connect_timeout(Duration::from_secs(5))
        .connect()
        .await
        .expect("the server must accept a connection");
    let unserved = TestClient::new(channel)
        .get_version(TestRequest {
            protocol_version: TEST_VERSION.to_owned(),
        })
        .await;

    assert!(
        unserved.is_err(),
        "an unregistered protocol package has no route to answer on"
    );
    let rendered = metrics.render();
    assert!(
        rendered.contains(
            "sovereign_config_protocol_requests_total{version=\"unrecognised\",outcome=\"attempted\"} 1"
        ),
        "traffic on an unserved version is visible, but under a fixed label: {rendered}"
    );
    assert!(
        !rendered.contains(TEST_VERSION),
        "a request must never introduce a label of its own: {rendered}"
    );
    drop(harness);
}
