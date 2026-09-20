//! What the native transport actually dials, asserted on the route the server
//! received rather than on anything the client reports about itself.
//!
//! This is the half of protocol versioning that used to be taken on trust. A
//! client negotiates a version, the server counts its traffic by the version
//! the route names, and the gate for retiring a version reads those counts — so
//! a client that negotiated `vN` and dialled `vN-1` would report the live
//! version as idle and the idle one as live. Nothing about the client's own
//! view of itself can catch that; only the path on the wire can.
//!
//! The server here implements no version. It records the route and answers
//! `UNIMPLEMENTED`, which is exactly what a server that does not serve the
//! dialled version says, so the assertions hold for a version that exists and
//! for one that does not.

use std::sync::{Arc, Mutex};

use axum::{
    body::Body,
    extract::Request,
    response::{IntoResponse, Response},
};
use sovereign_config_client::{
    Handshake, ManagedConnectionTransport, Transport, ValueTransport, negotiate,
};
use sovereign_config_core::{
    ConfigPath, ConnectionId, DisplayName, ErrorKind, ManagedPermission, ManagedPermissions,
    PlainValue, ProtocolVersion, Secret, SecretInput, SubTreeMutationContent, SubTreeMutationValue,
};
use sovereign_config_native::{TonicChannel, TonicTransport};

/// Every call [`issue_every_rpc`] makes — the transport's whole surface, so a
/// version that gains dispatch for some of its routes and not others is caught
/// rather than sampled. One more than the number of distinct routes, because
/// plain and secret writes are the same RPC.
const RPC_COUNT: usize = 14;

#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<String>>>);

impl Recorder {
    fn record(&self, path: &str) {
        self.0
            .lock()
            .expect("recorder is not poisoned")
            .push(path.to_owned());
    }

    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.0.lock().expect("recorder is not poisoned"))
    }
}

/// A server that serves no protocol version at all: it records the route it
/// was asked for and answers `UNIMPLEMENTED`, as a real server does for a
/// route it has no service registered on.
async fn serve(recorder: Recorder) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = axum::Router::new().fallback(move |request: Request| {
        let recorder = recorder.clone();
        async move {
            recorder.record(request.uri().path());
            Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .header("grpc-status", "12")
                .body(Body::empty())
                .unwrap()
                .into_response()
        }
    });
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{address}")
}

/// Issues every RPC the transport offers, discarding the (failing) results.
/// Each one is here for its route, not its answer.
async fn issue_every_rpc(transport: &TonicTransport) {
    let bearer = Secret::new("dispatch-token-sentinel");
    let path = ConfigPath::parse("/apps/api/feature").unwrap();
    let root = ConfigPath::parse("/apps/api").unwrap();
    let connection_id = ConnectionId::parse("a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8").unwrap();
    let display_name = DisplayName::parse("Dispatch").unwrap();
    let permissions = ManagedPermissions::new([ManagedPermission::Read]).unwrap();
    let mutation = SubTreeMutationValue {
        path: path.clone(),
        value: SubTreeMutationContent::Plain(PlainValue::new("dispatch-sentinel")),
    };

    let _ = transport.get_identity(&bearer).await;
    let _ = transport.list_values(&root, &bearer).await;
    let _ = transport.get_subtree(&root, &bearer).await;
    let _ = transport
        .put_value(&path, &PlainValue::new("dispatch-sentinel"), &bearer)
        .await;
    let _ = transport
        .put_secret(
            &path,
            &SecretInput::new("dispatch-secret-sentinel"),
            &bearer,
        )
        .await;
    let _ = transport
        .replace_subtree(&root, std::slice::from_ref(&mutation), &bearer)
        .await;
    let _ = transport.delete_values(&root, true, &bearer).await;
    let _ = transport.reveal_secret(&path, &bearer).await;
    let _ = transport.add_value_path(&path, &path, &bearer).await;
    let _ = transport.list_value_paths(&path, &bearer).await;
    let _ = transport.list_managed_connections(&bearer).await;
    let _ = transport
        .create_managed_connection(&display_name, &root, &permissions, &bearer)
        .await;
    let _ = transport
        .rotate_managed_connection(&connection_id, &bearer)
        .await;
    let _ = transport
        .revoke_managed_connection(&connection_id, &bearer)
        .await;
}

/// Every RPC a session issues travels on the routes of the version it
/// negotiated — for every version this build speaks.
///
/// Table-driven over `ProtocolVersion::ALL` on purpose: a version added to that
/// list is covered here the moment it is declared, without anyone remembering
/// to extend this test.
#[tokio::test(flavor = "multi_thread")]
async fn every_rpc_travels_on_the_routes_of_the_version_the_session_speaks() {
    let recorder = Recorder::default();
    let endpoint = serve(recorder.clone()).await;
    let channel = TonicChannel::connect(endpoint).await.unwrap();

    for version in ProtocolVersion::ALL.iter().copied() {
        issue_every_rpc(&channel.speaking(version)).await;

        let routes = recorder.take();
        let expected_package = format!("/sovereign.config.{version}.");
        assert_eq!(
            routes.len(),
            RPC_COUNT,
            "{version}: every RPC should have reached the server: {routes:?}"
        );
        for route in &routes {
            assert!(
                route.starts_with(&expected_package),
                "{version}: dialled {route}, which does not name the negotiated version"
            );
        }
    }
}

/// Negotiation dials the **unversioned** handshake first, and only that.
///
/// Asserted on the route the server received, because this is the one route in
/// the system that must never name a version: a handshake inside a version's
/// namespace would be answered by the catch-all the moment that version was
/// retired, and no client could ever negotiate its way out again.
#[tokio::test(flavor = "multi_thread")]
async fn negotiation_dials_the_unversioned_handshake_first() {
    let recorder = Recorder::default();
    let endpoint = serve(recorder.clone()).await;
    let channel = TonicChannel::connect(endpoint).await.unwrap();

    let _ = channel.served_versions(ProtocolVersion::ALL).await;

    assert_eq!(recorder.take(), ["/sovereign.config.Handshake/Negotiate"]);
}

/// A service with no handshake is reached on the legacy version's own route.
///
/// This server answers `UNIMPLEMENTED` to everything, so negotiation tries the
/// handshake, finds none, falls back to the legacy route, and fails there. Both
/// routes, in that order, are what the fallback *is* — and the legacy one must
/// name the legacy version, because that is the only route a pre-handshake
/// server exempts from authentication.
#[tokio::test(flavor = "multi_thread")]
async fn a_service_without_a_handshake_is_asked_on_the_legacy_route() {
    let recorder = Recorder::default();
    let endpoint = serve(recorder.clone()).await;
    let channel = TonicChannel::connect(endpoint).await.unwrap();

    let error = negotiate(&channel).await.unwrap_err();

    // A route that answers nothing at all is indistinguishable from a version
    // the server has retired, and reads the same way to the caller.
    assert_eq!(error.kind, ErrorKind::IncompatibleProtocol);
    assert_eq!(
        recorder.take(),
        [
            "/sovereign.config.Handshake/Negotiate".to_owned(),
            format!(
                "/sovereign.config.{}.System/GetVersion",
                ProtocolVersion::LEGACY
            ),
        ]
    );
}

/// A transport reports the version its routes name, for every version this
/// build speaks — so the protocol the CLI and the MCP `status` tool print is
/// the protocol on the wire, not a value carried alongside it.
#[tokio::test(flavor = "multi_thread")]
async fn a_transport_reports_the_version_its_routes_name() {
    let recorder = Recorder::default();
    let endpoint = serve(recorder.clone()).await;
    let channel = TonicChannel::connect(endpoint).await.unwrap();

    for version in ProtocolVersion::ALL.iter().copied() {
        let transport = channel.speaking(version);

        assert_eq!(transport.protocol_version(), version);

        let _ = transport
            .get_identity(&Secret::new("dispatch-token-sentinel"))
            .await;
        assert_eq!(
            recorder.take(),
            [format!(
                "/sovereign.config.{}.System/GetIdentity",
                transport.protocol_version()
            )]
        );
    }
}
