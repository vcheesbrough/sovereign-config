//! Where an audit query goes, asserted on the route the server received.
//!
//! The audit trail exists only from `v4`. A `v4` session dials `v4`'s `Audit`
//! route; a `v3` session has no such route and must not invent one — it answers
//! with a bounded error and puts nothing on the wire.

use std::sync::{Arc, Mutex};

use axum::{
    body::Body,
    extract::Request,
    response::{IntoResponse, Response},
};
use sovereign_config_client::AuditTransport;
use sovereign_config_core::{AuditQuery, ErrorKind, ProtocolVersion, Secret};
use sovereign_config_native::TonicChannel;

#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<String>>>);

impl Recorder {
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.0.lock().expect("recorder is not poisoned"))
    }
}

/// Records every route asked for and answers `UNIMPLEMENTED`.
async fn serve(recorder: Recorder) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = axum::Router::new().fallback(move |request: Request| {
        let recorder = recorder.clone();
        async move {
            recorder
                .0
                .lock()
                .expect("recorder is not poisoned")
                .push(request.uri().path().to_owned());
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

#[tokio::test(flavor = "multi_thread")]
async fn an_audit_query_travels_on_v4s_audit_route() {
    let recorder = Recorder::default();
    let channel = TonicChannel::connect(serve(recorder.clone()).await)
        .await
        .unwrap();

    let _ = channel
        .speaking(ProtocolVersion::V4)
        .query_audit_trail(&AuditQuery::default(), &Secret::new("audit-token"))
        .await;

    assert_eq!(
        recorder.take(),
        ["/sovereign.config.v4.Audit/QueryAuditTrail"]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_v3_session_answers_an_audit_query_itself_and_dials_nothing() {
    let recorder = Recorder::default();
    let channel = TonicChannel::connect(serve(recorder.clone()).await)
        .await
        .unwrap();

    let error = channel
        .speaking(ProtocolVersion::V3)
        .query_audit_trail(&AuditQuery::default(), &Secret::new("audit-token"))
        .await
        .expect_err("v3 has no audit trail");

    // Not `VersionNotServed`: `v3` is served, and re-handshaking would only
    // land on it again.
    assert_eq!(error.kind, ErrorKind::IncompatibleProtocol);
    assert_eq!(
        error.message(),
        "the audit trail is not available on protocol v3"
    );
    assert!(recorder.take().is_empty(), "nothing may reach the wire");
}
