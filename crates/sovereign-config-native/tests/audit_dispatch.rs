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
use sovereign_config_core::{AuditEventKind, AuditQuery, ErrorKind, ProtocolVersion, Secret};
use sovereign_config_native::TonicChannel;
use sovereign_config_proto::sovereign::config::v4::{
    AuditEvent, AuditEventKind as WireKind, QueryAuditTrailRequest, QueryAuditTrailResponse,
    audit_server::{Audit, AuditServer},
};

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

/// A real `v4` `Audit` service that records the request it was given and
/// answers with a scripted page.
struct ScriptedAudit {
    seen: Arc<Mutex<Option<QueryAuditTrailRequest>>>,
    next_cursor: &'static str,
}

#[tonic::async_trait]
impl Audit for ScriptedAudit {
    async fn query_audit_trail(
        &self,
        request: tonic::Request<QueryAuditTrailRequest>,
    ) -> Result<tonic::Response<QueryAuditTrailResponse>, tonic::Status> {
        *self.seen.lock().unwrap() = Some(request.into_inner());
        Ok(tonic::Response::new(QueryAuditTrailResponse {
            events: vec![AuditEvent {
                id: 7,
                kind: WireKind::SecretRevealed as i32,
                path: "/apps/db/password".into(),
                occurred_at: Some(prost_types::Timestamp {
                    seconds: 200,
                    nanos: 0,
                }),
                first_occurred_at: Some(prost_types::Timestamp {
                    seconds: 100,
                    nanos: 0,
                }),
                event_count: 3,
                actor_subject: "subject".into(),
                actor_name: None,
                protocol_version: "v3".into(),
                old_value: None,
                new_value: None,
                narrative: "subject revealed secret /apps/db/password — 3 times".into(),
            }],
            next_cursor: self.next_cursor.into(),
        }))
    }
}

async fn scripted(
    next_cursor: &'static str,
) -> (String, Arc<Mutex<Option<QueryAuditTrailRequest>>>) {
    let seen = Arc::new(Mutex::new(None));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let service = AuditServer::new(ScriptedAudit {
        seen: Arc::clone(&seen),
        next_cursor,
    });
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
    );
    (format!("http://{address}"), seen)
}

/// The whole round trip: a populated query arrives intact and a populated
/// page comes back decoded — with an empty cursor meaning "no more", not "a
/// cursor that is empty".
#[tokio::test(flavor = "multi_thread")]
async fn a_populated_query_and_page_survive_the_round_trip() {
    for (cursor_on_wire, cursor_decoded) in [("next-sentinel", Some("next-sentinel")), ("", None)] {
        let (endpoint, seen) = scripted(cursor_on_wire).await;
        let channel = TonicChannel::connect(endpoint).await.unwrap();

        let page = channel
            .speaking(ProtocolVersion::V4)
            .query_audit_trail(
                &AuditQuery {
                    path_filter: Some("db".into()),
                    kinds: vec![AuditEventKind::SecretRevealed],
                    page_size: 5,
                    cursor: Some("previous-sentinel".into()),
                    ..AuditQuery::default()
                },
                &Secret::new("audit-token"),
            )
            .await
            .expect("the scripted page must decode");

        let request = seen.lock().unwrap().take().expect("the request arrived");
        assert_eq!(request.path_filter, "db");
        assert_eq!(request.kinds, [WireKind::SecretRevealed as i32]);
        assert_eq!(request.page_size, 5);
        assert_eq!(request.cursor, "previous-sentinel");

        assert_eq!(page.next_cursor.as_deref(), cursor_decoded);
        let [entry] = page.events.as_slice() else {
            panic!("one event expected: {page:?}");
        };
        assert_eq!(entry.id, 7);
        assert_eq!(entry.kind, AuditEventKind::SecretRevealed);
        assert_eq!(entry.path.as_str(), "/apps/db/password");
        assert_eq!(entry.event_count, 3);
        assert_eq!(
            (entry.first_occurred_at.seconds, entry.occurred_at.seconds),
            (100, 200)
        );
        assert_eq!(entry.actor_name, None);
        assert_eq!(entry.protocol_version, "v3");
    }
}
