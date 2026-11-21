//! The native client — the transport the CLI, the MCP server, the provider
//! and the broker share — through a proxy that forwards **HTTP/1.1 only**,
//! in front of the Connect stack: what a deployment without h2c offers a
//! client from 3.0 on.
//!
//! The proxy refuses any request that is not HTTP/1.1 and speaks HTTP/1.1
//! upstream, so nothing in a session that reaches the end can have needed
//! HTTP/2.

use std::env;

use axum::{body::Body, extract::Request, response::Response};
use http::{StatusCode, Version};
use sovereign_config_client::{Transport, ValueTransport, negotiate};
use sovereign_config_core::{ConfigPath, PlainValue, ProtocolVersion, Secret, ValueContent};
use sovereign_config_native::TonicChannel;

use super::tests::Harness;

/// The stand-in authentication's writer, without the scheme the transport
/// adds itself.
const WRITER_TOKEN: &str = "writer-token";

/// An HTTP/1.1-only reverse proxy to `upstream`, on an ephemeral port.
async fn http1_only_proxy(upstream: String) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let client = reqwest::Client::builder().http1_only().build().unwrap();
    let app = axum::Router::new().fallback(move |request: Request| {
        let client = client.clone();
        let upstream = upstream.clone();
        async move {
            if request.version() != Version::HTTP_11 {
                return Response::builder()
                    .status(StatusCode::HTTP_VERSION_NOT_SUPPORTED)
                    .body(Body::empty())
                    .unwrap();
            }
            let (parts, body) = request.into_parts();
            let body = axum::body::to_bytes(body, 8 * 1024 * 1024).await.unwrap();
            let mut forwarded = client
                .request(parts.method, format!("{upstream}{}", parts.uri.path()))
                .body(body);
            for (name, value) in &parts.headers {
                if name != http::header::HOST && name != http::header::CONTENT_LENGTH {
                    forwarded = forwarded.header(name, value);
                }
            }
            let answer = forwarded.send().await.unwrap();
            let mut response = Response::builder().status(answer.status());
            for (name, value) in answer.headers() {
                if name != http::header::TRANSFER_ENCODING && name != http::header::CONTENT_LENGTH {
                    response = response.header(name, value);
                }
            }
            response
                .body(Body::from(answer.bytes().await.unwrap()))
                .unwrap()
        }
    });
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{address}")
}

/// Negotiation, the release version and the caller's identity, through the
/// proxy: a whole session on `v6` with nothing to store.
#[tokio::test(flavor = "multi_thread")]
async fn the_native_client_negotiates_and_works_on_v6_through_an_http1_only_proxy() {
    let harness = Harness::start().await;
    let proxy = http1_only_proxy(harness.url("")).await;
    let channel = TonicChannel::connect(proxy).await.unwrap();

    let service = negotiate(&channel).await.unwrap();
    assert_eq!(service.protocol_version, ProtocolVersion::V6);
    let transport = channel.speaking(service.protocol_version);
    let version = transport.dialer_version().await.unwrap();
    assert_eq!(version.protocol_version, "v6");
    assert_eq!(version.application_version, crate::APPLICATION_VERSION);
    let identity = transport
        .get_identity(&Secret::new(WRITER_TOKEN))
        .await
        .unwrap();
    assert!(identity.authenticated);
}

/// A value written and read back through the proxy, on storage.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn the_native_client_writes_and_reads_on_v6_through_an_http1_only_proxy() {
    let database_url = env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL")
        .expect("SOVEREIGN_CONFIG_TEST_DATABASE_URL must be configured");
    super::db_tests::migrate(&database_url).await;
    let harness = Harness::over(&database_url).await;
    let proxy = http1_only_proxy(harness.url("")).await;
    let channel = TonicChannel::connect(proxy).await.unwrap();
    let transport = channel.speaking(negotiate(&channel).await.unwrap().protocol_version);
    assert_eq!(transport.protocol_version(), ProtocolVersion::V6);

    let root = super::db_tests::fresh_root("proxy");
    let path = ConfigPath::parse(format!("{root}/feature")).unwrap();
    let bearer = Secret::new(WRITER_TOKEN);
    transport
        .put_value(&path, &PlainValue::new("proxy-value-sentinel"), &bearer)
        .await
        .unwrap();
    let subtree = transport
        .get_subtree(&ConfigPath::parse(root).unwrap(), &bearer)
        .await
        .unwrap();
    assert_eq!(subtree.values.len(), 1);
    assert!(matches!(
        &subtree.values[0].value,
        ValueContent::Plain(value) if value.expose() == "proxy-value-sentinel"
    ));
}
