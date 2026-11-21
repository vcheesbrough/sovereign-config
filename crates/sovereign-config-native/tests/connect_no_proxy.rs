//! The Connect transport never takes a proxy from the environment: it goes
//! straight to the endpoint, as the gRPC transport does, so a bearer cannot
//! leave on an undeclared route — in clear text, for a loopback endpoint.
//!
//! The proxy variables are process-wide, and setting them in-process is
//! `unsafe` (which the workspace forbids) and would leak into other tests. So
//! the test runs itself again as a child process with them set, while this
//! process hosts both the endpoint and the proxy and counts what reaches each.

use std::{
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{body::Body, extract::Request, response::Response};
use prost::Message;
use sovereign_config_client::Handshake;
use sovereign_config_core::ProtocolVersion;
use sovereign_config_native::TonicChannel;
use sovereign_config_proto::sovereign::config::{NegotiateResponse, ServedProtocolVersion};

const TEST_NAME: &str = "the_connect_transport_ignores_proxies_in_the_environment";
/// Set only in the child: the endpoint it is to call.
const CHILD_ENDPOINT: &str = "SOVEREIGN_CONFIG_NO_PROXY_TEST_ENDPOINT";

/// A server that counts what reaches it, answering every request with a
/// Connect handshake reply naming `v6`.
async fn counting_server(seen: Arc<AtomicUsize>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = axum::Router::new().fallback(move |_: Request| {
        let seen = Arc::clone(&seen);
        async move {
            seen.fetch_add(1, Ordering::SeqCst);
            let reply = NegotiateResponse {
                served_protocol_versions: vec![ServedProtocolVersion {
                    protocol_version: "v6".into(),
                    deprecation_date: None,
                }],
            };
            Response::builder()
                .status(200)
                .header("content-type", "application/proto")
                .body(Body::from(reply.encode_to_vec()))
                .unwrap()
        }
    });
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{address}")
}

#[tokio::test(flavor = "multi_thread")]
async fn the_connect_transport_ignores_proxies_in_the_environment() {
    // The child: one handshake, under the proxy variables the parent set.
    if let Ok(endpoint) = std::env::var(CHILD_ENDPOINT) {
        let channel = TonicChannel::connect(endpoint).await.unwrap();
        let served = channel
            .served_versions(ProtocolVersion::ALL)
            .await
            .expect("the handshake must reach the endpoint");
        assert_eq!(served[0].version, "v6");
        return;
    }

    let proxied = Arc::new(AtomicUsize::new(0));
    let reached = Arc::new(AtomicUsize::new(0));
    let proxy = counting_server(Arc::clone(&proxied)).await;
    let endpoint = counting_server(Arc::clone(&reached)).await;
    let child = tokio::task::spawn_blocking(move || {
        Command::new(std::env::current_exe().unwrap())
            .args([TEST_NAME, "--exact", "--nocapture"])
            .env(CHILD_ENDPOINT, &endpoint)
            .env("HTTP_PROXY", &proxy)
            .env("http_proxy", &proxy)
            .env("HTTPS_PROXY", &proxy)
            .env("ALL_PROXY", &proxy)
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        child.status.success(),
        "{}",
        String::from_utf8_lossy(&child.stdout)
    );
    assert_eq!(
        proxied.load(Ordering::SeqCst),
        0,
        "nothing went to the proxy"
    );
    assert_eq!(reached.load(Ordering::SeqCst), 1, "the endpoint was called");
}
