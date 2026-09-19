//! End-to-end tests driving `Provider::connect`/`load` against a mock OIDC
//! issuer (axum) and an in-process native gRPC server (tonic). These reuse the
//! same harness shapes as `sovereign-config-native`'s own transport/OIDC tests.

use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response as AxumResponse},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::json;
use sovereign_config_core::{ConfigPath, ConnectionUrl, Secret};
use sovereign_config_proto::sovereign::config::v3::{
    AddValuePathRequest, AddValuePathResponse, DeleteValuesRequest, DeleteValuesResponse,
    GetIdentityRequest, GetIdentityResponse, GetSubTreeRequest, GetSubTreeResponse,
    GetVersionRequest, GetVersionResponse, ListValuePathsRequest, ListValuePathsResponse,
    ListValuesRequest, ListValuesResponse, MaskedSecret, PutValueRequest, PutValueResponse,
    ReplaceSubTreeRequest, ReplaceSubTreeResponse, RevealSecretRequest, RevealSecretResponse,
    SubTreeValue, ValueClassification,
    configuration_server::{Configuration, ConfigurationServer},
    sub_tree_value,
    system_server::{System, SystemServer},
};
use sovereign_config_provider::{Provider, ProviderError};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Code, Request, Response, Status, transport::Server};

const ROOT: &str = "/apps/api";

#[derive(Clone)]
enum SubtreeOutcome {
    Ok,
    Status(Code),
    Malformed,
}

struct MockState {
    application_version: String,
    protocol_version: String,
    supported_protocol_versions: Vec<String>,
    token_ok: bool,
    /// Behind a `Mutex` so a test can change what the service does *between*
    /// loads, which is how the no-caching guarantee is asserted.
    subtree: Mutex<SubtreeOutcome>,
    plain: BTreeMap<String, String>,
    secrets: BTreeMap<String, String>,
    token_requests: AtomicUsize,
    subtree_requests: AtomicUsize,
    reveal_requests: AtomicUsize,
}

impl MockState {
    fn happy() -> Self {
        let mut plain = BTreeMap::new();
        plain.insert("/apps/api/feature".to_owned(), "on".to_owned());
        plain.insert(
            "/apps/api/database/url".to_owned(),
            "postgres://localhost/app".to_owned(),
        );
        let mut secrets = BTreeMap::new();
        secrets.insert(
            "/apps/api/database/password".to_owned(),
            "app-password-sentinel".to_owned(),
        );
        Self {
            application_version: "2.0.0".to_owned(),
            protocol_version: "v3".to_owned(),
            supported_protocol_versions: vec!["v3".to_owned()],
            token_ok: true,
            subtree: Mutex::new(SubtreeOutcome::Ok),
            plain,
            secrets,
            token_requests: AtomicUsize::new(0),
            subtree_requests: AtomicUsize::new(0),
            reveal_requests: AtomicUsize::new(0),
        }
    }
}

struct MockSystem(Arc<MockState>);

#[tonic::async_trait]
impl System for MockSystem {
    async fn get_version(
        &self,
        _: Request<GetVersionRequest>,
    ) -> Result<Response<GetVersionResponse>, Status> {
        Ok(Response::new(GetVersionResponse {
            application_version: self.0.application_version.clone(),
            protocol_version: self.0.protocol_version.clone(),
            supported_protocol_versions: self.0.supported_protocol_versions.clone(),
        }))
    }

    async fn get_identity(
        &self,
        _: Request<GetIdentityRequest>,
    ) -> Result<Response<GetIdentityResponse>, Status> {
        Ok(Response::new(GetIdentityResponse {
            authenticated: true,
        }))
    }
}

struct MockConfiguration(Arc<MockState>);

#[tonic::async_trait]
impl Configuration for MockConfiguration {
    async fn list_values(
        &self,
        _: Request<ListValuesRequest>,
    ) -> Result<Response<ListValuesResponse>, Status> {
        Err(Status::unimplemented("list_values"))
    }

    async fn get_sub_tree(
        &self,
        _: Request<GetSubTreeRequest>,
    ) -> Result<Response<GetSubTreeResponse>, Status> {
        self.0.subtree_requests.fetch_add(1, Ordering::SeqCst);
        let outcome = self.0.subtree.lock().expect("subtree outcome lock").clone();
        match &outcome {
            SubtreeOutcome::Status(code) => Err(Status::new(*code, "denied")),
            SubtreeOutcome::Malformed => Ok(Response::new(GetSubTreeResponse {
                values: vec![SubTreeValue {
                    path: format!("{ROOT}/feature"),
                    content: Some(sub_tree_value::Content::PlainValue("on".to_owned())),
                    classification: ValueClassification::Unspecified as i32,
                }],
            })),
            SubtreeOutcome::Ok => {
                let mut values = Vec::new();
                for (path, value) in &self.0.plain {
                    values.push(SubTreeValue {
                        path: path.clone(),
                        content: Some(sub_tree_value::Content::PlainValue(value.clone())),
                        classification: ValueClassification::Plain as i32,
                    });
                }
                for path in self.0.secrets.keys() {
                    values.push(SubTreeValue {
                        path: path.clone(),
                        content: Some(sub_tree_value::Content::MaskedSecret(MaskedSecret {})),
                        classification: ValueClassification::Secret as i32,
                    });
                }
                Ok(Response::new(GetSubTreeResponse { values }))
            }
        }
    }

    async fn put_value(
        &self,
        _: Request<PutValueRequest>,
    ) -> Result<Response<PutValueResponse>, Status> {
        Err(Status::unimplemented("put_value"))
    }

    async fn replace_sub_tree(
        &self,
        _: Request<ReplaceSubTreeRequest>,
    ) -> Result<Response<ReplaceSubTreeResponse>, Status> {
        Err(Status::unimplemented("replace_sub_tree"))
    }

    async fn delete_values(
        &self,
        _: Request<DeleteValuesRequest>,
    ) -> Result<Response<DeleteValuesResponse>, Status> {
        Err(Status::unimplemented("delete_values"))
    }

    async fn reveal_secret(
        &self,
        request: Request<RevealSecretRequest>,
    ) -> Result<Response<RevealSecretResponse>, Status> {
        self.0.reveal_requests.fetch_add(1, Ordering::SeqCst);
        let path = request.into_inner().path;
        match self.0.secrets.get(&path) {
            Some(value) => Ok(Response::new(RevealSecretResponse {
                value: value.clone(),
            })),
            None => Err(Status::not_found("no secret")),
        }
    }

    async fn add_value_path(
        &self,
        _: Request<AddValuePathRequest>,
    ) -> Result<Response<AddValuePathResponse>, Status> {
        Err(Status::unimplemented("add_value_path"))
    }

    async fn list_value_paths(
        &self,
        _: Request<ListValuePathsRequest>,
    ) -> Result<Response<ListValuePathsResponse>, Status> {
        Err(Status::unimplemented("list_value_paths"))
    }
}

async fn issuer_discovery(State(state): State<Arc<IssuerState>>) -> Json<serde_json::Value> {
    Json(json!({"token_endpoint": format!("{}token", state.issuer)}))
}

async fn issuer_token(State(state): State<Arc<IssuerState>>) -> AxumResponse {
    state.mock.token_requests.fetch_add(1, Ordering::SeqCst);
    if state.mock.token_ok {
        Json(json!({"access_token": "access-token-sentinel"})).into_response()
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_client"})),
        )
            .into_response()
    }
}

struct IssuerState {
    issuer: String,
    mock: Arc<MockState>,
}

struct Harness {
    url: String,
    mock: Arc<MockState>,
    issuer_task: tokio::task::JoinHandle<()>,
    grpc_task: tokio::task::JoinHandle<()>,
}

impl Harness {
    async fn start(mock: Arc<MockState>) -> Self {
        let issuer_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer_address = issuer_listener.local_addr().unwrap();
        let issuer = format!("http://{issuer_address}/");
        let issuer_state = Arc::new(IssuerState {
            issuer: issuer.clone(),
            mock: mock.clone(),
        });
        let issuer_app = Router::new()
            .route("/.well-known/openid-configuration", get(issuer_discovery))
            .route("/token", post(issuer_token))
            .with_state(issuer_state);
        let issuer_task = tokio::spawn(async move {
            axum::serve(issuer_listener, issuer_app).await.unwrap();
        });

        let grpc_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let grpc_address = grpc_listener.local_addr().unwrap();
        let grpc_mock = mock.clone();
        let grpc_task = tokio::spawn(async move {
            Server::builder()
                .add_service(SystemServer::new(MockSystem(grpc_mock.clone())))
                .add_service(ConfigurationServer::new(MockConfiguration(grpc_mock)))
                .serve_with_incoming(TcpListenerStream::new(grpc_listener))
                .await
                .unwrap();
        });

        let root = ConfigPath::parse(ROOT).unwrap();
        let url = ConnectionUrl::managed(
            &format!("http://{grpc_address}"),
            &root,
            &issuer,
            "test-client",
            "generated-username",
            &Secret::new("app-password"),
        )
        .unwrap();
        let url = url.canonical().expose().to_owned();

        Self {
            url,
            mock,
            issuer_task,
            grpc_task,
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.issuer_task.abort();
        self.grpc_task.abort();
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
struct Database {
    url: String,
    password: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
struct AppConfig {
    feature: String,
    database: Database,
}

async fn load_error(provider: &Provider) -> ProviderError {
    match provider.load::<AppConfig>().await {
        Ok(_) => panic!("load unexpectedly succeeded"),
        Err(error) => error,
    }
}

#[tokio::test]
async fn loads_typed_configuration_including_revealed_secrets() {
    let harness = Harness::start(Arc::new(MockState::happy())).await;
    let provider = Provider::connect(&harness.url).await.unwrap();
    let config: AppConfig = provider.load().await.unwrap();

    assert_eq!(
        config,
        AppConfig {
            feature: "on".to_owned(),
            database: Database {
                url: "postgres://localhost/app".to_owned(),
                password: "app-password-sentinel".to_owned(),
            },
        }
    );
    assert_eq!(harness.mock.reveal_requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn load_json_returns_the_revealed_subtree_as_json() {
    let harness = Harness::start(Arc::new(MockState::happy())).await;
    let provider = Provider::connect(&harness.url).await.unwrap();
    let json = provider.load_json().await.unwrap();

    // A downstream `config`-crate layer parses exactly this text.
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        parsed,
        json!({
            "feature": "on",
            "database": {
                "url": "postgres://localhost/app",
                "password": "app-password-sentinel",
            },
        })
    );
    assert_eq!(harness.mock.reveal_requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn load_does_not_coerce_string_leaves_to_typed_fields() {
    // Every stored leaf is text, and `load` deserializes strictly through
    // serde_json, which does not turn `"8080"` into a `u16`.
    #[derive(Debug, Deserialize)]
    struct Typed {
        #[allow(dead_code)]
        port: u16,
    }

    let mut state = MockState::happy();
    state.plain.clear();
    state.secrets.clear();
    state
        .plain
        .insert("/apps/api/port".to_owned(), "8080".to_owned());
    let harness = Harness::start(Arc::new(state)).await;
    let provider = Provider::connect(&harness.url).await.unwrap();

    let result = provider.load::<Typed>().await;
    assert!(matches!(result, Err(ProviderError::InvalidConversion)));
}

#[cfg(feature = "config")]
#[tokio::test]
async fn config_source_coerces_string_leaves_to_typed_fields() {
    use config::Config;
    use sovereign_config_provider::SovereignConfigSource;

    // The same string leaves that `load` rejects deserialize cleanly through
    // `config`, which coerces `"8080"` -> u16 and `"true"` -> bool.
    #[derive(Debug, Deserialize, Eq, PartialEq)]
    struct Typed {
        port: u16,
        enabled: bool,
    }

    let mut state = MockState::happy();
    state.plain.clear();
    state.secrets.clear();
    state
        .plain
        .insert("/apps/api/port".to_owned(), "8080".to_owned());
    state
        .plain
        .insert("/apps/api/enabled".to_owned(), "true".to_owned());
    let harness = Harness::start(Arc::new(state)).await;
    let url = harness.url.clone();

    let typed = tokio::task::spawn_blocking(move || {
        Config::builder()
            .add_source(SovereignConfigSource::initialise_from_url(url))
            .build()
            .unwrap()
            .try_deserialize::<Typed>()
            .unwrap()
    })
    .await
    .unwrap();

    assert_eq!(
        typed,
        Typed {
            port: 8080,
            enabled: true,
        }
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn config_source_layers_the_managed_subtree() {
    use config::Config;
    use sovereign_config_provider::SovereignConfigSource;

    let harness = Harness::start(Arc::new(MockState::happy())).await;
    let url = harness.url.clone();

    // The source blocks internally, so run the builder off the async runtime
    // thread; the mock servers keep running on this test's runtime meanwhile.
    let config = tokio::task::spawn_blocking(move || {
        Config::builder()
            .add_source(SovereignConfigSource::initialise_from_url(url))
            .build()
            .unwrap()
            .try_deserialize::<AppConfig>()
            .unwrap()
    })
    .await
    .unwrap();

    assert_eq!(
        config,
        AppConfig {
            feature: "on".to_owned(),
            database: Database {
                url: "postgres://localhost/app".to_owned(),
                password: "app-password-sentinel".to_owned(),
            },
        }
    );
    assert_eq!(harness.mock.reveal_requests.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "config")]
#[test]
fn config_source_debug_does_not_leak_the_url() {
    use sovereign_config_provider::SovereignConfigSource;

    let source = SovereignConfigSource::initialise_from_url(
        "https://config.example.test/apps/api#v=1&client_secret=super-secret-sentinel",
    );
    let rendered = format!("{source:?}");
    assert!(!rendered.contains("super-secret-sentinel"));
    assert!(!rendered.contains("config.example.test"));
}

#[tokio::test]
async fn each_load_reacquires_token_and_rereads_without_cache() {
    let harness = Harness::start(Arc::new(MockState::happy())).await;
    let provider = Provider::connect(&harness.url).await.unwrap();
    let _first: AppConfig = provider.load().await.unwrap();
    let _second: AppConfig = provider.load().await.unwrap();

    assert_eq!(harness.mock.token_requests.load(Ordering::SeqCst), 2);
    assert_eq!(harness.mock.subtree_requests.load(Ordering::SeqCst), 2);
    assert_eq!(harness.mock.reveal_requests.load(Ordering::SeqCst), 2);
}

/// The rejected design, asserted rather than merely absent.
///
/// Caching a last-known-good subtree would hold revealed secrets in process
/// memory for the application's lifetime, so the provider deliberately does not
/// do it: a server that stops answering fails the *next* load instead of
/// silently serving a stale value. The supported-version range removes the
/// fleet-outage reason to want a cache; this asserts the cache never arrives by
/// the back door.
#[tokio::test]
async fn a_server_that_fails_after_a_successful_load_is_not_served_from_cache() {
    let harness = Harness::start(Arc::new(MockState::happy())).await;
    let provider = Provider::connect(&harness.url).await.unwrap();

    let first: AppConfig = provider.load().await.expect("the first load must succeed");
    assert_eq!(first.feature, "on");

    // The server stops answering after that successful load.
    *harness.mock.subtree.lock().unwrap() = SubtreeOutcome::Status(Code::Unavailable);

    assert_eq!(load_error(&provider).await, ProviderError::Unavailable);
    assert_eq!(
        harness.mock.subtree_requests.load(Ordering::SeqCst),
        2,
        "the second load must reach the server rather than answer from memory"
    );
}

/// The same guarantee across a protocol retirement: a connected provider does
/// not keep serving once the server has dropped the version it speaks.
#[tokio::test]
async fn a_load_after_the_server_becomes_incompatible_fails_rather_than_serving_stale_values() {
    let harness = Harness::start(Arc::new(MockState::happy())).await;
    let provider = Provider::connect(&harness.url).await.unwrap();
    let _first: AppConfig = provider.load().await.expect("the first load must succeed");

    // A retired protocol version is refused at the RPC, not at connect: the
    // provider connected before the retirement and never reconnects.
    *harness.mock.subtree.lock().unwrap() = SubtreeOutcome::Status(Code::FailedPrecondition);

    assert_eq!(
        load_error(&provider).await,
        ProviderError::IncompatibleProtocol
    );
}

#[tokio::test]
async fn token_rejection_is_authentication_failed() {
    let mut state = MockState::happy();
    state.token_ok = false;
    let harness = Harness::start(Arc::new(state)).await;
    let provider = Provider::connect(&harness.url).await.unwrap();
    assert_eq!(
        load_error(&provider).await,
        ProviderError::AuthenticationFailed
    );
    assert_eq!(harness.mock.subtree_requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn grpc_unauthenticated_is_authentication_failed() {
    let mut state = MockState::happy();
    state.subtree = Mutex::new(SubtreeOutcome::Status(Code::Unauthenticated));
    let harness = Harness::start(Arc::new(state)).await;
    let provider = Provider::connect(&harness.url).await.unwrap();
    assert_eq!(
        load_error(&provider).await,
        ProviderError::AuthenticationFailed
    );
}

#[tokio::test]
async fn denied_path_is_permission_denied() {
    let mut state = MockState::happy();
    state.subtree = Mutex::new(SubtreeOutcome::Status(Code::PermissionDenied));
    let harness = Harness::start(Arc::new(state)).await;
    let provider = Provider::connect(&harness.url).await.unwrap();
    assert_eq!(load_error(&provider).await, ProviderError::PermissionDenied);
    assert_eq!(harness.mock.reveal_requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn protocol_mismatch_is_incompatible_at_connect() {
    let mut state = MockState::happy();
    state.protocol_version = "v2".to_owned();
    state.supported_protocol_versions = vec!["v2".to_owned()];
    let harness = Harness::start(Arc::new(state)).await;
    match Provider::connect(&harness.url).await {
        Ok(_) => panic!("connect unexpectedly succeeded"),
        Err(error) => assert_eq!(error, ProviderError::IncompatibleProtocol),
    }
}

/// The regression that protects the deployed fleet.
///
/// A server that has gained a newer protocol version must keep serving this
/// build's version and must keep echoing the version that was *requested*. A
/// server echoing its own newest version instead would fail every already
/// deployed application the day that version ships, which is the fleet-wide
/// outage the supported range exists to prevent.
#[tokio::test]
async fn a_server_newer_than_this_build_still_connects() {
    let mut state = MockState::happy();
    state.application_version = "99.0.0".to_owned();
    state.protocol_version = "v3".to_owned();
    state.supported_protocol_versions = vec!["v3".to_owned(), "v4".to_owned()];
    let harness = Harness::start(Arc::new(state)).await;

    let provider = Provider::connect(&harness.url)
        .await
        .expect("a server still serving v3 must connect");

    // And the session works, not merely the handshake.
    let loaded: serde_json::Value = provider.load().await.expect("load must succeed");
    assert_eq!(loaded["feature"], "on");
}

/// A server that has *retired* this build's version hard-fails, which is the
/// announced, observable end of the deprecation window rather than a surprise.
#[tokio::test]
async fn a_server_that_retired_this_version_is_incompatible() {
    let mut state = MockState::happy();
    state.protocol_version = "v5".to_owned();
    state.supported_protocol_versions = vec!["v4".to_owned(), "v5".to_owned()];
    let harness = Harness::start(Arc::new(state)).await;

    match Provider::connect(&harness.url).await {
        Ok(_) => panic!("connect unexpectedly succeeded"),
        Err(error) => assert_eq!(error, ProviderError::IncompatibleProtocol),
    }
}

/// A server older than 2.25.0 advertises no supported set at all. Negotiation
/// must fall back to its echoed version rather than treating the empty set as
/// "serves nothing".
#[tokio::test]
async fn a_server_advertising_no_supported_set_still_connects() {
    let mut state = MockState::happy();
    state.supported_protocol_versions = Vec::new();
    let harness = Harness::start(Arc::new(state)).await;

    Provider::connect(&harness.url)
        .await
        .expect("a pre-2.25.0 server must still connect");
}

#[tokio::test]
async fn malformed_subtree_value_is_internal() {
    let mut state = MockState::happy();
    state.subtree = Mutex::new(SubtreeOutcome::Malformed);
    let harness = Harness::start(Arc::new(state)).await;
    let provider = Provider::connect(&harness.url).await.unwrap();
    assert_eq!(load_error(&provider).await, ProviderError::Internal);
}

#[tokio::test]
async fn unavailable_issuer_is_unavailable() {
    let harness = Harness::start(Arc::new(MockState::happy())).await;
    let provider = Provider::connect(&harness.url).await.unwrap();
    harness.issuer_task.abort();
    // Give the aborted listener a moment to release the port.
    for _ in 0..50 {
        if provider.load::<AppConfig>().await.is_err() {
            break;
        }
    }
    assert_eq!(load_error(&provider).await, ProviderError::Unavailable);
}
