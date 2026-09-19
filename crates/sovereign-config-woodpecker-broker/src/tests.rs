//! End-to-end tests: a real `axum::serve` listener, a real signed request, a
//! real gRPC client, against an in-process mock configuration service and mock
//! OIDC issuer.
//!
//! These run on a **multi-thread** runtime deliberately. The broker's whole
//! concurrency design is the `Send` HTTP handler / `!Send` reader split, and a
//! current-thread runtime would not exercise it.

use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response as AxumResponse},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey, pkcs8::EncodePublicKey};
use serde_json::json;
use sha2::{Digest, Sha256};
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
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Code, Request, Response, Status, transport::Server};

use crate::{
    handler::{self, AppState},
    layers::LayerTemplates,
    metrics::Metrics,
    signature::SignatureVerifier,
    sovereign::{self, ConnectError},
};

const ROOT: &str = "/woodpecker";
const LAYERS: &str = "/woodpecker/global,/woodpecker/repos/{repo.owner}/{repo.name}";
const GITHUB_TOKEN: &str = "github-token-sentinel";
const ZOT_PASSWORD: &str = "zot-password-sentinel";

// ---------------------------------------------------------------------------
// Mock configuration service
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Eq, PartialEq)]
enum LayerOutcome {
    Values,
    Empty,
    Status(Code),
}

struct MockState {
    protocol_version: String,
    supported_protocol_versions: Vec<String>,
    /// Layer path -> what `GetSubTree` does for it.
    layers: BTreeMap<String, LayerOutcome>,
    plain: BTreeMap<String, String>,
    secrets: BTreeMap<String, String>,
    /// Number of leading `RevealSecret` calls to reject as unauthenticated,
    /// simulating a token revoked before its reported expiry.
    reject_reveals: AtomicUsize,
    /// Paths listed by `GetSubTree` whose `RevealSecret` returns `NotFound`,
    /// simulating a delete or re-alias that races the reveal.
    vanished_reveals: Mutex<std::collections::HashSet<String>>,
    /// Paths whose `RevealSecret` returns `PermissionDenied`, simulating a grant
    /// that does not actually cover a leaf its layer could list.
    denied_reveals: Mutex<std::collections::HashSet<String>>,
    token_requests: AtomicUsize,
    subtree_requests: AtomicUsize,
    reveal_requests: AtomicUsize,
    subtree_paths: Mutex<Vec<String>>,
}

impl MockState {
    fn happy() -> Self {
        let mut layers = BTreeMap::new();
        layers.insert("/woodpecker/global".to_owned(), LayerOutcome::Values);
        layers.insert(
            "/woodpecker/repos/vcheesbrough/sovereign-config".to_owned(),
            LayerOutcome::Values,
        );
        layers.insert(
            "/woodpecker/repos/vcheesbrough/bored".to_owned(),
            LayerOutcome::Values,
        );

        let mut plain = BTreeMap::new();
        // Global default, overridden per repository below.
        plain.insert("/woodpecker/global/zot_ci_user".to_owned(), "ci".to_owned());
        plain.insert(
            "/woodpecker/global/registry".to_owned(),
            "registry.desync.link".to_owned(),
        );
        plain.insert(
            "/woodpecker/repos/vcheesbrough/sovereign-config/zot_ci_user".to_owned(),
            "sovereign-ci".to_owned(),
        );
        plain.insert(
            "/woodpecker/repos/vcheesbrough/bored/zot_ci_user".to_owned(),
            "bored-ci".to_owned(),
        );

        let mut secrets = BTreeMap::new();
        secrets.insert(
            "/woodpecker/global/zot_ci_password".to_owned(),
            ZOT_PASSWORD.to_owned(),
        );
        secrets.insert(
            "/woodpecker/repos/vcheesbrough/sovereign-config/github_token".to_owned(),
            GITHUB_TOKEN.to_owned(),
        );

        Self {
            protocol_version: sovereign_config_core::ProtocolVersion::PREFERRED
                .as_str()
                .to_owned(),
            supported_protocol_versions: vec![
                sovereign_config_core::ProtocolVersion::PREFERRED
                    .as_str()
                    .to_owned(),
            ],
            layers,
            plain,
            secrets,
            reject_reveals: AtomicUsize::new(0),
            vanished_reveals: Mutex::new(std::collections::HashSet::new()),
            denied_reveals: Mutex::new(std::collections::HashSet::new()),
            token_requests: AtomicUsize::new(0),
            subtree_requests: AtomicUsize::new(0),
            reveal_requests: AtomicUsize::new(0),
            subtree_paths: Mutex::new(Vec::new()),
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
            application_version: "2.15.0".to_owned(),
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
    async fn get_sub_tree(
        &self,
        request: Request<GetSubTreeRequest>,
    ) -> Result<Response<GetSubTreeResponse>, Status> {
        self.0.subtree_requests.fetch_add(1, Ordering::SeqCst);
        let path = request.into_inner().path;
        self.0.subtree_paths.lock().unwrap().push(path.clone());

        match self.0.layers.get(&path) {
            // An unconfigured layer behaves as the real service does for an
            // absent path: an empty subtree, not an error.
            None | Some(LayerOutcome::Empty) => {
                Ok(Response::new(GetSubTreeResponse { values: Vec::new() }))
            }
            Some(LayerOutcome::Status(code)) => Err(Status::new(*code, "denied")),
            Some(LayerOutcome::Values) => {
                let mut values = Vec::new();
                for (stored, value) in &self.0.plain {
                    if is_child(&path, stored) {
                        values.push(SubTreeValue {
                            path: stored.clone(),
                            content: Some(sub_tree_value::Content::PlainValue(value.clone())),
                            classification: ValueClassification::Plain as i32,
                        });
                    }
                }
                for stored in self.0.secrets.keys() {
                    if is_child(&path, stored) {
                        values.push(SubTreeValue {
                            path: stored.clone(),
                            content: Some(sub_tree_value::Content::MaskedSecret(MaskedSecret {})),
                            classification: ValueClassification::Secret as i32,
                        });
                    }
                }
                Ok(Response::new(GetSubTreeResponse { values }))
            }
        }
    }

    async fn reveal_secret(
        &self,
        request: Request<RevealSecretRequest>,
    ) -> Result<Response<RevealSecretResponse>, Status> {
        self.0.reveal_requests.fetch_add(1, Ordering::SeqCst);
        if self
            .0
            .reject_reveals
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(Status::unauthenticated("token rejected"));
        }
        let path = request.into_inner().path;
        if self.0.denied_reveals.lock().unwrap().contains(&path) {
            return Err(Status::permission_denied("denied"));
        }
        if self.0.vanished_reveals.lock().unwrap().contains(&path) {
            return Err(Status::not_found("no secret"));
        }
        match self.0.secrets.get(&path) {
            Some(value) => Ok(Response::new(RevealSecretResponse {
                value: value.clone(),
            })),
            None => Err(Status::not_found("no secret")),
        }
    }

    async fn list_values(
        &self,
        _: Request<ListValuesRequest>,
    ) -> Result<Response<ListValuesResponse>, Status> {
        Err(Status::unimplemented("list_values"))
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

fn is_child(layer: &str, path: &str) -> bool {
    path.strip_prefix(layer)
        .and_then(|rest| rest.strip_prefix('/'))
        .is_some_and(|name| !name.is_empty() && !name.contains('/'))
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct IssuerState {
    issuer: String,
    mock: Arc<MockState>,
}

async fn issuer_discovery(State(state): State<Arc<IssuerState>>) -> Json<serde_json::Value> {
    Json(json!({"token_endpoint": format!("{}token", state.issuer)}))
}

async fn issuer_token(State(state): State<Arc<IssuerState>>) -> AxumResponse {
    state.mock.token_requests.fetch_add(1, Ordering::SeqCst);
    Json(json!({"access_token": "access-token-sentinel", "expires_in": 3600})).into_response()
}

struct Harness {
    address: String,
    mock: Arc<MockState>,
    signing_key: SigningKey,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Harness {
    async fn start(mock: Arc<MockState>) -> Result<Self, ConnectError> {
        Self::start_with_layers(mock, LAYERS).await
    }

    async fn start_with_layers(mock: Arc<MockState>, layers: &str) -> Result<Self, ConnectError> {
        let mut tasks = Vec::new();

        let issuer_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}/", issuer_listener.local_addr().unwrap());
        let issuer_app = Router::new()
            .route("/.well-known/openid-configuration", get(issuer_discovery))
            .route("/token", post(issuer_token))
            .with_state(Arc::new(IssuerState {
                issuer: issuer.clone(),
                mock: Arc::clone(&mock),
            }));
        tasks.push(tokio::spawn(async move {
            axum::serve(issuer_listener, issuer_app).await.unwrap();
        }));

        let grpc_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let grpc_address = grpc_listener.local_addr().unwrap();
        let grpc_mock = Arc::clone(&mock);
        tasks.push(tokio::spawn(async move {
            Server::builder()
                .add_service(SystemServer::new(MockSystem(Arc::clone(&grpc_mock))))
                .add_service(ConfigurationServer::new(MockConfiguration(grpc_mock)))
                .serve_with_incoming(TcpListenerStream::new(grpc_listener))
                .await
                .unwrap();
        }));

        let url = ConnectionUrl::managed(
            &format!("http://{grpc_address}"),
            &ConfigPath::parse(ROOT).unwrap(),
            &issuer,
            "broker",
            "generated-username",
            &Secret::new("app-password"),
        )
        .unwrap();

        // `spawn` blocks until the reader has connected and negotiated the
        // protocol, so it must not run on the runtime's only thread.
        let connection = Secret::new(url.canonical().expose().to_owned());
        let handle = tokio::task::spawn_blocking(move || {
            sovereign::spawn(connection, 16, Duration::from_secs(3600))
        })
        .await
        .unwrap();
        let handle = match handle {
            Ok(handle) => handle,
            Err(error) => {
                for task in tasks {
                    task.abort();
                }
                return Err(error);
            }
        };

        let signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let pem = signing_key
            .verifying_key()
            .to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .unwrap();

        let app = handler::router(AppState {
            verifier: Arc::new(SignatureVerifier::from_spki_pem(&pem).unwrap()),
            layers: Arc::new(LayerTemplates::parse(layers).unwrap()),
            sovereign: handle,
            metrics: Arc::new(Metrics::default()),
        });
        let broker_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = broker_listener.local_addr().unwrap().to_string();
        tasks.push(tokio::spawn(async move {
            axum::serve(broker_listener, app).await.unwrap();
        }));

        Ok(Self {
            address,
            mock,
            signing_key,
            tasks,
        })
    }

    /// Signs and sends a `/secrets` request the way Woodpecker does.
    async fn post_secrets(&self, owner: &str, name: &str) -> (StatusCode, serde_json::Value) {
        let body = serde_json::to_vec(&json!({
            "repo": {"owner": owner, "name": name, "full_name": format!("{owner}/{name}")},
            "pipeline": {"branch": "main", "event": "push"},
            "netrc": {"machine": "forge", "login": "u", "password": "netrc-sentinel"},
        }))
        .unwrap();
        self.send(self.sign(&body), body).await
    }

    fn sign(&self, body: &[u8]) -> Vec<(String, String)> {
        let created = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let digest = format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(body)));
        let params =
            format!("(\"@request-target\" \"content-digest\");created={created};alg=\"ed25519\"");
        let base = format!(
            "\"@request-target\": /secrets\n\"content-digest\": {digest}\n\"@signature-params\": {params}"
        );
        let signature = self.signing_key.sign(base.as_bytes());
        vec![
            ("content-digest".to_owned(), digest),
            (
                "signature-input".to_owned(),
                format!("woodpecker-ci-extensions={params}"),
            ),
            (
                "signature".to_owned(),
                format!(
                    "woodpecker-ci-extensions=:{}:",
                    STANDARD.encode(signature.to_bytes())
                ),
            ),
        ]
    }

    async fn send(
        &self,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> (StatusCode, serde_json::Value) {
        let mut request = reqwest::Client::new()
            .post(format!("http://{}/secrets", self.address))
            .header("content-type", "application/json");
        for (name, value) in headers {
            request = request.header(name, value);
        }
        let response = request.body(body).send().await.unwrap();
        let status = response.status();
        let json = response
            .json::<serde_json::Value>()
            .await
            .unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    fn names_and_values(response: &serde_json::Value) -> Vec<(String, String)> {
        response["secrets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|secret| {
                (
                    secret["name"].as_str().unwrap().to_owned(),
                    secret["value"].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The headline behaviour: the per-repo layer is chosen from the *request*, and
/// overrides the global layer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_repository_resolves_its_own_layer_over_the_shared_ones() {
    let harness = Harness::start(Arc::new(MockState::happy())).await.unwrap();

    let (status, body) = harness
        .post_secrets("vcheesbrough", "sovereign-config")
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        Harness::names_and_values(&body),
        vec![
            // Sorted by name; the repo layer's zot_ci_user wins over global's.
            ("github_token".to_owned(), GITHUB_TOKEN.to_owned()),
            ("registry".to_owned(), "registry.desync.link".to_owned()),
            ("zot_ci_password".to_owned(), ZOT_PASSWORD.to_owned()),
            ("zot_ci_user".to_owned(), "sovereign-ci".to_owned()),
        ]
    );

    // A different repository in the same process reads a different per-repo
    // layer and does not see the other repository's secret.
    let (status, body) = harness.post_secrets("vcheesbrough", "bored").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        Harness::names_and_values(&body),
        vec![
            ("registry".to_owned(), "registry.desync.link".to_owned()),
            ("zot_ci_password".to_owned(), ZOT_PASSWORD.to_owned()),
            ("zot_ci_user".to_owned(), "bored-ci".to_owned()),
        ]
    );

    let read = harness.mock.subtree_paths.lock().unwrap().clone();
    assert_eq!(
        read,
        vec![
            "/woodpecker/global",
            "/woodpecker/repos/vcheesbrough/sovereign-config",
            "/woodpecker/global",
            "/woodpecker/repos/vcheesbrough/bored",
        ]
    );
}

/// One `GetSubTree` per layer, one `RevealSecret` per secret leaf, and exactly
/// one token across both requests — the cache is doing its job.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reads_are_one_subtree_per_layer_and_one_reveal_per_secret() {
    let harness = Harness::start(Arc::new(MockState::happy())).await.unwrap();

    harness
        .post_secrets("vcheesbrough", "sovereign-config")
        .await;
    assert_eq!(harness.mock.subtree_requests.load(Ordering::SeqCst), 2);
    assert_eq!(harness.mock.reveal_requests.load(Ordering::SeqCst), 2);

    harness
        .post_secrets("vcheesbrough", "sovereign-config")
        .await;
    assert_eq!(harness.mock.subtree_requests.load(Ordering::SeqCst), 4);
    assert_eq!(harness.mock.reveal_requests.load(Ordering::SeqCst), 4);
    assert_eq!(
        harness.mock.token_requests.load(Ordering::SeqCst),
        1,
        "the access token should be cached across requests"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_absent_or_forbidden_layer_is_skipped_and_the_others_still_resolve() {
    let mut state = MockState::happy();
    // The repo has no per-repo layer at all.
    state.layers.insert(
        "/woodpecker/repos/vcheesbrough/v-note".to_owned(),
        LayerOutcome::Empty,
    );
    let harness = Harness::start(Arc::new(state)).await.unwrap();

    let (status, body) = harness.post_secrets("vcheesbrough", "v-note").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        Harness::names_and_values(&body)
            .into_iter()
            .map(|(name, _)| name)
            .collect::<Vec<_>>(),
        vec!["registry", "zot_ci_password", "zot_ci_user"]
    );

    // A layer the connection may not read is skipped the same way.
    let mut state = MockState::happy();
    state.layers.insert(
        "/woodpecker/repos/vcheesbrough/sovereign-config".to_owned(),
        LayerOutcome::Status(Code::PermissionDenied),
    );
    let harness = Harness::start(Arc::new(state)).await.unwrap();
    let (status, body) = harness
        .post_secrets("vcheesbrough", "sovereign-config")
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        Harness::names_and_values(&body)
            .into_iter()
            .map(|(name, _)| name)
            .collect::<Vec<_>>(),
        vec!["registry", "zot_ci_password", "zot_ci_user"]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unavailable_store_is_a_service_error_not_an_empty_result() {
    // Returning 200 with no secrets here would look to Woodpecker like "this
    // repo has no secrets" and produce a baffling pipeline failure.
    let mut state = MockState::happy();
    state.layers.insert(
        "/woodpecker/global".to_owned(),
        LayerOutcome::Status(Code::Unavailable),
    );
    let harness = Harness::start(Arc::new(state)).await.unwrap();

    let (status, body) = harness
        .post_secrets("vcheesbrough", "sovereign-config")
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "secret store unavailable");
}

/// A token can be revoked before its reported lifetime ends; the reader must
/// notice, drop the cache, and retry once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejected_token_is_re_acquired_and_the_call_retried_once() {
    let state = MockState::happy();
    state.reject_reveals.store(1, Ordering::SeqCst);
    let harness = Harness::start(Arc::new(state)).await.unwrap();

    let (status, body) = harness
        .post_secrets("vcheesbrough", "sovereign-config")
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(Harness::names_and_values(&body).len(), 4);
    assert_eq!(
        harness.mock.token_requests.load(Ordering::SeqCst),
        2,
        "the rejected token should have been re-acquired exactly once"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_persistently_rejected_token_reports_auth_unavailable() {
    let state = MockState::happy();
    state.reject_reveals.store(usize::MAX, Ordering::SeqCst);
    let harness = Harness::start(Arc::new(state)).await.unwrap();

    let (status, body) = harness
        .post_secrets("vcheesbrough", "sovereign-config")
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "auth unavailable");
}

/// A leaf that `GetSubTree` lists can be deleted or re-aliased before its
/// `RevealSecret`. That must drop the one value, not fail the whole request —
/// Woodpecker swallows a 503 and falls back to its own store, so one racing
/// delete would otherwise strip every concurrent pipeline of every secret.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_secret_removed_between_listing_and_reveal_is_dropped_not_failed() {
    let state = MockState::happy();
    state
        .vanished_reveals
        .lock()
        .unwrap()
        .insert("/woodpecker/global/zot_ci_password".to_owned());
    let harness = Harness::start(Arc::new(state)).await.unwrap();

    let (status, body) = harness
        .post_secrets("vcheesbrough", "sovereign-config")
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        Harness::names_and_values(&body)
            .into_iter()
            .map(|(name, _)| name)
            .collect::<Vec<_>>(),
        // zot_ci_password vanished; every other secret still resolves.
        vec!["github_token", "registry", "zot_ci_user"]
    );
}

/// Unlike a vanished leaf, a denied reveal is not a race: the layer itself was
/// readable, so a denial on one of its leaves means the grant does not cover
/// what it appears to. That is worth surfacing rather than silently dropping.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_permission_denied_reveal_fails_the_whole_request() {
    let state = MockState::happy();
    state
        .denied_reveals
        .lock()
        .unwrap()
        .insert("/woodpecker/global/zot_ci_password".to_owned());
    let harness = Harness::start(Arc::new(state)).await.unwrap();

    let (status, body) = harness
        .post_secrets("vcheesbrough", "sovereign-config")
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "secret store unavailable");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsigned_tampered_and_replayed_requests_are_rejected() {
    let harness = Harness::start(Arc::new(MockState::happy())).await.unwrap();
    let body = serde_json::to_vec(&json!({
        "repo": {"owner": "vcheesbrough", "name": "sovereign-config", "full_name": "vcheesbrough/sovereign-config"},
        "pipeline": {"branch": "main", "event": "push"},
    }))
    .unwrap();

    // No signature at all.
    let (status, json) = harness.send(Vec::new(), body.clone()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["error"], "signature verification failed");

    // Signed for this body, delivered with a different one — the replay the Go
    // broker would have accepted, because it never checks the digest.
    let forged = serde_json::to_vec(&json!({
        "repo": {"owner": "attacker", "name": "evil", "full_name": "attacker/evil"},
        "pipeline": {"branch": "main", "event": "push"},
    }))
    .unwrap();
    let (status, json) = harness.send(harness.sign(&body), forged).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["error"], "signature verification failed");

    // Nothing was read for any of the rejected requests.
    assert_eq!(harness.mock.subtree_requests.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_signed_but_malformed_body_is_a_client_error() {
    let harness = Harness::start(Arc::new(MockState::happy())).await.unwrap();

    for (body, expected) in [
        (b"not json at all".to_vec(), "invalid request body"),
        (
            serde_json::to_vec(&json!({"pipeline": {"branch": "main", "event": "push"}})).unwrap(),
            "repo and pipeline are required",
        ),
        (
            serde_json::to_vec(&json!({
                "repo": null, "pipeline": {"branch": "main", "event": "push"}
            }))
            .unwrap(),
            "repo and pipeline are required",
        ),
    ] {
        let (status, json) = harness.send(harness.sign(&body), body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body {body:?}");
        assert_eq!(json["error"], expected);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_is_unauthenticated() {
    let harness = Harness::start(Arc::new(MockState::happy())).await.unwrap();
    let response = reqwest::get(format!("http://{}/health", harness.address))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.json::<serde_json::Value>().await.unwrap(),
        json!({"status": "ok"})
    );
}

/// A protocol mismatch must fail the container, not every pipeline: Woodpecker
/// swallows extension errors, so a broker that starts but cannot read is far
/// worse than one that refuses to start.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_protocol_mismatch_fails_startup() {
    let mut state = MockState::happy();
    state.protocol_version = "v2".to_owned();
    state.supported_protocol_versions = vec!["v2".to_owned()];
    match Harness::start(Arc::new(state)).await {
        Ok(_) => panic!("the broker started against an incompatible service"),
        Err(error) => assert_eq!(error, ConnectError::IncompatibleProtocol),
    }
}

/// The broker is deployed independently of the server, so a server that has
/// gained a newer protocol version must not stop it starting — and the reads
/// it goes on to serve must travel on the version it negotiated, not on the
/// newest one the server happened to mention. The mock serves only the
/// `sovereign.config.v3` routes, so secrets coming back at all is that
/// assertion made on the wire: a broker dialling `v4` would get `UNIMPLEMENTED`
/// on every pipeline instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_newer_than_this_build_starts_and_still_reads_on_its_own_version() {
    let mut state = MockState::happy();
    state.supported_protocol_versions = vec!["v3".to_owned(), "v4".to_owned()];
    let harness = Harness::start(Arc::new(state))
        .await
        .expect("a server still serving v3 must start the broker");

    let (status, body) = harness
        .post_secrets("vcheesbrough", "sovereign-config")
        .await;

    assert_eq!(status, StatusCode::OK);
    assert!(!Harness::names_and_values(&body).is_empty());
}

/// Values must reach the HTTP response and nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revealed_values_do_not_leak_through_diagnostics() {
    let harness = Harness::start(Arc::new(MockState::happy())).await.unwrap();
    let (status, body) = harness
        .post_secrets("vcheesbrough", "sovereign-config")
        .await;
    assert_eq!(status, StatusCode::OK);

    // The value is present where it must be...
    assert!(serde_json::to_string(&body).unwrap().contains(GITHUB_TOKEN));

    // ...and the request DTO, which is the thing that gets logged, carries
    // neither a configuration value nor the forge credential from `netrc`.
    let request: crate::model::SecretsRequest = serde_json::from_slice(
        &serde_json::to_vec(&json!({
            "repo": {"owner": "o", "name": "r", "full_name": "o/r"},
            "pipeline": {"branch": "main", "event": "push"},
            "netrc": {"machine": "forge", "login": "u", "password": "netrc-sentinel"},
        }))
        .unwrap(),
    )
    .unwrap();
    let rendered = format!("{request:?}");
    assert!(!rendered.contains("netrc-sentinel"));
    assert!(!rendered.contains(GITHUB_TOKEN));
}
