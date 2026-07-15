use std::{
    collections::HashMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{
    Form, Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::json;
use sovereign_config_proto::sovereign::config::v1::{
    GetIdentityRequest, GetIdentityResponse, GetVersionRequest, GetVersionResponse,
    system_server::{System, SystemServer},
};
use tempfile::TempDir;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Status, transport::Server};

const DEVICE_SECRET: &str = "device-secret-sentinel";
const ACCESS_SECRET: &str = "access-secret-sentinel";
const REFRESH_SECRET: &str = "refresh-secret-sentinel";
const ROTATED_REFRESH_SECRET: &str = "rotated-refresh-secret-sentinel";

#[derive(Clone, Copy)]
enum DeviceResult {
    Success,
    PendingThenSuccess,
    SlowDownThenSuccess,
    Denied,
    Expired,
    Rejected,
    Unavailable,
}

struct OidcState {
    issuer: String,
    device_result: DeviceResult,
    poll_count: AtomicUsize,
    refresh_count: AtomicUsize,
}

struct TestServices {
    issuer: String,
    endpoint: String,
    oidc_state: Arc<OidcState>,
    oidc_task: tokio::task::JoinHandle<()>,
    grpc_task: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
}

impl Drop for TestServices {
    fn drop(&mut self) {
        self.oidc_task.abort();
        self.grpc_task.abort();
    }
}

#[derive(Default)]
struct MockSystem;

#[tonic::async_trait]
impl System for MockSystem {
    async fn get_version(
        &self,
        request: Request<GetVersionRequest>,
    ) -> Result<tonic::Response<GetVersionResponse>, Status> {
        if request.into_inner().protocol_version != "v1" {
            return Err(Status::failed_precondition("protocol mismatch"));
        }
        Ok(tonic::Response::new(GetVersionResponse {
            application_version: "1.3.0-test".to_owned(),
            protocol_version: "v1".to_owned(),
        }))
    }

    async fn get_identity(
        &self,
        request: Request<GetIdentityRequest>,
    ) -> Result<tonic::Response<GetIdentityResponse>, Status> {
        let authorization = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok());
        if authorization != Some("Bearer access-secret-sentinel") {
            return Err(Status::unauthenticated("authentication required"));
        }
        Ok(tonic::Response::new(GetIdentityResponse {
            authenticated: true,
        }))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn login_status_logout_flow_is_authenticated_private_and_secret_safe() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();

    let login = run_cli(home.path(), &services, &["login"]).await;
    assert_success(&login);
    let login_output = combined(&login);
    assert!(login_output.contains("Code: TEST-CODE"));
    assert!(login_output.contains("Logged in"));
    assert_secrets_absent(&login_output);

    let [credential] = credential_files(home.path()).try_into().unwrap();
    assert_eq!(fs::read_to_string(&credential).unwrap(), REFRESH_SECRET);
    assert_eq!(
        fs::metadata(&credential).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let status = run_cli(home.path(), &services, &["status"]).await;
    assert_success(&status);
    let status_output = combined(&status);
    assert!(status_output.contains("Service 1.3.0-test (protocol v1)"));
    assert!(status_output.contains("Authentication: logged in"));
    assert_secrets_absent(&status_output);
    assert_eq!(
        fs::read_to_string(&credential).unwrap(),
        ROTATED_REFRESH_SECRET
    );

    let logout = run_cli(home.path(), &services, &["logout"]).await;
    assert_success(&logout);
    assert_eq!(String::from_utf8_lossy(&logout.stdout).trim(), "Logged out");
    assert!(!credential.exists());

    let logged_out = run_cli(home.path(), &services, &["status"]).await;
    assert_success(&logged_out);
    let logged_out_output = combined(&logged_out);
    assert!(logged_out_output.contains("Authentication: logged out"));
    assert_secrets_absent(&logged_out_output);
}

#[tokio::test(flavor = "multi_thread")]
async fn credentials_are_isolated_by_issuer_and_client() {
    let development = start_services(DeviceResult::Success).await;
    let production = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();

    assert_success(&run_cli(home.path(), &development, &["login"]).await);
    assert_eq!(credential_files(home.path()).len(), 1);

    let production_status = run_cli(home.path(), &production, &["status"]).await;
    assert_success(&production_status);
    assert!(combined(&production_status).contains("Authentication: logged out"));
    assert_eq!(
        production.oidc_state.refresh_count.load(Ordering::SeqCst),
        0
    );
    assert_eq!(credential_files(home.path()).len(), 1);

    assert_success(&run_cli(home.path(), &production, &["login"]).await);
    assert_eq!(credential_files(home.path()).len(), 2);

    assert_success(&run_cli(home.path(), &production, &["logout"]).await);
    assert_eq!(credential_files(home.path()).len(), 1);

    let development_status = run_cli(home.path(), &development, &["status"]).await;
    assert_success(&development_status);
    assert!(combined(&development_status).contains("Authentication: logged in"));
    assert_eq!(
        development.oidc_state.refresh_count.load(Ordering::SeqCst),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn denied_device_login_fails_without_exposing_credentials() {
    let services = start_services(DeviceResult::Denied).await;
    let home = TempDir::new().unwrap();

    let output = run_cli(home.path(), &services, &["login"]).await;
    assert!(!output.status.success());
    let output = combined(&output);
    assert!(output.contains("device login denied"));
    assert_secrets_absent(&output);
    assert!(credential_files(home.path()).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_device_login_polls_until_authorized() {
    assert_eventual_login(DeviceResult::PendingThenSuccess).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn slow_down_device_login_honors_the_provider_response() {
    assert_eventual_login(DeviceResult::SlowDownThenSuccess).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn expired_device_login_returns_a_bounded_error() {
    assert_login_failure(DeviceResult::Expired, "device login expired").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn rejected_device_authorization_returns_a_bounded_error() {
    assert_login_failure(
        DeviceResult::Rejected,
        "authentication service is unavailable",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unavailable_identity_provider_returns_a_bounded_error() {
    assert_login_failure(
        DeviceResult::Unavailable,
        "authentication service is unavailable",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unavailable_service_returns_a_bounded_error_without_retrying() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    let unavailable = TestServices {
        issuer: services.issuer.clone(),
        endpoint: "http://127.0.0.1:1".to_owned(),
        oidc_state: services.oidc_state.clone(),
        oidc_task: tokio::spawn(async {}),
        grpc_task: tokio::spawn(async { Ok(()) }),
    };

    let output = run_cli(home.path(), &unavailable, &["status"]).await;
    assert!(!output.status.success());
    let output = combined(&output);
    assert!(output.contains("service is unavailable"));
    assert_secrets_absent(&output);
}

#[test]
fn version_does_not_require_connection_configuration() {
    let output = Command::new(env!("CARGO_BIN_EXE_sovereign-config"))
        .arg("--version")
        .env_clear()
        .output()
        .unwrap();
    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "sovereign-config 1.3.0"
    );
}

async fn start_services(device_result: DeviceResult) -> TestServices {
    let oidc_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let oidc_address = oidc_listener.local_addr().unwrap();
    let issuer = format!("http://{oidc_address}/");
    let oidc_state = Arc::new(OidcState {
        issuer: issuer.clone(),
        device_result,
        poll_count: AtomicUsize::new(0),
        refresh_count: AtomicUsize::new(0),
    });
    let oidc = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/device", post(device_authorization))
        .route("/token", post(token))
        .with_state(oidc_state.clone());
    let oidc_task = tokio::spawn(async move {
        axum::serve(oidc_listener, oidc).await.unwrap();
    });

    let grpc_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let grpc_address = grpc_listener.local_addr().unwrap();
    let grpc_task = tokio::spawn(
        Server::builder()
            .add_service(SystemServer::new(MockSystem))
            .serve_with_incoming(TcpListenerStream::new(grpc_listener)),
    );

    TestServices {
        issuer,
        endpoint: format!("http://{grpc_address}"),
        oidc_state,
        oidc_task,
        grpc_task,
    }
}

async fn discovery(State(state): State<Arc<OidcState>>) -> Response {
    if matches!(state.device_result, DeviceResult::Unavailable) {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    Json(json!({
        "device_authorization_endpoint": format!("{}device", state.issuer),
        "token_endpoint": format!("{}token", state.issuer),
    }))
    .into_response()
}

async fn device_authorization(
    State(state): State<Arc<OidcState>>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if form.get("client_id").map(String::as_str) != Some("sovereign-config")
        || form.get("scope").map(String::as_str) != Some("openid sovereign-config offline_access")
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_request"})),
        )
            .into_response();
    }
    if matches!(state.device_result, DeviceResult::Rejected) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_request"})),
        )
            .into_response();
    }
    Json(json!({
        "device_code": DEVICE_SECRET,
        "user_code": "TEST-CODE",
        "verification_uri": "https://auth.example.test/device",
        "verification_uri_complete": "https://auth.example.test/device?code=TEST-CODE",
        "expires_in": 30,
        "interval": 1,
    }))
    .into_response()
}

async fn token(
    State(state): State<Arc<OidcState>>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    match form.get("grant_type").map(String::as_str) {
        Some("urn:ietf:params:oauth:grant-type:device_code") => {
            if form.get("device_code").map(String::as_str) != Some(DEVICE_SECRET) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "invalid_grant"})),
                )
                    .into_response();
            }
            match state.device_result {
                DeviceResult::Success => Json(json!({
                    "access_token": ACCESS_SECRET,
                    "refresh_token": REFRESH_SECRET,
                }))
                .into_response(),
                DeviceResult::PendingThenSuccess
                    if state.poll_count.fetch_add(1, Ordering::SeqCst) == 0 =>
                {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": "authorization_pending"})),
                    )
                        .into_response()
                }
                DeviceResult::SlowDownThenSuccess
                    if state.poll_count.fetch_add(1, Ordering::SeqCst) == 0 =>
                {
                    (StatusCode::BAD_REQUEST, Json(json!({"error": "slow_down"}))).into_response()
                }
                DeviceResult::PendingThenSuccess | DeviceResult::SlowDownThenSuccess => {
                    Json(json!({
                        "access_token": ACCESS_SECRET,
                        "refresh_token": REFRESH_SECRET,
                    }))
                    .into_response()
                }
                DeviceResult::Denied => (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "access_denied"})),
                )
                    .into_response(),
                DeviceResult::Expired => (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "expired_token"})),
                )
                    .into_response(),
                DeviceResult::Rejected | DeviceResult::Unavailable => unreachable!(),
            }
        }
        Some("refresh_token") => {
            state.refresh_count.fetch_add(1, Ordering::SeqCst);
            if form.get("refresh_token").map(String::as_str) != Some(REFRESH_SECRET) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "invalid_grant"})),
                )
                    .into_response();
            }
            Json(json!({
                "access_token": ACCESS_SECRET,
                "refresh_token": ROTATED_REFRESH_SECRET,
            }))
            .into_response()
        }
        _ => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "unsupported_grant_type"})),
        )
            .into_response(),
    }
}

async fn assert_eventual_login(result: DeviceResult) {
    let services = start_services(result).await;
    let home = TempDir::new().unwrap();
    let output = run_cli(home.path(), &services, &["login"]).await;
    assert_success(&output);
    let output = combined(&output);
    assert!(output.contains("Logged in"));
    assert_secrets_absent(&output);
    let [credential] = credential_files(home.path()).try_into().unwrap();
    assert_eq!(fs::read_to_string(credential).unwrap(), REFRESH_SECRET);
}

async fn assert_login_failure(result: DeviceResult, expected: &str) {
    let services = start_services(result).await;
    let home = TempDir::new().unwrap();
    let output = run_cli(home.path(), &services, &["login"]).await;
    assert!(!output.status.success());
    let output = combined(&output);
    assert!(
        output.contains(expected),
        "unexpected command output: {output}"
    );
    assert_secrets_absent(&output);
    assert!(credential_files(home.path()).is_empty());
}

fn credential_files(home: &Path) -> Vec<PathBuf> {
    let directory = home.join("sovereign-config/credentials");
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut paths = entries
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

async fn run_cli(home: &Path, services: &TestServices, arguments: &[&str]) -> Output {
    let binary = env!("CARGO_BIN_EXE_sovereign-config");
    let home = home.to_owned();
    let endpoint = services.endpoint.clone();
    let issuer = services.issuer.clone();
    let arguments = arguments
        .iter()
        .map(|argument| (*argument).to_owned())
        .collect::<Vec<_>>();
    tokio::task::spawn_blocking(move || {
        Command::new(binary)
            .args(arguments)
            .env_clear()
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", &home)
            .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent")
            .env("SOVEREIGN_CONFIG_ENDPOINT", endpoint)
            .env("SOVEREIGN_CONFIG_OIDC_ISSUER", issuer)
            .output()
            .unwrap()
    })
    .await
    .unwrap()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed: {}",
        combined(output)
    );
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_secrets_absent(output: &str) {
    for secret in [
        DEVICE_SECRET,
        ACCESS_SECRET,
        REFRESH_SECRET,
        ROTATED_REFRESH_SECRET,
    ] {
        assert!(
            !output.contains(secret),
            "secret appeared in command output"
        );
    }
}
