use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{StatusCode, header},
    response::Response,
};
use reqwest::Url;
use serde_json::json;
use sovereign_config_core::Secret;
use tokio::{net::TcpListener, task::JoinHandle, time::sleep};

use super::{AdminError, AuthentikAdminClient, MAX_ADMIN_RESPONSE_BYTES};

const TEST_API_TOKEN: &str = "authentik-admin-token-sentinel";
const TEST_USERNAME: &str = "sc-managed-0123456789abcdefghijklmnopqrst";

/// Every request the mock received as `(path_with_query, authorization)`.
type RecordedRequests = Arc<Mutex<Vec<(String, Option<String>)>>>;

#[derive(Clone)]
struct MockState {
    status: StatusCode,
    body: String,
    delay: Duration,
    location: Option<&'static str>,
    hits: RecordedRequests,
}

struct MockServer {
    origin: Url,
    hits: RecordedRequests,
    task: JoinHandle<()>,
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn handle(State(state): State<MockState>, request: Request) -> Response {
    let path = match request.uri().query() {
        Some(query) => format!("{}?{query}", request.uri().path()),
        None => request.uri().path().to_owned(),
    };
    let authorization = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    state.hits.lock().unwrap().push((path, authorization));
    sleep(state.delay).await;
    let mut response = Response::builder()
        .status(state.status)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(location) = state.location {
        response = response.header(header::LOCATION, location);
    }
    response.body(Body::from(state.body)).unwrap()
}

async fn server(
    status: StatusCode,
    body: impl Into<String>,
    delay: Duration,
    location: Option<&'static str>,
) -> MockServer {
    let hits = Arc::new(Mutex::new(Vec::new()));
    let state = MockState {
        status,
        body: body.into(),
        delay,
        location,
        hits: Arc::clone(&hits),
    };
    let app = Router::new().fallback(handle).with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    MockServer {
        origin: format!("http://{address}/").parse().unwrap(),
        hits,
        task,
    }
}

async fn ok_server(body: impl Into<String>) -> MockServer {
    server(StatusCode::OK, body, Duration::ZERO, None).await
}

fn client(server: &MockServer) -> AuthentikAdminClient {
    AuthentikAdminClient::new(
        server.origin.clone(),
        Secret::new(TEST_API_TOKEN),
        Duration::from_millis(250),
    )
    .unwrap()
}

#[tokio::test]
async fn create_service_account_decodes_the_created_account() {
    let server = ok_server(
        json!({
            "username": TEST_USERNAME,
            "user_uid": "uid-sentinel-1",
            "user_pk": 42,
            "token": "app-password-sentinel",
        })
        .to_string(),
    )
    .await;

    let account = client(&server)
        .create_service_account(TEST_USERNAME)
        .await
        .unwrap();

    assert_eq!(account.user_id, 42);
    assert_eq!(account.user_uid, "uid-sentinel-1");
    assert_eq!(account.app_password.expose(), "app-password-sentinel");
    let hits = server.hits.lock().unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].0, "/api/v3/core/users/service_account/");
    assert_eq!(
        hits[0].1.as_deref(),
        Some(format!("Bearer {TEST_API_TOKEN}").as_str())
    );
}

#[tokio::test]
async fn create_service_account_rejects_malformed_payloads() {
    let mismatched_username = json!({
        "username": "someone-else",
        "user_uid": "uid-sentinel-1",
        "user_pk": 42,
        "token": "app-password-sentinel",
    })
    .to_string();
    let colon_in_token = json!({
        "username": TEST_USERNAME,
        "user_uid": "uid-sentinel-1",
        "user_pk": 42,
        "token": "user:app-password",
    })
    .to_string();
    let malformed_json = "not-json-at-all".to_owned();
    let oversized_body = "a".repeat(MAX_ADMIN_RESPONSE_BYTES + 1);

    for body in [
        mismatched_username,
        colon_in_token,
        malformed_json,
        oversized_body,
    ] {
        let preview = body.chars().take(32).collect::<String>();
        let server = ok_server(body).await;
        let error = client(&server)
            .create_service_account(TEST_USERNAME)
            .await
            .unwrap_err();
        assert_eq!(error, AdminError::Invalid, "body {preview:?}");
    }
}

#[tokio::test]
async fn http_statuses_classify_to_bounded_errors() {
    for (status, expected) in [
        (StatusCode::FORBIDDEN, AdminError::Rejected),
        (StatusCode::NOT_FOUND, AdminError::NotFound),
        (StatusCode::TOO_MANY_REQUESTS, AdminError::Rejected),
        (StatusCode::INTERNAL_SERVER_ERROR, AdminError::Ambiguous),
    ] {
        let server = server(
            status,
            "authentik-error-response-sentinel",
            Duration::ZERO,
            None,
        )
        .await;
        let error = client(&server)
            .create_service_account(TEST_USERNAME)
            .await
            .unwrap_err();
        assert_eq!(error, expected, "status {status}");
        assert!(!format!("{error:?}").contains("authentik-error-response-sentinel"));
    }
}

#[tokio::test]
async fn timeouts_classify_as_ambiguous() {
    let server = server(StatusCode::OK, "{}", Duration::from_millis(600), None).await;
    let error = client(&server)
        .create_service_account(TEST_USERNAME)
        .await
        .unwrap_err();
    assert_eq!(error, AdminError::Ambiguous);
}

#[tokio::test]
async fn redirects_are_invalid_and_never_followed() {
    let server = server(
        StatusCode::MOVED_PERMANENTLY,
        String::new(),
        Duration::ZERO,
        Some("/redirect-target/"),
    )
    .await;
    let error = client(&server).delete_user(7).await.unwrap_err();
    assert_eq!(error, AdminError::Invalid);
    let hits = server.hits.lock().unwrap();
    assert_eq!(hits.len(), 1);
    assert!(
        hits.iter()
            .all(|(path, _)| !path.starts_with("/redirect-target")),
        "the redirect target must never be requested"
    );
}

#[test]
fn new_accepts_only_https_or_numeric_loopback_http_origins() {
    for origin in [
        "https://authentik.example/",
        "http://127.0.0.1:9000/",
        "http://[::1]:9000/",
    ] {
        let url: Url = origin.parse().unwrap();
        assert!(
            AuthentikAdminClient::new(url, Secret::new("token"), Duration::from_secs(1)).is_ok(),
            "rejected {origin}"
        );
    }
    for origin in [
        "http://example.com/",
        "http://localhost:9000/",
        "https://authentik.example/api/",
        "https://authentik.example/?tenant=default",
        "https://authentik.example/#fragment",
        "https://admin@authentik.example/",
        "https://admin:secret@authentik.example/",
    ] {
        let url: Url = origin.parse().unwrap();
        assert!(
            AuthentikAdminClient::new(url, Secret::new("token"), Duration::from_secs(1)).is_err(),
            "accepted {origin}"
        );
    }
}

#[tokio::test]
async fn app_password_discovery_validates_identifiers() {
    let valid = ok_server(json!({"results": [{"identifier": "token-id_1.x"}]}).to_string()).await;
    let identifiers = client(&valid)
        .find_app_password_identifiers(TEST_USERNAME)
        .await
        .unwrap();
    assert_eq!(identifiers, ["token-id_1.x"]);
    {
        let hits = valid.hits.lock().unwrap();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].0.starts_with("/api/v3/core/tokens/?"));
        assert!(
            hits[0]
                .0
                .contains(&format!("user__username={TEST_USERNAME}"))
        );
        assert!(hits[0].0.contains("intent=app_password"));
    }

    let invalid =
        ok_server(json!({"results": [{"identifier": "bad identifier!"}]}).to_string()).await;
    let error = client(&invalid)
        .find_app_password_identifiers(TEST_USERNAME)
        .await
        .unwrap_err();
    assert_eq!(error, AdminError::Invalid);
}

#[tokio::test]
async fn group_lookup_finds_the_exact_name_and_rejects_ambiguity() {
    const GROUP_ID: &str = "b3f5c2a0-0000-4000-8000-0123456789ab";

    let found = ok_server(
        json!({"results": [{"pk": GROUP_ID, "name": "sovereign-config-connections"}]}).to_string(),
    )
    .await;
    let group_id = client(&found)
        .find_group_by_name("sovereign-config-connections")
        .await
        .unwrap();
    assert_eq!(group_id.as_deref(), Some(GROUP_ID));
    {
        let hits = found.hits.lock().unwrap();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].0.starts_with("/api/v3/core/groups/?"));
        assert!(hits[0].0.contains("name=sovereign-config-connections"));
    }

    let missing = ok_server(json!({"results": []}).to_string()).await;
    assert_eq!(
        client(&missing)
            .find_group_by_name("sovereign-config-connections")
            .await
            .unwrap(),
        None
    );

    let ambiguous = ok_server(
        json!({"results": [
            {"pk": GROUP_ID, "name": "sovereign-config-connections"},
            {"pk": "c3f5c2a0-0000-4000-8000-0123456789ab", "name": "sovereign-config-connections"}
        ]})
        .to_string(),
    )
    .await;
    let error = client(&ambiguous)
        .find_group_by_name("sovereign-config-connections")
        .await
        .unwrap_err();
    assert_eq!(error, AdminError::Invalid);
}

#[tokio::test]
async fn group_assignment_patches_the_exact_user_with_the_exact_group() {
    const GROUP_ID: &str = "b3f5c2a0-0000-4000-8000-0123456789ab";
    let server = ok_server("{}").await;

    client(&server)
        .add_user_to_group(42, GROUP_ID)
        .await
        .unwrap();

    let hits = server.hits.lock().unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].0, "/api/v3/core/users/42/");
}
