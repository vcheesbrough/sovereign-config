//! Server-only Authentik administration adapter for managed connections.
//!
//! Every request uses the dedicated connection-manager API token over the
//! exact configured origin with redirects disabled, a short total timeout,
//! bounded response bodies, strict JSON decoding, and no automatic retries.
//! All Authentik identifiers, request bodies, and responses are treated as
//! sensitive: errors carry only a bounded classification and never any
//! Authentik response text.

use std::{net::IpAddr, time::Duration};

use reqwest::{Client, StatusCode, Url, redirect::Policy};
use serde::Deserialize;
use serde_json::json;
use sovereign_config_core::Secret;

const MAX_ADMIN_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_EXTERNAL_IDENTIFIER_CHARS: usize = 128;

/// Bounded classification of an Authentik administration failure.
///
/// The classification deliberately discards all Authentik response content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdminError {
    /// The exact target object does not exist.
    NotFound,
    /// Authentik definitively rejected the request without applying it.
    Rejected,
    /// The request could not be delivered, so it was definitively not applied.
    Unavailable,
    /// The outcome is unknown: Authentik may have applied the request.
    Ambiguous,
    /// The response violated the adapter's strict decoding or redirect policy.
    Invalid,
}

/// The service account created for one managed connection.
pub(crate) struct CreatedServiceAccount {
    pub(crate) user_id: i64,
    pub(crate) user_uid: String,
    pub(crate) app_password: Secret,
}

/// Redacts every Authentik identifier and the app password by construction,
/// so a failed assertion or diagnostic can never print them.
impl core::fmt::Debug for CreatedServiceAccount {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CreatedServiceAccount")
            .finish_non_exhaustive()
    }
}

/// An existing Authentik user located by exact generated username.
pub(crate) struct FoundUser {
    pub(crate) user_id: i64,
}

pub(crate) struct AuthentikAdminClient {
    http: Client,
    api_origin: Url,
    api_token: Secret,
}

impl AuthentikAdminClient {
    /// Builds the administration client for the exact configured origin.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when the origin is not HTTPS (numeric loopback
    /// HTTP remains test-only) or the HTTP client cannot be constructed.
    pub(crate) fn new(
        api_origin: Url,
        api_token: Secret,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        let loopback_http = api_origin.scheme() == "http"
            && api_origin
                .host_str()
                .and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok())
                .is_some_and(|address| address.is_loopback());
        if !(api_origin.scheme() == "https" || loopback_http)
            || api_origin.host_str().is_none()
            || !api_origin.username().is_empty()
            || api_origin.password().is_some()
            || api_origin.path() != "/"
            || api_origin.query().is_some()
            || api_origin.fragment().is_some()
        {
            anyhow::bail!("managed connection API origin is not permitted");
        }
        let http = Client::builder()
            .redirect(Policy::none())
            .timeout(timeout)
            .build()
            .map_err(|_| anyhow::anyhow!("unable to build managed connection API client"))?;
        Ok(Self {
            http,
            api_origin,
            api_token,
        })
    }

    /// Creates one non-expiring service account and returns its app password.
    pub(crate) async fn create_service_account(
        &self,
        username: &str,
    ) -> Result<CreatedServiceAccount, AdminError> {
        #[derive(Deserialize)]
        struct ServiceAccountResponse {
            username: String,
            user_uid: String,
            user_pk: i64,
            token: String,
        }

        let response = self
            .http
            .post(self.endpoint("/api/v3/core/users/service_account/")?)
            .bearer_auth(self.api_token.expose())
            .json(&json!({
                "name": username,
                "create_group": false,
                "expiring": false,
            }))
            .send()
            .await
            .map_err(|error| classify_transport(&error))?;
        let body = expect_success(response).await?;
        let decoded: ServiceAccountResponse =
            serde_json::from_slice(&body).map_err(|_| AdminError::Invalid)?;
        if decoded.username != username
            || decoded.token.is_empty()
            || decoded.token.bytes().any(|byte| byte.is_ascii_control())
            || decoded.token.contains(':')
            || decoded.user_uid.is_empty()
            || decoded.user_uid.len() > MAX_EXTERNAL_IDENTIFIER_CHARS
        {
            return Err(AdminError::Invalid);
        }
        Ok(CreatedServiceAccount {
            user_id: decoded.user_pk,
            user_uid: decoded.user_uid,
            app_password: Secret::new(decoded.token),
        })
    }

    /// Replaces the managed service account's attributes with the exact
    /// managed marker, grants, and preserved service-account markers.
    pub(crate) async fn set_managed_attributes(
        &self,
        user_id: i64,
        connection_id: &str,
        grants_attribute: &str,
        root: &str,
    ) -> Result<(), AdminError> {
        let mut attributes = serde_json::Map::new();
        attributes.insert(
            "goauthentik.io/user/service-account".to_owned(),
            json!(true),
        );
        attributes.insert("goauthentik.io/user/token-expires".to_owned(), json!(false));
        attributes.insert("sovereign_config_managed".to_owned(), json!(connection_id));
        attributes.insert(
            grants_attribute.to_owned(),
            json!([{ "prefix": root, "permissions": ["read"] }]),
        );
        let response = self
            .http
            .patch(self.endpoint(&format!("/api/v3/core/users/{user_id}/"))?)
            .bearer_auth(self.api_token.expose())
            .json(&json!({ "attributes": attributes }))
            .send()
            .await
            .map_err(|error| classify_transport(&error))?;
        expect_success(response).await.map(|_| ())
    }

    /// Locates a group by exact name, purely to group managed service
    /// accounts together for browsing in Authentik. Never authorizes
    /// anything: authorization is granted directly on the service account.
    pub(crate) async fn find_group_by_name(
        &self,
        name: &str,
    ) -> Result<Option<String>, AdminError> {
        #[derive(Deserialize)]
        struct GroupRecord {
            pk: String,
            name: String,
        }
        #[derive(Deserialize)]
        struct GroupListResponse {
            results: Vec<GroupRecord>,
        }

        let mut endpoint = self.endpoint("/api/v3/core/groups/")?;
        endpoint.query_pairs_mut().append_pair("name", name);
        let response = self
            .http
            .get(endpoint)
            .bearer_auth(self.api_token.expose())
            .send()
            .await
            .map_err(|error| classify_transport(&error))?;
        let body = expect_success(response).await?;
        let decoded: GroupListResponse =
            serde_json::from_slice(&body).map_err(|_| AdminError::Invalid)?;
        let mut matching = decoded.results.into_iter().filter(|record| {
            record.name == name
                && !record.pk.is_empty()
                && record.pk.len() <= MAX_EXTERNAL_IDENTIFIER_CHARS
        });
        let found = matching.next().map(|record| record.pk);
        if matching.next().is_some() {
            return Err(AdminError::Invalid);
        }
        Ok(found)
    }

    /// Adds the exact managed service account to one group, replacing any
    /// existing membership. Safe because the account is freshly created with
    /// no prior group membership. Best-effort: failure here must never block
    /// or roll back connection creation.
    pub(crate) async fn add_user_to_group(
        &self,
        user_id: i64,
        group_id: &str,
    ) -> Result<(), AdminError> {
        let response = self
            .http
            .patch(self.endpoint(&format!("/api/v3/core/users/{user_id}/"))?)
            .bearer_auth(self.api_token.expose())
            .json(&json!({ "groups": [group_id] }))
            .send()
            .await
            .map_err(|error| classify_transport(&error))?;
        expect_success(response).await.map(|_| ())
    }

    /// Locates a user by exact generated username for reconciliation only.
    ///
    /// Only usable while the manager can still see at least one managed
    /// account; Authentik refuses user reads outright otherwise. Absence must
    /// therefore be confirmed through the app password rather than the user.
    pub(crate) async fn find_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<FoundUser>, AdminError> {
        #[derive(Deserialize)]
        struct UserRecord {
            pk: i64,
            username: String,
        }
        #[derive(Deserialize)]
        struct UserListResponse {
            results: Vec<UserRecord>,
        }

        let mut endpoint = self.endpoint("/api/v3/core/users/")?;
        endpoint.query_pairs_mut().append_pair("username", username);
        let response = self
            .http
            .get(endpoint)
            .bearer_auth(self.api_token.expose())
            .send()
            .await
            .map_err(|error| classify_transport(&error))?;
        let body = expect_success(response).await?;
        let decoded: UserListResponse =
            serde_json::from_slice(&body).map_err(|_| AdminError::Invalid)?;
        let mut matching = decoded
            .results
            .into_iter()
            .filter(|record| record.username == username);
        let found = matching
            .next()
            .map(|record| FoundUser { user_id: record.pk });
        if matching.next().is_some() {
            return Err(AdminError::Invalid);
        }
        Ok(found)
    }

    /// Discovers the single app-password token identifier for a username
    /// without viewing its key.
    pub(crate) async fn find_app_password_identifiers(
        &self,
        username: &str,
    ) -> Result<Vec<String>, AdminError> {
        #[derive(Deserialize)]
        struct TokenRecord {
            identifier: String,
        }
        #[derive(Deserialize)]
        struct TokenListResponse {
            results: Vec<TokenRecord>,
        }

        let mut endpoint = self.endpoint("/api/v3/core/tokens/")?;
        endpoint
            .query_pairs_mut()
            .append_pair("user__username", username)
            .append_pair("intent", "app_password");
        let response = self
            .http
            .get(endpoint)
            .bearer_auth(self.api_token.expose())
            .send()
            .await
            .map_err(|error| classify_transport(&error))?;
        let body = expect_success(response).await?;
        let decoded: TokenListResponse =
            serde_json::from_slice(&body).map_err(|_| AdminError::Invalid)?;
        let identifiers = decoded
            .results
            .into_iter()
            .map(|record| record.identifier)
            .collect::<Vec<_>>();
        if identifiers.iter().any(|identifier| {
            identifier.is_empty()
                || identifier.len() > MAX_EXTERNAL_IDENTIFIER_CHARS
                || !identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        }) {
            return Err(AdminError::Invalid);
        }
        Ok(identifiers)
    }

    /// Replaces the key of the exact app-password token.
    pub(crate) async fn set_credential_secret(
        &self,
        identifier: &str,
        replacement: &Secret,
    ) -> Result<(), AdminError> {
        let response = self
            .http
            .post(self.endpoint(&format!("/api/v3/core/tokens/{identifier}/set_key/"))?)
            .bearer_auth(self.api_token.expose())
            .json(&json!({ "key": replacement.expose() }))
            .send()
            .await
            .map_err(|error| classify_transport(&error))?;
        expect_success(response).await.map(|_| ())
    }

    /// Deletes the exact managed service account.
    pub(crate) async fn delete_user(&self, user_id: i64) -> Result<(), AdminError> {
        let response = self
            .http
            .delete(self.endpoint(&format!("/api/v3/core/users/{user_id}/"))?)
            .bearer_auth(self.api_token.expose())
            .send()
            .await
            .map_err(|error| classify_transport(&error))?;
        expect_success(response).await.map(|_| ())
    }

    fn endpoint(&self, path: &str) -> Result<Url, AdminError> {
        self.api_origin.join(path).map_err(|_| AdminError::Invalid)
    }
}

fn classify_transport(error: &reqwest::Error) -> AdminError {
    if error.is_timeout() {
        AdminError::Ambiguous
    } else if error.is_connect() || error.is_builder() || error.is_request() {
        AdminError::Unavailable
    } else if error.is_redirect() {
        AdminError::Invalid
    } else {
        AdminError::Ambiguous
    }
}

fn classify_status(status: StatusCode) -> AdminError {
    if status == StatusCode::NOT_FOUND {
        AdminError::NotFound
    } else if status.is_client_error() {
        AdminError::Rejected
    } else if status.is_redirection() {
        AdminError::Invalid
    } else {
        AdminError::Ambiguous
    }
}

/// Reads a bounded successful response body, discarding any failure text.
async fn expect_success(response: reqwest::Response) -> Result<Vec<u8>, AdminError> {
    let status = response.status();
    if !status.is_success() {
        return Err(classify_status(status));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_ADMIN_RESPONSE_BYTES as u64)
    {
        return Err(AdminError::Invalid);
    }
    let mut body = Vec::new();
    let mut stream = response;
    while let Some(chunk) = stream.chunk().await.map_err(|error| {
        if error.is_timeout() {
            AdminError::Ambiguous
        } else {
            AdminError::Invalid
        }
    })? {
        if body.len() + chunk.len() > MAX_ADMIN_RESPONSE_BYTES {
            return Err(AdminError::Invalid);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
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
                AuthentikAdminClient::new(url, Secret::new("token"), Duration::from_secs(1))
                    .is_ok(),
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
                AuthentikAdminClient::new(url, Secret::new("token"), Duration::from_secs(1))
                    .is_err(),
                "accepted {origin}"
            );
        }
    }

    #[tokio::test]
    async fn app_password_discovery_validates_identifiers() {
        let valid =
            ok_server(json!({"results": [{"identifier": "token-id_1.x"}]}).to_string()).await;
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
            json!({"results": [{"pk": GROUP_ID, "name": "sovereign-config-connections"}]})
                .to_string(),
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
}

/// End-to-end checks against a real Authentik instance.
///
/// These run only when `SOVEREIGN_CONFIG_LIVE_AUTHENTIK_URL` and
/// `SOVEREIGN_CONFIG_LIVE_AUTHENTIK_TOKEN` are set, which CI does after the
/// environment's blueprint has been applied. They exercise the connection
/// manager's real permission model — the layer a mock cannot reproduce, and
/// where a missing global `view_token` previously made every created app
/// password undiscoverable in production.
#[cfg(test)]
mod live_tests {
    use std::{env, time::Duration};

    use reqwest::Url;
    use sovereign_config_core::Secret;

    use super::{AdminError, AuthentikAdminClient, CreatedServiceAccount};

    const LIVE_TIMEOUT: Duration = Duration::from_secs(15);
    /// CI only ever runs these tests against the development environment,
    /// whose blueprint creates this exact browsing group.
    const DEV_MANAGED_GROUP: &str = "sovereign-config-dev-connections";

    fn live_client() -> Option<AuthentikAdminClient> {
        let origin = env::var("SOVEREIGN_CONFIG_LIVE_AUTHENTIK_URL").ok()?;
        let token = env::var("SOVEREIGN_CONFIG_LIVE_AUTHENTIK_TOKEN").ok()?;
        if origin.trim().is_empty() || token.trim().is_empty() {
            return None;
        }
        let origin: Url = origin.parse().expect("live Authentik URL must be valid");
        Some(
            AuthentikAdminClient::new(origin, Secret::new(token.trim()), LIVE_TIMEOUT)
                .expect("live Authentik client must build"),
        )
    }

    /// An elevated client used only to create and clean up disposable canary
    /// objects that the manager under test must be denied access to. Never
    /// used to exercise the manager's own restricted behavior.
    fn live_admin_client() -> Option<AuthentikAdminClient> {
        let origin = env::var("SOVEREIGN_CONFIG_LIVE_AUTHENTIK_URL").ok()?;
        let token = env::var("SOVEREIGN_CONFIG_LIVE_AUTHENTIK_ADMIN_TOKEN").ok()?;
        if origin.trim().is_empty() || token.trim().is_empty() {
            return None;
        }
        let origin: Url = origin.parse().expect("live Authentik URL must be valid");
        Some(
            AuthentikAdminClient::new(origin, Secret::new(token.trim()), LIVE_TIMEOUT)
                .expect("live Authentik admin client must build"),
        )
    }

    /// A disposable username that cannot collide with a managed connection.
    fn disposable_username(suffix: &str) -> String {
        let mut bytes = [0_u8; 8];
        getrandom::fill(&mut bytes).expect("CSPRNG must be available");
        let random = bytes.iter().fold(String::new(), |mut value, byte| {
            use std::fmt::Write as _;
            let _ = write!(value, "{byte:02x}");
            value
        });
        format!("sc-livetest-{suffix}-{random}")
    }

    async fn cleanup(client: &AuthentikAdminClient, account: &CreatedServiceAccount) {
        let _ = client.delete_user(account.user_id).await;
    }

    /// The full lifecycle the manager performs for one managed connection.
    /// This is the check that would have caught the production failure: the
    /// app password must be *discoverable* by the manager that created it.
    #[tokio::test]
    #[ignore = "requires SOVEREIGN_CONFIG_LIVE_AUTHENTIK_URL and _TOKEN"]
    async fn live_manager_completes_the_managed_connection_lifecycle() {
        let Some(client) = live_client() else {
            return;
        };
        let username = disposable_username("lifecycle");

        let account = client
            .create_service_account(&username)
            .await
            .expect("the manager must be able to create a service account");

        // Assertions are collected rather than panicking so the disposable
        // account is always removed from the real directory.
        let checks = async {
            let identifiers = client
                .find_app_password_identifiers(&username)
                .await
                .map_err(|error| format!("listing the app password failed: {error:?}"))?;
            if identifiers.len() != 1 {
                return Err(format!(
                    "expected exactly one discoverable app password, found {}",
                    identifiers.len()
                ));
            }
            client
                .set_managed_attributes(
                    account.user_id,
                    "livetestconnectionid0123456789ab",
                    "sovereign_config_live_test_grants",
                    "/apps/api",
                )
                .await
                .map_err(|error| format!("patching the created account failed: {error:?}"))?;
            client
                .set_credential_secret(&identifiers[0], &Secret::new("live-test-replacement-key"))
                .await
                .map_err(|error| format!("rotating the app password failed: {error:?}"))?;
            // Group membership is best-effort in production, but the manager
            // must actually be able to resolve and use it against real
            // Authentik, not only against the mock.
            let group_id = client
                .find_group_by_name(DEV_MANAGED_GROUP)
                .await
                .map_err(|error| format!("resolving the browsing group failed: {error:?}"))?
                .ok_or_else(|| {
                    format!("the {DEV_MANAGED_GROUP} browsing group must exist in this environment")
                })?;
            client
                .add_user_to_group(account.user_id, &group_id)
                .await
                .map_err(|error| {
                    format!("adding the account to the browsing group failed: {error:?}")
                })?;
            let found = client
                .find_user_by_username(&username)
                .await
                .map_err(|error| format!("reconciliation failed: {error:?}"))?;
            if found.is_none() {
                return Err("reconciliation did not locate the created account".to_owned());
            }
            Ok::<(), String>(())
        }
        .await;

        cleanup(&client, &account).await;
        checks.expect("the manager must complete the managed connection lifecycle");

        // Absence is confirmed through the app password, not the user.
        // Authentik refuses user reads and deletes for an account the manager
        // can no longer see, so those cannot distinguish "gone" from "denied";
        // the token view is global and cascades with the user, so an empty
        // result proves no usable credential survives.
        let remaining = client
            .find_app_password_identifiers(&username)
            .await
            .expect("confirming credential absence must succeed");
        assert!(
            remaining.is_empty(),
            "deleting the account must leave no usable credential"
        );
    }

    /// Credential discovery must stay scoped to one account even though the
    /// manager holds a global token view, so a second connection can never
    /// consume another connection's credential.
    #[tokio::test]
    #[ignore = "requires SOVEREIGN_CONFIG_LIVE_AUTHENTIK_URL and _TOKEN"]
    async fn live_credential_discovery_is_scoped_to_one_account() {
        let Some(client) = live_client() else {
            return;
        };
        let first_name = disposable_username("scope-a");
        let second_name = disposable_username("scope-b");

        let first = client
            .create_service_account(&first_name)
            .await
            .expect("first disposable account must be creatable");
        let second = client.create_service_account(&second_name).await;

        let checks = async {
            let identifiers = client
                .find_app_password_identifiers(&first_name)
                .await
                .map_err(|error| format!("first discovery failed: {error:?}"))?;
            let others = client
                .find_app_password_identifiers(&second_name)
                .await
                .map_err(|error| format!("second discovery failed: {error:?}"))?;
            if identifiers.len() != 1 || others.len() != 1 {
                return Err(format!(
                    "discovery must be scoped to one account, found {} and {}",
                    identifiers.len(),
                    others.len()
                ));
            }
            if identifiers[0] == others[0] {
                return Err("each account must own a distinct credential".to_owned());
            }
            Ok::<(), String>(())
        }
        .await;

        cleanup(&client, &first).await;
        if let Ok(second) = &second {
            cleanup(&client, second).await;
        }
        checks.expect("credential discovery must be scoped to a single account");
    }

    /// The manager must not be able to act on an object it did not create.
    ///
    /// Uses a disposable canary rather than a real object: verifying a denial
    /// by attempting a live, mutating delete against a precious, irreplaceable
    /// object (e.g. the bootstrap administrator) would make the very
    /// permission regression this test exists to catch also the mechanism
    /// that destroys that object. The canary is created and, regardless of
    /// outcome, cleaned up with a separate, more-privileged credential that
    /// the manager under test never has access to.
    #[tokio::test]
    #[ignore = "requires SOVEREIGN_CONFIG_LIVE_AUTHENTIK_URL, _TOKEN, and _ADMIN_TOKEN"]
    async fn live_manager_cannot_touch_unrelated_objects() {
        let (Some(client), Some(admin)) = (live_client(), live_admin_client()) else {
            return;
        };
        let canary_username = disposable_username("canary");
        let canary = admin
            .create_service_account(&canary_username)
            .await
            .expect("the admin credential must be able to create a canary account");

        let checks = async {
            let denied = client.delete_user(canary.user_id).await;
            if !matches!(denied, Err(AdminError::NotFound | AdminError::Rejected)) {
                return Err(format!(
                    "deleting an unrelated user must be denied, got {denied:?}"
                ));
            }

            let missing = client
                .find_app_password_identifiers("sc-livetest-nonexistent-account")
                .await
                .map_err(|error| {
                    format!("a scoped lookup for an unknown account failed: {error:?}")
                })?;
            if !missing.is_empty() {
                return Err("an unknown account must yield no credentials".to_owned());
            }
            Ok::<(), String>(())
        }
        .await;

        // Cleanup uses the admin credential: the manager must never be relied
        // on to delete an object it was just proven unable to delete.
        let _ = admin.delete_user(canary.user_id).await;
        checks.expect("the manager must be denied access to an object it did not create");
    }
}
