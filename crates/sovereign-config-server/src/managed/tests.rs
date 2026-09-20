use std::{
    collections::BTreeSet,
    env,
    sync::{
        Arc, Mutex,
        atomic::{AtomicI64, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, patch, post},
};
use reqwest::Url;
use serde_json::{Value, json};
use sovereign_config_core::{ConnectionUrl, ManagedPermission};
use sqlx::postgres::PgPoolOptions;
use tokio::{net::TcpListener, task::JoinHandle, time::sleep};

use sovereign_config_core::Secret;
use tonic::{Request, Status};

use super::identity::{
    USERNAME_PREFIX, USERNAME_SLUG_MAX_CHARS, generate_app_password, generate_connection_id,
    managed_username, username_slug,
};
use super::store::ConnectionRow;
use super::{ManagedConnectionsService, ManagedSettings, V3ManagedConnections};
use crate::auth::{AuthenticatedPrincipal, Grant, Permission};
use crate::authentik::AuthentikAdminClient;
use crate::metrics::ManagedConnectionMetrics;
use sovereign_config_proto::sovereign::config::v3::{
    CreateManagedConnectionRequest, ListManagedConnectionsRequest, RevokeManagedConnectionRequest,
    RotateManagedConnectionRequest, managed_connections_server::ManagedConnections,
};

const APP_PASSWORD_SENTINEL: &str = "created-app-password-sentinel";
const CREDENTIAL_IDENTIFIER: &str = "app-password-identifier-sentinel";
const PUBLIC_ORIGIN: &str = "https://config.example.test";
const ISSUER: &str = "https://auth.example.test/application/o/sovereign-config/";
const GRANTS_ATTRIBUTE: &str = "sovereign_config_test_grants";
const MANAGED_GROUP: &str = "sovereign-config-test-connections";
const TEST_GROUP_ID: &str = "11111111-1111-1111-1111-111111111111";
/// Longer than the mock client timeout so an in-flight rotation is
/// rejected, but short enough to exercise recovery without a long sleep.
const ROTATION_LEASE: Duration = Duration::from_millis(800);

/// One scripted outcome for a mocked Authentik route.
#[derive(Clone)]
enum Behavior {
    Ok,
    Status(StatusCode),
    Timeout,
    /// Succeed at the transport level but return an unexpected payload.
    Body(String),
    /// Apply the change, then never answer: the caller cannot tell whether
    /// Authentik committed it.
    CommitThenTimeout,
    /// Apply the change, then refuse, as Authentik does once the caller can
    /// no longer see the object.
    CommitThenRefuse,
    /// Apply the change, then report "not found", as Authentik does for
    /// an object the caller has lost visibility into after it is gone.
    CommitThenNotFound,
}

#[derive(Clone)]
struct Script {
    create_account: Behavior,
    set_attributes: Behavior,
    find_user: Behavior,
    find_credentials: Behavior,
    set_credential: Behavior,
    delete_user: Behavior,
    find_group: Behavior,
    add_to_group: Behavior,
    /// Whether a reconciliation lookup should report the account exists.
    user_exists: bool,
    /// Whether the caller may see the service account's app password,
    /// reproducing Authentik's token ownership and permission rules.
    credentials_visible: bool,
    /// Whether the configured browsing group exists in the directory.
    group_exists: bool,
    set_credential_delay: Duration,
    /// Delay applied before the account is registered in the mock,
    /// modeling a create request that has not yet committed in
    /// Authentik while the client is still waiting for a response.
    create_account_delay: Duration,
}

impl Default for Script {
    fn default() -> Self {
        Self {
            create_account: Behavior::Ok,
            set_attributes: Behavior::Ok,
            find_user: Behavior::Ok,
            find_credentials: Behavior::Ok,
            set_credential: Behavior::Ok,
            delete_user: Behavior::Ok,
            find_group: Behavior::Ok,
            add_to_group: Behavior::Ok,
            user_exists: false,
            credentials_visible: true,
            group_exists: true,
            set_credential_delay: Duration::ZERO,
            create_account_delay: Duration::ZERO,
        }
    }
}

#[derive(Clone)]
struct MockState {
    script: Arc<Mutex<Script>>,
    created_users: Arc<Mutex<Vec<String>>>,
    deleted_users: Arc<Mutex<Vec<i64>>>,
    patched_attributes: Arc<Mutex<Vec<Value>>>,
    revoked_usernames: Arc<Mutex<Vec<String>>>,
    usernames_by_id: Arc<Mutex<std::collections::HashMap<i64, String>>>,
    rotated_keys: Arc<Mutex<Vec<String>>>,
    group_assignments: Arc<Mutex<Vec<(i64, String)>>>,
    next_user_id: Arc<AtomicI64>,
}

struct MockAuthentik {
    origin: Url,
    state: MockState,
    task: JoinHandle<()>,
}

impl Drop for MockAuthentik {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MockAuthentik {
    fn script(&self, update: impl FnOnce(&mut Script)) {
        update(&mut self.state.script.lock().unwrap());
    }

    fn deleted_users(&self) -> Vec<i64> {
        self.state.deleted_users.lock().unwrap().clone()
    }

    fn patched_attributes(&self) -> Vec<Value> {
        self.state.patched_attributes.lock().unwrap().clone()
    }

    fn rotated_keys(&self) -> Vec<String> {
        self.state.rotated_keys.lock().unwrap().clone()
    }

    fn group_assignments(&self) -> Vec<(i64, String)> {
        self.state.group_assignments.lock().unwrap().clone()
    }
}

async fn apply(behavior: &Behavior) -> Option<Response> {
    match behavior {
        // `CommitThenTimeout` applies the change in the handler itself,
        // so it produces no scripted response here.
        Behavior::Ok
        | Behavior::CommitThenTimeout
        | Behavior::CommitThenRefuse
        | Behavior::CommitThenNotFound => None,
        Behavior::Status(status) => Some((*status, "authentik-body-sentinel").into_response()),
        Behavior::Timeout => {
            sleep(Duration::from_secs(30)).await;
            Some((StatusCode::OK, "{}").into_response())
        }
        Behavior::Body(body) => Some((StatusCode::OK, body.clone()).into_response()),
    }
}

fn behavior(state: &MockState, select: impl FnOnce(&Script) -> Behavior) -> Behavior {
    select(&state.script.lock().unwrap())
}

async fn create_account(State(state): State<MockState>, Json(body): Json<Value>) -> Response {
    let delay = state.script.lock().unwrap().create_account_delay;
    sleep(delay).await;
    if let Some(response) = apply(&behavior(&state, |script| script.create_account.clone())).await {
        return response;
    }
    let username = body
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let user_pk = state.next_user_id.fetch_add(1, Ordering::Relaxed);
    state.created_users.lock().unwrap().push(username.clone());
    state
        .usernames_by_id
        .lock()
        .unwrap()
        .insert(user_pk, username.clone());
    Json(json!({
        "username": username,
        "user_uid": format!("uid-{user_pk}"),
        "user_pk": user_pk,
        "token": APP_PASSWORD_SENTINEL,
    }))
    .into_response()
}

/// Handles every PATCH to the user detail endpoint. Real Authentik
/// accepts a partial update, so the attribute-setting and group-assignment
/// calls share this one route; the body shape distinguishes them, the way
/// the real serializer does.
async fn set_attributes(
    State(state): State<MockState>,
    Path(user_id): Path<i64>,
    Json(body): Json<Value>,
) -> Response {
    if body.get("groups").is_some() {
        return assign_group(state, user_id, body).await;
    }
    if let Some(response) = apply(&behavior(&state, |script| script.set_attributes.clone())).await {
        return response;
    }
    state.patched_attributes.lock().unwrap().push(body);
    Json(json!({})).into_response()
}

async fn assign_group(state: MockState, user_id: i64, body: Value) -> Response {
    if let Some(response) = apply(&behavior(&state, |script| script.add_to_group.clone())).await {
        return response;
    }
    if let Some(group_id) = body
        .get("groups")
        .and_then(Value::as_array)
        .and_then(|groups| groups.first())
        .and_then(Value::as_str)
    {
        state
            .group_assignments
            .lock()
            .unwrap()
            .push((user_id, group_id.to_owned()));
    }
    Json(json!({})).into_response()
}

async fn list_users(
    State(state): State<MockState>,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Response {
    if let Some(response) = apply(&behavior(&state, |script| script.find_user.clone())).await {
        return response;
    }
    let username = query.get("username").cloned().unwrap_or_default();
    let exists = state.script.lock().unwrap().user_exists;
    let results = if exists {
        json!([{ "pk": 4242, "username": username }])
    } else {
        json!([])
    };
    Json(json!({ "results": results })).into_response()
}

/// Mirrors Authentik: results are filtered by the exact `user__username`
/// and `intent` query parameters, and a token is only visible when the
/// caller may see it. Returning a token regardless of the query would let
/// a permission or filter mistake pass unnoticed.
async fn list_tokens(
    State(state): State<MockState>,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Response {
    if let Some(response) = apply(&behavior(&state, |script| script.find_credentials.clone())).await
    {
        return response;
    }
    let visible = state.script.lock().unwrap().credentials_visible;
    let created = state.created_users.lock().unwrap().clone();
    // Authentik removes a service account's tokens along with the account,
    // so a deleted account must stop yielding a credential.
    let revoked = state.revoked_usernames.lock().unwrap().clone();
    let matches = visible
        && query
            .get("intent")
            .is_some_and(|intent| intent == "app_password")
        && query
            .get("user__username")
            .is_some_and(|username| created.contains(username) && !revoked.contains(username));
    let results = if matches {
        json!([{ "identifier": CREDENTIAL_IDENTIFIER }])
    } else {
        json!([])
    };
    Json(json!({ "results": results })).into_response()
}

/// Serves the group name lookup used for best-effort browsing membership.
async fn list_groups(
    State(state): State<MockState>,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Response {
    if let Some(response) = apply(&behavior(&state, |script| script.find_group.clone())).await {
        return response;
    }
    let exists = state.script.lock().unwrap().group_exists;
    let name = query.get("name").cloned().unwrap_or_default();
    let results = if exists {
        json!([{ "pk": TEST_GROUP_ID, "name": name }])
    } else {
        json!([])
    };
    Json(json!({ "results": results })).into_response()
}

async fn set_key(
    State(state): State<MockState>,
    Path(_identifier): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    let delay = state.script.lock().unwrap().set_credential_delay;
    sleep(delay).await;
    if let Some(response) = apply(&behavior(&state, |script| script.set_credential.clone())).await {
        return response;
    }
    if let Some(key) = body.get("key").and_then(Value::as_str) {
        state.rotated_keys.lock().unwrap().push(key.to_owned());
    }
    Json(json!({})).into_response()
}

/// Serves the detail probe used to confirm deletion by primary key.
#[allow(clippy::unused_async)]
async fn get_user(State(state): State<MockState>, Path(user_id): Path<i64>) -> Response {
    let deleted = state.deleted_users.lock().unwrap().contains(&user_id);
    if deleted {
        return StatusCode::NOT_FOUND.into_response();
    }
    Json(json!({ "pk": user_id, "username": "sc-managed-probe" })).into_response()
}

async fn delete_user(State(state): State<MockState>, Path(user_id): Path<i64>) -> Response {
    let scripted = behavior(&state, |script| script.delete_user.clone());
    if let Some(response) = apply(&scripted).await {
        return response;
    }
    state.deleted_users.lock().unwrap().push(user_id);
    // Authentik cascades a service account's tokens with the user.
    if let Some(username) = state.usernames_by_id.lock().unwrap().get(&user_id).cloned() {
        state.revoked_usernames.lock().unwrap().push(username);
    }
    if matches!(scripted, Behavior::CommitThenTimeout) {
        sleep(Duration::from_secs(30)).await;
    }
    if matches!(scripted, Behavior::CommitThenRefuse) {
        return (StatusCode::FORBIDDEN, "authentik-body-sentinel").into_response();
    }
    if matches!(scripted, Behavior::CommitThenNotFound) {
        return (StatusCode::NOT_FOUND, "authentik-body-sentinel").into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn mock_authentik() -> MockAuthentik {
    let state = MockState {
        script: Arc::new(Mutex::new(Script::default())),
        created_users: Arc::new(Mutex::new(Vec::new())),
        deleted_users: Arc::new(Mutex::new(Vec::new())),
        patched_attributes: Arc::new(Mutex::new(Vec::new())),
        revoked_usernames: Arc::new(Mutex::new(Vec::new())),
        usernames_by_id: Arc::new(Mutex::new(std::collections::HashMap::new())),
        rotated_keys: Arc::new(Mutex::new(Vec::new())),
        group_assignments: Arc::new(Mutex::new(Vec::new())),
        next_user_id: Arc::new(AtomicI64::new(1000)),
    };
    let app = Router::new()
        .route("/api/v3/core/users/service_account/", post(create_account))
        .route(
            "/api/v3/core/users/{user_id}/",
            patch(set_attributes).delete(delete_user).get(get_user),
        )
        .route("/api/v3/core/users/", get(list_users))
        .route("/api/v3/core/tokens/", get(list_tokens))
        .route("/api/v3/core/tokens/{identifier}/set_key/", post(set_key))
        .route("/api/v3/core/groups/", get(list_groups))
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    MockAuthentik {
        origin: format!("http://{address}/").parse().unwrap(),
        state,
        task,
    }
}

fn principal(grants: &[(&str, &[Permission])]) -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        subject: "test-subject".to_owned(),
        grants: grants
            .iter()
            .map(|(prefix, permissions)| Grant {
                prefix: (*prefix).to_owned(),
                permissions: permissions.iter().copied().collect::<BTreeSet<_>>(),
            })
            .collect(),
    }
}

/// A fully-authorized operator (read + write + manage) scoped to `prefix`
/// — the common fixture for lifecycle tests, which need to both use the
/// feature (Manage on the root) and grant the permissions they request.
fn operator(prefix: &str) -> AuthenticatedPrincipal {
    principal(&[(
        prefix,
        &[Permission::Read, Permission::Write, Permission::Manage],
    )])
}

fn request<T>(message: T, principal: &AuthenticatedPrincipal) -> Request<T> {
    let mut request = Request::new(message);
    request.extensions_mut().insert(principal.clone());
    request
}

async fn service(mock: &MockAuthentik) -> Option<V3ManagedConnections> {
    service_with_metrics(mock, Arc::new(ManagedConnectionMetrics::default())).await
}

async fn service_with_metrics(
    mock: &MockAuthentik,
    metrics: Arc<ManagedConnectionMetrics>,
) -> Option<V3ManagedConnections> {
    let database_url = env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL").ok()?;
    let database = PgPoolOptions::new()
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database_url)
        .await
        .expect("test database must be reachable");
    sqlx::migrate!("./migrations")
        .run(&database)
        .await
        .expect("migrations must apply");
    sqlx::query("DELETE FROM managed_connections")
        .execute(&database)
        .await
        .expect("managed connection table must be clearable");
    let admin = AuthentikAdminClient::new(
        mock.origin.clone(),
        Secret::new("manager-api-token-sentinel"),
        Duration::from_millis(400),
    )
    .expect("mock admin client must build");
    Some(V3ManagedConnections::new(Arc::new(
        ManagedConnectionsService::new(
            database,
            admin,
            ManagedSettings {
                public_origin: PUBLIC_ORIGIN.to_owned(),
                issuer: ISSUER.to_owned(),
                client_id: "sovereign-config".to_owned(),
                grants_attribute: GRANTS_ATTRIBUTE.to_owned(),
                managed_group: MANAGED_GROUP.to_owned(),
                rotation_lease: ROTATION_LEASE,
            },
            metrics,
        ),
    )))
}

async fn rows(service: &V3ManagedConnections) -> Vec<ConnectionRow> {
    sqlx::query_as::<_, ConnectionRow>(
        r"
        SELECT connection_id, display_name, root, provider_user_id,
               credential_identifier, state, permissions, created_at, updated_at
        FROM managed_connections
        ORDER BY created_at, connection_id
        ",
    )
    .fetch_all(&service.shared.database)
    .await
    .expect("managed connection rows must be readable")
}

async fn create(
    service: &V3ManagedConnections,
    name: &str,
    root: &str,
    principal: &AuthenticatedPrincipal,
) -> Result<(String, String), Status> {
    create_with(service, name, root, &[ManagedPermission::Read], principal).await
}

async fn create_with(
    service: &V3ManagedConnections,
    name: &str,
    root: &str,
    permissions: &[ManagedPermission],
    principal: &AuthenticatedPrincipal,
) -> Result<(String, String), Status> {
    let response = service
        .create_managed_connection(request(
            CreateManagedConnectionRequest {
                display_name: name.to_owned(),
                root: root.to_owned(),
                permissions: permissions.iter().map(|p| p.as_proto()).collect(),
            },
            principal,
        ))
        .await?
        .into_inner();
    let metadata = response.metadata.expect("create must return metadata");
    Ok((metadata.connection_id, response.connection_url))
}

/// Fails the test when a status message leaks any request-derived value.
fn assert_bounded(status: &Status) {
    const ALLOWED: [&str; 7] = [
        "configuration storage is unavailable",
        "managed connection dependency is unavailable",
        "managed connection requires cleanup",
        "managed connection not found",
        "managed connection request is invalid",
        "managed connection operation is already in progress",
        "configuration operation is not permitted",
    ];
    let message = status.message();
    assert!(
        ALLOWED.contains(&message),
        "unbounded status message: {message}"
    );
    for sentinel in [
        APP_PASSWORD_SENTINEL,
        CREDENTIAL_IDENTIFIER,
        "authentik-body-sentinel",
        "manager-api-token-sentinel",
        "sc-managed-",
        "Pipeline reader",
    ] {
        assert!(
            !message.contains(sentinel),
            "status message leaked {sentinel}: {message}"
        );
    }
}

macro_rules! service_or_skip {
    ($mock:expr) => {
        match service($mock).await {
            Some(service) => service,
            None => return,
        }
    };
}

#[test]
fn username_slug_embeds_a_recognizable_display_name() {
    assert_eq!(username_slug("Pipeline reader"), "pipeline-reader");
    assert_eq!(username_slug("  Extra   Spaces  "), "extra-spaces");
    assert_eq!(username_slug("MixedCASE123"), "mixedcase123");
    // Non-ASCII characters are dropped rather than transliterated, and the
    // surrounding separators collapse to a single hyphen.
    assert_eq!(username_slug("café → app"), "caf-app");
    // Truncation must never leave a trailing hyphen.
    let long = "a-".repeat(40);
    let slug = username_slug(&long);
    assert!(slug.len() <= USERNAME_SLUG_MAX_CHARS);
    assert!(!slug.ends_with('-'));
    // A display name with no slug-able characters yields an empty slug.
    assert_eq!(username_slug("★★★"), "");
}

#[test]
fn managed_username_is_unique_even_for_identical_display_names() {
    let first = generate_connection_id().unwrap();
    let second = generate_connection_id().unwrap();

    let first_username = managed_username(&first, "Pipeline reader");
    let second_username = managed_username(&second, "Pipeline reader");

    assert_ne!(first_username, second_username);
    assert!(first_username.contains("pipeline-reader"));
    assert!(first_username.contains(first.as_str()));
    assert!(first_username.starts_with(USERNAME_PREFIX));

    // A display name with nothing to slug falls back to the opaque form,
    // never leaving a dangling separator.
    let opaque = managed_username(&first, "★★★");
    assert_eq!(opaque, format!("{USERNAME_PREFIX}{}", first.as_str()));
}

#[test]
fn generated_identifiers_are_opaque_and_bounded() {
    let first = generate_connection_id().unwrap();
    let second = generate_connection_id().unwrap();

    assert_ne!(first.as_str(), second.as_str());
    assert_eq!(first.as_str().len(), 32);
    assert!(
        first
            .as_str()
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    );

    let password = generate_app_password().unwrap();
    assert_eq!(password.expose().len(), 48);
    assert!(
        password
            .expose()
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric())
    );
    assert_ne!(password.expose(), generate_app_password().unwrap().expose());
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn create_provisions_exactly_one_read_only_grant_and_returns_one_url() {
    let mock = mock_authentik().await;
    let service = service_or_skip!(&mock);

    let (connection_id, url) = create(&service, "Pipeline reader", "/apps/api", &operator("/"))
        .await
        .expect("create must succeed");

    let connection = ConnectionUrl::parse(&url).expect("returned URL must be canonical");
    assert_eq!(connection.root().as_str(), "/apps/api");
    assert_eq!(connection.issuer(), ISSUER);
    assert!(connection.client_authentication().is_some());
    assert!(url.starts_with(PUBLIC_ORIGIN));

    let rows = rows(&service).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].connection_id, connection_id);
    assert_eq!(rows[0].state, "active");
    assert_eq!(rows[0].root, "/apps/api");
    assert_eq!(rows[0].permissions, "read");
    assert_eq!(
        rows[0].credential_identifier.as_deref(),
        Some(CREDENTIAL_IDENTIFIER)
    );
    assert!(rows[0].provider_user_id.is_some());

    // The persisted row must never carry credential material.
    let serialized = format!(
        "{}{}{}{}",
        rows[0].connection_id,
        rows[0].display_name,
        rows[0].root,
        rows[0].credential_identifier.clone().unwrap_or_default()
    );
    assert!(!serialized.contains(APP_PASSWORD_SENTINEL));

    let patched = mock.patched_attributes();
    assert_eq!(patched.len(), 1);
    let attributes = &patched[0]["attributes"];
    assert_eq!(
        attributes[GRANTS_ATTRIBUTE],
        json!([{ "prefix": "/apps/api", "permissions": ["read"] }])
    );
    assert_eq!(attributes["sovereign_config_managed"], json!(connection_id));
    assert_eq!(
        attributes["goauthentik.io/user/token-expires"],
        json!(false)
    );
    assert_eq!(
        attributes["goauthentik.io/user/service-account"],
        json!(true)
    );

    // The new account is added to the configured browsing group.
    let assignments = mock.group_assignments();
    assert_eq!(assignments.len(), 1);
    assert_eq!(assignments[0].1, TEST_GROUP_ID);
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn selected_permissions_flow_to_the_grant_row_and_metadata() {
    // Each non-empty subset the operator selects must be reflected exactly:
    // in the Authentik grant JSON, the persisted row, and the listed
    // metadata — canonically ordered, no more and no less.
    for (requested, tokens, proto) in [
        (
            vec![ManagedPermission::Write],
            json!(["write"]),
            vec![ManagedPermission::Write.as_proto()],
        ),
        (
            // Deliberately out of order and duplicated on the wire.
            vec![
                ManagedPermission::Manage,
                ManagedPermission::Read,
                ManagedPermission::Read,
            ],
            json!(["read", "manage"]),
            vec![
                ManagedPermission::Read.as_proto(),
                ManagedPermission::Manage.as_proto(),
            ],
        ),
        (
            vec![
                ManagedPermission::Read,
                ManagedPermission::Write,
                ManagedPermission::Manage,
            ],
            json!(["read", "write", "manage"]),
            vec![
                ManagedPermission::Read.as_proto(),
                ManagedPermission::Write.as_proto(),
                ManagedPermission::Manage.as_proto(),
            ],
        ),
    ] {
        let mock = mock_authentik().await;
        let service = service_or_skip!(&mock);

        let (connection_id, _) = create_with(
            &service,
            "Selected",
            "/apps/api",
            &requested,
            &operator("/"),
        )
        .await
        .expect("create must succeed");

        // Grant JSON carries exactly the selected permissions.
        let patched = mock.patched_attributes();
        assert_eq!(patched.len(), 1);
        assert_eq!(
            patched[0]["attributes"][GRANTS_ATTRIBUTE],
            json!([{ "prefix": "/apps/api", "permissions": tokens }])
        );

        // Listed metadata echoes the same set in canonical order.
        let listed = service
            .list_managed_connections(request(ListManagedConnectionsRequest {}, &operator("/")))
            .await
            .expect("list must succeed")
            .into_inner();
        let metadata = listed
            .connections
            .iter()
            .find(|connection| connection.connection_id == connection_id)
            .expect("created connection must be listed");
        assert_eq!(metadata.permissions, proto);
    }
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn create_rejects_an_empty_permission_selection() {
    let mock = mock_authentik().await;
    let service = service_or_skip!(&mock);

    let status = create_with(&service, "Empty", "/apps/api", &[], &operator("/"))
        .await
        .expect_err("an empty permission selection must be rejected");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert_bounded(&status);
    assert!(rows(&service).await.is_empty());
    assert!(mock.patched_attributes().is_empty());
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn create_cannot_grant_a_permission_the_caller_lacks() {
    let mock = mock_authentik().await;
    let service = service_or_skip!(&mock);

    // A principal that can manage and read the root, but cannot write it,
    // must not be able to mint a write-capable access URL.
    let manage_and_read = principal(&[("/apps/api", &[Permission::Read, Permission::Manage])]);
    let status = create_with(
        &service,
        "Escalation",
        "/apps/api",
        &[ManagedPermission::Read, ManagedPermission::Write],
        &manage_and_read,
    )
    .await
    .expect_err("granting write without holding write must be denied");
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    assert_bounded(&status);
    assert!(rows(&service).await.is_empty());
    assert!(mock.patched_attributes().is_empty());

    // The permissions it does hold are still grantable.
    create_with(
        &service,
        "Permitted",
        "/apps/api",
        &[ManagedPermission::Read, ManagedPermission::Manage],
        &manage_and_read,
    )
    .await
    .expect("granting only held permissions must succeed");
}

/// Group membership is a pure operator convenience and must never block or
/// roll back an otherwise-successful connection, whether the configured
/// group cannot be resolved or the assignment itself is rejected.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn group_assignment_failure_does_not_block_creation() {
    let mock = mock_authentik().await;
    let service = service_or_skip!(&mock);

    mock.script(|script| script.group_exists = false);
    let (connection_id, _) = create(&service, "No group", "/apps/api", &operator("/"))
        .await
        .expect("a missing browsing group must not fail creation");
    assert_eq!(rows(&service).await[0].connection_id, connection_id);
    assert!(mock.group_assignments().is_empty());

    mock.script(|script| {
        script.group_exists = true;
        script.add_to_group = Behavior::Status(StatusCode::FORBIDDEN);
    });
    let (connection_id, _) = create(&service, "Rejected group", "/apps/api", &operator("/"))
        .await
        .expect("a rejected group assignment must not fail creation");
    let rows = rows(&service).await;
    assert!(
        rows.iter()
            .any(|row| row.connection_id == connection_id && row.state == "active")
    );
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn authorization_requires_manage_on_the_connection_root() {
    let mock = mock_authentik().await;
    let service = service_or_skip!(&mock);

    // Exact root and ancestor grants both authorize creation.
    create(&service, "Exact", "/apps/api", &operator("/apps/api"))
        .await
        .expect("exact root must authorize");
    create(&service, "Ancestor", "/apps/web", &operator("/apps"))
        .await
        .expect("ancestor root must authorize");

    // A sibling grant and read/write without manage must not.
    let sibling = create(&service, "Sibling", "/apps/api", &operator("/apps/other")).await;
    let status = sibling.expect_err("sibling grant must be denied");
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    assert_bounded(&status);

    let read_write = principal(&[("/", &[Permission::Read, Permission::Write])]);
    let status = create(&service, "ReadWrite", "/apps/api", &read_write)
        .await
        .expect_err("read and write without manage must be denied");
    assert_eq!(status.code(), tonic::Code::PermissionDenied);

    // Listing only discloses rows the caller can manage.
    let scoped = service
        .list_managed_connections(request(
            ListManagedConnectionsRequest {},
            &operator("/apps/web"),
        ))
        .await
        .expect("list must succeed")
        .into_inner();
    assert_eq!(scoped.connections.len(), 1);
    assert_eq!(scoped.connections[0].root, "/apps/web");

    let global = service
        .list_managed_connections(request(ListManagedConnectionsRequest {}, &operator("/")))
        .await
        .expect("list must succeed")
        .into_inner();
    assert_eq!(global.connections.len(), 2);
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn unmanageable_and_missing_connections_are_indistinguishable() {
    let mock = mock_authentik().await;
    let service = service_or_skip!(&mock);
    let (connection_id, _) = create(&service, "Scoped", "/apps/api", &operator("/"))
        .await
        .expect("create must succeed");
    let unknown = "0123456789abcdef0123456789abcdef";

    for id in [connection_id.as_str(), unknown] {
        let rotate = service
            .rotate_managed_connection(request(
                RotateManagedConnectionRequest {
                    connection_id: id.to_owned(),
                },
                &operator("/apps/other"),
            ))
            .await
            .expect_err("non-manageable rotate must fail");
        assert_eq!(rotate.code(), tonic::Code::NotFound);
        assert_eq!(rotate.message(), "managed connection not found");

        let revoke = service
            .revoke_managed_connection(request(
                RevokeManagedConnectionRequest {
                    connection_id: id.to_owned(),
                },
                &operator("/apps/other"),
            ))
            .await
            .expect_err("non-manageable revoke must fail");
        assert_eq!(revoke.code(), tonic::Code::NotFound);
        assert_eq!(revoke.message(), "managed connection not found");
    }
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn invalid_and_unauthenticated_requests_are_rejected_before_any_call() {
    let mock = mock_authentik().await;
    let service = service_or_skip!(&mock);
    let global = operator("/");

    for (name, root) in [
        ("", "/apps"),
        ("  padded", "/apps"),
        (&"x".repeat(101), "/apps"),
        ("control\nname", "/apps"),
        ("Valid", "not-rooted"),
        // `_` became a legal segment character in 2.15.0; `.` did not.
        ("Valid", "/Apps/Bad.Name"),
    ] {
        let status = create(&service, name, root, &global)
            .await
            .expect_err("invalid input must be rejected");
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert_bounded(&status);
    }

    let status = service
        .rotate_managed_connection(request(
            RotateManagedConnectionRequest {
                connection_id: "TOO-SHORT".to_owned(),
            },
            &global,
        ))
        .await
        .expect_err("invalid identifier must be rejected");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);

    // No principal extension at all must fail closed.
    let status = service
        .list_managed_connections(Request::new(ListManagedConnectionsRequest {}))
        .await
        .expect_err("unauthenticated list must be rejected");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);

    assert!(rows(&service).await.is_empty());
    assert!(mock.patched_attributes().is_empty());
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn definitive_create_failures_roll_back_without_orphaning_a_credential() {
    let mock = mock_authentik().await;
    let service = service_or_skip!(&mock);

    // Account creation refused outright: nothing to compensate.
    mock.script(|script| script.create_account = Behavior::Status(StatusCode::FORBIDDEN));
    let status = create(&service, "Refused", "/apps/api", &operator("/"))
        .await
        .expect_err("refused creation must fail");
    assert_bounded(&status);
    assert!(rows(&service).await.is_empty());
    assert!(mock.deleted_users().is_empty());

    // Credential discovery returning the wrong count must roll back.
    for body in [
        json!({ "results": [] }).to_string(),
        json!({ "results": [
            { "identifier": "first-identifier" },
            { "identifier": "second-identifier" }
        ] })
        .to_string(),
    ] {
        mock.script(|script| {
            script.create_account = Behavior::Ok;
            script.find_credentials = Behavior::Body(body);
        });
        let status = create(
            &service,
            "Ambiguous credential",
            "/apps/api",
            &operator("/"),
        )
        .await
        .expect_err("ambiguous credential discovery must fail");
        assert_bounded(&status);
        assert!(rows(&service).await.is_empty(), "row must be rolled back");
        assert!(
            !mock.deleted_users().is_empty(),
            "the created account must be deleted"
        );
    }

    // A failed grant patch must also roll back the created account.
    mock.script(|script| {
        script.find_credentials = Behavior::Ok;
        script.set_attributes = Behavior::Status(StatusCode::FORBIDDEN);
    });
    let before = mock.deleted_users().len();
    let status = create(&service, "Patch failure", "/apps/api", &operator("/"))
        .await
        .expect_err("failed grant patch must fail");
    assert_bounded(&status);
    assert!(rows(&service).await.is_empty());
    assert!(mock.deleted_users().len() > before);
}

/// Regression: in production the manager could create the app password but
/// not see it, because Authentik only shows a non-superuser tokens they own
/// and the service-account endpoint creates the token with a direct ORM
/// call. Discovery returned zero rows and creation failed with an
/// unavailable dependency after rolling the account back.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn unreadable_app_password_rolls_back_and_is_visible_in_metrics() {
    let mock = mock_authentik().await;
    let metrics = Arc::new(ManagedConnectionMetrics::default());
    let Some(service) = service_with_metrics(&mock, Arc::clone(&metrics)).await else {
        return;
    };
    mock.script(|script| script.credentials_visible = false);

    let status = create(
        &service,
        "Invisible credential",
        "/apps/api",
        &operator("/"),
    )
    .await
    .expect_err("an undiscoverable credential must fail creation");
    assert_bounded(&status);

    // The account must not be left behind with a usable credential.
    assert!(rows(&service).await.is_empty());
    assert!(!mock.deleted_users().is_empty());

    // The failure must be attributable from metrics alone, which is what
    // made the production incident diagnosable.
    let rendered = metrics.render();
    assert!(
        rendered.contains(
            "sovereign_config_managed_dependency_total{call=\"find_credentials\",outcome=\"invalid\"} 1"
        ),
        "an unreadable credential must record a bounded dependency failure"
    );
    assert!(rendered.contains(
        "sovereign_config_managed_dependency_total{call=\"set_attributes\",outcome=\"ok\"} 0"
    ));
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn ambiguous_creation_reconciles_only_the_exact_generated_account() {
    let mock = mock_authentik().await;
    let service = service_or_skip!(&mock);

    // Authentik times out but did commit the account.
    mock.script(|script| {
        script.create_account = Behavior::Timeout;
        script.user_exists = true;
    });
    let status = create(&service, "Ambiguous", "/apps/api", &operator("/"))
        .await
        .expect_err("ambiguous creation must not return a URL");
    assert_bounded(&status);
    assert_eq!(
        mock.deleted_users(),
        [4242],
        "only the reconciled account may be deleted"
    );
    assert!(rows(&service).await.is_empty());

    // Ambiguous creation where compensation is also unavailable must
    // retain a recoverable cleanup_required row rather than silently
    // orphaning a usable credential.
    mock.script(|script| {
        script.create_account = Behavior::Timeout;
        script.user_exists = true;
        script.delete_user = Behavior::Status(StatusCode::INTERNAL_SERVER_ERROR);
    });
    let status = create(&service, "Unrecoverable", "/apps/api", &operator("/"))
        .await
        .expect_err("unrecoverable compensation must fail");
    assert_eq!(status.message(), "managed connection requires cleanup");
    assert_bounded(&status);
    let rows = rows(&service).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].state, "cleanup_required");
}

/// Regression: a 2xx create response that fails this server's own strict
/// validation (not a transport failure) must be reconciled the same way
/// as a timeout, because Authentik may genuinely have committed the
/// account even though the response body did not pass validation.
/// Treating it as definitively absent would orphan a live credential.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn invalid_create_response_reconciles_a_genuinely_created_account() {
    let mock = mock_authentik().await;
    let service = service_or_skip!(&mock);

    // The response is valid JSON but fails strict validation (username
    // mismatch), while the account was actually created.
    mock.script(|script| {
        script.create_account = Behavior::Body(
            json!({
                "username": "not-the-requested-username",
                "user_uid": "uid-mismatch",
                "user_pk": 4242,
                "token": APP_PASSWORD_SENTINEL,
            })
            .to_string(),
        );
        script.user_exists = true;
    });
    let status = create(&service, "Invalid response", "/apps/api", &operator("/"))
        .await
        .expect_err("an invalid create response must not return a URL");
    assert_bounded(&status);
    assert_eq!(
        mock.deleted_users(),
        [4242],
        "the genuinely created account must be reconciled and deleted"
    );
    assert!(rows(&service).await.is_empty());
}

/// Regression: a single reconciliation probe cannot distinguish "the
/// account was never created" from "Authentik is still processing the
/// original request". If every retry finds nothing, the row must be kept
/// as `cleanup_required` rather than deleted, so a create that lands
/// after the last retry can still be found (via revoke) instead of being
/// silently orphaned with no record anywhere in Sovereign Config.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn exhausted_reconciliation_retains_a_cleanup_required_row_instead_of_deleting_it() {
    let mock = mock_authentik().await;
    let service = service_or_skip!(&mock);

    // The account genuinely never existed, and every reconciliation probe
    // confirms that consistently.
    mock.script(|script| {
        script.create_account = Behavior::Timeout;
        script.user_exists = false;
    });
    let status = create(&service, "Never created", "/apps/api", &operator("/"))
        .await
        .expect_err("an unresolved create must not return a URL");
    assert_eq!(status.message(), "managed connection requires cleanup");
    assert_bounded(&status);

    let rows = rows(&service).await;
    assert_eq!(
        rows.len(),
        1,
        "the row must be retained, not deleted, when absence cannot be confirmed"
    );
    assert_eq!(rows[0].state, "cleanup_required");
    assert!(
        mock.deleted_users().is_empty(),
        "nothing was found to delete"
    );
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn rotation_replaces_the_credential_and_recovers_from_ambiguity() {
    let mock = mock_authentik().await;
    let service = service_or_skip!(&mock);
    let (connection_id, first_url) = create(&service, "Rotating", "/apps/api", &operator("/"))
        .await
        .expect("create must succeed");
    let rotate_request = || {
        request(
            RotateManagedConnectionRequest {
                connection_id: connection_id.clone(),
            },
            &operator("/"),
        )
    };

    let rotated = service
        .rotate_managed_connection(rotate_request())
        .await
        .expect("rotation must succeed")
        .into_inner();
    assert_ne!(rotated.connection_url, first_url);
    let connection =
        ConnectionUrl::parse(&rotated.connection_url).expect("rotated URL must be canonical");
    assert_eq!(connection.root().as_str(), "/apps/api");
    assert_eq!(rows(&service).await[0].state, "active");
    assert_eq!(mock.rotated_keys().len(), 1);

    // A definitive rejection leaves the previous credential current.
    mock.script(|script| script.set_credential = Behavior::Status(StatusCode::BAD_REQUEST));
    let status = service
        .rotate_managed_connection(rotate_request())
        .await
        .expect_err("rejected rotation must fail");
    assert_bounded(&status);
    assert_eq!(rows(&service).await[0].state, "active");

    // A timeout is ambiguous: no URL, and the row records the ambiguity.
    mock.script(|script| script.set_credential = Behavior::Timeout);
    let status = service
        .rotate_managed_connection(rotate_request())
        .await
        .expect_err("ambiguous rotation must fail");
    assert_bounded(&status);
    assert_eq!(rows(&service).await[0].state, "rotation_unknown");

    // While the lease is unexpired the ambiguous rotation may still be in
    // flight, so a further attempt must be refused rather than overlapping.
    mock.script(|script| script.set_credential = Behavior::Ok);
    let status = service
        .rotate_managed_connection(rotate_request())
        .await
        .expect_err("rotation within the lease must be refused");
    assert_eq!(status.code(), tonic::Code::Aborted);
    assert_bounded(&status);

    // Once the lease expires the earlier attempt cannot still be running,
    // so an explicit retry overwrites the key with a known fresh value.
    sleep(ROTATION_LEASE).await;
    let recovered = service
        .rotate_managed_connection(rotate_request())
        .await
        .expect("retried rotation must succeed")
        .into_inner();
    assert_ne!(recovered.connection_url, rotated.connection_url);
    assert_eq!(rows(&service).await[0].state, "active");
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn concurrent_rotation_never_issues_two_current_credentials() {
    let mock = mock_authentik().await;
    let service = service_or_skip!(&mock);
    let (connection_id, _) = create(&service, "Concurrent", "/apps/api", &operator("/"))
        .await
        .expect("create must succeed");
    mock.script(|script| script.set_credential_delay = Duration::from_millis(120));

    let first = service.rotate_managed_connection(request(
        RotateManagedConnectionRequest {
            connection_id: connection_id.clone(),
        },
        &operator("/"),
    ));
    let second = service.rotate_managed_connection(request(
        RotateManagedConnectionRequest {
            connection_id: connection_id.clone(),
        },
        &operator("/"),
    ));
    let (first, second) = tokio::join!(first, second);

    let succeeded = usize::from(first.is_ok()) + usize::from(second.is_ok());
    assert_eq!(
        succeeded, 1,
        "exactly one concurrent rotation may report a current credential"
    );
    for status in [first.err(), second.err()].into_iter().flatten() {
        assert_eq!(status.code(), tonic::Code::Aborted);
        assert_bounded(&status);
    }
    // Only the winning rotation may have replaced the credential.
    assert_eq!(mock.rotated_keys().len(), 1);
    let rows = rows(&service).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].state, "active");
}

/// Regression: rotation moves the row to `rotation_unknown` and releases
/// its lock before the slow external call, so a concurrent revoke can
/// claim and delete the row in between. The rotation's later write-back
/// must not resurrect a row a revoke already claimed.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn a_concurrent_revoke_is_not_undone_by_a_slow_rotation_write_back() {
    let mock = mock_authentik().await;
    let service = service_or_skip!(&mock);
    let (connection_id, _) = create(&service, "Raced", "/apps/api", &operator("/"))
        .await
        .expect("create must succeed");
    mock.script(|script| script.set_credential_delay = Duration::from_millis(120));

    let rotation = service.rotate_managed_connection(request(
        RotateManagedConnectionRequest {
            connection_id: connection_id.clone(),
        },
        &operator("/"),
    ));

    // Give rotation time to move the row to `rotation_unknown` and
    // release its lock before the revoke starts.
    sleep(Duration::from_millis(40)).await;
    service
        .revoke_managed_connection(request(
            RevokeManagedConnectionRequest {
                connection_id: connection_id.clone(),
            },
            &operator("/"),
        ))
        .await
        .expect("revocation must succeed even while a rotation is in flight");

    let status = rotation
        .await
        .expect_err("rotation must not resurrect a row a concurrent revoke already claimed");
    assert_bounded(&status);

    // The revoke's own deletion already completed; the rotation
    // write-back must not have recreated or reactivated the row.
    assert!(rows(&service).await.is_empty());
}

/// Regression: a revoke targeting a still-`provisioning` row (its create
/// call has not yet committed in Authentik) finds no account to delete
/// and removes the row as if nothing existed. The account that create
/// goes on to create moments later must not be left orphaned: the CAS
/// guard on the final `transition_state` call must notice its row is
/// gone and route create's own compensation to delete it.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn a_revoke_racing_an_in_flight_create_does_not_orphan_the_account() {
    let mock = mock_authentik().await;
    let service = service_or_skip!(&mock);
    mock.script(|script| script.create_account_delay = Duration::from_millis(120));
    let principal = operator("/");

    let create_future = create(&service, "Racing", "/apps/api", &principal);

    let revoke_future = async {
        // The row is inserted before the delayed create call returns;
        // give it time to land, then target it before create finishes.
        sleep(Duration::from_millis(30)).await;
        let connection_id = rows(&service)
            .await
            .into_iter()
            .find(|row| row.state == "provisioning")
            .expect("the row must be visible before the delayed create call returns")
            .connection_id;
        service
            .revoke_managed_connection(request(
                RevokeManagedConnectionRequest { connection_id },
                &principal,
            ))
            .await
    };

    let (created, revoked) = tokio::join!(create_future, revoke_future);

    created.expect_err("create must fail once its row disappears underneath it");
    revoked.expect("revoke racing a not-yet-committed create must still succeed");
    assert!(rows(&service).await.is_empty());
    assert!(
        !mock.deleted_users().is_empty(),
        "the account created after the race must be cleaned up rather than orphaned"
    );
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn revocation_confirms_deletion_before_removing_metadata() {
    let mock = mock_authentik().await;
    let service = service_or_skip!(&mock);
    let (connection_id, _) = create(&service, "Revoked", "/apps/api", &operator("/"))
        .await
        .expect("create must succeed");
    let revoke_request = || {
        request(
            RevokeManagedConnectionRequest {
                connection_id: connection_id.clone(),
            },
            &operator("/"),
        )
    };

    // An unavailable dependency must retain a retryable row.
    mock.script(|script| script.delete_user = Behavior::Timeout);
    let status = service
        .revoke_managed_connection(revoke_request())
        .await
        .expect_err("ambiguous revocation must fail");
    assert_bounded(&status);
    let rows_after = rows(&service).await;
    assert_eq!(rows_after.len(), 1);
    assert_eq!(rows_after[0].state, "revoking");

    // Retrying after recovery confirms deletion and removes metadata.
    mock.script(|script| script.delete_user = Behavior::Ok);
    service
        .revoke_managed_connection(revoke_request())
        .await
        .expect("retried revocation must succeed");
    assert!(rows(&service).await.is_empty());
    assert!(!mock.deleted_users().is_empty());
}

/// An ambiguous deletion is settled by checking the app password, which is
/// authoritative because the token view is global and the token cascades with
/// the account, so revocation is not reported as failed when Authentik
/// already committed the delete.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn ambiguous_deletion_is_confirmed_by_credential_absence() {
    let mock = mock_authentik().await;
    let service = service_or_skip!(&mock);
    let (connection_id, _) = create(&service, "Ambiguous delete", "/apps/api", &operator("/"))
        .await
        .expect("create must succeed");

    // Authentik commits the deletion but the response never arrives.
    mock.script(|script| script.delete_user = Behavior::CommitThenTimeout);
    service
        .revoke_managed_connection(request(
            RevokeManagedConnectionRequest { connection_id },
            &operator("/"),
        ))
        .await
        .expect("a committed deletion must be confirmed despite the timeout");

    assert!(rows(&service).await.is_empty());
}

/// Regression: Authentik refuses user deletes for an account the manager
/// can no longer see rather than reporting "not found", so treating only
/// "not found" as confirmation left the last connection stuck in
/// `revoking` forever. Absence is confirmed through the app password,
/// whose view is global and which cascades with the account.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn revocation_is_confirmed_when_deletion_is_refused_but_the_credential_is_gone() {
    let mock = mock_authentik().await;
    let service = service_or_skip!(&mock);
    let (connection_id, _) = create(&service, "Refused delete", "/apps/api", &operator("/"))
        .await
        .expect("create must succeed");

    // Authentik commits the deletion, then refuses every later request
    // about an account the manager can no longer see.
    mock.script(|script| script.delete_user = Behavior::CommitThenRefuse);
    service
        .revoke_managed_connection(request(
            RevokeManagedConnectionRequest {
                connection_id: connection_id.clone(),
            },
            &operator("/"),
        ))
        .await
        .expect("a refused delete with no surviving credential must confirm revocation");
    assert!(rows(&service).await.is_empty());
}

/// A refusal while the credential still exists must not be reported as a
/// successful revocation.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn revocation_is_not_confirmed_while_the_credential_survives() {
    let mock = mock_authentik().await;
    let service = service_or_skip!(&mock);
    let (connection_id, _) = create(&service, "Surviving", "/apps/api", &operator("/"))
        .await
        .expect("create must succeed");

    mock.script(|script| script.delete_user = Behavior::Status(StatusCode::FORBIDDEN));
    let status = service
        .revoke_managed_connection(request(
            RevokeManagedConnectionRequest { connection_id },
            &operator("/"),
        ))
        .await
        .expect_err("a surviving credential must not be reported as revoked");
    assert_bounded(&status);

    let rows = rows(&service).await;
    assert_eq!(rows.len(), 1, "the row must remain for retry");
    assert_eq!(rows[0].state, "revoking");
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn revocation_treats_a_confirmed_absent_account_as_revoked() {
    let mock = mock_authentik().await;
    let service = service_or_skip!(&mock);
    let (connection_id, _) = create(&service, "Already gone", "/apps/api", &operator("/"))
        .await
        .expect("create must succeed");

    // Authentik commits the deletion, then reports "not found" for an
    // account the manager can no longer see.
    mock.script(|script| script.delete_user = Behavior::CommitThenNotFound);
    service
        .revoke_managed_connection(request(
            RevokeManagedConnectionRequest { connection_id },
            &operator("/"),
        ))
        .await
        .expect("confirmed absence must count as revoked");

    assert!(rows(&service).await.is_empty());
}

/// Regression: Authentik masks a *denied* delete as "not found" the same
/// way it masks a denied read. Trusting `NotFound` on its own would let a
/// lost delete permission orphan a still-live credential with no record
/// left to retry revocation.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn revocation_is_not_confirmed_when_a_denied_delete_is_masked_as_not_found() {
    let mock = mock_authentik().await;
    let service = service_or_skip!(&mock);
    let (connection_id, _) = create(&service, "Denied", "/apps/api", &operator("/"))
        .await
        .expect("create must succeed");

    // No cascading deletion: the account and its credential survive.
    mock.script(|script| script.delete_user = Behavior::Status(StatusCode::NOT_FOUND));
    let status = service
        .revoke_managed_connection(request(
            RevokeManagedConnectionRequest { connection_id },
            &operator("/"),
        ))
        .await
        .expect_err("a surviving credential must not be reported as revoked");
    assert_bounded(&status);

    let rows = rows(&service).await;
    assert_eq!(rows.len(), 1, "the row must remain for retry");
    assert_eq!(rows[0].state, "revoking");
}

/// Regression: a row with no `provider_user_id` (left by an exhausted
/// create reconciliation) must not get stuck forever just because the
/// user lookup itself is refused; confirm absence through the app
/// password before giving up, the same way a failed delete already does.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn revocation_confirms_absence_via_credential_when_the_user_lookup_is_refused() {
    let mock = mock_authentik().await;
    let service = service_or_skip!(&mock);

    // The account genuinely never existed, so no `provider_user_id` was
    // ever recorded.
    mock.script(|script| {
        script.create_account = Behavior::Timeout;
        script.user_exists = false;
    });
    create(&service, "Never created", "/apps/api", &operator("/"))
        .await
        .expect_err("an unresolved create must not return a URL");
    let connection_id = rows(&service)
        .await
        .into_iter()
        .next()
        .expect("the cleanup_required row must be retained")
        .connection_id;

    // The user lookup itself is refused, as Authentik does for an
    // account the manager can no longer see.
    mock.script(|script| script.find_user = Behavior::Status(StatusCode::FORBIDDEN));
    service
        .revoke_managed_connection(request(
            RevokeManagedConnectionRequest { connection_id },
            &operator("/"),
        ))
        .await
        .expect("a refused lookup with no surviving credential must confirm revocation");

    assert!(rows(&service).await.is_empty());
}
