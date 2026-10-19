//! `AuthentikProvider` passes the identity-provider conformance suite against
//! a stateful mock of the Authentik REST API it calls.
//!
//! The mock keeps users, app-password tokens and groups the way Authentik
//! does — exact-match filters, tokens cascading with their user — so the
//! suite observes the implementation's behaviour, not the mock's. Each
//! scripted failure is produced as Authentik would produce it (a status code,
//! a redirect, a garbled body, a commit whose response is a 500), so the
//! classification under test is the implementation's own.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, patch, post},
};
use serde_json::{Value, json};
use sovereign_config_authentik::{AuthentikConfig, AuthentikProvider};
use sovereign_config_core::Secret;
use sovereign_config_identity::{
    ManagedIdentityProvider, ProviderError,
    conformance::{ConformanceTarget, Operation, run_conformance},
};
use tokio::{net::TcpListener, task::JoinHandle};

const GROUP_NAME: &str = "sovereign-config-conformance";
const GROUP_PK: &str = "22222222-2222-2222-2222-222222222222";

struct User {
    username: String,
}

#[derive(Default)]
struct Backend {
    users: BTreeMap<i64, User>,
    /// Token identifier → owning user.
    tokens: BTreeMap<String, i64>,
    next_pk: i64,
    faults: HashMap<Operation, VecDeque<ProviderError>>,
}

type Shared = Arc<Mutex<Backend>>;

/// What the scripted failure does to the request: whether the change lands,
/// and the response Authentik would then give.
enum Outcome {
    Proceed,
    Respond(Response),
    ApplyThen(Response),
}

fn take_fault(state: &Shared, operation: Operation, decoded: bool) -> Outcome {
    let Some(error) = state
        .lock()
        .unwrap()
        .faults
        .get_mut(&operation)
        .and_then(VecDeque::pop_front)
    else {
        return Outcome::Proceed;
    };
    let body = "authentik-response-sentinel";
    match error {
        ProviderError::NotFound => Outcome::Respond((StatusCode::NOT_FOUND, body).into_response()),
        ProviderError::Rejected => Outcome::Respond((StatusCode::FORBIDDEN, body).into_response()),
        ProviderError::Ambiguous => {
            Outcome::ApplyThen((StatusCode::INTERNAL_SERVER_ERROR, body).into_response())
        }
        // A call whose body is decoded gets a garbled one; any other gets a
        // redirect, which the client refuses to follow.
        ProviderError::Invalid if decoded => {
            Outcome::ApplyThen((StatusCode::OK, "{\"results\": [").into_response())
        }
        ProviderError::Invalid => Outcome::Respond(
            (
                StatusCode::FOUND,
                [(header::LOCATION, "https://elsewhere.example.test/")],
            )
                .into_response(),
        ),
        ProviderError::Unavailable => unreachable!("the target never arranges this"),
    }
}

/// Runs `apply` as the outcome says, returning its response unless the
/// fault replaces it.
fn respond(outcome: Outcome, apply: impl FnOnce() -> Response) -> Response {
    match outcome {
        Outcome::Proceed => apply(),
        Outcome::Respond(response) => response,
        Outcome::ApplyThen(response) => {
            let _ = apply();
            response
        }
    }
}

#[allow(clippy::unused_async, clippy::needless_pass_by_value)]
async fn create_account(State(state): State<Shared>, Json(body): Json<Value>) -> Response {
    let outcome = take_fault(&state, Operation::CreateAccount, true);
    respond(outcome, || {
        let username = body["name"].as_str().unwrap_or_default().to_owned();
        let mut backend = state.lock().unwrap();
        if backend.users.values().any(|user| user.username == username) {
            return (StatusCode::BAD_REQUEST, "duplicate").into_response();
        }
        backend.next_pk += 1;
        let pk = backend.next_pk;
        backend.users.insert(
            pk,
            User {
                username: username.clone(),
            },
        );
        backend.tokens.insert(format!("token-{pk}"), pk);
        Json(json!({
            "username": username,
            "user_uid": format!("uid-{pk}"),
            "user_pk": pk,
            "token": format!("app-password-{pk}"),
        }))
        .into_response()
    })
}

/// One PATCH route serves the grant, the rename and the group assignment;
/// the body tells them apart, as Authentik's partial update does.
#[allow(clippy::unused_async, clippy::needless_pass_by_value)]
async fn patch_user(
    State(state): State<Shared>,
    Path(pk): Path<i64>,
    Json(body): Json<Value>,
) -> Response {
    let operation = if body.get("attributes").is_some() {
        Operation::Grant
    } else if body.get("groups").is_some() {
        // The assignment's faults are scripted on its group lookup.
        return existing(&state, pk, || Json(json!({})).into_response());
    } else {
        Operation::RenameAccount
    };
    let outcome = take_fault(&state, operation, false);
    respond(outcome, || {
        existing(&state, pk, || Json(json!({})).into_response())
    })
}

fn existing(state: &Shared, pk: i64, found: impl FnOnce() -> Response) -> Response {
    if state.lock().unwrap().users.contains_key(&pk) {
        found()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

#[allow(clippy::unused_async, clippy::needless_pass_by_value)]
async fn delete_user(State(state): State<Shared>, Path(pk): Path<i64>) -> Response {
    let outcome = take_fault(&state, Operation::DeleteAccount, false);
    respond(outcome, || {
        let mut backend = state.lock().unwrap();
        if backend.users.remove(&pk).is_none() {
            return StatusCode::NOT_FOUND.into_response();
        }
        // Authentik deletes a user's tokens with it.
        backend.tokens.retain(|_, owner| *owner != pk);
        StatusCode::NO_CONTENT.into_response()
    })
}

#[allow(clippy::unused_async, clippy::needless_pass_by_value)]
async fn list_users(
    State(state): State<Shared>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let outcome = take_fault(&state, Operation::FindAccount, true);
    respond(outcome, || {
        let username = query.get("username").cloned().unwrap_or_default();
        let backend = state.lock().unwrap();
        let results: Vec<Value> = backend
            .users
            .iter()
            .filter(|(_, user)| user.username == username)
            .map(|(pk, user)| json!({ "pk": pk, "username": user.username }))
            .collect();
        Json(json!({ "results": results })).into_response()
    })
}

#[allow(clippy::unused_async, clippy::needless_pass_by_value)]
async fn list_tokens(
    State(state): State<Shared>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let outcome = take_fault(&state, Operation::FindCredentials, true);
    respond(outcome, || {
        let backend = state.lock().unwrap();
        let username = query.get("user__username");
        let results: Vec<Value> = backend
            .tokens
            .iter()
            .filter(|(_, owner)| {
                query.get("intent").map(String::as_str) == Some("app_password")
                    && backend.users.get(owner).map(|user| &user.username) == username
            })
            .map(|(identifier, _)| json!({ "identifier": identifier }))
            .collect();
        Json(json!({ "results": results })).into_response()
    })
}

#[allow(clippy::unused_async, clippy::needless_pass_by_value)]
async fn list_groups(
    State(state): State<Shared>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let outcome = take_fault(&state, Operation::AssignBrowseGroup, true);
    respond(outcome, || {
        let results = if query.get("name").map(String::as_str) == Some(GROUP_NAME) {
            json!([{ "pk": GROUP_PK, "name": GROUP_NAME }])
        } else {
            json!([])
        };
        Json(json!({ "results": results })).into_response()
    })
}

#[allow(clippy::unused_async, clippy::needless_pass_by_value)]
async fn set_key(State(state): State<Shared>, Path(identifier): Path<String>) -> Response {
    let outcome = take_fault(&state, Operation::ReplaceCredential, false);
    respond(outcome, || {
        if state.lock().unwrap().tokens.contains_key(&identifier) {
            Json(json!({})).into_response()
        } else {
            StatusCode::NOT_FOUND.into_response()
        }
    })
}

struct Target {
    provider: AuthentikProvider,
    state: Shared,
    task: JoinHandle<()>,
}

impl Drop for Target {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn target() -> Target {
    let state: Shared = Arc::default();
    let app = Router::new()
        .route("/api/v3/core/users/service_account/", post(create_account))
        .route(
            "/api/v3/core/users/{pk}/",
            patch(patch_user).delete(delete_user),
        )
        .route("/api/v3/core/users/", get(list_users))
        .route("/api/v3/core/tokens/", get(list_tokens))
        .route("/api/v3/core/tokens/{identifier}/set_key/", post(set_key))
        .route("/api/v3/core/groups/", get(list_groups))
        .with_state(Arc::clone(&state));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let issuer = format!("http://{address}/application/o/sovereign-config/")
        .parse()
        .unwrap();
    let config = AuthentikConfig::new(
        &issuer,
        Secret::new("conformance-api-token"),
        "sovereign_config_conformance_grants",
        GROUP_NAME,
        Duration::from_secs(2),
    )
    .unwrap();
    Target {
        provider: AuthentikProvider::new(config).unwrap(),
        state,
        task,
    }
}

#[async_trait]
impl ConformanceTarget for Target {
    fn provider(&self) -> &dyn ManagedIdentityProvider {
        &self.provider
    }

    /// A refused connection is the one class the mock cannot produce per
    /// operation; the client's own tests cover it.
    async fn fail_next(&self, operation: Operation, error: ProviderError) -> bool {
        if error == ProviderError::Unavailable {
            return false;
        }
        self.state
            .lock()
            .unwrap()
            .faults
            .entry(operation)
            .or_default()
            .push_back(error);
        true
    }
}

#[tokio::test]
async fn authentik_conforms_to_the_identity_provider_contract() {
    let report = run_conformance(target).await;
    let expected_skips: Vec<_> = Operation::ALL
        .into_iter()
        .map(|operation| (operation, ProviderError::Unavailable))
        .collect();
    assert_eq!(report.skipped, expected_skips);
    assert_eq!(
        report.produced.len(),
        Operation::ALL.len() * (ProviderError::ALL.len() - 1)
    );
}
