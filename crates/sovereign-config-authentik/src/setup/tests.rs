use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    routing::{get, post},
};
use reqwest::Url;
use serde_json::{Value, json};
use sovereign_config_core::Secret;
use tokio::{net::TcpListener, task::JoinHandle};

use super::{Blueprint, Setup, Verdict, at_least, render, validated_public_origin};
use crate::client::AuthentikAdminClient;

/// The `error.type` the step's root span will record for `error`.
fn classified(error: &anyhow::Error) -> Option<&'static str> {
    sovereign_config_telemetry::error::classification(error.as_ref())
}

const ADMIN_TOKEN: &str = "admin-token-sentinel";
const MANAGER_TOKEN: &str = "managertokensentinel";

fn variables(blueprint: &str, issuer: &str) -> BTreeMap<&'static str, String> {
    BTreeMap::from([
        ("SOVEREIGN_CONFIG_AUTHENTIK_BLUEPRINT", blueprint.to_owned()),
        (
            "SOVEREIGN_CONFIG_AUTHENTIK_ADMIN_TOKEN",
            ADMIN_TOKEN.to_owned(),
        ),
        ("SOVEREIGN_CONFIG_OIDC_ISSUER", issuer.to_owned()),
        (
            "SOVEREIGN_CONFIG_PUBLIC_ORIGIN",
            "https://config.example.test".to_owned(),
        ),
        (
            "SOVEREIGN_CONFIG_MANAGER_API_TOKEN",
            MANAGER_TOKEN.to_owned(),
        ),
    ])
}

const PRODUCTION_ISSUER: &str = "https://auth.example.test/application/o/sovereign-config/";
const DEVELOPMENT_ISSUER: &str = "https://auth.example.test/application/o/sovereign-config-dev/";

fn message(result: anyhow::Result<Option<Setup>>) -> String {
    match result {
        Ok(_) => panic!("the variables must be refused"),
        Err(error) => format!("{error:#}"),
    }
}

/// Selecting no blueprint is how an operator who configures Authentik
/// themselves runs `migrate`: the step needs none of its variables then.
#[test]
fn no_blueprint_selected_is_no_step() {
    for unset in [None, Some(""), Some("  ")] {
        let mut variables = BTreeMap::new();
        if let Some(value) = unset {
            variables.insert("SOVEREIGN_CONFIG_AUTHENTIK_BLUEPRINT", value.to_owned());
        }
        assert!(
            Setup::from_variables(&variables).unwrap().is_none(),
            "{unset:?}"
        );
    }
}

#[test]
fn an_unknown_blueprint_is_refused_by_listing_the_ones_there_are() {
    let message = message(Setup::from_variables(&variables(
        "staging-sentinel",
        PRODUCTION_ISSUER,
    )));
    assert_eq!(
        message,
        "SOVEREIGN_CONFIG_AUTHENTIK_BLUEPRINT names no blueprint; it is one of: production, development"
    );
}

/// The issuer names the application, and it must be the one the selected
/// blueprint creates: applying production's blueprint from development's
/// deployment would rewrite production's application.
#[test]
fn a_blueprint_for_another_application_is_refused() {
    for (blueprint, issuer) in [
        ("production", DEVELOPMENT_ISSUER),
        ("development", PRODUCTION_ISSUER),
    ] {
        let message = message(Setup::from_variables(&variables(blueprint, issuer)));
        assert_eq!(
            message,
            format!(
                "SOVEREIGN_CONFIG_OIDC_ISSUER does not name the application the {blueprint} \
                 blueprint creates"
            )
        );
    }
}

#[test]
fn a_selected_blueprint_needs_each_of_its_variables_and_quotes_none() {
    for (missing, named) in [
        (
            "SOVEREIGN_CONFIG_AUTHENTIK_ADMIN_TOKEN",
            "SOVEREIGN_CONFIG_AUTHENTIK_ADMIN_TOKEN_FILE",
        ),
        (
            "SOVEREIGN_CONFIG_MANAGER_API_TOKEN",
            "SOVEREIGN_CONFIG_MANAGER_API_TOKEN_FILE",
        ),
        (
            "SOVEREIGN_CONFIG_PUBLIC_ORIGIN",
            "SOVEREIGN_CONFIG_PUBLIC_ORIGIN",
        ),
        (
            "SOVEREIGN_CONFIG_OIDC_ISSUER",
            "SOVEREIGN_CONFIG_OIDC_ISSUER",
        ),
    ] {
        let mut variables = variables("production", PRODUCTION_ISSUER);
        variables.remove(missing);
        let message = message(Setup::from_variables(&variables));
        assert!(message.contains(named), "{missing}: {message}");
        assert!(!message.contains("sentinel"), "{missing}: {message}");
    }
}

#[test]
fn the_public_origin_is_canonical_as_the_server_requires() {
    assert_eq!(
        validated_public_origin("https://config.example.test/").unwrap(),
        "https://config.example.test"
    );
    for refused in [
        "http://config.example.test",
        "https://config.example.test/path",
        "https://config.example.test?q=1",
        "https://user@config.example.test",
        "https://CONFIG.example.test",
        "not a url",
    ] {
        let message = format!("{:#}", validated_public_origin(refused).unwrap_err());
        assert_eq!(
            message, "SOVEREIGN_CONFIG_PUBLIC_ORIGIN is not a permitted canonical origin",
            "{refused}"
        );
    }
}

/// Each environment's blueprint is filled from the deployment's own
/// settings — the same values the CI steps this replaces passed — with no
/// placeholder left over.
#[test]
fn each_blueprint_is_rendered_from_the_deployments_settings() {
    for (blueprint, issuer) in [
        ("production", PRODUCTION_ISSUER),
        ("development", DEVELOPMENT_ISSUER),
    ] {
        let setup = Setup::from_variables(&variables(blueprint, issuer))
            .unwrap()
            .expect("a blueprint is selected");
        let rendered = setup.rendered.expose();
        assert!(!rendered.contains("${"), "{blueprint}");
        assert!(
            rendered.contains("- url: https://config.example.test/auth/callback\n"),
            "{blueprint}"
        );
        assert!(
            rendered.contains(&format!("key: {MANAGER_TOKEN}\n")),
            "{blueprint}"
        );
        assert!(
            rendered.contains("domain: auth.example.test\n"),
            "{blueprint}"
        );
    }
}

#[test]
fn the_instance_names_are_the_ones_ci_applied_under() {
    // Another name would make Authentik keep a second instance claiming the
    // same objects.
    assert_eq!(Blueprint::Production.instance_name(), "sovereign-config");
    assert_eq!(
        Blueprint::Development.instance_name(),
        "sovereign-config-dev"
    );
}

#[test]
fn rendering_fails_on_a_missing_or_unfilled_placeholder() {
    assert_eq!(
        render("a: ${ONE}\nb: ${TWO}\n", &[("ONE", "1"), ("TWO", "2")]).unwrap(),
        "a: 1\nb: 2\n"
    );
    assert_eq!(
        format!("{:#}", render("a: ${ONE}\n", &[("TWO", "2")]).unwrap_err()),
        "the blueprint has no ${TWO} placeholder"
    );
    assert_eq!(
        format!(
            "{:#}",
            render("a: ${ONE}\nb: ${OTHER}\n", &[("ONE", "1")]).unwrap_err()
        ),
        "the blueprint's ${OTHER} placeholder has no value"
    );
}

#[test]
fn the_minimum_version_compares_by_number() {
    let minimum = (2026, 5, 2);
    for (version, accepted) in [
        ("2026.5.2", true),
        ("2026.5.10", true),
        ("2026.6.0", true),
        ("2027.1.0", true),
        ("2026.5.2-rc1", true),
        ("2026.5.1", false),
        ("2026.4.9", false),
        ("2025.12.5", false),
        ("2026.5", false),
        ("", false),
        ("unknown", false),
    ] {
        assert_eq!(at_least(version, minimum), accepted, "{version}");
    }
}

#[test]
fn a_status_is_applied_failed_or_still_pending() {
    assert_eq!(Verdict::of("successful"), Verdict::Applied);
    assert_eq!(Verdict::of("warning"), Verdict::Applied);
    assert_eq!(Verdict::of("error"), Verdict::Failed);
    assert_eq!(Verdict::of("orphaned"), Verdict::Failed);
    assert_eq!(Verdict::of("unknown"), Verdict::Pending);
    assert_eq!(Verdict::of("something-new"), Verdict::Pending);
}

// ---------------------------------------------------------------------------
// Against a fake Authentik
// ---------------------------------------------------------------------------

const INSTANCE_PK: &str = "0f9a2c4e-1b3d-4e5f-8a6b-7c8d9e0f1a2b";

#[derive(Default)]
struct Authentik {
    version: String,
    schema: String,
    /// `(pk, name, content)` of every instance.
    instances: Vec<(String, String, String)>,
    /// The status an apply leaves behind.
    applies_to: String,
    status: String,
    last_applied: Option<String>,
    /// How many status reads an apply takes to land: Authentik may apply in
    /// the background, after answering the request to.
    apply_after_reads: usize,
    /// Reads left before an apply asked for lands.
    landing_in: Option<usize>,
    applies: usize,
    /// `METHOD path` of every call, with whether it carried the admin token.
    calls: Vec<(String, bool)>,
}

type Shared = Arc<Mutex<Authentik>>;

fn record(state: &Shared, call: String, headers: &HeaderMap) {
    let authorised = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        == Some(&format!("Bearer {ADMIN_TOKEN}"));
    state.lock().unwrap().calls.push((call, authorised));
}

async fn version(State(state): State<Shared>, headers: HeaderMap) -> Json<Value> {
    record(&state, "GET version".to_owned(), &headers);
    Json(json!({ "version_current": state.lock().unwrap().version }))
}

async fn schema(State(state): State<Shared>, headers: HeaderMap) -> String {
    record(&state, "GET schema".to_owned(), &headers);
    state.lock().unwrap().schema.clone()
}

async fn list(
    State(state): State<Shared>,
    Query(query): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
) -> Json<Value> {
    record(&state, "GET instances".to_owned(), &headers);
    let name = query.get("name").cloned().unwrap_or_default();
    let results: Vec<Value> = state
        .lock()
        .unwrap()
        .instances
        .iter()
        .filter(|(_, instance, _)| *instance == name)
        .map(|(pk, name, _)| json!({ "pk": pk, "name": name, "status": "successful" }))
        .collect();
    Json(json!({ "pagination": {}, "results": results }))
}

async fn create(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    record(&state, "POST instances".to_owned(), &headers);
    let mut authentik = state.lock().unwrap();
    authentik.instances.push((
        INSTANCE_PK.to_owned(),
        body["name"].as_str().unwrap().to_owned(),
        body["content"].as_str().unwrap().to_owned(),
    ));
    (StatusCode::CREATED, Json(json!({ "pk": INSTANCE_PK })))
}

async fn update(
    State(state): State<Shared>,
    Path(pk): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    record(&state, format!("PATCH {pk}"), &headers);
    let mut authentik = state.lock().unwrap();
    let instance = authentik
        .instances
        .iter_mut()
        .find(|(instance, _, _)| *instance == pk)
        .expect("the instance exists");
    instance.2 = body["content"].as_str().unwrap().to_owned();
    Json(json!({ "pk": pk }))
}

async fn status(
    State(state): State<Shared>,
    Path(pk): Path<String>,
    headers: HeaderMap,
) -> Json<Value> {
    record(&state, format!("GET {pk}"), &headers);
    let mut authentik = state.lock().unwrap();
    match authentik.landing_in {
        Some(0) => {
            authentik.landing_in = None;
            land(&mut authentik);
        }
        Some(left) => authentik.landing_in = Some(left - 1),
        None => {}
    }
    Json(json!({
        "pk": pk,
        "status": authentik.status,
        "last_applied": authentik.last_applied,
    }))
}

/// Authentik's own bookkeeping: a successful apply moves `last_applied`, a
/// failed one does not.
fn land(authentik: &mut Authentik) {
    authentik.status = authentik.applies_to.clone();
    if matches!(authentik.status.as_str(), "successful" | "warning") {
        authentik.applies += 1;
        authentik.last_applied = Some(format!("2026-11-21T00:00:{:02}Z", authentik.applies));
    }
}

async fn apply(
    State(state): State<Shared>,
    Path(pk): Path<String>,
    headers: HeaderMap,
) -> Json<Value> {
    record(&state, format!("POST {pk} apply"), &headers);
    let mut authentik = state.lock().unwrap();
    if authentik.apply_after_reads == 0 {
        land(&mut authentik);
    } else {
        authentik.landing_in = Some(authentik.apply_after_reads);
    }
    Json(json!({}))
}

struct Fake {
    state: Shared,
    origin: Url,
    task: JoinHandle<()>,
}

impl Drop for Fake {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn fake(reported: &str, applies_to: &str) -> Fake {
    let state = Arc::new(Mutex::new(Authentik {
        version: reported.to_owned(),
        schema: "paths: /core/users/service_account/ /core/tokens/{identifier}/set_key/ \
                 initial_permissions grant_types"
            .to_owned(),
        applies_to: applies_to.to_owned(),
        status: "unknown".to_owned(),
        ..Authentik::default()
    }));
    let router = Router::new()
        .route("/api/v3/admin/version/", get(version))
        .route("/api/v3/schema/", get(schema))
        .route("/api/v3/managed/blueprints/", get(list).post(create))
        .route(
            "/api/v3/managed/blueprints/{pk}/",
            get(status).patch(update),
        )
        .route("/api/v3/managed/blueprints/{pk}/apply/", post(apply))
        .with_state(Arc::clone(&state));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    Fake {
        state,
        origin,
        task,
    }
}

fn setup_against(fake: &Fake, content: &str) -> Setup {
    Setup {
        client: AuthentikAdminClient::new(
            fake.origin.clone(),
            Secret::new(ADMIN_TOKEN),
            Duration::from_secs(5),
        )
        .unwrap(),
        blueprint: Blueprint::Development,
        rendered: Secret::new(content),
    }
}

fn calls(fake: &Fake) -> Vec<String> {
    let authentik = fake.state.lock().unwrap();
    assert!(
        authentik.calls.iter().all(|(_, authorised)| *authorised),
        "every call carries the admin token"
    );
    authentik
        .calls
        .iter()
        .map(|(call, _)| call.clone())
        .collect()
}

/// The first run creates the instance; the second finds it and replaces its
/// content, so there is still one instance holding the latest blueprint.
#[tokio::test]
async fn the_blueprint_is_created_once_then_updated_in_place() {
    let fake = fake("2026.5.2", "successful").await;

    setup_against(&fake, "first").apply().await.unwrap();
    setup_against(&fake, "second").apply().await.unwrap();

    assert_eq!(
        calls(&fake),
        [
            "GET version",
            "GET schema",
            "GET instances",
            "POST instances",
            &format!("GET {INSTANCE_PK}"),
            &format!("POST {INSTANCE_PK} apply"),
            &format!("GET {INSTANCE_PK}"),
            "GET version",
            "GET schema",
            "GET instances",
            &format!("PATCH {INSTANCE_PK}"),
            &format!("GET {INSTANCE_PK}"),
            &format!("POST {INSTANCE_PK} apply"),
            &format!("GET {INSTANCE_PK}"),
        ]
    );
    let authentik = fake.state.lock().unwrap();
    assert_eq!(
        authentik.instances,
        [(
            INSTANCE_PK.to_owned(),
            "sovereign-config-dev".to_owned(),
            "second".to_owned()
        )]
    );
}

/// Too old, or missing a surface: nothing is applied, and the message says
/// so.
#[tokio::test]
async fn an_incompatible_authentik_has_nothing_applied() {
    let old = fake("2026.5.1", "successful").await;
    let error = setup_against(&old, "x").apply().await.unwrap_err();
    assert_eq!(classified(&error), Some("authentik_too_old"));
    let message = format!("{error:#}");
    assert_eq!(
        message,
        "Authentik 2026.5.1 is older than 2026.5.2, the oldest this release supports; \
         nothing was applied"
    );
    assert_eq!(calls(&old), ["GET version"]);

    let incomplete = fake("2026.6.0", "successful").await;
    incomplete.state.lock().unwrap().schema = "grant_types".to_owned();
    let error = setup_against(&incomplete, "x").apply().await.unwrap_err();
    assert_eq!(classified(&error), Some("authentik_incompatible"));
    let message = format!("{error:#}");
    assert_eq!(
        message,
        "Authentik 2026.6.0 does not expose /core/users/service_account/, which managed \
         connections need; nothing was applied"
    );
    assert_eq!(calls(&incomplete), ["GET version", "GET schema"]);
}

/// Authentik's own text reaches a message only when it looks like a version.
#[tokio::test]
async fn an_odd_version_is_not_quoted() {
    let odd = fake("<script>token-sentinel</script>", "successful").await;
    let message = format!("{:#}", setup_against(&odd, "x").apply().await.unwrap_err());
    assert_eq!(
        message,
        "Authentik (an unreadable version) is older than 2026.5.2, the oldest this release \
         supports; nothing was applied"
    );
}

#[tokio::test]
async fn a_failed_apply_fails_the_step() {
    let fake = fake("2026.5.2", "error").await;
    let error = setup_against(&fake, "x").apply().await.unwrap_err();
    assert_eq!(classified(&error), Some("blueprint_failed"));
    let message = format!("{error:#}");
    assert_eq!(
        message,
        "Authentik reports the sovereign-config-dev blueprint error; its worker's log says why"
    );
}

/// Two instances under one name leave it unclear which owns the objects, so
/// neither is touched.
#[tokio::test]
async fn two_instances_under_one_name_are_left_alone() {
    let fake = fake("2026.5.2", "successful").await;
    {
        let mut authentik = fake.state.lock().unwrap();
        for pk in [INSTANCE_PK, "1f9a2c4e-1b3d-4e5f-8a6b-7c8d9e0f1a2b"] {
            authentik.instances.push((
                pk.to_owned(),
                "sovereign-config-dev".to_owned(),
                "old".to_owned(),
            ));
        }
    }
    let error = setup_against(&fake, "x").apply().await.unwrap_err();
    assert_eq!(classified(&error), Some("invalid"));
    assert_eq!(
        format!("{error:#}"),
        "unable to look up the blueprint instance (invalid)"
    );
    assert_eq!(calls(&fake), ["GET version", "GET schema", "GET instances"]);
}

/// An instance applied before, successfully, whose new apply Authentik runs
/// in the background: the old `successful` is not this apply's.
async fn previously_applied(applies_to: &str) -> Fake {
    let fake = fake("2026.5.2", applies_to).await;
    {
        let mut authentik = fake.state.lock().unwrap();
        authentik.instances.push((
            INSTANCE_PK.to_owned(),
            "sovereign-config-dev".to_owned(),
            "old".to_owned(),
        ));
        authentik.status = "successful".to_owned();
        authentik.last_applied = Some("2026-11-20T00:00:00Z".to_owned());
        authentik.apply_after_reads = 3;
    }
    fake
}

#[tokio::test]
async fn a_stale_success_is_not_taken_for_this_apply() {
    let fake = previously_applied("error").await;
    let error = setup_against(&fake, "new").apply().await.unwrap_err();
    assert_eq!(classified(&error), Some("blueprint_failed"));
}

#[tokio::test]
async fn an_apply_run_in_the_background_is_waited_for() {
    let fake = previously_applied("successful").await;
    setup_against(&fake, "new").apply().await.unwrap();
    let reads_after_apply = calls(&fake)
        .iter()
        .skip_while(|call| !call.ends_with(" apply"))
        .filter(|call| call.starts_with("GET "))
        .count();
    assert!(
        reads_after_apply > 1,
        "the verdict waited for the apply to land: {reads_after_apply}"
    );
    assert_eq!(fake.state.lock().unwrap().applies, 1);
}

#[test]
fn a_verdict_needs_this_apply_to_have_landed() {
    let state = |status: &str, last_applied: Option<&str>| super::BlueprintState {
        status: status.to_owned(),
        last_applied: last_applied.map(str::to_owned),
    };
    let before = state("successful", Some("t1"));
    assert_eq!(Verdict::after(&before, &before), Verdict::Pending);
    assert_eq!(
        Verdict::after(&before, &state("successful", Some("t2"))),
        Verdict::Applied
    );
    assert_eq!(
        Verdict::after(&before, &state("error", Some("t1"))),
        Verdict::Failed
    );
    // The same failure as before cannot be told from an apply not yet run.
    let failed = state("error", Some("t1"));
    assert_eq!(Verdict::after(&failed, &failed), Verdict::Pending);
    assert_eq!(
        Verdict::after(&failed, &state("successful", Some("t2"))),
        Verdict::Applied
    );
    // A first apply of a new instance.
    assert_eq!(
        Verdict::after(&state("unknown", None), &state("warning", Some("t1"))),
        Verdict::Applied
    );
}
