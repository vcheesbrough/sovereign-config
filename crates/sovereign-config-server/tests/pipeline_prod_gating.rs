//! Guards the deployment-trigger policy encoded in the `.woodpecker/` workflows:
//! a push (or manual run) only anchors a pipeline to deploy from, and never
//! builds or deploys — GitHub Actions builds (card #539); each environment
//! deploys only on a `deployment` event (Woodpecker's Deploy) targeting it —
//! production from main only (card #262), development from any branch (card
//! #466) — and ships only what the release-versions plugin resolves. The
//! pipeline files are not otherwise exercised by any test.

mod support;

use std::collections::BTreeSet;

use serde_yaml::Value;
use support::{Pipeline, pipeline};

/// The events the anchor runs on. A manual run from the Woodpecker UI does
/// exactly what a push does.
fn push_events() -> BTreeSet<String> {
    BTreeSet::from(["push".to_owned(), "manual".to_owned()])
}

/// The only branch permitted to trigger a production promotion.
const PROD_BRANCHES: &[&str] = &["main"];

const PROD_TARGET: &str = "CI_PIPELINE_DEPLOY_TARGET == \"prod\"";
const DEV_TARGET: &str = "CI_PIPELINE_DEPLOY_TARGET == \"dev\"";

fn deployment_event() -> BTreeSet<String> {
    BTreeSet::from(["deployment".to_owned()])
}

fn step<'a>(pipeline: &'a Pipeline, name: &str) -> &'a Value {
    pipeline.step(name)
}

/// All of a step's `commands` joined into one string for substring assertions.
fn commands_text(step: &Value) -> String {
    step.get("commands")
        .and_then(Value::as_sequence)
        .expect("step should have commands")
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("\n")
}

/// A single `when` condition. `event` and `branch` are each normalised to a set
/// (either may be a YAML scalar or sequence; `branch` may be absent, meaning
/// "any branch"). `evaluate` is the optional CEL guard expression.
struct Condition {
    events: BTreeSet<String>,
    branches: BTreeSet<String>,
    evaluate: Option<String>,
}

fn strings(value: &Value) -> BTreeSet<String> {
    match value {
        Value::String(single) => BTreeSet::from([single.clone()]),
        Value::Sequence(many) => many
            .iter()
            .map(|value| value.as_str().expect("value must be a string").to_owned())
            .collect(),
        other => panic!("unexpected scalar-or-sequence shape: {other:?}"),
    }
}

/// The `when` conditions of a step or of a whole workflow file.
fn when_conditions(step: &Value) -> Vec<Condition> {
    let conditions = step
        .get("when")
        .and_then(Value::as_sequence)
        .unwrap_or_else(|| panic!("step or workflow should carry a `when` list"));
    conditions
        .iter()
        .map(|condition| Condition {
            events: strings(condition.get("event").expect("`when` needs an event")),
            branches: condition.get("branch").map(strings).unwrap_or_default(),
            evaluate: condition
                .get("evaluate")
                .and_then(Value::as_str)
                .map(str::to_owned),
        })
        .collect()
}

/// The release-versions plugin, pinned by digest, which alone chooses what a
/// deployment ships and records it.
const RELEASE_VERSIONS: &str =
    "ghcr.io/vcheesbrough/woodpecker-plugin-release-versions:0.2.0@sha256:";

/// The three images of one release, as GHCR publishes them.
const RELEASE_IMAGES: [&str; 3] = [
    "ghcr.io/vcheesbrough/sovereign-config",
    "ghcr.io/vcheesbrough/sovereign-config-woodpecker-broker",
    "ghcr.io/vcheesbrough/sovereign-config-cli",
];

fn depends_on(step: &Value) -> Vec<&str> {
    step.get("depends_on")
        .and_then(Value::as_sequence)
        .expect("step should list its dependencies")
        .iter()
        .filter_map(Value::as_str)
        .collect()
}

fn setting<'a>(step: &'a Value, name: &str) -> Option<&'a Value> {
    step.get("settings").and_then(|settings| settings.get(name))
}

/// Every step of the prod deploy runs only on a deployment targeting prod,
/// from main.
#[test]
fn production_steps_deploy_to_prod_from_permitted_branches() {
    let permitted: BTreeSet<String> = PROD_BRANCHES.iter().map(|&b| b.to_owned()).collect();
    let pipeline = pipeline();
    let mut checked = 0;
    for (workflow, name, step) in pipeline.steps() {
        if workflow != "deploy-prod" {
            continue;
        }
        let conditions = when_conditions(step);
        assert!(
            conditions.iter().all(|c| c.events == deployment_event()),
            "{name} must only ever run on a deployment event, never on push"
        );
        // Restrict to the prod deploy target so a deployment with any other
        // (or mistyped) target from main cannot run the prod chain.
        assert!(
            conditions
                .iter()
                .all(|c| c.evaluate.as_deref() == Some(PROD_TARGET)),
            "{name} must be guarded by the prod deploy-target evaluate expression"
        );
        let branches: BTreeSet<String> = conditions
            .iter()
            .flat_map(|c| c.branches.iter().cloned())
            .collect();
        assert_eq!(
            branches, permitted,
            "{name} must be branch-restricted to exactly the permitted branches"
        );
        checked += 1;
    }
    assert_eq!(checked, 4, "a deploy-prod step was added or removed");
}

/// Every step of the dev deploy runs only on a deployment targeting dev, from
/// any branch, so a push never deploys and a prod promotion never touches dev.
#[test]
fn development_steps_deploy_to_dev_only_on_a_dev_deployment() {
    let pipeline = pipeline();
    let mut checked = 0;
    for (workflow, name, step) in pipeline.steps() {
        if workflow != "deploy-dev" {
            continue;
        }
        let conditions = when_conditions(step);
        assert!(!conditions.is_empty());
        for condition in conditions {
            assert_eq!(
                condition.events,
                deployment_event(),
                "{name} must only ever run on a deployment event, never on push"
            );
            assert_eq!(
                condition.evaluate.as_deref(),
                Some(DEV_TARGET),
                "{name} must be guarded by the dev deploy-target evaluate expression"
            );
            assert!(
                condition.branches.is_empty(),
                "{name} must deploy dev from any branch"
            );
        }
        checked += 1;
    }
    assert_eq!(checked, 4, "a deploy-dev step was added or removed");
}

/// Besides the code-vitals recorder (`pipeline_code_vitals.rs`), the anchor is
/// all a push runs here, and it only gives the push a pipeline to deploy from: Woodpecker drops a push no workflow matches, and
/// its Deploy action starts from an existing pipeline (card #539). It reads no
/// source, holds no secret, touches no Docker socket and runs no plugin, so it
/// can neither build nor publish nor tag.
#[test]
fn a_push_only_anchors_a_pipeline_to_deploy_from() {
    let pipeline = pipeline();
    assert_eq!(workflow_events(&pipeline, "anchor"), push_events());
    assert_eq!(
        pipeline
            .workflow("anchor")
            .get("skip_clone")
            .and_then(Value::as_bool),
        Some(true),
        "the anchor reads no source"
    );
    let anchor = pipeline.step_in("anchor", "anchor");
    assert!(
        when_conditions(anchor)
            .iter()
            .all(|condition| condition.events == push_events()),
        "the anchor runs on push and manual only"
    );
    for key in ["settings", "environment", "volumes"] {
        assert!(
            anchor.get(key).is_none(),
            "the anchor must not carry `{key}`: it builds, publishes and deploys nothing"
        );
    }
    let image = anchor.get("image").and_then(Value::as_str).expect("image");
    assert!(
        image.contains("@sha256:") && !image.starts_with(RELEASE_VERSIONS),
        "the anchor runs a digest-pinned image that is not the release plugin"
    );
    for workflow in ["deploy-dev", "deploy-prod"] {
        assert_eq!(workflow_events(&pipeline, workflow), deployment_event());
    }
}

/// A push never deploys: no step that runs on a push runs Compose, names a
/// deployed environment, applies a blueprint, or exercises the live Authentik
/// manager (card #466).
#[test]
fn a_push_never_deploys() {
    let pipeline = pipeline();
    let mut checked = 0;
    for (workflow, name, step) in pipeline.steps() {
        if !workflow_events(&pipeline, workflow).contains("push") {
            continue;
        }
        // The parsed step, so comments describing the pipeline do not count.
        let text = serde_yaml::to_string(step).expect("step serialises");
        // Keyed on what a deploy targets, not on one way of spelling it.
        for forbidden in [
            "compose",
            "authentik-blueprint",
            "live_",
            "sovereign-config-dev",
            "sovereign-config-prod",
        ] {
            assert!(
                !text.contains(forbidden),
                "{name} in {workflow} runs on a push and must not deploy ({forbidden})"
            );
        }
        checked += 1;
    }
    assert!(checked > 0, "no push step was found to check");
}

/// A deployment never builds, publishes or allocates: in both deploy
/// workflows the plugin's `resolve` chooses the build — the commit's release
/// tag, else its newest published build — and proves all three GHCR images
/// carry its labels, before anything is deployed. Nothing else in
/// Woodpecker names a version or runs the plugin's build-side modes.
#[test]
fn a_deployment_resolves_a_published_build_and_never_allocates() {
    let pipeline = pipeline();
    assert_eq!(
        pipeline.workflows_of("resolve"),
        ["deploy-dev", "deploy-prod"]
    );
    let resolve = pipeline.step_in("deploy-prod", "resolve");
    assert!(
        resolve
            .get("image")
            .and_then(Value::as_str)
            .is_some_and(|image| image.starts_with(RELEASE_VERSIONS)),
        "resolve must run the digest-pinned release plugin"
    );
    assert_eq!(
        setting(resolve, "mode").and_then(Value::as_str),
        Some("resolve")
    );
    let images: Vec<&str> = setting(resolve, "images")
        .and_then(Value::as_sequence)
        .expect("resolve lists the release's images")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(
        images, RELEASE_IMAGES,
        "resolve must prove all three images of the release are published"
    );
    assert!(
        depends_on(resolve).is_empty(),
        "resolve starts the deployment"
    );
    // The images are public: a registry credential here would be one more
    // secret the deploy holds for nothing.
    for credential in ["registry_username", "registry_password"] {
        assert!(setting(resolve, credential).is_none());
    }
    // The plugin's default policy is the repo's: dev from any branch, prod from
    // main (its default branch). A local override could widen it.
    assert!(setting(resolve, "environments").is_none());

    for (workflow, name, step) in pipeline.steps() {
        let mode = setting(step, "mode").and_then(Value::as_str);
        assert!(
            !matches!(mode, Some("version" | "publish")),
            "{name} in {workflow}: Woodpecker never claims or publishes a version"
        );
        if step
            .get("image")
            .and_then(Value::as_str)
            .is_some_and(|image| image.starts_with(RELEASE_VERSIONS))
        {
            assert!(
                matches!(mode, Some("resolve" | "tag")),
                "{name} in {workflow} runs the plugin outside resolve and tag"
            );
        }
    }
    for deploy in ["deploy-dev", "deploy-prod"] {
        let step = step(&pipeline, deploy);
        assert!(
            depends_on(step).contains(&"resolve"),
            "{deploy} must ship what resolve chose"
        );
    }
}

/// Each deploy records itself only once it has succeeded: `tag` waits for the
/// deploy step alone, so a smoke check (run after the pipeline, AGENTS.md)
/// never holds a tag back and a failed deploy is never tagged.
#[test]
fn each_deploy_is_tagged_once_it_has_succeeded() {
    let pipeline = pipeline();
    assert_eq!(pipeline.workflows_of("tag"), ["deploy-dev", "deploy-prod"]);
    for (workflow, deploy) in [("deploy-dev", "deploy-dev"), ("deploy-prod", "deploy-prod")] {
        let tag = pipeline.step_in(workflow, "tag");
        assert_eq!(depends_on(tag), [deploy]);
        assert_eq!(setting(tag, "mode").and_then(Value::as_str), Some("tag"));
        assert!(
            tag.get("image")
                .and_then(Value::as_str)
                .is_some_and(|image| image.starts_with(RELEASE_VERSIONS)),
            "{workflow}: tag must run the digest-pinned release plugin"
        );
    }
}

/// Woodpecker takes a GitHub deployment whose ref is a bare commit as a
/// deployment of main, so `branch: main` alone would let one ship a commit
/// main never had. Production refuses any commit main does not contain,
/// before its deploy — and so its `migrate` — runs.
#[test]
fn production_deploys_only_commits_main_contains() {
    let pipeline = pipeline();
    assert_eq!(
        pipeline.workflows_of("verify-commit-on-main"),
        ["deploy-prod"]
    );
    let check = commands_text(pipeline.step_in("deploy-prod", "verify-commit-on-main"));
    assert!(
        check.contains("/compare/$$CI_COMMIT_SHA...main")
            && check.contains(r#"grep -q '"behind_by": *0,'"#)
            && check.contains("exit 1"),
        "verify-commit-on-main must refuse a commit main is behind: {check}"
    );
    assert!(
        !check.contains("$$GITHUB_TOKEN@") && check.contains("--config /tmp/github-curl.conf"),
        "the token travels in a curl config file, never in a URL"
    );
    assert!(
        depends_on(pipeline.step_in("deploy-prod", "deploy-prod"))
            .contains(&"verify-commit-on-main"),
        "the production deploy must wait for the on-main check"
    );
}

/// The deploys pull the release from GHCR, where GitHub Actions published it,
/// anonymously: no deploy step holds a registry credential or names the old
/// registry, and the Compose file names the GHCR image. (The code-vitals
/// recorder's plugin comes from the estate's registry; it deploys
/// nothing of this repository's.)
#[test]
fn deployments_pull_the_release_from_ghcr() {
    let pipeline = pipeline();
    for (workflow, name, step) in pipeline.steps() {
        if !workflow.starts_with("deploy-") {
            continue;
        }
        let text = serde_yaml::to_string(step).expect("step serialises");
        for forbidden in ["registry.desync.link", "zot_ci_", "docker login"] {
            assert!(
                !text.contains(forbidden),
                "{name} in {workflow} must not use the old registry ({forbidden})"
            );
        }
    }
    let compose = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../compose.yaml"),
    )
    .expect("compose.yaml should be readable");
    assert!(
        compose.contains(
            "image: ghcr.io/vcheesbrough/sovereign-config:${SOVEREIGN_CONFIG_IMAGE_TAG:-local}"
        ),
        "compose.yaml must run the GHCR image at the resolved tag"
    );
}

/// Each environment's `migrate` applies its own blueprint (#615): the deploy
/// selects it, and the binary carries both (`sovereign-config-authentik`,
/// `setup`). Nothing applies a blueprint from CI any more.
#[test]
fn each_deploy_selects_its_own_environments_blueprint() {
    let pipeline = pipeline();
    for (deploy, blueprint, other) in [
        ("deploy-dev", "development", "production"),
        ("deploy-prod", "production", "development"),
    ] {
        let command = commands_text(step(&pipeline, deploy));
        assert!(
            command.contains(&format!("SOVEREIGN_CONFIG_AUTHENTIK_BLUEPRINT={blueprint}")),
            "{deploy} must select the {blueprint} blueprint"
        );
        assert!(
            !command.contains(&format!("SOVEREIGN_CONFIG_AUTHENTIK_BLUEPRINT={other}")),
            "{deploy} must not select the {other} blueprint"
        );
    }
    for (workflow, name, step) in pipeline.steps() {
        let image = step
            .get("image")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(
            !image.contains("authentik-blueprint"),
            "{workflow}/{name} applies a blueprint from CI; `migrate` does that"
        );
    }
}

/// A deploy runs `migrate` on its own and waits for it to exit before it
/// replaces the server, so a failed `migrate` leaves the running server in
/// place (#615). Compose alone would not: `up` recreates the server before
/// its `depends_on` condition is met, and `up --wait migrate` reports a
/// one-shot service ready before it has finished.
#[test]
fn each_deploy_runs_migrate_before_it_replaces_the_server() {
    let pipeline = pipeline();
    for (deploy, project) in [
        ("deploy-dev", "sovereign-config-dev"),
        ("deploy-prod", "sovereign-config-prod"),
    ] {
        let command = commands_text(step(&pipeline, deploy));
        let lines: Vec<&str> = command.lines().map(str::trim).collect();
        let position = |needle: &str| {
            lines
                .iter()
                .position(|line| line.contains(needle))
                .unwrap_or_else(|| panic!("{deploy} has no line with {needle}"))
        };
        let migrate = position(&format!(
            "\"$$COMPOSE\" -p {project} up -d --pull always --force-recreate migrate ||"
        ));
        let wait = position("MIGRATE_EXIT=$$(docker wait ");
        let refuse = position("if [ \"$$MIGRATE_EXIT\" != 0 ]; then");
        let server = position(&format!(
            "\"$$COMPOSE\" -p {project} up -d --no-deps --force-recreate --wait --wait-timeout 90 sovereign-config ||"
        ));
        assert!(
            migrate < wait && wait < refuse && refuse < server,
            "{deploy}: migrate, wait for it, refuse on failure, then the server"
        );
        assert_eq!(
            lines
                .iter()
                .filter(|line| line.contains(" up ") && !line.contains("otlp-ingest"))
                .count(),
            2,
            "{deploy}: no other Compose run may start the server"
        );
    }
}

/// Every credential reaches Compose as a variable of the deploy step's own
/// environment, under the name `compose.yaml` reads it by (#617): the stack
/// needs nothing from Woodpecker but those variables. Nothing is written to
/// a file or a volume, and no `*_FILE` path or direct server variable is
/// handed over.
#[test]
fn each_deploy_hands_compose_every_credential_as_a_variable() {
    let pipeline = pipeline();
    for (deploy, environment_name) in [("deploy-dev", "dev"), ("deploy-prod", "prod")] {
        let deploy_step = step(&pipeline, deploy);
        let command = commands_text(deploy_step);
        let environment = deploy_step.get("environment").expect("environment");
        for (variable, secret) in [
            (
                "POSTGRES_PASSWORD",
                format!("sovereign_config_{environment_name}_postgres_password"),
            ),
            (
                "MANAGER_API_TOKEN",
                format!("sovereign_config_{environment_name}_manager_api_token"),
            ),
            (
                "VALUE_ENCRYPTION_KEY",
                format!("sovereign_config_{environment_name}_value_encryption_key"),
            ),
            ("AUTHENTIK_ADMIN_TOKEN", "authentik_api_token".to_owned()),
        ] {
            assert_eq!(
                environment
                    .get(variable)
                    .and_then(|value| value.get("from_secret"))
                    .and_then(Value::as_str),
                Some(secret.as_str()),
                "{deploy} takes {variable} from {secret}"
            );
        }
        assert!(command.contains(
            "export POSTGRES_PASSWORD MANAGER_API_TOKEN VALUE_ENCRYPTION_KEY AUTHENTIK_ADMIN_TOKEN \
             DATABASE_URL=\"postgresql://sovereign_config:$$ENCODED_PASSWORD@postgres:5432/sovereign_config\""
        ));
        let mounts = strings(deploy_step.get("volumes").expect("volumes"));
        assert_eq!(
            mounts,
            BTreeSet::from(["/var/run/docker.sock:/var/run/docker.sock".to_owned()]),
            "{deploy} mounts no secrets volume"
        );
        for leftover in [
            "/run/deploy-secrets",
            "docker volume inspect",
            "_FILE=",
            "SOVEREIGN_CONFIG_DATABASE_URL=",
            "SOVEREIGN_CONFIG_MANAGER_API_TOKEN=",
            "SOVEREIGN_CONFIG_VALUE_ENCRYPTION_KEY=",
            "SOVEREIGN_CONFIG_AUTHENTIK_ADMIN_TOKEN=",
        ] {
            assert!(
                !command.contains(leftover),
                "{deploy} still carries {leftover}"
            );
        }
    }
}

#[test]
fn development_deploy_targets_the_development_environment() {
    let pipeline = pipeline();
    let command = commands_text(step(&pipeline, "deploy-dev"));
    assert!(command.contains("SOVEREIGN_CONFIG_ENV=dev"));
    assert!(command.contains("SOVEREIGN_CONFIG_HOST=sovereign-config-dev.desync.link"));
    assert!(command.contains("\"$$COMPOSE\" -p sovereign-config-dev"));
    // Nothing on the deploy path builds, so it pulls the resolved tag.
    assert!(command.contains("SOVEREIGN_CONFIG_IMAGE_TAG=$$(cat .release-tag)"));
    assert!(command.contains("--pull always"));
    assert!(!command.contains("sovereign-config-prod"));
    assert!(!command.contains("sovereign-config-production"));
}

#[test]
fn production_deploy_targets_the_production_environment() {
    let pipeline = pipeline();
    let command = commands_text(step(&pipeline, "deploy-prod"));
    assert!(command.contains("SOVEREIGN_CONFIG_ENV=prod"));
    assert!(command.contains("SOVEREIGN_CONFIG_HOST=sovereign-config.desync.link"));
    assert!(command.contains("\"$$COMPOSE\" -p sovereign-config-prod"));
    // It deploys the resolved, already-built tag and pulls it rather than
    // relying on a locally built image (there is no build on the deploy path).
    assert!(command.contains("SOVEREIGN_CONFIG_IMAGE_TAG=$$(cat .release-tag)"));
    assert!(command.contains("--pull always"));
    // A production deploy must never touch the development stack.
    assert!(!command.contains("sovereign-config-dev"));
}

/// Nothing gates on the client-telemetry ingest. The health-gated `up
/// --wait` leaves its profile out, and the separate start that follows is
/// allowed to fail: an ingest that cannot start costs the web UI's telemetry
/// and never a deploy (docs/observability.md).
#[test]
fn no_deploy_gates_on_the_client_telemetry_ingest() {
    let pipeline = pipeline();
    for deploy in ["deploy-dev", "deploy-prod"] {
        let command = commands_text(step(&pipeline, deploy));
        let lines: Vec<&str> = command.lines().map(str::trim).collect();
        let gated: Vec<&&str> = lines
            .iter()
            .filter(|line| line.contains("--wait"))
            .collect();
        assert_eq!(gated.len(), 1, "{deploy}: one health-gated Compose run");
        assert!(
            !gated[0].contains("client-telemetry") && !gated[0].contains("otlp-ingest"),
            "{deploy}: the health gate must not include the ingest"
        );
        let ingest: Vec<&&str> = lines
            .iter()
            .filter(|line| line.contains("otlp-ingest"))
            .collect();
        assert_eq!(ingest.len(), 1, "{deploy}: the ingest is started once");
        assert!(
            ingest[0].contains("--profile client-telemetry up -d --no-deps otlp-ingest ||"),
            "{deploy}: the ingest's start must tolerate failure"
        );
        assert!(!ingest[0].contains("--wait"));
        let gate_at = lines
            .iter()
            .position(|line| line.contains("--wait"))
            .unwrap();
        let ingest_at = lines
            .iter()
            .position(|line| line.contains("otlp-ingest"))
            .unwrap();
        assert!(
            ingest_at > gate_at,
            "{deploy}: the ingest starts after the gate"
        );
    }
}

/// The live manager tests run against what the dev deploy's `migrate`
/// applied, so after it (#615), against dev's own browsing group. They are
/// the promote gate for prod too: prod's blueprint differs from dev's only
/// in names, and a commit reaches prod only after its dev deploy.
#[test]
fn the_live_manager_tests_run_after_the_dev_deploy() {
    let pipeline = pipeline();
    let live = step(&pipeline, "validate-authentik-manager-live");
    assert_eq!(depends_on(live), ["deploy-dev"]);
    assert_eq!(
        live.get("environment")
            .and_then(|environment| environment.get("SOVEREIGN_CONFIG_LIVE_MANAGED_GROUP"))
            .and_then(Value::as_str),
        Some("sovereign-config-dev-connections")
    );
}

fn workflow_events(pipeline: &Pipeline, workflow: &str) -> BTreeSet<String> {
    when_conditions(pipeline.workflow(workflow))
        .into_iter()
        .flat_map(|condition| condition.events)
        .collect()
}

/// Workflows share nothing, so the order of a deployment rests on each step
/// sitting in the right workflow.
#[test]
fn every_step_sits_in_its_workflow() {
    let pipeline = pipeline();
    let expected: [(&str, &[&str]); 4] = [
        ("anchor", &["anchor"]),
        ("code-vitals", &["code-vitals"]),
        (
            "deploy-dev",
            &[
                "resolve",
                "deploy-dev",
                "validate-authentik-manager-live",
                "tag",
            ],
        ),
        (
            "deploy-prod",
            &["verify-commit-on-main", "resolve", "deploy-prod", "tag"],
        ),
    ];
    let actual: Vec<(&str, String)> = pipeline
        .steps()
        .into_iter()
        .map(|(workflow, name, _)| (workflow, name))
        .collect();
    let expected: Vec<(&str, String)> = expected
        .iter()
        .flat_map(|(workflow, steps)| steps.iter().map(|step| (*workflow, (*step).to_owned())))
        .collect();
    assert_eq!(
        actual, expected,
        "a step was added, removed, or moved workflow"
    );
}

/// The dev workflow is itself restricted to a dev deployment, from any branch.
/// It depends on no other workflow, because nothing else runs on a deployment.
#[test]
fn dev_workflow_is_gated_as_a_whole() {
    let pipeline = pipeline();
    assert!(
        pipeline.workflow("deploy-dev").get("depends_on").is_none(),
        "deploy-dev must not wait for a workflow that never runs on a deployment"
    );
    let conditions = when_conditions(pipeline.workflow("deploy-dev"));
    assert!(!conditions.is_empty());
    for condition in conditions {
        assert_eq!(condition.events, deployment_event());
        assert!(condition.branches.is_empty(), "dev deploys from any branch");
        assert_eq!(condition.evaluate.as_deref(), Some(DEV_TARGET));
    }
}

/// Both deploy workflows choose their build the same way. Workflows cannot
/// share a step, so it is defined in both and identical but for its `when`.
#[test]
fn deploy_workflows_share_their_promotion_steps() {
    let pipeline = pipeline();
    {
        let name = "resolve";
        assert_eq!(pipeline.workflows_of(name), ["deploy-dev", "deploy-prod"]);
        let copies: Vec<_> = ["deploy-dev", "deploy-prod"]
            .iter()
            .map(|workflow| {
                let mut copy = pipeline
                    .step_in(workflow, name)
                    .as_mapping()
                    .expect("step is a mapping")
                    .clone();
                copy.remove("when");
                copy
            })
            .collect();
        assert_eq!(
            copies[0], copies[1],
            "both copies of {name} must do the same thing"
        );
    }
}

/// The prod workflow is itself restricted to a prod deployment from main. It
/// depends on no other workflow, because nothing else runs on a deployment.
#[test]
fn prod_workflow_is_gated_as_a_whole() {
    let pipeline = pipeline();
    assert!(
        pipeline.workflow("deploy-prod").get("depends_on").is_none(),
        "deploy-prod must not wait for a workflow that never runs on a deployment"
    );
    let conditions = when_conditions(pipeline.workflow("deploy-prod"));
    assert!(!conditions.is_empty());
    for condition in conditions {
        assert_eq!(condition.events, deployment_event());
        assert_eq!(
            condition.branches,
            PROD_BRANCHES
                .iter()
                .map(|&branch| branch.to_owned())
                .collect()
        );
        assert_eq!(condition.evaluate.as_deref(), Some(PROD_TARGET));
    }
}

/// Triggering a pipeline by hand does exactly what a push does: every workflow
/// and step that runs on a push also runs on a manual trigger, and nothing runs
/// on one without the other.
#[test]
fn a_manual_run_matches_a_push() {
    let pipeline = pipeline();
    let mut checked = 0;
    for workflow in support::WORKFLOWS {
        let mut conditions = when_conditions(pipeline.workflow(workflow));
        for (owner, _, step) in pipeline.steps() {
            // A step without a `when` of its own runs under its workflow's.
            if owner == workflow && step.get("when").is_some() {
                conditions.extend(when_conditions(step));
            }
        }
        for condition in conditions {
            let push = condition.events.contains("push");
            let manual = condition.events.contains("manual");
            assert_eq!(
                push, manual,
                "{workflow} has a condition on {:?}: push and manual must go together",
                condition.events
            );
            checked += usize::from(push);
        }
    }
    assert!(checked > 0, "no push condition was found to compare");
}
