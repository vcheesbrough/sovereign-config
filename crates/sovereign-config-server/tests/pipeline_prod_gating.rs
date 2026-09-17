//! Guards the deployment-trigger policy encoded in the `.woodpecker/` workflows:
//! production runs only on a `deployment` event (Woodpecker's Deploy/promote to
//! prod), never on push; development deploys only on push, so a production
//! promotion never also redeploys it. This is the lowest-layer check for card
//! #262 — the pipeline file is not otherwise exercised by any test.

mod support;

use std::collections::BTreeSet;

use serde_yaml::Value;
use support::{Pipeline, pipeline};

/// The only branch permitted to trigger a production promotion.
const PROD_BRANCHES: &[&str] = &["main"];

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

#[test]
fn production_steps_deploy_to_prod_from_permitted_branches() {
    let permitted: BTreeSet<String> = PROD_BRANCHES.iter().map(|&b| b.to_owned()).collect();
    for name in [
        "resolve-release-tag",
        "verify-image",
        "apply-authentik-blueprint-prod",
        "validate-authentik-manager-live-prod",
        "deploy-prod",
    ] {
        let conditions = when_conditions(step(&pipeline(), name));
        assert!(
            conditions
                .iter()
                .all(|c| c.events == BTreeSet::from(["deployment".to_owned()])),
            "{name} must only ever run on a deployment event, never on push"
        );
        // Restrict to the prod deploy target so a deployment with any other
        // (or mistyped) target from main cannot run the prod chain.
        assert!(
            conditions
                .iter()
                .all(|c| c.evaluate.as_deref() == Some("CI_PIPELINE_DEPLOY_TARGET == \"prod\"")),
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
    }
}

#[test]
fn build_and_dev_deploy_steps_run_on_push_only() {
    // Everything that allocates a version, builds, publishes, tags, or deploys
    // dev is push-only, so a production promotion (a deployment event) never
    // mints a new version, never rebuilds or republishes the image, and never
    // touches development.
    for name in [
        "compute-version",
        "script-validation",
        "unit-test",
        "client-playwright",
        "build-server",
        "build-broker",
        "publish-dev-image",
        "apply-authentik-blueprint-auto-dev",
        "validate-authentik-manager-live",
        "auto-deploy-dev",
        "tag-release-auto-dev",
    ] {
        let conditions = when_conditions(step(&pipeline(), name));
        assert!(
            !conditions.is_empty()
                && conditions
                    .iter()
                    .all(|c| c.events == BTreeSet::from(["push".to_owned()])),
            "{name} must be push-only so a production promotion never touches it"
        );
    }
}

/// The Dockerfile has two final stages, so an untargeted `docker build .`
/// silently tags the *last* one. Without `--target`, `build-server` would
/// publish the broker binary under the server's image name — a failure that
/// would only surface at deploy time.
#[test]
fn each_image_build_names_its_dockerfile_target() {
    let pipeline = pipeline();
    for (name, target) in [
        ("build-server", "--target server-runtime"),
        ("build-broker", "--target broker-runtime"),
    ] {
        let commands = commands_text(step(&pipeline, name));
        assert!(
            commands.contains("docker build") && commands.contains(target),
            "{name} must build with {target}"
        );
    }
}

/// Server and broker ship as one release: the same commit, the same semver, the
/// same publish step. A tag that carries only one of them is not a release.
#[test]
fn the_release_publishes_both_images_under_one_semver() {
    let publish = commands_text(step(&pipeline(), "publish-dev-image"));
    assert!(
        publish.contains("registry.desync.link/sovereign-config:$$RELEASE_TAG")
            && publish
                .contains("registry.desync.link/sovereign-config-woodpecker-broker:$$RELEASE_TAG"),
        "publish-dev-image must push both images at the allocated release tag"
    );
}

#[test]
fn a_promotion_resolves_the_existing_tag_and_never_allocates() {
    let pipeline = pipeline();
    // compute-version (mode compute) allocates the next semver; it must be
    // push-only. On a deployment it would mint the *next* patch — an unbuilt tag
    // — and deploy-prod would pull an image that was never published.
    assert_eq!(
        step(&pipeline, "compute-version")
            .get("settings")
            .and_then(|settings| settings.get("mode"))
            .and_then(Value::as_str),
        Some("compute"),
        "compute-version allocates, so it must stay push-only (asserted above)"
    );
    // The deployment resolves the commit's already-built tag instead of
    // allocating, and verify-image proves the artifact exists rather than
    // rebuilding — so deploy-prod deploys the exact image the push already
    // published. Guard that both read/write `.release-tag` on the deploy path.
    let resolve = step(&pipeline, "resolve-release-tag");
    let resolve_cmd = commands_text(resolve);
    assert!(
        resolve_cmd.contains("git tag --points-at HEAD") && resolve_cmd.contains("> .release-tag"),
        "resolve-release-tag must resolve the commit's git tag into .release-tag, not allocate"
    );
    // The deploy path must not install packages at runtime; git comes from a
    // digest-pinned image instead (repo policy: pin by digest, no undeclared fetch).
    assert!(
        !resolve_cmd.contains("apk add"),
        "resolve-release-tag must not install git at runtime; use a digest-pinned git image"
    );
    assert!(
        resolve
            .get("image")
            .and_then(Value::as_str)
            .is_some_and(|image| image.contains("alpine/git:") && image.contains("@sha256:")),
        "resolve-release-tag must use a digest-pinned git image"
    );
    let verify_cmd = commands_text(step(&pipeline, "verify-image"));
    assert!(
        verify_cmd.contains("docker pull")
            && verify_cmd.contains("registry.desync.link/sovereign-config:")
            && !verify_cmd.contains("docker build"),
        "verify-image must pull the already-published image and never build"
    );
    // A release publishes the server and the Woodpecker broker under one semver.
    // Promoting the server without its matching broker would leave CI resolving
    // secrets against a stale extension, so the gate must cover both.
    assert!(
        verify_cmd.contains("registry.desync.link/sovereign-config-woodpecker-broker:"),
        "verify-image must also prove the broker image was published for this tag"
    );
    // validate-authentik-version lives in the authentik workflow, which runs on
    // both events, so it still gates both the dev and prod blueprint applies.
    assert_eq!(
        pipeline.workflow_of("validate-authentik-version"),
        "authentik"
    );
    let events: BTreeSet<String> = when_conditions(pipeline.workflow("authentik"))
        .into_iter()
        .flat_map(|condition| condition.events)
        .collect();
    assert_eq!(
        events,
        BTreeSet::from(["push".to_owned(), "deployment".to_owned()]),
        "the authentik workflow must run on both push and deployment"
    );
}

#[test]
fn production_blueprint_applies_the_production_environment() {
    let pipeline = pipeline();
    let settings = step(&pipeline, "apply-authentik-blueprint-prod")
        .get("settings")
        .expect("blueprint step needs settings");
    assert_eq!(
        settings.get("file").and_then(Value::as_str),
        Some("authentik/blueprint.yaml"),
        "production must apply the production blueprint"
    );
    assert_eq!(
        settings.get("instance_name").and_then(Value::as_str),
        Some("sovereign-config"),
        "production blueprint instance must be the production application"
    );
}

#[test]
fn production_deploy_targets_the_production_environment() {
    let pipeline = pipeline();
    let command = commands_text(step(&pipeline, "deploy-prod"));
    assert!(command.contains("SOVEREIGN_CONFIG_ENV=prod"));
    assert!(command.contains("SOVEREIGN_CONFIG_HOST=sovereign-config.desync.link"));
    assert!(command.contains("docker compose -p sovereign-config-prod"));
    // It deploys the resolved, already-built tag and pulls it rather than
    // relying on a locally built image (there is no build on the deploy path).
    assert!(command.contains("SOVEREIGN_CONFIG_IMAGE_TAG=$$(cat .release-tag)"));
    assert!(command.contains("--pull always"));
    // A production deploy must never touch the development stack.
    assert!(!command.contains("sovereign-config-dev"));
}

#[test]
fn prod_live_manager_check_validates_the_production_group() {
    // The live lifecycle test resolves the browsing group named by
    // SOVEREIGN_CONFIG_LIVE_MANAGED_GROUP; the prod gate must point it at the
    // production group so it actually validates prod, not the dev group.
    let pipeline = pipeline();
    let env = step(&pipeline, "validate-authentik-manager-live-prod")
        .get("environment")
        .expect("prod live-manager step needs environment");
    assert_eq!(
        env.get("SOVEREIGN_CONFIG_LIVE_MANAGED_GROUP")
            .and_then(Value::as_str),
        Some("sovereign-config-connections"),
        "the prod live-manager gate must validate the production browsing group"
    );
}

fn workflow_dependencies(pipeline: &Pipeline, workflow: &str) -> BTreeSet<String> {
    pipeline
        .workflow(workflow)
        .get("depends_on")
        .and_then(Value::as_sequence)
        .unwrap_or_else(|| panic!("workflow {workflow} should depend on other workflows"))
        .iter()
        .map(|dependency| {
            dependency
                .as_str()
                .unwrap_or_else(|| panic!("{workflow} dependencies must be required, not optional"))
                .to_owned()
        })
        .collect()
}

/// Workflows share nothing, so the order of the pipeline rests on each step
/// sitting in the right workflow and on the workflow-level `depends_on`.
#[test]
fn every_step_sits_in_its_workflow() {
    let pipeline = pipeline();
    for (workflow, steps) in [
        ("checks", &["script-validation", "unit-test"][..]),
        ("client", &["client-playwright"][..]),
        ("authentik", &["validate-authentik-version"][..]),
        (
            "deploy-dev",
            &[
                "compute-version",
                "build-server",
                "build-broker",
                "publish-dev-image",
                "apply-authentik-blueprint-auto-dev",
                "validate-authentik-manager-live",
                "auto-deploy-dev",
                "tag-release-auto-dev",
            ][..],
        ),
        (
            "deploy-prod",
            &[
                "resolve-release-tag",
                "verify-image",
                "apply-authentik-blueprint-prod",
                "validate-authentik-manager-live-prod",
                "deploy-prod",
            ][..],
        ),
    ] {
        for name in steps {
            assert_eq!(
                pipeline.workflow_of(name),
                workflow,
                "{name} moved workflow"
            );
        }
    }
    assert_eq!(pipeline.steps().len(), 17, "a step was added or removed");
}

/// Nothing is published or deployed to dev unless every gate passed: the tests,
/// the browser suite, the script checks, and the Authentik compatibility check.
#[test]
fn dev_deploy_waits_for_every_gate() {
    let pipeline = pipeline();
    assert_eq!(
        workflow_dependencies(&pipeline, "deploy-dev"),
        BTreeSet::from([
            "authentik".to_owned(),
            "checks".to_owned(),
            "client".to_owned()
        ]),
    );
    for workflow in ["checks", "client", "deploy-dev"] {
        let events: BTreeSet<String> = when_conditions(pipeline.workflow(workflow))
            .into_iter()
            .flat_map(|condition| condition.events)
            .collect();
        assert_eq!(
            events,
            BTreeSet::from(["push".to_owned()]),
            "{workflow} must be push-only, so deploy-dev's required dependencies always run with it"
        );
    }
}

/// The prod workflow is itself restricted to a prod deployment from main, and it
/// cannot start before Authentik is proven compatible.
#[test]
fn prod_workflow_is_gated_as_a_whole() {
    let pipeline = pipeline();
    assert_eq!(
        workflow_dependencies(&pipeline, "deploy-prod"),
        BTreeSet::from(["authentik".to_owned()]),
    );
    let conditions = when_conditions(pipeline.workflow("deploy-prod"));
    assert!(!conditions.is_empty());
    for condition in conditions {
        assert_eq!(condition.events, BTreeSet::from(["deployment".to_owned()]));
        assert_eq!(
            condition.branches,
            PROD_BRANCHES
                .iter()
                .map(|&branch| branch.to_owned())
                .collect()
        );
        assert_eq!(
            condition.evaluate.as_deref(),
            Some("CI_PIPELINE_DEPLOY_TARGET == \"prod\"")
        );
    }
}
