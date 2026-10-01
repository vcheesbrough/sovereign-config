//! Guards the deployment-trigger policy encoded in the `.woodpecker/` workflows:
//! a push (or manual run) checks, builds, tags and publishes, and never deploys;
//! each environment deploys only on a `deployment` event (Woodpecker's Deploy)
//! targeting it — production from main only (card #262), development from any
//! branch (card #466). The pipeline file is not otherwise exercised by any test.

mod support;

use std::collections::BTreeSet;

use serde_yaml::Value;
use support::{Pipeline, pipeline};

/// The events that build, tag and publish. A manual run from the Woodpecker UI
/// does exactly what a push does.
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
        let conditions = when_conditions(pipeline().step_in("deploy-prod", name));
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
    }
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
    assert_eq!(checked, 6, "a deploy-dev step was added or removed");
}

#[test]
fn build_and_publish_steps_never_run_on_a_deployment() {
    // Everything that allocates a version, builds, tags or publishes runs on
    // push and manual only, so a deployment never mints a new version and never
    // rebuilds or republishes an image.
    for name in [
        "compute-version",
        "script-validation",
        "unit-test",
        "client-playwright",
        "prune-build-cache",
        "build-server",
        "build-broker",
        "build-cli",
        "promote-images",
        "tag-release",
    ] {
        let pipeline = pipeline();
        let workflows = pipeline.workflows_of(name);
        assert!(!workflows.is_empty(), "step {name} should exist");
        for workflow in workflows {
            let conditions = when_conditions(pipeline.step_in(workflow, name));
            assert!(
                !conditions.is_empty() && conditions.iter().all(|c| c.events == push_events()),
                "{name} in {workflow} must run on push and manual only, so a deployment never touches it"
            );
        }
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

/// Publish releases a checked build: promote-images copies each candidate to
/// its release name inside the registry — never building, pushing from this
/// host, or overwriting a release — and only then does tag-release push the
/// git tag, a plain `git push` of a new tag, which refuses an existing one. It
/// runs only after checks and build (`publish_waits_for_checks_and_build`).
#[test]
fn publish_promotes_the_candidates_then_tags() {
    let pipeline = pipeline();
    let depends_on = |name: &str| -> Vec<String> {
        pipeline
            .step_in("publish", name)
            .get("depends_on")
            .and_then(Value::as_sequence)
            .expect("publish steps list their dependencies")
            .iter()
            .map(|dependency| dependency.as_str().expect("step name").to_owned())
            .collect()
    };
    assert_eq!(depends_on("promote-images"), ["compute-version"]);
    assert_eq!(depends_on("tag-release"), ["promote-images"]);

    let promote = commands_text(pipeline.step_in("publish", "promote-images"));
    for expected in [
        "for NAME in sovereign-config sovereign-config-woodpecker-broker sovereign-config-cli; do",
        "CANDIDATE=registry.desync.link/$$NAME-ci:$$RELEASE_TAG",
        "RELEASE=registry.desync.link/$$NAME:$$RELEASE_TAG",
        "docker buildx imagetools create --prefer-index=false --tag \"$$RELEASE\" \"$$CANDIDATE\"",
    ] {
        assert!(
            promote.contains(expected),
            "promote-images must contain `{expected}`"
        );
    }
    let refusal = promote
        .find("docker buildx imagetools inspect \"$$RELEASE\"")
        .expect("promote-images must check for an existing release");
    let copy = promote.find("imagetools create").expect("copies");
    assert!(refusal < copy, "the existing-release check comes first");
    for forbidden in ["docker build ", "docker push", "docker tag "] {
        assert!(
            !promote.contains(forbidden),
            "promote-images copies inside the registry and must not run `{forbidden}`"
        );
    }

    let tag = commands_text(pipeline.step_in("publish", "tag-release"));
    assert!(
        tag.contains("git tag \"$$RELEASE_TAG\" \"$$CI_COMMIT_SHA\"")
            && tag.contains("\"refs/tags/$$RELEASE_TAG\"")
            && !tag.contains("--force")
            && !tag.contains(" -f "),
        "tag-release must push this commit's release tag and never overwrite one"
    );
    assert_eq!(pipeline.workflows_of("tag-release"), ["publish"]);
    assert_eq!(pipeline.workflows_of("promote-images"), ["publish"]);
}

/// The repository root, where the `docker/` build files live.
fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn dockerfile(image: &str) -> String {
    let path = repo_root().join(format!("docker/{image}.Dockerfile"));
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} should be readable: {error}", path.display()))
}

/// Every `docker/*.Dockerfile`, by file name.
fn all_dockerfiles() -> Vec<(String, String)> {
    let mut files: Vec<(String, String)> = std::fs::read_dir(repo_root().join("docker"))
        .expect("docker/ should be readable")
        .map(|entry| entry.expect("docker/ entry should be readable").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "Dockerfile")
        })
        .map(|path| {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let text = std::fs::read_to_string(&path).expect("Dockerfile should be readable");
            (name, text)
        })
        .collect();
    files.sort();
    files
}

/// One named build stage of a Dockerfile: its `FROM … AS <name>` line up to the
/// next `FROM`.
///
/// `ARG` is scoped to the stage that declares it, so an assertion against the
/// whole file cannot tell "the server build receives this" from "some other
/// stage does". Only a slice can.
fn stage<'a>(dockerfile: &'a str, name: &str) -> &'a str {
    let header = format!(" AS {name}\n");
    let start = dockerfile
        .find(&header)
        .unwrap_or_else(|| panic!("the Dockerfile should have a stage named {name}"))
        + header.len();
    let rest = &dockerfile[start..];
    match rest.find("\nFROM ") {
        Some(end) => &rest[..end],
        None => rest,
    }
}

/// The digest-pinned references to `image@sha256:` in a Dockerfile.
fn pinned_digests<'a>(dockerfile: &'a str, image: &str) -> BTreeSet<&'a str> {
    dockerfile
        .split_whitespace()
        .filter(|word| word.contains(&format!("{image}@sha256:")))
        .collect()
}

/// Each image builds from its own file, which has one final stage, so no build
/// can pick the wrong image by omitting a `--target`.
#[test]
fn each_image_build_uses_its_own_dockerfile() {
    let pipeline = pipeline();
    for (name, image) in [
        ("build-server", "server"),
        ("build-broker", "broker"),
        ("build-cli", "cli"),
    ] {
        let commands = commands_text(step(&pipeline, name));
        let file = format!("-f docker/{image}.Dockerfile ");
        assert!(
            commands.contains("docker build") && commands.contains(&file),
            "{name} must build with {file}"
        );
        assert!(
            !commands.contains("--target"),
            "{name} must not select a stage: its Dockerfile builds one image"
        );
        dockerfile(image);
    }
    assert!(
        !repo_root().join("Dockerfile").exists(),
        "there must be no root Dockerfile for an untargeted `docker build .` to pick up"
    );
}

/// Every flag in an image build command must start a token of its own.
///
/// The build commands are single long shell lines, so an edit that drops one
/// space glues a flag onto the value before it. Docker does not complain about
/// an unknown flag — it takes the merged token as the build context path and
/// fails with a usage error about the argument count, which names neither the
/// flag nor the label that swallowed it. Nothing else here reads the command as
/// tokens, so only this catches it, and it catches it before a pipeline run
/// rather than after one.
#[test]
fn image_build_flags_are_never_glued_to_the_value_before_them() {
    let pipeline = pipeline();
    for name in ["build-server", "build-broker", "build-cli"] {
        let commands = commands_text(step(&pipeline, name));
        for (offset, _) in commands.match_indices("--") {
            let preceding = commands[..offset].chars().next_back();
            assert!(
                matches!(preceding, None | Some(' ' | '\n' | '"')),
                "{name}: a flag is glued to the token before it at {:?}",
                &commands[offset.saturating_sub(40)..commands.len().min(offset + 20)]
            );
        }
    }
}

/// The revision reaches the binary only if all four links hold: CI passes the
/// commit as a build arg, the **server** stage declares that arg, that stage
/// exports it to `cargo build`, and `build.rs` reads it into the compiled
/// binary.
///
/// A broken link degrades silently to `revision="unknown"` — the same value a
/// local build reports — so nothing fails and no unit test can tell the two
/// apart. The chain is only visible to someone scraping a deployment.
///
/// The `ARG` assertion is scoped to the `builder` stage on purpose: Docker
/// scopes `ARG` per stage, so an `ARG REVISION` sitting in `installer-builder`
/// would satisfy a file-wide search while the server binary got nothing.
#[test]
fn the_server_image_is_stamped_with_the_commit_it_was_built_from() {
    let commands = commands_text(step(&pipeline(), "build-server"));
    assert!(
        commands.contains("--build-arg REVISION=\"$$CI_COMMIT_SHA\""),
        "the build must pass the commit to the image"
    );

    let server_dockerfile = dockerfile("server");
    let builder = stage(&server_dockerfile, "builder");
    assert!(
        builder.contains("ARG REVISION"),
        "the stage that builds the server must declare the arg it is passed"
    );
    assert!(
        builder.contains("SOVEREIGN_CONFIG_REVISION=\"$REVISION\""),
        "the stage must export the arg to cargo, or build.rs never sees it"
    );

    let build_script =
        std::fs::read_to_string(repo_root().join("crates/sovereign-config-server/build.rs"))
            .expect("build.rs should be readable");
    assert!(
        build_script.contains("SOVEREIGN_CONFIG_REVISION"),
        "build.rs must read the variable the image build exports"
    );
}

/// The builder stages are duplicated across the files, not shared, so their
/// base images must not drift apart.
#[test]
fn every_dockerfile_pins_the_same_base_images() {
    let files = all_dockerfiles();
    assert!(
        files.len() >= 4,
        "expected web/server/broker/cli Dockerfiles, found {files:?}"
    );
    for image in [
        "docker.io/library/rust",
        "docker.io/library/debian",
        "docker:27-cli",
        "docker/dockerfile:1.7",
    ] {
        let digests: BTreeSet<&str> = files
            .iter()
            .flat_map(|(_, text)| pinned_digests(text, image))
            .collect();
        assert!(
            digests.len() <= 1,
            "every docker/*.Dockerfile must pin {image} to one digest, found {digests:?}"
        );
    }
    for (name, text) in &files {
        assert_eq!(
            pinned_digests(text, "docker.io/library/rust").len(),
            1,
            "{name} must build from the pinned rust image"
        );
        let mut stages: Vec<&str> = Vec::new();
        for from in text.lines().filter(|line| line.starts_with("FROM ")) {
            let words: Vec<&str> = from
                .split_whitespace()
                .filter(|word| !word.starts_with("--"))
                .collect();
            let base = words.get(1).copied().unwrap_or_default();
            assert!(
                base == "scratch" || base.contains("@sha256:") || stages.contains(&base),
                "{name}: {from} must pin its base image by digest or build on an earlier stage"
            );
            if let Some(stage) = words
                .iter()
                .position(|word| word.eq_ignore_ascii_case("AS"))
                .and_then(|index| words.get(index + 1))
            {
                stages.push(stage);
            }
        }
    }
}

/// The broker and CLI never ship the web bundle, and the broker never ships
/// the server, so neither build pays for them.
#[test]
fn broker_and_cli_builds_compile_only_what_they_ship() {
    for image in ["broker", "cli"] {
        let text = dockerfile(image);
        assert!(
            !text.contains("trunk") && !text.contains("wasm32") && !text.contains("web-dist"),
            "docker/{image}.Dockerfile must not build the web bundle"
        );
        assert!(
            !text.contains("--package sovereign-config-server"),
            "docker/{image}.Dockerfile must not compile the server"
        );
    }
    assert!(
        dockerfile("broker").contains("--package sovereign-config-woodpecker-broker"),
        "the broker Dockerfile must compile the broker"
    );
    assert!(
        dockerfile("cli").contains("--package sovereign-config-cli"),
        "the CLI Dockerfile must compile the CLI"
    );
}

/// The CLI image is the exact docker CLI image the pipeline's own docker steps
/// run, plus the static CLI binary on `PATH` — so another repository's step can
/// swap its image for it and gain `sovereign-config` without losing `docker`.
#[test]
fn the_cli_image_is_the_pipeline_docker_image_plus_the_cli() {
    let dockerfile = dockerfile("cli");
    let stage = dockerfile
        .split("\nFROM ")
        .find(|stage| {
            stage
                .lines()
                .next()
                .is_some_and(|from| from.ends_with(" AS cli-runtime"))
        })
        .expect("docker/cli.Dockerfile must define a cli-runtime stage");
    assert!(
        dockerfile.trim_end().ends_with(stage.trim_end()),
        "cli-runtime must be the final stage, so the untargeted build produces it"
    );
    let base = stage
        .split_whitespace()
        .next()
        .expect("cli-runtime needs a base image");
    let pipeline = pipeline();
    let build_image = step(&pipeline, "build-cli")
        .get("image")
        .and_then(Value::as_str)
        .expect("build-cli needs an image");
    assert!(
        base.starts_with("docker:27-cli@sha256:") && base == build_image,
        "cli-runtime must be based on the digest-pinned docker CLI image the pipeline uses, got {base}"
    );
    assert!(
        stage.contains("COPY --from=builder /tmp/sovereign-config /usr/local/bin/sovereign-config"),
        "cli-runtime must carry the static musl CLI"
    );
    assert!(
        dockerfile.contains("--target x86_64-unknown-linux-musl"),
        "the CLI must be built as a static musl binary"
    );
    // build-server strips and packages the same musl path in the shared target
    // cache, possibly at the same time, so the CLI image builds elsewhere.
    assert!(
        dockerfile.contains("--target-dir /src/target/cli-image")
            && dockerfile.contains(
                "/src/target/cli-image/x86_64-unknown-linux-musl/release/sovereign-config"
            ),
        "the CLI image must build into its own target directory, not the server's musl output"
    );
    assert!(
        !stage.contains("ENTRYPOINT") && !stage.contains("\nUSER "),
        "cli-runtime keeps the base image's entrypoint and user so pipeline commands can drive Docker"
    );
    assert!(
        stage.contains("sovereign-config --version") && stage.contains("$RELEASE_VERSION"),
        "cli-runtime must gate on the binary reporting the release it was built for"
    );
}

/// Server, broker and CLI ship as one release: the same commit, the same
/// semver. Each build step builds its image straight to its `-ci` candidate
/// name and pushes exactly that image — nothing re-reads a local image name
/// another pipeline could have replaced, and nothing in build writes a release
/// name; publish promotes candidates only after checks.
#[test]
fn every_image_is_pushed_as_a_candidate_as_it_is_built() {
    let pipeline = pipeline();
    for (build, published) in [
        (
            "build-server",
            "registry.desync.link/sovereign-config-ci:$$RELEASE_TAG",
        ),
        (
            "build-broker",
            "registry.desync.link/sovereign-config-woodpecker-broker-ci:$$RELEASE_TAG",
        ),
        (
            "build-cli",
            "registry.desync.link/sovereign-config-cli-ci:$$RELEASE_TAG",
        ),
    ] {
        let commands = commands_text(pipeline.step_in("build", build));
        assert!(
            commands.contains(&format!("IMAGE={published}\n")),
            "{build} must build {published}"
        );
        assert!(
            commands.contains("--tag \"$$IMAGE\""),
            "{build} must tag its build as the published image"
        );
        assert_eq!(
            commands.matches("docker push").count(),
            1,
            "{build} must push exactly its own image"
        );
        let built = commands.find("docker build").expect("builds");
        let pushed = commands.find("docker push \"$$IMAGE\"").expect("pushes");
        assert!(built < pushed, "{build} pushes what it just built");
        assert!(
            commands.contains("org.opencontainers.image.version=\"$$RELEASE_TAG\"")
                && commands.contains("org.opencontainers.image.revision=\"$$CI_COMMIT_SHA\""),
            "{build} must label its image with the release tag and commit"
        );
    }
}

#[test]
fn a_promotion_resolves_the_existing_tag_and_never_allocates() {
    let pipeline = pipeline();
    // compute-version names the version after the running pipeline; it must be
    // push/manual-only. A deployment is its own pipeline, so there it would name
    // a version that was never built and the deploy would pull an image that
    // was never published.
    assert_eq!(
        pipeline.workflows_of("compute-version"),
        ["build", "publish"]
    );
    for workflow in ["build", "publish"] {
        assert_eq!(
            commands_text(pipeline.step_in(workflow, "compute-version"))
                .lines()
                .next(),
            Some("sh scripts/ci-release-tag.sh Cargo.toml > .release-tag"),
            "both workflows of a pipeline must derive the tag the same way"
        );
    }
    // The deployment resolves the commit's already-built tag instead of
    // allocating, and verify-image proves the artifact exists rather than
    // rebuilding — so a deploy ships the exact image the push already
    // published. Guard that both read/write `.release-tag` on the deploy path.
    // Both deploy workflows carry the two steps;
    // deploy_workflows_share_their_promotion_steps holds the dev copy to these.
    let resolve = pipeline.step_in("deploy-prod", "resolve-release-tag");
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
    let verify_cmd = commands_text(pipeline.step_in("deploy-prod", "verify-image"));
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
    assert!(
        verify_cmd.contains("registry.desync.link/sovereign-config-cli:"),
        "verify-image must also prove the CLI image was published for this tag"
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
fn development_blueprint_applies_the_development_environment() {
    let pipeline = pipeline();
    let settings = step(&pipeline, "apply-authentik-blueprint-dev")
        .get("settings")
        .expect("blueprint step needs settings");
    assert_eq!(
        settings.get("file").and_then(Value::as_str),
        Some("authentik/blueprint-dev.yaml")
    );
    assert_eq!(
        settings.get("instance_name").and_then(Value::as_str),
        Some("sovereign-config-dev")
    );
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
/// and never a deploy (README "Observability").
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

fn workflow_events(pipeline: &Pipeline, workflow: &str) -> BTreeSet<String> {
    when_conditions(pipeline.workflow(workflow))
        .into_iter()
        .flat_map(|condition| condition.events)
        .collect()
}

/// Workflows share nothing, so the order of the pipeline rests on each step
/// sitting in the right workflow and on the workflow-level `depends_on`.
#[test]
fn every_step_sits_in_its_workflow() {
    let pipeline = pipeline();
    let expected: [(&str, &[&str]); 5] = [
        (
            "checks",
            &["script-validation", "unit-test", "client-playwright"],
        ),
        (
            "build",
            &[
                "compute-version",
                "prune-build-cache",
                "build-server",
                "build-broker",
                "build-cli",
            ],
        ),
        (
            "publish",
            &["compute-version", "promote-images", "tag-release"],
        ),
        (
            "deploy-dev",
            &[
                "validate-authentik-version",
                "resolve-release-tag",
                "verify-image",
                "apply-authentik-blueprint-dev",
                "validate-authentik-manager-live",
                "deploy-dev",
            ],
        ),
        (
            "deploy-prod",
            &[
                "validate-authentik-version",
                "resolve-release-tag",
                "verify-image",
                "apply-authentik-blueprint-prod",
                "validate-authentik-manager-live-prod",
                "deploy-prod",
            ],
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

/// Nothing is tagged or published unless every check passed — the tests, the
/// browser suite, and the script checks — and all three images are built.
#[test]
fn publish_waits_for_checks_and_build() {
    let pipeline = pipeline();
    let dependencies: Vec<&str> = pipeline
        .workflow("publish")
        .get("depends_on")
        .and_then(Value::as_sequence)
        .expect("publish should depend on checks and build")
        .iter()
        .map(|dependency| {
            dependency
                .as_str()
                .expect("publish's dependencies must be required, not optional")
        })
        .collect();
    assert_eq!(dependencies, ["checks", "build"]);
    for workflow in ["checks", "build", "publish"] {
        assert_eq!(
            workflow_events(&pipeline, workflow),
            push_events(),
            "{workflow} must run on push and manual alike, so publish's required dependencies always run with it"
        );
    }
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

/// Both deploy workflows promote the same way — resolve the commit's tag,
/// prove its images exist — and check Authentik the same way. Workflows cannot
/// share a step, so each is defined in both and identical but for its `when`.
#[test]
fn deploy_workflows_share_their_promotion_steps() {
    let pipeline = pipeline();
    for name in [
        "validate-authentik-version",
        "resolve-release-tag",
        "verify-image",
    ] {
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

/// Each deploy workflow checks Authentik compatibility, and that the commit is
/// released, before applying its blueprint: workflows cannot share a step, so the check is defined in
/// both and runs only with the deploy it guards (and
/// `deploy_workflows_share_their_promotion_steps` holds the copies identical).
#[test]
fn each_blueprint_apply_waits_for_the_authentik_version_check() {
    let pipeline = pipeline();
    for (workflow, apply, target) in [
        ("deploy-dev", "apply-authentik-blueprint-dev", DEV_TARGET),
        ("deploy-prod", "apply-authentik-blueprint-prod", PROD_TARGET),
    ] {
        let dependencies: Vec<&str> = pipeline
            .step_in(workflow, apply)
            .get("depends_on")
            .and_then(Value::as_sequence)
            .expect("blueprint apply should list its dependencies")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(
            dependencies.contains(&"validate-authentik-version"),
            "{apply} must wait for validate-authentik-version"
        );
        // verify-image follows resolve-release-tag, so an unreleased commit
        // fails before its blueprint or live tests touch Authentik.
        assert!(
            dependencies.contains(&"verify-image"),
            "{apply} must wait for the release check (verify-image)"
        );
        let check = pipeline.step_in(workflow, "validate-authentik-version");
        assert!(
            when_conditions(check).iter().all(|condition| {
                condition.events == deployment_event()
                    && condition.evaluate.as_deref() == Some(target)
            }),
            "the {workflow} copy of validate-authentik-version must run only on its own deployment"
        );
    }
}

/// The prod copy of the Authentik check carries the same prod-only guard as
/// every other production step.
#[test]
fn prod_authentik_check_is_gated_like_every_prod_step() {
    let pipeline = pipeline();
    let conditions = when_conditions(pipeline.step_in("deploy-prod", "validate-authentik-version"));
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
            if owner == workflow {
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
