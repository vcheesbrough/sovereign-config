//! Guards the bound on the shared Rust target cache in the `.woodpecker/` workflows.
//! The deploys' live Authentik steps share one `sovereign-config-contract-target` volume as
//! `CARGO_TARGET_DIR`; cargo never garbage-collects artifacts from commits it
//! no longer builds, so without these two measures the volume grows without
//! limit — it reached 92.6 GB before card #326.
//!
//! The assertions are discovered from the pipeline rather than listed, so a
//! third step that mounts the volume is covered the moment it is added. The
//! checks run on GitHub Actions (card #539), whose runners start empty; their
//! cache is GitHub's, and only the `--locked` rule below applies to them.

mod support;

use serde_yaml::Value;
use support::{Pipeline, build, pipeline};

/// The volume every shared-cache step mounts, and the path it mounts it at.
const CACHE_VOLUME: &str = "sovereign-config-contract-target";
const CACHE_PATH: &str = "/woodpecker/cache/sovereign-config-target";

/// The script that enforces the ceiling.
const PRUNE_SCRIPT: &str = "scripts/ci-prune-cargo-target.sh";

/// Every step mounting the shared target volume, in any workflow, as
/// `(name, step)`.
fn steps_sharing_the_cache(pipeline: &Pipeline) -> Vec<(String, &Value)> {
    pipeline
        .steps()
        .into_iter()
        .filter_map(|(_, name, step)| {
            let mount = format!("{CACHE_VOLUME}:{CACHE_PATH}");
            let mounts = step
                .get("volumes")
                .and_then(Value::as_sequence)
                .is_some_and(|volumes| {
                    volumes
                        .iter()
                        .filter_map(Value::as_str)
                        .any(|volume| volume == mount)
                });
            mounts.then_some((name, step))
        })
        .collect()
}

fn commands(step: &Value) -> Vec<&str> {
    step.get("commands")
        .and_then(Value::as_sequence)
        .expect("step should have commands")
        .iter()
        .filter_map(Value::as_str)
        .collect()
}

/// The two known steps, so a mount silently dropped from one of them fails
/// here rather than quietly shrinking what the checks below cover.
#[test]
fn the_shared_cache_is_mounted_by_the_steps_that_build_into_it() {
    let pipeline = pipeline();
    let names: Vec<String> = steps_sharing_the_cache(&pipeline)
        .into_iter()
        .map(|(name, _)| name)
        .collect();

    assert_eq!(
        names,
        vec![
            "validate-authentik-manager-live",
            "validate-authentik-manager-live-prod",
        ],
        "the set of steps sharing the target cache changed"
    );
}

/// Incremental compilation exists to speed up repeated rebuilds of one working
/// tree. Every CI run is a fresh checkout, so the state is written and never
/// usefully read — it was 43 GB of the volume.
#[test]
fn steps_sharing_the_cache_disable_incremental_compilation() {
    let pipeline = pipeline();
    let shared = steps_sharing_the_cache(&pipeline);
    assert!(!shared.is_empty(), "no step mounts the shared target cache");

    for (name, step) in shared {
        let environment = step
            .get("environment")
            .unwrap_or_else(|| panic!("{name} should have an environment"));

        assert_eq!(
            environment.get("CARGO_TARGET_DIR").and_then(Value::as_str),
            Some(CACHE_PATH),
            "{name} mounts the shared cache but does not build into it"
        );
        assert_eq!(
            environment.get("CARGO_INCREMENTAL").and_then(Value::as_str),
            Some("0"),
            "{name} must disable incremental compilation — CI never reads that state back"
        );
    }
}

/// The prune must run *before* anything writes to the cache, or the step
/// measures a directory it has already grown.
#[test]
fn steps_sharing_the_cache_prune_it_first() {
    let pipeline = pipeline();
    let shared = steps_sharing_the_cache(&pipeline);
    assert!(!shared.is_empty(), "no step mounts the shared target cache");

    for (name, step) in shared {
        let first = commands(step)
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("{name} should have at least one command"));

        assert_eq!(
            first, PRUNE_SCRIPT,
            "{name} must run {PRUNE_SCRIPT} before it builds into the shared cache"
        );
    }
}

/// The prune script and its own test suite must stay under shellcheck and must
/// actually be executed, or the bound rots silently.
#[test]
fn the_prune_script_is_linted_and_tested() {
    let commands = build().run_text("script-validation");

    assert!(
        commands.contains("shellcheck -s sh") && commands.contains(PRUNE_SCRIPT),
        "script-validation must shellcheck {PRUNE_SCRIPT}"
    );
    assert!(
        commands.contains("sh scripts/ci-prune-cargo-target-test.sh"),
        "script-validation must run the prune script's test suite"
    );
}

/// unit-test's cargo commands, one per `;`-separated command of its run.
fn unit_test_cargo_commands() -> Vec<String> {
    build()
        .run_text("unit-test")
        .split([';', '\'', '\n'])
        .map(str::trim)
        .filter(|command| {
            ["cargo clippy", "cargo test", "cargo check", "cargo build"]
                .iter()
                .any(|prefix| command.starts_with(prefix))
        })
        .map(str::to_owned)
        .collect()
}

/// The image builds resolve dependencies with --locked, so unit-test must too:
/// otherwise an out-of-date Cargo.lock passes every check and fails only in a
/// build.
#[test]
fn unit_test_resolves_dependencies_with_the_lockfile() {
    let cargo = unit_test_cargo_commands();
    assert!(
        cargo.len() >= 5,
        "expected unit-test's cargo commands, found {cargo:?}"
    );
    for command in cargo {
        assert!(
            command.split_whitespace().any(|word| word == "--locked"),
            "unit-test must pass --locked: {command}"
        );
    }
}

/// The live Authentik checks are selected by a crate and a name filter, so a
/// move of either would leave both deploy steps green and testing nothing.
/// They live in the Authentik implementation's crate (#381); the checks run
/// compiles them there too, where they skip without credentials.
#[test]
fn the_live_steps_run_the_authentik_crates_live_tests() {
    const LIVE_RUN: &str =
        "cargo test --package sovereign-config-authentik live_ -- --ignored --test-threads=1";
    let pipeline = pipeline();
    for step in [
        "validate-authentik-manager-live",
        "validate-authentik-manager-live-prod",
    ] {
        assert!(
            commands(pipeline.step(step)).contains(&LIVE_RUN),
            "{step} must run the Authentik crate's live tests"
        );
    }
    let live_tests = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../sovereign-config-authentik/src/client/live_tests.rs"),
    )
    .expect("the live tests live in the Authentik crate");
    assert!(
        live_tests.matches("async fn live_").count() >= 3,
        "the `live_` filter must still select the live tests"
    );
    assert!(
        unit_test_cargo_commands().iter().any(|command| {
            command.contains("--ignored")
                && command.contains("--package sovereign-config-authentik")
        }),
        "unit-test's ignored run must compile the Authentik crate's ignored tests"
    );
}
