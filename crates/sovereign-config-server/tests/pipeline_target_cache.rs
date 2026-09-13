//! Guards the bound on the shared Rust target cache in `.woodpecker/build.yml`.
//! Three steps share one `sovereign-config-contract-target` volume as
//! `CARGO_TARGET_DIR`; cargo never garbage-collects artifacts from commits it
//! no longer builds, so without these two measures the volume grows without
//! limit — it reached 92.6 GB before card #326.
//!
//! The assertions are discovered from the pipeline rather than listed, so a
//! fourth step that mounts the volume is covered the moment it is added.

use std::path::Path;

use serde_yaml::Value;

/// The volume every shared-cache step mounts, and the path it mounts it at.
const CACHE_VOLUME: &str = "sovereign-config-contract-target";
const CACHE_PATH: &str = "/woodpecker/cache/sovereign-config-target";

/// The script that enforces the ceiling.
const PRUNE_SCRIPT: &str = "scripts/ci-prune-cargo-target.sh";

fn pipeline() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.woodpecker/build.yml");
    let contents = std::fs::read_to_string(path).expect("pipeline should be readable");
    serde_yaml::from_str(&contents).expect("pipeline should be valid YAML")
}

/// Every step mounting the shared target volume, as `(name, step)`.
fn steps_sharing_the_cache(pipeline: &Value) -> Vec<(String, &Value)> {
    pipeline
        .get("steps")
        .and_then(Value::as_mapping)
        .expect("pipeline should have steps")
        .iter()
        .filter_map(|(name, step)| {
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
            mounts.then(|| (name.as_str().expect("step name").to_owned(), step))
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

/// The three known steps, so a mount silently dropped from one of them fails
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
            "workspace-validation",
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
    let pipeline = pipeline();
    let step = pipeline
        .get("steps")
        .and_then(|steps| steps.get("script-validation"))
        .expect("script-validation step should exist");
    let commands = commands(step).join("\n");

    assert!(
        commands.contains("shellcheck -s sh") && commands.contains(PRUNE_SCRIPT),
        "script-validation must shellcheck {PRUNE_SCRIPT}"
    );
    assert!(
        commands.contains("sh scripts/ci-prune-cargo-target-test.sh"),
        "script-validation must run the prune script's test suite"
    );
}
