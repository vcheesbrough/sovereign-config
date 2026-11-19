//! Guards `.woodpecker/code-vitals.yml` (cards #560, #568), which records
//! every `main` commit in code-vitals through its one plugin step. Its promise
//! to this repository is that it can never fail or hold up a build or a
//! deploy. What the plugin does with its settings is code-vitals' to test;
//! this pins the shape that promise rests on, and the settings themselves,
//! because changing them re-measures this repository's whole history.

mod support;

use std::collections::BTreeSet;

use serde_yaml::Value;
use support::{WORKFLOWS, pipeline};

const WORKFLOW: &str = "code-vitals";

/// The plugin, on the one moving tag this repository allows.
const IMAGE: &str = "registry.desync.link/code-vitals-plugin:stable";

/// Every setting the plugin accepts; it refuses any other.
const SETTINGS: [&str; 4] = ["areas", "trunk", "version_sources", "writer_password"];

/// The area rules as code-vitals held them for this repository (its
/// `tests/measured_repos.py`), in order: the first match wins.
const AREA_RULES: [(&str, &str); 5] = [
    ("crates/sovereign-config-server/**", "server"),
    ("crates/sovereign-config-woodpecker-broker/**", "server"),
    ("crates/sovereign-config-web/**", "web"),
    ("crates/**", "libraries"),
    ("proto/**", "libraries"),
];

fn strings(value: &Value) -> BTreeSet<&str> {
    match value {
        Value::String(one) => BTreeSet::from([one.as_str()]),
        Value::Sequence(many) => many.iter().filter_map(Value::as_str).collect(),
        other => panic!("unexpected scalar-or-sequence shape: {other:?}"),
    }
}

/// Each entry of a list of two-key maps, as a pair, in file order.
fn pairs<'a>(list: &'a Value, first: &str, second: &str) -> Vec<(&'a str, &'a str)> {
    list.as_sequence()
        .expect("a list")
        .iter()
        .map(|entry| {
            assert_eq!(entry.as_mapping().expect("a map").len(), 2);
            (
                entry[first].as_str().expect("a string"),
                entry[second].as_str().expect("a string"),
            )
        })
        .collect()
}

/// `main` pushes and manual runs only: never a deployment, a pull request, a
/// tag or a cron, and never another branch.
#[test]
fn it_records_main_pushes_and_manual_runs_only() {
    let pipeline = pipeline();
    let workflow = pipeline.workflow(WORKFLOW);
    let conditions = workflow["when"].as_sequence().expect("a `when` list");
    assert_eq!(conditions.len(), 1);
    assert_eq!(
        strings(&conditions[0]["event"]),
        BTreeSet::from(["manual", "push"])
    );
    assert_eq!(strings(&conditions[0]["branch"]), BTreeSet::from(["main"]));
    assert_eq!(
        workflow["skip_clone"].as_bool(),
        Some(true),
        "the collector clones the repository itself"
    );
}

/// One step that may fail without failing anything: `failure: ignore`, no
/// `depends_on` of its own, and no workflow waits for it.
#[test]
fn it_can_never_block_a_build_or_a_deploy() {
    let pipeline = pipeline();
    let steps: Vec<String> = pipeline
        .steps()
        .into_iter()
        .filter(|(workflow, _, _)| *workflow == WORKFLOW)
        .map(|(_, name, _)| name)
        .collect();
    assert_eq!(steps, ["code-vitals"]);
    let step = pipeline.step_in(WORKFLOW, "code-vitals");
    assert_eq!(step["failure"].as_str(), Some("ignore"));
    assert!(step.get("depends_on").is_none());
    assert!(pipeline.workflow(WORKFLOW).get("depends_on").is_none());
    for workflow in WORKFLOWS {
        let waits = pipeline
            .workflow(workflow)
            .get("depends_on")
            .map(strings)
            .unwrap_or_default();
        assert!(
            !waits.contains(WORKFLOW),
            "{workflow} must not wait for {WORKFLOW}"
        );
    }
}

/// The step is the plugin and nothing else: a plugin step takes `settings`,
/// so it has no script, no environment and no entrypoint of its own, and its
/// only mount is the docker socket the plugin starts the collector through.
#[test]
fn it_is_one_plugin_step() {
    let pipeline = pipeline();
    let step = pipeline.step_in(WORKFLOW, "code-vitals");
    assert_eq!(step["image"].as_str(), Some(IMAGE));
    for key in ["commands", "environment", "entrypoint", "privileged"] {
        assert!(step.get(key).is_none(), "a plugin step has no `{key}`");
    }
    assert_eq!(
        strings(&step["volumes"]),
        BTreeSet::from(["/var/run/docker.sock:/var/run/docker.sock"])
    );
}

/// The tag moves, so the agent must pull it on every run. Without `pull:
/// true` Woodpecker reuses a cached `:stable` plugin after a code-vitals
/// prod deploy, and that plugin starts the collector of its own, stale
/// version (code-vitals #573).
#[test]
fn it_pulls_the_moving_tag_every_run() {
    let pipeline = pipeline();
    let step = pipeline.step_in(WORKFLOW, "code-vitals");
    assert_eq!(step["pull"].as_bool(), Some(true));
}

/// The plugin is the only moving tag in the Woodpecker workflows (code-vitals'
/// approved exception); every other step image is pinned by digest.
#[test]
fn only_the_plugin_image_is_a_moving_tag() {
    let pipeline = pipeline();
    for (workflow, name, step) in pipeline.steps() {
        let image = step["image"].as_str().expect("a step image");
        if workflow == WORKFLOW {
            continue;
        }
        assert!(
            image.contains("@sha256:"),
            "{name} in {workflow} must pin its image by digest: {image}"
        );
        assert!(!image.contains("code-vitals"), "{name} in {workflow}");
    }
}

/// The settings are what code-vitals held for this repository, at the same
/// ruleset version, so that moving them here re-measured nothing. A change to
/// the rules needs a new `areas.version` (and this test updated with it).
#[test]
fn its_settings_are_the_ones_code_vitals_held() {
    let pipeline = pipeline();
    let settings = &pipeline.step_in(WORKFLOW, "code-vitals")["settings"];
    let names: BTreeSet<&str> = settings
        .as_mapping()
        .expect("settings")
        .keys()
        .map(|key| key.as_str().expect("a setting name"))
        .collect();
    assert_eq!(names, BTreeSet::from(SETTINGS));
    assert_eq!(settings["trunk"].as_str(), Some("main"));
    assert_eq!(
        pairs(&settings["version_sources"], "path", "kind"),
        [
            ("Cargo.toml", "cargo-workspace"),
            ("Cargo.toml", "cargo-package")
        ]
    );
    let areas = settings["areas"].as_mapping().expect("areas");
    assert_eq!(areas.len(), 2);
    assert_eq!(settings["areas"]["version"].as_u64(), Some(1));
    assert_eq!(
        pairs(&settings["areas"]["rules"], "glob", "area"),
        AREA_RULES
    );
}

/// The one credential reaches the plugin by name from the broker, never
/// inline, and no other setting is a secret.
#[test]
fn its_password_comes_from_the_broker() {
    let pipeline = pipeline();
    let step = pipeline.step_in(WORKFLOW, "code-vitals");
    let password = step["settings"]["writer_password"]
        .as_mapping()
        .expect("writer_password is a map");
    assert_eq!(password.len(), 1);
    assert_eq!(
        step["settings"]["writer_password"]["from_secret"].as_str(),
        Some("code_vitals_prod_writer_password")
    );
    let text = serde_yaml::to_string(step).expect("step serialises");
    assert_eq!(text.matches("from_secret").count(), 1);
}
