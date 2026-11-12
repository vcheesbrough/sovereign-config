//! Guards `.woodpecker/code-vitals.yml` (card #560), which records every
//! `main` commit in code-vitals. Its one promise to this repository is that it
//! can never fail or hold up a build or a deploy. The file is a copy of
//! code-vitals' `deploy/measured-repo-workflow.yml`, whose behaviour code-vitals
//! tests; this pins only the shape that promise rests on, as v-note's
//! `scripts/test-code-vitals-workflow.sh` does for v-note.

mod support;

use std::collections::BTreeSet;

use serde_yaml::Value;
use support::{WORKFLOWS, pipeline};

const WORKFLOW: &str = "code-vitals";

/// The broker secrets the step may read, by name.
const SECRETS: [&str; 3] = [
    "code_vitals_prod_writer_password",
    "zot_ci_password",
    "zot_ci_user",
];

fn strings(value: &Value) -> BTreeSet<&str> {
    match value {
        Value::String(one) => BTreeSet::from([one.as_str()]),
        Value::Sequence(many) => many.iter().filter_map(Value::as_str).collect(),
        other => panic!("unexpected scalar-or-sequence shape: {other:?}"),
    }
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

/// It records this repository, and every credential reaches it by name from
/// the broker, never inline.
#[test]
fn it_records_this_repository_with_brokered_secrets() {
    let pipeline = pipeline();
    let step = pipeline.step_in(WORKFLOW, "code-vitals");
    let commands: String = step["commands"]
        .as_sequence()
        .expect("commands")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(commands.contains("collect --repo sovereign-config --fetch --trigger push"));
    let environment = step["environment"].as_mapping().expect("environment");
    let secrets: BTreeSet<&str> = environment
        .values()
        .filter_map(|value| value.get("from_secret").and_then(Value::as_str))
        .collect();
    assert_eq!(secrets, BTreeSet::from(SECRETS));
    for (name, value) in environment {
        assert!(
            value.get("from_secret").is_some(),
            "{name:?} must come from the broker by name"
        );
    }
}

/// Woodpecker pipes the step's script into the shell, so `exec <…` anywhere
/// on a line would silently drop the rest of the script and still pass.
#[test]
fn it_never_redirects_the_shells_stdin() {
    let pipeline = pipeline();
    let step = pipeline.step_in(WORKFLOW, "code-vitals");
    for command in step["commands"].as_sequence().expect("commands") {
        let script = command.as_str().expect("command text");
        for line in script.lines() {
            let code = line.split('#').next().unwrap_or_default();
            let redirects = code
                .split([';', '&', '|', '('])
                .map(str::trim)
                .any(|part| part.starts_with("exec") && part.contains('<'));
            assert!(!redirects, "the step redirects the shell's stdin: {line}");
        }
    }
}
