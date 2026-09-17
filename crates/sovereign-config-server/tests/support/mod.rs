//! Loads the Woodpecker pipeline, which is split into one workflow file per
//! concern under `.woodpecker/` (see the header of `checks.yml`).
//!
//! Each integration test binary compiles this module separately and uses a
//! different subset of it.
#![allow(dead_code)]

use std::path::Path;

use serde_yaml::Value;

/// Every workflow file, in the order the pipeline reads: gates, then deploys.
pub const WORKFLOWS: [&str; 5] = ["checks", "client", "authentik", "deploy-dev", "deploy-prod"];

pub struct Pipeline {
    workflows: Vec<(&'static str, Value)>,
}

pub fn pipeline() -> Pipeline {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.woodpecker");
    let workflows = WORKFLOWS
        .iter()
        .map(|name| {
            let path = directory.join(format!("{name}.yml"));
            let contents = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("workflow {} should be readable", path.display()));
            let value = serde_yaml::from_str(&contents)
                .unwrap_or_else(|_| panic!("workflow {name} should be valid YAML"));
            (*name, value)
        })
        .collect();
    Pipeline { workflows }
}

impl Pipeline {
    pub fn workflow(&self, name: &str) -> &Value {
        self.workflows
            .iter()
            .find_map(|(workflow, value)| (*workflow == name).then_some(value))
            .unwrap_or_else(|| panic!("workflow {name} should exist"))
    }

    /// Every step as `(workflow, step name, step)`, workflows in [`WORKFLOWS`]
    /// order and steps in file order.
    pub fn steps(&self) -> Vec<(&'static str, String, &Value)> {
        self.workflows
            .iter()
            .flat_map(|(workflow, value)| {
                value
                    .get("steps")
                    .and_then(Value::as_mapping)
                    .unwrap_or_else(|| panic!("workflow {workflow} should have steps"))
                    .iter()
                    .map(move |(name, step)| {
                        (
                            *workflow,
                            name.as_str().expect("step name").to_owned(),
                            step,
                        )
                    })
            })
            .collect()
    }

    /// The workflow holding the step `name`. Step names are unique across the
    /// whole pipeline, so a name alone identifies a step.
    pub fn workflow_of(&self, name: &str) -> &'static str {
        let owners: Vec<&'static str> = self
            .steps()
            .into_iter()
            .filter(|(_, step, _)| step == name)
            .map(|(workflow, _, _)| workflow)
            .collect();
        match owners.as_slice() {
            [workflow] => workflow,
            [] => panic!("step {name} should exist"),
            many => panic!("step {name} is defined in more than one workflow: {many:?}"),
        }
    }

    pub fn step(&self, name: &str) -> &Value {
        let workflow = self.workflow_of(name);
        self.workflow(workflow)
            .get("steps")
            .and_then(|steps| steps.get(name))
            .expect("step located by workflow_of")
    }
}
