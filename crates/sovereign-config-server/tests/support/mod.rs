//! Loads the two CI systems' pipelines: the Woodpecker deployments, one
//! workflow file each under `.woodpecker/` (see the header of `anchor.yml`), and
//! the GitHub Actions build, `.github/workflows/build.yml`.
//!
//! Each integration test binary compiles this module separately and uses a
//! different subset of it.
#![allow(dead_code)]

use std::path::Path;

use serde_yaml::Value;

/// Every Woodpecker workflow file: the push anchor, the code-vitals recorder,
/// then the deploys.
pub const WORKFLOWS: [&str; 4] = ["anchor", "code-vitals", "deploy-dev", "deploy-prod"];

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

    /// Every workflow defining a step called `name`, in [`WORKFLOWS`] order.
    pub fn workflows_of(&self, name: &str) -> Vec<&'static str> {
        self.steps()
            .into_iter()
            .filter(|(_, step, _)| step == name)
            .map(|(workflow, _, _)| workflow)
            .collect()
    }

    /// The one workflow defining `name`. Panics if the name is missing or is
    /// defined in several workflows; use [`Pipeline::step_in`] for those.
    pub fn workflow_of(&self, name: &str) -> &'static str {
        match self.workflows_of(name).as_slice() {
            [workflow] => workflow,
            [] => panic!("step {name} should exist"),
            many => panic!("step {name} is defined in several workflows: {many:?}"),
        }
    }

    pub fn step(&self, name: &str) -> &Value {
        self.step_in(self.workflow_of(name), name)
    }

    pub fn step_in(&self, workflow: &str, name: &str) -> &Value {
        self.workflow(workflow)
            .get("steps")
            .and_then(|steps| steps.get(name))
            .unwrap_or_else(|| panic!("step {name} should exist in {workflow}"))
    }
}

/// A GitHub Actions workflow under `.github/workflows/`.
pub struct Build {
    workflow: Value,
}

/// The build workflow, `.github/workflows/build.yml`.
pub fn build() -> Build {
    github_workflow("build")
}

/// `.github/workflows/<name>.yml`.
pub fn github_workflow(name: &str) -> Build {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../.github/workflows")
        .join(format!("{name}.yml"));
    let contents = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("workflow {} should be readable", path.display()));
    let workflow = serde_yaml::from_str(&contents)
        .unwrap_or_else(|_| panic!("workflow {name} should be valid YAML"));
    Build { workflow }
}

/// Every workflow under `.github/workflows/`, by file stem.
pub fn github_workflows() -> Vec<(String, Build)> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows");
    let mut names: Vec<String> = std::fs::read_dir(&directory)
        .expect(".github/workflows should be readable")
        .map(|entry| entry.expect("workflow entry").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "yml"))
        .map(|path| path.file_stem().unwrap().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|name| {
            let workflow = github_workflow(&name);
            (name, workflow)
        })
        .collect()
}

impl Build {
    pub fn workflow(&self) -> &Value {
        &self.workflow
    }

    /// Every job's name, in file order.
    pub fn job_names(&self) -> Vec<String> {
        self.workflow
            .get("jobs")
            .and_then(Value::as_mapping)
            .expect("the build workflow should have jobs")
            .keys()
            .map(|name| name.as_str().expect("job name").to_owned())
            .collect()
    }

    pub fn job(&self, name: &str) -> &Value {
        self.workflow
            .get("jobs")
            .and_then(|jobs| jobs.get(name))
            .unwrap_or_else(|| panic!("job {name} should exist"))
    }

    pub fn steps(&self, job: &str) -> &[Value] {
        self.job(job)
            .get("steps")
            .and_then(Value::as_sequence)
            .unwrap_or_else(|| panic!("job {job} should have steps"))
    }

    /// The `run` scripts of a job's steps, joined in order.
    pub fn run_text(&self, job: &str) -> String {
        self.steps(job)
            .iter()
            .filter_map(|step| step.get("run").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The jobs a job waits for, whether `needs` is one name or a list.
    pub fn needs(&self, job: &str) -> Vec<String> {
        match self.job(job).get("needs") {
            None => Vec::new(),
            Some(Value::String(one)) => vec![one.clone()],
            Some(Value::Sequence(many)) => many
                .iter()
                .map(|need| need.as_str().expect("job name").to_owned())
                .collect(),
            Some(other) => panic!("unexpected needs shape in {job}: {other:?}"),
        }
    }

    /// The steps of a job that run the action `uses` starts with.
    pub fn uses<'a>(&'a self, job: &str, prefix: &str) -> Vec<&'a Value> {
        self.steps(job)
            .iter()
            .filter(|step| {
                step.get("uses")
                    .and_then(Value::as_str)
                    .is_some_and(|uses| uses.starts_with(prefix))
            })
            .collect()
    }
}
