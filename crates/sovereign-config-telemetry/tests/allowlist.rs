//! This crate is the only importer of an OpenTelemetry SDK or exporter
//! (`observability` skill §5). Swapping or upgrading the SDK stays a
//! one-crate change only while nothing else names it, and review would let
//! that erode one convenient import at a time; this does not.
//!
//! `tracing` and the `opentelemetry` API crate are the façade and may appear
//! anywhere.

use std::{
    fs,
    path::{Path, PathBuf},
};

/// Source paths (`use`, qualified calls) of the crates only this one may name.
const SDK_PATHS: [&str; 4] = [
    "opentelemetry_sdk",
    "opentelemetry_otlp",
    "tracing_opentelemetry",
    "opentelemetry_appender_tracing",
];

/// The same crates as a manifest names them.
const SDK_PACKAGES: [&str; 4] = [
    "opentelemetry_sdk",
    "opentelemetry-otlp",
    "tracing-opentelemetry",
    "opentelemetry-appender-tracing",
];

const THIS_CRATE: &str = "sovereign-config-telemetry";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate sits two levels below the workspace root")
        .to_path_buf()
}

fn rust_sources(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let path = entry.expect("readable directory entry").path();
        if path.is_dir() {
            rust_sources(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
}

/// Every workspace member other than this one: `crates/*` and
/// `test-consumers/*`.
fn other_members() -> Vec<PathBuf> {
    let root = workspace_root();
    let mut members = Vec::new();
    for group in ["crates", "test-consumers"] {
        for entry in fs::read_dir(root.join(group)).expect("member directory") {
            let path = entry.expect("readable directory entry").path();
            if path.is_dir() && path.file_name().is_some_and(|name| name != THIS_CRATE) {
                members.push(path);
            }
        }
    }
    assert!(
        members.len() > 5,
        "the scan must see the workspace, found {members:?}"
    );
    members
}

#[test]
fn no_other_source_names_an_sdk_or_exporter_crate() {
    let mut offenders = Vec::new();
    for member in other_members() {
        let mut sources = Vec::new();
        for dir in ["src", "tests", "benches", "examples"] {
            rust_sources(&member.join(dir), &mut sources);
        }
        if member.join("build.rs").is_file() {
            sources.push(member.join("build.rs"));
        }
        for source in sources {
            let text = fs::read_to_string(&source).expect("readable source");
            for path in SDK_PATHS {
                if text.contains(path) {
                    offenders.push(format!("{} names {path}", source.display()));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "only {THIS_CRATE} may name the SDK or an exporter:\n{}",
        offenders.join("\n")
    );
}

/// Asked of Cargo rather than read off the manifests, so the table form, a
/// target-specific table and a `package = "…"` rename are all resolved to the
/// real package name before the check.
#[test]
fn no_other_member_depends_on_an_sdk_or_exporter_crate() {
    let output = std::process::Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--offline",
        ])
        .current_dir(workspace_root())
        .output()
        .expect("cargo metadata must run");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata emits JSON");
    let packages = metadata["packages"].as_array().expect("a package list");
    assert!(packages.len() > 5, "the check must see the workspace");

    let mut offenders = Vec::new();
    for package in packages {
        let name = package["name"].as_str().unwrap_or_default();
        if name == THIS_CRATE {
            continue;
        }
        for dependency in package["dependencies"].as_array().into_iter().flatten() {
            let dependency = dependency["name"].as_str().unwrap_or_default();
            if SDK_PACKAGES.contains(&dependency) {
                offenders.push(format!("{name} depends on {dependency}"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "only {THIS_CRATE} may depend on the SDK or an exporter:\n{}",
        offenders.join("\n")
    );
}

/// The scan is only worth its green if it would go red: it must find the
/// names in this crate, where they legitimately are.
#[test]
fn the_scan_finds_the_names_where_they_are() {
    let mut sources = Vec::new();
    rust_sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut sources,
    );
    let text: String = sources
        .iter()
        .map(|path| fs::read_to_string(path).unwrap())
        .collect();
    for path in [
        "opentelemetry_sdk",
        "opentelemetry_otlp",
        "opentelemetry_appender_tracing",
    ] {
        assert!(text.contains(path), "{path} not found in {THIS_CRATE}");
    }
}
