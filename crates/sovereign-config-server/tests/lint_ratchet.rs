//! Guards the `clippy::too_many_lines` ratchet (bored card #340).
//!
//! The lint was once enabled and then switched off at exactly the functions it
//! fired on. These checks keep it live: the workspace threshold stays at
//! clippy's default, and no product source silences the lint locally. Test
//! code may still opt out, because a long scenario test is not a design smell
//! in the way a long handler is.

use std::fs;
use std::path::{Path, PathBuf};

const THRESHOLD_SETTING: &str = "too-many-lines-threshold = 100";
const SILENCERS: [&str; 2] = [
    "allow(clippy::too_many_lines",
    "expect(clippy::too_many_lines",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every Rust source under a crate's `src/`, excluding the sibling test modules
/// (`tests.rs`, `live_tests.rs`) product files declare with `#[cfg(test)]`.
fn product_sources(directory: &Path, found: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).expect("source directory should be readable") {
        let path = entry.expect("directory entry should be readable").path();
        if path.is_dir() {
            product_sources(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            if name != "tests.rs" && !name.ends_with("_tests.rs") {
                found.push(path);
            }
        }
    }
}

#[test]
fn the_workspace_threshold_is_clippys_default() {
    let config = fs::read_to_string(workspace_root().join("clippy.toml"))
        .expect("clippy.toml should be readable");
    let settings: Vec<&str> = config
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("too-many-lines-threshold"))
        .collect();
    assert_eq!(settings, [THRESHOLD_SETTING]);
}

#[test]
fn no_product_source_silences_the_line_count_lint() {
    let crates = workspace_root().join("crates");
    let mut sources = Vec::new();
    for entry in fs::read_dir(&crates).expect("crates directory should be readable") {
        let source = entry
            .expect("crate entry should be readable")
            .path()
            .join("src");
        if source.is_dir() {
            product_sources(&source, &mut sources);
        }
    }
    assert!(
        sources.len() > 50,
        "expected to scan the workspace, found {} files",
        sources.len()
    );

    let offenders: Vec<String> = sources
        .iter()
        .flat_map(|path| {
            let contents = fs::read_to_string(path).expect("source should be readable");
            contents
                .lines()
                .enumerate()
                .filter(|(_, line)| SILENCERS.iter().any(|silencer| line.contains(silencer)))
                .map(|(index, _)| format!("{}:{}", path.display(), index + 1))
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "split these functions instead of silencing clippy::too_many_lines: {offenders:?}"
    );
}
