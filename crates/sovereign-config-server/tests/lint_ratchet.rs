//! Guards the `clippy::too_many_lines` ratchet (bored card #340).
//!
//! The lint was once enabled and then switched off at exactly the functions it
//! fired on. These checks keep it live: the workspace threshold stays at
//! clippy's default, and no product source silences the lint locally. Test
//! code may still opt out, because a long scenario test is not a design smell
//! in the way a long handler is.
//!
//! It also guards the protocol seam in the server (bored card #397). The
//! service implementations are shared by every protocol version and must not
//! know which one called them, so only a `vN.rs` shim may name a version's
//! generated types. Review would let that erode one convenient import at a
//! time; this does not.

use std::fs;
use std::path::{Path, PathBuf};

const THRESHOLD_SETTING: &str = "too-many-lines-threshold = 100";
const SILENCERS: [&str; 2] = [
    "allow(clippy::too_many_lines",
    "expect(clippy::too_many_lines",
];

/// Spelled with the path separator so it cannot match the
/// `sovereign_config_protocol_requests_total` metric name.
const PROTO_CRATE: &str = "sovereign_config_proto::";

/// Server sources, relative to `src/`, that may name a protocol version's
/// generated types besides the `vN.rs` shims: the entry point registers each
/// version's servers, and `System` is per-version by nature because
/// `GetVersion` echoes the version it was asked for.
const VERSION_AWARE: [&str; 2] = ["main.rs", "system.rs"];

/// The shared implementations the shims translate for. Named so the guard
/// fails, rather than passing vacuously, if they move out from under it.
const SHARED_IMPLEMENTATIONS: [&str; 2] = ["values/service.rs", "managed/service.rs"];

/// Whether `path` is a protocol version's shim: a file named `v<digits>.rs`.
fn is_version_shim(path: &Path) -> bool {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .and_then(|stem| stem.strip_prefix('v'))
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
}

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

#[test]
fn only_version_shims_name_a_protocol_version() {
    let server = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = Vec::new();
    product_sources(&server, &mut sources);
    let relative = |path: &Path| {
        path.strip_prefix(&server)
            .expect("source should be under src/")
            .to_string_lossy()
            .replace('\\', "/")
    };
    let names_a_version = |path: &Path| {
        fs::read_to_string(path)
            .expect("source should be readable")
            .contains(PROTO_CRATE)
    };

    for shared in SHARED_IMPLEMENTATIONS {
        assert!(
            sources.iter().any(|path| relative(path) == shared),
            "{shared} is gone; point this guard at the shared implementation's new home"
        );
    }
    // A shim that names no version would mean the needle no longer matches
    // how the proto crate is imported, and the scan below proves nothing.
    let shims: Vec<&PathBuf> = sources
        .iter()
        .filter(|path| is_version_shim(path))
        .collect();
    assert!(
        shims.len() >= SHARED_IMPLEMENTATIONS.len(),
        "expected a shim per shared implementation, found {shims:?}"
    );
    for shim in &shims {
        assert!(
            names_a_version(shim),
            "{} imports no protocol version; is `{PROTO_CRATE}` still how it is spelled?",
            shim.display()
        );
    }

    let offenders: Vec<String> = sources
        .iter()
        .filter(|path| !is_version_shim(path))
        .filter(|path| !VERSION_AWARE.contains(&relative(path).as_str()))
        .filter(|path| names_a_version(path))
        .map(|path| relative(path))
        .collect();
    assert!(
        offenders.is_empty(),
        "these are shared by every protocol version and must not name one; \
         translate in a vN.rs shim instead: {offenders:?}"
    );
}
