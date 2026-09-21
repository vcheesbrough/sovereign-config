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

/// Server sources, relative to `src/`, that may name the generated protobuf
/// types besides the `vN.rs` shims.
///
/// - `main.rs` registers each version's servers;
/// - `system.rs` is each version's `System` service, per-version by nature
///   because `GetVersion` echoes the version it was asked for;
/// - `handshake.rs` names the **unversioned** `sovereign.config` package. It is
///   the one service that belongs to no version, which is exactly why it needs
///   naming here: the scan sees the proto crate, not which package of it, so
///   the module that is furthest from a version still has to be listed.
const VERSION_AWARE: [&str; 3] = ["main.rs", "system.rs", "handshake.rs"];

/// The server modules split at the protocol seam. Each holds one shared
/// implementation, `<module>/service.rs`, and a `<module>/vN.rs` shim per
/// protocol version served.
const SEAM_MODULES: [&str; 3] = ["values", "managed", "audit"];

/// The `vN` in `<module>/vN.rs` when `relative` is a protocol version's shim.
///
/// The name alone is not enough: a shim is exempt from the scan below, so the
/// exemption is confined to the modules that are actually split at the seam.
/// Anywhere else a file called `v2.rs` is an ordinary source.
fn version_shim(relative: &str) -> Option<&str> {
    let (module, file) = relative.split_once('/')?;
    let stem = file.strip_suffix(".rs")?;
    let digits = stem.strip_prefix('v')?;
    (SEAM_MODULES.contains(&module)
        && !digits.is_empty()
        && digits.bytes().all(|byte| byte.is_ascii_digit()))
    .then_some(stem)
}

/// Whether `source` uses `module` as a path segment: `module::…` or `…::module`.
fn uses_module(source: &str, module: &str) -> bool {
    let is_identifier = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    source.match_indices(module).any(|(start, _)| {
        let end = start + module.len();
        let before = &source.as_bytes()[..start];
        let after = &source.as_bytes()[end..];
        let whole_word = !before.last().is_some_and(|byte| is_identifier(*byte))
            && !after.first().is_some_and(|byte| is_identifier(*byte));
        whole_word && (before.ends_with(b"::") || after.starts_with(b"::"))
    })
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
    let mut paths = Vec::new();
    product_sources(&server, &mut paths);
    let sources: Vec<(String, String)> = paths
        .iter()
        .map(|path| {
            let relative = path
                .strip_prefix(&server)
                .expect("source should be under src/")
                .to_string_lossy()
                .replace('\\', "/");
            let contents = fs::read_to_string(path).expect("source should be readable");
            (relative, contents)
        })
        .collect();

    for module in SEAM_MODULES {
        let shared = format!("{module}/service.rs");
        assert!(
            sources.iter().any(|(relative, _)| *relative == shared),
            "{shared} is gone; point this guard at the shared implementation's new home"
        );
        let shims: Vec<&(String, String)> = sources
            .iter()
            .filter(|(relative, _)| {
                version_shim(relative).is_some() && relative.starts_with(&format!("{module}/"))
            })
            .collect();
        assert!(
            !shims.is_empty(),
            "{shared} has no vN.rs shim beside it, so nothing serves it and this guard is \
             checking a seam that no longer exists"
        );
        for (shim, contents) in shims {
            // A shim that names no version would mean the needle no longer
            // matches how the proto crate is imported, and the scan below
            // proves nothing.
            assert!(
                contents.contains(PROTO_CRATE),
                "{shim} imports no protocol version; is `{PROTO_CRATE}` still how it is spelled?"
            );
        }
    }

    let offenders: Vec<&str> = sources
        .iter()
        .filter(|(relative, _)| version_shim(relative).is_none())
        .filter(|(relative, _)| !VERSION_AWARE.contains(&relative.as_str()))
        .filter(|(_, contents)| contents.contains(PROTO_CRATE))
        .map(|(relative, _)| relative.as_str())
        .collect();
    assert!(
        offenders.is_empty(),
        "these are shared by every protocol version and must not name one; \
         translate in a vN.rs shim instead: {offenders:?}"
    );

    // The scan above only sees the proto crate named directly. A shared file
    // could still reach a version's types through its shim, were the shim to
    // re-export them; nothing on the shared side of the seam has any business
    // depending on a shim, so that direction is refused outright.
    let shim_modules: Vec<(&str, &str)> = sources
        .iter()
        .filter_map(|(relative, _)| {
            let module = relative.split_once('/')?.0;
            version_shim(relative).map(|stem| (module, stem))
        })
        .collect();
    let dependants: Vec<String> = sources
        .iter()
        .filter(|(relative, _)| version_shim(relative).is_none())
        .flat_map(|(relative, contents)| {
            shim_modules
                .iter()
                .filter(|(module, stem)| {
                    relative.starts_with(&format!("{module}/")) && uses_module(contents, stem)
                })
                .map(|(_, stem)| format!("{relative} uses {stem}"))
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(
        dependants.is_empty(),
        "a shared implementation must not depend on a protocol version's shim: {dependants:?}"
    );
}
