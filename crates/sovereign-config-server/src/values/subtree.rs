//! Pure validation for a `ReplaceSubTree` mutation. Everything here runs
//! without storage, so it is covered by fast unit tests; the service applies
//! the result inside the locked transaction.

use std::collections::{BTreeMap, BTreeSet};

use sovereign_config_core::{ConfigPath, MASKED_SECRET_TEXT};
use tonic::Status;

use super::paths::paths_collide;

/// One entry of a subtree mutation exactly as a caller sent it, in no
/// protocol version's terms. Nothing about it has been validated, and
/// `content` is `None` when the wire message carried none: rejecting either is
/// [`normalize`]'s job, so every version fails a bad subtree in the same order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SubTreeEntry {
    pub(super) path: String,
    pub(super) content: Option<SubTreeEntryContent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum SubTreeEntryContent {
    PlainValue(String),
    PreserveSecret,
}

/// A subtree mutation whose paths are all valid, at or below the root, free
/// of nesting and duplicates, folded, and sorted by fold key.
pub(super) struct NormalizedSubtree {
    /// Each value's `path` holds its fold key.
    pub(super) values: Vec<SubTreeEntry>,
    /// Fold key to the exact case it was written with, for the paths whose
    /// case differs from their fold. Consulted only where a path is written.
    pub(super) displays: BTreeMap<String, String>,
}

fn invalid_subtree() -> Status {
    Status::invalid_argument("configuration subtree is invalid")
}

/// Parses and folds every path up front, before sorting or the
/// ancestor-collision walk: both depend on paths comparing and ordering by
/// fold key, not by raw (possibly mixed-case) bytes.
#[expect(
    clippy::result_large_err,
    reason = "tonic::Status is the crate's RPC error type and is returned by value"
)]
pub(super) fn normalize(
    root: &ConfigPath,
    mut values: Vec<SubTreeEntry>,
) -> Result<NormalizedSubtree, Status> {
    let mut displays: BTreeMap<String, String> = BTreeMap::new();
    for value in &mut values {
        let value_path = ConfigPath::parse_operation(&value.path).map_err(|_| invalid_subtree())?;
        if !value_path.is_at_or_below(root) {
            return Err(invalid_subtree());
        }
        match value.content.as_ref() {
            Some(SubTreeEntryContent::PlainValue(content)) if !content.contains('\0') => {}
            Some(SubTreeEntryContent::PreserveSecret) => {}
            _ => return Err(invalid_subtree()),
        }
        let fold = value_path.fold();
        if fold != value_path.as_str() {
            displays.insert(fold.clone(), value_path.as_str().to_owned());
        }
        value.path = fold;
    }
    values.sort_by(|first, second| first.path.cmp(&second.path));
    let mut accepted_paths = BTreeSet::new();
    for value in &values {
        let mut ancestor = value.path.as_str();
        let mut has_stored_ancestor = false;
        while let Some((parent, _)) = ancestor.rsplit_once('/') {
            if parent.is_empty() {
                break;
            }
            if accepted_paths.contains(parent) {
                has_stored_ancestor = true;
                break;
            }
            ancestor = parent;
        }
        if has_stored_ancestor || !accepted_paths.insert(value.path.as_str()) {
            return Err(invalid_subtree());
        }
    }
    Ok(NormalizedSubtree { values, displays })
}

/// The JSON representation uses the masked token for both a preserved secret
/// and a legitimate plain value with the same text. Resolves that ambiguity
/// against the stored classification (read while the mutation path is
/// locked): a marker with no secret behind it becomes a plain masked token.
/// Markers colliding with an existing secret still fail [`plain_paths`].
pub(super) fn resolve_preserve_markers(
    values: &mut [SubTreeEntry],
    secret_paths: &BTreeSet<String>,
) {
    for value in values {
        let Some(SubTreeEntryContent::PreserveSecret) = value.content.as_ref() else {
            continue;
        };
        if !secret_paths.contains(&value.path) {
            value.content = Some(SubTreeEntryContent::PlainValue(MASKED_SECRET_TEXT.into()));
        }
    }
}

/// The fold paths this mutation writes as plain values, once every plain
/// value is known not to collide with a stored secret and every preserve
/// marker is known to name one.
#[expect(
    clippy::result_large_err,
    reason = "tonic::Status is the crate's RPC error type and is returned by value"
)]
pub(super) fn plain_paths(
    values: &[SubTreeEntry],
    secret_paths: &BTreeSet<String>,
) -> Result<Vec<String>, Status> {
    let plain_paths: Vec<String> = values
        .iter()
        .filter_map(|value| match value.content.as_ref() {
            Some(SubTreeEntryContent::PlainValue(_)) => Some(value.path.clone()),
            _ => None,
        })
        .collect();
    let preserve_paths = values
        .iter()
        .filter_map(|value| match value.content.as_ref() {
            Some(SubTreeEntryContent::PreserveSecret) => Some(value.path.as_str()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    if plain_paths.iter().any(|plain| {
        secret_paths
            .iter()
            .any(|secret| paths_collide(plain, secret))
    }) || !preserve_paths
        .iter()
        .all(|preserve| secret_paths.contains(*preserve))
    {
        return Err(invalid_subtree());
    }
    Ok(plain_paths)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use sovereign_config_core::{ConfigPath, MASKED_SECRET_TEXT};
    use tonic::Code;

    use super::{
        SubTreeEntry, SubTreeEntryContent, normalize, plain_paths, resolve_preserve_markers,
    };

    fn plain(path: &str, value: &str) -> SubTreeEntry {
        SubTreeEntry {
            path: path.into(),
            content: Some(SubTreeEntryContent::PlainValue(value.into())),
        }
    }

    fn preserve(path: &str) -> SubTreeEntry {
        SubTreeEntry {
            path: path.into(),
            content: Some(SubTreeEntryContent::PreserveSecret),
        }
    }

    fn root(path: &str) -> ConfigPath {
        ConfigPath::parse_selection(path).unwrap()
    }

    fn secrets(paths: &[&str]) -> BTreeSet<String> {
        paths.iter().map(|path| (*path).to_owned()).collect()
    }

    fn rejects(result: Result<impl Sized, tonic::Status>) {
        let status = result.err().expect("mutation must be rejected");
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.message(), "configuration subtree is invalid");
    }

    #[test]
    fn normalize_folds_sorts_and_remembers_display_case() {
        let normalized = normalize(
            &root("/apps"),
            vec![plain("/apps/Zeta", "z"), plain("/apps/alpha", "a")],
        )
        .unwrap();
        let paths: Vec<&str> = normalized.values.iter().map(|v| v.path.as_str()).collect();
        assert_eq!(paths, ["/apps/alpha", "/apps/zeta"]);
        assert_eq!(normalized.displays.len(), 1);
        assert_eq!(normalized.displays["/apps/zeta"], "/apps/Zeta");
    }

    #[test]
    fn normalize_rejects_paths_outside_the_root_or_invalid() {
        rejects(normalize(&root("/apps"), vec![plain("/other/a", "x")]));
        rejects(normalize(&root("/apps"), vec![plain("apps/a", "x")]));
    }

    #[test]
    fn normalize_rejects_nul_bytes_and_missing_content() {
        rejects(normalize(&root("/"), vec![plain("/a", "x\0y")]));
        rejects(normalize(
            &root("/"),
            vec![SubTreeEntry {
                path: "/a".into(),
                content: None,
            }],
        ));
    }

    #[test]
    fn normalize_rejects_nesting_and_fold_duplicates() {
        rejects(normalize(
            &root("/"),
            vec![plain("/a", "1"), plain("/a/b", "2")],
        ));
        rejects(normalize(
            &root("/"),
            vec![plain("/a/b", "1"), plain("/A/B", "2")],
        ));
        assert!(normalize(&root("/"), vec![plain("/a/b", "1"), plain("/a/c", "2")]).is_ok());
    }

    #[test]
    fn preserve_markers_without_a_stored_secret_become_the_plain_mask() {
        let mut values = vec![preserve("/a/kept"), preserve("/a/unknown")];
        resolve_preserve_markers(&mut values, &secrets(&["/a/kept"]));
        assert!(matches!(
            values[0].content,
            Some(SubTreeEntryContent::PreserveSecret)
        ));
        assert_eq!(
            values[1].content,
            Some(SubTreeEntryContent::PlainValue(MASKED_SECRET_TEXT.into()))
        );
    }

    #[test]
    fn plain_paths_reject_secret_collisions_and_orphan_markers() {
        let stored = secrets(&["/a/secret"]);
        assert_eq!(
            plain_paths(&[plain("/a/plain", "x"), preserve("/a/secret")], &stored).unwrap(),
            ["/a/plain"]
        );
        rejects(plain_paths(&[plain("/a/secret", "x")], &stored));
        rejects(plain_paths(&[plain("/a/secret/child", "x")], &stored));
        rejects(plain_paths(&[preserve("/a/other")], &stored));
    }
}
