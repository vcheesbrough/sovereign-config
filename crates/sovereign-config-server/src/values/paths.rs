use std::collections::BTreeMap;

use time::OffsetDateTime;

pub(super) fn paths_collide(first: &str, second: &str) -> bool {
    first == second
        || first
            .strip_prefix(second)
            .is_some_and(|suffix| suffix.starts_with('/'))
        || second
            .strip_prefix(first)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

/// The parent of a fold path. Takes `&str`, not `&ConfigPath`, so a caller
/// must explicitly hand in a fold key (e.g. `path.fold()` or a
/// `lowercase_path` column) rather than one that might carry display case.
pub(super) fn parent_path(fold_path: &str) -> &str {
    fold_path.rsplit_once('/').map_or(
        "/",
        |(parent, _)| if parent.is_empty() { "/" } else { parent },
    )
}

/// Records every ancestor namespace of `fold_path` (a stored row's fold key),
/// keyed by fold, mapped to the earliest `created_at` among rows sharing that
/// ancestor and the matching prefix of `display_path`.
///
/// `fold_path` and `display_path` always have the same segment count and byte
/// length per segment — display case never adds, removes, or resizes a
/// segment — so their segments can be walked in lockstep by index.
pub(super) fn add_parent_paths(
    paths: &mut BTreeMap<String, (OffsetDateTime, String)>,
    fold_path: &str,
    display_path: &str,
    created_at: OffsetDateTime,
) {
    upsert_ancestor(paths, "/".to_owned(), created_at, "/".to_owned());
    let fold_parent =
        fold_path.rsplit_once('/').map_or(
            "/",
            |(parent, _)| if parent.is_empty() { "/" } else { parent },
        );
    if fold_parent == "/" {
        return;
    }
    let fold_segments: Vec<&str> = fold_parent.trim_start_matches('/').split('/').collect();
    let display_segments: Vec<&str> = display_path.trim_start_matches('/').split('/').collect();
    let mut fold_prefix = String::new();
    let mut display_prefix = String::new();
    for index in 0..fold_segments.len() {
        fold_prefix.push('/');
        fold_prefix.push_str(fold_segments[index]);
        display_prefix.push('/');
        display_prefix.push_str(display_segments[index]);
        upsert_ancestor(
            paths,
            fold_prefix.clone(),
            created_at,
            display_prefix.clone(),
        );
    }
}

/// Keeps the display form from whichever row established this ancestor
/// first — ties break on the display string itself, so the choice stays
/// deterministic without depending on row iteration order.
fn upsert_ancestor(
    paths: &mut BTreeMap<String, (OffsetDateTime, String)>,
    fold: String,
    created_at: OffsetDateTime,
    display: String,
) {
    use std::collections::btree_map::Entry;
    match paths.entry(fold) {
        Entry::Vacant(entry) => {
            entry.insert((created_at, display));
        }
        Entry::Occupied(mut entry) => {
            if (created_at, display.as_str()) < (entry.get().0, entry.get().1.as_str()) {
                entry.insert((created_at, display));
            }
        }
    }
}
