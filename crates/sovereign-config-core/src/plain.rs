//! The plain subtree renderer: one `ABSOLUTE_PATH=VALUE` line per value.
//!
//! This is the line-oriented counterpart to [`crate::render_subtree_json`],
//! for readers that want `grep` and `cut` rather than a nested document. JSON
//! remains the byte-exact format: a plain line escapes the separators that
//! would otherwise split one value across two lines.

use crate::{ClientError, ConfigPath, SubTreeValue, json::invalid_subtree};

/// Renders a flat absolute-path collection as deterministic `PATH=VALUE` lines.
///
/// Values are ordered exactly as [`crate::render_subtree_json`] orders its
/// object keys, masked exactly as it masks secrets, and escaped so that one
/// value is always one line: `\` becomes `\\`, a line feed becomes `\n`, and a
/// carriage return becomes `\r`. Nothing else is escaped. A path segment
/// cannot contain `=` (the grammar is `[A-Za-z0-9_-]`), so the first `=` on a
/// line always separates the path from the value.
///
/// Unlike the JSON renderer, a value that also has descendants is not a
/// conflict here — `/a` and `/a/b` are simply two lines, the shorter first.
///
/// # Errors
///
/// Returns a bounded validation error when a path is outside the selection.
pub fn render_subtree_plain(
    root: &ConfigPath,
    values: &[SubTreeValue],
) -> Result<String, ClientError> {
    let mut entries = Vec::with_capacity(values.len());
    for value in values {
        if value.path.as_str() == "/" || !value.path.is_at_or_below(root) {
            return Err(invalid_subtree());
        }
        entries.push((fold_segments(&value.path), value));
    }
    // Segment-wise ordering, not whole-path byte ordering: the JSON renderer
    // nests a `BTreeMap` per level, so it compares one segment at a time and
    // never sees the `/` separator. The two disagree — `/a-c` precedes `/a/b`
    // by bytes (`-` < `/`) but follows it by segments (`a` < `a-c`) — and this
    // renderer follows JSON. `sort_by` is stable, so equal paths keep the
    // order they arrived in.
    entries.sort_by(|(first, _), (second, _)| first.cmp(second));

    let mut rendered = String::new();
    for (_, value) in entries {
        rendered.push_str(value.path.as_str());
        rendered.push('=');
        escape_into(&mut rendered, value.value.display_text());
        rendered.push('\n');
    }
    Ok(rendered)
}

/// The path's segments, folded, with the leading `/` dropped. Never called for
/// the tree root, which the caller rejects first.
fn fold_segments(path: &ConfigPath) -> Vec<String> {
    path.fold()
        .trim_start_matches('/')
        .split('/')
        .map(str::to_owned)
        .collect()
}

fn escape_into(rendered: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '\\' => rendered.push_str("\\\\"),
            '\n' => rendered.push_str("\\n"),
            '\r' => rendered.push_str("\\r"),
            other => rendered.push(other),
        }
    }
}
