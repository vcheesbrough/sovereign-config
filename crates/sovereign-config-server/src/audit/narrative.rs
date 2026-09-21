//! The sentence an audit event is stored with. Pure: no SQL, no clock, no I/O,
//! so every wording — and the rule that a secret never appears in one — is
//! tested without a database.
//!
//! A narrative never states how often something happened. A coalesced row's
//! count and period are rendered from `event_count`, `first_occurred_at` and
//! `occurred_at` when the row is served, so that bumping a window stays a
//! single-statement upsert.

use std::fmt::Write as _;

use time::{OffsetDateTime, UtcOffset};

use super::Recorded;

/// How much of a plain value a narrative quotes. The whole value is kept in
/// `old_value` / `new_value`; the sentence only has to be readable in a list.
const QUOTED_VALUE_CHARACTERS: usize = 80;

/// `value` as a narrative quotes it: bounded, on one line, and unambiguous
/// about where it ends.
fn quoted(value: &str) -> String {
    let mut shown: String = value
        .chars()
        .take(QUOTED_VALUE_CHARACTERS)
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    if value.chars().count() > QUOTED_VALUE_CHARACTERS {
        shown.push('…');
    }
    format!("\"{shown}\"")
}

fn counted(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("1 {singular}")
    } else {
        format!("{count} {plural}")
    }
}

pub(super) fn value_created(actor: &str, path: &str, new: Recorded<'_>) -> String {
    match new {
        Recorded::Plain(value) => format!("{actor} created {path} as {}", quoted(value)),
        Recorded::Secret => format!("{actor} created secret {path}"),
    }
}

pub(super) fn value_updated(
    actor: &str,
    path: &str,
    old: Recorded<'_>,
    new: Recorded<'_>,
) -> String {
    match (old, new) {
        (Recorded::Plain(old), Recorded::Plain(new)) => {
            format!(
                "{actor} changed {path} from {} to {}",
                quoted(old),
                quoted(new)
            )
        }
        (Recorded::Secret, Recorded::Secret) => format!("{actor} replaced secret {path}"),
        // A reclassification names both classes and only the plain side's
        // value: the secret side is never available to name.
        (Recorded::Plain(old), Recorded::Secret) => {
            format!(
                "{actor} replaced {path}, previously {}, with a secret",
                quoted(old)
            )
        }
        (Recorded::Secret, Recorded::Plain(new)) => {
            format!(
                "{actor} replaced secret {path} with plain value {}",
                quoted(new)
            )
        }
    }
}

pub(super) fn value_deleted(actor: &str, path: &str, old: Recorded<'_>) -> String {
    match old {
        Recorded::Plain(value) => format!("{actor} deleted {path}, previously {}", quoted(value)),
        Recorded::Secret => format!("{actor} deleted secret {path}"),
    }
}

/// Filed on the new path.
pub(super) fn path_added(actor: &str, new_path: &str, source: &str) -> String {
    format!("{actor} added {new_path} as a path to the value at {source}")
}

/// Filed on the source path.
pub(super) fn path_exposed(actor: &str, source: &str, new_path: &str) -> String {
    format!("{actor} exposed the value at {source} at {new_path}")
}

pub(super) fn subtree_replaced(
    actor: &str,
    root: &str,
    created: usize,
    updated: usize,
    deleted: usize,
    unrecorded: usize,
) -> String {
    let mut narrative = format!(
        "{actor} replaced subtree {root}: {created} created, {updated} changed, {deleted} deleted"
    );
    if unrecorded > 0 {
        write!(
            narrative,
            "; {} not recorded individually",
            counted(unrecorded, "change", "changes")
        )
        .expect("writing a narrative to a String cannot fail");
    }
    narrative
}

pub(super) fn subtree_deleted(
    actor: &str,
    root: &str,
    deleted: usize,
    unrecorded: usize,
) -> String {
    let mut narrative = format!(
        "{actor} deleted {} at or below {root}",
        counted(deleted, "value", "values")
    );
    if unrecorded > 0 {
        write!(
            narrative,
            "; {} not recorded individually",
            counted(unrecorded, "deletion", "deletions")
        )
        .expect("writing a narrative to a String cannot fail");
    }
    narrative
}

pub(super) fn secret_revealed(actor: &str, path: &str) -> String {
    format!("{actor} revealed secret {path}")
}

pub(super) fn subtree_read(actor: &str, root: &str, value_count: usize) -> String {
    format!(
        "{actor} read subtree {root} ({})",
        counted(value_count, "value", "values")
    )
}

pub(super) fn values_listed(actor: &str, namespace: &str, value_count: usize) -> String {
    format!(
        "{actor} listed {namespace} ({})",
        counted(value_count, "value", "values")
    )
}

pub(super) fn connection_created(
    actor: &str,
    root: &str,
    display_name: &str,
    connection_id: &str,
    permissions: &str,
) -> String {
    format!(
        "{actor} created managed connection {} ({connection_id}) on {root} with {permissions}",
        quoted(display_name)
    )
}

pub(super) fn connection_rotated(
    actor: &str,
    root: &str,
    display_name: &str,
    connection_id: &str,
) -> String {
    format!(
        "{actor} rotated managed connection {} ({connection_id}) on {root}",
        quoted(display_name)
    )
}

pub(super) fn connection_revoked(
    actor: &str,
    root: &str,
    display_name: &str,
    connection_id: &str,
) -> String {
    format!(
        "{actor} revoked managed connection {} ({connection_id}) on {root}",
        quoted(display_name)
    )
}

/// A coalesced event's narrative as it is served: the stored sentence, which
/// describes the latest access, followed by how many accesses the row stands
/// for and over what period. Rendered on read, never stored, so bumping a
/// window stays a single-statement upsert.
pub(super) fn served(
    narrative: &str,
    event_count: u32,
    first: OffsetDateTime,
    last: OffsetDateTime,
) -> String {
    if event_count <= 1 {
        return narrative.to_owned();
    }
    format!(
        "{narrative} — {event_count} times between {} and {}",
        utc(first),
        utc(last)
    )
}

/// A time as a narrative states it: to the second, in UTC, and saying so.
fn utc(at: OffsetDateTime) -> String {
    let at = at.to_offset(UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second()
    )
}

#[cfg(test)]
mod tests {
    use time::{OffsetDateTime, UtcOffset};

    use super::super::Recorded;
    use super::{
        QUOTED_VALUE_CHARACTERS, quoted, served, subtree_deleted, subtree_read, subtree_replaced,
        value_created, value_deleted, value_updated,
    };

    const SECRET_TEXT: &str = "hunter2-do-not-record";

    #[test]
    fn a_single_event_is_served_as_stored() {
        let at = OffsetDateTime::from_unix_timestamp(1_789_981_320).unwrap();
        assert_eq!(
            served("alice read subtree /apps (3 values)", 1, at, at),
            "alice read subtree /apps (3 values)"
        );
    }

    #[test]
    fn a_coalesced_event_is_served_with_its_count_and_period() {
        assert_eq!(
            served(
                "alice revealed secret /apps/db/password",
                14,
                OffsetDateTime::from_unix_timestamp(1_789_981_323).unwrap(),
                // Rendered in UTC whatever offset it arrives in.
                OffsetDateTime::from_unix_timestamp(1_790_009_159)
                    .unwrap()
                    .to_offset(UtcOffset::from_hms(1, 0, 0).unwrap()),
            ),
            "alice revealed secret /apps/db/password — 14 times between \
             2026-09-21 09:02:03 UTC and 2026-09-21 16:45:59 UTC"
        );
    }

    #[test]
    fn a_plain_change_names_both_values() {
        assert_eq!(
            value_updated(
                "alice",
                "/billing/limit",
                Recorded::Plain("10"),
                Recorded::Plain("20")
            ),
            "alice changed /billing/limit from \"10\" to \"20\""
        );
    }

    /// The invariant the whole card turns on, at the layer that words it: a
    /// value classified secret reaches this module only as `Recorded::Secret`,
    /// which carries nothing to print.
    #[test]
    fn no_wording_of_a_secret_event_can_carry_its_value() {
        let secret = Recorded::of("secret", SECRET_TEXT);
        let narratives = [
            value_created("alice", "/a/key", secret),
            value_updated("alice", "/a/key", secret, secret),
            value_updated("alice", "/a/key", Recorded::Plain("old"), secret),
            value_updated("alice", "/a/key", secret, Recorded::Plain("new")),
            value_deleted("alice", "/a/key", secret),
        ];
        for narrative in narratives {
            assert!(!narrative.contains(SECRET_TEXT), "{narrative}");
        }
    }

    #[test]
    fn a_reclassification_names_only_the_plain_side() {
        assert_eq!(
            value_updated(
                "alice",
                "/a/key",
                Recorded::Plain("visible"),
                Recorded::Secret
            ),
            "alice replaced /a/key, previously \"visible\", with a secret"
        );
        assert_eq!(
            value_updated(
                "alice",
                "/a/key",
                Recorded::Secret,
                Recorded::Plain("visible")
            ),
            "alice replaced secret /a/key with plain value \"visible\""
        );
    }

    #[test]
    fn a_long_or_multiline_value_is_quoted_bounded_and_on_one_line() {
        let long = "x".repeat(QUOTED_VALUE_CHARACTERS + 1);
        let shown = quoted(&long);
        assert!(shown.ends_with("…\""), "{shown}");
        assert_eq!(shown.chars().count(), QUOTED_VALUE_CHARACTERS + 3);

        assert_eq!(quoted("line one\nline two"), "\"line one line two\"");
    }

    #[test]
    fn a_read_states_how_many_values_it_returned_and_none_of_them() {
        assert_eq!(
            subtree_read("billing", "/billing", 1),
            "billing read subtree /billing (1 value)"
        );
        assert_eq!(
            subtree_read("billing", "/billing", 14),
            "billing read subtree /billing (14 values)"
        );
    }

    #[test]
    fn a_bulk_summary_says_what_was_left_out() {
        assert_eq!(
            subtree_replaced("alice", "/a", 1, 2, 3, 0),
            "alice replaced subtree /a: 1 created, 2 changed, 3 deleted"
        );
        assert_eq!(
            subtree_replaced("alice", "/a", 1, 2, 3, 4),
            "alice replaced subtree /a: 1 created, 2 changed, 3 deleted; 4 changes not recorded individually"
        );
        assert_eq!(
            subtree_deleted("alice", "/a", 5, 1),
            "alice deleted 5 values at or below /a; 1 deletion not recorded individually"
        );
    }
}
