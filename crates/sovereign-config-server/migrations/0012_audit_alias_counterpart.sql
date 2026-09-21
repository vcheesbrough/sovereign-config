-- Card #407, from review of PR #35: alias events and who may see them.
--
-- The other path of an alias event. `value.path_added` is filed on both paths
-- of an alias, and each event's narrative names the other one — so an event is
-- only visible to a caller who may read both, or the trail would disclose a
-- path name the rest of the service deliberately hides. It is stored as its own
-- column so visibility is decided in the query, not by reading the sentence.
ALTER TABLE audit_events
    ADD COLUMN counterpart_display_path TEXT COLLATE "C"
        CHECK (
            counterpart_display_path IS NULL
            OR counterpart_display_path ~ '^/[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$'
        ),
    ADD COLUMN counterpart_fold TEXT COLLATE "C"
        GENERATED ALWAYS AS (lower(counterpart_display_path)) STORED,
    ADD CHECK (counterpart_display_path IS NULL OR kind = 'value.path_added');

-- Events recorded before this migration: both alias narratives end with the
-- other path ("… as a path to the value at /a", "… exposed the value at /b at
-- /a"), and a path contains no space.
UPDATE audit_events
SET counterpart_display_path = substring(narrative FROM ' (/[A-Za-z0-9_/-]+)$')
WHERE kind = 'value.path_added';
