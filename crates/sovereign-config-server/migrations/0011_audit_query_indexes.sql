-- Indexes for reading the audit trail back (card #407, protocol `v4`'s
-- `QueryAuditTrail`).
--
-- The path and narrative filters match a fragment anywhere in the text, which a
-- btree cannot serve — `text_pattern_ops` only helps a left-anchored prefix —
-- so both are trigram indexes. `pg_trgm` ships with PostgreSQL's contrib
-- modules, which the official image includes, and has been a *trusted*
-- extension since PostgreSQL 13: a role with `CREATE` on the database may
-- create it without superuser. The deployed role is the image's bootstrap role
-- (`POSTGRES_USER` in `compose.yaml`), which owns the database in every
-- environment, so this cannot fail on privilege. It is `IF NOT EXISTS` so an
-- operator who pre-installed it is not refused.
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX audit_events_path_fold_trgm_idx
    ON audit_events USING GIN (path_fold gin_trgm_ops);

CREATE INDEX audit_events_narrative_trgm_idx
    ON audit_events USING GIN (narrative gin_trgm_ops);

-- The query pages on `(first_occurred_at, id)`, newest first. Not on
-- `occurred_at`, which a coalesced row moves forward every time its window is
-- bumped: a keyset over a moving key skips a row that moves past the cursor
-- mid-scroll. `first_occurred_at` and `id` never change once written.
CREATE INDEX audit_events_first_occurred_idx
    ON audit_events (first_occurred_at DESC, id DESC);

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
