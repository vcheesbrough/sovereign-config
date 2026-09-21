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
