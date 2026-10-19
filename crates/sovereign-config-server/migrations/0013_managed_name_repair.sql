-- Card #440: whether the one-time repair of managed connections' names has
-- completed. Until 2.42.0 a managed connection's account went by its generated
-- username and its tokens carried no name, so the audit trail recorded its
-- access by an opaque subject. The server repairs that at startup (accounts
-- named after their connections, past events renamed), and records here that
-- it is done, so it rewrites recorded history exactly once rather than at
-- every start. No row means not yet completed; an interrupted or partly
-- failed repair writes none, and the next start retries it.
CREATE TABLE managed_name_repair (
    -- At most one row.
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE
        CHECK (singleton),
    completed_at TIMESTAMPTZ NOT NULL
);

-- What the repair overwrote, kept beside it so the rewrite stays auditable
-- and reversible. This supersedes, for repaired rows only, 0010's "the name
-- is captured rather than joined so a later rename cannot rewrite history":
-- the repair is the one rewrite the trail allows, and these columns are its
-- record. `recorded_narrative` is set on exactly the repaired rows (a
-- narrative is never empty), with `recorded_actor_name` the name the row
-- carried before, NULL when it carried none. Neither is ever served: the
-- trail shows the repaired values.
ALTER TABLE audit_events
    ADD COLUMN recorded_actor_name TEXT,
    ADD COLUMN recorded_narrative TEXT,
    ADD CHECK (recorded_narrative IS NOT NULL OR recorded_actor_name IS NULL);
