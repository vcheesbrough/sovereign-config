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
