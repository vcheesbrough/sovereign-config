-- Card #483: protocol `v5`'s `QueryAuditTrailRequest.actor_filter` matches a
-- fragment anywhere in the actor's subject or recorded name, which, like the
-- path and narrative filters (0011), only a trigram index can serve. One index
-- per column: the filter ORs them, which the planner answers with a
-- `BitmapOr` over both. `pg_trgm` is already installed by 0011.
CREATE INDEX audit_events_actor_subject_trgm_idx
    ON audit_events USING GIN (actor_subject gin_trgm_ops);

CREATE INDEX audit_events_actor_name_trgm_idx
    ON audit_events USING GIN (actor_name gin_trgm_ops);
