-- The audit trail (card #373): every configuration change, every secret
-- access and every configuration read, attributed to the identity that caused
-- it and the protocol version it arrived on.
--
-- One invariant outranks every other in this table: **no secret value is ever
-- stored here.** `old_value` and `new_value` hold plain content only, and the
-- constraint below confines them to the three event kinds that describe a
-- single value changing — a read or a secret access cannot carry a value even
-- if a future code path tries to give it one. The narrative is rendered by the
-- server from the same plain-only inputs.
--
-- A row is either one event (`coalesce_digest` NULL) or a window of identical
-- accesses collapsed into one (`coalesce_digest` set, `event_count` > 1 once
-- bumped). Changes never coalesce. `occurred_at` is the most recent occurrence
-- and `first_occurred_at` the window's first; the count and the period are
-- rendered when a row is served, never stored in `narrative`, so bumping a
-- window stays a single-statement upsert rather than a read-modify-write.
CREATE TABLE audit_events (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL,
    first_occurred_at TIMESTAMPTZ NOT NULL,
    event_count INTEGER NOT NULL DEFAULT 1
        CHECK (event_count >= 1),
    kind TEXT COLLATE "C" NOT NULL
        CHECK (
            kind IN (
                'value.created',
                'value.updated',
                'value.deleted',
                'value.path_added',
                'subtree.replaced',
                'subtree.deleted',
                'secret.revealed',
                'subtree.read',
                'values.listed',
                'connection.created',
                'connection.rotated',
                'connection.revoked'
            )
        ),
    -- The path as the caller wrote it. `/` is legal: a subtree read or a
    -- listing may select the root.
    display_path TEXT COLLATE "C" NOT NULL
        CHECK (display_path = '/' OR display_path ~ '^/[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$'),
    -- What filters and authorization match on. Generated, as
    -- `configuration_paths.lowercase_path` is, so it can never drift from the
    -- path it folds.
    path_fold TEXT COLLATE "C"
        GENERATED ALWAYS AS (lower(display_path)) STORED,
    -- The stable identity, and the name it went by when the event happened. The
    -- name is captured rather than joined so a later rename cannot rewrite
    -- history; it is NULL when the identity provider supplied none.
    actor_subject TEXT NOT NULL
        CHECK (actor_subject <> ''),
    actor_name TEXT
        CHECK (actor_name IS NULL OR actor_name <> ''),
    -- The served-version label of the route the call was dialled on.
    protocol_version TEXT COLLATE "C" NOT NULL
        CHECK (protocol_version ~ '^[a-z0-9]{1,32}$'),
    old_value TEXT,
    new_value TEXT,
    narrative TEXT NOT NULL
        CHECK (narrative <> ''),
    -- A digest of (kind, protocol version, window, path, actor). A digest
    -- rather than the components themselves so an unusually long subject or
    -- path can never exceed the index row limit and turn an audit write — and
    -- with it a secret access — into a failure.
    coalesce_digest TEXT COLLATE "C" UNIQUE
        CHECK (coalesce_digest IS NULL OR coalesce_digest ~ '^[0-9a-f]{64}$'),
    CHECK (occurred_at >= first_occurred_at),
    CHECK (coalesce_digest IS NOT NULL OR event_count = 1),
    CHECK (
        kind IN ('value.created', 'value.updated', 'value.deleted')
        OR (old_value IS NULL AND new_value IS NULL)
    )
);

-- Keyset paging, newest first, and the retention sweep's range delete. The
-- partial-match indexes the query API will want belong to the card that adds
-- that query (#407): they need the `pg_trgm` extension, and a migration that
-- cannot create an extension stops the server at startup.
CREATE INDEX audit_events_occurred_idx ON audit_events (occurred_at DESC, id DESC);
