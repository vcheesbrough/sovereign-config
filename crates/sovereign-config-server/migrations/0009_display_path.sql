-- Retain the letter case a path was written with (card #294).
--
-- `path` changes meaning: it now holds the exact case a value was written
-- with, not the folded lookup key it held before. Every existing row is
-- already correct under the new meaning, because every path stored so far is
-- already all-lowercase — no backfill is needed.
--
-- `lowercase_path` is the synthetic lookup key every comparison, uniqueness
-- check, and collision check uses from here on. It is a generated column —
-- Postgres computes and stores `lower(path)` on every write and refuses any
-- attempt to write it directly — so it can never drift from `path`, which a
-- hand-maintained column and a CHECK constraint could only catch after the
-- fact. It replaces `path` as the primary key.

ALTER TABLE configuration_paths
    DROP CONSTRAINT configuration_paths_pkey;

ALTER TABLE configuration_paths
    DROP CONSTRAINT configuration_paths_path_check;

ALTER TABLE configuration_paths
    ADD CONSTRAINT configuration_paths_path_check
    CHECK (path ~ '^/[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$');

ALTER TABLE configuration_paths
    ADD COLUMN lowercase_path TEXT COLLATE "C"
    GENERATED ALWAYS AS (lower(path)) STORED
    PRIMARY KEY;
