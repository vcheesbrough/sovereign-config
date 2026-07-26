-- Widen the canonical path grammar to permit `_` in segments (card #270).
--
-- Woodpecker CI matches `from_secret:` names by exact lowercased string with no
-- `_`/`-` normalisation, and its established secret names are underscored
-- (github_token, zot_ci_user, authentik_api_token). Brokering those through
-- Sovereign Config requires storing them verbatim as path segments.
--
-- This widens the v3 canonical grammar from `^/[a-z0-9-]+(/[a-z0-9-]+)*$` to
-- `^/[a-z0-9_-]+(/[a-z0-9_-]+)*$`. Every previously valid path stays valid, so
-- no data is rewritten. It is not reversible once an underscored path exists:
-- re-applying the old constraint would fail, and a client built before release
-- 2.15.0 rejects such a path outright.
--
-- The corresponding server-side change is that subtree matching must use
-- starts_with rather than LIKE — `_` is a single-character LIKE wildcard, so
-- `LIKE '/a/b_c/%'` would otherwise also match the sibling subtree `/a/bXc/`.
-- See crates/sovereign-config-server/src/values.rs.
--
-- Constraint names are the ones Postgres generated for the inline column CHECKs
-- in 0007 (configuration_paths) and 0005 (managed_connections), verified against
-- pg_constraint. 0002 and 0003 constrained configuration_values, which 0007
-- dropped, so they need no change.

ALTER TABLE configuration_paths
    DROP CONSTRAINT configuration_paths_path_check;

ALTER TABLE configuration_paths
    ADD CONSTRAINT configuration_paths_path_check
    CHECK (path ~ '^/[a-z0-9_-]+(/[a-z0-9_-]+)*$');

ALTER TABLE managed_connections
    DROP CONSTRAINT managed_connections_root_check;

ALTER TABLE managed_connections
    ADD CONSTRAINT managed_connections_root_check
    CHECK (root = '/' OR root ~ '^/[a-z0-9_-]+(/[a-z0-9_-]+)*$');
