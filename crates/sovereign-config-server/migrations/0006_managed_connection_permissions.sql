-- Selectable permission set granted to a managed application connection.
--
-- Each connection carries a non-empty, canonically ordered set of the
-- permissions {read, write, manage} on its root, chosen by the operator at
-- creation. Existing connections were provisioned read-only, so the column
-- defaults to 'read', which correctly backfills every pre-existing row.
--
-- The stored form is the canonical comma-separated token list produced by
-- core's `ManagedPermissions::as_storage`; the CHECK enumerates exactly the
-- seven valid non-empty subsets in canonical (read < write < manage) order.
ALTER TABLE managed_connections
    ADD COLUMN permissions TEXT NOT NULL DEFAULT 'read'
        CHECK (
            permissions IN (
                'read',
                'write',
                'manage',
                'read,write',
                'read,manage',
                'write,manage',
                'read,write,manage'
            )
        );
