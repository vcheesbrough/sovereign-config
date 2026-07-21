-- Non-secret lifecycle metadata for managed application connections.
--
-- The table stores no connection URL, credential, or provider response
-- content. External Authentik identifiers are opaque references required
-- for lifecycle reconciliation only.
CREATE TABLE managed_connections (
    connection_id TEXT COLLATE "C" PRIMARY KEY
        CHECK (connection_id ~ '^[a-z0-9]{16,64}$'),
    display_name TEXT NOT NULL
        CHECK (
            display_name <> ''
            AND length(display_name) <= 100
            AND display_name !~ '^[[:space:]]'
            AND display_name !~ '[[:space:]]$'
            AND display_name !~ '[[:cntrl:]]'
        ),
    root TEXT COLLATE "C" NOT NULL
        CHECK (root = '/' OR root ~ '^/[a-z0-9-]+(/[a-z0-9-]+)*$'),
    provider_user_id BIGINT,
    provider_user_uid TEXT
        CHECK (provider_user_uid IS NULL OR length(provider_user_uid) <= 128),
    credential_identifier TEXT
        CHECK (
            credential_identifier IS NULL
            OR (credential_identifier <> '' AND length(credential_identifier) <= 128)
        ),
    state TEXT NOT NULL
        CHECK (
            state IN (
                'provisioning',
                'active',
                'rotation_unknown',
                'revoking',
                'cleanup_required'
            )
        ),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (updated_at >= created_at)
);

CREATE INDEX managed_connections_root_idx ON managed_connections (root);
