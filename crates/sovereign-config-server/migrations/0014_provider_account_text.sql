-- Card #381: a managed connection's account identifier is the identity
-- provider's, opaque to the server (`sovereign_config_identity::AccountId`).
-- 0005 stored it as Authentik's integer primary key; it is now text, bounded
-- and non-empty like `provider_user_uid` and `credential_identifier` beside
-- it, so any provider's identifier fits and #410 can carry it as a string.
-- Existing rows keep their key, as its decimal text, which is exactly what
-- the Authentik implementation issues and parses.
ALTER TABLE managed_connections
    ALTER COLUMN provider_user_id TYPE TEXT USING provider_user_id::text,
    ADD CHECK (
        provider_user_id IS NULL
        OR (provider_user_id <> '' AND length(provider_user_id) <= 128)
    );
