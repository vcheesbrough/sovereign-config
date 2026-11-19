-- Card #576: which identity provider this deployment's accounts belong to.
-- `managed_connections.provider_user_id`, `provider_user_uid` and
-- `credential_identifier`, and the audit trail's `actor_subject`, mean
-- something only to the provider that issued them, and from 2.56.0 the
-- provider is chosen by `SOVEREIGN_CONFIG_IDENTITY_PROVIDER` at launch. The
-- server records the chosen provider's name here at its first start and
-- refuses to start under another afterwards, so a changed setting cannot
-- orphan every stored account: changing provider is a migration of those
-- values, not a setting. No row means no start has recorded one yet.
CREATE TABLE identity_provider (
    -- At most one row.
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE
        CHECK (singleton),
    -- One of the names the server was built with, never operator text.
    name TEXT NOT NULL
        CHECK (name <> '' AND char_length(name) <= 64)
);
