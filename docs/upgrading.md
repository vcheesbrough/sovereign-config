# Upgrading

## Procedure

Run these where you run `docker compose` for the deployment, with its environment set.

1. Read the [notes](#releases-that-need-action) for every release after yours, up to and including the target.
2. Back up the database:

   ```sh
   docker compose exec -T postgres pg_dump -U sovereign_config -Fc sovereign_config > sovereign-config-backup.dump
   ```

   Secret values in the dump are sealed with the value encryption key. Keep the key with the dump.
3. Upgrade:

   ```sh
   export SOVEREIGN_CONFIG_IMAGE_TAG=<version>
   docker compose up -d --pull always --wait
   ```

   The server migrates the database before it reports healthy. `--wait` returns once it does, or fails.
4. Check the running version: `curl -s https://<host>/dist/manifest.json` lists installers named for it.

**Rolling back.** Migrations are forward-only, so an older image cannot run against a migrated database. Restore the backup into a new volume and start the older version there:

```sh
docker compose down
docker volume create sovereign-config-rollback-db
export POSTGRES_DATA_VOLUME=sovereign-config-rollback-db SOVEREIGN_CONFIG_IMAGE_TAG=<older version>
docker compose up -d --wait postgres
docker compose exec -T postgres pg_restore -U sovereign_config -d sovereign_config < sovereign-config-backup.dump
docker compose up -d --wait
```

**Clients.** Upgrading the server alone is safe for clients on a protocol version it still serves. The notes below say when clients must move before or after the server.

## Releases that need action

Newest first. A release not listed needs nothing beyond the procedure.

### 2.49.3: the image moved to GHCR

The image is `ghcr.io/vcheesbrough/sovereign-config`, public. Take `compose.yaml` from 2.49.3 or later, or change your own `image:` line. Releases before 2.49 are not on GHCR, except 2.48.428 and 2.46.418.

### 2.46.415: protocol `v5`

No action. Migration `0015` adds two indexes to `audit_events`, so the first start takes longer on a large audit trail. Clients from 2.46 negotiate `v5`; older ones keep their version.

### 2.44.396: one-way migration, client id checked at startup

- Migration `0014` changes `managed_connections.provider_user_id` to text. A 2.43 server cannot start against the migrated database. Roll back only by restoring the backup.
- The server refuses to start unless the access URLs' client id (`SOVEREIGN_CONFIG_MANAGER_CLIENT_ID`, default `SOVEREIGN_CONFIG_OIDC_AUDIENCE`) contains only ASCII letters, digits, `-`, `.`, `_` and `~`. With Authentik it must equal the audience. Leave `SOVEREIGN_CONFIG_MANAGER_CLIENT_ID` unset with Authentik.

### 2.42.372: past audit events renamed

No action. Audit events recorded by access URLs that still exist now name their actor `<display name> (access URL)`, where they showed a subject or a generated username. A saved search for the old value no longer matches them. The original values are kept, unserved, in `recorded_actor_name` and `recorded_narrative`.

### 2.31.0: protocol `v4`, `pg_trgm` required

Migration `0011` runs `CREATE EXTENSION pg_trgm`. The database role needs `CREATE` on the database (the bundled PostgreSQL's role has it). Otherwise have an administrator create the extension first, or the server stops at startup.

### 2.29.0: secret reveals fail when the audit trail cannot be written

No action. If the database serves reads but refuses writes, `RevealSecret` now fails with `UNAVAILABLE`, and so does any provider load that needs a secret. Alert on `sovereign_config_audit_events_total{kind="secret.revealed",outcome="failed"}`.

### 2.25.0: `GetVersion` never rejects

No action for clients from this repository. A third-party client that treats a successful `GetVersion` as acceptance must read the echoed `protocol_version` instead.

### 2.18.0: paths keep their letter case

Clients older than 2.18.0 fail every request whose response contains a mixed-case path. In order:

1. Upgrade the server.
2. Reinstall every CLI and MCP client from the server's `/dist`, and rebuild every provider and Woodpecker broker against 2.18.0 or later.
3. Only then write a path with an upper-case letter.

Once such a path exists, neither the server nor a client can go below 2.18.0.

### 2.15.0: `_` allowed in paths

Clients older than 2.15.0 fail every read of a namespace that contains a path with `_`. In order:

1. Upgrade the server.
2. Reinstall every CLI and MCP client from the server's `/dist`, and rebuild every provider against 2.15.0 or later.
3. Only then create a path with `_`.

Once such a path exists, neither the server nor a client can go below 2.15.0.

### 2.14.0: secrets encrypted at rest

Set `SOVEREIGN_CONFIG_VALUE_ENCRYPTION_KEY` or `SOVEREIGN_CONFIG_VALUE_ENCRYPTION_KEY_FILE` (in `compose.yaml`, the `VALUE_ENCRYPTION_KEY_FILE` secret). The server refuses to start without it. Back up the key before the first start. The first start seals existing plaintext secrets, so rolling back past 2.14.0 means restoring a backup.

### Before 2.13

Migration `0003` deletes every stored value: recreate them at absolute paths afterwards. Migration `0007` replaces the single-table layout, after which no release before 2.13 can run against the database.

## Rust crate changes

These break code that builds against the client crates, not deployed clients. Nothing breaks until you rebuild against the release. Newest first. `sovereign-config-provider`'s own API has not changed.

- **2.46.415:** `ProtocolVersion` gains `V5`, now `PREFERRED`. `AuditQuery` gains `actor_filter` and `AuditPage` gains `counts`: struct literals must set them or use `..Default::default()`. On a `v4` session, a query with an `actor_filter` fails as incompatible.
- **2.31.0:** `ProtocolVersion` gains `V4`, then `PREFERRED`. `SessionTransport` also requires `AuditTransport`.
- **2.28.0:**
  - `Handshake` is `served_versions(&[ProtocolVersion])` and `legacy_version()`. `get_version` is gone.
  - `negotiate` returns `protocol_version` and an optional `deprecation_date`. Read the application version from `TonicTransport::dialer_version()` or `SessionTransport::get_version()`.
  - `ProtocolVersion` is ordered most preferred first and no longer derives `Ord`.
  - `ClientError::message()` returns `&str`.
  - `ErrorKind` gains `VersionNotServed`.
  - In `sovereign-config-mcp`, `Backend::service_status` returns `ServiceReport`, and `ToolFailure::message` is a `String`.
  - A provider whose version is retired re-handshakes once and retries, instead of failing.
- **2.26.0:**
  - `TonicTransport::connect(endpoint)` becomes `TonicChannel::connect(endpoint)` followed by `channel.speaking(negotiate(&channel).await?.protocol_version)`.
  - `Client::service_status()` becomes `sovereign_config_client::negotiate(&channel)`.
  - `Transport::get_version` moves to `Handshake` and takes a `ProtocolVersion`.
  - `Provider::protocol_version()` is new.
