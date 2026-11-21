# Upgrading

## Procedure

Run these where you run `docker compose` for the deployment, with its environment set.

1. Read the [notes](#releases-that-need-action) for every release after yours, up to and including the target.
2. Stop the server, so nothing is written after the backup, and back up the database:

   ```sh
   docker compose stop sovereign-config
   docker compose exec -T postgres pg_dump -U sovereign_config -Fc sovereign_config > sovereign-config-backup.dump
   ```

   The dump holds plain values and the audit trail unencrypted, and secret values sealed with the value encryption key. Store it as securely as the key, but not with it. A restore needs both.
3. Upgrade:

   ```sh
   export SOVEREIGN_CONFIG_IMAGE_TAG=<version>
   docker compose up -d --pull always --wait
   ```

   The server migrates the database before it reports healthy. `--wait` returns once it does, or fails. With `OTEL_RESOURCE_ATTRIBUTES` set, run the Compose plugin binary instead of `docker compose` (see [Observability](../README.md#observability)).
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

### 3.0: protocol `v6` over Connect, and the end of `v3`–`v5` announced

3.0 is a major release: the product's wire changes. Upgrading the server alone is still safe, and every client already deployed keeps working.

- **Protocol `v6`, over Connect.** The server serves a new protocol version, `v6`, over the [Connect protocol](https://connectrpc.com/docs/protocol) only: unary calls, binary or JSON, over HTTP/1.1 or HTTP/2. It also serves the handshake over Connect. Clients from 3.0 on negotiate `v6`. `v6` is `v5` with a few changes to how values are written, so that its JSON form works with `curl` and needs no generated code ([Calling v6 with curl](connect-json.md)).
- **Each version has one transport.** `v3`–`v5` are still served over native gRPC and gRPC-Web, exactly as before, and never over Connect. `v6` is never served over gRPC. A call on the wrong transport gets the version-not-served answer ([Protocol versioning](protocol-versioning.md#each-version-names-its-transport)).
- **`v3`, `v4` and `v5` are deprecated.** Each carries a `deprecation_date` of `2027-01-01T00:00:00Z` in the handshake. A client on one of them warns its operator and keeps working. Retiring them, which also retires native gRPC, gRPC-Web and the need for h2c, comes in a later release (#594). That release can ship only after the date has passed and `sovereign_config_protocol_requests_total{outcome="authenticated"}` reads zero for each of the three versions.
- **Keep h2c on the proxy for now.** A client older than 3.0 speaks native gRPC, which needs the proxy to forward HTTP/2 cleartext. Keep `loadbalancer.server.scheme=h2c`, as the reference `compose.yaml` does, until every client in use is on 3.0 or later. A 3.0 client needs no h2c: it works through a proxy that forwards HTTP/1.1 only.
- **Order.** Upgrade the server first. A 3.0 client against an older server finds no Connect handshake, falls back to gRPC, and works on `v5` or earlier. An older client against a 3.0 server sees `v6` in the handshake and skips it, because it does not speak it.

### 2.59: admins groups, and sign-in gated on them

- **Rename the contributor groups first.** In Authentik, rename `sovereign-config-production-config-contributor` to `sovereign-config-admins` and `sovereign-config-development-config-contributor` to `sovereign-config-dev-admins` **in place, before applying the 2.59 blueprint**. Renaming keeps each group's members and grant attribute. A blueprint finds its groups by name, so applying it before the rename creates a new, empty admins group, binds the application to it, and locks every operator out.
- **Then apply the 2.59 blueprint.** It declares each application's policy bindings: the environment's admins group at order 0 and its connections group (`SOVEREIGN_CONFIG_MANAGER_GROUP`) at order 1 ([Who may sign in](authentik.md#who-may-sign-in)). From then on only operators in the admins group and managed accounts can sign in. A binding that already exists with those values is left unchanged.
- **Remove any other binding by hand.** A blueprint never deletes a binding it does not declare. If an application was bound to a group such as `admins` by hand, delete that binding in Authentik, or its members keep signing in. Before you delete it, check who signs in only through it. Add an operator to the environment's admins group. Give a person who holds only narrower grants a binding of their own. Anyone else in it can no longer sign in once it is gone.
- **Creating an access URL.** A create now fails with the same "dependency is unavailable" error as any other provisioning failure, and deletes the account, when the account cannot be added to the connections group. Before, the create succeeded and returned an access URL that could not obtain a token. Clients need no change, and no protocol version changed. This is a [recorded protocol exception](protocol-versioning.md#what-forces-a-new-version-and-what-does-not).

### 2.56: the identity provider is chosen by configuration

No action. `SOVEREIGN_CONFIG_IDENTITY_PROVIDER` selects the identity provider and defaults to `authentik`, so a deployment that does not set it starts exactly as before, with the same variables, the same access URLs and the same tokens. Migration `0016` adds one small table, in which the first start records `authentik` as the deployment's provider; from then on the server refuses to start under a different provider name ([Authentication](authentication.md#choosing-the-identity-provider)). Clients need no change, and no protocol version changed.

### 2.55: containers run with less privilege

Take `compose.yaml` from 2.55 or later. The server now runs with a read-only root filesystem, no capabilities and `no-new-privileges`. PostgreSQL keeps five capabilities and loses the rest. Nothing in the database volume changes owner.

- **Secret files.** The server still runs as uid `10001`, so a secret file it owns stays readable. Its group id changed from `999` to `10001`. A secret file the server could read only through group `999` must be re-owned: `chown 10001:10001 <file>`. Files owned and moded as the [README](../README.md#3-create-the-secrets) says need nothing.
- **Your own `compose.yaml`.** Nothing is required: the image runs as `10001:10001` by itself. To harden the server, copy `user:`, `cap_drop:`, `read_only:`, `tmpfs:` and `security_opt:` from the reference file.
- **Extra mounts.** A volume you added to the server must be writable by `10001:10001`, because nothing else in the container is writable.

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

- **3.0:**
  - **The crates are now version 3.** A dependency written `"2"` (or `"^2"`) does not pick up 3.x. Change it to `"3"`.
  - `ProtocolVersion` gains `V6`, now `PREFERRED`. Add a `V6` arm to any exhaustive `match` on it.
  - `TonicChannel::connect` no longer opens a connection. An unreachable service is reported by the first call, usually the handshake, with the same `Unavailable` error as before. The channel speaks Connect for `v6` and the handshake, and native gRPC for `v3`–`v5`. The type names are unchanged.
  - The Connect transport trusts the platform's root certificates, as the gRPC transport already did.
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
