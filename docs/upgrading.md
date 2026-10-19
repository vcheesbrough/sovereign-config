# Upgrading

Upgrading the server alone is always safe for clients on a supported protocol version: each client negotiates a version the server still serves (see [Protocol versioning](protocol-versioning.md)). Some releases nevertheless need sequencing, because a change can break older clients without being a protocol change, or because a migration constrains a rollback. Those releases are listed under [Release notes](#release-notes); read every note between your current release and the target before upgrading.

## Upgrade procedure

1. Stop Sovereign Config traffic at the reverse proxy, then stop the old Sovereign Config container while leaving PostgreSQL running, and verify no old server process remains before migration.
2. Verify a recoverable PostgreSQL backup from encrypted backup/staging storage.
3. Set `SOVEREIGN_CONFIG_IMAGE_TAG` to the new published tag and run `docker compose up -d`.
4. The service applies its forward-only migrations before accepting requests.
5. Validate native gRPC health/version and `/readyz` through the trusted internal network before restoring traffic.

Downgrades after a migration are unsupported. Restore the verified PostgreSQL backup into a replacement deployment instead. Exercise a new release against a non-production copy of your database before upgrading production.

## Release notes

Notes for releases that change what an operator or a client sees, oldest first. A release not listed here needs no special handling.

### Before 2.13

The rooted-path migration deletes every existing configuration value because prior releases stored unrooted paths; recreate required values at their absolute paths after deployment. The multi-path migration separates stored content from its access paths and drops the previous single-table layout, so a release earlier than 2.13 cannot run against a migrated database at all; verify the backup before applying it.

### 2.14.0 encrypts secret values at rest

Release 2.14.0 requires the value encryption key (`SOVEREIGN_CONFIG_VALUE_ENCRYPTION_KEY` or `VALUE_ENCRYPTION_KEY_FILE`); the server refuses to start without it. On first start with this key, the server seals any secrets still stored in plaintext from an earlier release. That step is one-way as far as older images are concerned: a version predating value encryption will return ciphertext instead of secrets, so rolling back past it means restoring a pre-upgrade dump. Back up the key before the first start.

### 2.15.0 widens the canonical path grammar

Release 2.15.0 adds `_` to the path segment character set, so the canonical grammar becomes `/` or `^/[a-z0-9_-]+(/[a-z0-9_-]+)*$`. This is a widening of the `v3` protocol's behaviour rather than a signature change: every previously valid path stays valid, no stored data is rewritten, and no request or response type changes.

It is **not** backward compatible for clients. A CLI, MCP server, or `sovereign-config-provider` build older than 2.15.0 rejects a path containing `_` as non-canonical and surfaces it as an opaque internal error. Because list, subtree, and path-query responses are validated as a whole, a single underscored path makes an older client fail every read of the namespace containing it — not just that one value.

Sequence the rollout accordingly:

1. Deploy the 2.15.0 server. Existing clients keep working, because no underscored path exists yet.
2. Reinstall every CLI and MCP client from the upgraded server's `/dist` installer, and rebuild every `sovereign-config-provider` consumer against tag 2.15.0 or later.
3. Only then create the first path containing `_`.

A database that has applied migration `0008` cannot be served by a release earlier than 2.15.0 once an underscored path exists, because that server would reject its own stored data.

### 2.18.0 retains path letter case

Release 2.18.0 stops discarding the letter case a path was written with. The canonical grammar and resolution behaviour are unchanged: paths are still ASCII case-insensitive, `/x/FOO` and `/x/foo` are still the same value, and the service still folds ASCII letters to one lowercase key for uniqueness, lookup, and authorization. What changes is that a path-carrying response field — `ListedValue.path`, `ListedValue.alias_paths`, `ListValuesResponse.paths`, `SubTreeValue.path`, `ListValuePathsResponse` — may now return the mixed case a path was actually stored with, instead of always being lowercase. This is an additive `v3` change: message signatures and datatypes are unchanged, and every path stored before 2.18.0 is already all-lowercase and behaves identically.

It is **not** backward compatible for clients that assumed every response path was already lowercase and therefore compared or stripped it byte-exactly. A CLI, MCP server, `sovereign-config-provider` consumer, or Woodpecker broker build older than 2.18.0 rejects a response containing a mixed-case path as invalid and fails the whole request it arrived in — the same failure shape as the 2.15.0 underscore widening, for the same reason: these clients parse every response path with the strict, already-canonical parser.

Sequence the rollout accordingly:

1. Deploy the 2.18.0 server. Existing clients keep working, because no path has ever been written with mixed case.
2. Reinstall every CLI and MCP client from the upgraded server's `/dist` installer, and rebuild every `sovereign-config-provider` and Woodpecker broker consumer against tag 2.18.0 or later.
3. Only then write a path with a letter in anything other than lowercase.

Downgrading either the **server** or a **client** below 2.18.0 is not safe once a path exists with any letter case other than lowercase. Migration `0009` repurposes `configuration_paths.path` from the fold key it held before into the exact case a value was written with, and adds a generated `lowercase_path` column as the fold key in its place. A pre-2.18.0 server binds every lookup, collision check, and write against `path` on the assumption that it is already the fold key — once a row's `path` carries real mixed case, those byte-exact comparisons miss it (`NotFound` on a read) or collide with it (a unique-constraint failure on `lowercase_path` on a write), for the same reason a pre-2.18.0 client fails the whole response it parses.

### 2.25.0 widens `GetVersion`

Release 2.25.0 changes what `System.GetVersion` does, inside the already-released `sovereign.config.v3` package and with no protocol version bump. Before 2.25.0 it returned `FAILED_PRECONDITION` for any requested version other than the server's own. From 2.25.0 it **never rejects**: it answers `grpc-status: 0` with `supported_protocol_versions` listing what the server serves, and echoes the requested version only when that version is served — otherwise the server's newest. It also adds the additive `supported_protocol_versions` field. See [Protocol versioning](protocol-versioning.md) for the mechanism this enables.

This is a deliberate exception to the rule, stated in that section, that changing what an existing RPC does requires a new package. It was made in place because a client has no other way to learn which versions a server serves: a rejection tells it only that *its* version is unwelcome, which is what forced servers and clients to be upgraded in lockstep. Shipping it as `v4` would have required every existing client to reach `v4` before benefiting, reproducing the flag-day problem it exists to remove. It was approved explicitly before implementation, as the project requires of any protocol change, and is recorded here because a rule with an unrecorded exception reads as a rule that is negotiable.

It is backward compatible for every client built from this repository, because none of them treats `grpc-status: 0` as acceptance, so all still fail closed. A build older than 2.25.0 compares the **echoed** `protocol_version` against the single version it speaks: asking for `v2` it receives `v3` back, sees a mismatch, and reports an incompatible protocol exactly as before. A 2.25.0 or later build selects from `supported_protocol_versions` and reports an incompatible protocol when that set shares nothing with its own.

It is **not** backward compatible for a third-party client that treats a successful `GetVersion` as acceptance and never reads the echo. Such a client used to be stopped at the handshake by `FAILED_PRECONDITION`; it now receives `grpc-status: 0`, concludes its version was accepted, and proceeds to issue RPCs on a protocol the server does not serve, failing later and less clearly with `UNIMPLEMENTED`. The echoed `protocol_version` has always been the documented answer to "which version is this session speaking", so the fix on the client side is to read it. No such client is known, and no rollout sequencing is required.

### 2.26.0 changes the client crates' API

Release 2.26.0 makes every client dial the version it negotiates. **No wire contract changes** — no `.proto` edit, no change to what any RPC does, and a 2.26.0 client and an older one negotiate against a server identically. Deploying the server needs no client change, as always.

It is, however, **source-breaking for code that builds against these crates**, which is the class [Protocol versioning](protocol-versioning.md) warns about: a change can break clients without being a protocol change. Nothing breaks until a consumer rebuilds against tag 2.26.0 or later, and the migration is mechanical:

- `TonicTransport::connect(endpoint)` → `TonicChannel::connect(endpoint)`, then `channel.speaking(negotiate(&channel).await?.protocol_version)` for a transport that can carry configuration traffic. A channel can only negotiate; naming the negotiated version is what produces a usable transport, which is what keeps a reported version and a dialled route the same thing.
- `Client::service_status()` → the free function `sovereign_config_client::negotiate(&channel)`.
- `Transport::get_version` moves to the new `Handshake` trait and now takes a `ProtocolVersion` rather than a `&str`, because `GetVersion` is itself routed by version. Only code implementing `Transport` by hand is affected; `sovereign-config-provider` consumers are not.

`sovereign-config-provider`'s own API is unchanged, and it gains `Provider::protocol_version()` — worth logging at startup, since it is the version the service's per-version counters attribute the application to.

### 2.28.0 adopts the unversioned handshake

Release 2.28.0 moves negotiation onto a **new unversioned service**, `sovereign.config.Handshake`, and gives a request for a version the server does not serve a **distinct error** instead of tonic's generic `UNIMPLEMENTED`. Both are protocol changes, approved before implementation as the project requires of any protocol change. Neither touches `proto/sovereign/config/v3/`: no `v3` signature, and no `v3` behaviour, changed.

**For deployed clients, nothing changes at connect.** A 2.25–2.27 client negotiates by calling `GetVersion` on `v3`'s own route, which is still served, still unauthenticated, and still echoes the version it was asked for. Upgrading the server alone remains safe, as always.

**The catch-all is the 2.15.0 / 2.18.0 class of change**, and is called out for it: it alters what an already-deployed client receives on a route it may one day hit, and negotiation cannot protect a client that is already in the field. The blast radius is nil in practice, because every client from 2.25 on maps `FAILED_PRECONDITION` and `UNIMPLEMENTED` to the same incompatible-protocol error, so one of them meets the new answer exactly as it meets a deleted route today. That is asserted, not assumed, by `a_client_that_predates_the_catch_all_still_reports_incompatible_protocol`.

It is **source-breaking for code that builds against the client crates**, the same class as 2.26.0. Nothing breaks until a consumer rebuilds against tag 2.28.0 or later:

- `Handshake` is now two methods: `served_versions(&[ProtocolVersion])`, which calls the unversioned handshake, and `legacy_version()`, which calls `GetVersion` on `ProtocolVersion::LEGACY`'s route for a server that has no handshake. `Handshake::get_version(version)` is gone.
- `negotiate` returns a `ServiceStatus` carrying `protocol_version` and an optional `deprecation_date`. It no longer carries `application_version`: the handshake carries versions and nothing else, so the service's release version is read from `System.GetVersion` on the negotiated route — `TonicTransport::dialer_version()` natively, `SessionTransport::get_version()` through a dialer.
- `ProtocolVersion` is declared **most preferred first** and no longer derives `Ord`. Nothing compares versions: selection follows the server's order.
- `ClientError::message()` returns `&str` rather than `&'static str`, because the incompatible-version error now names the version lists both ends offered, which cannot be known at compile time. It is bounded and stripped before it is built.
- `ErrorKind` gains `VersionNotServed`, distinct from `IncompatibleProtocol`. Exhaustive matches on `ErrorKind` must handle it.
- `sovereign-config-mcp`'s `Backend::service_status` returns a `ServiceReport` rather than a `ServiceStatus`, and `ToolFailure::message` is a `String`.

`sovereign-config-provider`'s own API is unchanged. Its documented **fail-fast-on-retirement contract is reversed**, however: a provider whose negotiated version is retired under it now re-handshakes once and retries the load, rather than failing. The retry is safe because the rejected call never executed, and the retirement stays observable through the logged version change and the per-version counters. See [How negotiation works](protocol-versioning.md#how-negotiation-works).


### 2.29.0 makes `RevealSecret` fail closed on an audit fault

Release 2.29.0 adds the [audit trail](audit-trail.md), and with it the second recorded exception to the rule that changing what an existing RPC does requires a new package. `v3`'s `RevealSecret` now writes an audit record before it returns a secret, and **fails the reveal if that record cannot be written**. It used to perform no writes at all.

What a client sees is unchanged: the failure is `UNAVAILABLE` with the message `configuration storage is unavailable`, exactly the status the RPC already returned when its own read failed, and the success path is byte-identical. What changes is **which faults produce it**. A database that still serves reads but refuses writes — disk full, a failover that leaves it read-only, a fault on the `audit_events` table — used to leave reveals working and now fails them. That is new behaviour on a released package, so it is recorded here rather than argued away.

It was made in place rather than as `v4` because it cannot be confined to a version. Recording that only happened on some protocol version would make every other version a way around the trail, which would defeat it. The alternative that avoids the exception — recording reveals best effort, as plain reads are — was considered and rejected: an unrecorded secret access is the one thing the trail exists to prevent, and a fault that silently stops recording secret access is exactly when it matters most. It was approved explicitly, during review of the change and before it merged; unlike 2.25.0 it was not approved before implementation, which is recorded because that is what happened.

**Who it can affect:** any client that reveals secrets, which includes every application embedding the provider. During a write-refusing fault, a provider load that needs a secret fails where it previously succeeded, and so does starting any such application, since the provider holds no last-known-good configuration. The provider already treats `UNAVAILABLE` as a failed load, so nothing misbehaves; it fails, visibly and for the reason stated. `sovereign_config_audit_events_total{kind="secret.revealed",outcome="failed"}` counts each one, and is the series to alert on. No rollout sequencing is required.

Changes (`PutValue`, `ReplaceSubTree`, `DeleteValues`, `AddValuePath`) also record inside their transactions and fail closed, but they are not part of this exception: they already wrote, and already failed when the database refused a write. `GetSubTree` and `ListValues` record best effort, and gain no failure mode at all.

### 2.31.0 introduces protocol `v4`

Release 2.31.0 serves `sovereign.config.v4` beside `v3`, the first time two protocol versions have been served at once. It was approved explicitly before implementation, as the project requires of any protocol change. `v3` is untouched: no `v3` signature and no `v3` behaviour changed, and a `v3` client negotiates, dials and fails exactly as before. `v4` is described under [Served versions](protocol-versioning.md#served-versions).

**Deploying the server needs no client change.** Clients built from 2.31.0 negotiate `v4` automatically; everything older continues on `v3`. The browser UI is served by the same release, so it moves to `v4` with the server.

Migration `0011` creates the `pg_trgm` extension for the audit query's filter indexes. It is a trusted extension, so it needs `CREATE` on the database rather than superuser, and the deployed role — the image's bootstrap role — owns the database in every environment. A deployment that connects as a role without `CREATE` must have an administrator run `CREATE EXTENSION pg_trgm` first, or the server stops at startup.

It is **source-breaking for code that builds against the client crates**, the same class as 2.26.0 and 2.28.0. Nothing breaks until a consumer rebuilds against tag 2.31.0 or later:

- `ProtocolVersion` gains `V4`, declared first, and `ProtocolVersion::PREFERRED` is now `V4`. An exhaustive `match` on `ProtocolVersion` must handle it.
- `SessionTransport` now also requires `AuditTransport`. Only code implementing a dialer by hand is affected; the dialers in this workspace implement it, and a `v3` one answers an audit query with a bounded incompatible-protocol error without dialling.

`sovereign-config-provider`'s own API is unchanged.

### 2.42.0 repairs past managed actor names

Release 2.42.0 names a managed connection's account after the connection, and its tokens carry that name (see [Audit trail](audit-trail.md)). Going forward this is no protocol change: `v4`'s `AuditEvent.actor_name` is still what the identity provider said at the time. The same is true of a person using the CLI or MCP server: the identity provider now signs their username even though those clients never request `profile`, so their new events are named. Their past events are not repaired. The **one-time repair of past events** is the third recorded exception to the rule that changing what an existing field reports requires a new package. For events recorded before the fix by a connection that still exists, `actor_name` now holds `<display name> (access URL)`, a name the identity provider never sent at the time. Before, it held nothing (the subject was shown) or the account's generated username. The narrative's leading actor changes with it, so a narrative search over those events matches the new name and no longer the old one.

It was made in place because a new version cannot confine it. The rows are shared, so every version that reads them would see the same repaired values, and the only way to keep `v4`'s literal contract is to leave the bug in the trail for good. The owner chose to repair it so the trail reads as if the bug never existed. Nothing is lost: each repaired row keeps what it recorded in `recorded_actor_name` and `recorded_narrative`, which are never served, and the server logs per connection how many events it renamed.

**Who it can affect:** a `v4` reader of past audit events by access URLs. It now sees the connection's name where it saw an opaque subject or a generated username. A reader that matched on the old value, such as a saved narrative search for a subject, finds those events under the new name instead. No status, field or RPC changes. The repair runs once per environment and only touches events of connections that still exist.


### 2.44.0 puts managed connections behind an identity-provider interface

Release 2.44.0 moves the Authentik administration client behind a provider-neutral interface. Nothing changes on the wire, and access URLs are byte-identical. Two things affect an upgrade.

**Migration 0014 is one-way.** It changes `managed_connections.provider_user_id` from an integer to text, keeping every existing value as its decimal digits. Once it has run, a 2.43 server can't start against that database. Back up PostgreSQL before upgrading, as the [procedure](#upgrade-procedure) says. Rolling back means restoring that backup, not running an older image.

**The access URL's client id is checked at startup.** Access URLs name an OAuth client: `SOVEREIGN_CONFIG_MANAGER_CLIENT_ID`, new and optional, which defaults to `SOVEREIGN_CONFIG_OIDC_AUDIENCE`. That client id must contain only ASCII letters, digits, `-`, `.`, `_` and `~`, or the server refuses to start and names the variable to fix. Before, an audience outside that set started the server and broke only managed create and rotate. Deployments whose audience is an Authentik client id such as `sovereign-config` need no change. If the audience is something a URL can't carry, set `SOVEREIGN_CONFIG_MANAGER_CLIENT_ID` to the client access URLs should name.
