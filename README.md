# Sovereign Config

Sovereign Config is a self-hosted configuration and secrets service. It keeps a tree of configuration values, both plain values and encrypted secrets, at absolute paths such as `/apps/api/database_url`. It authenticates every request through your own OIDC identity provider, and it records who read or changed what. People work with it through a web UI, a CLI and an MCP server. Applications and pipelines read it through narrowly scoped, revocable machine connections.

It is built for operators who want their configuration and secrets on infrastructure they control, with no cloud dependency, no telemetry they did not configure, and no outbound connection they did not ask for.

## Features

- **One tree of configuration.** Values live at case-insensitive, case-preserving absolute paths. A value can be exposed at several paths (aliases), and a whole subtree can be read or replaced atomically as JSON.
- **Secrets encrypted at rest.** Secret values are sealed with XChaCha20-Poly1305 under a key you hold. They are masked everywhere and returned in plaintext only by an explicit, authorized and audited reveal.
- **Path-scoped access control.** Grants of `read`, `write` and `manage` on a path prefix come from your identity provider and are checked on every request.
- **Access URLs for machines.** A managed connection is a single self-contained URL whose credential is confined to one subtree with exactly the permissions you choose. It can be rotated or revoked at any time.
- **Audit trail.** Every change, every secret reveal, every read and every access-URL lifecycle event is recorded with the identity behind it, kept for a year by default, and searchable from the web UI.
- **Deploy-time rendering.** `sovereign-config render` turns configuration into a command's environment without a shell, and fails closed.
- **Mixed-version operation.** Clients and server negotiate a protocol version on connect, so upgrading the server does not force every client to upgrade with it.
- **OpenTelemetry.** Spans, logs and metrics are exported over OTLP when you configure them, and nothing is exported when you don't.

## Components

| Component | What it is | How it is distributed |
| --- | --- | --- |
| Server | The gRPC and gRPC-Web service, with the web UI embedded. | Container image `sovereign-config` |
| [CLI](docs/cli.md) | `sovereign-config`: profiles, login, reads and writes, `render`. | Installer served by every server under `/downloads`; `cargo install` from a release tag |
| [MCP server](#mcp-server) | `sovereign-config-mcp`: the administration surface as Model Context Protocol tools for a local MCP host. | Installer served by every server; `cargo install` from a release tag |
| [Application provider](crates/sovereign-config-provider/README.md) | `sovereign-config-provider`: a Rust library that loads one subtree into a `serde` type. | Tagged workspace source |
| [Woodpecker secrets extension](crates/sovereign-config-woodpecker-broker/README.md) | `sovereign-config-woodpecker-broker`: serves Woodpecker CI secrets from the tree. | Container image `sovereign-config-woodpecker-broker` |
| CLI image | `docker:27-cli` with the CLI added, for CI deploy steps. | Container image `sovereign-config-cli` |

Every component is released together from one source tag under one version.

## Requirements

- **Docker with Compose** on linux/amd64. The reference stack is [`compose.yaml`](compose.yaml).
- **PostgreSQL.** The reference stack runs its own, pinned by digest. A deployment needs `CREATE` on its database, which the bundled role has.
- **Authentik 2026.5.2 or newer** as the identity provider. The repository ships Authentik blueprints that create everything the service needs (see [Authentication](docs/authentication.md)). Authentik is the only supported identity provider today; support for other OIDC providers is planned (see [Roadmap](#roadmap)).
- **A TLS-terminating reverse proxy** that forwards HTTP/2 cleartext (h2c) to the service. The reference stack is currently labelled for the author's own Traefik setup (see [step 4](#4-configure-and-start)).
- **Encrypted storage** for the database volume and for every backup.

## Concepts

- **Path.** Every value lives at an absolute path: `/` followed by segments of letters, digits, `-` and `_`. Paths are ASCII case-insensitive but case-*retentive*. `/x/FOO` and `/x/foo` are the same value, which keeps the case it was first written with.
- **Value.** A value is classified `plain` or `secret`. A secret is masked as `********` unless explicitly revealed.
- **Grant.** A grant gives a permission on a path prefix: `read` (read values and reveal secrets), `write` (put and delete values) or `manage` (administer access URLs). Replacing a subtree needs both `write` and `manage`.
- **Profile.** A profile is a named connection the CLI and MCP server keep locally: the server's endpoint, a configuration root, and how to authenticate.
- **Access URL.** An access URL is a managed connection for a machine. It is a version-1 connection URL carrying its own credential, confined to one root with exactly the grants it was created with.

## Deployment

### 1. Set up the identity provider

Apply the matching Authentik blueprint (`authentik/blueprint.yaml` for production, `authentik/blueprint-dev.yaml` for development) to your Authentik instance, substituting its `${VARIABLE}` placeholders first. It creates the OIDC provider, the grant scope mapping, the contributor group, and the restricted connection-manager service account and its API token. [Authentication](docs/authentication.md) lists every object it creates and the variables it needs. Note the blueprint's issuer URL, its client id (the audience) and the connection-manager API token. The server needs all three.

### 2. Prepare storage

The operator must pre-create the external volume named by `POSTGRES_DATA_VOLUME` that holds the PostgreSQL data directory on encrypted storage; Compose deliberately refuses to create a default volume. All backup and staging storage must be encrypted too.

The stack publishes no application, PostgreSQL, metrics, logging or tracing port. PostgreSQL sits on an internal network, and the service is reachable only through the reverse proxy on an external network. The reference stack names that network `proxy-backend`, after the author's own Traefik network.

### 3. Create the secrets

Create the secret files in an operator-controlled directory, and never commit them:

| Host variable | File contents | Owner and mode |
| --- | --- | --- |
| `POSTGRES_PASSWORD_SECRET_FILE` | Only the PostgreSQL password. | `root:root`, `0400` (read by the PostgreSQL entrypoint) |
| `DATABASE_URL_FILE` | The complete private-network URL, for example `postgresql://sovereign_config:<password>@postgres:5432/sovereign_config`. | `10001:10001`, `0400` |
| `MANAGER_API_TOKEN_FILE` | Only the Authentik connection-manager API token from the blueprint. | `10001:10001`, `0400` |
| `VALUE_ENCRYPTION_KEY_FILE` | Only the value encryption key: 32 random bytes in standard base64, from `openssl rand -base64 32`. | `10001:10001`, `0400` |

The server runs as the fixed UID `10001`, and Compose preserves host ownership for these file-backed secrets. Each server secret may instead be supplied directly through its environment variable: `SOVEREIGN_CONFIG_DATABASE_URL`, `SOVEREIGN_CONFIG_MANAGER_API_TOKEN` or `SOVEREIGN_CONFIG_VALUE_ENCRYPTION_KEY`. The variable takes precedence over the matching `_FILE`, which suits a secret manager that injects values into the environment. Startup fails with a redacted error when a required secret is absent through both routes.

**Back up the value encryption key, and keep that backup somewhere you would still have after losing the deployment.** It is the only thing that can decrypt the stored secrets; without it they are unrecoverable, no matter how good the database backups are. The server refuses to start if it finds a stored secret it cannot decrypt, rather than serving errors or sealing a second layer over intact data.

### 4. Configure and start

```sh
export SOVEREIGN_CONFIG_IMAGE_TAG='<version>'
export SOVEREIGN_CONFIG_ENV='prod'
export SOVEREIGN_CONFIG_HOST='config.example.com'
export SOVEREIGN_CONFIG_CONTAINER_NAME='sovereign-config-production'
export POSTGRES_DATA_VOLUME='sovereign-config-production-db'
export POSTGRES_PASSWORD_SECRET_FILE="$HOME/.config/sovereign-config/postgres-password"
export DATABASE_URL_FILE="$HOME/.config/sovereign-config/database-url"
export MANAGER_API_TOKEN_FILE="$HOME/.config/sovereign-config/manager-api-token"
export VALUE_ENCRYPTION_KEY_FILE="$HOME/.config/sovereign-config/value-encryption-key"
export SOVEREIGN_CONFIG_OIDC_ISSUER='https://auth.example.com/application/o/sovereign-config/'
export SOVEREIGN_CONFIG_OIDC_AUDIENCE='sovereign-config'
export SOVEREIGN_CONFIG_PUBLIC_ORIGIN='https://config.example.com'
export SOVEREIGN_CONFIG_MANAGER_GRANTS_ATTRIBUTE='sovereign_config_prod_grants'
export SOVEREIGN_CONFIG_MANAGER_GROUP='sovereign-config-connections'
docker compose up -d --wait
```

The service starts only after PostgreSQL reports healthy. It applies its forward-only database migrations before accepting requests.

> **`compose.yaml` currently depends on the author's own infrastructure.** It was written for the project's own deployment, and the image registry and reverse-proxy names below belong to that environment, not to Sovereign Config. The author intends to remove these dependencies, so that the stack runs as shipped with configuration alone (see [Roadmap](#roadmap)). Until then, adapt them to your environment.

- **The image.** It pulls `registry.desync.link/sovereign-config:<tag>` from the author's own registry. To run an image you built yourself ([Development](docs/development.md#building-and-testing)), tag it to match or change the `image:` line.
- **The reverse proxy.** The Traefik labels name parts of the author's own Traefik setup: an external network named `proxy-backend`, a `websecure` entrypoint, a certificate resolver named `myresolver`, and the middlewares `lan-vpn-only`, `rate-limit`, `crowdsec` and `security-headers`. None of these exists in a fresh Traefik. Rename them to match your Traefik, or replace the labels for another proxy. Whatever proxy you use, it must forward h2c to port `50051`.
- **Client telemetry.** The optional `otlp-ingest` service runs only in the `client-telemetry` profile (see [Observability](docs/observability.md#client-telemetry-the-web-ui)). A plain `docker compose up` leaves it out.

### 5. Verify

- `https://<host>/` serves the web UI. Sign in with an Authentik user in the environment's contributor group.
- `https://<host>/downloads` offers the CLI and MCP installers matched to this server.
- The gRPC health service, the protocol handshake and `System.GetVersion` are the only unauthenticated RPCs. The container's own health check uses the gRPC health service.
- `/readyz` on the internal listener (port `9090` inside the container) reports readiness, including the database.

## Configuration reference

The server is configured entirely through environment variables. `compose.yaml` sets the listener addresses itself.

| Variable | Required | Purpose |
| --- | --- | --- |
| `SOVEREIGN_CONFIG_DATABASE_URL` / `_FILE` | yes | The PostgreSQL connection URL. |
| `SOVEREIGN_CONFIG_OIDC_ISSUER` | yes | The Authentik provider's issuer URL. The Authentik administration origin is derived from it, so the API and issuer origins can never diverge. |
| `SOVEREIGN_CONFIG_OIDC_AUDIENCE` | yes | The provider's client id. Tokens for any other audience are refused. |
| `SOVEREIGN_CONFIG_PUBLIC_ORIGIN` | yes | The exact canonical HTTPS origin embedded in generated access URLs. No userinfo, no path other than `/`, no query and no fragment. |
| `SOVEREIGN_CONFIG_MANAGER_API_TOKEN` / `_FILE` | yes | The Authentik connection-manager API token. |
| `SOVEREIGN_CONFIG_MANAGER_GRANTS_ATTRIBUTE` | yes | The Authentik user and group attribute that carries this environment's grants, matching the blueprint's scope mapping (`sovereign_config_prod_grants` or `sovereign_config_dev_grants`). |
| `SOVEREIGN_CONFIG_MANAGER_GROUP` | yes | The Authentik group each access URL's service account is added to so an operator can browse them. It grants no permissions and must match the blueprint (`sovereign-config-connections` or `sovereign-config-dev-connections`). |
| `SOVEREIGN_CONFIG_VALUE_ENCRYPTION_KEY` / `_FILE` | yes | The base64 32-byte key that seals secret values. |
| `SOVEREIGN_CONFIG_CLIENT_TELEMETRY_ENDPOINT` | no | When set, it must equal `SOVEREIGN_CONFIG_PUBLIC_ORIGIN`, and it tells the web UI to send its spans and logs to the ingest on that origin. Unset means the web UI sends none. Any other value fails startup. |
| `SOVEREIGN_CONFIG_AUDIT_RETENTION_DAYS` | no | How long an audit event is kept after it was last seen. Default `365`, maximum `3650`. |
| `SOVEREIGN_CONFIG_AUDIT_COALESCE_WINDOW_HOURS` | no | The window in which repeated reads collapse into one audit event. Default `24`, maximum `168`. |
| `SOVEREIGN_CONFIG_AUDIT_PAGE_SIZE` | no | The default and maximum number of events one audit query returns. Default `100`, maximum `1000`. |
| `SOVEREIGN_CONFIG_GRPC_ADDR` | yes | The public listener, `0.0.0.0:50051` in `compose.yaml`. |
| `SOVEREIGN_CONFIG_METRICS_ADDR` | yes | The internal listener that serves `/readyz`, `0.0.0.0:9090` in `compose.yaml`. The name predates metrics moving to OTLP. |
| `OTEL_*` | no | Telemetry export. See [Observability](docs/observability.md). |
| `RUST_LOG` | no | Filters log output. |

The Compose stack also reads `SOVEREIGN_CONFIG_IMAGE_TAG` (default `local`), `SOVEREIGN_CONFIG_ENV` (the environment named on container labels, default `dev`), `SOVEREIGN_CONFIG_HOST`, `SOVEREIGN_CONFIG_CONTAINER_NAME` and `POSTGRES_DATA_VOLUME`.

An optional setting that is set but unusable fails startup rather than falling back to its default.

## How data is stored and protected

Sovereign Config applies application-level encryption to secret-classified configuration values, and to nothing else. Those values are sealed with XChaCha20-Poly1305 under the key supplied through `SOVEREIGN_CONFIG_VALUE_ENCRYPTION_KEY`, each bound to the row that stores it, so a dump, a backup, a replication stream, or direct SQL access yields no readable secret. **Everything else in the database is stored verbatim** — every `plain` value, the complete tree of configuration paths, and managed-connection metadata such as display names and credential identifiers. Volume and backup encryption therefore remain a requirement, not a redundancy: they are still the only thing protecting that material.

Configuration values are stored in PostgreSQL as content rows. Each holds a `plain` or `secret` classification and the value itself, sealed as an `enc:v1:` AEAD envelope when the classification is `secret` and verbatim when it is `plain`, along with service-generated UTC creation and update timestamps. Each content row has one or more path rows, each exposing it at a canonical absolute path. Writing through any path updates the shared content, so every path to that value sees the change. A value's classification cannot be changed while more than one path resolves to it. Deleting a path removes only that path, and the value is deleted for good, in the same transaction, once its last path is removed. Updates are last-write-wins and keep the original creation timestamp. Deletion is a hard delete with no tombstone or value history. What was done to a value is recorded separately in the [audit trail](docs/audit-trail.md), which holds a plain value's previous text but never a secret's.

Exposing one value at several paths (aliasing) is a deliberate administrative act. It requires `write` on both paths and `read` on the existing one. It also widens who can reach that value: a secret aliased into a namespace where more principals hold `read` becomes revealable by them. Listings only ever return the paths a caller may read.

The server never seeds users, groups or authorization state, and PostgreSQL holds no ACL, grant, token or session records. Access tokens are verified locally against the identity provider's published keys, and tokens, claims, grants and provider URLs are never logged.

## Using Sovereign Config

### Web UI

The server embeds a WebAssembly administration UI and serves it from the same origin as its gRPC-Web API. Signing in uses OIDC authorization code with PKCE. Access tokens stay in WASM memory only, and the rotating refresh token stays in tab-scoped session storage, so a reload restores the session but closing the tab ends it.

- **Configuration** browses the namespace tree and edits the values at a path. A secret is a padlocked field: blank until you open the padlock to reveal it, and writable without being revealed. A JSON mode edits a whole subtree at once while preserving masked secrets.
- **Access URLs** for a path are listed beneath its values, where they can be created, rotated and revoked. The Access URLs page is the estate-wide view.
- **Audit trail** at `/audit/` searches the events you may see. Each value row links to its own history.
- **Downloads** offers the CLI and MCP installers matched to this server.

[Web UI](docs/web-ui.md) describes each view in detail.

### CLI

Install the CLI from your server, which serves an installer built from its own release:

```sh
sh -c 'd=$(mktemp -d); trap "rm -rf \"$d\"" EXIT; curl -fsSL "https://<server>/dist/install-sovereign-config-cli-<version>-x86_64-linux.sh" -o "$d/installer.sh" && sh "$d/installer.sh"'
```

The exact command for your server is at `https://<server>/downloads`. Add a profile by pasting a connection URL at the hidden prompt, then log in with device flow:

```sh
sovereign-config profile add prod
sovereign-config login
sovereign-config status
```

```sh
sovereign-config get /apps/api/settings
sovereign-config get /apps/api --tree --format json
printf '%s' 'enabled=true' | sovereign-config set /apps/api/settings
printf '%s' 's3cr3t' | sovereign-config set /apps/api/database_password --secret
sovereign-config list /apps/api
sovereign-config delete /apps/api/settings --yes
```

Written content is always read from standard input, and connection URLs are never accepted as process arguments, so neither appears in shell history or process listings. To start a process with configuration in its environment, use `render`:

```sh
sovereign-config render /apps/api /apps/api/prod -- ./deploy.sh
```

`render` reads each subtree in order, with later layers winning, and exports each direct child as a variable named exactly as stored. It then replaces itself with the command, with no shell in between. Every read happens before the command starts, so a failure means the command never runs. The [CLI reference](docs/cli.md) covers profiles, output formats, `render` and credential inputs for CI.

### MCP server

`sovereign-config-mcp` is a local stdio [Model Context Protocol](https://modelcontextprotocol.io/) server that exposes the administration surface as tools to an MCP host, acting with the signed-in user's permissions. It uses the same client library as the CLI, so it never shells out and never bypasses server authorization. Install it from your server the same way as the CLI:

```sh
sh -c 'd=$(mktemp -d); trap "rm -rf \"$d\"" EXIT; curl -fsSL "https://<server>/dist/install-sovereign-config-mcp-<version>-x86_64-linux.sh" -o "$d/installer.sh" && sh "$d/installer.sh"'
```

The binary can also be built from source with `cargo install --locked --git https://github.com/vcheesbrough/sovereign-config --tag <version> --bin sovereign-config-mcp`. Configure the MCP host to launch it directly:

```toml
[mcp_servers.sovereign-config]
command = "sovereign-config-mcp"
# args = ["--profile", "prod"]   # optional; omit to use the default profile
```

It reuses the CLI's profiles and stored credentials. Select a profile with `--profile <name>` or `SOVEREIGN_CONFIG_PROFILE`, and manage profiles with the CLI. Restart or reload the MCP host after installing, upgrading or reconfiguring it. [MCP server](docs/mcp.md) has the details.

Its tools cover authentication status and device-flow `login`/`logout`, plus `get`, `list`, `put_value`, `put_secret`, `replace_subtree`, `delete`, `reveal_secret`, `alias_add`, `alias_list`, `list_connections`, `create_connection`, `rotate_connection` and `revoke_connection`. Secrets and authentication material never appear in tool arguments, diagnostics or logs. Plaintext is returned only by an explicit authorized reveal, and an access URL only by the call that creates or rotates it.

### Applications

Rust applications can read their configuration with [`sovereign-config-provider`](crates/sovereign-config-provider/README.md). It takes an access URL, obtains a client-credentials token, reads the URL's subtree, reveals secret leaves and deserializes the result into a `serde` type. It negotiates a protocol version on connect, so a server upgrade does not require rebuilding its consumers. It deliberately caches nothing, so revealed secrets never outlive a load in memory. Rust is the only provider language today; providers for other languages, such as .NET, are planned (see [Roadmap](#roadmap)).

Other deploy tooling can use `sovereign-config render` with an access URL in `SOVEREIGN_CONFIG_URL`, or the `sovereign-config-cli` image in a CI step (see [CLI](docs/cli.md#the-cli-image-for-woodpecker-pipelines)).

### Woodpecker CI

[`sovereign-config-woodpecker-broker`](crates/sovereign-config-woodpecker-broker/README.md) is a Woodpecker CI external secrets extension. It verifies Woodpecker's signed request, reads an ordered list of configuration layers derived from the repository through a read-only access URL, and returns the merged secrets. Pipeline YAML is unchanged: secret names are stored as path segments, and `from_secret:` names resolve case-insensitively.

## Access control

Authorization lives in the identity provider. Each environment's blueprint creates a contributor group holding `read`, `write` and `manage` on `/`, and adding a person to it gives them the whole tree. For narrower access, set the environment's grant attribute on a user, a service account or a group:

```yaml
sovereign_config_prod_grants:
  - prefix: /apps/example
    permissions:
      - read
```

The identity provider signs the combined grants into every access token, and the server checks the relevant permission for every operation. A grant change reaches a principal with their next token, within five minutes.

A caller holding `manage` on a path can create **access URLs** rooted there, granting any of the permissions it holds itself. Each access URL is backed by a dedicated Authentik service account whose only grant is that root. The URL is shown exactly once, on creation or rotation, and the service stores no copy. Rotation invalidates the previous URL immediately, and revocation deletes the service account. A token already issued remains valid until it expires, at most five minutes later. See [Authentication](docs/authentication.md) for the full model.

## Audit trail

Every configuration change, every secret reveal, every read and every access-URL create, rotate and revoke is recorded. Each record names the identity behind it and the protocol version the call arrived on. No secret value is ever recorded. Changes and reveals fail closed: one that cannot be recorded does not happen. Repeated reads by the same identity collapse into a single event per window, which keeps a year of retention practical. The trail is searchable in the web UI and through the `v4` API, and each caller sees only events on paths they may read. See [Audit trail](docs/audit-trail.md).

## Observability

With no `OTEL_*` variable set, the server logs JSON to stdout and exports nothing. Set the standard OpenTelemetry variables to export spans, structured logs and metrics over OTLP (`http/protobuf`) to a collector of your choice:

```sh
export OTEL_SERVICE_NAME=sovereign-config
export OTEL_RESOURCE_ATTRIBUTES=deployment.environment.name=prod,telemetry_source=otlp
export OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4318
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
export OTEL_LOGS_EXPORTER=otlp
export OTEL_METRICS_EXPORTER=otlp
export OTEL_TRACES_EXPORTER=otlp
```

With `OTEL_RESOURCE_ATTRIBUTES` set, start the stack with the Compose plugin binary (for example `/usr/local/libexec/docker/cli-plugins/docker-compose up -d --wait`) rather than `docker compose`. The Docker 27 CLI overwrites that variable when it runs the plugin, and the server then fails startup because `deployment.environment.name` is missing.


Metrics are pushed rather than scraped, and there is no `/metrics` endpoint. A collector that is down never fails a request, a start or a health check. The web UI can also send its own traces through an authenticated, same-origin ingest. [Observability](docs/observability.md) documents every span, metric and log field, and the validation rules for the variables.

## Upgrading

Stop traffic and the old server, back up the database, set `SOVEREIGN_CONFIG_IMAGE_TAG` to the new release, and run `docker compose up -d`. Migrations are forward-only, so a downgrade means restoring the backup. Some releases need clients upgraded in a particular order. Read [Upgrading](docs/upgrading.md) for the procedure and the notes for every release between yours and the target.

## Compatibility

The API is served as versioned protobuf packages, currently `sovereign.config.v4` (preferred) and `sovereign.config.v3`, over native gRPC and gRPC-Web on one port. A client sends the versions it speaks to an unversioned handshake, and the server answers with every version it serves. The client then uses the best one both sides support. A client older than the server therefore keeps working, and upgrading the server alone is safe. A version is retired only after it is announced with a deprecation date and its authenticated traffic has dropped to zero.

`v4` adds the audit-trail query to `v3`'s surface and validates a request's shape before authorizing it. Negotiation does not cover every change: some releases changed what older clients see without a protocol change, and [Upgrading](docs/upgrading.md) says how to sequence them. [Protocol versioning](docs/protocol-versioning.md) describes negotiation, the compatibility rules, and how versions are introduced and retired.

## Roadmap

The project intends to extend Sovereign Config in these directions. They are statements of intent, not commitments, and none has a release date.

- **An infrastructure-neutral deployment.** `compose.yaml` still names the author's own image registry and Traefik setup (see [step 4](#4-configure-and-start)). The intent is to make the registry, proxy network, entrypoint, certificate resolver and middlewares configurable, or to ship them as an example rather than defaults, so the stack needs no editing.
- **More identity providers.** Authentication is built on standard OIDC access tokens, verified locally against the issuer's published keys, but the setup, grant mapping and managed connections currently depend on Authentik. The intent is to support other OIDC identity providers as well.
- **Providers for more languages.** Applications currently read configuration through the Rust `sovereign-config-provider` crate, or through `sovereign-config render` from any language. The intent is to offer native providers for other ecosystems, starting with .NET, with the same guarantees: a scoped access URL, protocol negotiation, and no caching of revealed secrets.

## Documentation

| Document | For |
| --- | --- |
| [CLI](docs/cli.md) | Profiles, commands, output formats, `render`, CI use. |
| [Web UI](docs/web-ui.md) | Sessions and the behaviour of each view. |
| [MCP server](docs/mcp.md) | Installing, configuring and the tool surface. |
| [Authentication](docs/authentication.md) | Authentik blueprints, grants, token verification, credential rotation, access URLs. |
| [Audit trail](docs/audit-trail.md) | What is recorded, failure policy, querying, the browser view. |
| [Observability](docs/observability.md) | Spans, metrics, logs, configuration, web UI telemetry. |
| [Upgrading](docs/upgrading.md) | The upgrade procedure and per-release notes. |
| [Protocol versioning](docs/protocol-versioning.md) | Version negotiation and the procedure for adding or retiring a version. |
| [Development](docs/development.md) | Workspace layout, building, testing and the release gate. |
| [Project deployment](docs/project-deployment.md) | How the project's own instance is built and deployed. |
| [Application provider](crates/sovereign-config-provider/README.md) | The Rust library API. |
| [Woodpecker secrets extension](crates/sovereign-config-woodpecker-broker/README.md) | Broker configuration, layer syntax and cutover. |

## License

Sovereign Config is licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE).
