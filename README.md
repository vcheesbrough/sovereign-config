# Sovereign Config

Sovereign Config is a self-hosted, gRPC-first configuration service. This repository is a Cargo-workspace monorepo: the server, protocol crates, shared Rust client libraries, CLI, MCP server, WASM UI, and Woodpecker CI secrets extension are released together from the same source tag.

## Deployment

The production Compose stack contains only PostgreSQL and Sovereign Config. It publishes no application, PostgreSQL, metrics, logging, or tracing ports. Traefik must provide the external `proxy-backend` network and is the only supported ingress. The operator must pre-create the external volume named by `POSTGRES_DATA_VOLUME` that holds the PostgreSQL data directory on encrypted storage; Compose deliberately refuses to create a default volume. All backup and staging storage must be encrypted too.

Sovereign Config applies application-level encryption to secret-classified configuration values, and to nothing else. Those values are sealed with XChaCha20-Poly1305 under the key supplied through `SOVEREIGN_CONFIG_VALUE_ENCRYPTION_KEY`, each bound to the row that stores it, so a dump, a backup, a replication stream, or direct SQL access yields no readable secret. **Everything else in the database is stored verbatim** — every `plain` value, the complete tree of configuration paths, and managed-connection metadata such as display names and credential identifiers. Volume and backup encryption therefore remain a requirement, not a redundancy: they are still the only thing protecting that material. What changed is that secrets no longer depend on it alone.

Create the secret files in an operator-controlled directory. The PostgreSQL password file is read by the PostgreSQL entrypoint and should be owned by `root:root` with mode `0400`. The database URL, Authentik introspection client secret, connection-manager API token, and value encryption key files are read by Sovereign Config's fixed UID `10001` and must be owned by `10001:10001` with mode `0400`. Compose preserves host ownership for these file-backed secrets.

`POSTGRES_PASSWORD_SECRET_FILE` points to the file containing only the PostgreSQL password. `DATABASE_URL_FILE` points to the file containing the complete private-network URL, for example `postgresql://sovereign_config:<password>@postgres:5432/sovereign_config`. `OIDC_INTROSPECTION_CLIENT_SECRET_FILE` points to the file containing only the matching Authentik introspection provider's client secret. `MANAGER_API_TOKEN_FILE` points to the file containing only the dedicated Authentik connection-manager API token used to provision managed application connections. `VALUE_ENCRYPTION_KEY_FILE` points to the file containing only the value encryption key: 32 random bytes in standard base64, generated with `openssl rand -base64 32`. Never commit these files.

Each of these secrets may instead be supplied directly through its environment variable — `SOVEREIGN_CONFIG_DATABASE_URL`, `SOVEREIGN_CONFIG_OIDC_INTROSPECTION_CLIENT_SECRET`, `SOVEREIGN_CONFIG_MANAGER_API_TOKEN`, and `SOVEREIGN_CONFIG_VALUE_ENCRYPTION_KEY` — which takes precedence over the matching `_FILE` variable. This suits an external secret manager that injects values into the environment. Startup fails with a redacted error when a required secret is absent through both routes.

**Back up the value encryption key, and keep that backup somewhere you would still have after losing the deployment.** It is the only thing that can decrypt the stored secrets; without it they are unrecoverable, no matter how good the database backups are. On first start with this key, the server seals any secrets still stored in plaintext from an earlier release. That step is one-way as far as older images are concerned: a version predating value encryption will return ciphertext instead of secrets, so rolling back past it means restoring a pre-upgrade dump. The server refuses to start if it finds a stored secret it cannot decrypt, rather than serving errors or sealing a second layer over intact data.

Set the required deployment inputs and start the stack:

```sh
export SOVEREIGN_CONFIG_IMAGE_TAG='1.5.0'
export SOVEREIGN_CONFIG_ENV='prod'
export SOVEREIGN_CONFIG_HOST='config.example.internal'
export SOVEREIGN_CONFIG_CONTAINER_NAME='sovereign-config-production'
export POSTGRES_DATA_VOLUME='sovereign-config-production-db'
export POSTGRES_PASSWORD_SECRET_FILE="$HOME/.config/sovereign-config/postgres-password"
export DATABASE_URL_FILE="$HOME/.config/sovereign-config/database-url"
export OIDC_INTROSPECTION_CLIENT_SECRET_FILE="$HOME/.config/sovereign-config/oidc-introspection-client-secret"
export MANAGER_API_TOKEN_FILE="$HOME/.config/sovereign-config/manager-api-token"
export VALUE_ENCRYPTION_KEY_FILE="$HOME/.config/sovereign-config/value-encryption-key"
export SOVEREIGN_CONFIG_OIDC_INTROSPECTION_URL='https://<authentik-host>/application/o/introspect/'
export SOVEREIGN_CONFIG_OIDC_ISSUER='https://<authentik-host>/application/o/sovereign-config/'
export SOVEREIGN_CONFIG_OIDC_AUDIENCE='sovereign-config'
export SOVEREIGN_CONFIG_OIDC_INTROSPECTION_CLIENT_ID='sovereign-config-introspection'
export SOVEREIGN_CONFIG_PUBLIC_ORIGIN='https://config.example.internal'
export SOVEREIGN_CONFIG_MANAGER_GRANTS_ATTRIBUTE='sovereign_config_prod_grants'
export SOVEREIGN_CONFIG_MANAGER_GROUP='sovereign-config-connections'
docker compose up -d
```

`SOVEREIGN_CONFIG_PUBLIC_ORIGIN` is the exact canonical HTTPS origin embedded in generated connection URLs. It must carry no userinfo, no path other than `/`, no query, and no fragment; numeric-loopback HTTP is accepted only in tests. `SOVEREIGN_CONFIG_MANAGER_GRANTS_ATTRIBUTE` names the environment-specific Authentik user attribute that carries managed grants, matching the scope mapping in that environment's blueprint. `SOVEREIGN_CONFIG_MANAGER_GROUP` names the Authentik group each managed connection's service account is added to purely so an operator can browse them together; it grants no permissions and must match a plain group entry in that environment's blueprint. The Authentik administration origin is derived from `SOVEREIGN_CONFIG_OIDC_ISSUER`, so the API and issuer origins can never diverge.

`SOVEREIGN_CONFIG_IMAGE_TAG` selects the published Zot image; it defaults to `local` for local builds. `SOVEREIGN_CONFIG_ENV` labels metrics and logs and defaults to `dev`. PostgreSQL is pinned by digest. The service starts only after PostgreSQL reports healthy.

Cargo supplies the `major.minor` release line. After a successful development deployment, Woodpecker tags the deployed commit and the next deployment advances the patch version. The deployed `System.GetVersion` response reports that computed release version; local builds report the Cargo version.

The development deployment is verified by calling `System.GetVersion` through the public gRPC endpoint after Woodpecker completes. gRPC health and `System.GetVersion` are the only RPCs that do not require authentication.

Production is deployed with Woodpecker's **Deploy feature — a `deployment` event targeting the `prod` environment, from `main`**. All build, publish, and version-allocation steps are gated to `push`, so a promotion never rebuilds, republishes, or mints a new version, and never redeploys development. Instead it **resolves the semver the push pipeline already tagged onto the commit** (`resolve-release-tag`; it never allocates — allocating on a deployment would mint an unbuilt tag), **verifies that exact image is present in the registry** (`verify-image`, no rebuild), applies the production Authentik blueprint (`authentik/blueprint.yaml`), validates the production connection manager against live Authentik, and deploys that image onto the production stack (`sovereign-config.desync.link`, container `sovereign-config-production`, compose project `sovereign-config-prod`). A commit can therefore only be promoted after its push pipeline has finished (build + dev deploy → git tag); a commit with no release tag fails closed.

Before the first promotion the operator provides the production Woodpecker secrets `sovereign_config_prod_postgres_password`, `sovereign_config_prod_oidc_introspection_client_secret`, `sovereign_config_prod_manager_api_token`, and `sovereign_config_prod_value_encryption_key` (the server refuses to start without it), the pre-created encrypted `sovereign-config-production-db` volume, and DNS/Traefik for the production host. The shared secrets the deployment path reuses — `github_token` (tag resolution), `zot_ci_user` and `zot_ci_password` (registry pull), and `authentik_api_token` (blueprint) — must permit the `deployment` event in their Woodpecker event allowlists.

Build release images only for linux/amd64 with `docker build --platform linux/amd64 --target server-runtime --tag sovereign-config:local .`. `--target` is mandatory: the Dockerfile has a second final stage, `broker-runtime`, for the Woodpecker secrets broker (`docker build --platform linux/amd64 --target broker-runtime --tag sovereign-config-woodpecker-broker:local .`), and an untargeted build tags whichever stage is last in the file.
Woodpecker reuses Cargo dependency and compilation caches across validation and server-image builds.

The server embeds the fingerprinted Rust WASM administration application and serves it with gRPC-Web on the native gRPC listener. Browser assets, runtime OIDC configuration, and gRPC-Web use the service origin; the server sends no cross-origin API permission. Browser access tokens remain only in WASM memory, while rotating refresh tokens remain in tab-scoped session storage. Access expiry refreshes transparently and reload restores the tab's session; logout, absolute refresh expiry, or definitive refresh rejection require a new PKCE authorization.

## CLI

Each running server publishes a prebuilt CLI installer matched to its own release. The installer is a static x86_64 Linux binary (no toolchain, no libc dependency) wrapped in a self-extracting shell script. Browse `https://<server>/downloads` for the download links and the exact command, or install directly — this downloads to a temporary directory that is removed afterwards:

```sh
sh -c 'd=$(mktemp -d); trap "rm -rf \"$d\"" EXIT; curl -fsSL "https://<server>/dist/install-sovereign-config-cli-<version>-x86_64-linux.sh" -o "$d/installer.sh" && sh "$d/installer.sh"'
```

The installer verifies its embedded checksum, installs `sovereign-config` into `~/.local/bin` (override with `SOVEREIGN_CONFIG_BIN`), and prints the installed version. Re-run it to upgrade. Because the binary is built from the server's own release tag, the installed CLI is protocol-matched to that server. The installer extracts itself from its own file, so download it and run it — it cannot be piped straight into a shell.

Alternatively, build the CLI from the matching tagged source with a Rust toolchain:

```sh
cargo install --locked --git https://github.com/vcheesbrough/sovereign-config --tag <version> sovereign-config-cli
```

Add a named development profile by entering its self-contained connection URL at the hidden prompt. The first profile becomes the default:

```sh
sovereign-config profile add dev
# New URL: https://sovereign-config-dev.desync.link/#v=1&issuer=https%3A%2F%2Fauth.desync.link%2Fapplication%2Fo%2Fsovereign-config-dev%2F&client_id=sovereign-config-dev
sovereign-config login
sovereign-config status
sovereign-config logout
```

Use `sovereign-config profile update <name>` to replace a URL and `sovereign-config profile default <name>` to change the default. A URL can instead be supplied as exactly one line on standard input. Profile URLs are never accepted as process arguments. Operational commands accept a global override, for example `sovereign-config --profile prod status`.

Read and write exact plain-text values or complete JSON subtrees with the selected profile. Every command path is absolute, begins with `/`, and is ASCII case-insensitive; the service stores one lowercase canonical path. Segments contain only letters, digits, `-`, and `_` — the full grammar is `/` or `^/[a-z0-9_-]+(/[a-z0-9_-]+)*$`. A profile with a configured root accepts only absolute paths within that subtree. Put content is read from standard input so it does not appear in process arguments. Interactive deletion requires typing `delete`; automation must pass `--yes` explicitly.

```sh
sovereign-config get /apps/api/settings
printf '%s' 'enabled=true' | sovereign-config put /apps/api/settings
printf '%s' 'database-password' | sovereign-config secret put /apps/api/database-password
sovereign-config get /apps/api/database-password
sovereign-config get --reveal /apps/api/database-password
sovereign-config get /apps/api --format json
sovereign-config get --reveal /apps/api --format json
printf '%s' '{"enabled":"true","workers":"4"}' | sovereign-config put /apps/api --format json
sovereign-config delete /apps/api/settings --yes
sovereign-config delete /apps/api --recurse --yes
```

Text get prints an exact plain value and prints `********` for a secret; it requires `--format json` when descendants exist. Add `--reveal` to return plaintext for an exact secret, or to reveal every secret leaf in a JSON result; it requires `read` permission and never changes the stored data. `secret put` is write-only and reads replacement content from standard input. `secret reveal` remains an explicit exact-value alias and requires a `read` grant. Rotation requires `write`, and exact or recursive deletion requires `write` and permanently removes the secret.

JSON output is deterministic and pretty printed; each stored plain-text value is represented as a JSON string and every secret is represented by the exact preservation marker `"********"`. JSON is relative to the selected path, so selecting `/foo/foo2/foo3` containing `/foo/foo2/foo3/deepvalue` returns `{"deepvalue":"deepvalue"}` without a `foo3` wrapper. An exact selected value is a root JSON string, and `/` is the root object. JSON put atomically replaces the selected subtree using the same relative shape. Omitted plain values are deleted, but existing secrets are never deleted or overwritten by a subtree replacement whether omitted or represented by their mask marker; a plain value may not collide structurally with an existing secret. Use an exact put, secret rotation, or explicit delete for those transitions. JSON replacement requires both independent `write` and `manage` grants covering the selected root. Exact text put requires `write`. Put and delete print only fixed success summaries and never echo values.

The native and gRPC-Web APIs use the breaking `sovereign.config.v3` protobuf package. Servers, CLIs, browser assets, and Rust clients must be upgraded together; there is no prior-version fallback or mixed-version operation.

The version-1 URL origin is the native gRPC endpoint, its path is the canonical configuration root, and its fragment contains the OIDC issuer and client ID. Without `client_secret`, login uses device flow. With `client_secret`, the value is unpadded Base64URL-encoded `service-account-username:app-password`; the CLI obtains a fresh client-credentials access token for each operation and does not support login or logout for that profile. The entire managed URL is a secret even though its credential is encoded.

Profiles are stored in `$XDG_CONFIG_HOME/sovereign-config/config.toml`, defaulting to `~/.config/sovereign-config/config.toml`. The directory is mode `0700` and the file is mode `0600`; because managed profiles contain credentials, protect the entire file. Human refresh credentials are stored in environment-bound mode-`0600` files under `$XDG_STATE_HOME/sovereign-config/credentials/`, defaulting to `~/.local/state/sovereign-config/credentials/`. Keep these paths in the WSL Linux filesystem rather than `/mnt/c` so Unix ownership and modes are enforced.

The CLI prints only the device verification URI and user code during login. Access tokens remain in process memory; refresh credentials and managed credentials never appear in arguments or command output. Each status operation acquires a fresh access token and performs fresh RPCs without response caching or automatic retry. A definitive refresh rejection deletes the unusable human credential; a temporary Authentik outage retains it for a later attempt.

## MCP server

Each running server also publishes a prebuilt local **Model Context Protocol** server, `sovereign-config-mcp`, matched to its own release. It exposes the full implemented administration surface as MCP tools to any local stdio MCP host (for example Codex), using the authenticated user's permissions. It is local software — not a container or a remote HTTP service — and it talks to Sovereign Config only through the same public Rust client library the CLI uses; it never shells out to the CLI and never bypasses server authorization. Browse `https://<server>/downloads` for the link and command, or install directly into a self-cleaning temporary directory:

```sh
sh -c 'd=$(mktemp -d); trap "rm -rf \"$d\"" EXIT; curl -fsSL "https://<server>/dist/install-sovereign-config-mcp-<version>-x86_64-linux.sh" -o "$d/installer.sh" && sh "$d/installer.sh"'
```

The installer verifies its embedded checksum, installs `sovereign-config-mcp` into `~/.local/bin` (override with `SOVEREIGN_CONFIG_BIN`), and prints the installed version. Re-run it to upgrade. Because the binary is built from the server's own release tag, the installed MCP server is protocol-matched to that server by construction. Like the CLI installer, it extracts itself from its own file, so download it and run it — it cannot be piped straight into a shell. A Rust-toolchain source fallback is also available:

```sh
cargo install --locked --git https://github.com/vcheesbrough/sovereign-config --tag <version> --bin sovereign-config-mcp
```

Configure the MCP host to launch the installed binary directly as a local stdio process — no container, no wrapper. It reuses the CLI's profiles and stored credentials, selecting a profile with `--profile <name>` or the `SOVEREIGN_CONFIG_PROFILE` environment variable (the default profile otherwise). A minimal host entry:

```toml
[mcp_servers.sovereign-config]
command = "sovereign-config-mcp"
# args = ["--profile", "prod"]   # optional; omit to use the default profile
```

After installing or upgrading the binary, or changing its configuration, restart or reload the MCP host once so it relaunches the stdio process — that is the single reload boundary. Credentials stay in the established credential store; profiles are managed with the CLI (`sovereign-config profile …`).

The server exposes tools for authentication status and explicit device-flow `login`/`logout`; exact and subtree reads (`get`, `list`); plain and secret writes (`put_value`, `put_secret`); JSON-merge subtree replacement (`replace_subtree`); exact/recursive deletion (`delete`); explicit secret reveal (`reveal_secret`); multi-path value aliasing (`alias_add`, `alias_list`); and managed application connection lifecycle with their permission grants (`list_connections`, `create_connection`, `rotate_connection`, `revoke_connection`). The `login` tool surfaces the device verification URL and user code as a log notification, then polls the provider to completion. Secrets and authentication material never appear in tool arguments, diagnostics, or logs; plaintext is returned only by an explicit authorized reveal, and a managed connection's one-time URL only as the result of creating or rotating it. Every request is authorized by the server: a caller cannot reveal an unreadable secret, expand a delegated prefix, grant an unheld permission, or otherwise widen a request through the adapter.

## Authentik

The repository owns two isolated Authentik blueprints:

| Environment | Blueprint | Application and issuer provider | Introspection provider | Audience |
| --- | --- | --- | --- | --- |
| Production | `authentik/blueprint.yaml` | `sovereign-config` | `sovereign-config-introspection` | `sovereign-config` |
| Development | `authentik/blueprint-dev.yaml` | `sovereign-config-dev` | `sovereign-config-introspection-dev` | `sovereign-config-dev` |

Each environment has one public issuing provider shared by the browser, human CLI, and future managed application connections. It permits authorization-code, device-code, refresh-token, and client-credentials grants, uses an exact same-origin browser callback through `SOVEREIGN_CONFIG_BROWSER_REDIRECT_URI` or `SOVEREIGN_CONFIG_DEV_BROWSER_REDIRECT_URI`, and permits introspection only by its same-environment confidential provider. Tokens and introspection credentials must never cross environments. Wildcard and first-use registration are not allowed.

Both blueprints own the authenticated `sovereign-config-device-code` Stage Configuration flow and assign it to the exact brand selected by `AUTHENTIK_BRAND_DOMAIN` or `AUTHENTIK_DEV_BRAND_DOMAIN`. Supply the domain of the brand active for the Authentik public hostname; do not point this at a different tenant or create a second active brand accidentally. Woodpecker applies the development blueprint before automatic development deployment. Production deployment must apply only the production blueprint before starting the production stack.

Authentik 2026.5.2 or newer is required. That version includes configurable grant allowlists along with the cross-provider introspection and device-authorization scope clipping fixes needed by this design. Woodpecker checks the development deployment's authenticated version endpoint and schema before applying its blueprint; verify production the same way before applying its blueprint.

The issuing providers use the selected Authentik signing certificate, five-minute access tokens, and rotating refresh tokens bounded to eight hours. Browser and human CLI clients request `openid sovereign-config offline_access`. Browser access tokens remain only in WASM memory; the rotating refresh credential is held in tab-scoped session storage so a reload can obtain a fresh access token without persisting a long-lived login across browser sessions. Logout, refresh expiry, or refresh rejection clears the browser session. Use authorization code with PKCE or device flow and keep all tokens out of shell history and logs.

### Configuration grants

Each blueprint creates an environment-specific contributor group that bundles global `read`, `write`, and `manage` grants:

| Environment | Contributor group | Direct grant attribute |
| --- | --- | --- |
| Production | `sovereign-config-production-config-contributor` | `sovereign_config_prod_grants` |
| Development | `sovereign-config-development-config-contributor` | `sovereign_config_dev_grants` |

Add a user or service account only to the contributor groups required for that environment. Group membership is an Authentik administration convenience, not a Sovereign Config role: the environment's scope mapping emits the existing granular `sovereign_config_grants` claim, and the server independently evaluates `read`, `write`, or `manage` for every operation. No contributor role name is sent to or expanded by the server.

For narrower access, place grants in the environment-specific direct grant attribute on a user, service account, or another group. For example, this development-only attribute permits reading one subtree without write or manage:

```yaml
sovereign_config_dev_grants:
  - prefix: /apps/example
    permissions:
      - read
```

Use `sovereign_config_prod_grants` for the equivalent production assignment. The `/` prefix is the global root. Every direct grant prefix must be absolute, for example `/apps/example`; after changing grants, obtain a new access token. Each environment's `sovereign-config` scope mapping combines and deduplicates only its own direct and group grants before emitting the common granular claim, so the same principal can have different development and production permissions. Sovereign Config rejects malformed, non-canonical, or unknown grants. It never seeds users or authorization state and PostgreSQL contains no ACL, grant, token, session, or audit records.

When upgrading from the shared `sovereign-config grants` scope mapping, apply both environment blueprints before deleting that legacy mapping manually. Neither blueprint deletes it because development and production can be migrated at different times.

### Request authentication

Every non-operational RPC requires exactly one Bearer token. Sovereign Config requires an `RS256` JOSE header, then performs a fresh Authentik introspection request using HTTP Basic client authentication. It accepts only an active response matching the configured environment issuer and audience, the exact `sovereign-config` scope, a non-empty subject, and valid `sovereign_config_grants`.

The introspection endpoint must use HTTPS and cannot contain credentials, a query, or a fragment. Tokens, claims, subjects, grants, credentials, and provider URLs are not logged. There is no JWT, JWKS, token, or claim cache and no automatic retry. Invalid tokens return gRPC `UNAUTHENTICATED`; Authentik timeouts, outages, non-success responses, and malformed responses return `UNAVAILABLE`.

### Credential rotation

Authentik supports one client secret per introspection provider, so rotation has a short fail-closed maintenance window. Remove traffic, update the environment's secret source, apply that environment's blueprint, redeploy Sovereign Config with the same new secret, verify an authenticated request and unauthenticated `System.GetVersion`, then restore traffic. During the interval between blueprint application and redeployment, protected requests fail with `UNAVAILABLE`; no prior credential or authorization result is used.

Rotating the connection-manager API token is narrower: update the environment's blueprint secret and the `MANAGER_API_TOKEN_FILE` contents together, apply the blueprint, then redeploy. Only managed-connection operations are affected while the two disagree; configuration reads and writes continue through the separate introspection credential. Verify by listing managed connections after redeployment.

### Managed application connections (Access URLs)

A caller holding `manage` on a configuration root can provision a named machine connection — an **access URL**, as the administration UI calls it — and chooses which of `read`, `write`, and `manage` it grants on that root. At least one permission is required, and a caller can grant only permissions it itself holds on the root, so a manage-only operator cannot mint a write-capable URL. Sovereign Config creates a dedicated Authentik service account whose only grant is `{"prefix": "<root>", "permissions": [<selected>]}` — for example `["read"]` or `["read","write"]` — discovers its single non-expiring app password, and returns one canonical version-1 connection URL. The unchanged CLI accepts that URL on stdin through `profile add`/`profile update` and uses client credentials to operate within the encoded root, and each RPC is authorized against the URL's exact grant: a `read`-only URL can only read; a `write`-capable URL can additionally put and delete values within its root; a `manage`-capable URL can administer access URLs under its root. Value mutation therefore needs `write` (a `manage`-only URL cannot put or delete values), and JSON subtree replacement needs both `write` and `manage`.

The complete URL is a secret and is returned exactly once, by creation and by successful rotation. Sovereign Config stores only non-secret lifecycle metadata — the opaque connection ID, display name, canonical root, selected permission set, opaque Authentik identifiers, and bounded state — and can never re-reveal a URL. A lost URL must be replaced by rotation, which invalidates the previous URL immediately and preserves the connection's permissions.

An interrupted rotation is reported as ambiguous: no URL is returned, the connection is marked `rotation_unknown`, and the previous URL is never claimed to be still valid. A further rotation is refused while the earlier attempt could still be in flight, then permitted once that lease expires so the credential can be overwritten with a known fresh value. Revocation deletes the Authentik service account and removes the metadata row only after deletion is confirmed by the app password's absence, since Authentik denies at the permission layer before object lookup once the manager holds no remaining visible account, so "gone" and "not permitted" cannot be told apart on the user object itself; a partial failure stays visible as recoverable state rather than silently orphaning a usable credential.

Each service account's Authentik username embeds a slug of its display name so an operator can recognize it directly in Authentik, with the opaque connection ID appended to guarantee uniqueness even when two connections share a display name. It is also added to the configured `SOVEREIGN_CONFIG_MANAGER_GROUP` group purely for browsing; group membership carries no permissions, and its failure is best-effort and never blocks or rolls back a connection.

The connection-manager identity is isolated from the introspection credential and from the browser. It holds global `add_user`, `add_token`, `view_token`, and `view_group` — no key or user content is exposed by any of these, only metadata needed to discover and label an account it created — plus object-level `view`/`change`/`delete` on the users and `set_key` on the tokens it creates. It is not a superuser, cannot view any token key, and cannot touch unrelated Authentik objects. Browser code reaches only same-origin gRPC-Web; the Authentik administration endpoint and token are absent from every browser response and built asset.

## Application provider

`sovereign-config-provider` is an ergonomic Rust facade for consuming a managed connection from application code: it parses the version-1 connection URL, obtains a fresh client-credentials token, reads only the encoded subtree over native gRPC, transparently reveals secret leaves, and deserializes the result into a `serde` type. It is a thin layer over the shared core/client/native crates and adds no new URL format, authentication, or transport. It is distributed as tagged workspace source only — there is no provider container or prebuilt library artifact — and must be built from the same tag as the server. See `crates/sovereign-config-provider/README.md` for the API, error surface, and the no-cache/no-retry contract.

## Woodpecker CI secrets extension

`sovereign-config-woodpecker-broker` is a Woodpecker CI external secrets extension backed by Sovereign Config, published as its own image (`registry.desync.link/sovereign-config-woodpecker-broker`) under the same semver as the server. Woodpecker POSTs signed repository and pipeline metadata to a single configured endpoint; the broker verifies the RFC 9421 Ed25519 signature — including recomputing the body digest — renders an ordered list of configuration layers from the repository in the request, reads them through a read-only managed connection, and returns the merged secrets in Woodpecker's format. Later layers override earlier ones, so a per-repository path can override a shared default, and the repository identity always comes from the signed request rather than from configuration. Woodpecker supports exactly one secret-extension endpoint, so adopting it is a replacement rather than an addition. Pipeline YAML is unchanged: secret names are stored verbatim as path segments, which is why the canonical path grammar permits `_`. See `crates/sovereign-config-woodpecker-broker/README.md` for the environment surface, the layer syntax, the security notes, and the cutover runbook.

## Upgrade

1. Stop Sovereign Config traffic through Traefik, stop the old Sovereign Config container while leaving PostgreSQL running, and verify no v2 server process remains before migration or v3 writes.
2. Verify a recoverable PostgreSQL backup from encrypted backup/staging storage.
3. Set `SOVEREIGN_CONFIG_IMAGE_TAG` to the new published tag and run `docker compose up -d`.
4. The service applies its forward-only migrations before accepting requests.
5. Validate native gRPC health/version and `/readyz` through the trusted internal network before restoring traffic.

Downgrades after a migration are unsupported. Restore the verified PostgreSQL backup into a replacement deployment instead. The rooted-path migration deletes every existing configuration value because prior releases stored unrooted paths; recreate required values at their absolute paths after deployment. The multi-path migration separates stored content from its access paths and drops the previous single-table layout, so a release earlier than 2.13 cannot run against a migrated database at all; verify the backup in step 2 before applying it, and promote to production only after the development deployment has exercised the new schema.

### 2.15.0 widens the canonical path grammar

Release 2.15.0 adds `_` to the path segment character set, so the canonical grammar becomes `/` or `^/[a-z0-9_-]+(/[a-z0-9_-]+)*$`. This is a widening of the `v3` protocol's behaviour rather than a signature change: every previously valid path stays valid, no stored data is rewritten, and no request or response type changes.

It is **not** backward compatible for clients. A CLI, MCP server, or `sovereign-config-provider` build older than 2.15.0 rejects a path containing `_` as non-canonical and surfaces it as an opaque internal error. Because list, subtree, and path-query responses are validated as a whole, a single underscored path makes an older client fail every read of the namespace containing it — not just that one value.

Sequence the rollout accordingly:

1. Deploy the 2.15.0 server. Existing clients keep working, because no underscored path exists yet.
2. Reinstall every CLI and MCP client from the upgraded server's `/dist` installer, and rebuild every `sovereign-config-provider` consumer against tag 2.15.0 or later.
3. Only then create the first path containing `_`.

A database that has applied migration `0008` cannot be served by a release earlier than 2.15.0 once an underscored path exists, because that server would reject its own stored data.

Configuration values are stored in PostgreSQL as content rows holding a `plain` or `secret` classification, the value itself — sealed as an `enc:v1:` AEAD envelope when the classification is `secret`, verbatim when it is `plain` — and service-generated UTC creation/update timestamps, plus one or more path rows that each expose that content at a canonical absolute path beginning with `/`. Existing values migrate to exactly one path each. Writing through any path updates the shared content, so every path to that value observes the change; classification cannot be changed while more than one path resolves to the value. Deleting a path removes only that path, and the value is deleted permanently once its last path is removed, in the same transaction and with no background reconciliation. There is no history or duplicate secret copy. Updates are last-write-wins and preserve the original creation timestamp. Deletion is a hard delete with no tombstone, rollback record, or retained value history. Application-level encryption covers secret-classified values only, so PostgreSQL volume and backup encryption remain operator responsibilities for everything else the database holds.

Exposing one value at several paths is a deliberate administrative act that requires `write` on both the existing and the new path and `read` on the existing one. It widens who can reach that value: a secret aliased into a namespace where more principals hold `read` becomes revealable by them. Listings and path queries only ever return the paths a caller may read, so a value may have paths that a given principal can neither see nor operate on.

The browser exposes system status and configuration values as separate client-side pages. Configuration URLs use `/configuration/<path>` and display absolute paths beginning with `/`; the final segment of each stored path is the value name. The path selector offers namespaces containing readable values and also accepts a valid namespace that does not exist yet. Listing filters every returned value through server-side `read` permission, while row saves and deletes both require `write` permission. Secret rows always load masked, provide a blank password-style replacement field that never receives stored content, and reveal plaintext only after an explicit action. Revealed values are cleared when hidden, reloaded, navigated away from, logged out, or when a request fails. The JSON switch is off by default; when enabled it loads the entire selected subtree with all-or-nothing `read` authorization and replaces the grid with a pretty JSON editor. Saving preserves masked secrets, atomically replaces plain values, and leaves per-value deletion unavailable in JSON mode.

## Observability

The application writes structured redacted JSON logs to stdout. Authentication events contain only the RPC path and bounded outcome/reason values. Internal Alloy discovers `/metrics` using the Docker labels in `compose.yaml`; that endpoint is not routed through Traefik. `sovereign_config_authentication_total` reports bounded success/failure reasons without request-derived labels. OTLP export is introduced by its separate card.

## Release Gate

Publish an image tag only after `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `shellcheck` of the installer and migration scripts, native and WASM checks, unit and integration checks, PostgreSQL migration checks, gRPC/gRPC-Web checks, and Chromium/Firefox UI checks pass. Each release publishes **two** images from the same source tag and the same semver — `sovereign-config` and `sovereign-config-woodpecker-broker` — so the pair is protocol-matched by construction; a production promotion fails closed if either is missing from the registry. Both image builds must pass `--target` (`server-runtime` / `broker-runtime`), because the Dockerfile has more than one final stage. The release image bundles static musl CLI and MCP-server installers built from the same tag and served unauthenticated under `/dist`; the image build gates on each installer extracting to a binary whose reported version equals the release tag. The tagged source also supplies the protocol-matched CLI and MCP server through `cargo install --locked`. SBOM generation is out of scope for the MVP.
