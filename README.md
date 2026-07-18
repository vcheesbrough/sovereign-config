# Sovereign Config

Sovereign Config is a self-hosted, gRPC-first configuration service. This repository is a Cargo-workspace monorepo: the server, protocol crates, shared Rust client libraries, CLI, and WASM UI are released together from the same source tag.

## Deployment

The production Compose stack contains only PostgreSQL and Sovereign Config. It publishes no application, PostgreSQL, metrics, logging, or tracing ports. Traefik must provide the external `proxy-backend` network and is the only supported ingress. The operator must pre-create the external PostgreSQL volume named by `POSTGRES_DATA_VOLUME` on encrypted storage; Compose deliberately refuses to create a default volume. All backup and staging storage must be encrypted too. Sovereign Config does not add application-level encryption or manage an application encryption key: PostgreSQL volume and backup encryption are the release boundary.

Create the secret files in an operator-controlled directory. The PostgreSQL password file is read by the PostgreSQL entrypoint and should be owned by `root:root` with mode `0400`. The database URL and Authentik introspection client secret files are read by Sovereign Config's fixed UID `10001` and must be owned by `10001:10001` with mode `0400`. Compose preserves host ownership for these file-backed secrets.

`POSTGRES_PASSWORD_SECRET_FILE` points to the file containing only the PostgreSQL password. `DATABASE_URL_FILE` points to the file containing the complete private-network URL, for example `postgresql://sovereign_config:<password>@postgres:5432/sovereign_config`. `OIDC_INTROSPECTION_CLIENT_SECRET_FILE` points to the file containing only the matching Authentik introspection provider's client secret. Never commit these files.

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
export SOVEREIGN_CONFIG_OIDC_INTROSPECTION_URL='https://<authentik-host>/application/o/introspect/'
export SOVEREIGN_CONFIG_OIDC_ISSUER='https://<authentik-host>/application/o/sovereign-config/'
export SOVEREIGN_CONFIG_OIDC_AUDIENCE='sovereign-config'
export SOVEREIGN_CONFIG_OIDC_INTROSPECTION_CLIENT_ID='sovereign-config-introspection'
docker compose up -d
```

`SOVEREIGN_CONFIG_IMAGE_TAG` selects the published Zot image; it defaults to `local` for local builds. `SOVEREIGN_CONFIG_ENV` labels metrics and logs and defaults to `dev`. PostgreSQL is pinned by digest. The service starts only after PostgreSQL reports healthy.

Cargo supplies the `major.minor` release line. After a successful development deployment, Woodpecker tags the deployed commit and the next deployment advances the patch version. The deployed `System.GetVersion` response reports that computed release version; local builds report the Cargo version.

The development deployment is verified by calling `System.GetVersion` through the public gRPC endpoint after Woodpecker completes. gRPC health and `System.GetVersion` are the only RPCs that do not require authentication.

Build release images only for linux/amd64 with `docker build --platform linux/amd64 --tag sovereign-config:local .`.
Woodpecker reuses Cargo dependency and compilation caches across validation and server-image builds.

The server embeds the fingerprinted Rust WASM administration application and serves it with gRPC-Web on the native gRPC listener. Browser assets, runtime OIDC configuration, and gRPC-Web use the service origin; the server sends no cross-origin API permission. Browser access tokens remain only in WASM memory, while rotating refresh tokens remain in tab-scoped session storage. Access expiry refreshes transparently and reload restores the tab's session; logout, absolute refresh expiry, or definitive refresh rejection require a new PKCE authorization.

## CLI

Install the CLI from the matching tagged source with a Rust toolchain:

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

Read and write exact plain-text values or complete JSON subtrees with the selected profile. Every command path is absolute, begins with `/`, and is ASCII case-insensitive; the service stores one lowercase canonical path. A profile with a configured root accepts only absolute paths within that subtree. Put content is read from standard input so it does not appear in process arguments. Interactive deletion requires typing `delete`; automation must pass `--yes` explicitly.

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

Text get prints an exact plain value and prints `********` for a secret; it requires `--format json` when descendants exist. Add `--reveal` to return plaintext for an exact secret, or to reveal every secret leaf in a JSON result; it requires `read` permission and never changes the stored data. `secret put` is write-only and reads replacement content from standard input. `secret reveal` remains an explicit exact-value alias and requires a `read` grant. Rotation requires `write`, while exact or recursive deletion requires `manage` and permanently removes the secret.

JSON output is deterministic and pretty printed; each stored plain-text value is represented as a JSON string and every secret is represented by the exact preservation marker `"********"`. JSON is relative to the selected path, so selecting `/foo/foo2/foo3` containing `/foo/foo2/foo3/deepvalue` returns `{"deepvalue":"deepvalue"}` without a `foo3` wrapper. An exact selected value is a root JSON string, and `/` is the root object. JSON put atomically replaces the selected subtree using the same relative shape. Omitted plain values are deleted, but existing secrets are never deleted or overwritten by a subtree replacement whether omitted or represented by their mask marker; a plain value may not collide structurally with an existing secret. Use an exact put, secret rotation, or explicit delete for those transitions. JSON replacement requires both independent `write` and `manage` grants covering the selected root. Exact text put requires `write`. Put and delete print only fixed success summaries and never echo values.

The native and gRPC-Web APIs use the breaking `sovereign.config.v3` protobuf package. Servers, CLIs, browser assets, and Rust clients must be upgraded together; there is no prior-version fallback or mixed-version operation.

The version-1 URL origin is the native gRPC endpoint, its path is the canonical configuration root, and its fragment contains the OIDC issuer and client ID. Without `client_secret`, login uses device flow. With `client_secret`, the value is unpadded Base64URL-encoded `service-account-username:app-password`; the CLI obtains a fresh client-credentials access token for each operation and does not support login or logout for that profile. The entire managed URL is a secret even though its credential is encoded.

Profiles are stored in `$XDG_CONFIG_HOME/sovereign-config/config.toml`, defaulting to `~/.config/sovereign-config/config.toml`. The directory is mode `0700` and the file is mode `0600`; because managed profiles contain credentials, protect the entire file. Human refresh credentials are stored in environment-bound mode-`0600` files under `$XDG_STATE_HOME/sovereign-config/credentials/`, defaulting to `~/.local/state/sovereign-config/credentials/`. Keep these paths in the WSL Linux filesystem rather than `/mnt/c` so Unix ownership and modes are enforced.

The CLI prints only the device verification URI and user code during login. Access tokens remain in process memory; refresh credentials and managed credentials never appear in arguments or command output. Each status operation acquires a fresh access token and performs fresh RPCs without response caching or automatic retry. A definitive refresh rejection deletes the unusable human credential; a temporary Authentik outage retains it for a later attempt.

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

## Upgrade

1. Stop Sovereign Config traffic through Traefik, stop the old Sovereign Config container while leaving PostgreSQL running, and verify no v2 server process remains before migration or v3 writes.
2. Verify a recoverable PostgreSQL backup from encrypted backup/staging storage.
3. Set `SOVEREIGN_CONFIG_IMAGE_TAG` to the new published tag and run `docker compose up -d`.
4. The service applies its forward-only migrations before accepting requests.
5. Validate native gRPC health/version and `/readyz` through the trusted internal network before restoring traffic.

Downgrades after a migration are unsupported. Restore the verified PostgreSQL backup into a replacement deployment instead. The rooted-path migration deletes every existing configuration value because prior releases stored unrooted paths; recreate required values at their absolute paths after deployment.

Configuration values are stored in PostgreSQL as canonical absolute paths beginning with `/`, a `plain` or `secret` classification, plaintext content, and service-generated UTC creation/update timestamps. The classification migration preserves every existing value as `plain`; there is no history or duplicate secret copy. Updates are last-write-wins and preserve the original creation timestamp. Deletion is a hard delete with no tombstone, rollback record, or retained value history. PostgreSQL volume and backup encryption remain operator responsibilities.

The browser exposes system status and configuration values as separate client-side pages. Configuration URLs use `/configuration/<path>` and display absolute paths beginning with `/`; the final segment of each stored path is the value name. The path selector offers namespaces containing readable values and also accepts a valid namespace that does not exist yet. Listing filters every returned value through server-side `read` permission, while row saves and deletes continue to require independent `write` and `manage` permissions. Secret rows always load masked, provide a blank password-style replacement field that never receives stored content, and reveal plaintext only after an explicit action. Revealed values are cleared when hidden, reloaded, navigated away from, logged out, or when a request fails. The JSON switch is off by default; when enabled it loads the entire selected subtree with all-or-nothing `read` authorization and replaces the grid with a pretty JSON editor. Saving preserves masked secrets, atomically replaces plain values, and leaves per-value deletion unavailable in JSON mode.

## Observability

The application writes structured redacted JSON logs to stdout. Authentication events contain only the RPC path and bounded outcome/reason values. Internal Alloy discovers `/metrics` using the Docker labels in `compose.yaml`; that endpoint is not routed through Traefik. `sovereign_config_authentication_total` reports bounded success/failure reasons without request-derived labels. OTLP export is introduced by its separate card.

## Release Gate

Publish an image tag only after `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, native and WASM checks, unit and integration checks, PostgreSQL migration checks, gRPC/gRPC-Web checks, and Chromium/Firefox UI checks pass. The tagged source supplies the protocol-matched CLI installed with `cargo install --locked`. SBOM generation is out of scope for the MVP.
