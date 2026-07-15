# Sovereign Config

Sovereign Config is a self-hosted, gRPC-first configuration service. This repository is a Cargo-workspace monorepo: the server, protocol crates, shared client libraries, Rust provider, WASM UI, and local MCP binary are released together from the same source tag.

## Deployment

The production Compose stack contains only PostgreSQL and Sovereign Config. It publishes no application, PostgreSQL, metrics, logging, or tracing ports. Traefik must provide the external `proxy-backend` network and is the only supported ingress. The PostgreSQL volume and all backup/staging storage must be encrypted by the operator.

Create the secret files in an operator-controlled directory. The PostgreSQL password file is read by the PostgreSQL entrypoint and should be owned by `root:root` with mode `0400`. The database URL and Authentik introspection client secret files are read by Sovereign Config's fixed UID `10001` and must be owned by `10001:10001` with mode `0400`. Compose preserves host ownership for these file-backed secrets.

`POSTGRES_PASSWORD_SECRET_FILE` points to the file containing only the PostgreSQL password. `DATABASE_URL_FILE` points to the file containing the complete private-network URL, for example `postgresql://sovereign_config:<password>@postgres:5432/sovereign_config`. `OIDC_INTROSPECTION_CLIENT_SECRET_FILE` points to the file containing only the matching Authentik introspection provider's client secret. Never commit these files.

Set the required deployment inputs and start the stack:

```sh
export SOVEREIGN_CONFIG_IMAGE_TAG='1.2.0'
export SOVEREIGN_CONFIG_ENV='prod'
export SOVEREIGN_CONFIG_HOST='config.example.internal'
export SOVEREIGN_CONFIG_CONTAINER_NAME='sovereign-config-production'
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

The server embeds the fingerprinted Rust WASM administration application and serves it with gRPC-Web on the native gRPC listener. Browser assets, runtime OIDC configuration, and gRPC-Web use the service origin; the server sends no cross-origin API permission. The browser retains access and rotating refresh tokens only in WASM memory. Access expiry refreshes transparently; reload or refresh-session failure requires a new PKCE authorization.

## CLI

The supported prebuilt CLI target is 64-bit Linux on Debian 12 or a distribution with glibc 2.36 or newer. Release CI records the ELF dependencies and rejects anything outside `libc`, `libgcc_s`, `libm`, `libdl`, `libpthread`, the ELF loader, and the virtual DSO. The Secret Service dependency is statically vendored. The CLI first uses the desktop credential store and falls back to `$XDG_CONFIG_HOME/sovereign-config/refresh-token` (or `~/.config/sovereign-config/refresh-token`) with user ownership and mode `0600`.

Download the binary and checksum file from the matching GitHub release, then verify before installation:

```sh
sha256sum --check --ignore-missing SHA256SUMS
install -m 0755 sovereign-config-linux-amd64 "$HOME/.local/bin/sovereign-config"
```

Configure the development connection and use device login. For another deployment, replace the
service URL, issuer, and client ID with that environment's matching values:

```sh
export SOVEREIGN_CONFIG_ENDPOINT='https://sovereign-config-dev.desync.link'
export SOVEREIGN_CONFIG_OIDC_ISSUER='https://auth.desync.link/application/o/sovereign-config-dev/'
export SOVEREIGN_CONFIG_OIDC_CLI_CLIENT_ID='sovereign-config-dev'
sovereign-config status
sovereign-config login
sovereign-config status
sovereign-config logout
```

The CLI prints only the device verification URI and user code during login. Access tokens remain in process memory; refresh credentials never appear in arguments or command output. Each status operation refreshes credentials and performs fresh RPCs without response caching or automatic retry.

The locked source-build fallback requires the Rust toolchain:

```sh
cargo install --locked --git https://github.com/vcheesbrough/sovereign-config --tag <version> sovereign-config-cli
```

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

### Bootstrap administrator

Before starting Sovereign Config for the first time, create or select the administrator manually in Authentik and set this user attribute:

```yaml
sovereign_config_grants:
  - prefix: ""
    permissions:
      - read
      - write
      - manage
```

The empty prefix is the global root. The `sovereign-config` scope mapping combines and deduplicates grants from the authenticated user or service-account attributes and all group attributes. Sovereign Config rejects malformed, non-canonical, or unknown grants. It never seeds users or authorization state and PostgreSQL contains no ACL, grant, token, session, or audit records.

### Request authentication

Every non-operational RPC requires exactly one Bearer token. Sovereign Config requires an `RS256` JOSE header, then performs a fresh Authentik introspection request using HTTP Basic client authentication. It accepts only an active response matching the configured environment issuer and audience, the exact `sovereign-config` scope, a non-empty subject, and valid `sovereign_config_grants`.

The introspection endpoint must use HTTPS and cannot contain credentials, a query, or a fragment. Tokens, claims, subjects, grants, credentials, and provider URLs are not logged. There is no JWT, JWKS, token, or claim cache and no automatic retry. Invalid tokens return gRPC `UNAUTHENTICATED`; Authentik timeouts, outages, non-success responses, and malformed responses return `UNAVAILABLE`.

### Credential rotation

Authentik supports one client secret per introspection provider, so rotation has a short fail-closed maintenance window. Remove traffic, update the environment's secret source, apply that environment's blueprint, redeploy Sovereign Config with the same new secret, verify an authenticated request and unauthenticated `System.GetVersion`, then restore traffic. During the interval between blueprint application and redeployment, protected requests fail with `UNAVAILABLE`; no prior credential or authorization result is used.

## Upgrade

1. Stop Sovereign Config traffic through Traefik.
2. Verify a recoverable PostgreSQL backup from encrypted backup/staging storage.
3. Set `SOVEREIGN_CONFIG_IMAGE_TAG` to the new published tag and run `docker compose up -d`.
4. The service applies its forward-only migrations before accepting requests.
5. Validate native gRPC health/version and `/readyz` through the trusted internal network before restoring traffic.

Downgrades after a migration are unsupported. Restore the verified PostgreSQL backup into a replacement deployment instead.

## Observability

The application writes structured redacted JSON logs to stdout. Authentication events contain only the RPC path and bounded outcome/reason values. Internal Alloy discovers `/metrics` using the Docker labels in `compose.yaml`; that endpoint is not routed through Traefik. `sovereign_config_authentication_total` reports bounded success/failure reasons without request-derived labels. OTLP export is introduced by its separate card.

## Release Gate

Publish an image tag only after `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, native and WASM checks, unit and integration checks, PostgreSQL migration checks, gRPC/gRPC-Web checks, and Chromium/Firefox UI checks pass. The tag pipeline builds the CLI from that tagged commit, verifies its reported release, records and allowlists its ELF dependencies, executes it in clean Debian 12, generates `SHA256SUMS`, and publishes those artifacts. SBOM generation is out of scope for the MVP.
