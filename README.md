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

`SOVEREIGN_CONFIG_PUBLIC_ORIGIN` is the exact canonical HTTPS origin embedded in generated connection URLs. It must carry no userinfo, no path other than `/`, no query, and no fragment; numeric-loopback HTTP is accepted only in tests. `SOVEREIGN_CONFIG_MANAGER_GRANTS_ATTRIBUTE` names the environment-specific Authentik user attribute that carries managed grants, matching the scope mapping in that environment's blueprint. `SOVEREIGN_CONFIG_MANAGER_GROUP` names the Authentik group each managed connection's service account is added to purely so an operator can browse them together; it grants no permissions and must match a plain group entry in that environment's blueprint. Both names are enumerated per environment under [Authentik objects by environment](#authentik-objects-by-environment). The Authentik administration origin is derived from `SOVEREIGN_CONFIG_OIDC_ISSUER`, so the API and issuer origins can never diverge.

`SOVEREIGN_CONFIG_IMAGE_TAG` selects the published Zot image; it defaults to `local` for local builds. `SOVEREIGN_CONFIG_ENV` labels metrics and logs and defaults to `dev`. PostgreSQL is pinned by digest. The service starts only after PostgreSQL reports healthy.

Cargo supplies the `major.minor` release line. After a successful development deployment, Woodpecker tags the deployed commit and the next deployment advances the patch version. The deployed `System.GetVersion` response reports that computed release version; local builds report the Cargo version.

The development deployment is verified by calling `System.GetVersion` through the public gRPC endpoint after Woodpecker completes. gRPC health and `System.GetVersion` are the only RPCs that do not require authentication.

Production is deployed with Woodpecker's **Deploy feature — a `deployment` event targeting the `prod` environment, from `main`**. All build, publish, and version-allocation steps run only on a `push` or a manual run of the pipeline, never on a `deployment`, so a promotion never rebuilds, republishes, or mints a new version, and never redeploys development. Instead it **resolves the semver the push pipeline already tagged onto the commit** (`resolve-release-tag`; it never allocates — allocating on a deployment would mint an unbuilt tag), **verifies that exact image is present in the registry** (`verify-image`, no rebuild), applies the production Authentik blueprint (`authentik/blueprint.yaml`), validates the production connection manager against live Authentik, and deploys that image onto the production stack (`sovereign-config.desync.link`, container `sovereign-config-production`, compose project `sovereign-config-prod`). A commit can therefore only be promoted after its push pipeline has finished (build + dev deploy → git tag); a commit with no release tag fails closed.

Before the first promotion the operator provides the production Woodpecker secrets `sovereign_config_prod_postgres_password`, `sovereign_config_prod_oidc_introspection_client_secret`, `sovereign_config_prod_manager_api_token`, and `sovereign_config_prod_value_encryption_key` (the server refuses to start without it), the pre-created encrypted `sovereign-config-production-db` volume, and DNS/Traefik for the production host. The shared secrets the deployment path reuses — `github_token` (tag resolution), `zot_ci_user` and `zot_ci_password` (registry pull), and `authentik_api_token` (blueprint) — must permit the `deployment` event in their Woodpecker event allowlists.

Build release images only for linux/amd64 with `docker build --platform linux/amd64 --target server-runtime --tag sovereign-config:local .`. `--target` is mandatory: the Dockerfile has a second final stage, `broker-runtime`, for the Woodpecker secrets broker (`docker build --platform linux/amd64 --target broker-runtime --tag sovereign-config-woodpecker-broker:local .`), and an untargeted build tags whichever stage is last in the file.
Woodpecker keeps two separate Cargo caches, and neither reuses the other. The `unit-test` step builds debug and test artifacts into the `sovereign-config-contract-target` volume. The image builds compile release artifacts into the `sovereign-config-cargo-target` BuildKit cache mount. Each cache is bounded at 20 GiB by its own prune script, `scripts/ci-prune-cargo-target.sh` and `scripts/ci-prune-buildkit-cache.sh`.

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

Use `sovereign-config profile update <name>` to replace a URL and `sovereign-config profile default <name>` to change the default. A URL can instead be supplied as exactly one line on standard input. Profile URLs are never accepted as process arguments. Operational commands accept a global override, for example `sovereign-config --profile prod status`. A host with no profile store at all — a CI container, a deploy step — can instead supply the URL through `--url-file` or `SOVEREIGN_CONFIG_URL`; see [Credential inputs](#credential-inputs).

`sovereign-config profile list` shows the stored profiles by name, marking the default with `*` and naming the server each one points at — its endpoint, followed by the configuration root when the profile is confined to one:

```
  dev         https://sovereign-config-dev.desync.link
* prod        https://sovereign-config.desync.link/team/service
```

`--format json` instead renders an array of `{ "name", "default", "endpoint", "root", "url" }`, where `url` is the whole connection URL with any managed credential replaced by `*`. **Nothing a listing prints is a secret** — but the file it reads is not safe to print, because a managed profile's stored URL embeds its credential. Use this command rather than reading `config.toml`. Listing succeeds with an empty result before the first profile is added.

Every value command reads `sovereign-config <verb> <ABSOLUTE_PATH> [OPTIONS]` — the path comes immediately after the verb — and acts on **exactly one value**. Add `--tree` and the same command acts on the whole subtree at that path instead: that is the only way to select subtree scope. `--format` then means one thing only, how a read is rendered: `plain` (the default) or `json`.

Every command path is absolute, begins with `/`, and is ASCII case-insensitive: `/x/FOO` and `/x/foo` are the same value, resolved and authorized without regard to case. This is case-**retentive**, not case-sensitive — the service is a case-preserving store like APFS or NTFS. The first write of a path stores the exact case it was given; later writes through a differently-cased spelling of that same path update the value but leave its case exactly as first established. Reads, listings, and subtree keys return whatever case is currently established, which may not match the case just typed. Changing an established path's case requires deleting it and writing it again under the new spelling — there is no rename. Segments contain only letters, digits, `-`, and `_` — the full grammar is `/` or `^/[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$`. A profile with a configured root accepts only absolute paths within that subtree. Written content is read from standard input so it never appears in process arguments. Interactive deletion requires typing `delete`; automation must pass `--yes` explicitly.

```sh
sovereign-config get /apps/api/settings
sovereign-config get /apps/api/database-password --reveal
sovereign-config get /apps/api --tree
sovereign-config get /apps/api --tree --reveal --format json
printf '%s' 'enabled=true' | sovereign-config set /apps/api/settings
printf '%s' 'database-password' | sovereign-config set /apps/api/database-password --secret
printf '%s' '{"enabled":"true","workers":"4"}' | sovereign-config set /apps/api --tree
sovereign-config list /apps/api
sovereign-config list /apps/api/settings --aliases
sovereign-config alias /apps/api/settings /apps/api-v2/settings
sovereign-config delete /apps/api/settings --yes
sovereign-config delete /apps/api --tree --yes
```

`get <PATH>` prints the one value stored at exactly that path, byte-exact and with no trailing newline, or `********` when it is a secret; descendants below it are ignored, and a path holding no value of its own fails with `configuration value not found`. `get <PATH> --tree` prints every value at or below the path. Add `--reveal` to return secret plaintext instead of the mask — for the one value, or for every secret leaf in a subtree. Revealing requires a `read` grant and never changes the stored data.

`set <PATH>` stores a plain value, `set <PATH> --secret` stores a secret, and `set <PATH> --tree` atomically replaces the subtree from a JSON document. All three read their content from standard input only. Writing a plain value requires `write`; subtree replacement requires both independent `write` and `manage` grants covering the selected root. `set` and `delete` print only fixed success summaries and never echo values.

`list <PATH>` prints the paths directly below a namespace: each child value as written, and each child namespace with a trailing `/`. `list <PATH> --aliases` instead prints every path that resolves to the one value at that path, including the path itself. `alias <SOURCE_PATH> <NEW_PATH>` exposes an existing value at a second path; both are then the same value, and deleting one leaves the other intact.

Plain output from `--tree` and `list` is one absolute path per line. A `--tree` line is `ABSOLUTE_PATH=VALUE`: a path segment can never contain `=`, so the **first** `=` always separates the two. So that one value is always one line, the value escapes `\` as `\\`, a line feed as `\n`, and a carriage return as `\r`; nothing else is escaped. **Plain output is therefore not byte-exact — use `--format json` when the exact bytes matter.** Values are ordered the same way the JSON renderer orders its keys, so the two formats always agree on order. They do not always agree on what is representable: a value that also has descendants — `/a` holding a value while `/a/b` exists — is two ordinary lines in plain, but cannot be a JSON node that is both a string and an object, so `--format json` fails on it. Plain is the more permissive of the two.

JSON output is deterministic and pretty printed; each stored plain-text value is represented as a JSON string and every secret is represented by the exact preservation marker `"********"`. `list` in JSON is an array of the same strings its plain form prints. Subtree JSON is relative to the selected path, so selecting `/foo/foo2/foo3` containing `/foo/foo2/foo3/deepvalue` returns `{"deepvalue":"deepvalue"}` without a `foo3` wrapper. An exact selected value is a root JSON string, and `/` is the root object. `set --tree` atomically replaces the selected subtree using the same relative shape. Omitted plain values are deleted, but existing secrets are never deleted or overwritten by a subtree replacement whether omitted or represented by their mask marker; a plain value may not collide structurally with an existing secret. Use an exact `set`, a secret rotation, or an explicit delete for those transitions.

### Rendering configuration into a command (`render`)

`sovereign-config render [<ABSOLUTE_PATH>...] [OPTIONS] -- <cmd> [args...]` reads one or more configuration subtrees, overlays them onto the inherited environment as environment variables, and then **replaces itself** with `<cmd>`. This is the deploy-time consumption path: a Compose stack or a CI deploy step keeps one narrow, read-only, centrally revocable connection rooted at its own subtree, instead of carrying every value inline.

```sh
sovereign-config render -- docker compose up -d --wait            # the connection root
sovereign-config render /apps/api -- ./deploy.sh                  # one layer
sovereign-config render /apps/api /apps/api/prod -- ./deploy.sh   # ordered, later wins
```

Paths are **layers**, read in the order given, with a later layer overriding an earlier one on a name collision. With no path at all, the layer is the connection's own root — the prefix the credential already encodes. Only the **direct children** of a layer become variables; a deeper descendant has no flat name and is ignored.

**The variable name is the leaf, exactly as stored.** `/foo/AbC` holding `bAr` reaches the command as `AbC=bAr`, precisely as `export AbC=bAr` would. Nothing is uppercased, lowercased or otherwise transformed: paths are case-retentive (see [2.18.0 retains path letter case](#2180-retains-path-letter-case)), so the spelling a value was created under is the spelling the command sees, and it is the only one a deploy can predict. Uppercasing would leave `AbC` unreachable, because no path would produce it.

So the case has to be right where the value is created. `/apps/api/database_url` yields `database_url`, not `DATABASE_URL`; store leaves under the exact variable names the command expects.

It follows that a collision is byte-exact on the name: two layers spelling a leaf differently produce **two** variables rather than overriding, because `AbC` and `abc` are two variables to the command as well. Only an exact match overrides.

Because path segments admit `-` and a leading digit but environment variable names do not, a leaf that cannot be a variable name — `db-password`, `2fa_key` — is **refused**, naming the offending path, rather than exported under a name no shell and no Compose file can reference. `-` is not folded to `_`: that mapping is many-to-one, and `db-password` and `db_password` are different values. Name leaves using letters, digits and `_` only.

The inherited environment is kept, not cleared: `PATH`, `HOME` and anything the caller set on the command line survive, because a deploy step routinely supplies one variable inline alongside everything it reads from configuration. Rendered values win a collision, being the more specific statement of intent — again matched byte-exactly, so an inherited `abc` and a rendered `AbC` are two variables.

```sh
SOVEREIGN_CONFIG_IMAGE_TAG=$(cat .release-tag) \
  sovereign-config render -- docker compose -p sovereign-config-dev up -d --wait
```

Three properties make this safe to point at a production deploy:

- **No shell is involved.** Values are placed in the child's environment through `execve`, so a value containing `$(...)`, a backtick, a quote or an embedded newline arrives byte-exact and is data. There is no stage at which it could be re-parsed as syntax.
- **The process is replaced, not wrapped.** The command's exit status and signal disposition are `render`'s own, with no supervisor in between.
- **It fails closed.** Every read happens before the exec, so a credential, read, reveal, confinement or naming failure means the command **never runs at all**, rather than running against a half-populated environment. A layer that contributes no variables is itself a failure: the service answers an absent subtree with an empty list, so a mistyped path is indistinguishable from a real but empty one, and neither is worth launching a deploy over.

  That cuts both ways, deliberately. An override layer you have not populated yet must be left off the command line until it holds something, and `render` against a connection root with no values at all will not start a command — there is no layer to drop in that case, so give the root a value first. Both are the same refusal: a layer named on the command line was named because it was meant to contribute.

`render` is a read; nothing is written to disk and no output mode other than the exec form exists yet.

#### Credential inputs

The hosts `render` exists for — a CI container, a Compose deploy step — have no profile store and no terminal to create one at, so two further credential inputs sit alongside `--profile`. All three are global and work on every operational command. Resolution order is fixed:

1. `--profile <name>` — an explicit choice always wins.
2. `--url-file <path>` — a file holding the connection URL as one line, such as a mounted CI secret. A single trailing newline is tolerated; an embedded one is refused rather than guessed at.
3. `SOVEREIGN_CONFIG_URL` — the variable a CI step injects.
4. Otherwise the default profile, which is where every interactive invocation lands.

**A connection URL is never a process argument**, here as everywhere else: it carries the credential, and process arguments are world-readable on a typical host. `--url-file` names a file and `SOVEREIGN_CONFIG_URL` names a variable; neither is the URL itself.

`render` removes `SOVEREIGN_CONFIG_URL` from the environment it hands the command, whether or not this invocation used it — the credential that read the configuration stops at `render`. It is removed before rendered values are applied, so configuration that legitimately holds a connection URL for the executed application's own use still reaches it; only the *inherited* credential is stripped.

#### Self-hosting exception

Sovereign Config's own deploy steps deliberately do **not** consume their configuration through `render`, and keep their Woodpecker secrets. Reading `/sovereign-config/prod/...` in order to deploy Sovereign Config would create a circular availability dependency: a broken production deployment could not be redeployed through a path that requires production to be readable. Other repositories and the homelab stacks are the intended consumers.

The native and gRPC-Web APIs use the `sovereign.config.v3` protobuf package. A client is not required to match the server's release: each connection negotiates a protocol version from the set the server advertises, so a client that speaks an older version than the server's newest keeps working and mixed-version operation is supported. Upgrading the server alone is therefore safe. See [Protocol versioning](#protocol-versioning) for how a version is introduced and retired, and note that protocol compatibility is a separate question from the client-visible behaviour changes described under [Upgrade](#upgrade) — 2.15.0 and 2.18.0 each broke older clients without any protocol version change.

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

### Authentik objects by environment

Every Authentik object this application relies on is created by that environment's blueprint, and **the two environments share nothing that carries authorization**. Each name below exists in exactly one environment; a principal added to a production object has no development access and vice versa. The only objects both blueprints own are the `sovereign-config-device-code` flow and the brand assignment that references it, which are identical in each and carry no permissions.

Nothing here is created by Sovereign Config itself except the per-connection service accounts noted at the end of each table — the server never seeds users, groups, roles, or authorization state.

#### Production — `authentik/blueprint.yaml`

| Object | Authentik kind | Purpose | Confers permission? |
| --- | --- | --- | --- |
| `sovereign-config-production-config-contributor` | Group | The contributor group. Carries the attribute `sovereign_config_prod_grants` set to `[{prefix: "/", permissions: [read, write, manage]}]`, so its members hold every permission on the whole production tree. **Add human operators here.** | Yes — through its grant attribute, not through the group name |
| `sovereign-config-connections` | Group | Organizational only. Every managed access-URL service account Sovereign Config provisions is added here so an operator can browse them together in Authentik. Carries no roles and no attributes. Named by `SOVEREIGN_CONFIG_MANAGER_GROUP`; membership failure is best-effort and never blocks a connection. | No — deliberately none |
| `sovereign-config-connection-manager` | Group | Binds the RBAC role of the same name to the connection-manager service account, which is its only member. Not for human membership. | Yes — Authentik RBAC, via its role |
| `sovereign-config-connection-manager` | RBAC role | Global `authentik_core.add_user`, `add_token`, `view_token`, and `view_group` — metadata only. `view_token_key` is deliberately never granted, so no token key is ever readable, and the role is not a superuser and has no Admin UI access. | Yes — global, narrow |
| `sovereign-config-connection-manager-objects` | Initial-permissions policy | Attaches object-level `view_user`, `change_user`, `delete_user`, `view_token`, and `set_token_key` to the role above **for the objects it creates only**, so it cannot read, change, or delete an unrelated user or token. | Yes — per object created |
| `sovereign-config-connection-manager` | Service account (user) | The connection-manager identity, in `goauthentik.io/service-accounts`, a member of the manager group above. Isolated from the introspection credential and from the browser. | Through its group |
| `sovereign-config-connection-manager-api` | Token (`intent: api`, non-expiring) | The API token that identity authenticates with. Supplied to the server as `MANAGER_API_TOKEN_FILE` / `SOVEREIGN_CONFIG_MANAGER_API_TOKEN`. | Acts as the service account |
| `sovereign_config_prod_grants` | User/group attribute | The direct grant attribute for this environment, named to the server by `SOVEREIGN_CONFIG_MANAGER_GRANTS_ATTRIBUTE`. Set it on a user, a service account, or any group for access narrower than the contributor group. | Yes — this is where production authorization actually lives |
| `sovereign-config production grants` | OAuth2 scope mapping (scope `sovereign-config`) | Reads `sovereign_config_prod_grants` from the requesting user **and every group they belong to**, deduplicates, and emits the common `sovereign_config_grants` claim. | Emits the claim the server evaluates |
| `<display-name-slug>-<connection-id>` | Service accounts (created at runtime) | One per managed access URL, created by the connection manager, granted exactly `{"prefix": "<root>", "permissions": [...]}` in `sovereign_config_prod_grants`, and added to `sovereign-config-connections`. | Yes — exactly the grant it was minted with |

#### Development — `authentik/blueprint-dev.yaml`

| Object | Authentik kind | Purpose | Confers permission? |
| --- | --- | --- | --- |
| `sovereign-config-development-config-contributor` | Group | The development contributor group. Carries `sovereign_config_dev_grants` set to `[{prefix: "/", permissions: [read, write, manage]}]`. | Yes — through its grant attribute |
| `sovereign-config-dev-connections` | Group | Browsing group for development managed access-URL service accounts. No roles, no attributes. Named by `SOVEREIGN_CONFIG_MANAGER_GROUP` in the development deployment. | No — deliberately none |
| `sovereign-config-dev-connection-manager` | Group | Binds the development RBAC role to the development connection-manager service account, its only member. | Yes — Authentik RBAC, via its role |
| `sovereign-config-dev-connection-manager` | RBAC role | Same narrow global permissions as production: `add_user`, `add_token`, `view_token`, `view_group`. No `view_token_key`, not a superuser. | Yes — global, narrow |
| `sovereign-config-dev-connection-manager-objects` | Initial-permissions policy | Same per-object `view`/`change`/`delete_user`, `view_token`, `set_token_key` attachment as production. | Yes — per object created |
| `sovereign-config-dev-connection-manager` | Service account (user) | The development connection-manager identity. | Through its group |
| `sovereign-config-dev-connection-manager-api` | Token (`intent: api`, non-expiring) | Its API token, supplied to the development deployment as `MANAGER_API_TOKEN_FILE` / `SOVEREIGN_CONFIG_MANAGER_API_TOKEN`. | Acts as the service account |
| `sovereign_config_dev_grants` | User/group attribute | The development direct grant attribute, named by `SOVEREIGN_CONFIG_MANAGER_GRANTS_ATTRIBUTE`. | Yes — this is where development authorization lives |
| `sovereign-config development grants` | OAuth2 scope mapping (scope `sovereign-config`) | Reads `sovereign_config_dev_grants` from the user and their groups and emits the same `sovereign_config_grants` claim. | Emits the claim the server evaluates |
| `<display-name-slug>-<connection-id>` | Service accounts (created at runtime) | One per development managed access URL, granted in `sovereign_config_dev_grants` and added to `sovereign-config-dev-connections`. | Yes — exactly the grant it was minted with |

The environment-specific names the server must be told about are exactly two, and both must match the blueprint that was applied to the same Authentik instance:

| Deployment variable | Production | Development |
| --- | --- | --- |
| `SOVEREIGN_CONFIG_MANAGER_GRANTS_ATTRIBUTE` | `sovereign_config_prod_grants` | `sovereign_config_dev_grants` |
| `SOVEREIGN_CONFIG_MANAGER_GROUP` | `sovereign-config-connections` | `sovereign-config-dev-connections` |

Note that the production connection-manager objects carry **no** environment word in their names (`sovereign-config-connection-manager`, `sovereign-config-connections`) while their development counterparts are infixed with `-dev-`, whereas the contributor groups spell both environments out in full (`-production-` / `-development-`). Read the name, not the pattern.

### Configuration grants

Each blueprint creates an environment-specific contributor group that bundles global `read`, `write`, and `manage` grants — `sovereign-config-production-config-contributor` against `sovereign_config_prod_grants`, and `sovereign-config-development-config-contributor` against `sovereign_config_dev_grants`.

Add a user or service account only to the contributor groups required for that environment. Group membership is an Authentik administration convenience, not a Sovereign Config role: the environment's scope mapping emits the existing granular `sovereign_config_grants` claim, and the server independently evaluates `read`, `write`, or `manage` for every operation. No contributor role name is sent to or expanded by the server.

For narrower access, place grants in the environment-specific direct grant attribute on a user, service account, or another group. For example, this development-only attribute permits reading one subtree without write or manage:

```yaml
sovereign_config_dev_grants:
  - prefix: /apps/example
    permissions:
      - read
```

Use `sovereign_config_prod_grants` for the equivalent production assignment. The `/` prefix is the global root. Every direct grant prefix must be absolute, for example `/apps/example`; after changing grants, obtain a new access token. Each environment's `sovereign-config` scope mapping combines and deduplicates only its own direct and group grants before emitting the common granular claim, so the same principal can have different development and production permissions. Sovereign Config rejects malformed, non-canonical, or unknown grants. It never seeds users or authorization state and PostgreSQL contains no ACL, grant, token, or session records. The one thing it does record is the [audit trail](#audit-trail), which holds no authorization state: it says what each identity did, never what it may do.

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

`sovereign-config-provider` is an ergonomic Rust facade for consuming a managed connection from application code: it parses the version-1 connection URL, obtains a fresh client-credentials token, reads only the encoded subtree over native gRPC, transparently reveals secret leaves, and deserializes the result into a `serde` type. It is a thin layer over the shared core/client/native crates and adds no new URL format, authentication, or transport. It is distributed as tagged workspace source only — there is no provider container or prebuilt library artifact. It does not have to be built from the server's tag: it negotiates a protocol version on connect (see [Protocol versioning](#protocol-versioning)), so a server upgrade does not require redeploying its consumers. See `crates/sovereign-config-provider/README.md` for the API, error surface, and the no-cache/no-retry contract.

## Woodpecker CI secrets extension

`sovereign-config-woodpecker-broker` is a Woodpecker CI external secrets extension backed by Sovereign Config, published as its own image (`registry.desync.link/sovereign-config-woodpecker-broker`) under the same semver as the server. Woodpecker POSTs signed repository and pipeline metadata to a single configured endpoint; the broker verifies the RFC 9421 Ed25519 signature — including recomputing the body digest — renders an ordered list of configuration layers from the repository in the request, reads them through a read-only managed connection, and returns the merged secrets in Woodpecker's format. Later layers override earlier ones, so a per-repository path can override a shared default, and the repository identity always comes from the signed request rather than from configuration. Woodpecker supports exactly one secret-extension endpoint, so adopting it is a replacement rather than an addition. Pipeline YAML is unchanged: secret names are stored verbatim as path segments, which is why the canonical path grammar permits `_`. Woodpecker matches `from_secret:` names by exact lowercase string, so the broker always resolves a layer's direct children by their fold key regardless of the case a value was written with — a value stored as `serverIP` is still found under `from_secret: serverip`. See `crates/sovereign-config-woodpecker-broker/README.md` for the environment surface, the layer syntax, the security notes, and the cutover runbook.

## Workspace layout

Each crate has one consumer, target, or artifact. Dependencies only point down this list.

| Crate | Role | Depends on |
| --- | --- | --- |
| `sovereign-config-proto` | Generated `sovereign.config.v3` gRPC types. | — |
| `sovereign-config-core` | The shared contract: paths, value and secret newtypes, listing shapes, the JSON subtree codec, connection URLs, and `ClientError`. No I/O and no async. | — |
| `sovereign-config-server` | The service binary: gRPC, gRPC-Web, PostgreSQL, Authentik. | proto, core |
| `sovereign-config-client` | The transport-agnostic client: the `Handshake` trait and the `negotiate` function that settles a session's protocol version, the `Transport`, `ValueTransport` and `ManagedConnectionTransport` traits a transport bound to that version implements, `SessionTransport` for one version's whole surface, `AccessTokenProvider`, and the `Client` facade. | core |
| `sovereign-config-native` | The native tonic transport, split into a `TonicChannel` that can only negotiate and the `TonicTransport` its `speaking` returns, with one dialer module per protocol version; plus OIDC device and refresh flows and the profile store. | proto, core, client |
| `sovereign-config-web` | The browser UI, compiled to WebAssembly, with its own gRPC-Web transport and dialer module per protocol version. | proto, core, client |
| `sovereign-config-layers` | Ordered configuration-layer reading and merging: per-layer `GetSubTree`, per-secret `RevealSecret`, direct-children-only naming, later-wins merge, and a caching client-credentials token provider. | core, client, native |
| `sovereign-config-mcp`, `sovereign-config-provider` | The MCP server and the application provider facade. | core, client, native |
| `sovereign-config-cli` | The CLI, whose `render` reads layers. | core, client, native, layers |
| `sovereign-config-woodpecker-broker` | The Woodpecker CI secrets extension image. | core, client, native, layers |

`core`, `client` and `native` stay three crates. Folding `client` into `core` would put `async-trait` and the transport abstraction into the server, which needs only the data contract. Folding `native` into `client` would pull tokio, reqwest and rustix into the WebAssembly build, which implements the same traits over gRPC-Web instead.

`sovereign-config-layers` sits above `native`, not inside it. The reader needs the native transport and a cached client-credentials token provider, and only the broker and the CLI need layer merging — the provider and the MCP server do not, and `client` must stay free of tokio for the WebAssembly UI. What stays with each consumer is everything around the read: how the layer list is arrived at (Woodpecker templates against a signed request in `woodpecker-broker/src/layers.rs`; positional paths in the CLI), how a connection is opened, and what is done with the merged map.

The two consumers differ on two policies, which is why each is a parameter rather than a default:

- **An unreadable layer.** The broker **skips** it, because failing a request would strip every concurrent pipeline of every secret; `render` **fails** on it, because a deploy that silently receives less configuration than it asked for is the failure it exists to remove.
- **Letter case.** The broker **folds** the leaf name and merges on the fold, because Woodpecker matches a `from_secret:` reference by exact lowercase string; `render` reports it **exactly as stored** and merges on that, because an environment variable name is case sensitive. One leaf `/apps/api/AbC` is therefore `abc` to the broker and `AbC` to `render`, and both are right.

### Where code goes

A module holds one concern. When a file starts mixing concerns, add a sibling module rather than growing it. `clippy.toml` holds functions to clippy's default of 100 lines, and `crates/sovereign-config-server/tests/lint_ratchet.rs` fails if product code silences that lint.

- **Server services** (`values/`, `managed/`): each is split at the protocol seam. `service.rs` is the **shared implementation** — authorization, validation, the control flow and every `Status` — written in no protocol version's terms: it takes a `CallContext` and unvalidated inputs, returns `sovereign-config-core` types, and holds no SQL. `v3.rs` is the **`v3` shim**: the tonic impl, which only restates a `v3` message as those inputs and encodes the result. Nothing but a `vN.rs` shim may import the proto crate, and `tests/lint_ratchet.rs` fails if anything else does. `store.rs` holds every row type and query. Authorization, pure validation such as `values/subtree.rs`, secret masking (`content.rs`) and version-free connection metadata (`wire.rs`) each get their own module. Authentik orchestration lives in `managed/provisioning.rs`. `rpc.rs` holds what every service shares, including the `CallContext`.
- **Server root**: `main.rs` is the startup sequence, one named step per concern. Authentication, Authentik, configuration, encryption, metrics and static assets each keep their own module.
- **Core**: one module per concept (`path`, `value`, `listing`, `json`, `status`, `error`, `connection`, `managed`). Every public item is re-exported from the crate root, and dependants import it from there.
- **Web**: one module per view (`configuration`, `value_rows`, `path_selector`, `tree`, `connections`, `downloads`) plus shared plumbing (`transport`, `session`, `route`, `shell`, `dom`, `browser`, `icons`). A thread-local static lives beside the code that owns it. Event handlers are registered through `dom::on_element_id` or `dom::listen`.
- **Tests**: unit tests sit in a sibling `tests.rs` declared with `#[cfg(test)] mod tests;`, and Postgres-backed ones are `#[ignore]` and run in CI with `--ignored`. Browser tests use one `browser-tests/tests/<area>.spec.js` per view, with shared mocks in `helpers.js`.

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

### 2.18.0 retains path letter case

Release 2.18.0 stops discarding the letter case a path was written with. The canonical grammar and resolution behaviour are unchanged: paths are still ASCII case-insensitive, `/x/FOO` and `/x/foo` are still the same value, and the service still folds ASCII letters to one lowercase key for uniqueness, lookup, and authorization. What changes is that a path-carrying response field — `ListedValue.path`, `ListedValue.alias_paths`, `ListValuesResponse.paths`, `SubTreeValue.path`, `ListValuePathsResponse` — may now return the mixed case a path was actually stored with, instead of always being lowercase. This is an additive `v3` change: message signatures and datatypes are unchanged, and every path stored before 2.18.0 is already all-lowercase and behaves identically.

It is **not** backward compatible for clients that assumed every response path was already lowercase and therefore compared or stripped it byte-exactly. A CLI, MCP server, `sovereign-config-provider` consumer, or Woodpecker broker build older than 2.18.0 rejects a response containing a mixed-case path as invalid and fails the whole request it arrived in — the same failure shape as the 2.15.0 underscore widening, for the same reason: these clients parse every response path with the strict, already-canonical parser.

Sequence the rollout accordingly:

1. Deploy the 2.18.0 server. Existing clients keep working, because no path has ever been written with mixed case.
2. Reinstall every CLI and MCP client from the upgraded server's `/dist` installer, and rebuild every `sovereign-config-provider` and Woodpecker broker consumer against tag 2.18.0 or later.
3. Only then write a path with a letter in anything other than lowercase.

Downgrading either the **server** or a **client** below 2.18.0 is not safe once a path exists with any letter case other than lowercase. Migration `0009` repurposes `configuration_paths.path` from the fold key it held before into the exact case a value was written with, and adds a generated `lowercase_path` column as the fold key in its place. A pre-2.18.0 server binds every lookup, collision check, and write against `path` on the assumption that it is already the fold key — once a row's `path` carries real mixed case, those byte-exact comparisons miss it (`NotFound` on a read) or collide with it (a unique-constraint failure on `lowercase_path` on a write), for the same reason a pre-2.18.0 client fails the whole response it parses.

### 2.25.0 widens `GetVersion`

Release 2.25.0 changes what `System.GetVersion` does, inside the already-released `sovereign.config.v3` package and with no protocol version bump. Before 2.25.0 it returned `FAILED_PRECONDITION` for any requested version other than the server's own. From 2.25.0 it **never rejects**: it answers `grpc-status: 0` with `supported_protocol_versions` listing what the server serves, and echoes the requested version only when that version is served — otherwise the server's newest. It also adds the additive `supported_protocol_versions` field. See [Protocol versioning](#protocol-versioning) for the mechanism this enables.

This is a deliberate exception to the rule, stated in that section, that changing what an existing RPC does requires a new package. It was made in place because a client has no other way to learn which versions a server serves: a rejection tells it only that *its* version is unwelcome, which is what forced servers and clients to be upgraded in lockstep. Shipping it as `v4` would have required every existing client to reach `v4` before benefiting, reproducing the flag-day problem it exists to remove. It was approved explicitly before implementation, as `AGENTS.md` §3 requires of any protocol change, and is recorded here because a rule with an unrecorded exception reads as a rule that is negotiable.

It is backward compatible for every client built from this repository, because none of them treats `grpc-status: 0` as acceptance, so all still fail closed. A build older than 2.25.0 compares the **echoed** `protocol_version` against the single version it speaks: asking for `v2` it receives `v3` back, sees a mismatch, and reports an incompatible protocol exactly as before. A 2.25.0 or later build selects from `supported_protocol_versions` and reports an incompatible protocol when that set shares nothing with its own.

It is **not** backward compatible for a third-party client that treats a successful `GetVersion` as acceptance and never reads the echo. Such a client used to be stopped at the handshake by `FAILED_PRECONDITION`; it now receives `grpc-status: 0`, concludes its version was accepted, and proceeds to issue RPCs on a protocol the server does not serve, failing later and less clearly with `UNIMPLEMENTED`. The echoed `protocol_version` has always been the documented answer to "which version is this session speaking", so the fix on the client side is to read it. No such client is known, and no rollout sequencing is required.

### 2.26.0 changes the client crates' API

Release 2.26.0 makes every client dial the version it negotiates. **No wire contract changes** — no `.proto` edit, no change to what any RPC does, and a 2.26.0 client and an older one negotiate against a server identically. Deploying the server needs no client change, as always.

It is, however, **source-breaking for code that builds against these crates**, which is the class [Protocol versioning](#protocol-versioning) warns about: a change can break clients without being a protocol change. Nothing breaks until a consumer rebuilds against tag 2.26.0 or later, and the migration is mechanical:

- `TonicTransport::connect(endpoint)` → `TonicChannel::connect(endpoint)`, then `channel.speaking(negotiate(&channel).await?.protocol_version)` for a transport that can carry configuration traffic. A channel can only negotiate; naming the negotiated version is what produces a usable transport, which is what keeps a reported version and a dialled route the same thing.
- `Client::service_status()` → the free function `sovereign_config_client::negotiate(&channel)`.
- `Transport::get_version` moves to the new `Handshake` trait and now takes a `ProtocolVersion` rather than a `&str`, because `GetVersion` is itself routed by version. Only code implementing `Transport` by hand is affected; `sovereign-config-provider` consumers are not.

`sovereign-config-provider`'s own API is unchanged, and it gains `Provider::protocol_version()` — worth logging at startup, since it is the version the service's per-version counters attribute the application to.

### 2.28.0 adopts the unversioned handshake

Release 2.28.0 moves negotiation onto a **new unversioned service**, `sovereign.config.Handshake`, and gives a request for a version the server does not serve a **distinct error** instead of tonic's generic `UNIMPLEMENTED`. Both are protocol changes, approved before implementation as `AGENTS.md` §3 requires. Neither touches `proto/sovereign/config/v3/`: no `v3` signature, and no `v3` behaviour, changed.

**For deployed clients, nothing changes at connect.** A 2.25–2.27 client negotiates by calling `GetVersion` on `v3`'s own route, which is still served, still unauthenticated, and still echoes the version it was asked for. Upgrading the server alone remains safe, as always.

**The catch-all is the 2.15.0 / 2.18.0 class of change**, and is called out for it: it alters what an already-deployed client receives on a route it may one day hit, and negotiation cannot protect a client that is already in the field. The blast radius is nil in practice, because every client from 2.25 on maps `FAILED_PRECONDITION` and `UNIMPLEMENTED` to the same incompatible-protocol error, so one of them meets the new answer exactly as it meets a deleted route today. That is asserted, not assumed, by `a_client_that_predates_the_catch_all_still_reports_incompatible_protocol`.

It is **source-breaking for code that builds against the client crates**, the same class as 2.26.0. Nothing breaks until a consumer rebuilds against tag 2.28.0 or later:

- `Handshake` is now two methods: `served_versions(&[ProtocolVersion])`, which calls the unversioned handshake, and `legacy_version()`, which calls `GetVersion` on `ProtocolVersion::LEGACY`'s route for a server that has no handshake. `Handshake::get_version(version)` is gone.
- `negotiate` returns a `ServiceStatus` carrying `protocol_version` and an optional `deprecation_date`. It no longer carries `application_version`: the handshake carries versions and nothing else, so the service's release version is read from `System.GetVersion` on the negotiated route — `TonicTransport::dialer_version()` natively, `SessionTransport::get_version()` through a dialer.
- `ProtocolVersion` is declared **most preferred first** and no longer derives `Ord`. Nothing compares versions: selection follows the server's order.
- `ClientError::message()` returns `&str` rather than `&'static str`, because the incompatible-version error now names the version lists both ends offered, which cannot be known at compile time. It is bounded and stripped before it is built.
- `ErrorKind` gains `VersionNotServed`, distinct from `IncompatibleProtocol`. Exhaustive matches on `ErrorKind` must handle it.
- `sovereign-config-mcp`'s `Backend::service_status` returns a `ServiceReport` rather than a `ServiceStatus`, and `ToolFailure::message` is a `String`.

`sovereign-config-provider`'s own API is unchanged. Its documented **fail-fast-on-retirement contract is reversed**, however: a provider whose negotiated version is retired under it now re-handshakes once and retries the load, rather than failing. The retry is safe because the rejected call never executed, and the retirement stays observable through the logged version change and the per-version counters. See [How negotiation works](#how-negotiation-works).

Configuration values are stored in PostgreSQL as content rows holding a `plain` or `secret` classification, the value itself — sealed as an `enc:v1:` AEAD envelope when the classification is `secret`, verbatim when it is `plain` — and service-generated UTC creation/update timestamps, plus one or more path rows that each expose that content at a canonical absolute path beginning with `/`. Existing values migrate to exactly one path each. Each path row stores the exact case it was written with in `path`, and Postgres computes and stores its lowercase fold key in the generated `lowercase_path` column, which carries the primary key; `lowercase_path` can never drift from `path` because it cannot be written to directly. The fold key is what every comparison, lookup, and collision check uses — a path's stored case is a display concern only, never resolved or rewritten a segment at a time, so two path rows sharing a fold-equal ancestor may each keep their own case for it (see 2.18.0 above). Writing through any path updates the shared content, so every path to that value observes the change; classification cannot be changed while more than one path resolves to the value. Deleting a path removes only that path, and the value is deleted permanently once its last path is removed, in the same transaction and with no background reconciliation. There is no history or duplicate secret copy of the value itself; what was done to it is recorded separately in the [audit trail](#audit-trail), which holds a plain value's previous text but never a secret's. Updates are last-write-wins and preserve the original creation timestamp. Deletion is a hard delete with no tombstone, rollback record, or retained value history. Application-level encryption covers secret-classified values only, so PostgreSQL volume and backup encryption remain operator responsibilities for everything else the database holds.

Exposing one value at several paths is a deliberate administrative act that requires `write` on both the existing and the new path and `read` on the existing one. It widens who can reach that value: a secret aliased into a namespace where more principals hold `read` becomes revealable by them. Listings and path queries only ever return the paths a caller may read, so a value may have paths that a given principal can neither see nor operate on.

The browser opens on configuration values; `/` resolves there, and the Access URLs and Downloads views are reached from a menu on the brand mark. The header carries the signed-in operator's name, taken from the OIDC ID token and used for that label alone, alongside the application version the service reports; an unreachable service is called out there rather than on a page of its own. The session's protocol version is deliberately not shown there — it is a client-compatibility concern, not an operator's — so the CLI and the MCP `status` tool are where it is read. Configuration URLs use `/configuration/<path>` and are always lowercase, but the path field, grid rows, and JSON editor all display each value under the exact case it was stored with; the final segment of each stored path is the value name. A drag-resizable sidebar carries the whole readable namespace tree, drawn with box-drawing characters and labeling each namespace with whichever case one of its own values established first — when two values under one namespace disagree on its case, the tie is broken deterministically, not by displaying two rows. Selecting a node opens that path directly, a node holding values of its own is shown in bold, and a node that is the root of an access URL carries a key. The tree is built from one whole-estate read, so a principal scoped to a prefix — which cannot read the root subtree — still gets the tree, without the bold markers. Below the sidebar breakpoint the tree is not shown and the path selector is the way to move between paths. The path selector offers namespaces containing readable values and also accepts a valid namespace that does not exist yet, which is how a value is first created under a namespace the tree cannot yet show. Leaving a path that holds an unsaved value edit — including through the browser's Back button — raises a confirmation before the edit is discarded. Each path's own access URLs are listed and can be created, rotated, and revoked beneath its values, with the selected node as the root; the Access URLs page remains the estate-wide view. Listing filters every returned value through server-side `read` permission, while row saves and deletes both require `write` permission. A secret is one padlocked field: blank behind a masked placeholder, never pre-filled with stored content, and the same box a replacement is typed into — so writing a new secret never requires the permission to read the current one. Opening the padlock is the explicit action that reveals the stored plaintext and leaves it editable in place. Revealed values are cleared when the padlock is shut, reloaded, navigated away from, logged out, or when any request fails. Per-row and per-entry actions are icon buttons whose tooltip and accessible name both name the value they act on. The JSON switch is off by default; when enabled it loads the entire selected subtree with all-or-nothing `read` authorization and replaces the grid with a pretty JSON editor. Saving preserves masked secrets, atomically replaces plain values, and leaves per-value deletion unavailable in JSON mode.

### 2.29.0 makes `RevealSecret` fail closed on an audit fault

Release 2.29.0 adds the [audit trail](#audit-trail), and with it the second recorded exception to the rule that changing what an existing RPC does requires a new package. `v3`'s `RevealSecret` now writes an audit record before it returns a secret, and **fails the reveal if that record cannot be written**. It used to perform no writes at all.

What a client sees is unchanged: the failure is `UNAVAILABLE` with the message `configuration storage is unavailable`, exactly the status the RPC already returned when its own read failed, and the success path is byte-identical. What changes is **which faults produce it**. A database that still serves reads but refuses writes — disk full, a failover that leaves it read-only, a fault on the `audit_events` table — used to leave reveals working and now fails them. That is new behaviour on a released package, so it is recorded here rather than argued away.

It was made in place rather than as `v4` because it cannot be confined to a version. Recording that only happened on some protocol version would make every other version a way around the trail, which would defeat it. The alternative that avoids the exception — recording reveals best effort, as plain reads are — was considered and rejected: an unrecorded secret access is the one thing the trail exists to prevent, and a fault that silently stops recording secret access is exactly when it matters most. It was approved explicitly, during review of the change and before it merged; unlike 2.25.0 it was not approved before implementation, which is recorded because that is what happened.

**Who it can affect:** any client that reveals secrets, which includes every application embedding the provider. During a write-refusing fault, a provider load that needs a secret fails where it previously succeeded, and so does starting any such application, since the provider holds no last-known-good configuration. The provider already treats `UNAVAILABLE` as a failed load, so nothing misbehaves; it fails, visibly and for the reason stated. `sovereign_config_audit_events_total{kind="secret.revealed",outcome="failed"}` counts each one, and is the series to alert on. No rollout sequencing is required.

Changes (`PutValue`, `ReplaceSubTree`, `DeleteValues`, `AddValuePath`) also record inside their transactions and fail closed, but they are not part of this exception: they already wrote, and already failed when the database refused a write. `GetSubTree` and `ListValues` record best effort, and gain no failure mode at all.

## Protocol versioning

Applications embedding `sovereign-config-provider` are deployed independently of the server and are expected to lag it. A server upgrade must therefore never break them. This section is the whole procedure for introducing and retiring a protocol version; it is self-contained and needs no reading of source.

### How negotiation works

1. The client calls the **handshake** — `/sovereign.config.Handshake/Negotiate` — sending every protocol version it speaks. The handshake is the one operation that is **not versioned and not routed by version**, and the only one a client may call before a version is agreed.
2. The client's list exists for the server's **usage records only**. The server never filters or reorders its answer by it, never rejects on it, and treats it as untrusted input: it is counted under compiled-in labels, bounded in how much is examined, and can never mint a metric label of its own.
3. The server answers with **every version it serves, most preferred first**, whatever the client asked for, and **never rejects**. Each version may carry a `deprecation_date` — an RFC 3339 UTC timestamp before which the server does not expect to retire it. That is a statement of intent, not a guarantee: a version may be served well past it, and a security flaw may retire one before it.
4. The client selects the first version in the **server's** order that it also speaks, passing over a version carrying a deprecation date while one without is still to come. A selected deprecation date **warns and never fails** — the CLI to stderr, the MCP `status` tool in its output, the provider and broker through `tracing`, the browser in the header slot it already uses to report trouble with the service. With no version in common the client aborts with a bounded incompatible-protocol error that **names both lists**, so an operator can tell which end has to move.
5. **Every RPC that follows travels on the negotiated version's routes.** A client is opened as a connection that can do nothing but negotiate; naming the negotiated version is the only way to obtain one that can carry configuration traffic. What an operator is shown is read back off that transport, so a reported version and a dialled route cannot disagree.
6. If a later call fails with the **version-not-served** error, the client repeats the handshake **once**, selects again, obtains a *new* transport, and retries that call. The rejected call never executed, so the retry is safe. It logs the change of version. If nothing is in common, or the retry fails the same way, it aborts.

**The handshake's shape is fixed, forever.** It can never be versioned, because it is the operation that tells a client which versions exist. It never gains, loses, retypes or repurposes a member. Anything a client needs beyond the list of served versions belongs in a versioned operation — which is why the service's release version is read from `System.GetVersion` on the negotiated route rather than from the handshake.

The handshake is **unauthenticated**, and this is the recorded reason: a client has no token before it has negotiated, `System.GetVersion` already publishes the same list to anyone, and leaving the handshake outside authentication keeps each protocol version free to change its own authentication scheme. The cost is that the served list and the client lists sent to it are public, which is what the untrusted-input handling in step 2 exists for.

#### Reaching a server that has no handshake

Every server up to 2.27 authenticates **before** it routes, and exempts only the health probes and `<served>.System/GetVersion`. A handshake call carries no token, so such a server refuses it `UNAUTHENTICATED` — the request never reaches the router that would have said `UNIMPLEMENTED`. **Detecting a pre-handshake server is therefore not "`UNIMPLEMENTED`"**, and the obvious test fixture lies about this: a bare router with no authentication in front of it answers `UNIMPLEMENTED`, while a real deployed server answers `UNAUTHENTICATED`.

On either answer the client falls back to `GetVersion` on `ProtocolVersion::LEGACY`'s own route, which those servers do exempt. If it answers, the server serves exactly that version. A handshake failure of any other kind — `UNAVAILABLE`, say — is reported as itself, and a fallback that also fails reports the fallback's failure. A server that *has* the handshake never answers it `UNAUTHENTICATED`, so the fallback cannot mask a genuine authentication problem.

### The rule that makes this work

**Adding a protocol version must never change what an existing version's clients see.**

`GetVersionResponse.protocol_version` is why. Clients compiled before `supported_protocol_versions` existed ignore that field entirely and compare the echoed `protocol_version` against the single version they were built with. If the server ever echoed *its own preferred* version instead of the requested one, every one of those clients would fail on the day a newer version shipped — and they are already deployed, so they cannot be fixed retroactively. That is the fleet-wide outage this mechanism exists to prevent. **Never change the echo semantics.**

The echo falls back to the server's preferred version only when the requested version is not served at all. A client asking for a version it speaks can never observe that fallback.

`v3` also advertises its `supported_protocol_versions` **oldest first**, while the handshake reports **most preferred first**. The two orders are opposite on purpose: `v3` has advertised oldest-first since the field was added and a `v3` client is entitled to that order, so changing it would be a `v3` behaviour change and therefore a new version.

The regression tests that protect this are `a_server_newer_than_this_build_still_connects`, `a_client_compiled_without_the_supported_set_still_decodes_and_negotiates`, and the echo tests in `system.rs`. Do not weaken them.

### The version-not-served error

A request on a **version-shaped route naming a version this server does not serve** — retired, or never existed — is answered by a catch-all with `FAILED_PRECONDITION` plus two fixed metadata keys: one naming the kind (`version-not-served`), one echoing the version asked for. A client identifies it by the **marker, never by the status code**, which is shared with failures that are not about versions.

A mistyped service or method on a *served* version stays `UNIMPLEMENTED`. Keeping those two apart is the point: a retired version is something a session can recover from by re-handshaking, and a typo is not.

Two placement decisions are load-bearing, and `auth::grpc_service_layer` is what pins them:

- the catch-all sits **inside** the gRPC-Web layer, so a browser receives an answer it can decode. Outside it, a retirement would reach the browser as an undecodable transport failure with no version in it;
- it sits **outside** authentication, because an unserved version has no authentication scheme left to apply, and a client whose credentials also expired while it was away should still be told what actually broke.

Both are asserted in `crates/sovereign-config-server/src/protocol/serving_tests.rs`.

### What forces a new version, and what does not

A new version **is** required for:

- renaming, renumbering, retyping, removing or repurposing an existing field;
- changing what an existing RPC does — the behaviour of a call is part of the contract, not just its signature;
- **adding any field or RPC, even an optional one**;
- **changing the set of values an existing field may carry** — a wider or narrower grammar, letter case, range, or a new enumeration member.

The last two were relaxed until 2.28.0, which is what releases 2.15.0 (path grammar) and 2.18.0 (path letter case) are this repository's own evidence against: both were additive to the `v3` contract, both shipped without a version bump, and both broke older clients, because a client validates what it was built to expect and one unexpected value fails the whole response carrying it.

A new version is **not** required for bug fixes or performance improvements that change no API shape and no substantive behaviour.

**Exceptions are approved before implementation and recorded**, with the reason and who they can affect — a rule with an unrecorded exception reads as a rule that is negotiable. There have been two:

- release 2.25.0 widened `GetVersion` itself in place, because the negotiation mechanism could not otherwise be introduced without the flag day it exists to remove. It is recorded under [2.25.0 widens `GetVersion`](#2250-widens-getversion). Treat it as the bootstrap of this mechanism, not as precedent.
- release 2.29.0 made `RevealSecret` fail closed when its audit record cannot be written, because recording confined to one version would make every other version a way around the audit trail. It is recorded under [2.29.0 makes `RevealSecret` fail closed on an audit fault](#2290-makes-revealsecret-fail-closed-on-an-audit-fault). It is not precedent for other behaviour changes either: its justification is specific to a record that must not be bypassable.

Note the converse: a change can break clients *without* being a protocol change. 2.26.0 and 2.28.0 both changed the client crates' API without touching any wire contract. Version negotiation does not protect against that class; see [Upgrade](#upgrade) for how those were sequenced.

### Recorded deviations

Where this repository knowingly differs from the general contract, with the reason:

- **A `v3` shim validates nothing.** Input it cannot translate, such as an unset oneof, goes down as `None` for the shared implementation to reject. The general rule is that a version's shim performs that version's own basic validation, but moving it into `v3`'s shim would reorder `v3`'s errors — `PutValue` authorizes before it validates content — and changing the order in which an existing RPC fails is a behaviour change, and so a new version. **A new version's shim does its own basic validation**; `v3`'s does not, and will not.
- **Shims do not yet share adapter code.** The rule is that adapter code for an operation whose wire shape is identical across versions lives once and is referenced by each shim, never copied and never chained. Generated types differ per package, so sharing needs a macro or a generic; whoever adds `v4` chooses, with a second real version to test against. Until then there is one shim per service and nothing to share.

### Introducing a new version

Each version is its own protobuf package, because the gRPC route path embeds the package name — `/sovereign.config.v3.System/GetVersion`. Distinct packages mean distinct routes, so two versions serve concurrently on one router with no dispatch ambiguity. This is proven end to end by `test-consumers/sovereign-config-proto-testversion`, a dev-only package registered alongside `v3` in the server's own tests; read those tests if you want to see the mechanism working before you rely on it.

The handshake is **not** part of this. It lives outside every version in `proto/sovereign/config/handshake.proto` and `crates/sovereign-config-server/src/handshake.rs`, has no shim, and is never copied or edited when a version is added.

To add `vN`:

1. Add `proto/sovereign/config/vN/service.proto` with `package sovereign.config.vN`, starting from the previous version's file. Make the breaking change there, and only there.
2. Compile it in `crates/sovereign-config-proto/build.rs` and expose it as a `vN` module in that crate's `lib.rs`, alongside `v3`.
3. Write the `vN` ↔ core mapping shims beside `crates/sovereign-config-server/src/values/v3.rs` and `managed/v3.rs`, point each at the `vN` generated types, and add its `mod` line and re-export in `values.rs` / `managed.rs`. **This layer must be only the proto↔core translation, plus that version's own basic validation.** Domain types in `sovereign-config-core` stay version-free, so a second version is a translation shim over one implementation rather than a forked server. If you find yourself duplicating logic rather than mapping types, the change belongs in the shared implementation (`service.rs`) or in core, not in the shim.

   **Share adapter code, do not copy it and never chain it.** Because every added field or RPC is now a new version, most of a new version is unchanged from the one before — so an operation whose wire shape is identical in both should have one adapter referenced by both shims. A shim must never call another version's shim, or retiring a version would mean untangling the ones built on it. See [Recorded deviations](#recorded-deviations) for where this stands today.

   And the shared implementation **never branches on the version**: the `CallContext` it receives may record which version a call arrived on, but an implementation that behaves differently per version is a forked server with extra steps. `System` stays per-version (`system.rs`), because `GetVersion`'s echo is version-specific by nature.
4. Register the `vN` services on the router in `crates/sovereign-config-server/src/main.rs`, **leaving every existing `add_service` line in place.** Construct each `vN` shim over the same `Arc` of the shared implementation the `v3` line uses — one implementation, however many versions.
5. Teach the **clients** to dial `vN`:
   - Add `VN` to `ProtocolVersion` in `crates/sovereign-config-core/src/status.rs`, declared **before** the existing variants — the list is preference order, most preferred first. This says only that clients in this workspace can *speak* `vN`; it advertises nothing.
   - **The workspace now fails to compile**, in `crates/sovereign-config-native/src/transport/mod.rs` and `crates/sovereign-config-web/src/transport/mod.rs`. Each selects its routes with an exhaustive `match` on `ProtocolVersion`, so a version with no dialer is a non-exhaustive-patterns error naming the transport that cannot speak it.
   - Fix it by writing the dialers: add `transport/vN.rs` in each crate pointing at the `vN` stubs (native) or the `/sovereign.config.vN.…` paths (browser), and add the `ProtocolVersion::VN` arm. **These modules must be only the proto↔core translation**, and share adapter code for the same reason step 3 gives on the server side.

   The order is deliberate: declaring the version first is what produces the compile error, and the compile error is what stops the version being declared without dispatch. Do not work around it by returning an older version's dialer — a version negotiated and reported while its traffic travels on an older version's routes makes `sovereign_config_protocol_requests_total` read backwards, showing the version actually carrying the traffic as idle and the unused one as busy. Since that counter is the retirement gate below, the result is a gate that says it is safe to delete the version everything is using.

   `crates/sovereign-config-native/tests/protocol_dispatch.rs` then checks, for every version in `ProtocolVersion::ALL`, that each RPC reaches a route naming that version — asserted on what the server received. It covers `vN` the moment `vN` is declared; there is no list in it to extend. The browser's equivalent is `every_route_the_browser_dials_names_the_version_it_speaks`.
6. Add `vN` to `SERVED_PROTOCOL_VERSIONS` and `SERVED_PROTOCOL_LABELS` in `crates/sovereign-config-server/src/system.rs`, `vN` **first** — that list is the server's preference order, and the handshake reports it verbatim. Do this **last**: it advertises the version to clients, so the services implementing it must already be registered.

Two things you do *not* have to edit, because they derive from `SERVED_PROTOCOL_VERSIONS` and would be easy to miss:

- **The unauthenticated-RPC allowlist.** `GetVersion` is called before any token exists by every client that predates the handshake, so it must stay unauthenticated on every served version. `is_operational_rpc` in `crates/sovereign-config-server/src/auth.rs` matches `/sovereign.config.<served>.System/GetVersion` against the served set rather than listing paths, so step 6 exempts `vN` automatically. The handshake route is exempt by name, and is not version-derived because it names no version.
- **The per-version metric label**, which comes from `SERVED_PROTOCOL_LABELS` in the same step.

Deploy the server before any client change. Clients now negotiate `vN` automatically; clients that have not been rebuilt continue on `v3`.

### Retiring a version

**Announce it first.** Set a `deprecation_date` on the version in `SERVED_PROTOCOL_VERSIONS` and ship that, so clients selecting it warn their operators and clients that can move to a non-deprecated version do so on their own. The date is a statement of intent, not a commitment: it binds nothing, and a security flaw may retire a version before it.

**Then confirm no real consumer still speaks the version.** The gate is the **authenticated** series:

```
sovereign_config_protocol_requests_total{version="v3",outcome="authenticated"}
```

A version may be retired only once that series has been flat at zero across an observation window long enough to cover the slowest-moving consumer — at minimum a full deployment cycle of every application that embeds the provider. `sovereign_config_protocol_client_versions_total` is the companion view: it counts the versions clients *say* they speak in their handshake lists, so it shows a fleet becoming ready for a retirement before the request series goes quiet.

**Check how much metric history you actually have before reading the gate.** "Flat at zero across a full deployment cycle" is a claim about a window, and it can only be made over samples that still exist. Prometheus retention is set outside this repository (the homelab `monitoring-stack` keeps one day), and a consumer that loads configuration at startup and restarts weekly is invisible six days in seven — so a one-day window says almost nothing about a monthly deployment cycle. Either raise retention to cover the observation window, or alert on any authenticated traffic for the version after cutover, since an alert's firing history does not depend on how long samples are kept.

**Use the [audit trail](#audit-trail) to explain the metric, not to replace it.** The trail records the identity *and* the protocol version on every hooked call and keeps them for a year, so it is what names the consumer to chase when the gate will not go quiet; every application that embeds the provider begins a load with a plain read, so none of them can stay on an old version without appearing there. The metric stays the gate all the same: it is counted in the authentication layer for every authenticated RPC by construction, including calls nobody thought to audit, while the trail covers the calls that were hooked and records reads on a best-effort basis. In practice the two agree. If they do not, that is a finding to understand before retiring anything.

Gate on `authenticated`, **not** on `attempted`. The gRPC endpoint is public, so `outcome="attempted"` counts everything whose route names the version before authentication runs — including an internet scanner, or a decommissioned application whose credentials were revoked months ago but whose process still retries. None of those breaks when the version is retired, yet any of them can hold `attempted` above zero indefinitely; gating on it would mean never retiring anything, or learning to ignore the counter. Nothing unauthenticated can move `authenticated`. A non-zero `attempted` with `authenticated` at zero is worth a look in the logs, but it is not a reason to keep the version.

This is a precondition, not a courtesy. The provider does not cache: it holds no last-known-good configuration, by deliberate design, because retaining one would keep revealed secrets in process memory for the application's lifetime. An application still speaking a version you delete therefore fails on its next configuration load — it re-handshakes once, and if nothing is left in common, that is the end of it.

Once the authenticated series reads zero:

1. Delete `proto/sovereign/config/v3/` and its entry in `crates/sovereign-config-proto/build.rs` and `lib.rs`.
2. Delete the `v3` mapping shims — `crates/sovereign-config-server/src/values/v3.rs` and `crates/sovereign-config-server/src/managed/v3.rs` — with their `mod` lines and re-exports. The shared implementations beside them (`service.rs`) are untouched: they never knew `v3` existed.
3. Delete the `v3` client dialers — `crates/sovereign-config-native/src/transport/v3.rs` and `crates/sovereign-config-web/src/transport/v3.rs` — with their `mod` lines and their arm of each `dialer` match.
4. Delete the `v3` `add_service` lines in `crates/sovereign-config-server/src/main.rs`. **Its routes now fall to the catch-all**, which answers them version-not-served; there is nothing else to remove for dispatch.
5. Remove `V3` from `ProtocolVersion`, `SERVED_PROTOCOL_VERSIONS` and `SERVED_PROTOCOL_LABELS`, and repoint `ProtocolVersion::LEGACY` if it named `V3`.
6. Update `SYSTEM_SERVICE_NAME` in `main.rs`, which the container health probe asks for by name.

Steps 3 and 5 hold each other honest: removing the variant while a dialer still names it is a compile error in that dialer, and removing the dialer while the variant remains is a non-exhaustive `match`. `LEGACY` is checked the same way. A retired version leaves no orphan in either direction.

Announce the retirement to every consuming repository before it ships. A client outside the supported range fails with a bounded incompatible-protocol error naming both lists at connect, which is a clear error but not a recoverable one.

## Audit trail

Every change to a configuration value, every reveal of a secret, every read of configuration, and every managed-connection create, rotate and revoke is recorded in the `audit_events` table, attributed to the identity that caused it and the protocol version its call arrived on. Nothing reads the trail back over the protocol yet — that needs a protocol version of its own — so it is queried directly in PostgreSQL for now.

**No secret value is ever recorded.** A value reaches the trail only as plain content: `old_value` and `new_value` are populated for a plain value changing and are `NULL` for everything else, and a narrative naming a secret names its path, actor and action and nothing more. A read records the path it was asked for and how many values came back, never the values themselves — a subtree can hold secrets, masked or not, and the trail has no business copying content it was only asked to witness. The rule is enforced three times over: values reach an event only through a constructor that discards anything not classified plain, a table constraint confines them to the three single-value change kinds, and tests assert directly that no secret text reaches any column.

Recording lives in the version-free service implementations, never in a protocol shim, so **every served protocol version is audited identically** and speaking an older one is not a way around the trail. Each record carries the served-version label of the route actually dialled, taken from the request rather than from a per-version constant, so a version added by copying an existing shim cannot misattribute its own traffic.

**A repeated access collapses into one row.** Secret reveals, subtree reads and listings are keyed by identity, protocol version, path and time window: a repeat inside the window bumps `event_count` and moves `occurred_at` to the latest occurrence rather than inserting a row. This is what keeps a year of retention viable, because the provider does not cache and reveals every secret on every load. Changes never coalesce. The count and the period are rendered from `event_count`, `first_occurred_at` and `occurred_at` when a row is read, and are deliberately not stored in the narrative, so bumping a window stays a single statement. **The protocol version is part of the key on purpose**: during a rolling deploy one identity is seen on two versions inside one window, and they must stay two rows or the trail would misreport the very thing the column exists to show.

**Failure policy differs by what is at stake.** A change records inside the mutation's own transaction and fails closed, so a change that could not be recorded did not happen. A secret reveal fails closed too, before the secret is returned. Both report the storage fault the RPC already returns when its own query fails, so no deployed client meets a status it does not already handle. A plain read is best effort: `GetSubTree` and `ListValues` perform no other write, and making every configuration read depend on the database accepting writes would give them a failure mode they do not have today — so a failed record is counted and logged and the read is served. Managed-connection flows call Authentik between their database steps, so their record is atomic with the state change that completes the operation; a failure leaves the row in the intermediate state that flow already recovers from.

`sovereign_config_audit_events_total{kind="…",outcome="…"}` counts every write by event kind. **`outcome="failed"` is the series to alert on:** a failed write either failed the operation it belonged to or, for a plain read, was dropped while the read was served — either way the trail and reality have parted, and this counter is the only place that shows. `sovereign_config_audit_retention_swept_total` and `sovereign_config_audit_retention_sweep_failures_total` cover the retention sweep, which runs hourly in the background, deletes events last seen before the retention cutoff, and never takes the server down on failure.

| Variable | Default | Purpose |
| --- | --- | --- |
| `SOVEREIGN_CONFIG_AUDIT_RETENTION_DAYS` | `365` | How long an event is kept after it was last seen. Maximum `3650`. |
| `SOVEREIGN_CONFIG_AUDIT_COALESCE_WINDOW_HOURS` | `24` | The window inside which repeated accesses collapse into one event. Maximum `168`. |

Each is optional, because the defaults are the intended configuration. One that is set but unusable fails startup rather than falling back, so a mistyped retention cannot silently become a year.

**Used with the retirement gate, not instead of it.** Because every consumer begins a configuration load with a plain read, the trail sees every application that embeds the provider, and — unlike Prometheus, which keeps one day — it remembers for a year, so it can name the consumer still on an old protocol version. The `authenticated` metric series remains the formal gate under [Retiring a version](#retiring-a-version): it is counted in the authentication layer for every authenticated RPC by construction, while the trail covers the calls that were hooked and records reads best effort. If the two disagree, that is a finding, not a tie to break in favour of the more convenient one.

## Observability

The application writes structured redacted JSON logs to stdout. Authentication events contain only the RPC path and bounded outcome/reason values. Internal Alloy discovers `/metrics` using the Docker labels in `compose.yaml`; that endpoint is not routed through Traefik. `sovereign_config_authentication_total` reports bounded success/failure reasons without request-derived labels. OTLP export is introduced by its separate card.

`sovereign_config_protocol_requests_total{version="…",outcome="…"}` counts gRPC requests by the protocol version their route names, in two series:

| `outcome` | Counts | Answers |
| --- | --- | --- |
| `attempted` | Every `POST` to a well-formed route of that version, **before** authentication. gRPC and gRPC-Web are `POST`-only, so a crawler's `GET` against a versioned path counts nowhere. | Is anything still *trying* to speak this version? Includes scanners and clients with revoked credentials. |
| `authenticated` | The subset of those that passed authentication. | Is any **real consumer** still speaking this version? |

**The `authenticated` series is the input to the retirement decision** described under [Protocol versioning](#protocol-versioning): a protocol version may not be removed until it has been flat at zero across a full deployment cycle of every consuming application, because clients have no fallback. It is a separate series precisely so the gate is reachable — the endpoint is public, and traffic that would not break on retirement can hold `attempted` above zero forever. `attempted ≥ authenticated` always holds, and the difference is refused traffic.

Both answer a question `GetVersion` alone cannot — negotiation happens once at connect, so a long-lived provider registers a single connect and then goes quiet while its traffic continues. The `GetVersion` handshake is itself unauthenticated, so it appears under `attempted` only. The `version` label is drawn from a compiled-in list and never from the request. Traffic on a `/sovereign.config.` route this build does not serve — an unknown version, or a path not shaped like `<version>.<Service>/<Method>` — is counted under `version="unrecognised",outcome="attempted"` rather than creating a label of its own or being credited to a real version.

## Release Gate

Publish an image tag only after `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `shellcheck` and unit tests of the repository's shell scripts, native and WASM checks, unit and integration checks, PostgreSQL migration checks, gRPC/gRPC-Web checks, and Chromium/Firefox UI checks pass. Each release publishes **two** images from the same source tag and the same semver — `sovereign-config` and `sovereign-config-woodpecker-broker` — so the pair is protocol-matched by construction; a production promotion fails closed if either is missing from the registry. Both image builds must pass `--target` (`server-runtime` / `broker-runtime`), because the Dockerfile has more than one final stage. The release image bundles static musl CLI and MCP-server installers built from the same tag and served unauthenticated under `/dist`; the image build gates on each installer extracting to a binary whose reported version equals the release tag. The tagged source also supplies the protocol-matched CLI and MCP server through `cargo install --locked`. SBOM generation is out of scope for the MVP.
