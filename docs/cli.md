# CLI

`sovereign-config` is the command-line client: it manages connection profiles, logs in, reads and writes configuration, and renders configuration into another command's environment.

## Installing

Each running server publishes a prebuilt CLI installer matched to its own release. The installer is a static x86_64 Linux binary (no toolchain, no libc dependency) wrapped in a self-extracting shell script. Browse `https://<server>/downloads` for the download links and the exact command, or install directly — this downloads to a temporary directory that is removed afterwards:

```sh
sh -c 'd=$(mktemp -d); trap "rm -rf \"$d\"" EXIT; curl -fsSL "https://<server>/dist/install-sovereign-config-cli-<version>-x86_64-linux.sh" -o "$d/installer.sh" && sh "$d/installer.sh"'
```

The installer verifies its embedded checksum, installs `sovereign-config` into `~/.local/bin` (override with `SOVEREIGN_CONFIG_BIN`), and prints the installed version. Re-run it to upgrade. Because the binary is built from the server's own release tag, the installed CLI is protocol-matched to that server. The installer extracts itself from its own file, so download it and run it — it cannot be piped straight into a shell.

Alternatively, build the CLI from the matching tagged source with a Rust toolchain:

```sh
cargo install --locked --git https://github.com/vcheesbrough/sovereign-config --tag <version> sovereign-config-cli
```

## Profiles and login

Add a named profile by entering its self-contained connection URL at the hidden prompt. The first profile becomes the default:

```sh
sovereign-config profile add dev
# New URL: https://config-dev.example.com/#v=1&issuer=https%3A%2F%2Fauth.example.com%2Fapplication%2Fo%2Fsovereign-config-dev%2F&client_id=sovereign-config-dev
sovereign-config login
sovereign-config status
sovereign-config logout
```

Use `sovereign-config profile update <name>` to replace a URL and `sovereign-config profile default <name>` to change the default. A URL can instead be supplied as exactly one line on standard input. Profile URLs are never accepted as process arguments. Operational commands accept a global override, for example `sovereign-config --profile prod status`. A host with no profile store at all — a CI container, a deploy step — can instead supply the URL through `--url-file` or `SOVEREIGN_CONFIG_URL`; see [Credential inputs](#credential-inputs).

`sovereign-config profile list` shows the stored profiles by name, marking the default with `*` and naming the server each one points at — its endpoint, followed by the configuration root when the profile is confined to one:

```
  dev         https://config-dev.example.com
* prod        https://config.example.com/team/service
```

`--format json` instead renders an array of `{ "name", "default", "endpoint", "root", "url" }`, where `url` is the whole connection URL with any managed credential replaced by `*`. **Nothing a listing prints is a secret** — but the file it reads is not safe to print, because a managed profile's stored URL embeds its credential. Use this command rather than reading `config.toml`. Listing succeeds with an empty result before the first profile is added.

## Reading and writing values

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

## Rendering configuration into a command (`render`)

`sovereign-config render [<ABSOLUTE_PATH>...] [OPTIONS] -- <cmd> [args...]` reads one or more configuration subtrees, overlays them onto the inherited environment as environment variables, and then **replaces itself** with `<cmd>`. This is the deploy-time consumption path: a Compose stack or a CI deploy step keeps one narrow, read-only, centrally revocable connection rooted at its own subtree, instead of carrying every value inline.

```sh
sovereign-config render -- docker compose up -d --wait            # the connection root
sovereign-config render /apps/api -- ./deploy.sh                  # one layer
sovereign-config render /apps/api /apps/api/prod -- ./deploy.sh   # ordered, later wins
```

Paths are **layers**, read in the order given, with a later layer overriding an earlier one on a name collision. With no path at all, the layer is the connection's own root — the prefix the credential already encodes. Only the **direct children** of a layer become variables; a deeper descendant has no flat name and is ignored.

**The variable name is the leaf, exactly as stored.** `/foo/AbC` holding `bAr` reaches the command as `AbC=bAr`, precisely as `export AbC=bAr` would. Nothing is uppercased, lowercased or otherwise transformed: paths are case-retentive (see [2.18.0 retains path letter case](upgrading.md#2180-retains-path-letter-case)), so the spelling a value was created under is the spelling the command sees, and it is the only one a deploy can predict. Uppercasing would leave `AbC` unreachable, because no path would produce it.

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

### Credential inputs

The hosts `render` exists for — a CI container, a Compose deploy step — have no profile store and no terminal to create one at, so two further credential inputs sit alongside `--profile`. All three are global and work on every operational command. Resolution order is fixed:

1. `--profile <name>` — an explicit choice always wins.
2. `--url-file <path>` — a file holding the connection URL as one line, such as a mounted CI secret. A single trailing newline is tolerated; an embedded one is refused rather than guessed at.
3. `SOVEREIGN_CONFIG_URL` — the variable a CI step injects.
4. Otherwise the default profile, which is where every interactive invocation lands.

**A connection URL is never a process argument**, here as everywhere else: it carries the credential, and process arguments are world-readable on a typical host. `--url-file` names a file and `SOVEREIGN_CONFIG_URL` names a variable; neither is the URL itself.

`render` removes `SOVEREIGN_CONFIG_URL` from the environment it hands the command, whether or not this invocation used it — the credential that read the configuration stops at `render`. It is removed before rendered values are applied, so configuration that legitimately holds a connection URL for the executed application's own use still reaches it; only the *inherited* credential is stripped.

### The CLI image for Woodpecker pipelines

Each release also publishes a `sovereign-config-cli:<version>` image: the digest-pinned `docker:27-cli` image, with the same static `sovereign-config` binary the installer carries at `/usr/local/bin/sovereign-config`. A Woodpecker step that already runs `docker` can swap its image for this one and gain the CLI with no install step and no download at run time. The image keeps the base image's root user and entrypoint, so the step's `commands:` drive the mounted Docker socket exactly as before. It is published under the server's semver, so pin the tag of the server you talk to; the image build fails unless the binary reports exactly that release.

```yaml
deploy:
  image: <registry>/sovereign-config-cli:<version>
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock
  environment:
    SOVEREIGN_CONFIG_URL:
      from_secret: sovereign_config_url
  commands:
    - sovereign-config render /apps/api /apps/api/prod -- docker compose up -d --wait
```

The connection URL arrives through `SOVEREIGN_CONFIG_URL` from a Woodpecker secret — never inline in the pipeline file — and `render` strips it before the command runs (see [Credential inputs](#credential-inputs)). Use a read-only managed connection rooted at the step's own subtree.


## Connection URLs and stored credentials

The version-1 URL origin is the native gRPC endpoint, its path is the canonical configuration root, and its fragment contains the OIDC issuer and client ID. Without `client_secret`, login uses device flow. With `client_secret`, the value is unpadded Base64URL-encoded `service-account-username:app-password`; the CLI obtains a fresh client-credentials access token for each operation and does not support login or logout for that profile. The entire managed URL is a secret even though its credential is encoded.

Profiles are stored in `$XDG_CONFIG_HOME/sovereign-config/config.toml`, defaulting to `~/.config/sovereign-config/config.toml`. The directory is mode `0700` and the file is mode `0600`; because managed profiles contain credentials, protect the entire file. Human refresh credentials are stored in environment-bound mode-`0600` files under `$XDG_STATE_HOME/sovereign-config/credentials/`, defaulting to `~/.local/state/sovereign-config/credentials/`. Keep these paths in the WSL Linux filesystem rather than `/mnt/c` so Unix ownership and modes are enforced.

The CLI prints only the device verification URI and user code during login. Access tokens remain in process memory; refresh credentials and managed credentials never appear in arguments or command output. Each status operation acquires a fresh access token and performs fresh RPCs without response caching or automatic retry. A definitive refresh rejection deletes the unusable human credential; a temporary Authentik outage retains it for a later attempt.

