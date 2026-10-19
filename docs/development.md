# Development

This guide is for people changing Sovereign Config itself: how the workspace is laid out, where new code goes, how to build and test it, and what a release must pass. For how a protocol version is introduced or retired, read [Protocol versioning](protocol-versioning.md) before touching anything under `proto/`. How the project's own instance is built and deployed is in [Project deployment](project-deployment.md).

## Workspace layout

The repository is a Cargo-workspace monorepo. The server, protocol crates, shared Rust client libraries, CLI, MCP server, WASM UI, and Woodpecker CI secrets extension are released together from the same source tag.

Each crate has one consumer, target, or artifact. Dependencies only point down this list.

| Crate | Role | Depends on |
| --- | --- | --- |
| `sovereign-config-proto` | Generated gRPC types: one module per protocol version (`v3`, `v4`) plus the unversioned handshake. | — |
| `sovereign-config-core` | The shared contract: paths, value and secret newtypes, listing shapes, the JSON subtree codec, connection URLs, and `ClientError`. No I/O and no async. | — |
| `sovereign-config-telemetry` | The server's telemetry module: `OTEL_*` validation, resource identity, OTLP export and flushing shutdown. The only crate that may name an OpenTelemetry SDK or exporter type; its `tests/allowlist.rs` fails if any other does. | — |
| `sovereign-config-server` | The service binary: gRPC, gRPC-Web, PostgreSQL, Authentik. | proto, core, telemetry |
| `sovereign-config-client` | The transport-agnostic client: the `Handshake` trait and the `negotiate` function that settles a session's protocol version, the `Transport`, `ValueTransport`, `ManagedConnectionTransport` and `AuditTransport` traits a transport bound to that version implements, `SessionTransport` for one version's whole surface, `AccessTokenProvider`, and the `Client` facade. | core |
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

## Where code goes

A module holds one concern. When a file starts mixing concerns, add a sibling module rather than growing it. `clippy.toml` holds functions to clippy's default of 100 lines, and `crates/sovereign-config-server/tests/lint_ratchet.rs` fails if product code silences that lint.

- **Server services** (`values/`, `managed/`, `audit/`): each is split at the protocol seam. `service.rs` is the **shared implementation** — authorization, validation, the control flow and every `Status` — written in no protocol version's terms: it takes a `CallContext` and unvalidated inputs, returns `sovereign-config-core` types, and holds no SQL. `shim.rs` is the **one adapter** every version's shim instantiates — a macro, because each version's generated types are distinct types — plus the validation policies a version chooses between. `vN.rs` is **`vN`'s shim**: one invocation of that adapter naming `vN`'s generated package, plus anything only `vN` has. Nothing but a `vN.rs` shim may import the proto crate, and `tests/lint_ratchet.rs` fails if anything else does. `store.rs` holds every row type and query. Authorization, pure validation such as `values/subtree.rs`, secret masking (`content.rs`) and version-free connection metadata (`wire.rs`) each get their own module. Authentik orchestration lives in `managed/provisioning.rs`. `rpc.rs` holds what every service shares, including the `CallContext`.
- **Server root**: `main.rs` is the startup sequence, one named step per concern. Authentication, Authentik, configuration, encryption, metrics and static assets each keep their own module.
- **Core**: one module per concept (`path`, `value`, `listing`, `json`, `status`, `error`, `connection`, `managed`). Every public item is re-exported from the crate root, and dependants import it from there.
- **Web**: one module per view (`configuration`, `value_rows`, `path_selector`, `tree`, `connections`, `downloads`) plus shared plumbing (`transport`, `session`, `route`, `shell`, `dom`, `browser`, `icons`). A thread-local static lives beside the code that owns it. Event handlers are registered through `dom::on_element_id` or `dom::listen`.
- **Tests**: unit tests sit in a sibling `tests.rs` declared with `#[cfg(test)] mod tests;`, and Postgres-backed ones are `#[ignore]` and run in CI with `--ignored`. Browser tests use one `browser-tests/tests/<area>.spec.js` per view, with shared mocks in `helpers.js`.

Telemetry has rules of its own — which crate may name the SDK, where spans and metrics are created, and which label values are allowed. They are in [Observability](observability.md) and the repository's `AGENTS.md`.

## Storage model

Each configuration value is a content row in PostgreSQL holding its classification and value, plus one or more path rows that expose it. Each path row stores the exact case it was written with in `path`, and Postgres computes and stores its lowercase fold key in the generated `lowercase_path` column, which carries the primary key; `lowercase_path` can never drift from `path` because it cannot be written to directly. The fold key is what every comparison, lookup, and collision check uses — a path's stored case is a display concern only, never resolved or rewritten a segment at a time, so two path rows sharing a fold-equal ancestor may each keep their own case for it. Deleting the last path deletes the content in the same transaction, with no background reconciliation, and there is no duplicate secret copy of a value.

## Building and testing

```sh
cargo fmt --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
```

The PostgreSQL-backed suites are `#[ignore]`d, so a plain `cargo test` skips them. Run them against a disposable database by setting `SOVEREIGN_CONFIG_TEST_DATABASE_URL` and passing `-- --ignored --test-threads=1` to `cargo test --package sovereign-config-server`. The browser tests are Playwright suites under `browser-tests/`, run against the release web bundle in Chromium and Firefox.

Build release images only for linux/amd64. Each image has its own Dockerfile under `docker/`, which builds only what that image ships:

```sh
docker build --platform linux/amd64 -f docker/server.Dockerfile --tag sovereign-config:local .
docker build --platform linux/amd64 -f docker/broker.Dockerfile --tag sovereign-config-woodpecker-broker:local .
docker build --platform linux/amd64 -f docker/cli.Dockerfile --tag sovereign-config-cli:local .
```

`docker/web.Dockerfile` exports the release web bundle on its own (`--output type=local,dest=<dir>`) for the browser tests. The files duplicate their builder stages rather than share them; keep their pinned base-image digests in step, which a test enforces. Container images are always pinned by digest.

## Versioning

Cargo supplies the `major.minor` release line and the CI pipeline number is the patch (`scripts/ci-release-tag.sh`): pipeline 362 on a `2.41.x` workspace releases `2.41.362`. Pipeline numbers are unique and increasing, so there is nothing to allocate and no two pipelines can claim one version. A re-run is a new pipeline and tags the same commit again under its own number; a deployment takes the commit's highest tag. Patch numbers are therefore sparse. The deployed `System.GetVersion` response reports that computed release version; local builds report the Cargo version.

## Release gate

Release a version — push its git tag — only after `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `shellcheck` and unit tests of the repository's shell scripts, native and WASM checks, unit and integration checks, PostgreSQL migration checks, gRPC/gRPC-Web checks, and Chromium/Firefox UI checks pass. Candidate images are pushed as soon as they are built, before those checks finish; only a release copies them to the names deployments and other pipelines pin. Each release publishes **three** images from the same source tag and the same semver — `sovereign-config`, `sovereign-config-woodpecker-broker` and `sovereign-config-cli` — so they are protocol-matched by construction; a deployment fails closed if any is missing from the registry. Each image builds from its own `docker/<image>.Dockerfile` (`server` / `broker` / `cli`). The release image bundles static musl CLI and MCP-server installers built from the same tag and served unauthenticated under `/dist`; the image build gates on each installer extracting to a binary whose reported version equals the release tag. The tagged source also supplies the protocol-matched CLI and MCP server through `cargo install --locked`. SBOM generation is out of scope for the MVP.

How the project's own pipelines implement this — candidate repositories, promotion and tagging — is described in [Project deployment](project-deployment.md#build-and-release).
