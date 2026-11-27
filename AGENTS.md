# Agent guide — Sovereign Config

This file holds the **sovereign-config-specific** working rules. The
machine-global rules common to every repo — Kanban/bored workflow, iteration &
versioning defaults, branching & git safety, CI-after-push, PR self-review +
comment loop, test coverage, and MCP/secrets discipline — live in the shared
**agent-shared baseline**, imported on this machine via `~/.codex/AGENTS.md` and
`~/.claude/CLAUDE.md`. **Read that baseline first;** this file only records what
is specific to sovereign-config or overrides the baseline.

If a sovereign-config rule changes, change it here — there is no parallel copy.
Cross-repo rules change in `agent-shared`, not here.

User-facing documentation belongs in `README.md` and `docs/`; development
workflow in `docs/development.md` and `docs/protocol-versioning.md`; the
project's own infrastructure in `docs/project-deployment.md`, never the
README; this file defines the repo-specific collaboration rules.

---

## Repository context

| Item | Value |
| --- | --- |
| **Remote / `gh` repo** | `vcheesbrough/sovereign-config` |
| **Trunk** | `main` |
| **Kanban board** | `https://bored.desync.link/boards/sovereign-config` |
| **Production version** | `System.GetVersion` on `https://sovereign-config.desync.link` (the `curl` in §1) |

### Bootstrap exception

This repository was initialized directly on `main`. The initial commit that
creates this file and establishes the default branch is allowed on `main`.
After initialization, follow the baseline feature-branch workflow (§2–§3).

---

## 1. CI after every push (repo specifics)

Run the **`ci-watch`** skill (baseline §4) with `OWNER=vcheesbrough`,
`REPO=sovereign-config`. Repo specifics:

- **A push's CI is GitHub Actions** (#539), overriding baseline §4's
  Woodpecker default for pushes. `.github/workflows/build.yml` runs the
  checks, builds the three images and publishes them to GHCR. Watch that run
  (`gh run list --commit $SHA`, `gh run watch`). The commit-status API does
  not show it, because GitHub Actions reports check runs. On a push, Woodpecker
  runs `anchor.yml`, which is green as soon as Woodpecker sees the push and
  says nothing about the build. On `main` it also runs `code-vitals.yml`
  (#560, #568), one plugin step that records the commit and can never fail
  the pipeline. Its image is the moving `code-vitals-plugin:stable` tag,
  code-vitals' approved exception to §2's digest pinning. That exception now
  carries host-level access: the image holds the docker socket, so moving
  `:stable` runs new code with the agent host's Docker daemon (and the
  writer password) without a change here. Its `settings:` are
  how code-vitals measures this repo: changing the area rules needs a new
  `areas.version`, which re-measures the whole history. Woodpecker runs the
  deployments, and those are still watched there.
- **Releases follow the release-flow skill** (#539). The Woodpecker deploys
  read it with `woodpecker-plugin-release-versions` (`resolve`, `tag`). The
  GitHub build keeps it with `scripts/ci-claim-build.sh` and
  `scripts/ci-publish-images.sh`, and **no GitHub workflow runs a Woodpecker
  plugin** (#550). `Cargo.toml` supplies `major.minor`, and each build claims the next patch
  (keep patch `0`). The
  first deploy of a build to dev, or its promotion to prod, writes its git
  tag, so a tag means "deployed to dev or promoted to prod".
  **Deviation from release-flow (mini-config #614):** production is deployed
  by mini-config, not from here. Its `sovereign-config-stack` pins the
  release's server image by tag and digest, keeps production's credentials in
  its SOPS file, and runs `migrate` then the server, so production comes back
  from cold without Woodpecker, the broker or Sovereign Config itself.
  `promote-prod` (Woodpecker Deploy → `prod`, from main) resolves the build
  and tags it, and deploys nothing. A release reaches production when
  mini-config's pin is bumped to that tag and deployed there, so a tag never
  proves production runs it: read production's version from production.
  `release.yml` then gives the tag a GitHub Release that lists its images. A
  card's **Version** records the `major.minor`.
- **An iteration is the release line it ships in** (baseline §2): *Iteration
  3.1* is everything released as `3.1.x`, and may bundle several cards.
  Versions follow in sequence from the version production runs (after 3.0.x
  comes 3.1, then 3.2), never from a card number or a count. Read it from
  production itself before starting a card: `curl -s --http1.1 -X POST -H
  'content-type: application/json' -d '{"protocolVersion":"v6"}'
  https://sovereign-config.desync.link/sovereign.config.v6.System/GetVersion`
  (`applicationVersion`). Cards before 3.1 carry the old `Iteration N`
  headings (1–62), which are not versions; 3.60–3.63 were out of sequence and
  were removed on 2026-11-22.
- **A push never deploys** (#466). A push is green once the GitHub Actions
  build has published its images. Dev is deployed only by a Woodpecker Deploy
  targeting `dev` (any branch), started from that push's anchor pipeline. The
  one dev environment runs whichever branch was deployed last, so trigger a
  dev deployment only when the user asks for one.
- **Deploy a main commit to dev before promoting it to prod.** This is an
  operator rule; the pipeline does not enforce it. A release then goes: dev
  deploy, `promote-prod`, then a pin bump in mini-config's
  `sovereign-config-stack/docker-compose.yml` (tag and digest, with that
  file kept in step with this release's `compose.yaml`), deployed there. A published build means
  only that checks passed, so only a dev deploy proves a release against the
  long-lived database and live Authentik (`docs/project-deployment.md`).
- **Deployment smoke check** (post-pipeline, not part of `ci-watch`): for a
  successful development deployment, directly
  call its public native gRPC `System.GetVersion` endpoint **after** the
  pipeline completes — do **not** embed this check in the pipeline. Verify
  `grpc-status: 0` and report the returned application and protocol versions.
  Then make the same call on `v6` over Connect JSON —
  `POST /sovereign.config.v6.System/GetVersion` with
  `Content-Type: application/json` and `{"protocolVersion":"v6"}` — and verify
  HTTP `200` with `"protocolVersion":"v6"`. Treat any other response to either
  as a deployment failure and fix it before reporting completion.

---

## 2. Repository safety (repo specifics)

In addition to baseline §3 (git safety) and §7 (MCP/secrets):

- Use `apply_patch` for manual file edits.
- **Pin container images by digest.** Do not introduce cloud dependencies,
  telemetry, update checks, or undeclared outbound connections.
- Never log or expose configuration secrets, OIDC tokens, Authentik
  credentials, provider URLs, or connection credentials.

---

## 3. Protocol Compatibility

Compatibility is a **supported range**, settled on **one unversioned
handshake** — `/sovereign.config.Handshake/Negotiate`. The client sends every
version it speaks; the server answers with every version it serves, most
preferred first, each optionally carrying a deprecation date; the client selects
from the server's order. Clients (cli/mcp/provider/web/broker) are likely running
an **earlier** protocol version than the server, and that is explicitly
supported — a server upgrade alone must never break them.

**The full procedure for introducing and retiring a protocol version is
`docs/protocol-versioning.md`.** Read it before changing anything in
`proto/`. The rules below are the agent-facing summary, not a second copy.

- **Any protocol change requires explicit permission, requested up front.**
  Raise it as the first thing when planning or estimating the work — before
  implementation, while there is still a decision to make. Never let a protocol
  change surface mid-implementation or be discovered in the diff. This covers a
  behaviour change to an existing endpoint as much as a signature change.
- Treat a card's "no protocol change / client-side only" scope as a **claim to
  verify**, not an assumption. If the work turns out to need one, stop and ask.
- A protocol version defines not only signatures/datatypes but also the **key
  behaviour** of endpoints. Earlier behaviour contracts cannot be broken without
  a protocol version change.
- **A released `proto/sovereign/config/vN/` package is frozen.** A new version
  is required for renaming, renumbering, retyping, removing or repurposing a
  field; for changing what an RPC does; for **adding any field or RPC, even an
  optional one**; and for **changing the set of values an existing field may
  carry** — a wider or narrower grammar, letter case, range, or a new enum
  member. Anything else is a new package served alongside the old one, never an
  edit in place. Exceptions are approved before implementation and recorded in
  `docs/protocol-versioning.md` with their reason; there are four (2.25.0, 2.29.0, 2.42.372 and 2.59.0).
- **A version names its transport** (#582). `v3`–`v5` are served over native
  gRPC and gRPC-Web only; `v6` and every later version over Connect unary
  (binary and JSON) only; the handshake over every transport the server
  speaks. Changing a version's transport is a new version, and a call on the
  wrong one is answered version-not-served, with the marker placed as that
  transport places it (a header for Connect, trailers for gRPC), never both.
  From `v6` on, JSON field and enum value names are wire contract
  (`test-contracts/v6-json-names.txt`); behaviour must not depend on the
  encoding; nothing travels in a URL (Connect `GET` is never enabled); error
  text is not contract. `docs/protocol-versioning.md`, *Each version names its
  transport*, is the full statement.
- **The handshake's shape is fixed, forever**, because it can never itself be
  versioned. Do not add to it, and do not give it a version-shaped package name
  — `/sovereign.config.Handshake/…` has one dotted segment fewer than a
  versioned route, which is the whole mechanism keeping it outside every
  version.
- **Never change the `GetVersionResponse.protocol_version` echo semantics.** It
  returns the version the client *requested*; echoing the server's preferred
  version instead would fail every already-deployed client the day a newer
  version ships. Its regression tests are named in `docs/protocol-versioning.md`, along
  with `v3`'s oldest-first advertised ordering, which is `v3` behaviour and is
  deliberately the reverse of the handshake's.
- Breaking changes are a **last resort** and must be avoided wherever possible.
  If unavoidable: document it and communicate it to all clients.
- New protocol versions may be added, but **the server must continue to support
  older versions.** Announce a retirement with a `deprecation_date` first. A
  version is retired only once the `outcome="authenticated"` series of
  `sovereign_config_protocol_requests_total` has read zero for it across a full
  deployment cycle — the provider does not cache, so a client on a retired
  version re-handshakes once and then fails with no fallback. Gate on
  `authenticated`, never `attempted`: the endpoint is public, so unauthenticated
  traffic can hold the latter above zero indefinitely.
- Remember the converse: a change can break clients **without** being a protocol
  change (releases 2.15.0, 2.18.0, 2.26.0 and 2.28.0 all did). Negotiation does
  not protect against that class.

## 4. Observability

The `observability` skill (baseline §10) is the contract; this section records
how this repo applies it and where it does not yet.

- **`sovereign-config-telemetry` is the only crate that may name an
  OpenTelemetry SDK or exporter type** (`opentelemetry_sdk`,
  `opentelemetry_otlp`, `tracing_opentelemetry`,
  `opentelemetry_appender_tracing`), in source or in a manifest.
  `crates/sovereign-config-telemetry/tests/allowlist.rs` fails otherwise.
  Product code logs through `tracing`. The telemetry crates are pinned as one
  set in the workspace `Cargo.toml`, paced by `tracing-opentelemetry`; move
  them together, re-verifying the pairing on crates.io.
- **The `OTEL_*` variables are the whole configuration interface.** Never add
  a `SOVEREIGN_CONFIG_*` name or a config field for a telemetry knob.
  `compose.yaml` passes names only (`deployment_policy.rs` enforces it); the
  values live in the deploy steps (`docs/project-deployment.md`, *Telemetry platform*, says why). Two
  things are not knobs of the server's telemetry and are deliberately outside
  this rule: `SOVEREIGN_CONFIG_CLIENT_TELEMETRY_ENDPOINT`, product
  configuration the server hands the web UI (only ever its own public
  origin), and the client ingest's own `OTEL_SERVICE_NAME` literal in
  `compose.yaml`.
- **Spans are the transport's job, in `crates/sovereign-config-server/src/spans.rs`:**
  a hand-written `tower` layer opens each request's server span (no
  `tower-http`, one pin fewer), and only that module adopts trace context.
  A new outbound HTTP call goes through `client_span` and `send` from
  `sovereign_config_telemetry::client` (which `spans` re-exports, and the
  only place context is injected), so the server and the Authentik crate
  open the same client span; a new store function gets `#[instrument]` with
  the `db.*` fields its neighbours carry; a new served RPC goes into
  `spans::RPC_ROUTES` (a test compares it with the served `.proto` files).
  Span attribute keys are semantic-convention names or `sovereign_config.`-
  prefixed; `sovereign_config_telemetry::testing::Capture::finish` fails any
  test that exports another.
- **Metrics are pushed over OTLP, in `crates/sovereign-config-server/src/metrics.rs`**
  (there is no `/metrics`; #421). Instruments are created once at startup on
  `Telemetry::meter()`. A counter family counts in atomics and reports every
  label combination through an observable counter; a duration is a seconds
  histogram on `metrics::DURATION_BOUNDARIES`. Every label value comes from an
  exhaustive enum match, never a request. A new instrument goes into the
  `STORED_NAMES` table in `metrics/tests.rs` with the name the platform
  stores it under; `Capture::finish` fails any exported series carrying a key
  from `keys::FORBIDDEN_METRIC_KEYS`, or build identity anywhere but
  `sovereign_config.build.info`. From #422 on, a new metric ships with its
  dashboard panel in the same PR.
- **The web UI's telemetry is `crates/sovereign-config-web/src/telemetry/`**
  (`docs/observability.md`, *Client telemetry: the web UI*). Every `spawn_local` in the
  crate is `telemetry::spawn_local`, which is what gives each user action its
  trace and root span — import that one, never
  `wasm_bindgen_futures::spawn_local`, and name a new action with a new
  `span::ActionKind` variant (a bounded name, never a path or a value).
  A record's or span's name and attribute values are `&'static str` or
  numbers by type, and its keys are `record::Key`; keep it that way, because
  it is what keeps a token, a value or a path out of telemetry. The page sets no `user.*`, and
  telemetry never refreshes a token itself.
- **Every card that changes behaviour records its telemetry decision** — new
  or changed log fields, spans, metrics, dashboards, alerts or runbook text —
  including "no change needed". Not having thought about it is not a
  decision.

### Deviations register

What differs from the skill today, why, and what closes it. Remove an entry
in the change that closes it.

| Deviation | Why | Closed by |
| --- | --- | --- |
| The SDK exports nothing about itself (no dropped-record, dropped-span or failed-export counter). | **Decided in #421: kept, not wrapped.** The drops that matter happen in the SDK's batch processors when their bounded queues fill — before any exporter sees the record — so a wrapped exporter could count only failed exports, not drops. A failed-export counter would itself leave over the export path that is failing, and go dark exactly when it is needed; metrics are cumulative, so a failed metric export loses nothing the next one does not carry. Export failures show as `ERROR` lines from the `opentelemetry_sdk` target on stdout, which the platform ships independently of OTLP. | An SDK release that counts its own queue drops |
| `grpc` is not a supported `OTEL_EXPORTER_OTLP_PROTOCOL`; it fails startup. | The tonic exporter would add a second tonic beside the server's 0.12 and needs an async-runtime batch processor, for a transport the estate's collector does not need. (The `http/protobuf` path already brings second majors of prost and reqwest; that was accepted.) | Adding `grpc-tonic` when a collector requires it |
| The platform indexes `log_source` and `deployment_environment`, not the skill's `telemetry_source` and `deployment.environment.name`. | The product emits only the skill's names; the shared collector (`monitor-alloy`, mini-config) copies the resource attributes `telemetry_source` → `log_source` and `deployment.environment.name` → `deployment.environment` at ingest when absent; Loki stores them as the labels `log_source` and `deployment_environment` (dots become underscores). No second key is emitted from here. | A platform rename in mini-config |
| The same log line reaches Loki twice: from stdout (`log_source="docker"`) and over OTLP (`log_source="otlp"`). The client ingest does the same with its own logs (its default `LOG_OUTPUT=both`, where the reference deployment sets `otlp`). | `docker logs` stays useful, and whether the platform ships this container's stdout is the platform's decision. Postgres keeps its Docker stream regardless. | The platform dropping the server container's Docker stream once OTLP is trusted |
| The `OTEL_*` values live in the deploy pipelines, not a sovereign-config `otel` layer. | This service is the store `render` reads; its own deploy cannot depend on it. | — (deliberate) |
| The server's own `hyper_util` client and `reqwest` events are never exported over OTLP (stdout only). | They are also the exporter's HTTP client; bridging them would let an export produce records that need exporting. The server's gRPC stack (`tonic`, `h2`, `hyper`) is bridged. | — (deliberate) |
| The internal listener (`/readyz`) and the public port's gRPC health service (`grpc.health.v1.Health/*`) open no span and record no RED data point. | Health is separate from telemetry, and the container health check probes every few seconds: a span or data point per probe is noise. | — (deliberate) |
| A Postgres span's `db.operation.name` is the store function's name (`insert_provisioning`), not the SQL verb, and there is no `db.query.summary`. | sqlx has no hook, so spans sit at the store functions, where the query *names* are; naming by function keeps SQL text off spans by construction (a test fails on `SELECT`/`INSERT`/`UPDATE`/`DELETE`/`$1` in any attribute). | — (deliberate) |
| Spans carry `code.module.name`, the span bridge's own key, which is not a semantic-convention name. | It is the quickest way from a span to the code that opened it; it is the one allowed exception in `sovereign-config-telemetry`'s key check. | Dropping it, if the conventions gain nothing `tracing` can fill |
| Metric label keys other than the RED and pool ones (`version`, `outcome`, `reason`, `kind`, `operation`, `result`, `call`) are neither semantic-convention names nor `sovereign_config.`-prefixed. | They predate the contract, and the retirement gate (`sovereign_config_protocol_requests_total{outcome="authenticated"}`) and the audit alert series are written against them; renaming would move every stored series. The forbidden-key test covers them; only span keys are checked against `keys::is_known`. | A protocol-gate rewrite that can afford a rename |
| Instruments are held by what records them (`Arc` families, `RequestMetrics`, `JobMetrics`), not in statics as `references/rust.md` suggests. | Every test assembles its own capture; statics would make parallel tests share series. They are still created once, at startup. | — (deliberate) |
| A Connect call's span and RED data point carry `rpc.system.name="grpc"`, not the conventions' `connect_rpc`. | **Decided in #582:** `v6` is counted in the same series as every gRPC version, under its own `rpc.method` and version label, so the protocol panels and the retirement gate read it with no edit and no new label value. The web UI's client spans do the same. | #594, when gRPC is retired and every call is Connect |
| The CLI, MCP server, provider and broker emit no telemetry. | The first three are operator tools, not user devices sending to a public endpoint; the broker is a server-side process not yet instrumented. | #423 (broker); the rest — deliberate |
| The web UI's OTLP is hand-built OTLP/JSON over `fetch`, not an SDK. | No OpenTelemetry SDK builds for `wasm32`; binding the JavaScript SDK is larger than the few hundred lines needed. | An SDK for `wasm32` |
| `telemetry:write` cannot be withdrawn from one user. | Authentik grants a provider's scopes to every user who signs in to it; the skill's per-user opt-out needs a provider that withholds scopes per user or group. It does keep the CLI and MCP (same client id, never requesting it) out of the ingest. | A per-user scope policy in the provider |
| The client ingest's own metrics are scraped from `:8888` (Docker labels), not pushed. | The published image serves Prometheus; its reference deployment scrapes it. | The image pushing its own metrics |
| No client-logs or ingest-volume panel, and no ingest-volume alert. | The product has not opted into dashboards or alerts (skill §8); the panels #376 names join the product dashboard. | #422 |

## 5. Migrations

The `migrations` skill (baseline §10) is the contract (#615);
`docs/project-deployment.md`, *Migrations*, is the operator's account.

- **Everything a release changes outside its image runs in
  `sovereign-config-server migrate`**, a one-shot `migrate` service from the
  server's image, in this order: `schema` (the embedded SQL migrations,
  tolerating unknown applied ones), `runtime_role` (the server's own
  login, `sovereign_config_runtime`, with exactly its grants and default
  privileges, #616), `identity_claim` (the deployment's
  identity provider), `reseal` (encrypting stored plaintext secrets; a key
  that opens none aborts), `identity_provider` (with Authentik, the version
  check and the environment's blueprint, compiled into the image),
  `runtime_password` (an existing runtime login's password, last, so a
  failed `migrate` leaves the running server's working). Each is
  idempotent and a root span `sovereign_config.migrate.<step>`. A new kind of
  outside state is a new step here, never a CI step and never server
  startup.
- **The server verifies, never applies.** At startup it refuses a pending or
  diverged migration, an unclaimed deployment, a plaintext secret or the
  wrong key, naming `migrate`. Do not add a write to server startup.
- **A migration must work with release N-1.** `migrate` runs while the
  previous release serves, and leaves it serving if it fails. Expand first;
  contract (drop, rename, tighten) in a later release. Never edit a migration
  that has been deployed to dev; add a new one.
- **Credentials reach containers as files, never as their variables**, and
  Compose reads them from its own environment (`secrets: … environment:`,
  #617), so the stack starts from variables alone, without Woodpecker.
  Compose writes them into each container at `/run/secrets/<name>`, which is
  why the server and `migrate` have no `read_only` (a recorded exception)
  and are always `--force-recreate`d. `deployment_policy.rs` pins it. Only `migrate` gets the Authentik admin
  token (`authentik_api_token`), the schema owner's database URL and the
  runtime login's password; it also gets the value encryption key and the
  manager token. The server gets the runtime login's URL, the key and the
  manager token, and never the owner's password (#616).
- **The server's login owns nothing.** It reads and writes rows; a new
  table needs no grant (default privileges), but a migration that needs the
  server to do anything else (a new schema, a function it must own) changes
  the `runtime_role` step too. A dump is restored with `--no-privileges`:
  the role comes back from `migrate`, not from the dump.
- **A deploy runs `migrate` alone, `docker wait`s for it, then replaces the
  server.** Compose's own `depends_on` would replace the server first.
  `pipeline_prod_gating.rs` pins the order.

*Kanban workflow and automated test coverage follow the agent-shared baseline
unchanged — see baseline §1 and §6. Start a card with the **`start-iteration`**
skill (baseline §2). PR self-review + comment loop: run the **`pr-review-loop`**
skill (baseline §5). Skill parameters for this repo: `OWNER=vcheesbrough`,
`REPO=sovereign-config`.*
