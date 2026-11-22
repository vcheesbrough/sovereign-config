# Project deployment

This document describes how the project's own instance of Sovereign Config is built, released and deployed: its GitHub Actions build, Woodpecker deployments, registry, hosts, secrets and telemetry platform. None of it is required to run Sovereign Config elsewhere. A deployment of your own needs only what the [README](../README.md) describes. This document records the decisions the project's pipelines depend on.

## Environments

| Environment | Host | Compose project | Container | Authentik blueprint |
| --- | --- | --- | --- | --- |
| Development | `sovereign-config-dev.desync.link` | `sovereign-config-dev` | — | `authentik/blueprint-dev.yaml` |
| Production | `sovereign-config.desync.link` | `sovereign-config-prod` | `sovereign-config-production` | `authentik/blueprint.yaml` |

Both use the Authentik instance at `auth.desync.link` and sit behind the estate's Traefik on the external `proxy-backend` network. The Traefik labels in `compose.yaml` name that platform's middlewares (`lan-vpn-only`, `rate-limit`, `crowdsec`, `security-headers`) and certificate resolver (`myresolver`).

## Build and release

Checks and builds run on **GitHub Actions**, in `.github/workflows/build.yml`. Deployments run on **Woodpecker**, on the host, in `.woodpecker/` (card #539). The split keeps every deploy secret and the Docker socket on the host. It also leaves Sovereign Config with no build or registry dependency on the estate's devops stack (Woodpecker, Zot), so restoring it needs only Traefik, Authentik and GHCR.

Every push to a branch (or a manual run of the workflow) does the following:

1. The `version` job claims the run's version.
2. In parallel, the checks run and the three images build.
3. Once every check has passed and all three images are built, `publish` pushes them to GHCR.

The images are `ghcr.io/vcheesbrough/sovereign-config`, `sovereign-config-woodpecker-broker` and `sovereign-config-cli`, all public. Versioning and publishing follow the shared release-flow contract. The Woodpecker deploys read that contract with [`woodpecker-plugin-release-versions`](https://github.com/vcheesbrough/woodpecker-plugin-release-versions). The GitHub build keeps it with the repository's own scripts and runs no Woodpecker plugin (card #550):

- `version` runs `scripts/ci-claim-build.sh`. It reads `major.minor` from `Cargo.toml` and claims the next patch on that line by creating `refs/builds/<version>` on GitHub. The ref is an annotated tag object that peels to the commit, created by a create-only push. A build that loses a race claims the next number. This is the record the deploys' `resolve` step matches to commits.
- `publish` runs `scripts/ci-publish-images.sh`. It refuses an image that lacks this version's `org.opencontainers.image.version` and `.revision` labels, or one that is already published, and it refuses before pushing anything.

A failed build uses its number up, so gaps in the patch sequence mark failed builds. The image builds save their images as workflow artifacts rather than pushing them, so a name in GHCR only ever holds a checked build. Nothing is pushed under a second name.

The checks keep one Cargo cache in GitHub's Actions cache, keyed on `Cargo.lock`. The image builds start cold on every run: their BuildKit cache mounts do not outlive a hosted runner.

Each published package links to this repository through its `org.opencontainers.image.source` label. The packages are public, as the repository is: deployments and other repositories' pipelines pull them anonymously, so none of them holds a registry credential. Releases from before #539 are in GHCR only where they were copied from Zot by digest, for a restore by hand. A Woodpecker deploy of a pre-#539 commit runs that commit's own workflows, which still pull from Zot (`registry.desync.link`) with the `zot_ci_*` secrets. Rolling back past #539 through the pipeline therefore needs both to stay.

### Why a push still runs a Woodpecker pipeline

Woodpecker starts a deployment from an existing pipeline (its Deploy button), and it records no pipeline for a push that no workflow matches. So `.woodpecker/anchor.yml` runs on every push. It does nothing but give the push a pipeline to deploy from. Its green status means only that Woodpecker saw the push. Whether the commit has a build to deploy is the deployment's own `resolve` step, which refuses a commit GitHub Actions has not published.

On `main`, a push also runs `.woodpecker/code-vitals.yml`, which records the commit in code-vitals. Its one step is code-vitals' Woodpecker plugin (`registry.desync.link/code-vitals-plugin:stable`), which starts the collector through the docker socket. The step's `settings:` tell code-vitals how to measure this repository: its trunk, where its version is, and which paths belong to which area. code-vitals' deployments read the same settings from this file at the head of `main`. The step is `failure: ignore`, and nothing waits for it, so it never blocks a build or a deploy.

## Deploying

**A push never deploys.** Development is deployed with Woodpecker's **Deploy feature: a `deployment` event targeting the `dev` environment, from any branch**, started from that branch's anchor pipeline. Pushes from several branches therefore never queue behind each other's deploys or fight over the one dev environment. Production is deployed the same way, **targeting `prod`, from `main`**.

Both deploy workflows run the same sequence:

1. **`resolve`** (the release plugin) chooses what to ship: the commit's release tag if it was deployed before, otherwise its newest published build. It refuses a target or branch outside the plugin's policy (dev from any branch, prod from main) and checks all three images' labels in GHCR. A commit with no published build fails here, before anything is deployed.
2. They deploy onto the environment's stack: **`migrate`** first, then the server ([Migrations](#migrations)). `migrate` applies the environment's Authentik blueprint (`authentik/blueprint-dev.yaml` or `authentik/blueprint.yaml`), after checking that live Authentik is new enough.
3. **`tag`** pushes the annotated git tag. A git tag therefore means **"this build was deployed"**, not "this build passed its checks". The first deploy of a commit, to either environment, writes the tag, and every later deploy of that commit reuses the build the tag names.

The tag push runs `.github/workflows/release.yml`, which gives the version a **GitHub Release**. The Release lists the three images at that version, each with its pinned `docker pull …@sha256:` and its package page, so a reader of the tag can find what was deployed. A tag whose commit `main` does not contain (a branch deployed to dev) becomes a pre-release, never "latest", so the Releases page leads with what `main` ships. A manual run of the workflow for an existing tag rewrites that tag's Release, which is how tags from before #550 get one.

A deployment never builds, publishes or claims a version.

Production also refuses a commit `main` does not contain (`verify-commit-on-main`). Woodpecker takes a GitHub deployment whose ref is a bare commit as a deployment of `main`, so the `branch: main` condition alone would not stop such a deployment from shipping some other commit. The check guards against an accident, not an attacker: the deployed commit supplies the workflow file.

Dev runs whichever branch was deployed last. A migration deployed from a branch stays applied to the dev database. Each deployment is verified after Woodpecker completes by calling `System.GetVersion` through the public endpoint twice: over native gRPC, and on `v6` over Connect JSON.

After the dev deploy, **`validate-authentik-manager-live`** exercises the connection manager against live Authentik, with the permissions the blueprint `migrate` just applied. Production runs no live check of its own: the production blueprint differs from the development one only in names, so this run is the promote gate. It is an operator gate, like deploying to dev first: the pipeline does not stop a promotion whose dev run was red, so do not promote one.

The pipeline does not require a dev deployment before a promotion, but **deploy the main commit to dev before promoting it to prod**. That is an operator rule, not a gate. A published build means the checks passed. CI's migration checks run against a fresh PostgreSQL. Only a dev deployment proves the release against a long-lived database and against live Authentik, and runs the live connection-manager check. Skipping it is an accepted risk, not an oversight.

## Migrations

Everything a release changes outside its image runs in **`sovereign-config-server migrate`**: a one-shot container from the same image, which every deploy runs before the server is replaced (#615, the `migrations` skill). Its steps, in order, each idempotent and each a root span `sovereign_config.migrate.<step>`:

| Step | What it does |
| --- | --- |
| `schema` | Applies the SQL migrations the binary embeds. Applied migrations it does not know are tolerated: that is a rollback to an older image. |
| `identity_claim` | Records the deployment's identity provider the first time, and refuses any other afterwards. |
| `reseal` | Encrypts any stored secret still in plaintext. A key that opens none of the sealed secrets aborts it, and nothing is changed. |
| `identity_provider` | With Authentik: checks its version and API, then applies the environment's blueprint ([Authentik](authentik.md#applying-a-blueprint)). |

**The server never applies any of this.** At startup it checks that each step has run — every embedded migration applied, the provider claimed, no plaintext secret, a key that opens the sealed ones — and refuses to serve otherwise, naming `migrate`.

**A deploy runs `migrate` on its own and waits for it** (`docker wait`), and replaces the server only once it has exited 0. If `migrate` fails part-way, the deploy fails and the previous release goes on serving, against whatever `migrate` changed. A plain `docker compose up` would not keep that promise: Compose replaces the server before the `depends_on` condition on `migrate` is met, and `up --wait migrate` reports a one-shot service ready before it has finished.

**Every migration must therefore work with the release before it.** The previous release serves against the new state during every deploy, and after a failed one. Expand in one release; contract (drop, rename, tighten) in a later one, once no running release reads the old shape. A rollback to 3.62 or later is a deploy of the older image, whose `migrate` tolerates migrations it does not know. An image from before 3.62 migrates in-process and refuses a database carrying a migration it does not know, so rolling back that far needs the backup restore in [Upgrading](upgrading.md#procedure) once a newer migration has been applied.

**Credentials reach every container as files**, never as its own variables, because an exited `migrate` keeps its environment in `docker inspect`. Compose reads each from the environment it runs in — the deploy step exports the Woodpecker secrets under the names `compose.yaml` reads — and writes it into each container given it, at `/run/secrets/<name>`, mode `0400`, owned by the user that reads it (#617). Nothing but those variables is needed to start the stack, so it can be started without Woodpecker. The file lives in the container's own layer until the container is recreated: an exited `migrate` holds the Authentik admin token until the next deploy, out of `docker inspect` but within reach of `docker cp`.

| Credential | `migrate` | Server | PostgreSQL |
| --- | :---: | :---: | :---: |
| Database URL (`database_url`) | ✅ | ✅ | — |
| Value encryption key (`value_encryption_key`) | ✅ | ✅ | — |
| Connection-manager token (`manager_api_token`) | ✅ (the blueprint sets it) | ✅ | — |
| Authentik admin token (`authentik_admin_token`) | ✅ | — | — |
| PostgreSQL password (`postgres_password`) | — | — | ✅ |

**Checking a deploy:** `docker inspect -f '{{.State.ExitCode}}' sovereign-config-dev-migrate` (or `sovereign-config-production-migrate`) is `0`, and its log says what each step changed. An exited `migrate` is expected: it is not a container that is down. Compose writes a secret into a container only when it creates it, so the deploy recreates `migrate` and the server every time (`--force-recreate`), and a redeploy is how a rotated credential reaches them.

### Production prerequisites

Before the first promotion the operator provides the production Woodpecker secrets `sovereign_config_prod_postgres_password`, `sovereign_config_prod_manager_api_token`, and `sovereign_config_prod_value_encryption_key` (the server refuses to start without it), the pre-created encrypted `sovereign-config-production-db` volume, and DNS/Traefik for the production host. The deployment path also reuses the shared secrets `github_token` (resolving the build, writing the tag, and the on-main check) and `authentik_api_token` (the Authentik admin token `migrate` applies the blueprint with). It holds no registry credential: the images are public. Every CI secret is served by the Sovereign Config Woodpecker secrets broker, which offers it to every event except pull requests, so moving a step between `push` and `deployment` needs no secret change.

### Self-hosting exception

Sovereign Config's own deploy steps deliberately do **not** consume their configuration through `render`, and keep their Woodpecker secrets. Reading `/sovereign-config/prod/...` in order to deploy Sovereign Config would create a circular availability dependency: a broken production deployment could not be redeployed through a path that requires production to be readable. Other repositories and the homelab stacks are the intended consumers.

The build sits outside the estate for the same reason. If its images lived in the estate's registry, restoring Sovereign Config would need the devops stack, so that stack could never render its own secrets from Sovereign Config. With the images in GHCR, the stacks Sovereign Config needs at run time are Traefik and Authentik alone. The deploys' Woodpecker secrets still come through the broker from Sovereign Config itself. A rebuilt host is therefore brought up by hand once, from `compose.yaml`, and Woodpecker takes over after that (mini-config `RECOVERY.md`, step 11a).

## Container users

Every container runs as a stated, unprivileged user (card #579). `tests/deployment_policy.rs` fails if a service in `compose.yaml` or a Dockerfile under `docker/` departs from this table.

| Container | Runs as | Hardening | Where it is set |
| --- | --- | --- | --- |
| Server (`sovereign-config`) | `10001:10001` | `cap_drop: ALL`, `no-new-privileges`, `tmpfs` on `/tmp`; a writable root filesystem (below) | `docker/server.Dockerfile` and `user:` in `compose.yaml` |
| `migrate` | `10001:10001` | The same | The server's image, and `user:` in `compose.yaml` |
| Client-telemetry ingest (`otlp-ingest`) | `10001:10001` | `cap_drop: ALL`, `no-new-privileges`, read-only root filesystem, `tmpfs` on `/tmp` | `user:` in `compose.yaml` (a published image) |
| Woodpecker broker | `10001:10001` | See below | `docker/broker.Dockerfile` |
| PostgreSQL (`postgres`) | Starts as root, runs as `postgres`, `999:999` | `cap_drop: ALL` with five capabilities added back, `no-new-privileges` | The upstream image's entrypoint |
| CLI image | Root | None | `docker/cli.Dockerfile` sets no `USER` |

**One id for every image this repository builds: uid `10001`, gid `10001`.** The server, the broker and the ingest already ran as uid 10001, so no secret file changes owner. The containers share no volume, so a uid each would separate nothing today. The images name the ids as numbers (`USER 10001:10001`), and `compose.yaml` restates them, so the deployment does not depend on the image for its user.

**A volume shared between containers is owned by group `10001`**, with its directory group-writable and setgid (`chown 10001:10001`, `chmod 2770`). A container from another image that must share it either runs as `10001:10001` or adds the group with `group_add: ["10001"]`. The identity-provider socket (card #578) is the first such volume.

**The server's and `migrate`'s root filesystems are writable, as a decided exception (#617).** Neither writes a file: the server's state is the database, and both log to stdout and OTLP. But Compose delivers their credentials by writing them into the container, from the environment it runs in, and refuses to do that for a read-only container. Credentials from the environment were chosen over host files so the stack can be started without the deploy pipeline (#617). Everything else stays: uid 10001, no capabilities, `no-new-privileges`, and `/tmp` as a `tmpfs`. `tests/deployment_policy.rs` lists both as the only writable-root services.

**PostgreSQL keeps the upstream image's own user handling**, and sets no `user:`. Its entrypoint starts as root to take ownership of the data directory and to read the password file, then drops to `postgres` for good. With `user: "999:999"` it could do neither. A pre-created volume owned by root would then fail its first start, and the documented `root:root`, `0400` password file would be unreadable. That is too much risk to a long-lived database for the gain. What the entrypoint needs as root is five capabilities: `CHOWN` and `FOWNER` for the data directory, `DAC_OVERRIDE` to read and write what root does not own, and `SETGID` and `SETUID` to drop to `postgres`. `compose.yaml` drops every other capability. The database process itself runs as `999:999` and holds none. `docker exec` into that container still starts as root, so read the database process's user from `/proc/1/status`, not from `id`.

**The CLI image stays root.** It is an operator tool that pipeline steps run, not a service. Those steps drive the host's Docker socket, whose group id differs from host to host, and write in a workspace Woodpecker creates as root. An unprivileged user would break every pipeline that uses the image.

**The broker is deployed from `mini-config`** (`devops-stack/docker-compose.yml`), so its hardening is that repository's to apply. Its image runs as `10001:10001` whether or not the service says so. It writes no file either, so its service can carry the server's lines unchanged:

```yaml
user: "10001:10001"
cap_drop:
  - ALL
read_only: true
tmpfs:
  - /tmp
security_opt:
  - no-new-privileges:true
```

## Telemetry platform

Both environments export to the estate's shared collector, `http://monitor-alloy:4318` on the `proxy-backend` network. Its configuration lives in the `mini-config` repository. The deploy steps set:

| Variable | Dev / prod value |
| --- | --- |
| `OTEL_SERVICE_NAME` | `sovereign-config` |
| `OTEL_RESOURCE_ATTRIBUTES` | `deployment.environment.name=<dev\|prod>,telemetry_source=otlp` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://monitor-alloy:4318` |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` |
| `OTEL_LOGS_EXPORTER`, `OTEL_METRICS_EXPORTER`, `OTEL_TRACES_EXPORTER` | `otlp` |

These values live in the deploy steps of `.woodpecker/deploy-dev.yml` and `deploy-prod.yml`, not in a Sovereign Config layer as other products on the estate keep them: this service is the store `render` reads, and rendering its own deploy from itself would make redeploying a broken store depend on the store. None of the values is secret. The deploy steps also start the client-telemetry ingest after the health gate, with `--profile client-telemetry up -d --no-deps otlp-ingest`, and treat its failure as a warning.

The collector copies the resource attributes `telemetry_source` to `log_source` and `deployment.environment.name` to `deployment.environment` at ingest when absent; Loki stores them as the labels `log_source` and `deployment_environment`, and keeps `telemetry_source` as structured metadata. The same server lines also arrive once more from the container's stdout under `log_source="docker"` while both paths run. Each container's `observability.*` Docker labels are what the platform's stdout shipping and scraping read.

Finding things:

- **Server logs:** `{service_name="sovereign-config", deployment_environment="dev", log_source="otlp"}`; append `| trace_id="…"` to follow a trace.
- **Server traces:** `{resource.service.name="sovereign-config" && resource.deployment.environment="dev"}`.
- **Web UI traces:** `{resource.service.name="sovereign-config-web" && resource.deployment.environment="dev"}`, each rooted in the browser (`resource.log_source="client"` marks what came through the ingest); `{resource.service.name="sovereign-config-web" && name="navigate"}` for one kind of action.
- **Web UI logs:** `{service_name="sovereign-config-web", log_source="client", deployment_environment="dev"}`; `telemetry_source="client"` and `user_name` are structured metadata.
- **Ingest logs:** `{service_name="sovereign-config-otlp-ingest"}`.
- **Metrics:** `{job="sovereign-config", deployment_environment="dev"}`.

**Retention.** Loki keeps 7 days, which is the stated mitigation for the `user.*` attributes the web UI's records carry, and how a deletion request is answered: nothing in the product deletes a record, and none outlives that window. Prometheus, in the homelab `monitoring-stack`, keeps one day — too short to read the protocol retirement gate over a deployment cycle on its own (see [Protocol versioning](protocol-versioning.md#retiring-a-version)). Grafana permissions over Loki and Tempo are a personal-data control and are granted as the audit trail is.
