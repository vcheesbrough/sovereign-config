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

The images are `ghcr.io/vcheesbrough/sovereign-config`, `sovereign-config-woodpecker-broker` and `sovereign-config-cli`, all public. Versioning and publishing follow the shared release-flow contract, enforced by [`woodpecker-plugin-release-versions`](https://github.com/vcheesbrough/woodpecker-plugin-release-versions):

- `version` reads `major.minor` from `Cargo.toml`. It claims the next patch on that line by creating `refs/builds/<version>` on GitHub.
- `publish` refuses an image that lacks this version's `org.opencontainers.image.version` and `.revision` labels, or one that is already published. It refuses before pushing anything.

A failed build uses its number up, so gaps in the patch sequence mark failed builds. The image builds save their images as workflow artifacts rather than pushing them, so a name in GHCR only ever holds a checked build. Nothing is pushed under a second name.

The checks keep one Cargo cache in GitHub's Actions cache, keyed on `Cargo.lock`. The image builds start cold on every run: their BuildKit cache mounts do not outlive a hosted runner.

Each published package links to this repository through its `org.opencontainers.image.source` label. The packages must be public: deployments and other repositories' pipelines pull them anonymously. A package GitHub has just created starts private. Make it public once, in the package's settings. Releases from before #539 are in GHCR only where they were copied from Zot by digest. Every other pre-#539 release stays in Zot (`registry.desync.link`), which no deployment reads any more.

### Why a push still runs a Woodpecker pipeline

Woodpecker starts a deployment from an existing pipeline (its Deploy button), and it records no pipeline for a push that no workflow matches. So `.woodpecker/anchor.yml` runs on every push. It does nothing but give the push a pipeline to deploy from. Its green status means only that Woodpecker saw the push. Whether the commit has a build to deploy is the deployment's own `resolve` step, which refuses a commit GitHub Actions has not published.

## Deploying

**A push never deploys.** Development is deployed with Woodpecker's **Deploy feature: a `deployment` event targeting the `dev` environment, from any branch**, started from that branch's anchor pipeline. Pushes from several branches therefore never queue behind each other's deploys or fight over the one dev environment. Production is deployed the same way, **targeting `prod`, from `main`**.

Both deploy workflows run the same sequence:

1. They check that live Authentik is new enough.
2. **`resolve`** (the release plugin) chooses what to ship: the commit's release tag if it was deployed before, otherwise its newest published build. It refuses a target or branch outside the plugin's policy (dev from any branch, prod from main) and checks all three images' labels in GHCR. A commit with no published build fails here, before anything touches Authentik.
3. They apply the environment's Authentik blueprint (`authentik/blueprint-dev.yaml` or `authentik/blueprint.yaml`).
4. They validate the connection manager against live Authentik.
5. They deploy onto the environment's stack.
6. **`tag`** pushes the annotated git tag. A git tag therefore means **"this build was deployed"**, not "this build passed its checks". The first deploy of a commit, to either environment, writes the tag, and every later deploy of that commit reuses the build the tag names.

A deployment never builds, publishes or claims a version.

Production also refuses a commit `main` does not contain (`verify-commit-on-main`). Woodpecker takes a GitHub deployment whose ref is a bare commit as a deployment of `main`, so the `branch: main` condition alone would not stop such a deployment from shipping some other commit. The check guards against an accident, not an attacker: the deployed commit supplies the workflow file.

Dev runs whichever branch was deployed last. A migration deployed from a branch stays applied to the dev database. Each deployment is verified by calling `System.GetVersion` through the public gRPC endpoint after Woodpecker completes.

The pipeline does not require a dev deployment before a promotion, but **deploy the main commit to dev before promoting it to prod**. That is an operator rule, not a gate. A published build means the checks passed. CI's migration checks run against a fresh PostgreSQL, and `deploy-prod` runs its own live connection-manager check. Only a dev deployment proves the release against a long-lived database and against live Authentik with the development blueprint. Skipping it is an accepted risk, not an oversight.

Each deployment applies its environment's blueprint before starting the stack; production applies only the production blueprint. Before applying, the pipeline checks the Authentik instance's authenticated version endpoint and schema against the minimum version the blueprints need ([Authentication](authentication.md)).

### Production prerequisites

Before the first promotion the operator provides the production Woodpecker secrets `sovereign_config_prod_postgres_password`, `sovereign_config_prod_manager_api_token`, and `sovereign_config_prod_value_encryption_key` (the server refuses to start without it), the pre-created encrypted `sovereign-config-production-db` volume, and DNS/Traefik for the production host. The deployment path also reuses the shared secrets `github_token` (resolving the build, writing the tag, and the on-main check) and `authentik_api_token` (blueprint). It holds no registry credential: the images are public. Every CI secret is served by the Sovereign Config Woodpecker secrets broker, which offers it to every event except pull requests, so moving a step between `push` and `deployment` needs no secret change.

### Self-hosting exception

Sovereign Config's own deploy steps deliberately do **not** consume their configuration through `render`, and keep their Woodpecker secrets. Reading `/sovereign-config/prod/...` in order to deploy Sovereign Config would create a circular availability dependency: a broken production deployment could not be redeployed through a path that requires production to be readable. Other repositories and the homelab stacks are the intended consumers.

The build sits outside the estate for the same reason. If its images lived in the estate's registry, restoring Sovereign Config would need the devops stack, so that stack could never render its own secrets from Sovereign Config. With the images in GHCR, the stacks Sovereign Config needs at run time are Traefik and Authentik alone. The deploys' Woodpecker secrets still come through the broker from Sovereign Config itself. A rebuilt host is therefore brought up by hand once, from `compose.yaml`, and Woodpecker takes over after that (mini-config `RECOVERY.md`, step 11a).

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
