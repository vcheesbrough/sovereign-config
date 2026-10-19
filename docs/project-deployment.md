# Project deployment

This document describes how the project's own instance of Sovereign Config is built, released and deployed: its Woodpecker pipelines, registry, hosts, secrets and telemetry platform. None of it is required to run Sovereign Config elsewhere. A deployment of your own needs only what the [README](../README.md) describes. This document records the decisions the project's pipelines depend on.

## Environments

| Environment | Host | Compose project | Container | Authentik blueprint |
| --- | --- | --- | --- | --- |
| Development | `sovereign-config-dev.desync.link` | `sovereign-config-dev` | — | `authentik/blueprint-dev.yaml` |
| Production | `sovereign-config.desync.link` | `sovereign-config-prod` | `sovereign-config-production` | `authentik/blueprint.yaml` |

Both use the Authentik instance at `auth.desync.link` and sit behind the estate's Traefik on the external `proxy-backend` network. The Traefik labels in `compose.yaml` name that platform's middlewares (`lan-vpn-only`, `rate-limit`, `crowdsec`, `security-headers`) and certificate resolver (`myresolver`).

## Build and release

The pipelines live in `.woodpecker/`: `checks.yml`, `build.yml` and `publish.yml` run on a push or a manual run; `deploy-dev.yml` and `deploy-prod.yml` run on a `deployment` event.

Every push (or manual run) builds the three images and pushes each as soon as it is built — as a **candidate**, to its `-ci` repository (`registry.desync.link/sovereign-config-ci:<version>`, and likewise `-woodpecker-broker-ci`, `-cli-ci`). Once every check has passed, the `publish` workflow **releases** them (`compute-version` → `promote-images` → `tag-release`): it copies each candidate to its release name inside the registry, by digest, refusing to overwrite an existing release, and then tags the commit. A release name therefore only ever holds a checked build, and a git tag always has its images. Candidates of failed pipelines stay in the `-ci` repositories, which hold nothing else; `zot_ci_user` pushes to them as it does to the release repositories. Nothing prunes them yet (bored #468).

The release version is `major.minor.<Woodpecker pipeline number>` (see [Development](development.md#versioning)). Patch numbers jump by however many pipelines ran in between, deployments included.

Woodpecker keeps two separate Cargo caches, and neither reuses the other. The `unit-test` step builds debug and test artifacts into the `sovereign-config-contract-target` volume. The image builds compile release artifacts into the `sovereign-config-cargo-target` BuildKit cache mount. Each cache is bounded at 20 GiB by its own prune script, `scripts/ci-prune-cargo-target.sh` and `scripts/ci-prune-buildkit-cache.sh`.

Release images are published to `registry.desync.link` (Zot): `sovereign-config`, `sovereign-config-woodpecker-broker` and `sovereign-config-cli`. The CLI image pulls anonymously, so a Woodpecker step using it needs no registry credentials; if the registry is ever made to require authentication for pulls, the consuming repository needs a Woodpecker registry entry for `registry.desync.link`.

## Deploying

**A push never deploys.** Development is deployed with Woodpecker's **Deploy feature — a `deployment` event targeting the `dev` environment, from any branch** — so pushes from several branches never queue behind each other's deploys or fight over the one dev environment. It promotes exactly as production does (below): it resolves the commit's existing tag, verifies the three published images, applies the development Authentik blueprint (`authentik/blueprint-dev.yaml`), validates the development connection manager against live Authentik, and deploys onto the development stack. Dev runs whichever branch was deployed last; a migration deployed from a branch stays applied to the dev database. The development deployment is verified by calling `System.GetVersion` through the public gRPC endpoint after Woodpecker completes.

Production is deployed with Woodpecker's **Deploy feature — a `deployment` event targeting the `prod` environment, from `main`**. All build, tag, publish, and version-allocation steps run only on a `push` or a manual run of the pipeline, never on a `deployment`, so a promotion never rebuilds, republishes, or mints a new version, and never redeploys development. Instead it **resolves the semver the push pipeline already tagged onto the commit** (`resolve-release-tag`; it never allocates — allocating on a deployment would mint an unbuilt tag), **verifies that exact image is present in the registry** (`verify-image`, no rebuild), applies the production Authentik blueprint (`authentik/blueprint.yaml`), validates the production connection manager against live Authentik, and deploys that image onto the production stack. A commit can therefore only be deployed — to either environment — after its push pipeline has finished (checks + build + publish → git tag); a commit with no release tag fails closed.

The pipeline does not require a dev deployment before a promotion, but **deploy the main commit to dev before promoting it to prod**. That is an operator rule, not a gate. A release tag means the checks passed: CI's migration checks run against a fresh PostgreSQL, and `deploy-prod` runs its own live connection-manager check. Only a dev deployment proves the release against a long-lived database and against live Authentik with the development blueprint, and before #466 every release had that proof. Skipping it is an accepted risk, not an oversight.

Each deployment applies its environment's blueprint before starting the stack; production applies only the production blueprint. Before applying, the pipeline checks the Authentik instance's authenticated version endpoint and schema against the minimum version the blueprints need ([Authentication](authentication.md)).

### Production prerequisites

Before the first promotion the operator provides the production Woodpecker secrets `sovereign_config_prod_postgres_password`, `sovereign_config_prod_manager_api_token`, and `sovereign_config_prod_value_encryption_key` (the server refuses to start without it), the pre-created encrypted `sovereign-config-production-db` volume, and DNS/Traefik for the production host. The deployment path also reuses the shared secrets `github_token` (tag resolution), `zot_ci_user` and `zot_ci_password` (registry pull), and `authentik_api_token` (blueprint). Every CI secret is served by the Sovereign Config Woodpecker secrets broker, which offers it to every event except pull requests, so moving a step between `push` and `deployment` needs no secret change.

### Self-hosting exception

Sovereign Config's own deploy steps deliberately do **not** consume their configuration through `render`, and keep their Woodpecker secrets. Reading `/sovereign-config/prod/...` in order to deploy Sovereign Config would create a circular availability dependency: a broken production deployment could not be redeployed through a path that requires production to be readable. Other repositories and the homelab stacks are the intended consumers.

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
