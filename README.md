# Sovereign Config

Sovereign Config is a self-hosted, gRPC-first configuration service. This repository is a Cargo-workspace monorepo: the server, protocol crates, shared client libraries, Rust provider, WASM UI, and local MCP binary are released together from the same source tag.

## Deployment

The production Compose stack contains only PostgreSQL and Sovereign Config. It publishes no application, PostgreSQL, metrics, logging, or tracing ports. Traefik must provide the external `traefik` network and is the only supported ingress. The PostgreSQL volume and all backup/staging storage must be encrypted by the operator.

Create operator-owned secret files with mode `0600`. `POSTGRES_PASSWORD_FILE` contains only the PostgreSQL password. `DATABASE_URL_FILE` contains the complete private-network URL, for example `postgresql://sovereign_config:<password>@postgres:5432/sovereign_config`. Never commit either file.

Set the required deployment inputs and start the stack:

```sh
export SOVEREIGN_CONFIG_IMAGE_TAG='1.1.0'
export SOVEREIGN_CONFIG_HOST='config.example.internal'
export POSTGRES_PASSWORD_FILE="$HOME/.config/sovereign-config/postgres-password"
export DATABASE_URL_FILE="$HOME/.config/sovereign-config/database-url"
docker compose up -d
```

`SOVEREIGN_CONFIG_IMAGE_TAG` selects the published Zot image; it defaults to `local` for local builds. PostgreSQL is pinned by digest. The service starts only after PostgreSQL reports healthy.

Build release images only for linux/amd64 with `docker build --platform linux/amd64 --tag sovereign-config:local .`.

## Upgrade

1. Stop Sovereign Config traffic through Traefik.
2. Verify a recoverable PostgreSQL backup from encrypted backup/staging storage.
3. Set `SOVEREIGN_CONFIG_IMAGE` to the new published digest and run `docker compose up -d`.
4. The service applies its forward-only migrations before accepting requests.
5. Validate native gRPC health/version and `/readyz` through the trusted internal network before restoring traffic.

Downgrades after a migration are unsupported. Restore the verified PostgreSQL backup into a replacement deployment instead.

## Observability

The application writes structured redacted JSON logs to stdout. Internal Alloy discovers `/metrics` using the Docker labels in `compose.yaml`; that endpoint is not routed through Traefik. OTLP export and the Authentik dependency are introduced with their respective cards and will be required explicit boot configuration.

## Release Gate

Publish an image digest only after `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, unit and integration checks, PostgreSQL migration checks, gRPC/gRPC-Web end-to-end checks, and supported-browser UI checks pass. SBOM generation is out of scope for the MVP.
