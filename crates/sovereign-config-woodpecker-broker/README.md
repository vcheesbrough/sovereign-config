# sovereign-config-woodpecker-broker

A Woodpecker CI **external secrets extension** backed by Sovereign Config.

Woodpecker resolves a pipeline's secrets by POSTing signed repository and
pipeline metadata to a single configured endpoint. This service is that
endpoint: it verifies the signature, renders the configured layers for the
repository being built, reads them through a read-only managed connection, and
returns the merged result in Woodpecker's secret format.

It replaces [`woodpecker-openbao-broker`](https://github.com/vcheesbrough/woodpecker-openbao-broker)
and is wire-compatible with it, so **no pipeline YAML changes at the cutover** —
`from_secret: github_token` keeps working.

Published as `registry.desync.link/sovereign-config-woodpecker-broker:<semver>`
under the same workspace tag as the server, so the two are protocol-matched by
construction.

## How a repository's secrets are chosen

`SOVEREIGN_CONFIG_BROKER_LAYERS` is an ordered, comma- or newline-separated list
of paths **relative to the connection root**. Each is rendered per request from
the metadata in the signed body, read in declared order, and merged so that
**later layers override earlier ones** on a name collision.

With root `/woodpecker` and

```
SOVEREIGN_CONFIG_BROKER_LAYERS=shared/global,global,repos/{repo.owner}/{repo.name}
```

a pipeline for `vcheesbrough/sovereign-config` reads

```
/woodpecker/shared/global
/woodpecker/global
/woodpecker/repos/vcheesbrough/sovereign-config
```

while `vcheesbrough/bored` reads its own third path. The repository identity
comes from the request, never from configuration — one broker serves every repo.

Placeholders (the complete set; anything else fails at startup):

| Placeholder | Source field | Notes |
| --- | --- | --- |
| `{repo.owner}` | `repo.owner` | |
| `{repo.name}` | `repo.name` | |
| `{repo.full_name}` | `repo.full_name` | renders as **two** segments |
| `{repo.forge_id}` | `repo.forge_id` | optional on the wire |
| `{pipeline.branch}` | `pipeline.branch` | absent on tag pipelines |
| `{pipeline.event}` | `pipeline.event` | |

Substituted text is lowercased, characters outside `[a-z0-9_-]` fold to `-`,
runs collapse, and leading/trailing separators are dropped. A substitution that
reduces to nothing **skips that layer** rather than reading a truncated path —
so a hostile `full_name` cannot escape the root or invent a path level.

A layer that is absent, or that the connection may not read, is skipped and
logged. Any other failure is a 503; returning an empty 200 would look to
Woodpecker like "this repository has no secrets".

## Storage layout

Secret names are path segments, so they map one-to-one:

```
/woodpecker/global/github_token
/woodpecker/repos/vcheesbrough/sovereign-config/zot_ci_password
```

`_` in a path segment requires **release 2.15.0 or later** — see the `Upgrade`
section of the repository README before storing one.

Values shared with non-Woodpecker consumers should stay canonical outside the
broker's root and be exposed under it with an alias, because a managed
connection has exactly one root:

```sh
sovereign-config alias add /shared/global/registry /woodpecker/shared/global/registry
```

Reads cost one `GetSubTree` per layer plus one `RevealSecret` per
secret-classified leaf, because ordinary reads return secrets masked.

## Configuration

| Variable | Required | Default |
| --- | --- | --- |
| `SOVEREIGN_CONFIG_BROKER_CONNECTION_URL` / `…_FILE` | yes | — |
| `SOVEREIGN_CONFIG_BROKER_LAYERS` | yes | — |
| `SOVEREIGN_CONFIG_BROKER_LISTEN_ADDR` | no | `0.0.0.0:8080` |
| `SOVEREIGN_CONFIG_BROKER_METRICS_ADDR` | no | `0.0.0.0:9090` |
| `SOVEREIGN_CONFIG_BROKER_TOKEN_TTL_SECONDS` | no | `300` |
| `SOVEREIGN_CONFIG_BROKER_QUEUE_DEPTH` | no | `16` |
| `WOODPECKER_PUBLIC_KEY_FILE` | one of | — |
| `WOODPECKER_URL` + `WOODPECKER_TOKEN` | one of | — |

The connection URL must be a **managed** connection (client credentials) with
`read` only, rooted at the Woodpecker namespace. A live `WOODPECKER_URL` +
`WOODPECKER_TOKEN` takes precedence over the key file, matching the Go broker.

Endpoints: `GET /health` and `POST /secrets` on the request listener;
`GET /metrics` and `GET /readyz` on the metrics listener. Only `/secrets`
requires a signature.

## Security notes

**The body digest is verified.** Woodpecker signs each request under RFC 9421
with Ed25519 over exactly `("@request-target" "content-digest")`. The Go broker
calls `httpsign.VerifyRequest` directly, and that path never checks
`Content-Digest` against the body — digest validation lives only in the
`Handler`/`Client` wrappers it does not use. A captured request could therefore
be replayed with forged repository metadata inside the ~10 second `created`
window and be brokered another repository's secrets. This broker recomputes the
SHA-256 of the body and compares it in constant time; there is a dedicated
regression test for it.

`created` is accepted within `-10s … +2s`, matching `httpsign`'s verifier
defaults. Do not tighten it without checking clock skew between the Woodpecker
and broker containers.

**Least privilege.** The connection holds `read` on one subtree. It cannot
write, cannot manage connections, and cannot read outside its root.

**Redaction.** A configuration value becomes plain text at exactly one place:
serialising the 200 response. The request DTO does not declare Woodpecker's
`netrc` object at all, so the forge credential it carries never enters the
process as typed data.

**Startup is fail-fast.** A bad connection URL, an unreachable service, or a
protocol mismatch fails the container rather than every pipeline — which matters
because Woodpecker swallows extension errors (see below).

## Parity notes

Deliberate differences from the Go broker, all verified against its source:

- Layer templates are validated at **startup**, not per request.
- The placeholder set is closed rather than arbitrary struct field access.
- The body digest is actually verified (above).
- `pull_request_metadata` is **not** in the emitted event set, matching the Go
  broker's eight events. Woodpecker recognises it as a ninth; adding it is a
  deliberate change, not a bug fix.

## Cutover runbook

Woodpecker supports exactly one secret-extension endpoint, so this is a
replacement. There is no dual-run.

1. **Ship and deploy release 2.15.0**, then reinstall every CLI and MCP client
   from the server's `/dist` and rebuild every `sovereign-config-provider`
   consumer. Do this *before* any underscored path exists — older clients reject
   `_` paths and fail the whole namespace read.
2. **Create the managed connection** in the web UI: root `/woodpecker`,
   permission **read** only. Capture the one-time URL straight into the
   mini-config secret store.
3. **Migrate the secrets**:
   ```sh
   scripts/migrate-openbao-woodpecker-secrets.sh --repo vcheesbrough/sovereign-config --repo vcheesbrough/bored
   # review the printed names, then
   scripts/migrate-openbao-woodpecker-secrets.sh --repo … --apply
   ```
4. **Add the compose service** in the mini-config devops stack: the digest-pinned
   image, `SOVEREIGN_CONFIG_BROKER_CONNECTION_URL_FILE`, the layer spec, and the
   existing mounted `woodpecker-pubkey.pem`.
5. **Capture a live signed request** while an echo endpoint is still wired, and
   commit it as an interop vector. The verifier's profile is derived from
   Woodpecker's source, not from observed bytes; this is the check that closes
   that gap.
6. **Point Woodpecker at the broker**:
   ```
   WOODPECKER_SECRET_EXTENSION_ENDPOINT=http://devops-sovereign-config-broker:8080/secrets
   WOODPECKER_EXTENSIONS_ALLOWED_HOSTS=devops-sovereign-config-broker
   ```
   The allowed-hosts value is the hostname **without** the port — Woodpecker's
   hostmatcher strips the port before matching, so `host:8080` never matches.
7. **Verify with a canary pipeline** that echoes `${#SECRET}` (the length, never
   the value). Woodpecker's `combined.go` logs and *swallows* extension errors
   and falls back to its native store, so a broken broker presents as empty
   variables rather than an outage. Alert on `/readyz` and on
   `sovereign_config_broker_signature_failures_total`.
8. **Keep the OpenBao broker container defined but unwired** so rollback is a
   one-line endpoint revert. Decommission the OpenBao paths only after a week of
   green pipelines.

## Operational shape

Requests are serialised through a single reader thread, which also serialises
token refresh so concurrent pipelines cannot stampede the issuer. The queue is
bounded by `SOVEREIGN_CONFIG_BROKER_QUEUE_DEPTH` and sheds to 503 rather than
growing without limit. If pipeline concurrency ever outgrows one reader, add a
small pool of reader threads — the actor boundary already isolates it.
