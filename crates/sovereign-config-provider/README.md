# sovereign-config-provider

An ergonomic application-configuration facade over the Sovereign Config native
client. It turns a managed connection URL into typed application configuration:
authenticate with client credentials, read the permitted subtree over native
gRPC, and deserialize it into your own `serde` type.

This crate is a thin facade. URL parsing, the redacted secret type,
client-credentials token acquisition, the gRPC transport, and the subtree/reveal
RPCs all belong to `sovereign-config-core`, `-client`, and `-native`; the
provider only adds the connect/authenticate/map ergonomics on top. CLI, UI, and
other adapters use the shared crates directly and must not depend on this one.

## Distribution

The provider is distributed as **tagged workspace source only** — there is no
container image or prebuilt library artifact. Depend on it from the same tag as
the Sovereign Config server it talks to:

```toml
[dependencies]
sovereign-config-provider = { git = "https://github.com/vcheesbrough/sovereign-config", tag = "<version>" }
serde = { version = "1", features = ["derive"] }
```

- **Supported Rust:** the workspace `rust-version` (currently 1.94), edition 2024.
- **Protocol:** `v3`. The provider negotiates protocol compatibility on connect
  and fails closed on mismatch. Server and provider must share a release tag.

## Usage

```rust,no_run
use serde::Deserialize;
use sovereign_config_provider::{Provider, ProviderError};

#[derive(Deserialize)]
struct Database {
    url: String,
    password: String, // a secret-classified value, revealed transparently
}

#[derive(Deserialize)]
struct AppConfig {
    feature: String,
    database: Database,
}

async fn load(connection_url: &str) -> Result<AppConfig, ProviderError> {
    let provider = Provider::connect(connection_url).await?;
    provider.load().await
}
```

### Secret injection

The connection URL is itself a secret (its fragment carries an encoded app
password). The provider accepts it as a plain `&str` and reads nothing from the
environment or disk; the application owns how the URL is injected — typically an
environment variable or secret file mounted by your orchestrator. Never log it,
place it in process arguments, or commit it.

## Contract

- **Managed connections only.** A human device-flow URL is rejected with
  `ProviderError::UnsupportedCredential`; an unattended application must be given
  a managed client-credentials URL.
- **No caching.** Each `load()` acquires one fresh access token and re-reads the
  subtree. Nothing — token, subtree, or revealed secret — is retained across or
  within calls.
- **No retries.** Any failed step returns immediately.
- **Redaction.** No error, log, or public value exposes the URL, its fragment, a
  token, an app password, the issuer, an identity, a grant, or a configuration
  value.
- **Secret leaves cost one reveal each.** Secret-classified values are masked in
  ordinary reads, so `load()` issues one additional `reveal_secret` RPC per
  secret leaf under the root (the connection's read-only grant permits reveal).
  A load's RPC count is therefore `1 + (number of secret leaves)` plus one token
  acquisition.

## Errors

`ProviderError` is a bounded, redacted enum. Every variant carries a fixed
message with no dynamic content:

| Variant | Meaning |
| --- | --- |
| `MalformedUrl` | The connection URL is invalid or non-canonical. |
| `UnsupportedCredential` | A human device-flow URL was supplied instead of a managed one. |
| `AuthenticationFailed` | Token acquisition or an authenticated read was rejected. |
| `PermissionDenied` | The connection is not authorized for the configuration. |
| `IncompatibleProtocol` | The service protocol does not match this release. |
| `InvalidRequest` | The request was rejected as invalid. |
| `NotFound` | A value expected during the load was absent. |
| `Unavailable` | The identity provider or Sovereign Config was unavailable. |
| `InvalidConversion` | The subtree could not be converted into the requested type. |
| `Internal` | An internal error occurred. |

## Async runtime

The underlying transport is `!Send`; drive `connect`/`load` on the task owning
the runtime (a current-thread runtime, or `spawn_local`/`LocalSet`), not on a
`Send`-bound `tokio::spawn`.
