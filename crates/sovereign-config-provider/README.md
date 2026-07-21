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

### Layering with the `config` crate

Enable the optional `config` feature to get a [`config`](https://docs.rs/config)
source that loads the managed subtree *when the configuration is built* — the
application never initialises the provider itself. `SovereignConfigSource` slots
in as one ordinary layer alongside files and environment variables.

Consumer `Cargo.toml`:

```toml
[dependencies]
sovereign-config-provider = { git = "https://github.com/vcheesbrough/sovereign-config", tag = "<version>", features = ["config"] }
config = "0.15"
```

```rust,no_run
use std::collections::HashMap;

use config::{Config, Environment, File};
use sovereign_config_provider::SovereignConfigSource;

fn main() {
    let settings = Config::builder()
        // Add in `./examples/settings.toml`
        .add_source(File::with_name("examples/settings"))
        // Add in the managed Sovereign Config subtree; it connects, authenticates,
        // reads, and reveals its secrets when `build()` runs.
        .add_source(SovereignConfigSource::initialise_from_default_environment())
        // Add in settings from the environment (with a prefix of APP)
        // Eg.. `APP_DEBUG=1 ./target/app` would set the `debug` key
        .add_source(Environment::with_prefix("APP"))
        .build()
        .unwrap();

    // Print out our settings (as a HashMap)
    println!(
        "{:?}",
        settings
            .try_deserialize::<HashMap<String, String>>()
            .unwrap()
    );
}
```

Sources are layered in order, so Sovereign Config overrides the file defaults and
the environment overrides Sovereign Config. Because every Sovereign Config leaf
is stored as text, `config`'s type coercion turns string leaves into the target
type — a stored `"10"` into a `u32`, `"true"` into a `bool` — when you deserialize
into your own `#[derive(Deserialize)]` struct instead of a `HashMap`.

Two constructors, both resolving the *connection URL* at build time (the
configuration values always come from the Sovereign Config subtree):

- `initialise_from_default_environment()` — the standard deployment entry point.
  It first checks `SOVEREIGN_CONFIG_ACCESS_URL_FILE`; if set, the file at that
  path is read and its trimmed contents are the URL (suited to secret managers
  that mount the URL as a file). Otherwise it uses `SOVEREIGN_CONFIG_ACCESS_URL`
  directly. If neither is set, building fails with an error naming both
  variables.
- `initialise_from_url(url)` — takes a URL you already hold, from a custom
  environment variable or any other source.

`collect` performs blocking network I/O on a dedicated internal thread, so
`build()` is safe from both synchronous and asynchronous contexts. The source's
`Debug` output never prints the URL.

If you would rather load the subtree yourself — for example to add it as an
in-memory JSON layer without the feature — [`Provider::load_json`] returns the
revealed subtree as a JSON string ready for `config::File::from_str`. Either way
the loaded configuration contains real secret values, so keep it in memory and
out of logs.

### Typed values and coercion

Sovereign Config stores every value as text — there are no stored numbers,
booleans, or arrays (a deliberate design choice). Which load path you use decides
how those strings become typed fields:

- **`SovereignConfigSource` / `Provider::load_json` + `config`** — `config`
  coerces string leaves to the target type: `"8080"` → `u16`, `"true"` → `bool`,
  `"3.5"` → `f64`. This is the path to use for typed configuration structs.
- **`Provider::load::<T>()`** — deserializes *strictly* through `serde_json`,
  which does **not** coerce. A leaf `"8080"` will not fit a `u16` field; that
  returns `ProviderError::InvalidConversion`. Use `load::<T>()` for
  `String`-shaped configuration, or parse the strings yourself.

Arrays/sequences are not representable: nested paths form tables, not lists, and
`config` will not split a string into a `Vec`. Encode a sequence as a single
string value and parse it in your application if you need one.

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
