//! A [`config`](https://docs.rs/config) source that loads a managed subtree.
//!
//! Adding a [`SovereignConfigSource`] to a `config` builder makes the managed
//! connection load — connect, authenticate, read, reveal — happen when the
//! configuration is built, so the application never initialises the provider
//! itself.

use std::fmt;

use config::{ConfigError, Map, Source, Value, ValueKind};

use crate::{Provider, ProviderError};

/// A `config` source backed by a Sovereign Config managed connection.
///
/// The connection URL (or the environment variable holding it) is resolved and
/// loaded lazily inside [`Source::collect`], i.e. when the `config` builder's
/// `build()` runs — not when the source is constructed. The loaded subtree
/// becomes one layer of the composed configuration.
///
/// ```no_run
/// use std::collections::HashMap;
///
/// use config::{Config, Environment, File};
/// use sovereign_config_provider::SovereignConfigSource;
///
/// let settings = Config::builder()
///     .add_source(File::with_name("config/settings").required(false))
///     .add_source(SovereignConfigSource::from_env("APP_CONFIG_URL"))
///     .add_source(Environment::with_prefix("APP"))
///     .build()
///     .unwrap();
///
/// let values: HashMap<String, String> = settings.try_deserialize().unwrap();
/// # let _ = values;
/// ```
///
/// # Blocking
///
/// `collect` performs blocking network I/O on a dedicated internal thread and
/// runtime, so it is safe to call the `config` builder's `build()` from either a
/// synchronous or an asynchronous context.
///
/// # Redaction
///
/// The connection URL is a secret; the [`fmt::Debug`] implementation never
/// prints it, satisfying `config`'s `Source: Debug` bound without leaking.
#[derive(Clone)]
pub struct SovereignConfigSource {
    connection: Connection,
}

#[derive(Clone)]
enum Connection {
    Url(String),
    Env(String),
}

impl SovereignConfigSource {
    /// Builds a source from a literal managed connection URL.
    #[must_use]
    pub fn from_url(url: impl Into<String>) -> Self {
        Self {
            connection: Connection::Url(url.into()),
        }
    }

    /// Builds a source that reads the managed connection URL from the named
    /// environment variable when the configuration is built.
    #[must_use]
    pub fn from_env(variable: impl Into<String>) -> Self {
        Self {
            connection: Connection::Env(variable.into()),
        }
    }

    fn resolve_url(&self) -> Result<String, ConfigError> {
        match &self.connection {
            Connection::Url(url) => Ok(url.clone()),
            Connection::Env(variable) => std::env::var(variable).map_err(|_| {
                ConfigError::Message(format!(
                    "environment variable `{variable}` is not set or not valid UTF-8"
                ))
            }),
        }
    }
}

impl fmt::Debug for SovereignConfigSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render the connection URL: it is a secret.
        formatter
            .debug_struct("SovereignConfigSource")
            .finish_non_exhaustive()
    }
}

impl Source for SovereignConfigSource {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.clone())
    }

    fn collect(&self) -> Result<Map<String, Value>, ConfigError> {
        let url = self.resolve_url()?;
        let json = load_blocking(url).map_err(|error| ConfigError::Foreign(Box::new(error)))?;
        match json {
            serde_json::Value::Object(object) => Ok(object
                .into_iter()
                .map(|(key, value)| (key, json_to_value(value)))
                .collect()),
            // A subtree root is a JSON object; an exact scalar root has no
            // configuration table to layer.
            _ => Err(ConfigError::Message(
                "Sovereign Config connection root is not a configuration table".to_owned(),
            )),
        }
    }
}

/// Runs the async connect-and-load on a dedicated thread and runtime.
///
/// Using a separate thread means the caller's runtime (if any) is never nested
/// and never required to drive this work, so `build()` is safe from both sync
/// and async contexts.
fn load_blocking(url: String) -> Result<serde_json::Value, ProviderError> {
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| ProviderError::Unavailable)?;
        runtime.block_on(async move {
            let provider = Provider::connect(&url).await?;
            provider.load::<serde_json::Value>().await
        })
    })
    .join()
    .map_err(|_| ProviderError::Internal)?
}

fn json_to_value(json: serde_json::Value) -> Value {
    let kind = match json {
        serde_json::Value::String(text) => ValueKind::String(text),
        serde_json::Value::Object(object) => ValueKind::Table(
            object
                .into_iter()
                .map(|(key, value)| (key, json_to_value(value)))
                .collect(),
        ),
        // `subtree_to_json` only ever emits strings and nested objects.
        _ => ValueKind::Nil,
    };
    Value::new(None, kind)
}
