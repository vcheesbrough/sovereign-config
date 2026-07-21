//! A [`config`](https://docs.rs/config) source that loads a managed subtree.
//!
//! Adding a [`SovereignConfigSource`] to a `config` builder makes the managed
//! connection load — connect, authenticate, read, reveal — happen when the
//! configuration is built, so the application never initialises the provider
//! itself.

use std::fmt;

use config::{ConfigError, Map, Source, Value, ValueKind};

use crate::{Provider, ProviderError};

/// Environment variable naming a file whose contents are the connection URL.
const URL_FILE_VAR: &str = "SOVEREIGN_CONFIG_ACCESS_URL_FILE";
/// Environment variable holding the connection URL directly.
const URL_VAR: &str = "SOVEREIGN_CONFIG_ACCESS_URL";

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
///     .add_source(SovereignConfigSource::from_url_env("APP_CONFIG_URL"))
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
    DefaultEnvironment,
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
    ///
    /// Only the connection URL comes from the environment; the configuration
    /// values are still read from the Sovereign Config subtree.
    #[must_use]
    pub fn from_url_env(variable: impl Into<String>) -> Self {
        Self {
            connection: Connection::Env(variable.into()),
        }
    }

    /// Builds a source that resolves the managed connection URL from the
    /// standard deployment environment when the configuration is built.
    ///
    /// Resolution order, checked at build time:
    ///
    /// 1. `SOVEREIGN_CONFIG_ACCESS_URL_FILE` — if set, the file at that path is
    ///    read and its trimmed contents are used as the connection URL. This
    ///    suits secret managers that mount the URL as a file.
    /// 2. `SOVEREIGN_CONFIG_ACCESS_URL` — otherwise, if set, its value is the
    ///    connection URL.
    /// 3. If neither is set, building the configuration fails with an error that
    ///    names both variables.
    ///
    /// Only the connection URL comes from the environment; the configuration
    /// values are still read from the Sovereign Config subtree.
    #[must_use]
    pub fn initialise_from_default_environment() -> Self {
        Self {
            connection: Connection::DefaultEnvironment,
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
            Connection::DefaultEnvironment => resolve_default_environment(),
        }
    }
}

/// Resolves the connection URL from the standard deployment environment.
fn resolve_default_environment() -> Result<String, ConfigError> {
    let url_file = optional_env(URL_FILE_VAR)?;
    resolve_connection_url(url_file, || optional_env(URL_VAR), |path| {
        std::fs::read_to_string(path)
    })
}

/// Reads an environment variable, mapping absence to `None` and invalid UTF-8
/// to a bounded error.
fn optional_env(variable: &str) -> Result<Option<String>, ConfigError> {
    match std::env::var(variable) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(ConfigError::Message(format!(
            "`{variable}` is not valid UTF-8"
        ))),
    }
}

/// Applies the file-first precedence over the two access-URL sources.
///
/// `url` is consulted lazily so the direct variable is only read when no file is
/// configured. `read_file` is injected for testing.
fn resolve_connection_url<U, F>(
    url_file: Option<String>,
    url: U,
    read_file: F,
) -> Result<String, ConfigError>
where
    U: FnOnce() -> Result<Option<String>, ConfigError>,
    F: FnOnce(&str) -> std::io::Result<String>,
{
    if let Some(path) = url_file {
        let path = path.trim();
        if path.is_empty() {
            return Err(ConfigError::Message(format!(
                "`{URL_FILE_VAR}` is set but empty; unset it or point it at a file containing the connection URL"
            )));
        }
        let contents = read_file(path).map_err(|error| {
            ConfigError::Message(format!(
                "`{URL_FILE_VAR}` points to `{path}`, which could not be read: {error}"
            ))
        })?;
        let value = contents.trim();
        if value.is_empty() {
            return Err(ConfigError::Message(format!(
                "the connection URL file `{path}` referenced by `{URL_FILE_VAR}` is empty"
            )));
        }
        return Ok(value.to_owned());
    }
    if let Some(url) = url()? {
        let value = url.trim();
        if value.is_empty() {
            return Err(ConfigError::Message(format!("`{URL_VAR}` is set but empty")));
        }
        return Ok(value.to_owned());
    }
    Err(ConfigError::Message(format!(
        "no managed connection URL configured: set `{URL_FILE_VAR}` to a file containing the URL, or set `{URL_VAR}` to the URL itself"
    )))
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

#[cfg(test)]
mod tests {
    use std::io::{Error, ErrorKind};

    use super::{URL_FILE_VAR, URL_VAR, resolve_connection_url};

    #[test]
    fn url_file_takes_precedence_and_is_trimmed() {
        let url = resolve_connection_url(
            Some("/run/secrets/url".to_owned()),
            || panic!("the direct URL variable must not be consulted"),
            |path| {
                assert_eq!(path, "/run/secrets/url");
                Ok("https://from-file.example.test\n".to_owned())
            },
        )
        .unwrap();
        assert_eq!(url, "https://from-file.example.test");
    }

    #[test]
    fn falls_back_to_the_direct_url_variable() {
        let url = resolve_connection_url(
            None,
            || Ok(Some("https://from-var.example.test\n".to_owned())),
            |_| panic!("no file is configured"),
        )
        .unwrap();
        assert_eq!(url, "https://from-var.example.test");
    }

    #[test]
    fn missing_both_names_the_two_variables() {
        let message = resolve_connection_url(None, || Ok(None), |_| unreachable!())
            .unwrap_err()
            .to_string();
        assert!(message.contains(URL_FILE_VAR));
        assert!(message.contains(URL_VAR));
    }

    #[test]
    fn unreadable_url_file_reports_the_path_and_cause() {
        let message = resolve_connection_url(
            Some("/missing".to_owned()),
            || Ok(None),
            |_| Err(Error::new(ErrorKind::NotFound, "no such file")),
        )
        .unwrap_err()
        .to_string();
        assert!(message.contains("/missing"));
        assert!(message.contains("could not be read"));
    }

    #[test]
    fn empty_url_file_is_rejected() {
        let message = resolve_connection_url(
            Some("/empty".to_owned()),
            || Ok(None),
            |_| Ok("  \n".to_owned()),
        )
        .unwrap_err()
        .to_string();
        assert!(message.contains("is empty"));
    }

    #[test]
    fn empty_url_file_variable_is_rejected() {
        let message = resolve_connection_url(Some("   ".to_owned()), || Ok(None), |_| unreachable!())
            .unwrap_err()
            .to_string();
        assert!(message.contains("is set but empty"));
    }

    #[test]
    fn empty_direct_url_variable_is_rejected() {
        let message =
            resolve_connection_url(None, || Ok(Some("   ".to_owned())), |_| unreachable!())
                .unwrap_err()
                .to_string();
        assert!(message.contains("is set but empty"));
    }
}
