//! A [`config`](https://docs.rs/config) source that loads a managed subtree.
//!
//! Adding a [`SovereignConfigSource`] to a `config` builder makes the managed
//! connection load — connect, authenticate, read, reveal — happen when the
//! configuration is built, so the application never initialises the provider
//! itself.

use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use config::{ConfigError, Map, Source, Value, ValueKind};

use crate::mapping::Tree;
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
///     .add_source(SovereignConfigSource::initialise_from_default_environment())
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
/// # Protocol version
///
/// [`SovereignConfigSource::protocol_version`] reports the protocol version the
/// load negotiated, which is the version the service's per-version counters
/// attribute the application to. It is read *after* `build()`, so it can be
/// logged once the application's subscriber is installed — usually later than
/// the configuration is built, since the telemetry settings come from it.
/// `config` stores a clone of every source it is given, and clones share this
/// state, so keep a clone of the source and read the version from that:
///
/// ```no_run
/// use config::Config;
/// use sovereign_config_provider::SovereignConfigSource;
///
/// let source = SovereignConfigSource::initialise_from_default_environment();
/// let settings = Config::builder()
///     .add_source(source.clone())
///     .build()
///     .unwrap();
/// // ...install the subscriber from `settings`, then:
/// if let Some(version) = source.protocol_version() {
///     println!("sovereign-config protocol {version}");
/// }
/// # let _ = settings;
/// ```
///
/// # Redaction
///
/// The connection URL is a secret; the [`fmt::Debug`] implementation never
/// prints it, satisfying `config`'s `Source: Debug` bound without leaking.
#[derive(Clone)]
pub struct SovereignConfigSource {
    connection: Connection,
    /// Shared between clones: `config` collects from its own boxed clone, and
    /// the caller reads the version from the handle it kept.
    negotiated: Arc<Mutex<Option<&'static str>>>,
}

#[derive(Clone)]
enum Connection {
    Url(String),
    DefaultEnvironment,
}

impl SovereignConfigSource {
    /// Builds a source from a managed connection URL you already hold — for
    /// example one read from a custom environment variable or another secret
    /// source.
    #[must_use]
    pub fn initialise_from_url(url: impl Into<String>) -> Self {
        Self {
            connection: Connection::Url(url.into()),
            negotiated: Arc::default(),
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
            negotiated: Arc::default(),
        }
    }

    /// The protocol version the most recent build's session was bound to — on a
    /// successful build, the version its load travelled on, and what the
    /// service's per-request counters attribute this application to.
    ///
    /// `None` until the configuration has been built, and `None` after a build
    /// that failed before a session was negotiated. A build that negotiated and
    /// then failed (token, read, or re-negotiation) still reports the version
    /// the session was bound to. Shared between clones of
    /// this source, so the handle kept by the caller reports what the `config`
    /// builder's own clone loaded. Not secret; safe to log.
    #[must_use]
    pub fn protocol_version(&self) -> Option<&'static str> {
        *self
            .negotiated
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn resolve_url(&self) -> Result<String, ConfigError> {
        match &self.connection {
            Connection::Url(url) => Ok(url.clone()),
            Connection::DefaultEnvironment => resolve_default_environment(),
        }
    }
}

/// Resolves the connection URL from the standard deployment environment.
fn resolve_default_environment() -> Result<String, ConfigError> {
    let url_file = optional_env(URL_FILE_VAR)?;
    resolve_connection_url(
        url_file,
        || optional_env(URL_VAR),
        |path| std::fs::read_to_string(path),
    )
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
            // Never echo the path value: a misconfigured `_FILE` could hold the
            // secret URL itself. The OS error does not contain the path.
            ConfigError::Message(format!(
                "`{URL_FILE_VAR}` points to a file that could not be read: {error}"
            ))
        })?;
        let value = contents.trim();
        if value.is_empty() {
            return Err(ConfigError::Message(format!(
                "the file referenced by `{URL_FILE_VAR}` is empty"
            )));
        }
        return Ok(value.to_owned());
    }
    if let Some(url) = url()? {
        let value = url.trim();
        if value.is_empty() {
            return Err(ConfigError::Message(format!(
                "`{URL_VAR}` is set but empty"
            )));
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
        // Cleared first, so a build that fails before negotiating never reports
        // the version an earlier build negotiated.
        *self
            .negotiated
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
        let url = self.resolve_url()?;
        let (negotiated, tree) = load_blocking(url);
        // Recorded whether or not the load succeeded: once negotiated, the
        // session is bound to this version, even if the token, the read, or a
        // re-negotiation then failed. It is not evidence that the service
        // counted an authenticated request on it.
        *self
            .negotiated
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = negotiated;
        let tree = tree.map_err(|error| ConfigError::Foreign(Box::new(error)))?;
        match tree {
            Tree::Node(children) => Ok(children
                .into_iter()
                .map(|(key, value)| (key, tree_to_value(value)))
                .collect()),
            // A subtree root nests into a table; an exact scalar root has no
            // configuration table to layer.
            Tree::Leaf(_) => Err(ConfigError::Message(
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
///
/// Returns the protocol version the load travelled on — read *after* the load,
/// because a load re-negotiates if the version is retired under it — or `None`
/// when no session was negotiated.
fn load_blocking(url: String) -> (Option<&'static str>, Result<Tree, ProviderError>) {
    std::thread::spawn(move || {
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            return (None, Err(ProviderError::Unavailable));
        };
        runtime.block_on(async move {
            let provider = match Provider::connect(&url).await {
                Ok(provider) => provider,
                Err(error) => return (None, Err(error)),
            };
            let tree = provider.load_tree().await;
            (Some(provider.protocol_version()), tree)
        })
    })
    .join()
    .unwrap_or((None, Err(ProviderError::Internal)))
}

/// Transcodes the format-neutral tree straight into `config::Value` — no JSON.
fn tree_to_value(tree: Tree) -> Value {
    let kind = match tree {
        Tree::Leaf(text) => ValueKind::String(text),
        Tree::Node(children) => ValueKind::Table(
            children
                .into_iter()
                .map(|(key, value)| (key, tree_to_value(value)))
                .collect(),
        ),
    };
    Value::new(None, kind)
}

#[cfg(test)]
mod tests {
    use std::io::{Error, ErrorKind};

    use super::{URL_FILE_VAR, URL_VAR, resolve_connection_url};

    /// Clearing at the start of `collect` matters only on the early return from
    /// `resolve_url`; every later path overwrites the value anyway.
    #[test]
    fn a_build_that_fails_to_resolve_the_url_clears_an_earlier_version() {
        use config::Source;
        assert!(
            std::env::var_os(URL_FILE_VAR).is_none() && std::env::var_os(URL_VAR).is_none(),
            "this test needs both access-URL variables unset"
        );
        let source = super::SovereignConfigSource::initialise_from_default_environment();
        *source.negotiated.lock().unwrap() = Some("v3");
        assert!(source.collect().is_err());
        assert_eq!(source.protocol_version(), None);
    }

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
    fn unreadable_url_file_reports_the_cause_without_the_path() {
        let message = resolve_connection_url(
            Some("/run/secrets/managed-url".to_owned()),
            || Ok(None),
            |_| Err(Error::new(ErrorKind::NotFound, "no such file")),
        )
        .unwrap_err()
        .to_string();
        assert!(message.contains(URL_FILE_VAR));
        assert!(message.contains("could not be read"));
        // The path value is redacted: it could be a misconfigured secret URL.
        assert!(!message.contains("/run/secrets/managed-url"));
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
        let message =
            resolve_connection_url(Some("   ".to_owned()), || Ok(None), |_| unreachable!())
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
