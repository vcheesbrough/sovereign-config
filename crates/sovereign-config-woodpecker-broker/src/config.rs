//! Environment-driven broker configuration.
//!
//! Every value is resolved and validated once at startup so a misconfiguration
//! fails the process rather than the first pipeline. Secrets follow the same
//! `NAME` / `NAME_FILE` convention as the server, so Compose can mount them as
//! files.
//!
//! Resolution reads through an injected [`Env`] lookup rather than calling
//! `std::env` directly. Mutating process environment is `unsafe` in edition
//! 2024 and this workspace forbids `unsafe_code`, so tests supply a map instead
//! of setting real variables.

use std::{collections::BTreeMap, env, fs, net::SocketAddr, path::PathBuf, time::Duration};

use sovereign_config_core::Secret;

use crate::layers::LayerTemplates;

/// The default cap on how long an access token is reused, regardless of the
/// lifetime the provider reports.
const DEFAULT_TOKEN_TTL: Duration = Duration::from_secs(300);
/// Requests queued for the reader before the broker sheds load as 503.
const DEFAULT_QUEUE_DEPTH: usize = 16;
const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:8080";
const DEFAULT_METRICS_ADDR: &str = "0.0.0.0:9090";

/// A source of environment values. Implemented for the real process
/// environment and, in tests, for a plain map.
pub(crate) trait Env {
    fn get(&self, name: &str) -> Option<String>;
}

pub(crate) struct ProcessEnv;

impl Env for ProcessEnv {
    fn get(&self, name: &str) -> Option<String> {
        env::var(name).ok()
    }
}

impl Env for BTreeMap<&str, &str> {
    fn get(&self, name: &str) -> Option<String> {
        self.get(name).map(|value| (*value).to_owned())
    }
}

pub(crate) struct Config {
    /// The managed connection URL. Carries the client-credentials secret, so it
    /// is held as a [`Secret`] and never formatted.
    pub(crate) connection_url: Secret,
    pub(crate) layers: LayerTemplates,
    pub(crate) listen_addr: SocketAddr,
    pub(crate) metrics_addr: SocketAddr,
    pub(crate) token_ttl: Duration,
    pub(crate) queue_depth: usize,
    pub(crate) public_key: PublicKeySource,
}

/// Where the Woodpecker request-signing public key comes from.
///
/// Mirrors the Go broker's precedence: an API fetch wins when both are
/// configured, so an operator can point at a live server without first removing
/// a stale file.
pub(crate) enum PublicKeySource {
    Fetch { url: String, token: Secret },
    File(PathBuf),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ConfigError {
    #[error("{0} is required")]
    Missing(&'static str),
    #[error("{0} is empty")]
    Empty(String),
    #[error("{0} is not readable")]
    Unreadable(String),
    #[error("{name} is not a valid {expected}")]
    Invalid {
        name: &'static str,
        expected: &'static str,
    },
    #[error("WOODPECKER_PUBLIC_KEY_FILE, or WOODPECKER_URL with WOODPECKER_TOKEN, is required")]
    NoPublicKeySource,
    #[error("the request and metrics listeners must use different addresses")]
    DuplicateListener,
    #[error("SOVEREIGN_CONFIG_BROKER_LAYERS is invalid: {0}")]
    Layers(#[from] crate::layers::LayerError),
}

impl Config {
    pub(crate) fn from_env() -> Result<Self, ConfigError> {
        Self::resolve(&ProcessEnv)
    }

    pub(crate) fn resolve(env: &impl Env) -> Result<Self, ConfigError> {
        let connection_url = Secret::new(required_secret(
            env,
            "SOVEREIGN_CONFIG_BROKER_CONNECTION_URL",
        )?);
        let layers = LayerTemplates::parse(&required(env, "SOVEREIGN_CONFIG_BROKER_LAYERS")?)?;
        let listen_addr = listen_addr(env)?;
        let metrics_addr = socket_addr(
            env,
            "SOVEREIGN_CONFIG_BROKER_METRICS_ADDR",
            DEFAULT_METRICS_ADDR,
        )?;
        if listen_addr == metrics_addr {
            return Err(ConfigError::DuplicateListener);
        }

        let token_ttl = Duration::from_secs(positive(
            env,
            "SOVEREIGN_CONFIG_BROKER_TOKEN_TTL_SECONDS",
            DEFAULT_TOKEN_TTL.as_secs(),
            "positive number of seconds",
        )?);
        let queue_depth = usize::try_from(positive(
            env,
            "SOVEREIGN_CONFIG_BROKER_QUEUE_DEPTH",
            DEFAULT_QUEUE_DEPTH as u64,
            "positive integer",
        )?)
        .map_err(|_| ConfigError::Invalid {
            name: "SOVEREIGN_CONFIG_BROKER_QUEUE_DEPTH",
            expected: "positive integer",
        })?;

        Ok(Self {
            connection_url,
            layers,
            listen_addr,
            metrics_addr,
            token_ttl,
            queue_depth,
            public_key: public_key_source(env)?,
        })
    }
}

fn public_key_source(env: &impl Env) -> Result<PublicKeySource, ConfigError> {
    match (
        optional(env, "WOODPECKER_URL"),
        optional(env, "WOODPECKER_TOKEN"),
    ) {
        (Some(url), Some(token)) => Ok(PublicKeySource::Fetch {
            url,
            token: Secret::new(token),
        }),
        _ => optional(env, "WOODPECKER_PUBLIC_KEY_FILE")
            .map(|path| PublicKeySource::File(PathBuf::from(path)))
            .ok_or(ConfigError::NoPublicKeySource),
    }
}

/// Reads a variable, treating whitespace-only as absent so an empty Compose
/// substitution does not silently become a value.
fn optional(env: &impl Env, name: &str) -> Option<String> {
    env.get(name)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn required(env: &impl Env, name: &'static str) -> Result<String, ConfigError> {
    optional(env, name).ok_or(ConfigError::Missing(name))
}

/// Resolves the request listener address.
///
/// Shared with the `healthcheck` subcommand so the two cannot disagree about
/// what the variable means. They previously read it independently, and the
/// healthcheck's stricter reading turned an empty Compose substitution into a
/// container that ran correctly on the default while its `HEALTHCHECK` failed
/// forever.
pub(crate) fn listen_addr(env: &impl Env) -> Result<SocketAddr, ConfigError> {
    socket_addr(
        env,
        "SOVEREIGN_CONFIG_BROKER_LISTEN_ADDR",
        DEFAULT_LISTEN_ADDR,
    )
}

fn socket_addr(
    env: &impl Env,
    name: &'static str,
    default: &str,
) -> Result<SocketAddr, ConfigError> {
    optional(env, name)
        .unwrap_or_else(|| default.to_owned())
        .parse()
        .map_err(|_| ConfigError::Invalid {
            name,
            expected: "socket address",
        })
}

fn positive(
    env: &impl Env,
    name: &'static str,
    default: u64,
    expected: &'static str,
) -> Result<u64, ConfigError> {
    let Some(value) = optional(env, name) else {
        return Ok(default);
    };
    match value.parse::<u64>() {
        Ok(parsed) if parsed > 0 => Ok(parsed),
        _ => Err(ConfigError::Invalid { name, expected }),
    }
}

/// Resolves a secret from `NAME`, falling back to the contents of the file at
/// `NAME_FILE`. The direct variable wins so a local run can override a mount.
fn required_secret(env: &impl Env, name: &'static str) -> Result<String, ConfigError> {
    if let Some(value) = optional(env, name) {
        return Ok(value);
    }
    let file_name = format!("{name}_FILE");
    let path = optional(env, &file_name).ok_or(ConfigError::Missing(name))?;
    let value =
        fs::read_to_string(&path).map_err(|_| ConfigError::Unreadable(file_name.clone()))?;
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err(ConfigError::Empty(file_name));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, io::Write, net::SocketAddr};

    use super::{
        Config, ConfigError, PublicKeySource, listen_addr, public_key_source, required_secret,
        socket_addr,
    };

    const URL: &str = "https://config.example.test/woodpecker#v=1&issuer=https%3A%2F%2Fauth.example.test%2Fapplication%2Fo%2Fconfig%2F&client_id=broker&client_secret=dXNlcjpwYXNz";

    fn base() -> BTreeMap<&'static str, &'static str> {
        BTreeMap::from([
            ("SOVEREIGN_CONFIG_BROKER_CONNECTION_URL", URL),
            (
                "SOVEREIGN_CONFIG_BROKER_LAYERS",
                "global,repos/{repo.owner}/{repo.name}",
            ),
            ("WOODPECKER_PUBLIC_KEY_FILE", "/etc/woodpecker/pubkey.pem"),
        ])
    }

    #[test]
    fn defaults_apply_when_only_the_required_values_are_set() {
        let config = Config::resolve(&base()).unwrap();
        assert_eq!(config.listen_addr, addr("0.0.0.0:8080"));
        assert_eq!(config.metrics_addr, addr("0.0.0.0:9090"));
        assert_eq!(config.token_ttl.as_secs(), 300);
        assert_eq!(config.queue_depth, 16);
        assert_eq!(config.connection_url.expose(), URL);
    }

    #[test]
    fn each_required_value_is_named_when_absent() {
        for (name, message) in [
            (
                "SOVEREIGN_CONFIG_BROKER_CONNECTION_URL",
                "SOVEREIGN_CONFIG_BROKER_CONNECTION_URL is required",
            ),
            (
                "SOVEREIGN_CONFIG_BROKER_LAYERS",
                "SOVEREIGN_CONFIG_BROKER_LAYERS is required",
            ),
        ] {
            let mut env = base();
            env.remove(name);
            assert_eq!(resolve_error(&env).to_string(), message);
        }
    }

    /// `Config` has no `Debug` — it holds the connection secret — so errors are
    /// extracted without `unwrap_err`.
    fn resolve_error(env: &BTreeMap<&str, &str>) -> ConfigError {
        match Config::resolve(env) {
            Ok(_) => panic!("configuration unexpectedly resolved"),
            Err(error) => error,
        }
    }

    #[test]
    fn identical_listeners_are_rejected() {
        let mut env = base();
        env.insert("SOVEREIGN_CONFIG_BROKER_LISTEN_ADDR", "0.0.0.0:9000");
        env.insert("SOVEREIGN_CONFIG_BROKER_METRICS_ADDR", "0.0.0.0:9000");
        assert!(matches!(
            Config::resolve(&env),
            Err(ConfigError::DuplicateListener)
        ));
    }

    #[test]
    fn bounded_numbers_reject_zero_and_junk() {
        for (name, value) in [
            ("SOVEREIGN_CONFIG_BROKER_TOKEN_TTL_SECONDS", "0"),
            ("SOVEREIGN_CONFIG_BROKER_TOKEN_TTL_SECONDS", "soon"),
            ("SOVEREIGN_CONFIG_BROKER_TOKEN_TTL_SECONDS", "-1"),
            ("SOVEREIGN_CONFIG_BROKER_QUEUE_DEPTH", "0"),
            ("SOVEREIGN_CONFIG_BROKER_QUEUE_DEPTH", "lots"),
        ] {
            let mut env = base();
            env.insert(name, value);
            assert!(Config::resolve(&env).is_err(), "accepted {name}={value:?}");
        }
    }

    #[test]
    fn a_whitespace_only_value_counts_as_absent() {
        let mut env = base();
        env.insert("SOVEREIGN_CONFIG_BROKER_LAYERS", "   ");
        assert!(matches!(
            Config::resolve(&env),
            Err(ConfigError::Missing("SOVEREIGN_CONFIG_BROKER_LAYERS"))
        ));
    }

    #[test]
    fn a_secret_falls_back_to_its_file_and_is_trimmed() {
        let path = write_temp("secret-a", "  from-file\n");
        let env = BTreeMap::from([("SOVEREIGN_CONFIG_BROKER_CONNECTION_URL_FILE", path.as_str())]);
        assert_eq!(
            required_secret(&env, "SOVEREIGN_CONFIG_BROKER_CONNECTION_URL").unwrap(),
            "from-file"
        );
    }

    #[test]
    fn the_direct_variable_wins_over_the_file() {
        let path = write_temp("secret-b", "from-file");
        let env = BTreeMap::from([
            ("SOVEREIGN_CONFIG_BROKER_CONNECTION_URL", "from-env"),
            ("SOVEREIGN_CONFIG_BROKER_CONNECTION_URL_FILE", path.as_str()),
        ]);
        assert_eq!(
            required_secret(&env, "SOVEREIGN_CONFIG_BROKER_CONNECTION_URL").unwrap(),
            "from-env"
        );
    }

    #[test]
    fn an_empty_or_unreadable_secret_file_is_an_error_not_an_absent_value() {
        let empty = write_temp("secret-c", "   \n");
        let env = BTreeMap::from([(
            "SOVEREIGN_CONFIG_BROKER_CONNECTION_URL_FILE",
            empty.as_str(),
        )]);
        assert!(matches!(
            required_secret(&env, "SOVEREIGN_CONFIG_BROKER_CONNECTION_URL"),
            Err(ConfigError::Empty(_))
        ));

        let env = BTreeMap::from([(
            "SOVEREIGN_CONFIG_BROKER_CONNECTION_URL_FILE",
            "/nonexistent/sovereign-config-broker-test",
        )]);
        assert!(matches!(
            required_secret(&env, "SOVEREIGN_CONFIG_BROKER_CONNECTION_URL"),
            Err(ConfigError::Unreadable(_))
        ));
    }

    #[test]
    fn a_public_key_source_is_mandatory_and_a_live_server_wins() {
        assert!(matches!(
            public_key_source(&BTreeMap::new()),
            Err(ConfigError::NoPublicKeySource)
        ));
        assert!(matches!(
            public_key_source(&BTreeMap::from([(
                "WOODPECKER_PUBLIC_KEY_FILE",
                "/etc/woodpecker/pubkey.pem"
            )]))
            .unwrap(),
            PublicKeySource::File(_)
        ));
        // A URL without a token cannot fetch, so it must not shadow the file.
        assert!(matches!(
            public_key_source(&BTreeMap::from([
                ("WOODPECKER_URL", "https://woodpecker.example.test"),
                ("WOODPECKER_PUBLIC_KEY_FILE", "/etc/woodpecker/pubkey.pem"),
            ]))
            .unwrap(),
            PublicKeySource::File(_)
        ));
        assert!(matches!(
            public_key_source(&BTreeMap::from([
                ("WOODPECKER_URL", "https://woodpecker.example.test"),
                ("WOODPECKER_TOKEN", "token-sentinel"),
                ("WOODPECKER_PUBLIC_KEY_FILE", "/etc/woodpecker/pubkey.pem"),
            ]))
            .unwrap(),
            PublicKeySource::Fetch { .. }
        ));
    }

    // The healthcheck subcommand resolves its probe target through
    // `listen_addr` too. If these diverged, an empty Compose substitution would
    // give a container that serves correctly on the default while its
    // HEALTHCHECK fails on every probe.
    #[test]
    fn the_healthcheck_and_the_server_agree_on_the_listener() {
        for (value, expected) in [
            (None, "0.0.0.0:8080"),
            (Some(""), "0.0.0.0:8080"),
            (Some("   "), "0.0.0.0:8080"),
            (Some(" 127.0.0.1:9000 "), "127.0.0.1:9000"),
        ] {
            let mut env = base();
            match value {
                Some(value) => {
                    env.insert("SOVEREIGN_CONFIG_BROKER_LISTEN_ADDR", value);
                }
                None => {
                    env.remove("SOVEREIGN_CONFIG_BROKER_LISTEN_ADDR");
                }
            }
            let probed = listen_addr(&env).unwrap();
            assert_eq!(
                probed,
                addr(expected),
                "listen_addr disagreed for {value:?}"
            );
            assert_eq!(
                Config::resolve(&env).unwrap().listen_addr,
                probed,
                "the server and the healthcheck disagreed for {value:?}"
            );
        }
    }

    #[test]
    fn listener_addresses_fall_back_to_the_default_and_reject_junk() {
        assert_eq!(
            socket_addr(&BTreeMap::new(), "UNSET", "0.0.0.0:8080").unwrap(),
            addr("0.0.0.0:8080")
        );
        assert!(
            socket_addr(
                &BTreeMap::from([("BAD", "not-an-address")]),
                "BAD",
                "0.0.0.0:8080"
            )
            .is_err()
        );
    }

    fn addr(value: &str) -> SocketAddr {
        value.parse().unwrap()
    }

    fn write_temp(label: &str, contents: &str) -> String {
        let path = std::env::temp_dir().join(format!(
            "sovereign-config-broker-{label}-{}.tmp",
            std::process::id()
        ));
        let mut file = std::fs::File::create(&path).unwrap();
        write!(file, "{contents}").unwrap();
        path.to_string_lossy().into_owned()
    }
}
