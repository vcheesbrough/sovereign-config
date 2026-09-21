use std::{env, fs, net::IpAddr, net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result, bail};
use reqwest::Url;

use crate::encryption::{ValueCipher, decode_key};

const INTROSPECTION_TIMEOUT: Duration = Duration::from_secs(3);
const MANAGER_TIMEOUT: Duration = Duration::from_secs(5);

const SECONDS_PER_HOUR: u64 = 60 * 60;
const SECONDS_PER_DAY: u64 = 24 * SECONDS_PER_HOUR;

pub(crate) struct Config {
    pub(crate) database_url: String,
    pub(crate) grpc_addr: SocketAddr,
    pub(crate) metrics_addr: SocketAddr,
    pub(crate) authentication: AuthenticationConfig,
    pub(crate) web: WebConfig,
    pub(crate) managed: ManagedConnectionConfig,
    pub(crate) audit: AuditConfig,
    /// Seals secret-classified configuration values before they reach
    /// `PostgreSQL`. Held as a live cipher rather than key bytes so no part of
    /// the process keeps a copy that could be printed.
    pub(crate) value_cipher: ValueCipher,
}

/// Audit trail settings. Every one is optional, because the defaults are the
/// intended configuration and a deployment that sets none of them is correct.
pub(crate) struct AuditConfig {
    /// How long an event is kept after it was last seen.
    pub(crate) retention: Duration,
    /// The window inside which repeated accesses collapse into one event.
    pub(crate) coalesce_window: Duration,
}

pub(crate) struct ManagedConnectionConfig {
    pub(crate) public_origin: String,
    pub(crate) issuer: String,
    pub(crate) client_id: String,
    pub(crate) grants_attribute: String,
    pub(crate) managed_group: String,
    pub(crate) api_origin: Url,
    pub(crate) api_token: String,
    pub(crate) timeout: Duration,
}

pub(crate) struct WebConfig {
    pub(crate) issuer: String,
    pub(crate) client_id: String,
    /// Optional directory of prebuilt installer artifacts to serve under
    /// `/dist`. Absent in local runs that ship no installers.
    pub(crate) dist_dir: Option<PathBuf>,
}

pub(crate) struct AuthenticationConfig {
    pub(crate) introspection_url: Url,
    pub(crate) accepted_identities: Vec<AcceptedIdentity>,
    pub(crate) introspection_client_id: String,
    pub(crate) introspection_client_secret: String,
    pub(crate) timeout: Duration,
}

#[derive(Clone)]
pub(crate) struct AcceptedIdentity {
    pub(crate) issuer: String,
    pub(crate) audience: String,
}

impl Config {
    pub(crate) fn from_env() -> Result<Self> {
        let database_url = required_secret("SOVEREIGN_CONFIG_DATABASE_URL")?;
        let grpc_addr = required_env("SOVEREIGN_CONFIG_GRPC_ADDR")?
            .parse()
            .context("SOVEREIGN_CONFIG_GRPC_ADDR must be a socket address")?;
        let metrics_addr = required_env("SOVEREIGN_CONFIG_METRICS_ADDR")?
            .parse()
            .context("SOVEREIGN_CONFIG_METRICS_ADDR must be a socket address")?;

        if grpc_addr == metrics_addr {
            bail!("gRPC and metrics listeners must use different addresses");
        }

        let introspection_url = required_env("SOVEREIGN_CONFIG_OIDC_INTROSPECTION_URL")?
            .parse::<Url>()
            .context("SOVEREIGN_CONFIG_OIDC_INTROSPECTION_URL must be a valid URL")?;
        validate_introspection_url(&introspection_url)?;
        let issuer = required_env("SOVEREIGN_CONFIG_OIDC_ISSUER")?;
        let issuer_url = issuer
            .parse::<Url>()
            .context("SOVEREIGN_CONFIG_OIDC_ISSUER must be a valid URL")?;
        validate_issuer_url(&issuer, &issuer_url)?;
        let audience = required_identifier("SOVEREIGN_CONFIG_OIDC_AUDIENCE")?;
        let introspection_client_id =
            required_identifier("SOVEREIGN_CONFIG_OIDC_INTROSPECTION_CLIENT_ID")?;

        let public_origin =
            validated_public_origin(&required_env("SOVEREIGN_CONFIG_PUBLIC_ORIGIN")?)?;
        let dist_dir = env::var("SOVEREIGN_CONFIG_DIST_DIR")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from);
        let grants_attribute = validated_grants_attribute(&required_env(
            "SOVEREIGN_CONFIG_MANAGER_GRANTS_ATTRIBUTE",
        )?)?;
        let managed_group = validated_group_name(&required_env("SOVEREIGN_CONFIG_MANAGER_GROUP")?)?;
        let api_origin = issuer_api_origin(&issuer_url)?;
        let api_token = required_secret("SOVEREIGN_CONFIG_MANAGER_API_TOKEN")?;
        let value_cipher = value_cipher_from_env()?;
        let audit = AuditConfig {
            retention: Duration::from_secs(
                u64::from(optional_bounded(
                    "SOVEREIGN_CONFIG_AUDIT_RETENTION_DAYS",
                    365,
                    3650,
                )?) * SECONDS_PER_DAY,
            ),
            coalesce_window: Duration::from_secs(
                u64::from(optional_bounded(
                    "SOVEREIGN_CONFIG_AUDIT_COALESCE_WINDOW_HOURS",
                    24,
                    168,
                )?) * SECONDS_PER_HOUR,
            ),
        };

        Ok(Self {
            database_url,
            grpc_addr,
            metrics_addr,
            authentication: AuthenticationConfig {
                introspection_url,
                accepted_identities: vec![AcceptedIdentity {
                    issuer: issuer.clone(),
                    audience: audience.clone(),
                }],
                introspection_client_id,
                introspection_client_secret: required_secret(
                    "SOVEREIGN_CONFIG_OIDC_INTROSPECTION_CLIENT_SECRET",
                )?,
                timeout: INTROSPECTION_TIMEOUT,
            },
            web: WebConfig {
                issuer: issuer.clone(),
                client_id: audience.clone(),
                dist_dir,
            },
            managed: ManagedConnectionConfig {
                public_origin,
                issuer,
                client_id: audience,
                grants_attribute,
                managed_group,
                api_origin,
                api_token,
                timeout: MANAGER_TIMEOUT,
            },
            audit,
            value_cipher,
        })
    }
}

/// Builds the value cipher from the operator-supplied encryption key.
///
/// The key is required unconditionally, exactly like the database URL and the
/// manager token. Making it conditional on secrets already being stored would
/// only move the failure to the first secret write, long after startup, where
/// it is far harder to diagnose and far easier to miss.
fn value_cipher_from_env() -> Result<ValueCipher> {
    const NAME: &str = "SOVEREIGN_CONFIG_VALUE_ENCRYPTION_KEY";

    let encoded = required_secret(NAME)?;
    // Only the shape of the failure is reported; the supplied value never
    // reaches the message, so a startup error is safe to log.
    let mut key = decode_key(&encoded).map_err(|error| anyhow::anyhow!("{NAME} {error}"))?;
    Ok(ValueCipher::new(&mut key))
}

/// Validates the exact canonical public origin used for generated URLs.
///
/// The origin must be HTTPS (or numeric-loopback HTTP for tests only) with no
/// userinfo, path other than `/`, query, or fragment.
fn validated_public_origin(value: &str) -> Result<String> {
    let url = value
        .parse::<Url>()
        .context("SOVEREIGN_CONFIG_PUBLIC_ORIGIN must be a valid URL")?;
    let loopback_http = url.scheme() == "http"
        && url
            .host_str()
            .and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok())
            .is_some_and(|address| address.is_loopback());
    if !(url.scheme() == "https" || loopback_http)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("SOVEREIGN_CONFIG_PUBLIC_ORIGIN is not a permitted canonical origin");
    }
    let canonical = url.origin().ascii_serialization();
    if value.trim_end_matches('/') != canonical {
        bail!("SOVEREIGN_CONFIG_PUBLIC_ORIGIN is not a permitted canonical origin");
    }
    Ok(canonical)
}

/// Validates the environment-specific user attribute holding managed grants.
fn validated_grants_attribute(value: &str) -> Result<String> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        bail!("SOVEREIGN_CONFIG_MANAGER_GRANTS_ATTRIBUTE is not a permitted attribute name");
    }
    Ok(value.to_owned())
}

/// Validates the exact name of the Authentik group managed service accounts
/// are added to for browsing. Not a security boundary, so only bounded and
/// non-empty, matching the shape of a display name rather than an identifier.
fn validated_group_name(value: &str) -> Result<String> {
    if value.is_empty()
        || value.trim() != value
        || value.chars().count() > 100
        || value.chars().any(char::is_control)
    {
        bail!("SOVEREIGN_CONFIG_MANAGER_GROUP is not a permitted group name");
    }
    Ok(value.to_owned())
}

/// An optional whole-number setting: `default` when unset or blank, otherwise
/// a value from `1` to `maximum`.
fn optional_bounded(name: &str, default: u32, maximum: u32) -> Result<u32> {
    bounded_setting(name, env::var(name).ok().as_deref(), default, maximum)
}

/// A setting that is present but unusable fails startup rather than falling
/// back: an operator who set a one-week retention and mistyped it must not
/// silently get a year, and must certainly not get zero.
fn bounded_setting(name: &str, value: Option<&str>, default: u32, maximum: u32) -> Result<u32> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(default);
    };
    match value.parse::<u32>() {
        Ok(parsed) if (1..=maximum).contains(&parsed) => Ok(parsed),
        _ => bail!("{name} must be a whole number from 1 to {maximum}"),
    }
}

/// Derives the Authentik administration origin from the configured issuer so
/// the API origin always matches the issuer origin exactly.
fn issuer_api_origin(issuer: &Url) -> Result<Url> {
    issuer
        .origin()
        .ascii_serialization()
        .parse::<Url>()
        .context("SOVEREIGN_CONFIG_OIDC_ISSUER origin is not a permitted API origin")
}

fn validate_introspection_url(url: &Url) -> Result<()> {
    if url.scheme() != "https" || url.path() != "/application/o/introspect/" {
        bail!("SOVEREIGN_CONFIG_OIDC_INTROSPECTION_URL must use HTTPS");
    }
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("SOVEREIGN_CONFIG_OIDC_INTROSPECTION_URL is not a permitted endpoint URL");
    }
    Ok(())
}

/// Rejects issuers that are valid URLs but not in the exact canonical form
/// `ConnectionUrl::managed` requires when it later reparses the same string:
/// accepting a non-canonical issuer here would only surface as a failure
/// after Authentik has already been mutated by a create or rotate.
fn validate_issuer_url(raw: &str, url: &Url) -> Result<()> {
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.path().starts_with("/application/o/")
        || !url.path().ends_with('/')
    {
        bail!("SOVEREIGN_CONFIG_OIDC_ISSUER is not a permitted issuer URL");
    }
    if url.as_str() != raw {
        bail!("SOVEREIGN_CONFIG_OIDC_ISSUER must be in canonical form (expected {url})");
    }
    Ok(())
}

fn required_identifier(name: &str) -> Result<String> {
    let value = required_env(name)?;
    if value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        bail!("required configuration {name} must not contain whitespace");
    }
    Ok(value)
}

pub(crate) fn required_env(name: &str) -> Result<String> {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        _ => bail!("required configuration {name} is missing or empty"),
    }
}

pub(crate) fn required_secret(name: &str) -> Result<String> {
    if let Ok(value) = env::var(name)
        && !value.trim().is_empty()
    {
        return Ok(value);
    }

    let file_name = format!("{name}_FILE");
    let path = required_env(&file_name)?;
    let value = fs::read_to_string(&path).with_context(|| format!("unable to read {file_name}"))?;
    if value.trim().is_empty() {
        bail!("{file_name} points to an empty secret file");
    }
    Ok(value.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::{
        bounded_setting, issuer_api_origin, required_env, validate_introspection_url,
        validate_issuer_url, validated_group_name, validated_public_origin,
    };

    #[test]
    fn required_env_rejects_missing_values() {
        assert!(required_env("SOVEREIGN_CONFIG_TEST_UNSET_6F63A8D9").is_err());
    }

    #[test]
    fn introspection_url_requires_https_without_credentials_or_query() {
        assert!(
            validate_introspection_url(
                &"https://example.test/application/o/introspect/"
                    .parse()
                    .unwrap()
            )
            .is_ok()
        );
        assert!(
            validate_introspection_url(
                &"http://example.test/application/o/introspect/"
                    .parse()
                    .unwrap()
            )
            .is_err()
        );
        assert!(
            validate_introspection_url(
                &"https://user@example.test/application/o/introspect/"
                    .parse()
                    .unwrap()
            )
            .is_err()
        );
        assert!(
            validate_introspection_url(
                &"https://example.test/application/o/introspect/?token=value"
                    .parse()
                    .unwrap()
            )
            .is_err()
        );
        assert!(
            validate_introspection_url(
                &"https://example.test/application/o/other/".parse().unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn public_origin_requires_an_exact_canonical_origin() {
        assert_eq!(
            validated_public_origin("https://config.example.test").unwrap(),
            "https://config.example.test"
        );
        assert_eq!(
            validated_public_origin("https://config.example.test/").unwrap(),
            "https://config.example.test"
        );
        assert_eq!(
            validated_public_origin("http://127.0.0.1:50051").unwrap(),
            "http://127.0.0.1:50051"
        );
        for invalid in [
            "http://config.example.test",
            "https://config.example.test/path",
            "https://config.example.test?query=1",
            "https://config.example.test#fragment",
            "https://user@config.example.test",
            "https://CONFIG.example.test",
            "https://config.example.test:443",
            "not-a-url",
        ] {
            assert!(validated_public_origin(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn api_origin_is_derived_from_the_issuer_origin() {
        let issuer = "https://auth.example.test/application/o/sovereign-config/"
            .parse()
            .unwrap();
        assert_eq!(
            issuer_api_origin(&issuer).unwrap().as_str(),
            "https://auth.example.test/"
        );
    }

    const SETTING: &str = "SOVEREIGN_CONFIG_AUDIT_RETENTION_DAYS";

    #[test]
    fn an_absent_or_blank_bounded_setting_takes_its_default() {
        for absent in [None, Some(""), Some("   "), Some("\t\n")] {
            assert_eq!(
                bounded_setting(SETTING, absent, 365, 3650).unwrap(),
                365,
                "{absent:?}"
            );
        }
    }

    #[test]
    fn a_bounded_setting_accepts_every_whole_number_in_range() {
        assert_eq!(bounded_setting(SETTING, Some("1"), 365, 3650).unwrap(), 1);
        assert_eq!(
            bounded_setting(SETTING, Some("3650"), 365, 3650).unwrap(),
            3650
        );
        assert_eq!(
            bounded_setting(SETTING, Some(" 30 "), 365, 3650).unwrap(),
            30
        );
    }

    /// The promise the README makes: a value that is set but unusable fails
    /// startup rather than falling back. Zero matters most — a retention of
    /// zero days would have the hourly sweep delete the entire trail.
    #[test]
    fn a_set_but_unusable_bounded_setting_fails_rather_than_falling_back() {
        for unusable in [
            "0",
            "3651",
            "-1",
            "7d",
            "1.5",
            "365 days",
            "4294967296",
            "one",
        ] {
            let error = bounded_setting(SETTING, Some(unusable), 365, 3650)
                .expect_err(unusable)
                .to_string();
            // Names the variable, so the operator knows which one to fix.
            assert!(error.contains(SETTING), "{unusable:?}: {error}");
            assert!(error.contains("1 to 3650"), "{unusable:?}: {error}");
        }
    }

    #[test]
    fn group_name_is_bounded_and_trimmed() {
        assert_eq!(
            validated_group_name("Sovereign Config Connections").unwrap(),
            "Sovereign Config Connections"
        );
        for invalid in ["", " padded", "padded ", &"x".repeat(101), "line\nbreak"] {
            assert!(validated_group_name(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn issuer_requires_an_https_per_provider_url() {
        let canonical = "https://example.test/application/o/sovereign-config/";
        assert!(validate_issuer_url(canonical, &canonical.parse().unwrap()).is_ok());
        let no_provider_path = "https://example.test/";
        assert!(validate_issuer_url(no_provider_path, &no_provider_path.parse().unwrap()).is_err());
        let insecure = "http://example.test/application/o/sovereign-config/";
        assert!(validate_issuer_url(insecure, &insecure.parse().unwrap()).is_err());
    }

    /// Regression: a valid-but-non-canonical issuer must be rejected at
    /// startup rather than accepted and later fail managed URL generation
    /// after Authentik has already been mutated by a create or rotate.
    #[test]
    fn issuer_must_already_be_in_canonical_form() {
        let raw = "HTTPS://Example.test:443/application/o/sovereign-config/";
        let url: reqwest::Url = raw.parse().unwrap();
        assert_ne!(
            url.as_str(),
            raw,
            "the test issuer must actually be non-canonical"
        );
        assert!(validate_issuer_url(raw, &url).is_err());
    }
}
