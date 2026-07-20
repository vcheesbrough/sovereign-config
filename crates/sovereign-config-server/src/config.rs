use std::{env, fs, io::Read, net::IpAddr, net::SocketAddr, time::Duration};

use anyhow::{Context, Result, bail};
use reqwest::Url;

const INTROSPECTION_TIMEOUT: Duration = Duration::from_secs(3);
const MANAGER_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_MANAGER_SECRET_BYTES: u64 = 16 * 1024;

pub(crate) struct Config {
    pub(crate) database_url: String,
    pub(crate) grpc_addr: SocketAddr,
    pub(crate) metrics_addr: SocketAddr,
    pub(crate) authentication: AuthenticationConfig,
    pub(crate) web: WebConfig,
    pub(crate) managed: ManagedConnectionConfig,
}

pub(crate) struct ManagedConnectionConfig {
    pub(crate) public_origin: String,
    pub(crate) issuer: String,
    pub(crate) client_id: String,
    pub(crate) grants_attribute: String,
    pub(crate) api_origin: Url,
    pub(crate) api_token: String,
    pub(crate) timeout: Duration,
}

pub(crate) struct WebConfig {
    pub(crate) issuer: String,
    pub(crate) client_id: String,
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
        validate_issuer_url(&issuer_url)?;
        let audience = required_identifier("SOVEREIGN_CONFIG_OIDC_AUDIENCE")?;
        let introspection_client_id =
            required_identifier("SOVEREIGN_CONFIG_OIDC_INTROSPECTION_CLIENT_ID")?;

        let public_origin =
            validated_public_origin(&required_env("SOVEREIGN_CONFIG_PUBLIC_ORIGIN")?)?;
        let grants_attribute = validated_grants_attribute(&required_env(
            "SOVEREIGN_CONFIG_MANAGER_GRANTS_ATTRIBUTE",
        )?)?;
        let api_origin = issuer_api_origin(&issuer_url)?;
        let api_token = required_manager_secret_file("SOVEREIGN_CONFIG_MANAGER_API_TOKEN_FILE")?;

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
            },
            managed: ManagedConnectionConfig {
                public_origin,
                issuer,
                client_id: audience,
                grants_attribute,
                api_origin,
                api_token,
                timeout: MANAGER_TIMEOUT,
            },
        })
    }
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

/// Derives the Authentik administration origin from the configured issuer so
/// the API origin always matches the issuer origin exactly.
fn issuer_api_origin(issuer: &Url) -> Result<Url> {
    issuer
        .origin()
        .ascii_serialization()
        .parse::<Url>()
        .context("SOVEREIGN_CONFIG_OIDC_ISSUER origin is not a permitted API origin")
}

/// Reads the manager API token from a protected regular file only.
///
/// The file must not be a symlink, must be owned by the server user, must have
/// mode `0400`, and must hold one bounded non-empty line. All failures are
/// reported without echoing any configured value.
fn required_manager_secret_file(name: &str) -> Result<String> {
    let path = required_env(name)?;
    protected_secret_file(name, path.as_ref())
}

fn protected_secret_file(name: &str, path: &std::path::Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("unable to read {name}"))?;
    if !metadata.file_type().is_file() {
        bail!("{name} must reference a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != rustix::process::geteuid().as_raw() {
            bail!("{name} must reference a file owned by the server user");
        }
        if metadata.permissions().mode() & 0o777 != 0o400 {
            bail!("{name} must reference a file with mode 0400");
        }
    }
    if metadata.len() > MAX_MANAGER_SECRET_BYTES {
        bail!("{name} references an oversized secret file");
    }
    let mut value = String::new();
    fs::File::open(path)
        .and_then(|file| {
            let mut reader = file.take(MAX_MANAGER_SECRET_BYTES);
            reader.read_to_string(&mut value).map(|_| ())
        })
        .with_context(|| format!("unable to read {name}"))?;
    let value = value.trim();
    if value.is_empty() {
        bail!("{name} points to an empty secret file");
    }
    if value.lines().count() != 1 || value.bytes().any(|byte| byte.is_ascii_control()) {
        bail!("{name} must hold a single-line secret");
    }
    Ok(value.to_owned())
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

fn validate_issuer_url(url: &Url) -> Result<()> {
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
        issuer_api_origin, protected_secret_file, required_env, validate_introspection_url,
        validate_issuer_url, validated_public_origin,
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

    #[test]
    fn manager_secret_files_must_be_protected_regular_files() {
        use std::os::unix::fs::PermissionsExt;

        let name = "SOVEREIGN_CONFIG_TEST_MANAGER_SECRET_FILE";
        let directory = tempfile::tempdir().unwrap();

        let missing = directory.path().join("missing");
        assert!(protected_secret_file(name, &missing).is_err());

        let secret_path = directory.path().join("manager-api-token");
        std::fs::write(&secret_path, "manager-api-token-sentinel\n").unwrap();
        std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            protected_secret_file(name, &secret_path).is_err(),
            "wrong mode"
        );

        std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(
            protected_secret_file(name, &secret_path).unwrap(),
            "manager-api-token-sentinel"
        );

        let symlink_path = directory.path().join("symlinked");
        std::os::unix::fs::symlink(&secret_path, &symlink_path).unwrap();
        assert!(
            protected_secret_file(name, &symlink_path).is_err(),
            "symlink"
        );

        let empty_path = directory.path().join("empty");
        std::fs::write(&empty_path, "  \n").unwrap();
        std::fs::set_permissions(&empty_path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(protected_secret_file(name, &empty_path).is_err(), "empty");

        let multiline_path = directory.path().join("multiline");
        std::fs::write(&multiline_path, "first\nsecond\n").unwrap();
        std::fs::set_permissions(&multiline_path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(
            protected_secret_file(name, &multiline_path).is_err(),
            "multiline"
        );

        let failure = format!(
            "{:#}",
            protected_secret_file(name, &secret_path.join("missing")).unwrap_err()
        );
        assert!(!failure.contains("manager-api-token-sentinel"));
    }

    #[test]
    fn issuer_requires_an_https_per_provider_url() {
        assert!(
            validate_issuer_url(
                &"https://example.test/application/o/sovereign-config/"
                    .parse()
                    .unwrap()
            )
            .is_ok()
        );
        assert!(validate_issuer_url(&"https://example.test/".parse().unwrap()).is_err());
        assert!(
            validate_issuer_url(
                &"http://example.test/application/o/sovereign-config/"
                    .parse()
                    .unwrap()
            )
            .is_err()
        );
    }
}
