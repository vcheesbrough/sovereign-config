use std::{env, fs, net::SocketAddr, time::Duration};

use anyhow::{Context, Result, bail};
use reqwest::Url;

const INTROSPECTION_TIMEOUT: Duration = Duration::from_secs(3);

pub(crate) struct Config {
    pub(crate) database_url: String,
    pub(crate) grpc_addr: SocketAddr,
    pub(crate) metrics_addr: SocketAddr,
    pub(crate) authentication: AuthenticationConfig,
    pub(crate) web: WebConfig,
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
                issuer,
                client_id: audience,
            },
        })
    }
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
    use super::{required_env, validate_introspection_url, validate_issuer_url};

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
