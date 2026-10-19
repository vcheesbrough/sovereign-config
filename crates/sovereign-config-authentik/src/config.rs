//! What the Authentik implementation needs, validated once at startup. The
//! server parses the `SOVEREIGN_CONFIG_MANAGER_*` variables into it; error
//! messages name those variables and never quote a value.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::Url;
use sovereign_config_core::Secret;

pub struct AuthentikConfig {
    pub(crate) api_origin: Url,
    pub(crate) api_token: Secret,
    /// The OAuth client every managed account authenticates through: Authentik
    /// accepts an app password as `client_secret` for the server's own client.
    pub(crate) client_id: String,
    pub(crate) grants_attribute: String,
    pub(crate) managed_group: String,
    pub(crate) timeout: Duration,
}

impl AuthentikConfig {
    /// `issuer` is the OIDC issuer the server already validated; the
    /// administration API is served from its exact origin. `client_id` is the
    /// server's own OAuth client, which managed accounts authenticate through.
    ///
    /// # Errors
    ///
    /// The client id, grants attribute or group name is not permitted, or the
    /// issuer has no usable origin. The message names the setting, never its
    /// value.
    pub fn new(
        issuer: &Url,
        api_token: Secret,
        client_id: &str,
        grants_attribute: &str,
        managed_group: &str,
        timeout: Duration,
    ) -> Result<Self> {
        Ok(Self {
            api_origin: issuer_api_origin(issuer)?,
            api_token,
            client_id: validated_client_id(client_id)?,
            grants_attribute: validated_grants_attribute(grants_attribute)?,
            managed_group: validated_group_name(managed_group)?,
            timeout,
        })
    }

    /// How long one administration call may take.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

/// Validates the client id a connection URL carries, by the grammar the URL
/// itself admits.
fn validated_client_id(value: &str) -> Result<String> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
    {
        bail!("SOVEREIGN_CONFIG_OIDC_AUDIENCE is not a permitted client id");
    }
    Ok(value.to_owned())
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

/// Derives the Authentik administration origin from the configured issuer so
/// the API origin always matches the issuer origin exactly.
fn issuer_api_origin(issuer: &Url) -> Result<Url> {
    issuer
        .origin()
        .ascii_serialization()
        .parse::<Url>()
        .context("SOVEREIGN_CONFIG_OIDC_ISSUER origin is not a permitted API origin")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER: &str = "https://auth.example.test/application/o/sovereign-config/";
    const TOKEN_SENTINEL: &str = "manager-api-token-sentinel";

    fn config(grants_attribute: &str, group: &str) -> Result<AuthentikConfig> {
        AuthentikConfig::new(
            &ISSUER.parse().unwrap(),
            Secret::new(TOKEN_SENTINEL),
            "sovereign-config",
            grants_attribute,
            group,
            Duration::from_secs(5),
        )
    }

    #[test]
    fn api_origin_is_derived_from_the_issuer_origin() {
        let issuer = ISSUER.parse().unwrap();
        assert_eq!(
            issuer_api_origin(&issuer).unwrap().as_str(),
            "https://auth.example.test/"
        );
        assert_eq!(
            config("sovereign_config_grants", "Connections")
                .unwrap()
                .api_origin
                .as_str(),
            "https://auth.example.test/"
        );
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
    fn client_id_is_what_a_connection_url_admits() {
        assert_eq!(
            validated_client_id("sovereign-config_2.x~").unwrap(),
            "sovereign-config_2.x~"
        );
        for invalid in ["", "with space", "slash/ed", "q?uery"] {
            assert!(validated_client_id(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn grants_attribute_is_a_bounded_lowercase_identifier() {
        assert!(validated_grants_attribute("sovereign_config_grants_2").is_ok());
        for invalid in ["", "Upper", "with-hyphen", "dotted.name", &"x".repeat(65)] {
            assert!(validated_grants_attribute(invalid).is_err(), "{invalid:?}");
        }
    }

    /// An invalid setting fails by naming the variable, and neither the value
    /// nor the token ever reaches the message.
    #[test]
    fn errors_name_the_setting_and_quote_nothing() {
        for (attribute, group) in [
            ("bad-attribute-sentinel", "Connections"),
            ("sovereign_config_grants", " bad-group-sentinel"),
        ] {
            let message = format!("{:#}", config(attribute, group).err().unwrap());
            assert!(message.contains("SOVEREIGN_CONFIG_MANAGER_"), "{message}");
            assert!(!message.contains("sentinel"), "{message}");
        }
    }
}
