//! Authentik's variables, and Authentik as the server takes it: parsed and
//! validated here, so the server names none of them.
//!
//! - `SOVEREIGN_CONFIG_OIDC_ISSUER` — the application's per-provider issuer,
//!   `https://<authentik>/application/o/<slug>/`.
//! - `SOVEREIGN_CONFIG_OIDC_AUDIENCE` — the application's client id, which is
//!   also the audience of its tokens.
//! - `SOVEREIGN_CONFIG_MANAGER_API_TOKEN` (or `…_FILE`),
//!   `SOVEREIGN_CONFIG_MANAGER_GRANTS_ATTRIBUTE`,
//!   `SOVEREIGN_CONFIG_MANAGER_GROUP` — the connection manager.
//! - `SOVEREIGN_CONFIG_MANAGER_CLIENT_ID` — optional, and only ever the
//!   audience.
//!
//! No error message quotes a value.

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use reqwest::Url;
use sovereign_config_core::Secret;
use sovereign_config_identity::{
    ClientCredential, GrantsEncoding, IdentityProvider, LoginDescription, Variables,
    VerificationRules,
};

use crate::{AuthentikConfig, AuthentikProvider};

/// The name Authentik is selected by.
pub const NAME: &str = "authentik";

const ISSUER: &str = "SOVEREIGN_CONFIG_OIDC_ISSUER";
const AUDIENCE: &str = "SOVEREIGN_CONFIG_OIDC_AUDIENCE";
/// Optional: the OAuth client access URLs name, when it is not the audience.
const MANAGER_CLIENT_ID: &str = "SOVEREIGN_CONFIG_MANAGER_CLIENT_ID";
const MANAGER_TIMEOUT: Duration = Duration::from_secs(5);

/// The claim each environment's grants mapping signs the grants into.
const GRANTS_CLAIM: &str = "sovereign_config_grants";

/// How an Authentik application's access tokens are verified and read.
///
/// The key set is at `<issuer>jwks/`, the `jwks_uri` Authentik's discovery
/// document names for a per-provider issuer. The grants mapping in the
/// blueprint signs the grants as an array and the display name as
/// `preferred_username`; `username` is what older tokens of a service
/// account carried.
///
/// **The required scope claim is also what refuses an ID token.** Authentik
/// signs its ID tokens with the same key, issuer and audience as its access
/// tokens, and the grants mapping writes into both; it adds `scope` only when
/// it turns those claims into an access token. `nonce` and `at_hash` do not
/// tell the two apart — an Authentik access token copies them from its ID
/// token.
#[must_use]
pub fn verification_rules(issuer: &str, audience: &str) -> VerificationRules {
    VerificationRules {
        issuer: issuer.to_owned(),
        jwks_uri: format!("{issuer}jwks/"),
        audience: audience.to_owned(),
        scope_claim: "scope".to_owned(),
        grants_claim: GRANTS_CLAIM.to_owned(),
        grants_encoding: GrantsEncoding::Array,
        name_claims: vec!["preferred_username".to_owned(), "username".to_owned()],
    }
}

/// Authentik as the server's identity provider, from its variables.
///
/// # Errors
///
/// A variable is missing or not permitted. The message names the variable to
/// change and quotes no value.
pub fn from_variables(variables: &dyn Variables) -> Result<IdentityProvider> {
    let issuer = variables.required(ISSUER)?;
    let issuer_url = issuer
        .parse::<Url>()
        .with_context(|| format!("{ISSUER} must be a valid URL"))?;
    validate_issuer_url(&issuer, &issuer_url)?;
    let audience = required_identifier(variables, AUDIENCE)?;
    let client_id = manager_client_id(variables.get(MANAGER_CLIENT_ID).as_deref(), &audience)?;
    let config = AuthentikConfig::new(
        &issuer_url,
        Secret::new(variables.secret("SOVEREIGN_CONFIG_MANAGER_API_TOKEN")?),
        &client_id,
        &audience,
        &variables.required("SOVEREIGN_CONFIG_MANAGER_GRANTS_ATTRIBUTE")?,
        &variables.required("SOVEREIGN_CONFIG_MANAGER_GROUP")?,
        MANAGER_TIMEOUT,
    )?;
    let call_timeout = config.timeout();
    Ok(IdentityProvider {
        name: NAME,
        accounts: Arc::new(AuthentikProvider::new(config)?),
        verification: verification_rules(&issuer, &audience),
        // An Authentik application is one OAuth client: the web UI signs in
        // through the client whose id is the tokens' audience.
        login: LoginDescription {
            issuer,
            web_client_id: audience,
        },
        call_timeout,
    })
}

/// The OAuth client every access URL names, which managed accounts
/// authenticate through: `SOVEREIGN_CONFIG_MANAGER_CLIENT_ID` when set, else
/// the token audience. With Authentik the two must be equal — a token minted
/// through any other client carries that client's id as its `aud` and would
/// be refused — and the audience is then also what a connection URL must be
/// able to carry. Every refusal names the variable to change, never a value.
/// [`AuthentikConfig::new`] checks the same rule again; this is the check
/// that can name the variables.
fn manager_client_id(explicit: Option<&str>, audience: &str) -> Result<String> {
    if let Some(client_id) = explicit.map(str::trim).filter(|value| !value.is_empty()) {
        if !ClientCredential::admits_client_id(client_id) {
            bail!("{MANAGER_CLIENT_ID} is not a client id a connection URL can carry");
        }
        if client_id != audience {
            bail!(
                "{MANAGER_CLIENT_ID} must equal {AUDIENCE} with Authentik, \
                 whose tokens carry the client id they were minted through as their audience; \
                 leave it unset"
            );
        }
    }
    if !ClientCredential::admits_client_id(audience) {
        bail!(
            "{AUDIENCE} is not a client id a connection URL can carry; \
             with Authentik it is also the client id access URLs name, so it must be the \
             application's client id"
        );
    }
    Ok(audience.to_owned())
}

/// Rejects issuers that are valid URLs but not an Authentik per-provider
/// issuer in the exact canonical form a connection URL requires when it later
/// reparses the same string: accepting a non-canonical issuer here would only
/// surface as a failure after Authentik has already been mutated by a create
/// or rotate.
pub(crate) fn validate_issuer_url(raw: &str, url: &Url) -> Result<()> {
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.path().starts_with("/application/o/")
        || !url.path().ends_with('/')
    {
        bail!("{ISSUER} is not a permitted issuer URL");
    }
    if url.as_str() != raw {
        bail!("{ISSUER} must be in canonical form (expected {url})");
    }
    Ok(())
}

fn required_identifier(variables: &dyn Variables, name: &str) -> Result<String> {
    let value = variables.required(name)?;
    if value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        bail!("required configuration {name} must not contain whitespace");
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    const CANONICAL: &str = "https://example.test/application/o/sovereign-config/";

    fn variables() -> BTreeMap<&'static str, String> {
        BTreeMap::from([
            (ISSUER, CANONICAL.to_owned()),
            (AUDIENCE, "sovereign-config".to_owned()),
            (
                "SOVEREIGN_CONFIG_MANAGER_API_TOKEN",
                "manager-token-sentinel".to_owned(),
            ),
            (
                "SOVEREIGN_CONFIG_MANAGER_GRANTS_ATTRIBUTE",
                "sovereign_config_test_grants".to_owned(),
            ),
            (
                "SOVEREIGN_CONFIG_MANAGER_GROUP",
                "sovereign-config-test-connections".to_owned(),
            ),
        ])
    }

    /// What the server took from these variables before the provider owned
    /// them: the issuer for clients and for tokens, the audience as the web
    /// client, the key set under the issuer, and Authentik's claims.
    #[test]
    fn the_variables_describe_an_authentik_application() {
        let provider = from_variables(&variables()).unwrap();
        assert_eq!(provider.name, "authentik");
        assert_eq!(
            provider.login,
            LoginDescription {
                issuer: CANONICAL.to_owned(),
                web_client_id: "sovereign-config".to_owned(),
            }
        );
        assert_eq!(
            provider.verification,
            VerificationRules {
                issuer: CANONICAL.to_owned(),
                jwks_uri: format!("{CANONICAL}jwks/"),
                audience: "sovereign-config".to_owned(),
                scope_claim: "scope".to_owned(),
                grants_claim: "sovereign_config_grants".to_owned(),
                grants_encoding: GrantsEncoding::Array,
                name_claims: vec!["preferred_username".to_owned(), "username".to_owned()],
            }
        );
        assert_eq!(provider.verification.validate(), Ok(()));
        assert_eq!(provider.call_timeout, Duration::from_secs(5));
    }

    /// Each required variable, missing, fails by name; nothing set is quoted.
    #[test]
    fn a_missing_variable_fails_by_name_and_quotes_nothing() {
        for missing in [
            ISSUER,
            AUDIENCE,
            "SOVEREIGN_CONFIG_MANAGER_GRANTS_ATTRIBUTE",
            "SOVEREIGN_CONFIG_MANAGER_GROUP",
        ] {
            let mut variables = variables();
            variables.remove(missing);
            let message = format!("{:#}", from_variables(&variables).err().unwrap());
            assert!(message.contains(missing), "{missing}: {message}");
            assert!(!message.contains("sentinel"), "{message}");
        }
        let mut variables = variables();
        variables.remove("SOVEREIGN_CONFIG_MANAGER_API_TOKEN");
        let message = format!("{:#}", from_variables(&variables).err().unwrap());
        assert!(
            message.contains("SOVEREIGN_CONFIG_MANAGER_API_TOKEN_FILE"),
            "{message}"
        );
    }

    #[test]
    fn the_audience_holds_no_whitespace() {
        let mut variables = variables();
        variables.insert(AUDIENCE, "sovereign config".to_owned());
        let message = format!("{:#}", from_variables(&variables).err().unwrap());
        assert_eq!(
            message,
            "required configuration SOVEREIGN_CONFIG_OIDC_AUDIENCE must not contain whitespace"
        );
    }

    #[test]
    fn the_access_url_client_id_defaults_to_the_audience() {
        assert_eq!(
            manager_client_id(None, "sovereign-config").unwrap(),
            "sovereign-config"
        );
        for blank in ["", "   "] {
            assert_eq!(
                manager_client_id(Some(blank), "sovereign-config").unwrap(),
                "sovereign-config"
            );
        }
    }

    /// With Authentik the client id is the audience: setting it to anything
    /// else, or to a value of the wrong form, is refused, as is an audience a
    /// URL can't carry. Each refusal names the variable to change and quotes
    /// no value.
    #[test]
    fn the_access_url_client_id_is_checked_and_names_its_variable() {
        assert_eq!(
            manager_client_id(Some("sovereign-config"), "sovereign-config").unwrap(),
            "sovereign-config"
        );

        let mismatch = format!(
            "{:#}",
            manager_client_id(Some("other-sentinel"), "audience-sentinel").unwrap_err()
        );
        assert!(
            mismatch.starts_with(
                "SOVEREIGN_CONFIG_MANAGER_CLIENT_ID must equal SOVEREIGN_CONFIG_OIDC_AUDIENCE"
            ),
            "{mismatch}"
        );

        let malformed = format!(
            "{:#}",
            manager_client_id(Some("bad sentinel/id"), "sovereign-config").unwrap_err()
        );
        assert!(
            malformed.starts_with("SOVEREIGN_CONFIG_MANAGER_CLIENT_ID is not"),
            "{malformed}"
        );

        let audience = format!(
            "{:#}",
            manager_client_id(None, "urn:sentinel:audience").unwrap_err()
        );
        assert!(
            audience.starts_with("SOVEREIGN_CONFIG_OIDC_AUDIENCE is not"),
            "{audience}"
        );
        assert!(
            !audience.contains("set SOVEREIGN_CONFIG_MANAGER_CLIENT_ID"),
            "{audience}"
        );

        for message in [mismatch, malformed, audience] {
            assert!(!message.contains("sentinel"), "{message}");
        }
    }

    #[test]
    fn issuer_requires_an_https_per_provider_url() {
        assert!(validate_issuer_url(CANONICAL, &CANONICAL.parse().unwrap()).is_ok());
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
