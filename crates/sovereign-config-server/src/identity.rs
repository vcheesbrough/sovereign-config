//! Provider selection: the one place in the server that names an identity
//! provider's implementation.
//!
//! `SOVEREIGN_CONFIG_IDENTITY_PROVIDER` chooses the provider at launch, and
//! [`from_variables`] hands the choice its variables to parse and validate.
//! What comes back — managed accounts, verification rules, the login
//! description — is all the rest of the server sees, so a provider is added
//! here and in its own crate, and nowhere else
//! (`tests/lint_ratchet.rs` holds the rest of the source to that).
//!
//! A deployment has one provider for life: the accounts and subjects the
//! database records belong to the provider that issued them. So the first
//! start records its name ([`claim_deployment`]), and a start under another
//! name fails rather than orphan them.

use anyhow::{Context, Result, bail};
use reqwest::Url;
use sovereign_config_core::{ConfigPath, ConnectionUrl, Secret};
use sovereign_config_identity::{ClientCredential, IdentityProvider, Variables};
use sqlx::PgPool;
use tracing::{field::Empty, instrument};

use crate::spans;

const IDENTITY_PROVIDER: &str = "SOVEREIGN_CONFIG_IDENTITY_PROVIDER";

/// Every identity provider this server was built with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Authentik,
}

impl Kind {
    const ALL: [Self; 1] = [Self::Authentik];
    /// What a deployment that names none gets: the only provider there was
    /// before one could be named.
    const DEFAULT: Self = Self::Authentik;

    const fn name(self) -> &'static str {
        match self {
            Self::Authentik => sovereign_config_authentik::NAME,
        }
    }

    /// The provider `value` names, exactly; unset or blank is the default.
    /// The refusal lists the names there are and never quotes the value.
    fn named(value: Option<&str>) -> Result<Self> {
        let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
            return Ok(Self::DEFAULT);
        };
        match Self::ALL.into_iter().find(|kind| kind.name() == value) {
            Some(kind) => Ok(kind),
            None => bail!(
                "{IDENTITY_PROVIDER} names no identity provider this server has; it has: {}",
                Self::ALL.map(Self::name).join(", ")
            ),
        }
    }

    fn build(self, variables: &dyn Variables) -> Result<IdentityProvider> {
        match self {
            Self::Authentik => sovereign_config_authentik::from_variables(variables),
        }
    }
}

/// The identity provider the deployment's variables select, built from them.
///
/// # Errors
///
/// The selection names no provider, the provider refuses its variables, or
/// what it describes is something no client could use.
pub(crate) fn from_variables(variables: &dyn Variables) -> Result<IdentityProvider> {
    let kind = Kind::named(variables.get(IDENTITY_PROVIDER).as_deref())?;
    let provider = kind.build(variables)?;
    debug_assert_eq!(provider.name, kind.name());
    admit(&provider).with_context(|| {
        format!(
            "the {} identity provider's configuration is not usable",
            kind.name()
        )
    })?;
    Ok(provider)
}

/// Holds whatever a provider described to what every provider's description
/// must meet, so a provider that validates less than it should still cannot
/// start a server whose access URLs no client accepts.
fn admit(provider: &IdentityProvider) -> Result<()> {
    provider.verification.validate()?;
    // Whoever can answer the key fetch can mint accepted tokens, so the
    // signing keys are only ever read over TLS.
    if !provider
        .verification
        .jwks_uri
        .parse::<Url>()
        .is_ok_and(|url| url.scheme() == "https")
    {
        bail!("the signing-key location must be an https URL");
    }
    if !ClientCredential::admits_client_id(&provider.login.web_client_id) {
        bail!("the web client id is not one a connection URL can carry");
    }
    let issuer = &provider.login.issuer;
    let https = issuer
        .parse::<Url>()
        .is_ok_and(|url| url.scheme() == "https");
    // The connection URL is the authority on what issuer a client accepts:
    // canonical, ending with `/`, without credentials, query or fragment.
    let carried = ConnectionUrl::managed(
        "https://config.example.test",
        &ConfigPath::parse("/").context("the root is a path")?,
        issuer,
        &provider.login.web_client_id,
        "probe",
        &Secret::new("probe"),
    );
    if !https || carried.is_err() {
        bail!(
            "the issuer handed to clients must be a canonical https URL ending with `/`, \
             which is where they look for OIDC discovery"
        );
    }
    Ok(())
}

/// Records `provider` as this deployment's identity provider at its first
/// start, and refuses a start under any other afterwards.
///
/// # Errors
///
/// The database cannot be reached, or it records another provider. Changing
/// provider is a migration of the accounts and subjects the database holds,
/// not a setting.
#[instrument(
    name = "claim_deployment identity_provider",
    skip_all,
    fields(otel.kind = "client", otel.status_code = Empty, error.type = Empty, db.system.name = "postgresql", db.operation.name = "claim_deployment", db.collection.name = "identity_provider")
)]
pub(crate) async fn claim_deployment(database: &PgPool, provider: &'static str) -> Result<()> {
    let unavailable = |_| {
        spans::record_error("unavailable");
        anyhow::anyhow!("unable to read the deployment's identity provider")
    };
    // The table holds at most one row, so the first start's insert is the
    // only one that ever lands.
    sqlx::query("INSERT INTO identity_provider (name) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(provider)
        .execute(database)
        .await
        .map_err(unavailable)?;
    let recorded: String = sqlx::query_scalar("SELECT name FROM identity_provider")
        .fetch_one(database)
        .await
        .map_err(unavailable)?;
    if recorded != provider {
        spans::record_error("provider_mismatch");
        // Both names are from compiled-in sets: the recorded one was written
        // by this function, from the same kind of value.
        bail!(
            "this deployment's accounts belong to the {recorded} identity provider, and \
             {IDENTITY_PROVIDER} selects {provider}; changing provider is a migration, not a \
             setting (docs/authentication.md)"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use sovereign_config_identity::{LoginDescription, fake::FakeIdentityProvider};

    use super::*;

    fn authentik_variables() -> BTreeMap<&'static str, String> {
        BTreeMap::from([
            (
                "SOVEREIGN_CONFIG_OIDC_ISSUER",
                "https://auth.example.test/application/o/sovereign-config/".to_owned(),
            ),
            (
                "SOVEREIGN_CONFIG_OIDC_AUDIENCE",
                "sovereign-config".to_owned(),
            ),
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

    /// An existing deployment sets no selection and keeps the provider it
    /// had; naming it says the same thing.
    #[test]
    fn unset_or_blank_selects_authentik_and_so_does_its_name() {
        for selection in [
            None,
            Some(""),
            Some("  "),
            Some("authentik"),
            Some(" authentik "),
        ] {
            let mut variables = authentik_variables();
            if let Some(selection) = selection {
                variables.insert(IDENTITY_PROVIDER, selection.to_owned());
            }
            let provider = from_variables(&variables)
                .unwrap_or_else(|error| panic!("{selection:?}: {error:#}"));
            assert_eq!(provider.name, "authentik", "{selection:?}");
        }
    }

    /// A name the server does not have fails startup, saying which variable
    /// and which names there are, and never repeating what was set. Matching
    /// is exact: a near miss is not guessed at.
    #[test]
    fn an_unknown_provider_fails_and_lists_the_ones_there_are() {
        for unknown in ["keycloak-sentinel", "Authentik", "authentik,keycloak"] {
            let mut variables = authentik_variables();
            variables.insert(IDENTITY_PROVIDER, unknown.to_owned());
            let message = format!("{:#}", from_variables(&variables).err().unwrap());
            assert_eq!(
                message,
                "SOVEREIGN_CONFIG_IDENTITY_PROVIDER names no identity provider this server \
                 has; it has: authentik",
                "{unknown}"
            );
        }
    }

    /// The chosen provider's missing settings fail startup by naming them.
    #[test]
    fn the_chosen_providers_missing_settings_fail_by_name() {
        let mut variables = authentik_variables();
        variables.remove("SOVEREIGN_CONFIG_MANAGER_GROUP");
        let message = format!("{:#}", from_variables(&variables).err().unwrap());
        assert_eq!(
            message,
            "required configuration SOVEREIGN_CONFIG_MANAGER_GROUP is missing or empty"
        );
    }

    #[test]
    fn every_provider_has_its_own_name() {
        let mut names = Kind::ALL.map(Kind::name).to_vec();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), Kind::ALL.len());
        assert_eq!(Kind::DEFAULT.name(), "authentik");
    }

    fn described(issuer: &str, web_client_id: &str) -> IdentityProvider {
        IdentityProvider {
            name: "test",
            accounts: std::sync::Arc::new(FakeIdentityProvider::new()),
            verification: sovereign_config_authentik::verification_rules(issuer, "audience"),
            login: LoginDescription {
                issuer: issuer.to_owned(),
                web_client_id: web_client_id.to_owned(),
            },
            call_timeout: std::time::Duration::from_secs(1),
        }
    }

    /// Whatever a provider validates itself, the server refuses a login
    /// description a deployed client could not use: clients reject an issuer
    /// that does not end with `/`, and find discovery by appending to it.
    #[test]
    fn a_description_no_client_could_use_is_refused_whoever_wrote_it() {
        assert!(admit(&described("https://idp.example.test/realms/config/", "web")).is_ok());
        for (issuer, client_id) in [
            ("https://idp.example.test/realms/config", "web"),
            ("http://idp.example.test/realms/config/", "web"),
            ("http://127.0.0.1:8080/realms/config/", "web"),
            ("https://IDP.example.test/realms/config/", "web"),
            ("https://user@idp.example.test/realms/config/", "web"),
            ("https://idp.example.test/realms/config/?a=b", "web"),
            ("not a url", "web"),
            ("https://idp.example.test/realms/config/", "web client"),
            ("https://idp.example.test/realms/config/", ""),
        ] {
            assert!(
                admit(&described(issuer, client_id)).is_err(),
                "{issuer} {client_id:?}"
            );
        }
        let mut incomplete = described("https://idp.example.test/realms/config/", "web");
        incomplete.verification.grants_claim.clear();
        assert!(admit(&incomplete).is_err());

        // The issuer is fine; the keys would be fetched in the clear.
        for jwks_uri in [
            "http://idp.example.test/realms/config/keys",
            "http://127.0.0.1:8080/realms/config/keys",
            "not a url",
        ] {
            let mut plaintext_keys = described("https://idp.example.test/realms/config/", "web");
            plaintext_keys.verification.jwks_uri = jwks_uri.to_owned();
            let message = format!("{:#}", admit(&plaintext_keys).unwrap_err());
            assert_eq!(
                message, "the signing-key location must be an https URL",
                "{jwks_uri}"
            );
        }
    }

    /// The first start records the provider; the same provider starts again
    /// any number of times; another is refused, by both names, and changes
    /// nothing.
    #[tokio::test]
    #[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
    async fn a_deployment_keeps_the_provider_its_first_start_recorded() {
        let Ok(database_url) = std::env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL") else {
            return;
        };
        let database = PgPool::connect(&database_url)
            .await
            .expect("test database must be reachable");
        sqlx::migrate!("./migrations")
            .run(&database)
            .await
            .expect("migrations must apply");
        let clear = || async {
            sqlx::query("DELETE FROM identity_provider")
                .execute(&database)
                .await
                .expect("the provider record must be clearable");
        };
        let recorded = || async {
            sqlx::query_scalar::<_, String>("SELECT name FROM identity_provider")
                .fetch_all(&database)
                .await
                .expect("the provider record must be readable")
        };
        clear().await;

        for start in ["first", "second"] {
            claim_deployment(&database, "authentik")
                .await
                .unwrap_or_else(|error| panic!("the {start} start: {error:#}"));
            assert_eq!(recorded().await, ["authentik"], "{start}");
        }
        let refused = claim_deployment(&database, "other")
            .await
            .expect_err("a start under another provider must fail");
        let message = format!("{refused:#}");
        assert!(
            message.contains("belong to the authentik identity provider")
                && message.contains("SOVEREIGN_CONFIG_IDENTITY_PROVIDER selects other"),
            "{message}"
        );
        assert_eq!(recorded().await, ["authentik"]);

        // The table admits one row, whoever writes it.
        let second_row =
            sqlx::query("INSERT INTO identity_provider (singleton, name) VALUES (FALSE, 'x')")
                .execute(&database)
                .await;
        assert!(second_row.is_err());
        clear().await;
    }
}
