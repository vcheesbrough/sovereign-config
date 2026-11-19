//! The conformance suite's healthy path, with its token hooks, against a
//! real Authentik: a created account's credential obtains an access token at
//! the real token endpoint the way a deployed client asks for one, that
//! token carries the grant the account was given under the claim the
//! verification rules read, and a replaced or deleted credential stops
//! working.
//!
//! Ignored, and it skips unless it is told which Authentik application to
//! use, like the client's own live tests (`src/client/live_tests.rs`), beside
//! which the development deploy pipeline runs it
//! (`cargo test --package sovereign-config-authentik live_ -- --ignored`):
//!
//! - `SOVEREIGN_CONFIG_LIVE_AUTHENTIK_ISSUER` — the application's issuer;
//! - `SOVEREIGN_CONFIG_LIVE_AUTHENTIK_AUDIENCE` — its client id;
//! - `SOVEREIGN_CONFIG_LIVE_GRANTS_ATTRIBUTE` — the attribute its grants
//!   mapping reads;
//! - `SOVEREIGN_CONFIG_LIVE_AUTHENTIK_TOKEN` — the connection manager's token;
//! - `SOVEREIGN_CONFIG_LIVE_MANAGED_GROUP` — the browsing group.
//!
//! It creates one service account there, grants it `read` and `write` on
//! `/conformance/` under the real grants attribute — the grant has to be real
//! to reach a token — and deletes it, also when a check fails.

use std::{collections::BTreeMap, env, sync::Arc};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use sovereign_config_authentik::from_variables;
use sovereign_config_identity::{
    ClaimedGrant, Claims, ClientCredential, IdentityProvider, ManagedIdentityProvider,
    ProviderError,
    conformance::{
        ConformanceTarget, Operation, TokenRefused, USERNAME, lifecycle, presented_secret,
    },
    contract::REQUIRED_SCOPE,
};

struct Live {
    provider: IdentityProvider,
    http: reqwest::Client,
}

#[async_trait]
impl ConformanceTarget for Live {
    fn provider(&self) -> &dyn ManagedIdentityProvider {
        self.provider.accounts.as_ref()
    }

    /// A real Authentik fails on nobody's cue.
    async fn fail_next(&self, _: Operation, _: ProviderError) -> bool {
        false
    }

    /// Exactly a deployed client's request: discovery under the issuer it was
    /// handed, then the `client_credentials` grant with the form fields
    /// `sovereign-config-native` sends.
    async fn obtain_token(
        &self,
        username: &str,
        credential: &ClientCredential,
    ) -> Option<Result<String, TokenRefused>> {
        let presented = presented_secret(username, credential)
            .expect("a credential the provider returned forms a connection URL");
        let discovery: Value = self
            .http
            .get(format!(
                "{}.well-known/openid-configuration",
                self.provider.login.issuer
            ))
            .send()
            .await
            .expect("the issuer serves discovery")
            .json()
            .await
            .expect("discovery is JSON");
        let response = self
            .http
            .post(
                discovery["token_endpoint"]
                    .as_str()
                    .expect("discovery names the token endpoint"),
            )
            .form(&[
                ("grant_type", "client_credentials"),
                ("scope", REQUIRED_SCOPE),
                ("client_id", credential.client_id()),
                ("client_secret", presented.as_str()),
            ])
            .send()
            .await
            .expect("the token endpoint answers");
        if !response.status().is_success() {
            return Some(Err(TokenRefused));
        }
        let body: Value = response.json().await.expect("a token response is JSON");
        assert!(
            body.get("refresh_token").is_none(),
            "a client-credentials grant returns no refresh token"
        );
        Some(Ok(body["access_token"]
            .as_str()
            .expect("a token response carries an access token")
            .to_owned()))
    }

    /// The token's claims, read by the rules the server is given. The
    /// signature is the server's verifier's to check; what is checked here is
    /// that the token is one those rules accept and read a grant from.
    async fn token_grants(&self, token: &str) -> Option<Vec<ClaimedGrant>> {
        let rules = &self.provider.verification;
        let payload = URL_SAFE_NO_PAD.decode(token.split('.').nth(1)?).ok()?;
        let claims: Claims = serde_json::from_slice(&payload).ok()?;
        let issued_for_this_server = claims.get("iss").and_then(Value::as_str)
            == Some(&rules.issuer)
            && rules.has_scope(&claims, REQUIRED_SCOPE);
        issued_for_this_server
            .then(|| rules.grants(&claims))
            .flatten()
    }
}

/// The server's own variables for the application under test, or `None`
/// when the environment does not name one.
fn live_variables() -> Option<BTreeMap<&'static str, String>> {
    let variables: BTreeMap<&'static str, String> = [
        (
            "SOVEREIGN_CONFIG_OIDC_ISSUER",
            "SOVEREIGN_CONFIG_LIVE_AUTHENTIK_ISSUER",
        ),
        (
            "SOVEREIGN_CONFIG_OIDC_AUDIENCE",
            "SOVEREIGN_CONFIG_LIVE_AUTHENTIK_AUDIENCE",
        ),
        (
            "SOVEREIGN_CONFIG_MANAGER_GRANTS_ATTRIBUTE",
            "SOVEREIGN_CONFIG_LIVE_GRANTS_ATTRIBUTE",
        ),
        (
            "SOVEREIGN_CONFIG_MANAGER_API_TOKEN",
            "SOVEREIGN_CONFIG_LIVE_AUTHENTIK_TOKEN",
        ),
        (
            "SOVEREIGN_CONFIG_MANAGER_GROUP",
            "SOVEREIGN_CONFIG_LIVE_MANAGED_GROUP",
        ),
    ]
    .into_iter()
    .filter_map(|(variable, live)| {
        let value = env::var(live).ok()?;
        (!value.trim().is_empty()).then(|| (variable, value.trim().to_owned()))
    })
    .collect();
    (variables.len() == 5).then_some(variables)
}

/// Removes the account the lifecycle acts on, if it is there. The lookup may
/// be refused when the manager can see no account at all, which also means
/// there is none of its own to remove.
async fn remove_subject(provider: &dyn ManagedIdentityProvider) {
    if let Ok(Some(account)) = provider.find_account(USERNAME).await {
        let _ = provider.delete_account(&account).await;
    }
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_LIVE_AUTHENTIK_ISSUER, _AUDIENCE, _TOKEN, SOVEREIGN_CONFIG_LIVE_GRANTS_ATTRIBUTE and _MANAGED_GROUP"]
async fn live_authentik_issues_tokens_the_server_reads() {
    let Some(variables) = live_variables() else {
        return;
    };
    let live = Arc::new(Live {
        provider: from_variables(&variables).expect("the live Authentik variables are valid"),
        http: reqwest::Client::new(),
    });
    // A run that was killed halfway leaves its account behind.
    remove_subject(live.provider()).await;

    // In a task, so a failed check still gets its account removed from the
    // real directory before the failure is reported.
    let run = Arc::clone(&live);
    let outcome = tokio::spawn(async move { lifecycle(run.as_ref()).await }).await;
    remove_subject(live.provider()).await;
    match outcome {
        Ok(tokens_checked) => assert!(
            tokens_checked,
            "the token hooks ran against the live provider"
        ),
        Err(failure) => std::panic::resume_unwind(failure.into_panic()),
    }
}
