//! The conformance suite every [`ManagedIdentityProvider`] implementation
//! runs: what of the trait's contract a caller can observe, checked against
//! the implementation over its own (mock) backend.
//!
//! An implementation provides a [`ConformanceTarget`] — a fresh provider over
//! an empty backend, and a way to make that backend fail the next call of an
//! operation as each [`ProviderError`] class describes — and calls
//! [`run_conformance`]. A contract violation panics with what was violated.
//! The returned [`Report`] lists which failure classes the implementation
//! produced, so its own test can pin the set it is expected to produce.
//!
//! Two optional hooks take the suite past the provider's own API, to what the
//! server and a deployed client see: [`ConformanceTarget::obtain_token`]
//! presents a returned credential at the token endpoint, and
//! [`ConformanceTarget::token_grants`] reads back the grants the server would
//! find in that token. A target that implements them — over a mock, or live
//! against a real identity provider — has it proven that a credential
//! authenticates, that a grant reaches the token, and that a replaced or
//! deleted credential stops working.

use async_trait::async_trait;
use sovereign_config_core::{ConfigPath, ConnectionUrl};

use crate::{
    AccountGrant, AccountId, ClaimedGrant, ClientCredential, CredentialId, ManagedIdentityProvider,
    ProviderError, ProvisionedAccount,
};

/// One operation of [`ManagedIdentityProvider`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Operation {
    CreateAccount,
    Grant,
    AssignBrowseGroup,
    RenameAccount,
    FindAccount,
    FindCredentials,
    ReplaceCredential,
    DeleteAccount,
}

impl Operation {
    pub const ALL: [Self; 8] = [
        Self::CreateAccount,
        Self::Grant,
        Self::AssignBrowseGroup,
        Self::RenameAccount,
        Self::FindAccount,
        Self::FindCredentials,
        Self::ReplaceCredential,
        Self::DeleteAccount,
    ];
}

/// An implementation under test, over a fresh, empty backend.
#[async_trait]
pub trait ConformanceTarget: Send + Sync {
    fn provider(&self) -> &dyn ManagedIdentityProvider;

    /// Arranges for the backend to fail the next call of `operation` the way
    /// it would really produce `error` — an HTTP status, a timeout, a garbled
    /// body — so the suite checks the implementation's classification, not
    /// the target's. Returns `false` when the implementation cannot produce
    /// that class for that operation, which skips the check.
    async fn fail_next(&self, operation: Operation, error: ProviderError) -> bool;

    /// Presents `credential`, as the account `username`, at the provider's
    /// token endpoint the way a deployed client does ([`presented_secret`]
    /// is the secret it sends), and returns what came back: the access
    /// token, or [`TokenRefused`].
    ///
    /// `None` — the default — is a target without the hook, which skips the
    /// token checks.
    async fn obtain_token(
        &self,
        username: &str,
        credential: &ClientCredential,
    ) -> Option<Result<String, TokenRefused>> {
        let _ = (username, credential);
        None
    }

    /// The grants the server would read in `token`: its claims, read by the
    /// provider's own [`crate::VerificationRules`]. `None` — the default — is
    /// a target without the hook, or a token whose grants cannot be read.
    async fn token_grants(&self, token: &str) -> Option<Vec<ClaimedGrant>> {
        let _ = token;
        None
    }
}

/// The token endpoint refused the credential, and what it said: enough for a
/// failed run to explain itself, and never the response body.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TokenRefused {
    /// The HTTP status, when the refusal came over HTTP.
    pub status: Option<u16>,
    /// The OAuth `error` code (RFC 6749 §5.2), such as `invalid_grant`,
    /// when the response carried one in the expected form.
    pub error: Option<String>,
}

impl TokenRefused {
    /// A refusal over HTTP. `error` is the response's `error` field, kept only
    /// when it is a short code of the shape RFC 6749 gives it (lower-case
    /// letters and `_`), so no description, token or other text from the
    /// response is ever carried.
    #[must_use]
    pub fn http(status: u16, error: Option<&str>) -> Self {
        let error = error
            .filter(|code| {
                !code.is_empty()
                    && code.len() <= 64
                    && code
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            })
            .map(str::to_owned);
        Self {
            status: Some(status),
            error,
        }
    }
}

/// The `client_secret` a deployed client posts for `credential`: it takes the
/// connection URL the server would hand out for the account and presents
/// what that URL decodes to. `None` when no connection URL can carry the
/// credential.
#[must_use]
pub fn presented_secret(username: &str, credential: &ClientCredential) -> Option<String> {
    connection_url(username, credential)?
        .client_authentication()
        .map(|secret| secret.expose().to_owned())
}

/// What a run checked.
#[derive(Debug, Default)]
pub struct Report {
    /// Every `(operation, class)` the implementation produced and passed.
    pub produced: Vec<(Operation, ProviderError)>,
    /// Every `(operation, class)` its target could not arrange.
    pub skipped: Vec<(Operation, ProviderError)>,
    /// Whether the target implemented the token hooks, so that a credential
    /// was proven to authenticate and a grant to reach its token.
    pub tokens_checked: bool,
}

/// The account every check acts on. Public so that a target over a backend
/// that outlives a run — a live identity provider — can clear it first.
pub const USERNAME: &str = "sc-conformance-subject";
const OTHER_USERNAME: &str = "sc-conformance-bystander";
const PERMISSIONS: [&str; 2] = ["read", "write"];

fn grant() -> AccountGrant<'static> {
    AccountGrant {
        connection_id: "conformanceconnection0000000001",
        display_name: "Conformance pipeline",
        root: "/conformance/",
        permissions: &PERMISSIONS,
    }
}

/// Runs every check, each against a fresh target from `factory`.
///
/// # Panics
///
/// On the first contract violation, naming it.
pub async fn run_conformance<F, Fut, T>(factory: F) -> Report
where
    F: Fn() -> Fut,
    Fut: Future<Output = T>,
    T: ConformanceTarget,
{
    let tokens_checked = lifecycle(&factory().await).await;
    accounts_are_isolated(&factory().await).await;
    usernames_match_exactly(&factory().await).await;
    absent_targets_are_not_found(&factory().await).await;

    let mut report = Report {
        tokens_checked,
        ..Report::default()
    };
    for operation in Operation::ALL {
        for error in ProviderError::ALL {
            if failure_is_classified(&factory().await, operation, error).await {
                report.produced.push((operation, error));
            } else {
                report.skipped.push((operation, error));
            }
        }
    }
    report
}

/// Whether `credential` obtains a token for the account, or `None` when the
/// target has no token hook.
async fn authenticates(
    target: &impl ConformanceTarget,
    credential: &ClientCredential,
) -> Option<Result<String, TokenRefused>> {
    target.obtain_token(USERNAME, credential).await
}

/// The healthy path: every operation on one account, in the order the
/// server performs them. Returns whether the target's token hooks let the
/// credentials and the grant be checked in a token.
///
/// Public for a live identity provider, which can be put through this but
/// not through the scripted failures of [`run_conformance`]. It leaves
/// nothing behind when it passes; the backend must hold no account called
/// [`USERNAME`] when it starts.
///
/// # Panics
///
/// On the first contract violation, naming it.
pub async fn lifecycle(target: &impl ConformanceTarget) -> bool {
    let (created, credentials) = creates_an_account(target.provider()).await;
    let tokens_checked = grants_the_account(target, &created).await;
    let replacement = replaces_the_credential(target, &created, &credentials, tokens_checked).await;
    deletes_the_account(target, &created, &replacement, tokens_checked).await;
    tokens_checked
}

/// A created account has a subject, one credential a connection URL can
/// carry, and is found under its username.
async fn creates_an_account(
    provider: &dyn ManagedIdentityProvider,
) -> (ProvisionedAccount, Vec<CredentialId>) {
    let created = provider
        .create_account(USERNAME)
        .await
        .expect("create_account succeeds against a healthy backend");
    assert!(
        !created.subject.is_empty() && created.subject.len() <= crate::MAX_IDENTIFIER_CHARS,
        "the account's subject is a bounded, non-empty identifier"
    );
    assert!(
        !created.credential.secret().expose().is_empty(),
        "the account's credential is not empty"
    );
    assert!(
        forms_a_connection_url(&created.credential),
        "the credential's client id and secret form a connection URL"
    );
    assert_eq!(
        provider.find_account(USERNAME).await,
        Ok(Some(created.account.clone())),
        "find_account finds the account create_account made, by the same identifier"
    );
    let credentials = provider
        .find_credentials(USERNAME)
        .await
        .expect("find_credentials succeeds against a healthy backend");
    assert_eq!(
        credentials.len(),
        1,
        "a created account holds exactly one credential"
    );
    (created, credentials)
}

/// The account is granted, renamed and grouped; with the token hooks, its
/// credential obtains a token carrying exactly that grant. Returns whether
/// the hooks were there.
async fn grants_the_account(target: &impl ConformanceTarget, created: &ProvisionedAccount) -> bool {
    let provider = target.provider();
    for attempt in ["first", "repeated"] {
        assert_eq!(
            provider.grant(&created.account, &grant()).await,
            Ok(()),
            "a {attempt} grant succeeds: grant is idempotent"
        );
    }
    assert_eq!(
        provider
            .rename_account(&created.account, "Renamed pipeline")
            .await,
        Ok(()),
        "rename_account succeeds on an existing account"
    );
    assert_eq!(
        provider.assign_browse_group(&created.account).await,
        Ok(()),
        "assign_browse_group succeeds when the group exists"
    );
    // Only once the account is set up as the server sets it up — granted and
    // in its group — is its credential what an access URL hands out. An
    // identity provider may admit an account to the application only through
    // that group, as the development Authentik does.
    match authenticates(target, &created.credential).await {
        None => false,
        Some(token) => {
            let token = token.unwrap_or_else(|refused| {
                panic!("a provisioned account's credential obtains an access token: {refused:?}")
            });
            assert_eq!(
                target.token_grants(&token).await,
                Some(vec![ClaimedGrant {
                    prefix: grant().root.to_owned(),
                    permissions: PERMISSIONS.map(str::to_owned).to_vec(),
                }]),
                "the account's access token carries exactly the grant it was given"
            );
            true
        }
    }
}

/// The credential's value is replaced: the same credential, the same client,
/// a new value, and the old one obtains no token.
async fn replaces_the_credential(
    target: &impl ConformanceTarget,
    created: &ProvisionedAccount,
    credentials: &[CredentialId],
    tokens_checked: bool,
) -> ClientCredential {
    let provider = target.provider();
    let replacement = provider
        .replace_credential(&credentials[0])
        .await
        .expect("replace_credential succeeds on an existing credential");
    assert!(
        !replacement.secret().expose().is_empty()
            && replacement.secret().expose() != created.credential.secret().expose(),
        "a replaced credential has a new, non-empty value"
    );
    assert_eq!(
        replacement.client_id(),
        created.credential.client_id(),
        "a replaced credential authenticates as the same client"
    );
    assert!(
        forms_a_connection_url(&replacement),
        "the replaced credential forms a connection URL"
    );
    assert_eq!(
        provider.find_credentials(USERNAME).await,
        Ok(credentials.to_vec()),
        "replacing a credential's value keeps the credential"
    );
    if tokens_checked {
        let previous = authenticates(target, &created.credential).await;
        assert!(
            matches!(previous, Some(Err(_))),
            "a replaced credential's previous value no longer obtains a token"
        );
        // A target that checked the first credential checks this one too:
        // no token, for any reason, is a failure.
        match authenticates(target, &replacement).await {
            Some(Ok(_)) => {}
            other => panic!("a replaced credential's new value obtains a token, not {other:?}"),
        }
    }
    replacement
}

/// The account is deleted: no credential of it survives, and its last
/// credential obtains no token.
async fn deletes_the_account(
    target: &impl ConformanceTarget,
    created: &ProvisionedAccount,
    replacement: &ClientCredential,
    tokens_checked: bool,
) {
    let provider = target.provider();
    assert_eq!(
        provider.delete_account(&created.account).await,
        Ok(()),
        "delete_account succeeds on an existing account"
    );
    assert_eq!(
        provider.find_credentials(USERNAME).await,
        Ok(Vec::new()),
        "a deleted account's credentials are gone, and an empty result says so"
    );
    // A provider may refuse the lookup outright once the caller can see no
    // account at all (the trait says so); it may never still find this one.
    let found = provider.find_account(USERNAME).await;
    assert!(
        matches!(found, Ok(None) | Err(ProviderError::Rejected)),
        "a deleted account is not found, not {found:?}"
    );
    if tokens_checked {
        assert!(
            matches!(authenticates(target, replacement).await, Some(Err(_))),
            "a deleted account's credential no longer obtains a token"
        );
    }
}

/// The connection URL the server would hand out for `credential`, under any
/// issuer a client accepts: the issuer is no part of what is checked.
fn connection_url(username: &str, credential: &ClientCredential) -> Option<ConnectionUrl> {
    ConnectionUrl::managed(
        "https://config.example.test",
        &ConfigPath::parse("/").expect("the root is a path"),
        "https://identity.example.test/",
        credential.client_id(),
        username,
        credential.secret(),
    )
    .ok()
}

/// Whether the server can hand `credential` out: a connection URL admits its
/// client id and secret under the account's username.
fn forms_a_connection_url(credential: &ClientCredential) -> bool {
    connection_url(USERNAME, credential).is_some()
}

/// An operation on one account never reaches another.
async fn accounts_are_isolated(target: &impl ConformanceTarget) {
    let provider = target.provider();
    let subject = provider.create_account(USERNAME).await.unwrap();
    let bystander = provider.create_account(OTHER_USERNAME).await.unwrap();
    assert_ne!(
        subject.account, bystander.account,
        "two accounts have distinct identifiers"
    );
    provider.grant(&subject.account, &grant()).await.unwrap();
    provider.delete_account(&subject.account).await.unwrap();
    assert_eq!(
        provider.find_account(OTHER_USERNAME).await,
        Ok(Some(bystander.account)),
        "deleting one account leaves another"
    );
    assert_eq!(
        provider
            .find_credentials(OTHER_USERNAME)
            .await
            .map(|found| found.len()),
        Ok(1),
        "deleting one account leaves another's credential"
    );
}

/// A username is matched exactly, never as a prefix.
async fn usernames_match_exactly(target: &impl ConformanceTarget) {
    let provider = target.provider();
    provider.create_account(USERNAME).await.unwrap();
    let prefix = &USERNAME[..USERNAME.len() - 3];
    assert_eq!(
        provider.find_account(prefix).await,
        Ok(None),
        "find_account does not match a prefix of a username"
    );
    assert_eq!(
        provider.find_credentials(prefix).await,
        Ok(Vec::new()),
        "find_credentials does not match a prefix of a username"
    );
}

/// An absent target fails as `NotFound`, or as `Rejected` where the provider
/// hides what the caller cannot see; either way, nothing was applied.
async fn absent_targets_are_not_found(target: &impl ConformanceTarget) {
    let provider = target.provider();
    let created = provider.create_account(USERNAME).await.unwrap();
    let credential = provider.find_credentials(USERNAME).await.unwrap().remove(0);
    provider.delete_account(&created.account).await.unwrap();

    let absent = |operation: &str, result: Result<(), ProviderError>| {
        assert!(
            matches!(
                result,
                Err(ProviderError::NotFound | ProviderError::Rejected)
            ),
            "{operation} on an absent target fails as not_found or rejected, not {result:?}"
        );
    };
    absent("grant", provider.grant(&created.account, &grant()).await);
    absent(
        "rename_account",
        provider.rename_account(&created.account, "Gone").await,
    );
    absent(
        "replace_credential",
        provider.replace_credential(&credential).await.map(|_| ()),
    );
    absent(
        "delete_account",
        provider.delete_account(&created.account).await,
    );
}

/// The account and credential an operation acts on, created healthy first.
struct Fixture {
    account: AccountId,
    credential: CredentialId,
}

async fn fixture(provider: &dyn ManagedIdentityProvider) -> Fixture {
    let account = provider.create_account(USERNAME).await.unwrap().account;
    let credential = provider.find_credentials(USERNAME).await.unwrap().remove(0);
    Fixture {
        account,
        credential,
    }
}

async fn invoke(
    provider: &dyn ManagedIdentityProvider,
    operation: Operation,
    fixture: Option<&Fixture>,
) -> Result<(), ProviderError> {
    let fixture = || fixture.expect("this operation acts on an existing account");
    match operation {
        Operation::CreateAccount => provider.create_account(USERNAME).await.map(|_| ()),
        Operation::Grant => provider.grant(&fixture().account, &grant()).await,
        Operation::AssignBrowseGroup => provider.assign_browse_group(&fixture().account).await,
        Operation::RenameAccount => {
            provider
                .rename_account(&fixture().account, "Renamed pipeline")
                .await
        }
        Operation::FindAccount => provider.find_account(USERNAME).await.map(|_| ()),
        Operation::FindCredentials => provider.find_credentials(USERNAME).await.map(|_| ()),
        Operation::ReplaceCredential => provider
            .replace_credential(&fixture().credential)
            .await
            .map(|_| ()),
        Operation::DeleteAccount => provider.delete_account(&fixture().account).await,
    }
}

/// A failure arrives as exactly its class, after exactly one attempt (a
/// retry would have succeeded), and a definitely-unapplied create left no
/// account. Returns whether the target could arrange the failure.
async fn failure_is_classified(
    target: &impl ConformanceTarget,
    operation: Operation,
    error: ProviderError,
) -> bool {
    let provider = target.provider();
    let fixture = if operation == Operation::CreateAccount {
        None
    } else {
        Some(fixture(provider).await)
    };
    if !target.fail_next(operation, error).await {
        return false;
    }
    let result = invoke(provider, operation, fixture.as_ref()).await;
    assert_eq!(
        result,
        Err(error),
        "{operation:?} reports a {} failure as exactly that, without retrying",
        error.label()
    );
    if operation == Operation::CreateAccount && error.definitely_not_applied() {
        assert_eq!(
            provider.find_account(USERNAME).await,
            Ok(None),
            "a {} create made no account",
            error.label()
        );
        assert_eq!(
            provider.find_credentials(USERNAME).await,
            Ok(Vec::new()),
            "a {} create left no credential",
            error.label()
        );
    }
    if operation == Operation::DeleteAccount && error == ProviderError::Unavailable {
        assert_eq!(
            provider
                .find_credentials(USERNAME)
                .await
                .map(|found| found.len()),
            Ok(1),
            "an undelivered delete left the account's credential"
        );
    }
    true
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use super::{ConformanceTarget, Operation, TokenRefused, lifecycle};
    use crate::{
        ClientCredential, ManagedIdentityProvider, ProviderError, fake::FakeIdentityProvider,
    };

    /// The fake, except that its token hook goes quiet for every credential
    /// after the first one it is shown: a target that checked a created
    /// credential and then says nothing about its replacement.
    #[derive(Default)]
    struct SilentAfterFirst {
        fake: FakeIdentityProvider,
        first: std::sync::Mutex<Option<String>>,
    }

    #[async_trait]
    impl ConformanceTarget for SilentAfterFirst {
        fn provider(&self) -> &dyn ManagedIdentityProvider {
            &self.fake
        }

        async fn fail_next(&self, operation: Operation, error: ProviderError) -> bool {
            self.fake.fail_next(operation, error);
            true
        }

        async fn obtain_token(
            &self,
            username: &str,
            credential: &ClientCredential,
        ) -> Option<Result<String, TokenRefused>> {
            let secret = credential.secret().expose().to_owned();
            let first = self
                .first
                .lock()
                .unwrap()
                .get_or_insert_with(|| secret.clone())
                .clone();
            if first == secret {
                self.fake.obtain_token(username, credential).await
            } else {
                None
            }
        }

        async fn token_grants(&self, token: &str) -> Option<Vec<super::ClaimedGrant>> {
            self.fake.token_grants(token).await
        }
    }

    /// Once a target has checked tokens, a replaced credential that obtains
    /// none — even with no answer at all — fails the lifecycle.
    #[tokio::test]
    #[should_panic(expected = "a replaced credential's new value obtains a token, not None")]
    async fn a_replacement_with_no_token_fails_the_lifecycle() {
        lifecycle(&SilentAfterFirst::default()).await;
    }

    /// A refusal keeps the status and a well-formed OAuth error code, and
    /// nothing else the response said.
    #[test]
    fn a_refusal_keeps_only_the_status_and_an_error_code() {
        assert_eq!(
            TokenRefused::http(400, Some("invalid_grant")),
            TokenRefused {
                status: Some(400),
                error: Some("invalid_grant".to_owned()),
            }
        );
        for unusable in [
            None,
            Some(""),
            Some("User not authenticated"),
            Some("invalid_grant: token-sentinel"),
            Some("INVALID_GRANT"),
        ] {
            assert_eq!(
                TokenRefused::http(401, unusable).error,
                None,
                "{unusable:?}"
            );
        }
        let long = "a".repeat(65);
        assert_eq!(TokenRefused::http(400, Some(&long)).error, None);
    }
}
