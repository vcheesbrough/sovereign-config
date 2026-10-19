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

use async_trait::async_trait;
use sovereign_config_core::{ConfigPath, ConnectionUrl};

use crate::{
    AccountGrant, AccountId, ClientCredential, CredentialId, ManagedIdentityProvider, ProviderError,
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
}

/// What a run checked.
#[derive(Debug, Default)]
pub struct Report {
    /// Every `(operation, class)` the implementation produced and passed.
    pub produced: Vec<(Operation, ProviderError)>,
    /// Every `(operation, class)` its target could not arrange.
    pub skipped: Vec<(Operation, ProviderError)>,
}

const USERNAME: &str = "sc-conformance-subject";
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
    lifecycle(&factory().await).await;
    accounts_are_isolated(&factory().await).await;
    usernames_match_exactly(&factory().await).await;
    absent_targets_are_not_found(&factory().await).await;

    let mut report = Report::default();
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

/// The healthy path: every operation on one account, in the order the
/// server performs them.
async fn lifecycle(target: &impl ConformanceTarget) {
    let provider = target.provider();
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
        Ok(credentials.clone()),
        "replacing a credential's value keeps the credential"
    );

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
    assert_eq!(
        provider.find_account(USERNAME).await,
        Ok(None),
        "a deleted account is not found"
    );
}

/// Whether the server can hand `credential` out: a connection URL admits its
/// client id and secret under the account's username.
fn forms_a_connection_url(credential: &ClientCredential) -> bool {
    ConnectionUrl::managed(
        "https://config.example.test",
        &ConfigPath::parse("/").expect("the root is a path"),
        "https://auth.example.test/application/o/sovereign-config/",
        credential.client_id(),
        USERNAME,
        credential.secret(),
    )
    .is_ok()
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
