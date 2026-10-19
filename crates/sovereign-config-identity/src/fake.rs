//! An in-memory [`ManagedIdentityProvider`] that passes the conformance
//! suite, for tests that exercise a caller without any transport.
//!
//! Failures are scripted per operation with [`FakeIdentityProvider::fail_next`].
//! A scripted failure models its class's worst case: `Ambiguous` and `Invalid`
//! apply the operation before failing, as a provider that committed and then
//! lost the response would; the other classes apply nothing.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Mutex, MutexGuard};

use async_trait::async_trait;

use crate::conformance::{ConformanceTarget, Operation};
use crate::{
    AccountGrant, AccountId, CredentialId, ManagedIdentityProvider, ProviderError,
    ProvisionedAccount, Secret,
};

/// One account as the fake holds it, for a test to assert on.
#[derive(Clone, Debug)]
pub struct FakeAccount {
    pub account: AccountId,
    pub username: String,
    pub subject: String,
    pub credential: CredentialId,
    pub secret: String,
    pub name: Option<String>,
    pub connection_id: Option<String>,
    pub root: Option<String>,
    pub permissions: Vec<String>,
    pub in_browse_group: bool,
}

struct Scripted {
    error: ProviderError,
    applied: bool,
}

#[derive(Default)]
struct State {
    accounts: BTreeMap<String, FakeAccount>,
    next_id: u64,
    faults: BTreeMap<Operation, VecDeque<Scripted>>,
    calls: BTreeMap<Operation, usize>,
    browse_group_missing: bool,
}

#[derive(Default)]
pub struct FakeIdentityProvider {
    state: Mutex<State>,
}

impl FakeIdentityProvider {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Fails the next call of `operation` as `error`, after applying it when
    /// `error` is `Ambiguous` or `Invalid`. Calls queue in order.
    pub fn fail_next(&self, operation: Operation, error: ProviderError) {
        let applied = matches!(error, ProviderError::Ambiguous | ProviderError::Invalid);
        self.script(operation, error, applied);
    }

    /// Fails the next call of `operation` as `error` without applying it,
    /// whatever the class: an ambiguous create that never landed.
    pub fn fail_next_unapplied(&self, operation: Operation, error: ProviderError) {
        self.script(operation, error, false);
    }

    /// Fails the next call of `operation` as `error` after applying it,
    /// whatever the class: a provider that refuses a delete it has applied,
    /// once the caller can no longer see the account.
    pub fn fail_next_after_applying(&self, operation: Operation, error: ProviderError) {
        self.script(operation, error, true);
    }

    fn script(&self, operation: Operation, error: ProviderError, applied: bool) {
        self.state()
            .faults
            .entry(operation)
            .or_default()
            .push_back(Scripted { error, applied });
    }

    /// Makes the browsing group absent, so assigning it is `NotFound`.
    pub fn remove_browse_group(&self) {
        self.state().browse_group_missing = true;
    }

    /// The account called `username`, if it exists.
    #[must_use]
    pub fn account(&self, username: &str) -> Option<FakeAccount> {
        self.state()
            .accounts
            .values()
            .find(|account| account.username == username)
            .cloned()
    }

    /// Every account that exists.
    #[must_use]
    pub fn accounts(&self) -> Vec<FakeAccount> {
        self.state().accounts.values().cloned().collect()
    }

    /// How many times `operation` has been called, failed or not.
    #[must_use]
    pub fn calls(&self, operation: Operation) -> usize {
        self.state().calls.get(&operation).copied().unwrap_or(0)
    }

    /// Counts the call and takes its scripted failure, if any.
    fn begin(&self, operation: Operation) -> Option<Scripted> {
        let mut state = self.state();
        *state.calls.entry(operation).or_default() += 1;
        state
            .faults
            .get_mut(&operation)
            .and_then(VecDeque::pop_front)
    }

    /// Runs `apply` unless the scripted failure says not to, then reports
    /// that failure or `apply`'s own result.
    fn run<T>(
        &self,
        operation: Operation,
        apply: impl FnOnce(&mut State) -> Result<T, ProviderError>,
    ) -> Result<T, ProviderError> {
        let scripted = self.begin(operation);
        match scripted {
            None => apply(&mut self.state()),
            Some(Scripted { error, applied }) => {
                if applied {
                    let _ = apply(&mut self.state());
                }
                Err(error)
            }
        }
    }
}

fn existing<'a>(
    state: &'a mut State,
    account: &AccountId,
) -> Result<&'a mut FakeAccount, ProviderError> {
    state
        .accounts
        .get_mut(account.as_str())
        .ok_or(ProviderError::NotFound)
}

fn identifier<T>(
    parse: impl FnOnce(String) -> Result<T, crate::InvalidIdentifier>,
    value: String,
) -> T {
    parse(value).expect("the fake's identifiers are always valid")
}

#[async_trait]
impl ManagedIdentityProvider for FakeIdentityProvider {
    async fn create_account(&self, username: &str) -> Result<ProvisionedAccount, ProviderError> {
        self.run(Operation::CreateAccount, |state| {
            if state
                .accounts
                .values()
                .any(|account| account.username == username)
            {
                return Err(ProviderError::Rejected);
            }
            state.next_id += 1;
            let id = state.next_id;
            let account = identifier(AccountId::parse, id.to_string());
            let created = FakeAccount {
                account: account.clone(),
                username: username.to_owned(),
                subject: format!("fake-subject-{id}"),
                credential: identifier(CredentialId::parse, format!("fake-credential-{id}")),
                secret: format!("fake-secret-{id}-0"),
                name: None,
                connection_id: None,
                root: None,
                permissions: Vec::new(),
                in_browse_group: false,
            };
            let provisioned = ProvisionedAccount {
                account,
                subject: created.subject.clone(),
                secret: Secret::new(created.secret.clone()),
            };
            state.accounts.insert(id.to_string(), created);
            Ok(provisioned)
        })
    }

    async fn grant(
        &self,
        account: &AccountId,
        grant: &AccountGrant<'_>,
    ) -> Result<(), ProviderError> {
        self.run(Operation::Grant, |state| {
            let account = existing(state, account)?;
            account.name = Some(grant.display_name.to_owned());
            account.connection_id = Some(grant.connection_id.to_owned());
            account.root = Some(grant.root.to_owned());
            account.permissions = grant.permissions.iter().map(|&p| p.to_owned()).collect();
            Ok(())
        })
    }

    async fn assign_browse_group(&self, account: &AccountId) -> Result<(), ProviderError> {
        self.run(Operation::AssignBrowseGroup, |state| {
            if state.browse_group_missing {
                return Err(ProviderError::NotFound);
            }
            existing(state, account)?.in_browse_group = true;
            Ok(())
        })
    }

    async fn rename_account(
        &self,
        account: &AccountId,
        display_name: &str,
    ) -> Result<(), ProviderError> {
        self.run(Operation::RenameAccount, |state| {
            existing(state, account)?.name = Some(display_name.to_owned());
            Ok(())
        })
    }

    async fn find_account(&self, username: &str) -> Result<Option<AccountId>, ProviderError> {
        self.run(Operation::FindAccount, |state| {
            Ok(state
                .accounts
                .values()
                .find(|account| account.username == username)
                .map(|account| account.account.clone()))
        })
    }

    async fn find_credentials(&self, username: &str) -> Result<Vec<CredentialId>, ProviderError> {
        self.run(Operation::FindCredentials, |state| {
            Ok(state
                .accounts
                .values()
                .filter(|account| account.username == username)
                .map(|account| account.credential.clone())
                .collect())
        })
    }

    async fn replace_credential(&self, credential: &CredentialId) -> Result<Secret, ProviderError> {
        self.run(Operation::ReplaceCredential, |state| {
            state.next_id += 1;
            let generation = state.next_id;
            let account = state
                .accounts
                .values_mut()
                .find(|account| &account.credential == credential)
                .ok_or(ProviderError::NotFound)?;
            account.secret = format!("fake-secret-{}-{generation}", account.account.as_str());
            Ok(Secret::new(account.secret.clone()))
        })
    }

    async fn delete_account(&self, account: &AccountId) -> Result<(), ProviderError> {
        self.run(Operation::DeleteAccount, |state| {
            state
                .accounts
                .remove(account.as_str())
                .map(|_| ())
                .ok_or(ProviderError::NotFound)
        })
    }
}

#[async_trait]
impl ConformanceTarget for FakeIdentityProvider {
    fn provider(&self) -> &dyn ManagedIdentityProvider {
        self
    }

    async fn fail_next(&self, operation: Operation, error: ProviderError) -> bool {
        Self::fail_next(self, operation, error);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conformance::run_conformance;

    #[tokio::test]
    async fn the_fake_conforms_and_produces_every_class() {
        let report = run_conformance(|| async { FakeIdentityProvider::new() }).await;
        assert!(report.skipped.is_empty(), "{:?}", report.skipped);
        assert_eq!(
            report.produced.len(),
            Operation::ALL.len() * ProviderError::ALL.len()
        );
    }

    #[tokio::test]
    async fn an_ambiguous_create_may_have_made_the_account() {
        let fake = FakeIdentityProvider::new();
        fake.fail_next(Operation::CreateAccount, ProviderError::Ambiguous);
        assert_eq!(
            fake.create_account("sc-managed-x").await.map(|_| ()),
            Err(ProviderError::Ambiguous)
        );
        assert!(fake.find_account("sc-managed-x").await.unwrap().is_some());
        assert_eq!(fake.calls(Operation::CreateAccount), 1);
    }
}
