//! [`ManagedIdentityProvider`] in Authentik's terms.
//!
//! An account is a service account, identified by its integer primary key; a
//! credential is its app-password token, identified by the token's
//! identifier; a grant is the configured grants attribute on the user, which
//! the blueprint's scope mapping signs into its access tokens.

use async_trait::async_trait;
use sovereign_config_core::Secret;
use sovereign_config_identity::{
    AccountGrant, AccountId, ClientCredential, CredentialId, ManagedIdentityProvider,
    ProviderError, ProvisionedAccount,
};

use crate::client::AuthentikAdminClient;
use crate::config::AuthentikConfig;
use crate::password::generate_app_password;

pub struct AuthentikProvider {
    client: AuthentikAdminClient,
    client_id: String,
    grants_attribute: String,
    managed_group: String,
}

impl AuthentikProvider {
    /// # Errors
    ///
    /// The administration origin is not permitted (HTTPS only; numeric
    /// loopback HTTP for tests), or the HTTP client cannot be built.
    pub fn new(config: AuthentikConfig) -> anyhow::Result<Self> {
        Ok(Self {
            client: AuthentikAdminClient::new(config.api_origin, config.api_token, config.timeout)?,
            client_id: config.client_id,
            grants_attribute: config.grants_attribute,
            managed_group: config.managed_group,
        })
    }
}

impl AuthentikProvider {
    /// An app password, presented through the server's own client: every
    /// account shares its client id. The id was validated at startup, so a
    /// refusal here can only be a password Authentik returned that a URL
    /// cannot carry.
    fn credential(&self, app_password: Secret) -> Result<ClientCredential, ProviderError> {
        ClientCredential::new(self.client_id.clone(), app_password)
            .map_err(|_| ProviderError::Invalid)
    }
}

/// Authentik's primary key for an account this implementation issued. An
/// identifier that is not one is refused before anything is sent: `Rejected`
/// (definitely not applied), never `NotFound`, which would claim the account
/// is absent without asking.
fn user_id(account: &AccountId) -> Result<i64, ProviderError> {
    account
        .as_str()
        .parse()
        .map_err(|_| ProviderError::Rejected)
}

fn account_id(user_id: i64) -> Result<AccountId, ProviderError> {
    AccountId::parse(user_id.to_string()).map_err(|_| ProviderError::Invalid)
}

#[async_trait]
impl ManagedIdentityProvider for AuthentikProvider {
    async fn create_account(&self, username: &str) -> Result<ProvisionedAccount, ProviderError> {
        let created = self.client.create_service_account(username).await?;
        Ok(ProvisionedAccount {
            account: account_id(created.user_id)?,
            subject: created.user_uid,
            credential: self.credential(created.app_password)?,
        })
    }

    async fn grant(
        &self,
        account: &AccountId,
        grant: &AccountGrant<'_>,
    ) -> Result<(), ProviderError> {
        self.client
            .set_managed_attributes(
                user_id(account)?,
                grant.connection_id,
                grant.display_name,
                &self.grants_attribute,
                grant.root,
                grant.permissions,
            )
            .await
    }

    async fn assign_browse_group(&self, account: &AccountId) -> Result<(), ProviderError> {
        let user_id = user_id(account)?;
        let group_id = self
            .client
            .find_group_by_name(&self.managed_group)
            .await?
            .ok_or(ProviderError::NotFound)?;
        self.client.add_user_to_group(user_id, &group_id).await
    }

    async fn rename_account(
        &self,
        account: &AccountId,
        display_name: &str,
    ) -> Result<(), ProviderError> {
        self.client
            .rename_user(user_id(account)?, display_name)
            .await
    }

    async fn find_account(&self, username: &str) -> Result<Option<AccountId>, ProviderError> {
        self.client
            .find_user_by_username(username)
            .await?
            .map(|user| account_id(user.user_id))
            .transpose()
    }

    async fn find_credentials(&self, username: &str) -> Result<Vec<CredentialId>, ProviderError> {
        self.client
            .find_app_password_identifiers(username)
            .await?
            .into_iter()
            .map(|identifier| CredentialId::parse(identifier).map_err(|_| ProviderError::Invalid))
            .collect()
    }

    async fn replace_credential(
        &self,
        credential: &CredentialId,
    ) -> Result<ClientCredential, ProviderError> {
        // Nothing has been sent when generation fails, so it is definitively
        // not applied.
        let replacement = generate_app_password().map_err(|_| ProviderError::Unavailable)?;
        self.client
            .set_credential_secret(credential.as_str(), &replacement)
            .await?;
        self.credential(replacement)
    }

    async fn delete_account(&self, account: &AccountId) -> Result<(), ProviderError> {
        self.client.delete_user(user_id(account)?).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_identifier_this_implementation_never_issued_is_refused_not_absent() {
        let foreign = AccountId::parse("not-an-authentik-key").unwrap();
        assert_eq!(user_id(&foreign), Err(ProviderError::Rejected));
        assert_eq!(user_id(&account_id(4242).unwrap()), Ok(4242));
    }
}
