//! Authentik orchestration for a managed connection: provisioning the
//! service account, and the compensation and reconciliation that keep a
//! failed or ambiguous external call from orphaning a live credential.

use std::time::Duration;

use sovereign_config_core::{
    ConfigPath, ConnectionId, ConnectionUrl, ManagedConnectionState, ManagedPermissions,
};
use sovereign_config_proto::sovereign::config::v3::CreateManagedConnectionResponse;
use tokio::time::sleep;
use tonic::Status;

use super::ManagedConnectionsService;
use super::store::ConnectionRow;
use super::wire::{dependency_error, internal_error, proto_metadata};
use crate::authentik::{AdminError, CreatedServiceAccount};
use crate::metrics::{ManagedDependencyCall, ManagedDependencyOutcome};

/// How many times to re-probe for a possibly-delayed create before giving up
/// on finding it. A single immediate probe cannot distinguish "never
/// created" from "the original request is still processing".
const CREATE_RECONCILIATION_ATTEMPTS: u32 = 3;

/// Delay between reconciliation probes, giving a slow-but-still-processing
/// original create request a bounded chance to land before every retry is
/// exhausted.
const CREATE_RECONCILIATION_DELAY: Duration = Duration::from_millis(500);

pub(super) const CLEANUP_MESSAGE: &str = "managed connection requires cleanup";

impl ManagedConnectionsService {
    /// Runs the external provisioning steps for a freshly inserted row and
    /// compensates on every failure path.
    pub(super) async fn provision_inserted(
        &self,
        connection_id: &ConnectionId,
        username: &str,
        root: &ConfigPath,
        permissions: &ManagedPermissions,
    ) -> Result<CreateManagedConnectionResponse, Status> {
        let account = match self.admin.create_service_account(username).await {
            Ok(account) => {
                self.metrics.record_dependency(
                    ManagedDependencyCall::CreateAccount,
                    ManagedDependencyOutcome::Ok,
                );
                account
            }
            Err(error) => {
                self.metrics.record_dependency(
                    ManagedDependencyCall::CreateAccount,
                    dependency_outcome(error),
                );
                return Err(self
                    .recover_ambiguous_create(connection_id, username, error)
                    .await);
            }
        };

        let (row, connection_url) = match self
            .complete_provisioning(connection_id, username, root, permissions, &account)
            .await
        {
            Ok(completed) => completed,
            Err(status) => {
                return Err(self
                    .compensate_created_account(connection_id, account.user_id, status)
                    .await);
            }
        };

        Ok(CreateManagedConnectionResponse {
            metadata: Some(proto_metadata(&row)?),
            connection_url: connection_url.canonical().expose().to_owned(),
        })
    }

    /// Every provisioning step after the account exists. Any error here is
    /// compensated by the caller, which deletes the account it created.
    async fn complete_provisioning(
        &self,
        connection_id: &ConnectionId,
        username: &str,
        root: &ConfigPath,
        permissions: &ManagedPermissions,
        account: &CreatedServiceAccount,
    ) -> Result<(ConnectionRow, ConnectionUrl), Status> {
        // Record the external identity immediately so a crash from here on
        // leaves a row that revocation can reconcile and clean up.
        self.record_provider_user(connection_id, account).await?;
        self.configure_account(connection_id, username, root, permissions, account)
            .await?;
        let connection_url = ConnectionUrl::managed(
            &self.settings.public_origin,
            root,
            &self.settings.issuer,
            &self.settings.client_id,
            username,
            &account.app_password,
        )
        .map_err(|_| internal_error())?;
        let row = self
            .transition_state(
                connection_id,
                ManagedConnectionState::Provisioning,
                ManagedConnectionState::Active,
            )
            .await?
            .ok_or_else(internal_error)?;
        Ok((row, connection_url))
    }

    /// Discovers the single app-password credential, records its identifier,
    /// and patches the exact selected grant plus managed marker.
    pub(super) async fn configure_account(
        &self,
        connection_id: &ConnectionId,
        username: &str,
        root: &ConfigPath,
        permissions: &ManagedPermissions,
        account: &CreatedServiceAccount,
    ) -> Result<(), Status> {
        let identifiers = match self.admin.find_app_password_identifiers(username).await {
            Ok(identifiers) => identifiers,
            Err(error) => {
                self.metrics.record_dependency(
                    ManagedDependencyCall::FindCredentials,
                    dependency_outcome(error),
                );
                return Err(dependency_error());
            }
        };
        // A successful lookup that does not name exactly one credential is a
        // dependency failure, not a success: recording it here is what makes
        // an unreadable or duplicated credential diagnosable from metrics.
        let [credential_identifier] = identifiers.as_slice() else {
            self.metrics.record_dependency(
                ManagedDependencyCall::FindCredentials,
                ManagedDependencyOutcome::Invalid,
            );
            return Err(dependency_error());
        };
        self.metrics.record_dependency(
            ManagedDependencyCall::FindCredentials,
            ManagedDependencyOutcome::Ok,
        );

        self.record_credential_identifier(connection_id, credential_identifier)
            .await?;

        match self
            .admin
            .set_managed_attributes(
                account.user_id,
                connection_id.as_str(),
                &self.settings.grants_attribute,
                root.as_str(),
                &permissions.grant_tokens(),
            )
            .await
        {
            Ok(()) => {
                self.metrics.record_dependency(
                    ManagedDependencyCall::SetAttributes,
                    ManagedDependencyOutcome::Ok,
                );
            }
            Err(error) => {
                self.metrics.record_dependency(
                    ManagedDependencyCall::SetAttributes,
                    dependency_outcome(error),
                );
                return Err(dependency_error());
            }
        }

        // Group membership is an operator convenience for browsing accounts in
        // Authentik; it grants nothing and its failure must never fail or roll
        // back a connection that is otherwise fully functional.
        self.assign_managed_group(account.user_id).await;
        Ok(())
    }

    pub(super) async fn assign_managed_group(&self, user_id: i64) {
        let outcome = match self
            .admin
            .find_group_by_name(&self.settings.managed_group)
            .await
        {
            Ok(Some(group_id)) => match self.admin.add_user_to_group(user_id, &group_id).await {
                Ok(()) => ManagedDependencyOutcome::Ok,
                Err(error) => dependency_outcome(error),
            },
            Ok(None) => ManagedDependencyOutcome::NotFound,
            Err(error) => dependency_outcome(error),
        };
        self.metrics
            .record_dependency(ManagedDependencyCall::AssignGroup, outcome);
    }

    /// Deletes the created service account and metadata row after a failed
    /// creation step, or retains a recoverable `cleanup_required` row.
    pub(super) async fn compensate_created_account(
        &self,
        connection_id: &ConnectionId,
        user_id: i64,
        failure: Status,
    ) -> Status {
        let deletion = self.admin.delete_user(user_id).await;
        match deletion {
            Ok(()) | Err(AdminError::NotFound) => {
                self.metrics.record_dependency(
                    ManagedDependencyCall::DeleteUser,
                    deletion.map_or(ManagedDependencyOutcome::NotFound, |()| {
                        ManagedDependencyOutcome::Ok
                    }),
                );
                if self.delete_row(connection_id).await {
                    failure
                } else {
                    cleanup_required(connection_id, self).await
                }
            }
            Err(error) => {
                self.metrics.record_dependency(
                    ManagedDependencyCall::DeleteUser,
                    dependency_outcome(error),
                );
                cleanup_required(connection_id, self).await
            }
        }
    }

    /// Compensates an ambiguous or failed service-account creation.
    pub(super) async fn recover_ambiguous_create(
        &self,
        connection_id: &ConnectionId,
        username: &str,
        error: AdminError,
    ) -> Status {
        // `Invalid` covers two cases the adapter cannot tell apart: a garbled
        // 2xx that Authentik never really committed, and a 2xx that Authentik
        // did commit but whose fields failed this server's own strict
        // validation. Since the second case is a real, live account, `Invalid`
        // must be reconciled the same way as `Ambiguous` rather than assumed
        // definitively absent.
        if !matches!(error, AdminError::Ambiguous | AdminError::Invalid) {
            // Only a transport-level rejection or unavailability is
            // definitive: the request could not have been applied.
            let _ = self.delete_row(connection_id).await;
            return dependency_error();
        }
        // Authentik may have committed the account; probe only the exact
        // generated username and remove only the matching managed account. A
        // single immediate probe cannot distinguish "never created" from "the
        // original request is still processing", so retry with a bounded
        // delay before concluding absence. Even after every retry, retain a
        // `cleanup_required` row rather than deleting it: a create that lands
        // after the last retry can then still be found and revoked, instead
        // of being silently orphaned with no record anywhere.
        for attempt in 0..CREATE_RECONCILIATION_ATTEMPTS {
            if attempt > 0 {
                sleep(CREATE_RECONCILIATION_DELAY).await;
            }
            match self.admin.find_user_by_username(username).await {
                Ok(Some(user)) => {
                    self.metrics.record_dependency(
                        ManagedDependencyCall::FindUser,
                        ManagedDependencyOutcome::Ok,
                    );
                    return self
                        .compensate_created_account(connection_id, user.user_id, dependency_error())
                        .await;
                }
                Ok(None) => {
                    self.metrics.record_dependency(
                        ManagedDependencyCall::FindUser,
                        ManagedDependencyOutcome::Ok,
                    );
                    // Not found on this attempt; keep retrying rather than
                    // concluding absence from a single probe.
                }
                Err(probe_error) => {
                    self.metrics.record_dependency(
                        ManagedDependencyCall::FindUser,
                        dependency_outcome(probe_error),
                    );
                    return cleanup_required(connection_id, self).await;
                }
            }
        }
        cleanup_required(connection_id, self).await
    }

    /// Confirms that no app password remains for the exact managed username.
    ///
    /// This is the authoritative absence check. Deleting or reading the user
    /// depends on object permissions that vanish along with the account, so
    /// Authentik answers those with a refusal rather than "not found". The
    /// token view is global, and Authentik removes a service account's tokens
    /// with it, so an empty result proves no usable credential survives.
    /// Anything other than a definite empty result is treated as unknown.
    pub(super) async fn credential_is_gone(&self, username: &str) -> bool {
        match self.admin.find_app_password_identifiers(username).await {
            Ok(identifiers) => {
                self.metrics.record_dependency(
                    ManagedDependencyCall::FindCredentials,
                    if identifiers.is_empty() {
                        ManagedDependencyOutcome::NotFound
                    } else {
                        ManagedDependencyOutcome::Ok
                    },
                );
                identifiers.is_empty()
            }
            Err(error) => {
                self.metrics.record_dependency(
                    ManagedDependencyCall::FindCredentials,
                    dependency_outcome(error),
                );
                false
            }
        }
    }
}

pub(super) async fn cleanup_required(
    connection_id: &ConnectionId,
    service: &ManagedConnectionsService,
) -> Status {
    let _ = service
        .transition_state(
            connection_id,
            ManagedConnectionState::Provisioning,
            ManagedConnectionState::CleanupRequired,
        )
        .await;
    Status::unavailable(CLEANUP_MESSAGE)
}

pub(super) const fn dependency_outcome(error: AdminError) -> ManagedDependencyOutcome {
    match error {
        AdminError::NotFound => ManagedDependencyOutcome::NotFound,
        AdminError::Rejected => ManagedDependencyOutcome::Rejected,
        AdminError::Unavailable => ManagedDependencyOutcome::Unavailable,
        AdminError::Ambiguous => ManagedDependencyOutcome::Ambiguous,
        AdminError::Invalid => ManagedDependencyOutcome::Invalid,
    }
}
