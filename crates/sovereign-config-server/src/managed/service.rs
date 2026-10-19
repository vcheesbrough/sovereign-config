//! The `ManagedConnections` service, in no protocol version's terms: request
//! validation, authorization, outcome metrics, and the create / rotate /
//! revoke flows.
//!
//! Inputs arrive unvalidated — raw strings, and a permission selection that is
//! `None` when it had no version-free form — because validating them is this
//! layer's job, in an order that is part of the behaviour every protocol
//! version promises. Nothing here may import the proto crate: a version is a
//! shim over this file (`v3`), never a branch in it.

use std::{sync::Arc, time::Duration};

use sovereign_config_core::{
    ConfigPath, ConnectionId, ConnectionUrl, DisplayName, ManagedConnectionState,
    ManagedPermission, ManagedPermissions,
};
use sqlx::PgPool;
use time::OffsetDateTime;
use tonic::Status;
use tracing::{info, warn};

use sovereign_config_identity::{AccountId, ManagedIdentityProvider, ProviderError};

use super::identity::{generate_connection_id, managed_username};
use super::provisioning::{AccountName, CLEANUP_MESSAGE, dependency_outcome};
use super::store::{ConnectionRow, commit, mark_revoking, mark_rotation_unknown};
use super::wire::{
    ConnectionMetadata, ProvisionedConnection, conflict_error, dependency_error, internal_error,
    invalid_request, metadata,
};
use crate::audit::{AuditEvent, AuditRecorder, ConnectionSubject};
use crate::auth::Permission;
use crate::metrics::{
    ManagedConnectionMetrics, ManagedDependencyCall, ManagedDependencyOutcome, ManagedOperation,
    ManagedOperationResult,
};
use crate::rpc::{CallContext, STORAGE_UNAVAILABLE_MESSAGE};

/// Non-secret settings used to build canonical connection URLs. The client id
/// a URL carries is the identity provider's, returned with each credential.
pub(crate) struct ManagedSettings {
    pub(crate) public_origin: String,
    pub(crate) issuer: String,
    /// How long a rotation marked `rotation_unknown` is assumed to still be in
    /// flight. Must exceed the identity provider's call timeout so an expired
    /// lease proves the previous attempt has ended.
    pub(crate) rotation_lease: Duration,
}

pub(crate) struct ManagedConnectionsService {
    pub(super) database: PgPool,
    pub(super) provider: Arc<dyn ManagedIdentityProvider>,
    pub(super) settings: ManagedSettings,
    pub(super) metrics: Arc<ManagedConnectionMetrics>,
    pub(super) audit: AuditRecorder,
}

/// Maps a selected managed permission onto the server authorization
/// permission used for the anti-escalation check on the connection root.
const fn required_permission(permission: ManagedPermission) -> Permission {
    match permission {
        ManagedPermission::Read => Permission::Read,
        ManagedPermission::Write => Permission::Write,
        ManagedPermission::Manage => Permission::Manage,
    }
}

/// How a failed operation is counted.
fn refusal_outcome(status: &Status) -> ManagedOperationResult {
    match status.code() {
        tonic::Code::InvalidArgument => ManagedOperationResult::InvalidRequest,
        tonic::Code::Unauthenticated => ManagedOperationResult::Unauthenticated,
        tonic::Code::PermissionDenied => ManagedOperationResult::PermissionDenied,
        tonic::Code::NotFound => ManagedOperationResult::NotFound,
        tonic::Code::Aborted => ManagedOperationResult::Conflict,
        tonic::Code::Unavailable => match status.message() {
            STORAGE_UNAVAILABLE_MESSAGE => ManagedOperationResult::Storage,
            CLEANUP_MESSAGE => ManagedOperationResult::CleanupRequired,
            _ => ManagedOperationResult::Dependency,
        },
        _ => ManagedOperationResult::Internal,
    }
}

/// The operations a protocol shim calls. Each records its outcome here, so a
/// version can neither forget the metric nor count a call twice.
impl ManagedConnectionsService {
    pub(super) async fn list_managed_connections(
        &self,
        context: &CallContext<'_>,
    ) -> Result<Vec<ConnectionMetadata>, Status> {
        let result = self.list(context).await;
        self.record(ManagedOperation::List, &result);
        result
    }

    pub(super) async fn create_managed_connection(
        &self,
        context: &CallContext<'_>,
        display_name: &str,
        root: &str,
        permissions: Option<ManagedPermissions>,
    ) -> Result<ProvisionedConnection, Status> {
        let result = self.create(context, display_name, root, permissions).await;
        self.record(ManagedOperation::Create, &result);
        result
    }

    pub(super) async fn rotate_managed_connection(
        &self,
        context: &CallContext<'_>,
        connection_id: &str,
    ) -> Result<ProvisionedConnection, Status> {
        let result = self.rotate(context, connection_id).await;
        self.record(ManagedOperation::Rotate, &result);
        result
    }

    pub(super) async fn revoke_managed_connection(
        &self,
        context: &CallContext<'_>,
        connection_id: &str,
    ) -> Result<(), Status> {
        let result = self.revoke(context, connection_id).await;
        self.record(ManagedOperation::Revoke, &result);
        result
    }
}

impl ManagedConnectionsService {
    pub(crate) fn new(
        database: PgPool,
        provider: Arc<dyn ManagedIdentityProvider>,
        settings: ManagedSettings,
        metrics: Arc<ManagedConnectionMetrics>,
        audit: AuditRecorder,
    ) -> Self {
        Self {
            database,
            provider,
            settings,
            metrics,
            audit,
        }
    }

    /// A request a version's shim refused before calling in, counted exactly
    /// as the same refusal made here would be. Returns the refusal.
    pub(super) fn refused(&self, operation: ManagedOperation, status: Status) -> Status {
        self.metrics
            .record_operation(operation, refusal_outcome(&status));
        status
    }

    pub(super) fn record<T>(&self, operation: ManagedOperation, result: &Result<T, Status>) {
        let outcome = match result {
            Ok(_) => ManagedOperationResult::Success,
            Err(status) => refusal_outcome(status),
        };
        self.metrics.record_operation(operation, outcome);
    }

    pub(super) async fn list(
        &self,
        context: &CallContext<'_>,
    ) -> Result<Vec<ConnectionMetadata>, Status> {
        let principal = context.principal()?;
        let rows = self.list_rows().await?;
        let mut connections = Vec::new();
        for row in rows {
            let root = ConfigPath::parse(&row.root).map_err(|_| internal_error())?;
            if principal.allows(&root, Permission::Manage) {
                connections.push(metadata(&row)?);
            }
        }
        Ok(connections)
    }

    pub(super) async fn create(
        &self,
        context: &CallContext<'_>,
        display_name: &str,
        root: &str,
        permissions: Option<ManagedPermissions>,
    ) -> Result<ProvisionedConnection, Status> {
        let principal = context.principal()?;
        let actor = context.actor()?;
        let display_name = DisplayName::parse(display_name).map_err(|_| invalid_request())?;
        let root = ConfigPath::parse_selection(root).map_err(|_| invalid_request())?;
        // Managed connection roots are out of scope for case retention (card
        // #294): `managed_connections.root` has no display column, and
        // `ConnectionUrl` requires an exactly-lowercase root to round-trip.
        // Fold immediately so every use below — the stored row, the
        // identity provider's grant, the connection URL — sees only the fold,
        // regardless of the case the caller requested it in.
        let root = ConfigPath::parse(root.fold()).expect("a fold of a valid path is valid");
        // A non-empty selection is required; an empty or malformed set is a
        // client error, never a silent default.
        let permissions = permissions.ok_or_else(invalid_request)?;
        // Using the feature at all requires Manage on the root, and no access
        // URL may be granted a permission the caller does not itself hold on
        // that root — a manage-only principal cannot mint a write-capable URL.
        if !principal.allows(&root, Permission::Manage)
            || permissions
                .iter()
                .any(|permission| !principal.allows(&root, required_permission(permission)))
        {
            return Err(Status::permission_denied(
                "configuration operation is not permitted",
            ));
        }

        let connection_id = generate_connection_id()?;
        let username = managed_username(&connection_id, display_name.as_str());
        self.insert_provisioning(&connection_id, &display_name, &root, &permissions)
            .await?;

        let event = AuditEvent::connection_created(
            &actor,
            ConnectionSubject {
                root: root.as_str(),
                display_name: display_name.as_str(),
                connection_id: connection_id.as_str(),
            },
            &permissions.as_storage(),
        );
        let provisioned = self
            .provision_inserted(
                &connection_id,
                AccountName {
                    username: &username,
                    display_name: display_name.as_str(),
                },
                &root,
                &permissions,
                (&actor, event),
            )
            .await?;
        info!(
            connection_id = connection_id.as_str(),
            "managed connection created"
        );
        Ok(provisioned)
    }

    /// Locks the row, validates it is rotatable, and transitions it to
    /// `rotation_unknown` before the external call so an interruption is
    /// always represented as an ambiguous rotation.
    pub(super) async fn begin_rotation(
        &self,
        connection_id: &ConnectionId,
        context: &CallContext<'_>,
    ) -> Result<(ConnectionRow, ConfigPath), Status> {
        let principal = context.principal()?;
        let mut transaction = self.begin().await?;
        let row = self
            .lock_manageable(&mut transaction, connection_id, principal)
            .await?;
        let root = ConfigPath::parse(&row.root).map_err(|_| internal_error())?;
        let state = ManagedConnectionState::parse(&row.state).map_err(|_| internal_error())?;
        // `rotation_unknown` marks both an in-flight rotation and an
        // ambiguous outcome. Re-entering is safe only once the lease has
        // expired, which proves the *client* side of no earlier attempt
        // can still be waiting; otherwise two rotations would overwrite
        // each other's key and both report a URL as current.
        //
        // Residual risk (accepted, not closed): the lease bounds how long
        // our own client waits for a response, not how long the provider may
        // keep processing a request whose response we already gave up on.
        // If the original replacement is slow enough to land after a
        // later successful retry, it can silently overwrite the key again
        // and invalidate the URL just returned to the caller. Closing this
        // fully would need a precondition or idempotency mechanism on the
        // provider's credential replacement, which the provider does not offer;
        // until then this narrow race is a known, accepted gap rather than
        // a guarantee.
        let recoverable = state == ManagedConnectionState::RotationUnknown
            && OffsetDateTime::now_utc() - row.updated_at >= self.settings.rotation_lease;
        if !(state == ManagedConnectionState::Active || recoverable) {
            return Err(conflict_error());
        }
        if row.credential_identifier.is_none() {
            return Err(conflict_error());
        }
        mark_rotation_unknown(&mut transaction, connection_id).await?;
        commit(transaction).await?;
        Ok((row, root))
    }

    pub(super) async fn rotate(
        &self,
        context: &CallContext<'_>,
        connection_id: &str,
    ) -> Result<ProvisionedConnection, Status> {
        let connection_id = ConnectionId::parse(connection_id).map_err(|_| invalid_request())?;
        let (row, root) = self.begin_rotation(&connection_id, context).await?;
        let actor = context.actor()?;

        let credential = row.credential().ok_or_else(internal_error)?;
        let username = managed_username(&connection_id, &row.display_name);
        let replacement = match self.provider.replace_credential(&credential).await {
            Ok(replacement) => {
                self.metrics.record_dependency(
                    ManagedDependencyCall::SetCredential,
                    ManagedDependencyOutcome::Ok,
                );
                replacement
            }
            Err(error) => {
                self.metrics.record_dependency(
                    ManagedDependencyCall::SetCredential,
                    dependency_outcome(error),
                );
                self.settle_failed_rotation(&connection_id, &username, error)
                    .await;
                return Err(dependency_error());
            }
        };

        let connection_url = ConnectionUrl::managed(
            &self.settings.public_origin,
            &root,
            &self.settings.issuer,
            replacement.client_id(),
            &username,
            replacement.secret(),
        )
        .map_err(|_| internal_error())?;
        // If a concurrent revoke already claimed the row (it is no longer
        // `rotation_unknown`), the replacement credential was still applied
        // externally, but the row is being torn down; reporting this
        // rotation's URL as current would hand out a credential that is
        // about to be revoked.
        //
        // The rotation is recorded with this transition, which is what makes
        // it complete. Should the record fail, the row stays
        // `rotation_unknown` and the caller is told the rotation failed —
        // the same outcome as any other storage fault at this step, and one
        // a later rotation recovers from once the lease expires.
        let event = AuditEvent::connection_rotated(
            &actor,
            ConnectionSubject {
                root: root.as_str(),
                display_name: &row.display_name,
                connection_id: connection_id.as_str(),
            },
        );
        let Some(row) = self
            .transition_state_recorded(
                &connection_id,
                ManagedConnectionState::RotationUnknown,
                ManagedConnectionState::Active,
                &actor,
                event,
            )
            .await?
        else {
            warn!(
                connection_id = connection_id.as_str(),
                "the new credential was applied, but a concurrent revocation claimed the connection; the rotation is not reported as current"
            );
            return Err(dependency_error());
        };
        info!(
            connection_id = connection_id.as_str(),
            "managed connection rotated"
        );
        Ok(ProvisionedConnection {
            metadata: metadata(&row)?,
            connection_url,
        })
    }

    pub(super) async fn revoke(
        &self,
        context: &CallContext<'_>,
        connection_id: &str,
    ) -> Result<(), Status> {
        let connection_id = ConnectionId::parse(connection_id).map_err(|_| invalid_request())?;
        let row = self.claim_for_revocation(context, &connection_id).await?;
        let actor = context.actor()?;
        let username = managed_username(&connection_id, &row.display_name);
        if let Some(account) = self.revocation_target(&row, &username).await? {
            self.delete_account_confirmed(&connection_id, &account, &username)
                .await?;
        }
        let event = AuditEvent::connection_revoked(
            &actor,
            ConnectionSubject {
                root: &row.root,
                display_name: &row.display_name,
                connection_id: connection_id.as_str(),
            },
        );
        self.delete_connection_recorded(&connection_id, &actor, event)
            .await?;
        info!(
            connection_id = connection_id.as_str(),
            "managed connection revoked"
        );
        Ok(())
    }

    /// Locks a manageable row and marks it `revoking`, so a concurrent
    /// rotation cannot report its URL as current.
    async fn claim_for_revocation(
        &self,
        context: &CallContext<'_>,
        connection_id: &ConnectionId,
    ) -> Result<ConnectionRow, Status> {
        let principal = context.principal()?;
        let mut transaction = self.begin().await?;
        let row = self
            .lock_manageable(&mut transaction, connection_id, principal)
            .await?;
        mark_revoking(&mut transaction, connection_id).await?;
        commit(transaction).await?;
        Ok(row)
    }

    /// The identity provider's account to delete for a revocation, if one
    /// exists.
    async fn revocation_target(
        &self,
        row: &ConnectionRow,
        username: &str,
    ) -> Result<Option<AccountId>, Status> {
        if let Some(account) = row.account() {
            return Ok(Some(account));
        }
        // The account may never have been created; probe only the
        // exact generated username before declaring it absent.
        match self.provider.find_account(username).await {
            Ok(found) => {
                self.metrics.record_dependency(
                    ManagedDependencyCall::FindUser,
                    ManagedDependencyOutcome::Ok,
                );
                Ok(found)
            }
            Err(error) => {
                self.metrics
                    .record_dependency(ManagedDependencyCall::FindUser, dependency_outcome(error));
                // The lookup may be refused for an account the manager
                // can no longer see rather than reporting it missing.
                // Settle it via the credential, whose absence the provider
                // contract makes authoritative.
                if !self.credential_is_gone(username).await {
                    warn!(
                        connection_id = row.connection_id.as_str(),
                        "revocation could neither find the account nor confirm its credential is gone; the connection stays revoking"
                    );
                    return Err(dependency_error());
                }
                Ok(None)
            }
        }
    }

    /// Deletes the account, or confirms it is already gone. The row stays
    /// `revoking` on failure, so revocation can be retried until absence is
    /// confirmed.
    async fn delete_account_confirmed(
        &self,
        connection_id: &ConnectionId,
        account: &AccountId,
        username: &str,
    ) -> Result<(), Status> {
        match self.provider.delete_account(account).await {
            Ok(()) => {
                self.metrics.record_dependency(
                    ManagedDependencyCall::DeleteUser,
                    ManagedDependencyOutcome::Ok,
                );
            }
            Err(error) => {
                self.metrics.record_dependency(
                    ManagedDependencyCall::DeleteUser,
                    dependency_outcome(error),
                );
                // Deletion may already have happened: a provider may refuse,
                // or report "not found", for an account the manager can no
                // longer see, and a timeout is ambiguous by definition.
                // Settle it by looking for the account's credential, whose
                // absence the provider contract makes authoritative.
                // Trusting `NotFound` on its own would let a lost delete
                // permission orphan a still-live credential.
                if !self.credential_is_gone(username).await {
                    // The row stays `revoking`; revocation can be retried
                    // until absence is confirmed.
                    warn!(
                        connection_id = connection_id.as_str(),
                        "revocation could not confirm the account's credential is gone; the connection stays revoking"
                    );
                    return Err(dependency_error());
                }
            }
        }
        Ok(())
    }

    /// Settles a rotation whose credential write failed, according to whether
    /// the failure proves the previous credential is still current.
    async fn settle_failed_rotation(
        &self,
        connection_id: &ConnectionId,
        username: &str,
        error: ProviderError,
    ) {
        let credential_gone = match error {
            // Undelivered: nothing changed, so the previous credential is
            // still current.
            ProviderError::Unavailable => false,
            // Refused before mutation — but a provider may refuse, rather
            // than report missing, a credential it no longer has or hides.
            // Only the credential lookup, whose empty answer the contract
            // makes authoritative, tells "still current" from "gone"; when
            // it cannot answer either, the outcome is as unknown as an
            // ambiguous one, and settles the same way.
            ProviderError::Rejected => {
                let Some(gone) = self.credential_gone(username).await else {
                    warn!(
                        connection_id = connection_id.as_str(),
                        "rotation was refused and whether the credential still exists could not be confirmed; the connection stays rotation_unknown until its lease expires and a retry settles it"
                    );
                    return;
                };
                gone
            }
            ProviderError::NotFound => true,
            // Ambiguous: the provider may have applied the new key.
            ProviderError::Ambiguous | ProviderError::Invalid => {
                warn!(
                    connection_id = connection_id.as_str(),
                    "rotation outcome is unknown; the connection stays rotation_unknown until its lease expires and a retry settles it"
                );
                return;
            }
        };
        let settled = if credential_gone {
            // The credential is gone; only revocation can clean this up.
            warn!(
                connection_id = connection_id.as_str(),
                "the credential to rotate no longer exists; the connection requires cleanup by revocation"
            );
            ManagedConnectionState::CleanupRequired
        } else {
            warn!(
                connection_id = connection_id.as_str(),
                "rotation failed before the credential changed; the previous URL stays current"
            );
            ManagedConnectionState::Active
        };
        let _ = self
            .transition_state(
                connection_id,
                ManagedConnectionState::RotationUnknown,
                settled,
            )
            .await;
    }
}
