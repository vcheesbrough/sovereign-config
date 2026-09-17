//! The tonic `ManagedConnections` impl: request validation, authorization,
//! outcome metrics, and the create / rotate / revoke flows.

use std::{sync::Arc, time::Duration};

use sovereign_config_core::{
    ConfigPath, ConnectionId, ConnectionUrl, DisplayName, ManagedConnectionState,
    ManagedPermission, ManagedPermissions,
};
use sovereign_config_proto::sovereign::config::v3::{
    CreateManagedConnectionRequest, CreateManagedConnectionResponse, ListManagedConnectionsRequest,
    ListManagedConnectionsResponse, RevokeManagedConnectionRequest,
    RevokeManagedConnectionResponse, RotateManagedConnectionRequest,
    RotateManagedConnectionResponse, managed_connections_server::ManagedConnections,
};
use sqlx::PgPool;
use time::OffsetDateTime;
use tonic::{Request, Response, Status};

use super::identity::{generate_app_password, generate_connection_id, managed_username};
use super::provisioning::{CLEANUP_MESSAGE, dependency_outcome};
use super::store::ConnectionRow;
use super::wire::{
    conflict_error, dependency_error, internal_error, invalid_request, proto_metadata,
};
use crate::auth::Permission;
use crate::authentik::{AdminError, AuthentikAdminClient};
use crate::metrics::{
    ManagedConnectionMetrics, ManagedDependencyCall, ManagedDependencyOutcome, ManagedOperation,
    ManagedOperationResult,
};
use crate::rpc::{STORAGE_UNAVAILABLE_MESSAGE, principal, storage_unavailable};

/// Non-secret settings used to build canonical connection URLs and grants.
pub(crate) struct ManagedSettings {
    pub(crate) public_origin: String,
    pub(crate) issuer: String,
    pub(crate) client_id: String,
    pub(crate) grants_attribute: String,
    /// Exact name of the Authentik group each managed service account is
    /// added to, purely so an operator can browse them together. Best-effort:
    /// a connection is fully functional whether or not this succeeds.
    pub(crate) managed_group: String,
    /// How long a rotation marked `rotation_unknown` is assumed to still be in
    /// flight. Must exceed the Authentik client timeout so an expired lease
    /// proves the previous attempt has ended.
    pub(crate) rotation_lease: Duration,
}

pub(crate) struct ManagedConnectionsService {
    pub(super) database: PgPool,
    pub(super) admin: AuthentikAdminClient,
    pub(super) settings: ManagedSettings,
    pub(super) metrics: Arc<ManagedConnectionMetrics>,
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

#[tonic::async_trait]
impl ManagedConnections for ManagedConnectionsService {
    async fn list_managed_connections(
        &self,
        request: Request<ListManagedConnectionsRequest>,
    ) -> Result<Response<ListManagedConnectionsResponse>, Status> {
        let result = self.list(&request).await;
        self.record(ManagedOperation::List, &result);
        result.map(Response::new)
    }

    async fn create_managed_connection(
        &self,
        request: Request<CreateManagedConnectionRequest>,
    ) -> Result<Response<CreateManagedConnectionResponse>, Status> {
        let result = self.create(&request).await;
        self.record(ManagedOperation::Create, &result);
        result.map(Response::new)
    }

    async fn rotate_managed_connection(
        &self,
        request: Request<RotateManagedConnectionRequest>,
    ) -> Result<Response<RotateManagedConnectionResponse>, Status> {
        let result = self.rotate(&request).await;
        self.record(ManagedOperation::Rotate, &result);
        result.map(Response::new)
    }

    async fn revoke_managed_connection(
        &self,
        request: Request<RevokeManagedConnectionRequest>,
    ) -> Result<Response<RevokeManagedConnectionResponse>, Status> {
        let result = self.revoke(&request).await;
        self.record(ManagedOperation::Revoke, &result);
        result.map(Response::new)
    }
}

impl ManagedConnectionsService {
    pub(crate) fn new(
        database: PgPool,
        admin: AuthentikAdminClient,
        settings: ManagedSettings,
        metrics: Arc<ManagedConnectionMetrics>,
    ) -> Self {
        Self {
            database,
            admin,
            settings,
            metrics,
        }
    }

    pub(super) fn record<T>(&self, operation: ManagedOperation, result: &Result<T, Status>) {
        let outcome = match result {
            Ok(_) => ManagedOperationResult::Success,
            Err(status) => match status.code() {
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
            },
        };
        self.metrics.record_operation(operation, outcome);
    }

    pub(super) async fn list(
        &self,
        request: &Request<ListManagedConnectionsRequest>,
    ) -> Result<ListManagedConnectionsResponse, Status> {
        let principal = principal(request)?;
        let rows = sqlx::query_as::<_, ConnectionRow>(
            r"
            SELECT connection_id, display_name, root, provider_user_id,
                   credential_identifier, state, permissions, created_at, updated_at
            FROM managed_connections
            ORDER BY created_at, connection_id
            ",
        )
        .fetch_all(&self.database)
        .await
        .map_err(|_| storage_unavailable())?;
        let mut connections = Vec::new();
        for row in rows {
            let root = ConfigPath::parse(&row.root).map_err(|_| internal_error())?;
            if principal.allows(&root, Permission::Manage) {
                connections.push(proto_metadata(&row)?);
            }
        }
        Ok(ListManagedConnectionsResponse { connections })
    }

    pub(super) async fn create(
        &self,
        request: &Request<CreateManagedConnectionRequest>,
    ) -> Result<CreateManagedConnectionResponse, Status> {
        let principal = principal(request)?;
        let display_name = DisplayName::parse(request.get_ref().display_name.clone())
            .map_err(|_| invalid_request())?;
        let root =
            ConfigPath::parse_selection(&request.get_ref().root).map_err(|_| invalid_request())?;
        // Managed connection roots are out of scope for case retention (card
        // #294): `managed_connections.root` has no display column, and
        // `ConnectionUrl` requires an exactly-lowercase root to round-trip.
        // Fold immediately so every use below — the stored row, the
        // Authentik grant attribute, the connection URL — sees only the fold,
        // regardless of the case the caller requested it in.
        let root = ConfigPath::parse(root.fold()).expect("a fold of a valid path is valid");
        // A non-empty selection is required; an empty or malformed set is a
        // client error, never a silent default.
        let permissions = ManagedPermissions::from_proto(&request.get_ref().permissions)
            .map_err(|_| invalid_request())?;
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
        let now = OffsetDateTime::now_utc();
        sqlx::query(
            r"
            INSERT INTO managed_connections
                (connection_id, display_name, root, state, permissions, created_at, updated_at)
            VALUES ($1, $2, $3, 'provisioning', $4, $5, $5)
            ",
        )
        .bind(connection_id.as_str())
        .bind(display_name.as_str())
        .bind(root.as_str())
        .bind(permissions.as_storage())
        .bind(now)
        .execute(&self.database)
        .await
        .map_err(|_| storage_unavailable())?;

        self.provision_inserted(&connection_id, &username, &root, &permissions)
            .await
    }

    /// Locks the row, validates it is rotatable, and transitions it to
    /// `rotation_unknown` before the external call so an interruption is
    /// always represented as an ambiguous rotation.
    pub(super) async fn begin_rotation(
        &self,
        connection_id: &ConnectionId,
        request: &Request<RotateManagedConnectionRequest>,
    ) -> Result<(ConnectionRow, ConfigPath), Status> {
        let principal = principal(request)?;
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
        // our own client waits for a response, not how long Authentik may
        // keep processing a request whose response we already gave up on.
        // If the original `set_key` call is slow enough to land after a
        // later successful retry, it can silently overwrite the key again
        // and invalidate the URL just returned to the caller. Closing this
        // fully would need a precondition or idempotency mechanism on
        // Authentik's `set_key` endpoint that does not currently exist;
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
        sqlx::query(
            r"
            UPDATE managed_connections
            SET state = 'rotation_unknown', updated_at = $2
            WHERE connection_id = $1
            ",
        )
        .bind(connection_id.as_str())
        .bind(OffsetDateTime::now_utc())
        .execute(&mut *transaction)
        .await
        .map_err(|_| storage_unavailable())?;
        transaction
            .commit()
            .await
            .map_err(|_| storage_unavailable())?;
        Ok((row, root))
    }

    pub(super) async fn rotate(
        &self,
        request: &Request<RotateManagedConnectionRequest>,
    ) -> Result<RotateManagedConnectionResponse, Status> {
        let connection_id = ConnectionId::parse(request.get_ref().connection_id.clone())
            .map_err(|_| invalid_request())?;
        let (row, root) = self.begin_rotation(&connection_id, request).await?;

        let credential_identifier = row
            .credential_identifier
            .as_deref()
            .ok_or_else(internal_error)?;
        let replacement = generate_app_password()?;
        match self
            .admin
            .set_credential_secret(credential_identifier, &replacement)
            .await
        {
            Ok(()) => {
                self.metrics.record_dependency(
                    ManagedDependencyCall::SetCredential,
                    ManagedDependencyOutcome::Ok,
                );
            }
            Err(error) => {
                self.metrics.record_dependency(
                    ManagedDependencyCall::SetCredential,
                    dependency_outcome(error),
                );
                match error {
                    // Definitive rejection before mutation: the previous
                    // credential is still current.
                    AdminError::Rejected | AdminError::Unavailable => {
                        let _ = self
                            .transition_state(
                                &connection_id,
                                ManagedConnectionState::RotationUnknown,
                                ManagedConnectionState::Active,
                            )
                            .await;
                    }
                    // The token is gone; only revocation can clean this up.
                    AdminError::NotFound => {
                        let _ = self
                            .transition_state(
                                &connection_id,
                                ManagedConnectionState::RotationUnknown,
                                ManagedConnectionState::CleanupRequired,
                            )
                            .await;
                    }
                    // Ambiguous: Authentik may have applied the new key.
                    AdminError::Ambiguous | AdminError::Invalid => {}
                }
                return Err(dependency_error());
            }
        }

        let username = managed_username(&connection_id, &row.display_name);
        let connection_url = ConnectionUrl::managed(
            &self.settings.public_origin,
            &root,
            &self.settings.issuer,
            &self.settings.client_id,
            &username,
            &replacement,
        )
        .map_err(|_| internal_error())?;
        // If a concurrent revoke already claimed the row (it is no longer
        // `rotation_unknown`), the replacement credential was still applied
        // externally, but the row is being torn down; reporting this
        // rotation's URL as current would hand out a credential that is
        // about to be revoked.
        let Some(row) = self
            .transition_state(
                &connection_id,
                ManagedConnectionState::RotationUnknown,
                ManagedConnectionState::Active,
            )
            .await?
        else {
            return Err(dependency_error());
        };
        Ok(RotateManagedConnectionResponse {
            metadata: Some(proto_metadata(&row)?),
            connection_url: connection_url.canonical().expose().to_owned(),
        })
    }

    pub(super) async fn revoke(
        &self,
        request: &Request<RevokeManagedConnectionRequest>,
    ) -> Result<RevokeManagedConnectionResponse, Status> {
        let connection_id = ConnectionId::parse(request.get_ref().connection_id.clone())
            .map_err(|_| invalid_request())?;
        let row = {
            let principal = principal(request)?;
            let mut transaction = self.begin().await?;
            let row = self
                .lock_manageable(&mut transaction, &connection_id, principal)
                .await?;
            sqlx::query(
                r"
                UPDATE managed_connections
                SET state = 'revoking', updated_at = $2
                WHERE connection_id = $1
                ",
            )
            .bind(connection_id.as_str())
            .bind(OffsetDateTime::now_utc())
            .execute(&mut *transaction)
            .await
            .map_err(|_| storage_unavailable())?;
            transaction
                .commit()
                .await
                .map_err(|_| storage_unavailable())?;
            row
        };

        let user_id = if let Some(user_id) = row.provider_user_id {
            Some(user_id)
        } else {
            // The account may never have been created; probe only the
            // exact generated username before declaring it absent.
            let username = managed_username(&connection_id, &row.display_name);
            match self.admin.find_user_by_username(&username).await {
                Ok(found) => {
                    self.metrics.record_dependency(
                        ManagedDependencyCall::FindUser,
                        ManagedDependencyOutcome::Ok,
                    );
                    found.map(|user| user.user_id)
                }
                Err(error) => {
                    self.metrics.record_dependency(
                        ManagedDependencyCall::FindUser,
                        dependency_outcome(error),
                    );
                    // The lookup may be refused for an account the manager
                    // can no longer see rather than reporting it missing.
                    // Settle it via the app password, which is authoritative
                    // because the token view is global and cascades with
                    // the account.
                    if !self.credential_is_gone(&username).await {
                        return Err(dependency_error());
                    }
                    None
                }
            }
        };

        if let Some(user_id) = user_id {
            match self.admin.delete_user(user_id).await {
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
                    // Deletion may already have happened: Authentik refuses,
                    // or reports "not found", rather than reporting "not
                    // found" consistently for an account the manager can no
                    // longer see (the live RBAC test exercises both), and a
                    // timeout is ambiguous by definition. Settle it by
                    // looking for the account's app password, which is
                    // authoritative because the token view is global and
                    // Authentik cascades the token with the user. Trusting
                    // `NotFound` on its own would let a lost delete
                    // permission orphan a still-live credential.
                    let username = managed_username(&connection_id, &row.display_name);
                    if !self.credential_is_gone(&username).await {
                        // The row stays `revoking`; revocation can be retried
                        // until absence is confirmed.
                        return Err(dependency_error());
                    }
                }
            }
        }

        sqlx::query("DELETE FROM managed_connections WHERE connection_id = $1")
            .bind(connection_id.as_str())
            .execute(&self.database)
            .await
            .map_err(|_| storage_unavailable())?;
        Ok(RevokeManagedConnectionResponse {})
    }
}
