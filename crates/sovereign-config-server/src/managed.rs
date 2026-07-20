//! Managed application connection lifecycle service.
//!
//! Implements the `ManagedConnections` gRPC service: listing safe metadata,
//! and creating, rotating, and revoking read-only machine connections whose
//! credentials live only in Authentik. Sovereign Config persists non-secret
//! lifecycle metadata and returns each connection URL exactly once.

use std::{sync::Arc, time::Duration};

use sovereign_config_core::{
    ConnectionId, ConnectionUrl, DisplayName, ManagedConnectionState, Secret,
};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use time::OffsetDateTime;
use tonic::{Request, Response, Status};

use crate::auth::{AuthenticatedPrincipal, Permission};
use crate::authentik::{AdminError, AuthentikAdminClient};
use crate::metrics::{
    ManagedConnectionMetrics, ManagedDependencyCall, ManagedDependencyOutcome, ManagedOperation,
    ManagedOperationResult,
};
use sovereign_config_core::ConfigPath;
use sovereign_config_proto::sovereign::config::v3::{
    CreateManagedConnectionRequest, CreateManagedConnectionResponse, ListManagedConnectionsRequest,
    ListManagedConnectionsResponse, ManagedConnectionMetadata as ProtoManagedConnectionMetadata,
    ManagedConnectionState as ProtoManagedConnectionState, RevokeManagedConnectionRequest,
    RevokeManagedConnectionResponse, RotateManagedConnectionRequest,
    RotateManagedConnectionResponse, managed_connections_server::ManagedConnections,
};

const CONNECTION_ID_CHARS: usize = 32;
const APP_PASSWORD_CHARS: usize = 48;
const USERNAME_PREFIX: &str = "sc-managed-";

/// Non-secret settings used to build canonical connection URLs and grants.
pub(crate) struct ManagedSettings {
    pub(crate) public_origin: String,
    pub(crate) issuer: String,
    pub(crate) client_id: String,
    pub(crate) grants_attribute: String,
    /// How long a rotation marked `rotation_unknown` is assumed to still be in
    /// flight. Must exceed the Authentik client timeout so an expired lease
    /// proves the previous attempt has ended.
    pub(crate) rotation_lease: Duration,
}

pub(crate) struct ManagedConnectionsService {
    database: PgPool,
    admin: AuthentikAdminClient,
    settings: ManagedSettings,
    metrics: Arc<ManagedConnectionMetrics>,
}

#[derive(FromRow)]
struct ConnectionRow {
    connection_id: String,
    display_name: String,
    root: String,
    provider_user_id: Option<i64>,
    credential_identifier: Option<String>,
    state: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
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

    fn record<T>(&self, operation: ManagedOperation, result: &Result<T, Status>) {
        let outcome = match result {
            Ok(_) => ManagedOperationResult::Success,
            Err(status) => match status.code() {
                tonic::Code::InvalidArgument => ManagedOperationResult::InvalidRequest,
                tonic::Code::Unauthenticated => ManagedOperationResult::Unauthenticated,
                tonic::Code::PermissionDenied => ManagedOperationResult::PermissionDenied,
                tonic::Code::NotFound => ManagedOperationResult::NotFound,
                tonic::Code::Aborted => ManagedOperationResult::Conflict,
                tonic::Code::Unavailable => match status.message() {
                    STORAGE_MESSAGE => ManagedOperationResult::Storage,
                    CLEANUP_MESSAGE => ManagedOperationResult::CleanupRequired,
                    _ => ManagedOperationResult::Dependency,
                },
                _ => ManagedOperationResult::Internal,
            },
        };
        self.metrics.record_operation(operation, outcome);
    }

    async fn list(
        &self,
        request: &Request<ListManagedConnectionsRequest>,
    ) -> Result<ListManagedConnectionsResponse, Status> {
        let principal = principal(request)?;
        let rows = sqlx::query_as::<_, ConnectionRow>(
            r"
            SELECT connection_id, display_name, root, provider_user_id,
                   credential_identifier, state, created_at, updated_at
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

    async fn create(
        &self,
        request: &Request<CreateManagedConnectionRequest>,
    ) -> Result<CreateManagedConnectionResponse, Status> {
        let principal = principal(request)?;
        let display_name = DisplayName::parse(request.get_ref().display_name.clone())
            .map_err(|_| invalid_request())?;
        let root =
            ConfigPath::parse_selection(&request.get_ref().root).map_err(|_| invalid_request())?;
        if !principal.allows(&root, Permission::Manage) {
            return Err(Status::permission_denied(
                "configuration operation is not permitted",
            ));
        }

        let connection_id = generate_connection_id()?;
        let username = format!("{USERNAME_PREFIX}{}", connection_id.as_str());
        let now = OffsetDateTime::now_utc();
        sqlx::query(
            r"
            INSERT INTO managed_connections
                (connection_id, display_name, root, state, created_at, updated_at)
            VALUES ($1, $2, $3, 'provisioning', $4, $4)
            ",
        )
        .bind(connection_id.as_str())
        .bind(display_name.as_str())
        .bind(root.as_str())
        .bind(now)
        .execute(&self.database)
        .await
        .map_err(|_| storage_unavailable())?;

        self.provision_inserted(&connection_id, &username, &root)
            .await
    }

    /// Runs the external provisioning steps for a freshly inserted row and
    /// compensates on every failure path.
    async fn provision_inserted(
        &self,
        connection_id: &ConnectionId,
        username: &str,
        root: &ConfigPath,
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

        // Record the external identity immediately so a crash from here on
        // leaves a row that revocation can reconcile and clean up.
        if sqlx::query(
            r"
            UPDATE managed_connections
            SET provider_user_id = $2, provider_user_uid = $3, updated_at = $4
            WHERE connection_id = $1
            ",
        )
        .bind(connection_id.as_str())
        .bind(account.user_id)
        .bind(&account.user_uid)
        .bind(OffsetDateTime::now_utc())
        .execute(&self.database)
        .await
        .is_err()
        {
            return Err(self
                .compensate_created_account(connection_id, account.user_id, storage_unavailable())
                .await);
        }

        match self
            .configure_account(connection_id, username, root, &account)
            .await
        {
            Ok(()) => {}
            Err(status) => {
                return Err(self
                    .compensate_created_account(connection_id, account.user_id, status)
                    .await);
            }
        }

        let connection_url = ConnectionUrl::managed(
            &self.settings.public_origin,
            root,
            &self.settings.issuer,
            &self.settings.client_id,
            username,
            &account.app_password,
        )
        .map_err(|_| internal_error());
        let connection_url = match connection_url {
            Ok(url) => url,
            Err(status) => {
                return Err(self
                    .compensate_created_account(connection_id, account.user_id, status)
                    .await);
            }
        };

        let row = match self
            .transition_state(connection_id, ManagedConnectionState::Active)
            .await
        {
            Ok(row) => row,
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

    /// Discovers the single app-password credential, records its identifier,
    /// and patches the exact read-only grant plus managed marker.
    async fn configure_account(
        &self,
        connection_id: &ConnectionId,
        username: &str,
        root: &ConfigPath,
        account: &crate::authentik::CreatedServiceAccount,
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

        if sqlx::query(
            r"
            UPDATE managed_connections
            SET credential_identifier = $2, updated_at = $3
            WHERE connection_id = $1
            ",
        )
        .bind(connection_id.as_str())
        .bind(credential_identifier)
        .bind(OffsetDateTime::now_utc())
        .execute(&self.database)
        .await
        .is_err()
        {
            return Err(storage_unavailable());
        }

        match self
            .admin
            .set_managed_attributes(
                account.user_id,
                connection_id.as_str(),
                &self.settings.grants_attribute,
                root.as_str(),
            )
            .await
        {
            Ok(()) => {
                self.metrics.record_dependency(
                    ManagedDependencyCall::SetAttributes,
                    ManagedDependencyOutcome::Ok,
                );
                Ok(())
            }
            Err(error) => {
                self.metrics.record_dependency(
                    ManagedDependencyCall::SetAttributes,
                    dependency_outcome(error),
                );
                Err(dependency_error())
            }
        }
    }

    async fn rotate(
        &self,
        request: &Request<RotateManagedConnectionRequest>,
    ) -> Result<RotateManagedConnectionResponse, Status> {
        let connection_id = ConnectionId::parse(request.get_ref().connection_id.clone())
            .map_err(|_| invalid_request())?;
        let (row, root) = {
            let principal = principal(request)?;
            let mut transaction = self.begin().await?;
            let row = self
                .lock_manageable(&mut transaction, &connection_id, principal)
                .await?;
            let root = ConfigPath::parse(&row.root).map_err(|_| internal_error())?;
            let state = ManagedConnectionState::parse(&row.state).map_err(|_| internal_error())?;
            // `rotation_unknown` marks both an in-flight rotation and an
            // ambiguous outcome. Re-entering is safe only once the lease has
            // expired, which proves no earlier attempt can still be running;
            // otherwise two rotations would overwrite each other's key and
            // both report a URL as current.
            let recoverable = state == ManagedConnectionState::RotationUnknown
                && OffsetDateTime::now_utc() - row.updated_at >= self.settings.rotation_lease;
            if !(state == ManagedConnectionState::Active || recoverable) {
                return Err(conflict_error());
            }
            if row.credential_identifier.is_none() {
                return Err(conflict_error());
            }
            // The row transitions before the external call so an interruption
            // is always represented as an ambiguous rotation.
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
            (row, root)
        };

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
                            .transition_state(&connection_id, ManagedConnectionState::Active)
                            .await;
                    }
                    // The token is gone; only revocation can clean this up.
                    AdminError::NotFound => {
                        let _ = self
                            .transition_state(
                                &connection_id,
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

        let username = format!("{USERNAME_PREFIX}{}", connection_id.as_str());
        let connection_url = ConnectionUrl::managed(
            &self.settings.public_origin,
            &root,
            &self.settings.issuer,
            &self.settings.client_id,
            &username,
            &replacement,
        )
        .map_err(|_| internal_error())?;
        let row = self
            .transition_state(&connection_id, ManagedConnectionState::Active)
            .await?;
        Ok(RotateManagedConnectionResponse {
            metadata: Some(proto_metadata(&row)?),
            connection_url: connection_url.canonical().expose().to_owned(),
        })
    }

    async fn revoke(
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
            let username = format!("{USERNAME_PREFIX}{}", connection_id.as_str());
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
                    return Err(dependency_error());
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
                // Confirmed absence counts as a completed revocation.
                Err(AdminError::NotFound) => {
                    self.metrics.record_dependency(
                        ManagedDependencyCall::DeleteUser,
                        ManagedDependencyOutcome::NotFound,
                    );
                }
                Err(error) => {
                    self.metrics.record_dependency(
                        ManagedDependencyCall::DeleteUser,
                        dependency_outcome(error),
                    );
                    // Deletion may already have happened: Authentik refuses
                    // rather than reporting "not found" for an account the
                    // manager can no longer see, and a timeout is ambiguous by
                    // definition. Settle it by looking for the account's app
                    // password, which is authoritative because the token view
                    // is global and Authentik cascades the token with the user.
                    let username = format!("{USERNAME_PREFIX}{}", connection_id.as_str());
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

    async fn begin(&self) -> Result<Transaction<'_, Postgres>, Status> {
        self.database
            .begin()
            .await
            .map_err(|_| storage_unavailable())
    }

    /// Locks one row and requires the caller to manage its root; a missing row
    /// and a non-manageable row are externally indistinguishable.
    async fn lock_manageable(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        connection_id: &ConnectionId,
        principal: &AuthenticatedPrincipal,
    ) -> Result<ConnectionRow, Status> {
        let row = sqlx::query_as::<_, ConnectionRow>(
            r"
            SELECT connection_id, display_name, root, provider_user_id,
                   credential_identifier, state, created_at, updated_at
            FROM managed_connections
            WHERE connection_id = $1
            FOR UPDATE
            ",
        )
        .bind(connection_id.as_str())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| storage_unavailable())?
        .ok_or_else(not_found)?;
        let root = ConfigPath::parse(&row.root).map_err(|_| internal_error())?;
        if !principal.allows(&root, Permission::Manage) {
            return Err(not_found());
        }
        Ok(row)
    }

    async fn transition_state(
        &self,
        connection_id: &ConnectionId,
        state: ManagedConnectionState,
    ) -> Result<ConnectionRow, Status> {
        sqlx::query_as::<_, ConnectionRow>(
            r"
            UPDATE managed_connections
            SET state = $2, updated_at = $3
            WHERE connection_id = $1
            RETURNING connection_id, display_name, root, provider_user_id,
                      credential_identifier, state, created_at, updated_at
            ",
        )
        .bind(connection_id.as_str())
        .bind(state.as_str())
        .bind(OffsetDateTime::now_utc())
        .fetch_optional(&self.database)
        .await
        .map_err(|_| storage_unavailable())?
        .ok_or_else(internal_error)
    }

    /// Deletes the created service account and metadata row after a failed
    /// creation step, or retains a recoverable `cleanup_required` row.
    async fn compensate_created_account(
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
    async fn recover_ambiguous_create(
        &self,
        connection_id: &ConnectionId,
        username: &str,
        error: AdminError,
    ) -> Status {
        if error != AdminError::Ambiguous {
            // The account was definitively not created.
            let _ = self.delete_row(connection_id).await;
            return dependency_error();
        }
        // Authentik may have committed the account; probe only the exact
        // generated username and remove only the matching managed account.
        match self.admin.find_user_by_username(username).await {
            Ok(Some(user)) => {
                self.metrics.record_dependency(
                    ManagedDependencyCall::FindUser,
                    ManagedDependencyOutcome::Ok,
                );
                self.compensate_created_account(connection_id, user.user_id, dependency_error())
                    .await
            }
            Ok(None) => {
                self.metrics.record_dependency(
                    ManagedDependencyCall::FindUser,
                    ManagedDependencyOutcome::Ok,
                );
                let _ = self.delete_row(connection_id).await;
                dependency_error()
            }
            Err(probe_error) => {
                self.metrics.record_dependency(
                    ManagedDependencyCall::FindUser,
                    dependency_outcome(probe_error),
                );
                cleanup_required(connection_id, self).await
            }
        }
    }

    /// Confirms that no app password remains for the exact managed username.
    ///
    /// This is the authoritative absence check. Deleting or reading the user
    /// depends on object permissions that vanish along with the account, so
    /// Authentik answers those with a refusal rather than "not found". The
    /// token view is global, and Authentik removes a service account's tokens
    /// with it, so an empty result proves no usable credential survives.
    /// Anything other than a definite empty result is treated as unknown.
    async fn credential_is_gone(&self, username: &str) -> bool {
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

    async fn delete_row(&self, connection_id: &ConnectionId) -> bool {
        sqlx::query("DELETE FROM managed_connections WHERE connection_id = $1")
            .bind(connection_id.as_str())
            .execute(&self.database)
            .await
            .is_ok()
    }
}

async fn cleanup_required(
    connection_id: &ConnectionId,
    service: &ManagedConnectionsService,
) -> Status {
    let _ = service
        .transition_state(connection_id, ManagedConnectionState::CleanupRequired)
        .await;
    Status::unavailable(CLEANUP_MESSAGE)
}

#[allow(clippy::result_large_err)]
fn principal<T>(request: &Request<T>) -> Result<&AuthenticatedPrincipal, Status> {
    request
        .extensions()
        .get::<AuthenticatedPrincipal>()
        .ok_or_else(|| Status::unauthenticated("authentication required"))
}

#[allow(clippy::result_large_err)]
fn proto_metadata(row: &ConnectionRow) -> Result<ProtoManagedConnectionMetadata, Status> {
    let state = ManagedConnectionState::parse(&row.state).map_err(|_| internal_error())?;
    Ok(ProtoManagedConnectionMetadata {
        connection_id: row.connection_id.clone(),
        display_name: row.display_name.clone(),
        root: row.root.clone(),
        state: proto_state(state) as i32,
        created_at: Some(to_proto_timestamp(row.created_at)?),
        updated_at: Some(to_proto_timestamp(row.updated_at)?),
    })
}

const fn proto_state(state: ManagedConnectionState) -> ProtoManagedConnectionState {
    match state {
        ManagedConnectionState::Provisioning => ProtoManagedConnectionState::Provisioning,
        ManagedConnectionState::Active => ProtoManagedConnectionState::Active,
        ManagedConnectionState::RotationUnknown => ProtoManagedConnectionState::RotationUnknown,
        ManagedConnectionState::Revoking => ProtoManagedConnectionState::Revoking,
        ManagedConnectionState::CleanupRequired => ProtoManagedConnectionState::CleanupRequired,
    }
}

#[allow(clippy::result_large_err)]
fn to_proto_timestamp(value: OffsetDateTime) -> Result<prost_types::Timestamp, Status> {
    Ok(prost_types::Timestamp {
        seconds: value.unix_timestamp(),
        nanos: i32::try_from(value.nanosecond()).map_err(|_| internal_error())?,
    })
}

/// Generates an opaque random connection identifier from the OS CSPRNG.
#[allow(clippy::result_large_err)]
fn generate_connection_id() -> Result<ConnectionId, Status> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let value = random_string(ALPHABET, CONNECTION_ID_CHARS)?;
    ConnectionId::parse(value).map_err(|_| internal_error())
}

/// Generates a high-entropy replacement app password from the OS CSPRNG.
#[allow(clippy::result_large_err)]
fn generate_app_password() -> Result<Secret, Status> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    Ok(Secret::new(random_string(ALPHABET, APP_PASSWORD_CHARS)?))
}

/// Draws unbiased characters from the OS CSPRNG with rejection sampling.
#[allow(clippy::result_large_err)]
fn random_string(alphabet: &[u8], length: usize) -> Result<String, Status> {
    debug_assert!(alphabet.len() <= 64);
    let limit = u8::MAX - (u8::MAX % u8::try_from(alphabet.len()).map_err(|_| internal_error())?);
    let mut value = String::with_capacity(length);
    while value.len() < length {
        let mut buffer = [0_u8; 64];
        getrandom::fill(&mut buffer).map_err(|_| internal_error())?;
        for byte in buffer {
            if byte < limit && value.len() < length {
                value.push(char::from(alphabet[usize::from(byte) % alphabet.len()]));
            }
        }
    }
    Ok(value)
}

const STORAGE_MESSAGE: &str = "configuration storage is unavailable";
const CLEANUP_MESSAGE: &str = "managed connection requires cleanup";

const fn dependency_outcome(error: AdminError) -> ManagedDependencyOutcome {
    match error {
        AdminError::NotFound => ManagedDependencyOutcome::NotFound,
        AdminError::Rejected => ManagedDependencyOutcome::Rejected,
        AdminError::Unavailable => ManagedDependencyOutcome::Unavailable,
        AdminError::Ambiguous => ManagedDependencyOutcome::Ambiguous,
        AdminError::Invalid => ManagedDependencyOutcome::Invalid,
    }
}

fn invalid_request() -> Status {
    Status::invalid_argument("managed connection request is invalid")
}

fn not_found() -> Status {
    Status::not_found("managed connection not found")
}

fn conflict_error() -> Status {
    Status::aborted("managed connection operation is already in progress")
}

fn dependency_error() -> Status {
    Status::unavailable("managed connection dependency is unavailable")
}

fn storage_unavailable() -> Status {
    Status::unavailable(STORAGE_MESSAGE)
}

fn internal_error() -> Status {
    Status::internal("managed connection state is invalid")
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        env,
        sync::{
            Arc, Mutex,
            atomic::{AtomicI64, Ordering},
        },
        time::Duration,
    };

    use axum::{
        Json, Router,
        extract::{Path, Query, State},
        http::StatusCode,
        response::{IntoResponse, Response},
        routing::{get, patch, post},
    };
    use reqwest::Url;
    use serde_json::{Value, json};
    use sovereign_config_core::ConnectionUrl;
    use sqlx::postgres::PgPoolOptions;
    use tokio::{net::TcpListener, task::JoinHandle, time::sleep};

    use super::{
        ConnectionRow, ManagedConnectionsService, ManagedSettings, Request, Secret, Status,
        generate_app_password, generate_connection_id,
    };
    use crate::auth::{AuthenticatedPrincipal, Grant, Permission};
    use crate::authentik::AuthentikAdminClient;
    use crate::metrics::ManagedConnectionMetrics;
    use sovereign_config_proto::sovereign::config::v3::{
        CreateManagedConnectionRequest, ListManagedConnectionsRequest,
        RevokeManagedConnectionRequest, RotateManagedConnectionRequest,
        managed_connections_server::ManagedConnections,
    };

    const APP_PASSWORD_SENTINEL: &str = "created-app-password-sentinel";
    const CREDENTIAL_IDENTIFIER: &str = "app-password-identifier-sentinel";
    const PUBLIC_ORIGIN: &str = "https://config.example.test";
    const ISSUER: &str = "https://auth.example.test/application/o/sovereign-config/";
    const GRANTS_ATTRIBUTE: &str = "sovereign_config_test_grants";
    /// Longer than the mock client timeout so an in-flight rotation is
    /// rejected, but short enough to exercise recovery without a long sleep.
    const ROTATION_LEASE: Duration = Duration::from_millis(800);

    /// One scripted outcome for a mocked Authentik route.
    #[derive(Clone)]
    enum Behavior {
        Ok,
        Status(StatusCode),
        Timeout,
        /// Succeed at the transport level but return an unexpected payload.
        Body(String),
        /// Apply the change, then never answer: the caller cannot tell whether
        /// Authentik committed it.
        CommitThenTimeout,
        /// Apply the change, then refuse, as Authentik does once the caller can
        /// no longer see the object.
        CommitThenRefuse,
    }

    #[derive(Clone)]
    struct Script {
        create_account: Behavior,
        set_attributes: Behavior,
        find_user: Behavior,
        find_credentials: Behavior,
        set_credential: Behavior,
        delete_user: Behavior,
        /// Whether a reconciliation lookup should report the account exists.
        user_exists: bool,
        /// Whether the caller may see the service account's app password,
        /// reproducing Authentik's token ownership and permission rules.
        credentials_visible: bool,
        set_credential_delay: Duration,
    }

    impl Default for Script {
        fn default() -> Self {
            Self {
                create_account: Behavior::Ok,
                set_attributes: Behavior::Ok,
                find_user: Behavior::Ok,
                find_credentials: Behavior::Ok,
                set_credential: Behavior::Ok,
                delete_user: Behavior::Ok,
                user_exists: false,
                credentials_visible: true,
                set_credential_delay: Duration::ZERO,
            }
        }
    }

    #[derive(Clone)]
    struct MockState {
        script: Arc<Mutex<Script>>,
        created_users: Arc<Mutex<Vec<String>>>,
        deleted_users: Arc<Mutex<Vec<i64>>>,
        patched_attributes: Arc<Mutex<Vec<Value>>>,
        revoked_usernames: Arc<Mutex<Vec<String>>>,
        usernames_by_id: Arc<Mutex<std::collections::HashMap<i64, String>>>,
        rotated_keys: Arc<Mutex<Vec<String>>>,
        next_user_id: Arc<AtomicI64>,
    }

    struct MockAuthentik {
        origin: Url,
        state: MockState,
        task: JoinHandle<()>,
    }

    impl Drop for MockAuthentik {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl MockAuthentik {
        fn script(&self, update: impl FnOnce(&mut Script)) {
            update(&mut self.state.script.lock().unwrap());
        }

        fn deleted_users(&self) -> Vec<i64> {
            self.state.deleted_users.lock().unwrap().clone()
        }

        fn patched_attributes(&self) -> Vec<Value> {
            self.state.patched_attributes.lock().unwrap().clone()
        }

        fn rotated_keys(&self) -> Vec<String> {
            self.state.rotated_keys.lock().unwrap().clone()
        }
    }

    async fn apply(behavior: &Behavior) -> Option<Response> {
        match behavior {
            // `CommitThenTimeout` applies the change in the handler itself,
            // so it produces no scripted response here.
            Behavior::Ok | Behavior::CommitThenTimeout | Behavior::CommitThenRefuse => None,
            Behavior::Status(status) => Some((*status, "authentik-body-sentinel").into_response()),
            Behavior::Timeout => {
                sleep(Duration::from_secs(30)).await;
                Some((StatusCode::OK, "{}").into_response())
            }
            Behavior::Body(body) => Some((StatusCode::OK, body.clone()).into_response()),
        }
    }

    fn behavior(state: &MockState, select: impl FnOnce(&Script) -> Behavior) -> Behavior {
        select(&state.script.lock().unwrap())
    }

    async fn create_account(State(state): State<MockState>, Json(body): Json<Value>) -> Response {
        if let Some(response) =
            apply(&behavior(&state, |script| script.create_account.clone())).await
        {
            return response;
        }
        let username = body
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let user_pk = state.next_user_id.fetch_add(1, Ordering::Relaxed);
        state.created_users.lock().unwrap().push(username.clone());
        state
            .usernames_by_id
            .lock()
            .unwrap()
            .insert(user_pk, username.clone());
        Json(json!({
            "username": username,
            "user_uid": format!("uid-{user_pk}"),
            "user_pk": user_pk,
            "token": APP_PASSWORD_SENTINEL,
        }))
        .into_response()
    }

    async fn set_attributes(
        State(state): State<MockState>,
        Path(_user_id): Path<i64>,
        Json(body): Json<Value>,
    ) -> Response {
        if let Some(response) =
            apply(&behavior(&state, |script| script.set_attributes.clone())).await
        {
            return response;
        }
        state.patched_attributes.lock().unwrap().push(body);
        Json(json!({})).into_response()
    }

    async fn list_users(
        State(state): State<MockState>,
        Query(query): Query<std::collections::HashMap<String, String>>,
    ) -> Response {
        if let Some(response) = apply(&behavior(&state, |script| script.find_user.clone())).await {
            return response;
        }
        let username = query.get("username").cloned().unwrap_or_default();
        let exists = state.script.lock().unwrap().user_exists;
        let results = if exists {
            json!([{ "pk": 4242, "username": username }])
        } else {
            json!([])
        };
        Json(json!({ "results": results })).into_response()
    }

    /// Mirrors Authentik: results are filtered by the exact `user__username`
    /// and `intent` query parameters, and a token is only visible when the
    /// caller may see it. Returning a token regardless of the query would let
    /// a permission or filter mistake pass unnoticed.
    async fn list_tokens(
        State(state): State<MockState>,
        Query(query): Query<std::collections::HashMap<String, String>>,
    ) -> Response {
        if let Some(response) =
            apply(&behavior(&state, |script| script.find_credentials.clone())).await
        {
            return response;
        }
        let visible = state.script.lock().unwrap().credentials_visible;
        let created = state.created_users.lock().unwrap().clone();
        // Authentik removes a service account's tokens along with the account,
        // so a deleted account must stop yielding a credential.
        let revoked = state.revoked_usernames.lock().unwrap().clone();
        let matches = visible
            && query
                .get("intent")
                .is_some_and(|intent| intent == "app_password")
            && query
                .get("user__username")
                .is_some_and(|username| created.contains(username) && !revoked.contains(username));
        let results = if matches {
            json!([{ "identifier": CREDENTIAL_IDENTIFIER }])
        } else {
            json!([])
        };
        Json(json!({ "results": results })).into_response()
    }

    async fn set_key(
        State(state): State<MockState>,
        Path(_identifier): Path<String>,
        Json(body): Json<Value>,
    ) -> Response {
        let delay = state.script.lock().unwrap().set_credential_delay;
        sleep(delay).await;
        if let Some(response) =
            apply(&behavior(&state, |script| script.set_credential.clone())).await
        {
            return response;
        }
        if let Some(key) = body.get("key").and_then(Value::as_str) {
            state.rotated_keys.lock().unwrap().push(key.to_owned());
        }
        Json(json!({})).into_response()
    }

    /// Serves the detail probe used to confirm deletion by primary key.
    #[allow(clippy::unused_async)]
    async fn get_user(State(state): State<MockState>, Path(user_id): Path<i64>) -> Response {
        let deleted = state.deleted_users.lock().unwrap().contains(&user_id);
        if deleted {
            return StatusCode::NOT_FOUND.into_response();
        }
        Json(json!({ "pk": user_id, "username": "sc-managed-probe" })).into_response()
    }

    async fn delete_user(State(state): State<MockState>, Path(user_id): Path<i64>) -> Response {
        let scripted = behavior(&state, |script| script.delete_user.clone());
        if let Some(response) = apply(&scripted).await {
            return response;
        }
        state.deleted_users.lock().unwrap().push(user_id);
        // Authentik cascades a service account's tokens with the user.
        if let Some(username) = state.usernames_by_id.lock().unwrap().get(&user_id).cloned() {
            state.revoked_usernames.lock().unwrap().push(username);
        }
        if matches!(scripted, Behavior::CommitThenTimeout) {
            sleep(Duration::from_secs(30)).await;
        }
        if matches!(scripted, Behavior::CommitThenRefuse) {
            return (StatusCode::FORBIDDEN, "authentik-body-sentinel").into_response();
        }
        StatusCode::NO_CONTENT.into_response()
    }

    async fn mock_authentik() -> MockAuthentik {
        let state = MockState {
            script: Arc::new(Mutex::new(Script::default())),
            created_users: Arc::new(Mutex::new(Vec::new())),
            deleted_users: Arc::new(Mutex::new(Vec::new())),
            patched_attributes: Arc::new(Mutex::new(Vec::new())),
            revoked_usernames: Arc::new(Mutex::new(Vec::new())),
            usernames_by_id: Arc::new(Mutex::new(std::collections::HashMap::new())),
            rotated_keys: Arc::new(Mutex::new(Vec::new())),
            next_user_id: Arc::new(AtomicI64::new(1000)),
        };
        let app = Router::new()
            .route("/api/v3/core/users/service_account/", post(create_account))
            .route(
                "/api/v3/core/users/{user_id}/",
                patch(set_attributes).delete(delete_user).get(get_user),
            )
            .route("/api/v3/core/users/", get(list_users))
            .route("/api/v3/core/tokens/", get(list_tokens))
            .route("/api/v3/core/tokens/{identifier}/set_key/", post(set_key))
            .with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        MockAuthentik {
            origin: format!("http://{address}/").parse().unwrap(),
            state,
            task,
        }
    }

    fn principal(grants: &[(&str, &[Permission])]) -> AuthenticatedPrincipal {
        AuthenticatedPrincipal {
            subject: "test-subject".to_owned(),
            grants: grants
                .iter()
                .map(|(prefix, permissions)| Grant {
                    prefix: (*prefix).to_owned(),
                    permissions: permissions.iter().copied().collect::<BTreeSet<_>>(),
                })
                .collect(),
        }
    }

    fn manage(prefix: &str) -> AuthenticatedPrincipal {
        principal(&[(prefix, &[Permission::Manage])])
    }

    fn request<T>(message: T, principal: &AuthenticatedPrincipal) -> Request<T> {
        let mut request = Request::new(message);
        request.extensions_mut().insert(principal.clone());
        request
    }

    async fn service(mock: &MockAuthentik) -> Option<ManagedConnectionsService> {
        service_with_metrics(mock, Arc::new(ManagedConnectionMetrics::default())).await
    }

    async fn service_with_metrics(
        mock: &MockAuthentik,
        metrics: Arc<ManagedConnectionMetrics>,
    ) -> Option<ManagedConnectionsService> {
        let database_url = env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL").ok()?;
        let database = PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(5))
            .connect(&database_url)
            .await
            .expect("test database must be reachable");
        sqlx::migrate!("./migrations")
            .run(&database)
            .await
            .expect("migrations must apply");
        sqlx::query("DELETE FROM managed_connections")
            .execute(&database)
            .await
            .expect("managed connection table must be clearable");
        let admin = AuthentikAdminClient::new(
            mock.origin.clone(),
            Secret::new("manager-api-token-sentinel"),
            Duration::from_millis(400),
        )
        .expect("mock admin client must build");
        Some(ManagedConnectionsService::new(
            database,
            admin,
            ManagedSettings {
                public_origin: PUBLIC_ORIGIN.to_owned(),
                issuer: ISSUER.to_owned(),
                client_id: "sovereign-config".to_owned(),
                grants_attribute: GRANTS_ATTRIBUTE.to_owned(),
                rotation_lease: ROTATION_LEASE,
            },
            metrics,
        ))
    }

    async fn rows(service: &ManagedConnectionsService) -> Vec<ConnectionRow> {
        sqlx::query_as::<_, ConnectionRow>(
            r"
            SELECT connection_id, display_name, root, provider_user_id,
                   credential_identifier, state, created_at, updated_at
            FROM managed_connections
            ORDER BY created_at, connection_id
            ",
        )
        .fetch_all(&service.database)
        .await
        .expect("managed connection rows must be readable")
    }

    async fn create(
        service: &ManagedConnectionsService,
        name: &str,
        root: &str,
        principal: &AuthenticatedPrincipal,
    ) -> Result<(String, String), Status> {
        let response = service
            .create_managed_connection(request(
                CreateManagedConnectionRequest {
                    display_name: name.to_owned(),
                    root: root.to_owned(),
                },
                principal,
            ))
            .await?
            .into_inner();
        let metadata = response.metadata.expect("create must return metadata");
        Ok((metadata.connection_id, response.connection_url))
    }

    /// Fails the test when a status message leaks any request-derived value.
    fn assert_bounded(status: &Status) {
        const ALLOWED: [&str; 7] = [
            "configuration storage is unavailable",
            "managed connection dependency is unavailable",
            "managed connection requires cleanup",
            "managed connection not found",
            "managed connection request is invalid",
            "managed connection operation is already in progress",
            "configuration operation is not permitted",
        ];
        let message = status.message();
        assert!(
            ALLOWED.contains(&message),
            "unbounded status message: {message}"
        );
        for sentinel in [
            APP_PASSWORD_SENTINEL,
            CREDENTIAL_IDENTIFIER,
            "authentik-body-sentinel",
            "manager-api-token-sentinel",
            "sc-managed-",
            "Pipeline reader",
        ] {
            assert!(
                !message.contains(sentinel),
                "status message leaked {sentinel}: {message}"
            );
        }
    }

    macro_rules! service_or_skip {
        ($mock:expr) => {
            match service($mock).await {
                Some(service) => service,
                None => return,
            }
        };
    }

    #[test]
    fn generated_identifiers_are_opaque_and_bounded() {
        let first = generate_connection_id().unwrap();
        let second = generate_connection_id().unwrap();

        assert_ne!(first.as_str(), second.as_str());
        assert_eq!(first.as_str().len(), 32);
        assert!(
            first
                .as_str()
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        );

        let password = generate_app_password().unwrap();
        assert_eq!(password.expose().len(), 48);
        assert!(
            password
                .expose()
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric())
        );
        assert_ne!(password.expose(), generate_app_password().unwrap().expose());
    }

    #[tokio::test]
    #[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
    async fn create_provisions_exactly_one_read_only_grant_and_returns_one_url() {
        let mock = mock_authentik().await;
        let service = service_or_skip!(&mock);

        let (connection_id, url) = create(&service, "Pipeline reader", "/apps/api", &manage("/"))
            .await
            .expect("create must succeed");

        let connection = ConnectionUrl::parse(&url).expect("returned URL must be canonical");
        assert_eq!(connection.root().as_str(), "/apps/api");
        assert_eq!(connection.issuer(), ISSUER);
        assert!(connection.client_authentication().is_some());
        assert!(url.starts_with(PUBLIC_ORIGIN));

        let rows = rows(&service).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].connection_id, connection_id);
        assert_eq!(rows[0].state, "active");
        assert_eq!(rows[0].root, "/apps/api");
        assert_eq!(
            rows[0].credential_identifier.as_deref(),
            Some(CREDENTIAL_IDENTIFIER)
        );
        assert!(rows[0].provider_user_id.is_some());

        // The persisted row must never carry credential material.
        let serialized = format!(
            "{}{}{}{}",
            rows[0].connection_id,
            rows[0].display_name,
            rows[0].root,
            rows[0].credential_identifier.clone().unwrap_or_default()
        );
        assert!(!serialized.contains(APP_PASSWORD_SENTINEL));

        let patched = mock.patched_attributes();
        assert_eq!(patched.len(), 1);
        let attributes = &patched[0]["attributes"];
        assert_eq!(
            attributes[GRANTS_ATTRIBUTE],
            json!([{ "prefix": "/apps/api", "permissions": ["read"] }])
        );
        assert_eq!(attributes["sovereign_config_managed"], json!(connection_id));
        assert_eq!(
            attributes["goauthentik.io/user/token-expires"],
            json!(false)
        );
        assert_eq!(
            attributes["goauthentik.io/user/service-account"],
            json!(true)
        );
    }

    #[tokio::test]
    #[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
    async fn authorization_requires_manage_on_the_connection_root() {
        let mock = mock_authentik().await;
        let service = service_or_skip!(&mock);

        // Exact root and ancestor grants both authorize creation.
        create(&service, "Exact", "/apps/api", &manage("/apps/api"))
            .await
            .expect("exact root must authorize");
        create(&service, "Ancestor", "/apps/web", &manage("/apps"))
            .await
            .expect("ancestor root must authorize");

        // A sibling grant and read/write without manage must not.
        let sibling = create(&service, "Sibling", "/apps/api", &manage("/apps/other")).await;
        let status = sibling.expect_err("sibling grant must be denied");
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert_bounded(&status);

        let read_write = principal(&[("/", &[Permission::Read, Permission::Write])]);
        let status = create(&service, "ReadWrite", "/apps/api", &read_write)
            .await
            .expect_err("read and write without manage must be denied");
        assert_eq!(status.code(), tonic::Code::PermissionDenied);

        // Listing only discloses rows the caller can manage.
        let scoped = service
            .list_managed_connections(request(
                ListManagedConnectionsRequest {},
                &manage("/apps/web"),
            ))
            .await
            .expect("list must succeed")
            .into_inner();
        assert_eq!(scoped.connections.len(), 1);
        assert_eq!(scoped.connections[0].root, "/apps/web");

        let global = service
            .list_managed_connections(request(ListManagedConnectionsRequest {}, &manage("/")))
            .await
            .expect("list must succeed")
            .into_inner();
        assert_eq!(global.connections.len(), 2);
    }

    #[tokio::test]
    #[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
    async fn unmanageable_and_missing_connections_are_indistinguishable() {
        let mock = mock_authentik().await;
        let service = service_or_skip!(&mock);
        let (connection_id, _) = create(&service, "Scoped", "/apps/api", &manage("/"))
            .await
            .expect("create must succeed");
        let unknown = "0123456789abcdef0123456789abcdef";

        for id in [connection_id.as_str(), unknown] {
            let rotate = service
                .rotate_managed_connection(request(
                    RotateManagedConnectionRequest {
                        connection_id: id.to_owned(),
                    },
                    &manage("/apps/other"),
                ))
                .await
                .expect_err("non-manageable rotate must fail");
            assert_eq!(rotate.code(), tonic::Code::NotFound);
            assert_eq!(rotate.message(), "managed connection not found");

            let revoke = service
                .revoke_managed_connection(request(
                    RevokeManagedConnectionRequest {
                        connection_id: id.to_owned(),
                    },
                    &manage("/apps/other"),
                ))
                .await
                .expect_err("non-manageable revoke must fail");
            assert_eq!(revoke.code(), tonic::Code::NotFound);
            assert_eq!(revoke.message(), "managed connection not found");
        }
    }

    #[tokio::test]
    #[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
    async fn invalid_and_unauthenticated_requests_are_rejected_before_any_call() {
        let mock = mock_authentik().await;
        let service = service_or_skip!(&mock);
        let global = manage("/");

        for (name, root) in [
            ("", "/apps"),
            ("  padded", "/apps"),
            (&"x".repeat(101), "/apps"),
            ("control\nname", "/apps"),
            ("Valid", "not-rooted"),
            ("Valid", "/Apps/Bad_Name"),
        ] {
            let status = create(&service, name, root, &global)
                .await
                .expect_err("invalid input must be rejected");
            assert_eq!(status.code(), tonic::Code::InvalidArgument);
            assert_bounded(&status);
        }

        let status = service
            .rotate_managed_connection(request(
                RotateManagedConnectionRequest {
                    connection_id: "TOO-SHORT".to_owned(),
                },
                &global,
            ))
            .await
            .expect_err("invalid identifier must be rejected");
        assert_eq!(status.code(), tonic::Code::InvalidArgument);

        // No principal extension at all must fail closed.
        let status = service
            .list_managed_connections(Request::new(ListManagedConnectionsRequest {}))
            .await
            .expect_err("unauthenticated list must be rejected");
        assert_eq!(status.code(), tonic::Code::Unauthenticated);

        assert!(rows(&service).await.is_empty());
        assert!(mock.patched_attributes().is_empty());
    }

    #[tokio::test]
    #[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
    async fn definitive_create_failures_roll_back_without_orphaning_a_credential() {
        let mock = mock_authentik().await;
        let service = service_or_skip!(&mock);

        // Account creation refused outright: nothing to compensate.
        mock.script(|script| script.create_account = Behavior::Status(StatusCode::FORBIDDEN));
        let status = create(&service, "Refused", "/apps/api", &manage("/"))
            .await
            .expect_err("refused creation must fail");
        assert_bounded(&status);
        assert!(rows(&service).await.is_empty());
        assert!(mock.deleted_users().is_empty());

        // Credential discovery returning the wrong count must roll back.
        for body in [
            json!({ "results": [] }).to_string(),
            json!({ "results": [
                { "identifier": "first-identifier" },
                { "identifier": "second-identifier" }
            ] })
            .to_string(),
        ] {
            mock.script(|script| {
                script.create_account = Behavior::Ok;
                script.find_credentials = Behavior::Body(body);
            });
            let status = create(&service, "Ambiguous credential", "/apps/api", &manage("/"))
                .await
                .expect_err("ambiguous credential discovery must fail");
            assert_bounded(&status);
            assert!(rows(&service).await.is_empty(), "row must be rolled back");
            assert!(
                !mock.deleted_users().is_empty(),
                "the created account must be deleted"
            );
        }

        // A failed grant patch must also roll back the created account.
        mock.script(|script| {
            script.find_credentials = Behavior::Ok;
            script.set_attributes = Behavior::Status(StatusCode::FORBIDDEN);
        });
        let before = mock.deleted_users().len();
        let status = create(&service, "Patch failure", "/apps/api", &manage("/"))
            .await
            .expect_err("failed grant patch must fail");
        assert_bounded(&status);
        assert!(rows(&service).await.is_empty());
        assert!(mock.deleted_users().len() > before);
    }

    /// Regression: in production the manager could create the app password but
    /// not see it, because Authentik only shows a non-superuser tokens they own
    /// and the service-account endpoint creates the token with a direct ORM
    /// call. Discovery returned zero rows and creation failed with an
    /// unavailable dependency after rolling the account back.
    #[tokio::test]
    #[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
    async fn unreadable_app_password_rolls_back_and_is_visible_in_metrics() {
        let mock = mock_authentik().await;
        let metrics = Arc::new(ManagedConnectionMetrics::default());
        let Some(service) = service_with_metrics(&mock, Arc::clone(&metrics)).await else {
            return;
        };
        mock.script(|script| script.credentials_visible = false);

        let status = create(&service, "Invisible credential", "/apps/api", &manage("/"))
            .await
            .expect_err("an undiscoverable credential must fail creation");
        assert_bounded(&status);

        // The account must not be left behind with a usable credential.
        assert!(rows(&service).await.is_empty());
        assert!(!mock.deleted_users().is_empty());

        // The failure must be attributable from metrics alone, which is what
        // made the production incident diagnosable.
        let rendered = metrics.render();
        assert!(
            rendered.contains(
                "sovereign_config_managed_dependency_total{call=\"find_credentials\",outcome=\"invalid\"} 1"
            ),
            "an unreadable credential must record a bounded dependency failure"
        );
        assert!(rendered.contains(
            "sovereign_config_managed_dependency_total{call=\"set_attributes\",outcome=\"ok\"} 0"
        ));
    }

    #[tokio::test]
    #[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
    async fn ambiguous_creation_reconciles_only_the_exact_generated_account() {
        let mock = mock_authentik().await;
        let service = service_or_skip!(&mock);

        // Authentik times out but did commit the account.
        mock.script(|script| {
            script.create_account = Behavior::Timeout;
            script.user_exists = true;
        });
        let status = create(&service, "Ambiguous", "/apps/api", &manage("/"))
            .await
            .expect_err("ambiguous creation must not return a URL");
        assert_bounded(&status);
        assert_eq!(
            mock.deleted_users(),
            [4242],
            "only the reconciled account may be deleted"
        );
        assert!(rows(&service).await.is_empty());

        // Ambiguous creation where compensation is also unavailable must
        // retain a recoverable cleanup_required row rather than silently
        // orphaning a usable credential.
        mock.script(|script| {
            script.create_account = Behavior::Timeout;
            script.user_exists = true;
            script.delete_user = Behavior::Status(StatusCode::INTERNAL_SERVER_ERROR);
        });
        let status = create(&service, "Unrecoverable", "/apps/api", &manage("/"))
            .await
            .expect_err("unrecoverable compensation must fail");
        assert_eq!(status.message(), "managed connection requires cleanup");
        assert_bounded(&status);
        let rows = rows(&service).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, "cleanup_required");
    }

    #[tokio::test]
    #[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
    async fn rotation_replaces_the_credential_and_recovers_from_ambiguity() {
        let mock = mock_authentik().await;
        let service = service_or_skip!(&mock);
        let (connection_id, first_url) = create(&service, "Rotating", "/apps/api", &manage("/"))
            .await
            .expect("create must succeed");
        let rotate_request = || {
            request(
                RotateManagedConnectionRequest {
                    connection_id: connection_id.clone(),
                },
                &manage("/"),
            )
        };

        let rotated = service
            .rotate_managed_connection(rotate_request())
            .await
            .expect("rotation must succeed")
            .into_inner();
        assert_ne!(rotated.connection_url, first_url);
        let connection =
            ConnectionUrl::parse(&rotated.connection_url).expect("rotated URL must be canonical");
        assert_eq!(connection.root().as_str(), "/apps/api");
        assert_eq!(rows(&service).await[0].state, "active");
        assert_eq!(mock.rotated_keys().len(), 1);

        // A definitive rejection leaves the previous credential current.
        mock.script(|script| script.set_credential = Behavior::Status(StatusCode::BAD_REQUEST));
        let status = service
            .rotate_managed_connection(rotate_request())
            .await
            .expect_err("rejected rotation must fail");
        assert_bounded(&status);
        assert_eq!(rows(&service).await[0].state, "active");

        // A timeout is ambiguous: no URL, and the row records the ambiguity.
        mock.script(|script| script.set_credential = Behavior::Timeout);
        let status = service
            .rotate_managed_connection(rotate_request())
            .await
            .expect_err("ambiguous rotation must fail");
        assert_bounded(&status);
        assert_eq!(rows(&service).await[0].state, "rotation_unknown");

        // While the lease is unexpired the ambiguous rotation may still be in
        // flight, so a further attempt must be refused rather than overlapping.
        mock.script(|script| script.set_credential = Behavior::Ok);
        let status = service
            .rotate_managed_connection(rotate_request())
            .await
            .expect_err("rotation within the lease must be refused");
        assert_eq!(status.code(), tonic::Code::Aborted);
        assert_bounded(&status);

        // Once the lease expires the earlier attempt cannot still be running,
        // so an explicit retry overwrites the key with a known fresh value.
        sleep(ROTATION_LEASE).await;
        let recovered = service
            .rotate_managed_connection(rotate_request())
            .await
            .expect("retried rotation must succeed")
            .into_inner();
        assert_ne!(recovered.connection_url, rotated.connection_url);
        assert_eq!(rows(&service).await[0].state, "active");
    }

    #[tokio::test]
    #[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
    async fn concurrent_rotation_never_issues_two_current_credentials() {
        let mock = mock_authentik().await;
        let service = service_or_skip!(&mock);
        let (connection_id, _) = create(&service, "Concurrent", "/apps/api", &manage("/"))
            .await
            .expect("create must succeed");
        mock.script(|script| script.set_credential_delay = Duration::from_millis(120));

        let first = service.rotate_managed_connection(request(
            RotateManagedConnectionRequest {
                connection_id: connection_id.clone(),
            },
            &manage("/"),
        ));
        let second = service.rotate_managed_connection(request(
            RotateManagedConnectionRequest {
                connection_id: connection_id.clone(),
            },
            &manage("/"),
        ));
        let (first, second) = tokio::join!(first, second);

        let succeeded = usize::from(first.is_ok()) + usize::from(second.is_ok());
        assert_eq!(
            succeeded, 1,
            "exactly one concurrent rotation may report a current credential"
        );
        for status in [first.err(), second.err()].into_iter().flatten() {
            assert_eq!(status.code(), tonic::Code::Aborted);
            assert_bounded(&status);
        }
        // Only the winning rotation may have replaced the credential.
        assert_eq!(mock.rotated_keys().len(), 1);
        let rows = rows(&service).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, "active");
    }

    #[tokio::test]
    #[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
    async fn revocation_confirms_deletion_before_removing_metadata() {
        let mock = mock_authentik().await;
        let service = service_or_skip!(&mock);
        let (connection_id, _) = create(&service, "Revoked", "/apps/api", &manage("/"))
            .await
            .expect("create must succeed");
        let revoke_request = || {
            request(
                RevokeManagedConnectionRequest {
                    connection_id: connection_id.clone(),
                },
                &manage("/"),
            )
        };

        // An unavailable dependency must retain a retryable row.
        mock.script(|script| script.delete_user = Behavior::Timeout);
        let status = service
            .revoke_managed_connection(revoke_request())
            .await
            .expect_err("ambiguous revocation must fail");
        assert_bounded(&status);
        let rows_after = rows(&service).await;
        assert_eq!(rows_after.len(), 1);
        assert_eq!(rows_after[0].state, "revoking");

        // Retrying after recovery confirms deletion and removes metadata.
        mock.script(|script| script.delete_user = Behavior::Ok);
        service
            .revoke_managed_connection(revoke_request())
            .await
            .expect("retried revocation must succeed");
        assert!(rows(&service).await.is_empty());
        assert!(!mock.deleted_users().is_empty());
    }

    /// An ambiguous deletion is settled by checking the app password, which is
    /// authoritative because the token view is global and the token cascades with
    /// the account, so revocation is not reported as failed when Authentik
    /// already committed the delete.
    #[tokio::test]
    #[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
    async fn ambiguous_deletion_is_confirmed_by_credential_absence() {
        let mock = mock_authentik().await;
        let service = service_or_skip!(&mock);
        let (connection_id, _) = create(&service, "Ambiguous delete", "/apps/api", &manage("/"))
            .await
            .expect("create must succeed");

        // Authentik commits the deletion but the response never arrives.
        mock.script(|script| script.delete_user = Behavior::CommitThenTimeout);
        service
            .revoke_managed_connection(request(
                RevokeManagedConnectionRequest { connection_id },
                &manage("/"),
            ))
            .await
            .expect("a committed deletion must be confirmed despite the timeout");

        assert!(rows(&service).await.is_empty());
    }

    /// Regression: Authentik refuses user deletes for an account the manager
    /// can no longer see rather than reporting "not found", so treating only
    /// "not found" as confirmation left the last connection stuck in
    /// `revoking` forever. Absence is confirmed through the app password,
    /// whose view is global and which cascades with the account.
    #[tokio::test]
    #[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
    async fn revocation_is_confirmed_when_deletion_is_refused_but_the_credential_is_gone() {
        let mock = mock_authentik().await;
        let service = service_or_skip!(&mock);
        let (connection_id, _) = create(&service, "Refused delete", "/apps/api", &manage("/"))
            .await
            .expect("create must succeed");

        // Authentik commits the deletion, then refuses every later request
        // about an account the manager can no longer see.
        mock.script(|script| script.delete_user = Behavior::CommitThenRefuse);
        service
            .revoke_managed_connection(request(
                RevokeManagedConnectionRequest {
                    connection_id: connection_id.clone(),
                },
                &manage("/"),
            ))
            .await
            .expect("a refused delete with no surviving credential must confirm revocation");
        assert!(rows(&service).await.is_empty());
    }

    /// A refusal while the credential still exists must not be reported as a
    /// successful revocation.
    #[tokio::test]
    #[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
    async fn revocation_is_not_confirmed_while_the_credential_survives() {
        let mock = mock_authentik().await;
        let service = service_or_skip!(&mock);
        let (connection_id, _) = create(&service, "Surviving", "/apps/api", &manage("/"))
            .await
            .expect("create must succeed");

        mock.script(|script| script.delete_user = Behavior::Status(StatusCode::FORBIDDEN));
        let status = service
            .revoke_managed_connection(request(
                RevokeManagedConnectionRequest { connection_id },
                &manage("/"),
            ))
            .await
            .expect_err("a surviving credential must not be reported as revoked");
        assert_bounded(&status);

        let rows = rows(&service).await;
        assert_eq!(rows.len(), 1, "the row must remain for retry");
        assert_eq!(rows[0].state, "revoking");
    }

    #[tokio::test]
    #[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
    async fn revocation_treats_a_confirmed_absent_account_as_revoked() {
        let mock = mock_authentik().await;
        let service = service_or_skip!(&mock);
        let (connection_id, _) = create(&service, "Already gone", "/apps/api", &manage("/"))
            .await
            .expect("create must succeed");

        mock.script(|script| script.delete_user = Behavior::Status(StatusCode::NOT_FOUND));
        service
            .revoke_managed_connection(request(
                RevokeManagedConnectionRequest { connection_id },
                &manage("/"),
            ))
            .await
            .expect("confirmed absence must count as revoked");

        assert!(rows(&service).await.is_empty());
    }
}
