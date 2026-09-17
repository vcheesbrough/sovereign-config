//! Managed application connection lifecycle service.
//!
//! Implements the `ManagedConnections` gRPC service: listing safe metadata,
//! and creating, rotating, and revoking machine connections whose credentials
//! live only in Authentik. Each connection carries an operator-selected
//! permission set (read/write/manage) on its root. Sovereign Config persists
//! non-secret lifecycle metadata and returns each connection URL exactly once.

use std::{sync::Arc, time::Duration};

use sovereign_config_core::{
    ConnectionId, ConnectionUrl, DisplayName, ManagedConnectionState, ManagedPermission,
    ManagedPermissions, Secret,
};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use time::OffsetDateTime;
use tokio::time::sleep;
use tonic::{Request, Response, Status};

use crate::auth::{AuthenticatedPrincipal, Permission};
use crate::authentik::{AdminError, AuthentikAdminClient};
use crate::metrics::{
    ManagedConnectionMetrics, ManagedDependencyCall, ManagedDependencyOutcome, ManagedOperation,
    ManagedOperationResult,
};
use crate::rpc::{STORAGE_UNAVAILABLE_MESSAGE, principal, storage_unavailable, to_proto_timestamp};
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
const USERNAME_SLUG_MAX_CHARS: usize = 32;
/// How many times to re-probe for a possibly-delayed create before giving up
/// on finding it. A single immediate probe cannot distinguish "never
/// created" from "the original request is still processing".
const CREATE_RECONCILIATION_ATTEMPTS: u32 = 3;
/// Delay between reconciliation probes, giving a slow-but-still-processing
/// original create request a bounded chance to land before every retry is
/// exhausted.
const CREATE_RECONCILIATION_DELAY: Duration = Duration::from_millis(500);

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

/// Builds the Authentik username for a connection, embedding a slug of the
/// display name so operators can recognize the account in Authentik, with the
/// opaque connection ID guaranteeing uniqueness regardless of display-name
/// collisions. The connection ID alone is used only when the display name
/// contains no characters that survive slugging.
fn managed_username(connection_id: &ConnectionId, display_name: &str) -> String {
    let slug = username_slug(display_name);
    if slug.is_empty() {
        format!("{USERNAME_PREFIX}{}", connection_id.as_str())
    } else {
        format!("{USERNAME_PREFIX}{slug}-{}", connection_id.as_str())
    }
}

/// Lowercases and collapses a display name to `[a-z0-9-]`, bounded to
/// [`USERNAME_SLUG_MAX_CHARS`] characters with no leading or trailing hyphen.
fn username_slug(display_name: &str) -> String {
    let mut slug = String::with_capacity(USERNAME_SLUG_MAX_CHARS);
    for character in display_name.chars() {
        let lower = character.to_ascii_lowercase();
        if lower.is_ascii_alphanumeric() {
            if slug.len() >= USERNAME_SLUG_MAX_CHARS {
                break;
            }
            slug.push(lower);
        } else if !slug.is_empty() && !slug.ends_with('-') && slug.len() < USERNAME_SLUG_MAX_CHARS {
            slug.push('-');
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    slug
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
    permissions: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
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
                    STORAGE_UNAVAILABLE_MESSAGE => ManagedOperationResult::Storage,
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

    async fn create(
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

    /// Runs the external provisioning steps for a freshly inserted row and
    /// compensates on every failure path.
    async fn provision_inserted(
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
            .configure_account(connection_id, username, root, permissions, &account)
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
            .transition_state(
                connection_id,
                ManagedConnectionState::Provisioning,
                ManagedConnectionState::Active,
            )
            .await
        {
            Ok(Some(row)) => row,
            Ok(None) => {
                return Err(self
                    .compensate_created_account(connection_id, account.user_id, internal_error())
                    .await);
            }
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
    /// and patches the exact selected grant plus managed marker.
    async fn configure_account(
        &self,
        connection_id: &ConnectionId,
        username: &str,
        root: &ConfigPath,
        permissions: &ManagedPermissions,
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

    async fn assign_managed_group(&self, user_id: i64) {
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

    /// Locks the row, validates it is rotatable, and transitions it to
    /// `rotation_unknown` before the external call so an interruption is
    /// always represented as an ambiguous rotation.
    async fn begin_rotation(
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

    async fn rotate(
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
                   credential_identifier, state, permissions, created_at, updated_at
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

    /// Compare-and-set transition: only moves the row when it is still in
    /// `expected_state`. Returns `None` (rather than an error) when a
    /// concurrent operation already moved the row, so callers can decide
    /// whether that is a no-op or a failure without a spurious error being
    /// mistaken for a storage fault.
    async fn transition_state(
        &self,
        connection_id: &ConnectionId,
        expected_state: ManagedConnectionState,
        state: ManagedConnectionState,
    ) -> Result<Option<ConnectionRow>, Status> {
        sqlx::query_as::<_, ConnectionRow>(
            r"
            UPDATE managed_connections
            SET state = $3, updated_at = $4
            WHERE connection_id = $1 AND state = $2
            RETURNING connection_id, display_name, root, provider_user_id,
                      credential_identifier, state, permissions, created_at, updated_at
            ",
        )
        .bind(connection_id.as_str())
        .bind(expected_state.as_str())
        .bind(state.as_str())
        .bind(OffsetDateTime::now_utc())
        .fetch_optional(&self.database)
        .await
        .map_err(|_| storage_unavailable())
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
        .transition_state(
            connection_id,
            ManagedConnectionState::Provisioning,
            ManagedConnectionState::CleanupRequired,
        )
        .await;
    Status::unavailable(CLEANUP_MESSAGE)
}

#[expect(
    clippy::result_large_err,
    reason = "tonic::Status is the crate's RPC error type and is returned by value"
)]
fn proto_metadata(row: &ConnectionRow) -> Result<ProtoManagedConnectionMetadata, Status> {
    let state = ManagedConnectionState::parse(&row.state).map_err(|_| internal_error())?;
    let permissions = ManagedPermissions::parse(&row.permissions).map_err(|_| internal_error())?;
    Ok(ProtoManagedConnectionMetadata {
        connection_id: row.connection_id.clone(),
        display_name: row.display_name.clone(),
        root: row.root.clone(),
        state: proto_state(state) as i32,
        permissions: permissions.to_proto(),
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

/// Generates an opaque random connection identifier from the OS CSPRNG.
#[expect(
    clippy::result_large_err,
    reason = "tonic::Status is the crate's RPC error type and is returned by value"
)]
fn generate_connection_id() -> Result<ConnectionId, Status> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let value = random_string(ALPHABET, CONNECTION_ID_CHARS)?;
    ConnectionId::parse(value).map_err(|_| internal_error())
}

/// Generates a high-entropy replacement app password from the OS CSPRNG.
#[expect(
    clippy::result_large_err,
    reason = "tonic::Status is the crate's RPC error type and is returned by value"
)]
fn generate_app_password() -> Result<Secret, Status> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    Ok(Secret::new(random_string(ALPHABET, APP_PASSWORD_CHARS)?))
}

/// Draws unbiased characters from the OS CSPRNG with rejection sampling.
#[expect(
    clippy::result_large_err,
    reason = "tonic::Status is the crate's RPC error type and is returned by value"
)]
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

fn internal_error() -> Status {
    Status::internal("managed connection state is invalid")
}

#[cfg(test)]
mod tests;
