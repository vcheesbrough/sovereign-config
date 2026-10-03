//! Every `PostgreSQL` row type and query behind the `ManagedConnections`
//! service.

use sovereign_config_core::{
    ConfigPath, ConnectionId, DisplayName, ManagedConnectionState, ManagedPermissions,
};
use sqlx::{FromRow, Postgres, Transaction};
use time::OffsetDateTime;
use tonic::Status;
use tracing::{field::Empty, instrument};

use super::ManagedConnectionsService;
use super::wire::{internal_error, not_found};
use crate::audit::{Actor, AuditEvent};
use crate::auth::{AuthenticatedPrincipal, Permission};
use crate::authentik::CreatedServiceAccount;
use crate::rpc::store_unavailable;

/// A connection whose service account exists or did, as the name repair
/// (#440) reads it.
#[derive(FromRow)]
pub(super) struct AccountRow {
    pub(super) connection_id: String,
    pub(super) display_name: String,
    pub(super) provider_user_id: Option<i64>,
    pub(super) provider_user_uid: String,
    pub(super) state: String,
}

#[derive(FromRow)]
pub(super) struct ConnectionRow {
    pub(super) connection_id: String,
    pub(super) display_name: String,
    pub(super) root: String,
    pub(super) provider_user_id: Option<i64>,
    pub(super) credential_identifier: Option<String>,
    pub(super) state: String,
    pub(super) permissions: String,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl ManagedConnectionsService {
    #[instrument(
        name = "begin",
        skip_all,
        fields(otel.kind = "client", otel.status_code = Empty, error.type = Empty, db.system.name = "postgresql", db.operation.name = "begin")
    )]
    pub(super) async fn begin(&self) -> Result<Transaction<'_, Postgres>, Status> {
        self.database.begin().await.map_err(|_| store_unavailable())
    }

    /// Locks one row and requires the caller to manage its root; a missing row
    /// and a non-manageable row are externally indistinguishable.
    #[instrument(
        name = "lock_manageable managed_connections",
        skip_all,
        fields(otel.kind = "client", otel.status_code = Empty, error.type = Empty, db.system.name = "postgresql", db.operation.name = "lock_manageable", db.collection.name = "managed_connections")
    )]
    pub(super) async fn lock_manageable(
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
        .map_err(|_| store_unavailable())?
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
    #[instrument(
        name = "transition_state managed_connections",
        skip_all,
        fields(otel.kind = "client", otel.status_code = Empty, error.type = Empty, db.system.name = "postgresql", db.operation.name = "transition_state", db.collection.name = "managed_connections")
    )]
    pub(super) async fn transition_state(
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
        .map_err(|_| store_unavailable())
    }

    /// [`Self::transition_state`] for the transition that *completes* an
    /// operation, recording `event` in the same transaction.
    ///
    /// These flows call Authentik between their database steps, so there is no
    /// one transaction to put the audit record in. The last step is the one
    /// that makes the operation visible as done, so that is the one the record
    /// is atomic with: if the record cannot be written the row stays in the
    /// intermediate state it was already in, which is exactly the state the
    /// rest of this service recovers from — a compensated create, a
    /// re-rotatable `rotation_unknown`. Nothing is recorded when a concurrent
    /// operation already moved the row.
    #[instrument(
        name = "transition_state_recorded managed_connections",
        skip_all,
        fields(otel.kind = "client", otel.status_code = Empty, error.type = Empty, db.system.name = "postgresql", db.operation.name = "transition_state_recorded", db.collection.name = "managed_connections")
    )]
    pub(super) async fn transition_state_recorded(
        &self,
        connection_id: &ConnectionId,
        expected_state: ManagedConnectionState,
        state: ManagedConnectionState,
        actor: &Actor<'_>,
        event: AuditEvent<'_>,
    ) -> Result<Option<ConnectionRow>, Status> {
        let mut transaction = self.begin().await?;
        let now = OffsetDateTime::now_utc();
        let row = sqlx::query_as::<_, ConnectionRow>(
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
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| store_unavailable())?;
        if row.is_some() {
            self.audit
                .record_in(&mut transaction, actor, now, &[event])
                .await?;
        }
        commit(transaction).await?;
        Ok(row)
    }

    /// Deletes a revoked connection's row and records the revocation, in one
    /// transaction. A failure leaves the row `revoking`, and revocation can be
    /// retried until it is both gone and recorded. A row a concurrent revoke
    /// already removed is recorded by that revoke, not twice.
    #[instrument(
        name = "delete_connection_recorded managed_connections",
        skip_all,
        fields(otel.kind = "client", otel.status_code = Empty, error.type = Empty, db.system.name = "postgresql", db.operation.name = "delete_connection_recorded", db.collection.name = "managed_connections")
    )]
    pub(super) async fn delete_connection_recorded(
        &self,
        connection_id: &ConnectionId,
        actor: &Actor<'_>,
        event: AuditEvent<'_>,
    ) -> Result<(), Status> {
        let mut transaction = self.begin().await?;
        let deleted = sqlx::query("DELETE FROM managed_connections WHERE connection_id = $1")
            .bind(connection_id.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(|_| store_unavailable())?;
        if deleted.rows_affected() > 0 {
            self.audit
                .record_in(&mut transaction, actor, OffsetDateTime::now_utc(), &[event])
                .await?;
        }
        commit(transaction).await
    }

    pub(super) async fn delete_row(&self, connection_id: &ConnectionId) -> bool {
        self.delete_connection(connection_id).await.is_ok()
    }

    #[instrument(
        name = "delete_connection managed_connections",
        skip_all,
        fields(otel.kind = "client", otel.status_code = Empty, error.type = Empty, db.system.name = "postgresql", db.operation.name = "delete_connection", db.collection.name = "managed_connections")
    )]
    pub(super) async fn delete_connection(
        &self,
        connection_id: &ConnectionId,
    ) -> Result<(), Status> {
        sqlx::query("DELETE FROM managed_connections WHERE connection_id = $1")
            .bind(connection_id.as_str())
            .execute(&self.database)
            .await
            .map_err(|_| store_unavailable())?;
        Ok(())
    }

    /// Every connection row, oldest first.
    #[instrument(
        name = "list_rows managed_connections",
        skip_all,
        fields(otel.kind = "client", otel.status_code = Empty, error.type = Empty, db.system.name = "postgresql", db.operation.name = "list_rows", db.collection.name = "managed_connections")
    )]
    pub(super) async fn list_rows(&self) -> Result<Vec<ConnectionRow>, Status> {
        sqlx::query_as::<_, ConnectionRow>(
            r"
            SELECT connection_id, display_name, root, provider_user_id,
                   credential_identifier, state, permissions, created_at, updated_at
            FROM managed_connections
            ORDER BY created_at, connection_id
            ",
        )
        .fetch_all(&self.database)
        .await
        .map_err(|_| store_unavailable())
    }

    /// Every connection whose service account's subject is recorded, oldest
    /// first.
    #[instrument(
        name = "list_accounts managed_connections",
        skip_all,
        fields(otel.kind = "client", otel.status_code = Empty, error.type = Empty, db.system.name = "postgresql", db.operation.name = "list_accounts", db.collection.name = "managed_connections")
    )]
    pub(super) async fn list_accounts(&self) -> Result<Vec<AccountRow>, Status> {
        sqlx::query_as::<_, AccountRow>(
            r"
            SELECT connection_id, display_name, provider_user_id, provider_user_uid, state
            FROM managed_connections
            WHERE provider_user_uid IS NOT NULL
            ORDER BY created_at, connection_id
            ",
        )
        .fetch_all(&self.database)
        .await
        .map_err(|_| store_unavailable())
    }

    /// Whether the one-time name repair (#440) has completed.
    #[instrument(
        name = "name_repair_completed managed_name_repair",
        skip_all,
        fields(otel.kind = "client", otel.status_code = Empty, error.type = Empty, db.system.name = "postgresql", db.operation.name = "name_repair_completed", db.collection.name = "managed_name_repair")
    )]
    pub(super) async fn name_repair_completed(&self) -> Result<bool, Status> {
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM managed_name_repair)")
            .fetch_one(&self.database)
            .await
            .map_err(|_| store_unavailable())
    }

    /// Records that the one-time name repair (#440) has completed.
    #[instrument(
        name = "complete_name_repair managed_name_repair",
        skip_all,
        fields(otel.kind = "client", otel.status_code = Empty, error.type = Empty, db.system.name = "postgresql", db.operation.name = "complete_name_repair", db.collection.name = "managed_name_repair")
    )]
    pub(super) async fn complete_name_repair(&self) -> Result<(), Status> {
        sqlx::query(
            "INSERT INTO managed_name_repair (completed_at) VALUES (now()) ON CONFLICT DO NOTHING",
        )
        .execute(&self.database)
        .await
        .map(|_| ())
        .map_err(|_| store_unavailable())
    }

    /// Inserts a new connection in `provisioning`, before any external call.
    #[instrument(
        name = "insert_provisioning managed_connections",
        skip_all,
        fields(otel.kind = "client", otel.status_code = Empty, error.type = Empty, db.system.name = "postgresql", db.operation.name = "insert_provisioning", db.collection.name = "managed_connections")
    )]
    pub(super) async fn insert_provisioning(
        &self,
        connection_id: &ConnectionId,
        display_name: &DisplayName,
        root: &ConfigPath,
        permissions: &ManagedPermissions,
    ) -> Result<(), Status> {
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
        .map_err(|_| store_unavailable())?;
        Ok(())
    }

    #[instrument(
        name = "record_provider_user managed_connections",
        skip_all,
        fields(otel.kind = "client", otel.status_code = Empty, error.type = Empty, db.system.name = "postgresql", db.operation.name = "record_provider_user", db.collection.name = "managed_connections")
    )]
    pub(super) async fn record_provider_user(
        &self,
        connection_id: &ConnectionId,
        account: &CreatedServiceAccount,
    ) -> Result<(), Status> {
        sqlx::query(
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
        .map_err(|_| store_unavailable())?;
        Ok(())
    }

    #[instrument(
        name = "record_credential_identifier managed_connections",
        skip_all,
        fields(otel.kind = "client", otel.status_code = Empty, error.type = Empty, db.system.name = "postgresql", db.operation.name = "record_credential_identifier", db.collection.name = "managed_connections")
    )]
    pub(super) async fn record_credential_identifier(
        &self,
        connection_id: &ConnectionId,
        credential_identifier: &str,
    ) -> Result<(), Status> {
        sqlx::query(
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
        .map_err(|_| store_unavailable())?;
        Ok(())
    }
}

#[instrument(
    name = "commit",
    skip_all,
    fields(otel.kind = "client", otel.status_code = Empty, error.type = Empty, db.system.name = "postgresql", db.operation.name = "commit")
)]
pub(super) async fn commit(transaction: Transaction<'_, Postgres>) -> Result<(), Status> {
    transaction.commit().await.map_err(|_| store_unavailable())
}

/// Marks a locked row `rotation_unknown` before the external call, so an
/// interruption is always represented as an ambiguous rotation.
#[instrument(
    name = "mark_rotation_unknown managed_connections",
    skip_all,
    fields(otel.kind = "client", otel.status_code = Empty, error.type = Empty, db.system.name = "postgresql", db.operation.name = "mark_rotation_unknown", db.collection.name = "managed_connections")
)]
pub(super) async fn mark_rotation_unknown(
    transaction: &mut Transaction<'_, Postgres>,
    connection_id: &ConnectionId,
) -> Result<(), Status> {
    sqlx::query(
        r"
            UPDATE managed_connections
            SET state = 'rotation_unknown', updated_at = $2
            WHERE connection_id = $1
            ",
    )
    .bind(connection_id.as_str())
    .bind(OffsetDateTime::now_utc())
    .execute(&mut **transaction)
    .await
    .map_err(|_| store_unavailable())?;
    Ok(())
}

/// Marks a locked row `revoking`.
#[instrument(
    name = "mark_revoking managed_connections",
    skip_all,
    fields(otel.kind = "client", otel.status_code = Empty, error.type = Empty, db.system.name = "postgresql", db.operation.name = "mark_revoking", db.collection.name = "managed_connections")
)]
pub(super) async fn mark_revoking(
    transaction: &mut Transaction<'_, Postgres>,
    connection_id: &ConnectionId,
) -> Result<(), Status> {
    sqlx::query(
        r"
                UPDATE managed_connections
                SET state = 'revoking', updated_at = $2
                WHERE connection_id = $1
                ",
    )
    .bind(connection_id.as_str())
    .bind(OffsetDateTime::now_utc())
    .execute(&mut **transaction)
    .await
    .map_err(|_| store_unavailable())?;
    Ok(())
}
