//! Every `PostgreSQL` row type and query behind the `ManagedConnections`
//! service.

use sovereign_config_core::{
    ConfigPath, ConnectionId, DisplayName, ManagedConnectionState, ManagedPermissions,
};
use sqlx::{FromRow, Postgres, Transaction};
use time::OffsetDateTime;
use tonic::Status;

use super::ManagedConnectionsService;
use super::wire::{internal_error, not_found};
use crate::audit::{Actor, AuditEvent};
use crate::auth::{AuthenticatedPrincipal, Permission};
use crate::authentik::CreatedServiceAccount;
use crate::rpc::storage_unavailable;

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
    pub(super) async fn begin(&self) -> Result<Transaction<'_, Postgres>, Status> {
        self.database
            .begin()
            .await
            .map_err(|_| storage_unavailable())
    }

    /// Locks one row and requires the caller to manage its root; a missing row
    /// and a non-manageable row are externally indistinguishable.
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
        .map_err(|_| storage_unavailable())
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
        .map_err(|_| storage_unavailable())?;
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
            .map_err(|_| storage_unavailable())?;
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

    pub(super) async fn delete_connection(
        &self,
        connection_id: &ConnectionId,
    ) -> Result<(), Status> {
        sqlx::query("DELETE FROM managed_connections WHERE connection_id = $1")
            .bind(connection_id.as_str())
            .execute(&self.database)
            .await
            .map_err(|_| storage_unavailable())?;
        Ok(())
    }

    /// Every connection row, oldest first.
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
        .map_err(|_| storage_unavailable())
    }

    /// Inserts a new connection in `provisioning`, before any external call.
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
        .map_err(|_| storage_unavailable())?;
        Ok(())
    }

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
        .map_err(|_| storage_unavailable())?;
        Ok(())
    }

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
        .map_err(|_| storage_unavailable())?;
        Ok(())
    }
}

pub(super) async fn commit(transaction: Transaction<'_, Postgres>) -> Result<(), Status> {
    transaction
        .commit()
        .await
        .map_err(|_| storage_unavailable())
}

/// Marks a locked row `rotation_unknown` before the external call, so an
/// interruption is always represented as an ambiguous rotation.
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
    .map_err(|_| storage_unavailable())?;
    Ok(())
}

/// Marks a locked row `revoking`.
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
    .map_err(|_| storage_unavailable())?;
    Ok(())
}
