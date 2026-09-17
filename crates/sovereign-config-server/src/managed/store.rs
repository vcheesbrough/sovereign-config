//! Every `PostgreSQL` row type and query behind the `ManagedConnections`
//! service.

use sovereign_config_core::{ConfigPath, ConnectionId, ManagedConnectionState};
use sqlx::{FromRow, Postgres, Transaction};
use time::OffsetDateTime;
use tonic::Status;

use super::ManagedConnectionsService;
use super::wire::{internal_error, not_found};
use crate::auth::{AuthenticatedPrincipal, Permission};
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

    pub(super) async fn delete_row(&self, connection_id: &ConnectionId) -> bool {
        sqlx::query("DELETE FROM managed_connections WHERE connection_id = $1")
            .bind(connection_id.as_str())
            .execute(&self.database)
            .await
            .is_ok()
    }
}
