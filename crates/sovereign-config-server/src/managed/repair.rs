//! The startup repair for #440: until 2.42.0 a managed connection's service
//! account went by its generated username and its tokens carried no name at
//! all, so the audit trail recorded its access by an opaque subject.
//!
//! The repair names every existing account after its connection, as
//! provisioning now does for a new one, then — once every token minted under
//! the old name has expired — gives each of those accounts its current name
//! in every past event. It rewrites recorded history once: when every step
//! has succeeded it records that it is done (`managed_name_repair`), and every
//! later start skips it. A start interrupted halfway, or one where any step
//! failed, records nothing, and the next start runs it again — each step is
//! idempotent. It never fails startup.
//!
//! What it cannot repair: an event by a connection revoked before it ran. The
//! revocation deleted the only record linking that account's subject to a
//! connection.

use std::time::Duration;

use sovereign_config_core::{ConnectionId, ManagedConnectionState};
use tracing::{Instrument, field::Empty, info, warn};

use super::ManagedConnectionsService;
use super::identity::managed_username;
use super::provisioning::dependency_outcome;
use super::store::AccountRow;
use crate::audit::{self, ActorRename};
use crate::authentik::AdminError;
use crate::metrics::{ManagedDependencyCall, ManagedDependencyOutcome};
use crate::spans;

/// What the scope mapping in each environment's blueprint appends to a
/// managed account's name when it signs it as `preferred_username`, so an
/// access URL can never read as a person. A test holds the blueprints to it.
pub(crate) const ACCESS_URL_MARKER: &str = " (access URL)";

/// How long after renaming the accounts the trail is repaired: the provider's
/// access-token lifetime (`access_token_validity: minutes=5` in both
/// blueprints, which a test holds to this) plus a minute's margin. Until then a
/// token minted under an account's old name can still record an event under
/// it, and the repair would miss it.
pub(crate) const TRAIL_REPAIR_DELAY: Duration = Duration::from_mins(6);

/// The name an account's tokens carry: its connection's display name, marked.
pub(super) fn marked(name: &str) -> String {
    format!("{name}{ACCESS_URL_MARKER}")
}

impl ManagedConnectionsService {
    /// Runs the whole repair, unless it has already completed; `delay`
    /// separates renaming the accounts from repairing the trail
    /// ([`TRAIL_REPAIR_DELAY`] outside tests).
    pub(crate) async fn repair_actor_names(&self, delay: Duration) {
        match self.name_repair_completed().await {
            Ok(true) => return,
            Ok(false) => {}
            Err(_) => {
                warn!(
                    "whether the name repair has completed could not be read; retrying at the next start"
                );
                return;
            }
        }
        let accounts_named = self
            .rename_accounts()
            .instrument(tracing::info_span!(
                parent: None,
                "sovereign_config.managed.rename_accounts",
                otel.kind = "internal",
                otel.status_code = Empty,
                error.type = Empty,
                sovereign_config.managed.renamed = Empty,
            ))
            .await;
        tokio::time::sleep(delay).await;
        let trail_repaired = self
            .rename_actors_in_trail()
            .instrument(tracing::info_span!(
                parent: None,
                "sovereign_config.audit.rename_actors",
                otel.kind = "internal",
                otel.status_code = Empty,
                error.type = Empty,
                sovereign_config.audit.renamed = Empty,
            ))
            .await;
        if !(accounts_named && trail_repaired) {
            return;
        }
        if self.complete_name_repair().await.is_ok() {
            info!("the managed connections' name repair is complete");
        } else {
            warn!(
                "the name repair could not be recorded as complete; it runs again at the next start"
            );
        }
    }

    /// Names every live connection's account after the connection, returning
    /// whether every one was. One account failing is counted and logged, and
    /// the rest are still named.
    async fn rename_accounts(&self) -> bool {
        let Some(accounts) = self.accounts_or_log().await else {
            return false;
        };
        let mut renamed = 0_u64;
        // The last failure holding the repair open, which marks this run's
        // span failed so Tempo does not show an incomplete repair as clean.
        let mut holding_open: Option<&'static str> = None;
        for account in accounts.iter().filter(|account| is_live(account)) {
            let Some(user_id) = account.provider_user_id else {
                continue;
            };
            let outcome = match self.admin.rename_user(user_id, &account.display_name).await {
                Ok(()) => {
                    renamed += 1;
                    ManagedDependencyOutcome::Ok
                }
                Err(error) => {
                    // A deleted account has nothing left to name; only a
                    // failure a later start could fix keeps the repair open.
                    if !matches!(error, AdminError::NotFound) {
                        holding_open = Some(error.label());
                    }
                    warn!(
                        connection_id = account.connection_id.as_str(),
                        outcome = error.label(),
                        "a managed connection's account could not be named after it; its access is recorded under its generated username until the next start"
                    );
                    dependency_outcome(error)
                }
            };
            self.metrics
                .record_dependency(ManagedDependencyCall::RenameAccount, outcome);
        }
        tracing::Span::current().record("sovereign_config.managed.renamed", renamed);
        if renamed > 0 {
            info!(renamed, "managed connections' accounts named after them");
        }
        if let Some(classification) = holding_open {
            spans::record_error(classification);
        }
        holding_open.is_none()
    }

    /// Gives every connection's account its current name in past events,
    /// returning whether that succeeded.
    async fn rename_actors_in_trail(&self) -> bool {
        let Some(accounts) = self.accounts_or_log().await else {
            return false;
        };
        let names: Vec<ActorRename> = accounts.iter().filter_map(actor_rename).collect();
        if names.is_empty() {
            return true;
        }
        let Ok(renamed) = audit::rename_actors(&self.database, &names).await else {
            spans::record_error("storage_unavailable");
            warn!("past audit events could not be renamed; retrying at the next start");
            return false;
        };
        tracing::Span::current().record("sovereign_config.audit.renamed", renamed);
        if renamed > 0 {
            info!(
                renamed,
                "past audit events by managed connections now name them"
            );
        }
        true
    }

    async fn accounts_or_log(&self) -> Option<Vec<AccountRow>> {
        let Ok(accounts) = self.list_accounts().await else {
            spans::record_error("storage_unavailable");
            warn!(
                "managed connections could not be read for the name repair; retrying at the next start"
            );
            return None;
        };
        Some(accounts)
    }
}

/// Whether the account is meant to exist: a connection being revoked or
/// awaiting cleanup is left alone.
fn is_live(account: &AccountRow) -> bool {
    matches!(
        ManagedConnectionState::parse(&account.state),
        Ok(ManagedConnectionState::Active | ManagedConnectionState::RotationUnknown)
    )
}

/// The trail's rename for one account, or none for a row whose identifier
/// does not parse, which no generated username could then be derived for.
fn actor_rename(account: &AccountRow) -> Option<ActorRename> {
    let connection_id = ConnectionId::parse(account.connection_id.as_str()).ok()?;
    let username = managed_username(&connection_id, &account.display_name);
    Some(ActorRename {
        subject: account.provider_user_uid.clone(),
        name: marked(&account.display_name),
        superseded_marked: marked(&username),
        superseded: username,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLUEPRINTS: [&str; 2] = [
        include_str!("../../../../authentik/blueprint.yaml"),
        include_str!("../../../../authentik/blueprint-dev.yaml"),
    ];

    #[test]
    fn the_blueprints_mark_a_managed_name_as_the_repair_does() {
        let signed = format!(
            "claims[\"preferred_username\"] = f\"{{request.user.name}}{ACCESS_URL_MARKER}\""
        );
        for blueprint in BLUEPRINTS {
            assert!(blueprint.contains(&signed), "{signed}");
        }
        assert_eq!(marked("Pipeline reader"), "Pipeline reader (access URL)");
    }

    #[test]
    fn the_trail_is_repaired_only_after_every_old_token_has_expired() {
        for blueprint in BLUEPRINTS {
            assert!(blueprint.contains("access_token_validity: minutes=5"));
        }
        assert!(TRAIL_REPAIR_DELAY > Duration::from_mins(5));
    }
}
