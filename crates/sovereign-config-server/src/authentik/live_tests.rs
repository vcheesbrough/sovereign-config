use std::{env, time::Duration};

use reqwest::Url;
use sovereign_config_core::Secret;

use super::{AdminError, AuthentikAdminClient, CreatedServiceAccount};

const LIVE_TIMEOUT: Duration = Duration::from_secs(15);
/// Default browsing group when the environment does not name one — the
/// development blueprint creates this exact group.
const DEFAULT_MANAGED_GROUP: &str = "sovereign-config-dev-connections";

/// The browsing group the live lifecycle test must resolve, taken from the
/// deploying environment so a production promotion validates the production
/// group (`sovereign-config-connections`) rather than the development one.
fn live_managed_group() -> String {
    env::var("SOVEREIGN_CONFIG_LIVE_MANAGED_GROUP")
        .unwrap_or_else(|_| DEFAULT_MANAGED_GROUP.to_owned())
}

fn live_client() -> Option<AuthentikAdminClient> {
    let origin = env::var("SOVEREIGN_CONFIG_LIVE_AUTHENTIK_URL").ok()?;
    let token = env::var("SOVEREIGN_CONFIG_LIVE_AUTHENTIK_TOKEN").ok()?;
    if origin.trim().is_empty() || token.trim().is_empty() {
        return None;
    }
    let origin: Url = origin.parse().expect("live Authentik URL must be valid");
    Some(
        AuthentikAdminClient::new(origin, Secret::new(token.trim()), LIVE_TIMEOUT)
            .expect("live Authentik client must build"),
    )
}

/// An elevated client used only to create and clean up disposable canary
/// objects that the manager under test must be denied access to. Never
/// used to exercise the manager's own restricted behavior.
fn live_admin_client() -> Option<AuthentikAdminClient> {
    let origin = env::var("SOVEREIGN_CONFIG_LIVE_AUTHENTIK_URL").ok()?;
    let token = env::var("SOVEREIGN_CONFIG_LIVE_AUTHENTIK_ADMIN_TOKEN").ok()?;
    if origin.trim().is_empty() || token.trim().is_empty() {
        return None;
    }
    let origin: Url = origin.parse().expect("live Authentik URL must be valid");
    Some(
        AuthentikAdminClient::new(origin, Secret::new(token.trim()), LIVE_TIMEOUT)
            .expect("live Authentik admin client must build"),
    )
}

/// A disposable username that cannot collide with a managed connection.
fn disposable_username(suffix: &str) -> String {
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes).expect("CSPRNG must be available");
    let random = bytes.iter().fold(String::new(), |mut value, byte| {
        use std::fmt::Write as _;
        let _ = write!(value, "{byte:02x}");
        value
    });
    format!("sc-livetest-{suffix}-{random}")
}

async fn cleanup(client: &AuthentikAdminClient, account: &CreatedServiceAccount) {
    let _ = client.delete_user(account.user_id).await;
}

/// The full lifecycle the manager performs for one managed connection.
/// This is the check that would have caught the production failure: the
/// app password must be *discoverable* by the manager that created it.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_LIVE_AUTHENTIK_URL and _TOKEN"]
async fn live_manager_completes_the_managed_connection_lifecycle() {
    let Some(client) = live_client() else {
        return;
    };
    let username = disposable_username("lifecycle");

    let account = client
        .create_service_account(&username)
        .await
        .expect("the manager must be able to create a service account");

    // Assertions are collected rather than panicking so the disposable
    // account is always removed from the real directory.
    let checks = async {
        let identifiers = client
            .find_app_password_identifiers(&username)
            .await
            .map_err(|error| format!("listing the app password failed: {error:?}"))?;
        if identifiers.len() != 1 {
            return Err(format!(
                "expected exactly one discoverable app password, found {}",
                identifiers.len()
            ));
        }
        client
            .set_managed_attributes(
                account.user_id,
                "livetestconnectionid0123456789ab",
                "sovereign_config_live_test_grants",
                "/apps/api",
                &["read"],
            )
            .await
            .map_err(|error| format!("patching the created account failed: {error:?}"))?;
        client
            .set_credential_secret(&identifiers[0], &Secret::new("live-test-replacement-key"))
            .await
            .map_err(|error| format!("rotating the app password failed: {error:?}"))?;
        // Group membership is best-effort in production, but the manager
        // must actually be able to resolve and use it against real
        // Authentik, not only against the mock.
        let managed_group = live_managed_group();
        let group_id = client
            .find_group_by_name(&managed_group)
            .await
            .map_err(|error| format!("resolving the browsing group failed: {error:?}"))?
            .ok_or_else(|| {
                format!("the {managed_group} browsing group must exist in this environment")
            })?;
        client
            .add_user_to_group(account.user_id, &group_id)
            .await
            .map_err(|error| {
                format!("adding the account to the browsing group failed: {error:?}")
            })?;
        let found = client
            .find_user_by_username(&username)
            .await
            .map_err(|error| format!("reconciliation failed: {error:?}"))?;
        if found.is_none() {
            return Err("reconciliation did not locate the created account".to_owned());
        }
        Ok::<(), String>(())
    }
    .await;

    cleanup(&client, &account).await;
    checks.expect("the manager must complete the managed connection lifecycle");

    // Absence is confirmed through the app password, not the user.
    // Authentik refuses user reads and deletes for an account the manager
    // can no longer see, so those cannot distinguish "gone" from "denied";
    // the token view is global and cascades with the user, so an empty
    // result proves no usable credential survives.
    let remaining = client
        .find_app_password_identifiers(&username)
        .await
        .expect("confirming credential absence must succeed");
    assert!(
        remaining.is_empty(),
        "deleting the account must leave no usable credential"
    );
}

/// Credential discovery must stay scoped to one account even though the
/// manager holds a global token view, so a second connection can never
/// consume another connection's credential.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_LIVE_AUTHENTIK_URL and _TOKEN"]
async fn live_credential_discovery_is_scoped_to_one_account() {
    let Some(client) = live_client() else {
        return;
    };
    let first_name = disposable_username("scope-a");
    let second_name = disposable_username("scope-b");

    let first = client
        .create_service_account(&first_name)
        .await
        .expect("first disposable account must be creatable");
    let second = client.create_service_account(&second_name).await;

    let checks = async {
        let identifiers = client
            .find_app_password_identifiers(&first_name)
            .await
            .map_err(|error| format!("first discovery failed: {error:?}"))?;
        let others = client
            .find_app_password_identifiers(&second_name)
            .await
            .map_err(|error| format!("second discovery failed: {error:?}"))?;
        if identifiers.len() != 1 || others.len() != 1 {
            return Err(format!(
                "discovery must be scoped to one account, found {} and {}",
                identifiers.len(),
                others.len()
            ));
        }
        if identifiers[0] == others[0] {
            return Err("each account must own a distinct credential".to_owned());
        }
        Ok::<(), String>(())
    }
    .await;

    cleanup(&client, &first).await;
    if let Ok(second) = &second {
        cleanup(&client, second).await;
    }
    checks.expect("credential discovery must be scoped to a single account");
}

/// The manager must not be able to act on an object it did not create.
///
/// Uses a disposable canary rather than a real object: verifying a denial
/// by attempting a live, mutating delete against a precious, irreplaceable
/// object (e.g. the bootstrap administrator) would make the very
/// permission regression this test exists to catch also the mechanism
/// that destroys that object. The canary is created and, regardless of
/// outcome, cleaned up with a separate, more-privileged credential that
/// the manager under test never has access to.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_LIVE_AUTHENTIK_URL, _TOKEN, and _ADMIN_TOKEN"]
async fn live_manager_cannot_touch_unrelated_objects() {
    let (Some(client), Some(admin)) = (live_client(), live_admin_client()) else {
        return;
    };
    let canary_username = disposable_username("canary");
    let canary = admin
        .create_service_account(&canary_username)
        .await
        .expect("the admin credential must be able to create a canary account");

    let checks = async {
        let denied = client.delete_user(canary.user_id).await;
        if !matches!(denied, Err(AdminError::NotFound | AdminError::Rejected)) {
            return Err(format!(
                "deleting an unrelated user must be denied, got {denied:?}"
            ));
        }

        let missing = client
            .find_app_password_identifiers("sc-livetest-nonexistent-account")
            .await
            .map_err(|error| format!("a scoped lookup for an unknown account failed: {error:?}"))?;
        if !missing.is_empty() {
            return Err("an unknown account must yield no credentials".to_owned());
        }
        Ok::<(), String>(())
    }
    .await;

    // Cleanup uses the admin credential: the manager must never be relied
    // on to delete an object it was just proven unable to delete.
    let _ = admin.delete_user(canary.user_id).await;
    checks.expect("the manager must be denied access to an object it did not create");
}
