//! The managed-connection lifecycle driven through the in-memory identity
//! provider rather than Authentik over HTTP (#381): create, its ambiguous
//! reconciliation, rotate through every way a credential replacement can
//! fail, and revoke. That the whole lifecycle runs proves the trait is a
//! sufficient seam — nothing the service needs is hiding behind HTTP.

use std::sync::Arc;

use sovereign_config_core::{ConfigPath, ConnectionUrl, ManagedPermission, Secret};
use sovereign_config_identity::{
    ManagedIdentityProvider as _, ProviderError,
    conformance::Operation,
    fake::{FakeAccount, FakeIdentityProvider},
};
use sovereign_config_proto::sovereign::config::v3::{
    RevokeManagedConnectionRequest, RotateManagedConnectionRequest,
    managed_connections_server::ManagedConnections,
};

use super::super::store::ConnectionRow;
use super::{
    ISSUER, PUBLIC_ORIGIN, ROTATION_LEASE, assert_bounded, create, create_with, fresh_database,
    operator, request, rows,
};
use super::{ManagedConnectionsService, ManagedSettings, V3ManagedConnections};
use crate::audit::AuditRecorder;
use crate::metrics::ManagedConnectionMetrics;

async fn service_over(fake: &Arc<FakeIdentityProvider>) -> Option<V3ManagedConnections> {
    let database = fresh_database().await?;
    Some(V3ManagedConnections::new(Arc::new(
        ManagedConnectionsService::new(
            database,
            Arc::clone(fake) as _,
            ManagedSettings {
                public_origin: PUBLIC_ORIGIN.to_owned(),
                issuer: ISSUER.to_owned(),
                rotation_lease: ROTATION_LEASE,
            },
            Arc::new(ManagedConnectionMetrics::default()),
            AuditRecorder::for_tests(),
        ),
    )))
}

macro_rules! service_over_or_skip {
    ($fake:expr) => {
        match service_over($fake).await {
            Some(service) => service,
            None => return,
        }
    };
}

/// The URL a connection to `account` must be, byte for byte: deployed
/// clients decode it.
fn expected_url(root: &str, account: &FakeAccount) -> String {
    ConnectionUrl::managed(
        PUBLIC_ORIGIN,
        &ConfigPath::parse(root).unwrap(),
        ISSUER,
        &account.client_id,
        &account.username,
        &Secret::new(account.secret.clone()),
    )
    .unwrap()
    .canonical()
    .expose()
    .to_owned()
}

async fn row(service: &V3ManagedConnections, connection_id: &str) -> Option<ConnectionRow> {
    rows(service)
        .await
        .into_iter()
        .find(|row| row.connection_id == connection_id)
}

async fn rotate(
    service: &V3ManagedConnections,
    connection_id: &str,
) -> Result<String, tonic::Status> {
    service
        .rotate_managed_connection(request(
            RotateManagedConnectionRequest {
                connection_id: connection_id.to_owned(),
            },
            &operator("/"),
        ))
        .await
        .map(|response| response.into_inner().connection_url)
}

async fn revoke(service: &V3ManagedConnections, connection_id: &str) -> Result<(), tonic::Status> {
    service
        .revoke_managed_connection(request(
            RevokeManagedConnectionRequest {
                connection_id: connection_id.to_owned(),
            },
            &operator("/"),
        ))
        .await
        .map(|_| ())
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn create_grants_names_and_groups_the_account_and_returns_its_secret() {
    let fake = Arc::new(FakeIdentityProvider::new());
    let service = service_over_or_skip!(&fake);

    let (connection_id, url) = create_with(
        &service,
        "Pipeline reader",
        "/apps/api",
        &[ManagedPermission::Read, ManagedPermission::Write],
        &operator("/"),
    )
    .await
    .expect("create must succeed");

    let [account] = fake.accounts().try_into().expect("exactly one account");
    assert_eq!(account.name.as_deref(), Some("Pipeline reader"));
    assert_eq!(
        account.connection_id.as_deref(),
        Some(connection_id.as_str())
    );
    assert_eq!(account.root.as_deref(), Some("/apps/api"));
    assert_eq!(account.permissions, ["read", "write"]);
    assert!(account.in_browse_group);

    // The URL carries the provider's credential under the generated username.
    assert_eq!(url, expected_url("/apps/api", &account));

    let row = row(&service, &connection_id).await.expect("the row exists");
    assert_eq!(row.state, "active");
    assert_eq!(
        row.provider_user_id.as_deref(),
        Some(account.account.as_str())
    );
    assert_eq!(
        row.credential_identifier.as_deref(),
        Some(account.credential.as_str())
    );
}

/// The browsing group is a convenience: its absence never fails a create.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn create_succeeds_without_the_browsing_group() {
    let fake = Arc::new(FakeIdentityProvider::new());
    let service = service_over_or_skip!(&fake);
    fake.remove_browse_group();

    let (connection_id, _) = create(&service, "Ungrouped", "/", &operator("/"))
        .await
        .expect("create must succeed without the group");
    assert_eq!(
        row(&service, &connection_id).await.map(|row| row.state),
        Some("active".to_owned())
    );
    assert!(!fake.accounts()[0].in_browse_group);
}

/// An ambiguous create that did land is found by its exact username and
/// removed; one that never landed leaves a `cleanup_required` row behind, in
/// case it lands late. A definitive failure discards the row outright.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn create_failures_are_reconciled_by_what_they_may_have_applied() {
    let fake = Arc::new(FakeIdentityProvider::new());
    let service = service_over_or_skip!(&fake);

    for landed in [ProviderError::Ambiguous, ProviderError::Invalid] {
        fake.fail_next(Operation::CreateAccount, landed);
        let status = create(&service, "Landed", "/", &operator("/"))
            .await
            .expect_err("an ambiguous create fails");
        assert_bounded(&status);
        assert!(
            fake.accounts().is_empty(),
            "{landed:?}: the account it made is deleted"
        );
        assert!(
            rows(&service).await.is_empty(),
            "{landed:?}: the row is discarded"
        );
    }

    for refused in [ProviderError::Rejected, ProviderError::Unavailable] {
        fake.fail_next(Operation::CreateAccount, refused);
        create(&service, "Refused", "/", &operator("/"))
            .await
            .expect_err("a refused create fails");
        assert!(
            rows(&service).await.is_empty(),
            "{refused:?}: the row is discarded"
        );
    }
    let lookups_before = fake.calls(Operation::FindAccount);

    fake.fail_next_unapplied(Operation::CreateAccount, ProviderError::Ambiguous);
    let status = create(&service, "Never landed", "/", &operator("/"))
        .await
        .expect_err("an ambiguous create fails");
    assert_bounded(&status);
    assert!(fake.accounts().is_empty());
    let rows = rows(&service).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].state, "cleanup_required");
    assert!(
        fake.calls(Operation::FindAccount) - lookups_before > 1,
        "absence is concluded only after more than one probe"
    );
}

/// A create that fails after the account exists deletes the account it made.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn a_failure_after_the_account_exists_is_compensated() {
    let fake = Arc::new(FakeIdentityProvider::new());
    let service = service_over_or_skip!(&fake);

    fake.fail_next(Operation::Grant, ProviderError::Rejected);
    create(&service, "Ungranted", "/", &operator("/"))
        .await
        .expect_err("a failed grant fails the create");
    assert!(fake.accounts().is_empty());
    assert!(rows(&service).await.is_empty());
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn rotate_replaces_the_secret_and_settles_every_failure() {
    let fake = Arc::new(FakeIdentityProvider::new());
    let service = service_over_or_skip!(&fake);

    let (connection_id, first) = create(&service, "Rotating", "/", &operator("/"))
        .await
        .expect("create must succeed");
    let rotated = rotate(&service, &connection_id)
        .await
        .expect("rotation must succeed");
    assert_ne!(rotated, first);
    assert_eq!(
        rotated,
        expected_url("/", &fake.accounts()[0]),
        "the URL carries the replacement"
    );

    // Every way the replacement can fail, each on its own connection, and the
    // state `settle_failed_rotation` leaves it in.
    for (error, settled) in [
        (ProviderError::Rejected, "active"),
        (ProviderError::Unavailable, "active"),
        (ProviderError::NotFound, "cleanup_required"),
        (ProviderError::Ambiguous, "rotation_unknown"),
        (ProviderError::Invalid, "rotation_unknown"),
    ] {
        let (connection_id, _) = create(&service, "Settling", "/", &operator("/"))
            .await
            .expect("create must succeed");
        fake.fail_next(Operation::ReplaceCredential, error);
        let status = rotate(&service, &connection_id)
            .await
            .expect_err("a failed replacement fails the rotation");
        assert_bounded(&status);
        assert_eq!(
            row(&service, &connection_id).await.map(|row| row.state),
            Some(settled.to_owned()),
            "{error:?}"
        );
    }
}

/// A provider may refuse, rather than report missing, a credential that is
/// gone. A rejected rotation is therefore only settled as "the previous URL
/// stays current" once the credential is confirmed to exist; a vanished one
/// leaves the connection for revocation, never `active` with a dead URL.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn a_rejected_rotation_of_a_vanished_credential_requires_cleanup() {
    let fake = Arc::new(FakeIdentityProvider::new());
    let service = service_over_or_skip!(&fake);

    let (connection_id, _) = create(&service, "Vanishing", "/", &operator("/"))
        .await
        .expect("create must succeed");
    let [account] = fake.accounts().try_into().expect("exactly one account");
    // Gone behind the server's back, and refused rather than reported
    // missing when the rotation reaches it.
    fake.delete_account(&account.account)
        .await
        .expect("the account is deleted out of band");
    fake.fail_next(Operation::ReplaceCredential, ProviderError::Rejected);

    let status = rotate(&service, &connection_id)
        .await
        .expect_err("a rejected replacement fails the rotation");
    assert_bounded(&status);
    assert_eq!(
        row(&service, &connection_id).await.map(|row| row.state),
        Some("cleanup_required".to_owned())
    );
}

/// When the confirming lookup itself fails, nothing is known: the connection
/// stays `rotation_unknown`, as after an ambiguous failure, rather than being
/// declared `active` on no evidence.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn a_rejected_rotation_that_cannot_be_confirmed_stays_unknown() {
    let fake = Arc::new(FakeIdentityProvider::new());
    let service = service_over_or_skip!(&fake);

    let (connection_id, _) = create(&service, "Unconfirmed", "/", &operator("/"))
        .await
        .expect("create must succeed");
    fake.fail_next(Operation::ReplaceCredential, ProviderError::Rejected);
    fake.fail_next(Operation::FindCredentials, ProviderError::Unavailable);

    let status = rotate(&service, &connection_id)
        .await
        .expect_err("a rejected replacement fails the rotation");
    assert_bounded(&status);
    assert_eq!(
        row(&service, &connection_id).await.map(|row| row.state),
        Some("rotation_unknown".to_owned())
    );
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn revoke_deletes_the_account_and_confirms_absence_by_its_credential() {
    let fake = Arc::new(FakeIdentityProvider::new());
    let service = service_over_or_skip!(&fake);

    let (plain, _) = create(&service, "Plain", "/", &operator("/"))
        .await
        .expect("create must succeed");
    revoke(&service, &plain).await.expect("revoke must succeed");
    assert!(fake.accounts().is_empty());
    assert!(row(&service, &plain).await.is_none());

    // A delete refused after it was applied is settled by the credential
    // being gone, not by the refusal.
    let (refused, _) = create(&service, "Refused delete", "/", &operator("/"))
        .await
        .expect("create must succeed");
    fake.fail_next_after_applying(Operation::DeleteAccount, ProviderError::Rejected);
    revoke(&service, &refused)
        .await
        .expect("an applied delete is confirmed by its credential");
    assert!(row(&service, &refused).await.is_none());

    // A delete that did not land leaves the credential, so the row stays
    // `revoking` until a retry confirms absence.
    let (pending, _) = create(&service, "Pending delete", "/", &operator("/"))
        .await
        .expect("create must succeed");
    fake.fail_next_unapplied(Operation::DeleteAccount, ProviderError::Ambiguous);
    let status = revoke(&service, &pending)
        .await
        .expect_err("an unconfirmed delete fails the revoke");
    assert_bounded(&status);
    assert_eq!(
        row(&service, &pending).await.map(|row| row.state),
        Some("revoking".to_owned())
    );
    assert_eq!(fake.accounts().len(), 1);
    revoke(&service, &pending)
        .await
        .expect("a retried revoke completes");
    assert!(fake.accounts().is_empty());
    assert!(row(&service, &pending).await.is_none());
}
