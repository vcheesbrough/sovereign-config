use std::{env, sync::Arc, time::Duration};

use sqlx::{PgPool, postgres::PgPoolOptions};
use time::OffsetDateTime;

use super::test_support::{clear_trail, trail};
use super::{Actor, AuditEvent, AuditRecorder, EventKind, Recorded, coalesce_digest};
use crate::metrics::AuditMetrics;

const DAY: Duration = Duration::from_hours(24);

fn actor<'a>(subject: &'a str, protocol_version: &'static str) -> Actor<'a> {
    Actor {
        subject,
        name: None,
        protocol_version,
    }
}

async fn pool() -> PgPool {
    let database_url = env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL")
        .expect("SOVEREIGN_CONFIG_TEST_DATABASE_URL must be configured");
    let pool = PgPoolOptions::new().connect(&database_url).await.unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    pool
}

#[test]
fn every_kind_has_its_own_label_and_only_accesses_coalesce() {
    let mut labels: Vec<&str> = EventKind::ALL.iter().map(|kind| kind.as_str()).collect();
    labels.sort_unstable();
    labels.dedup();
    assert_eq!(labels.len(), EventKind::ALL.len());
    for (index, kind) in EventKind::ALL.iter().enumerate() {
        assert_eq!(kind.index(), index, "{kind:?} is out of order in ALL");
    }

    let coalescing: Vec<&str> = EventKind::ALL
        .iter()
        .filter(|kind| kind.coalesces())
        .map(|kind| kind.as_str())
        .collect();
    assert_eq!(
        coalescing,
        ["secret.revealed", "subtree.read", "values.listed"]
    );
}

/// Whatever the classification string is, only `plain` lets a value through.
/// An unknown classification fails towards recording too little.
#[test]
fn only_a_value_classified_plain_is_kept() {
    assert_eq!(Recorded::of("plain", "v"), Recorded::Plain("v"));
    for classification in ["secret", "", "PLAIN", "plain ", "confidential"] {
        assert_eq!(
            Recorded::of(classification, "v"),
            Recorded::Secret,
            "{classification:?}"
        );
    }
}

#[test]
fn a_window_is_one_actor_on_one_version_doing_one_thing_to_one_path() {
    let at = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
    let key = |kind, subject: &str, version, path, at| {
        coalesce_digest(kind, &actor(subject, version), path, at, DAY)
    };
    let base = key(EventKind::SecretRevealed, "alice", "v3", "/a/key", at);

    assert_eq!(base.len(), 64);
    assert_eq!(
        base,
        key(EventKind::SecretRevealed, "alice", "v3", "/A/Key", at),
        "a window is keyed by the fold, not by how the path was spelled"
    );
    assert_eq!(
        base,
        key(
            EventKind::SecretRevealed,
            "alice",
            "v3",
            "/a/key",
            at + Duration::from_secs(60)
        ),
        "a minute later is the same window"
    );
    for different in [
        key(EventKind::SubtreeRead, "alice", "v3", "/a/key", at),
        key(EventKind::SecretRevealed, "bob", "v3", "/a/key", at),
        key(EventKind::SecretRevealed, "alice", "vtest", "/a/key", at),
        key(EventKind::SecretRevealed, "alice", "v3", "/a/other", at),
        key(EventKind::SecretRevealed, "alice", "v3", "/a/key", at + DAY),
    ] {
        assert_ne!(base, different);
    }
    // The subject is the one unbounded, unvalidated component. It comes last
    // so that a separator inside it cannot shift into another component.
    assert_ne!(
        key(EventKind::SecretRevealed, "x|/a", "v3", "/b", at),
        key(EventKind::SecretRevealed, "x", "v3", "/b|/a", at),
    );
}

/// The table's own statement of the secret rule, independent of the code that
/// normally upholds it: a read or a secret access cannot carry a value.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn the_table_refuses_a_value_on_anything_but_a_single_value_change() {
    let pool = pool().await;
    clear_trail(&pool, "/tests/audit-constraint").await;

    for kind in [
        "secret.revealed",
        "subtree.read",
        "values.listed",
        "value.path_added",
    ] {
        let refused = sqlx::query(
            r"
            INSERT INTO audit_events (
                occurred_at, first_occurred_at, kind, display_path, actor_subject,
                protocol_version, new_value, narrative
            )
            VALUES (NOW(), NOW(), $1, '/tests/audit-constraint/key', 'alice', 'v3', 'leaked', 'n')
            ",
        )
        .bind(kind)
        .execute(&pool)
        .await;
        assert!(refused.is_err(), "{kind} accepted a value");
    }
    assert!(trail(&pool, "/tests/audit-constraint").await.is_empty());
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn an_odd_identity_claim_cannot_fail_an_audit_write() {
    let pool = pool().await;
    clear_trail(&pool, "/tests/audit-claims").await;
    let recorder = AuditRecorder::for_tests();
    let odd = Actor {
        subject: "sub\0ject",
        name: Some("na\0me"),
        protocol_version: "v3",
    };

    recorder
        .record(
            &pool,
            &odd,
            OffsetDateTime::now_utc(),
            AuditEvent::secret_revealed(&odd, "/tests/audit-claims/key"),
        )
        .await
        .expect("a NUL in a claim must not fail the write");

    let rows = trail(&pool, "/tests/audit-claims").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].actor_subject, "subject");
    assert_eq!(rows[0].actor_name.as_deref(), Some("name"));
    clear_trail(&pool, "/tests/audit-claims").await;
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn the_sweep_deletes_only_events_last_seen_before_the_cutoff() {
    let pool = pool().await;
    clear_trail(&pool, "/tests/audit-sweep").await;
    let metrics = Arc::new(AuditMetrics::default());
    let recorder = AuditRecorder::with_metrics(Arc::clone(&metrics));
    let alice = actor("alice", "v3");
    let now = OffsetDateTime::now_utc();
    let expired = now - 400 * DAY;

    recorder
        .record(
            &pool,
            &alice,
            expired,
            AuditEvent::value_deleted(&alice, "/tests/audit-sweep/expired", Recorded::Plain("v")),
        )
        .await
        .unwrap();
    recorder
        .record(
            &pool,
            &alice,
            now,
            AuditEvent::value_deleted(&alice, "/tests/audit-sweep/recent", Recorded::Plain("v")),
        )
        .await
        .unwrap();

    // The default retention, as the server computes its cutoff.
    let swept = recorder
        .sweep_expired(&pool, now - 365 * DAY)
        .await
        .expect("the sweep must run");

    assert!(swept >= 1, "the expired event must be swept");
    let remaining = trail(&pool, "/tests/audit-sweep").await;
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].display_path, "/tests/audit-sweep/recent");
    assert!(
        metrics.render().contains(&format!(
            "sovereign_config_audit_retention_swept_total {swept}"
        )),
        "{}",
        metrics.render()
    );
    clear_trail(&pool, "/tests/audit-sweep").await;
}
