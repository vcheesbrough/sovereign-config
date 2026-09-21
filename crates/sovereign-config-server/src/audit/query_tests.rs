//! Reading the trail back through `v4`'s `QueryAuditTrail`, end to end: the
//! shim's translation, the shared implementation's validation and grant check,
//! and the query against a real table.
//!
//! Every event here is written under [`ROOT`] and every caller's grants are
//! confined to it, so the suites sharing this database cannot leak into a
//! result, and nothing here can leak into theirs.

use std::{collections::BTreeSet, env, sync::Arc, time::Duration};

use sovereign_config_core::AuditEventKind;
use sovereign_config_proto::sovereign::config::v4::{
    self, QueryAuditTrailRequest, QueryAuditTrailResponse, audit_server::Audit,
};
use sqlx::{PgPool, postgres::PgPoolOptions};
use time::OffsetDateTime;
use tonic::{Code, Request};

use super::test_support::clear_trail;
use super::v4::V4Audit;
use super::{Actor, AuditEvent, AuditRecorder, AuditTrailService, EventKind, Recorded};
use crate::auth::{AuthenticatedPrincipal, Grant, Permission};

const ROOT: &str = "/tests/audit-query";

#[test]
fn every_kind_the_trail_records_is_one_a_query_can_return() {
    let recorded: Vec<&str> = EventKind::ALL.iter().map(|kind| kind.as_str()).collect();
    let queryable: Vec<&str> = AuditEventKind::ALL
        .iter()
        .map(|kind| kind.as_str())
        .collect();
    assert_eq!(recorded, queryable);
}

async fn pool() -> PgPool {
    let database_url = env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL")
        .expect("SOVEREIGN_CONFIG_TEST_DATABASE_URL must be configured");
    let pool = PgPoolOptions::new().connect(&database_url).await.unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    clear_trail(&pool, ROOT).await;
    pool
}

fn audit(pool: &PgPool, page_size: u32) -> V4Audit {
    V4Audit::new(Arc::new(AuditTrailService::new(pool.clone(), page_size)))
}

const fn actor(protocol_version: &'static str) -> Actor<'static> {
    Actor {
        subject: "query-subject",
        name: Some("Query Tester"),
        protocol_version,
    }
}

/// A moment `seconds` after a fixed instant, so ordering is the test's choice
/// rather than the clock's.
fn at(seconds: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_789_000_000 + seconds).unwrap()
}

async fn record(pool: &PgPool, when: i64, event: AuditEvent<'_>) {
    record_as(pool, when, "v4", event).await;
}

async fn record_as(pool: &PgPool, when: i64, version: &'static str, event: AuditEvent<'_>) {
    AuditRecorder::for_tests()
        .record(pool, &actor(version), at(when), event)
        .await
        .expect("the event must be recorded");
}

fn created(path: &str) -> AuditEvent<'_> {
    AuditEvent::value_created(&actor("v4"), path, Recorded::Plain("on"))
}

fn caller(grants: &[(&str, &[Permission])]) -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        subject: "query-caller".into(),
        name: None,
        grants: grants
            .iter()
            .map(|(prefix, permissions)| Grant {
                prefix: (*prefix).into(),
                permissions: permissions.iter().copied().collect::<BTreeSet<_>>(),
            })
            .collect(),
    }
}

fn reader_of(prefix: &str) -> AuthenticatedPrincipal {
    caller(&[(prefix, &[Permission::Read])])
}

async fn query(
    service: &V4Audit,
    principal: &AuthenticatedPrincipal,
    message: QueryAuditTrailRequest,
) -> Result<QueryAuditTrailResponse, tonic::Status> {
    let mut request = Request::new(message);
    request.extensions_mut().insert(principal.clone());
    service
        .query_audit_trail(request)
        .await
        .map(tonic::Response::into_inner)
}

fn paths(response: &QueryAuditTrailResponse) -> Vec<&str> {
    response
        .events
        .iter()
        .map(|event| event.path.as_str())
        .collect()
}

/// The grant check the rest of the service applies, applied to the trail: a
/// caller sees events on the paths they may read, and none on paths they may
/// only write — however much else is in the table.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn a_caller_sees_only_events_on_paths_they_may_read() {
    let pool = pool().await;
    let service = audit(&pool, 100);
    let visible = format!("{ROOT}/visible/key");
    let hidden = format!("{ROOT}/hidden/key");
    let beside = format!("{ROOT}/visible-not/key");
    record(&pool, 1, created(&visible)).await;
    record(&pool, 2, created(&hidden)).await;
    record(&pool, 3, created(&beside)).await;
    record(&pool, 4, AuditEvent::values_listed(&actor("v4"), ROOT, 2)).await;

    let partial = caller(&[
        (&format!("{ROOT}/visible"), &[Permission::Read]),
        (
            &format!("{ROOT}/hidden"),
            &[Permission::Write, Permission::Manage],
        ),
    ]);
    let response = query(&service, &partial, QueryAuditTrailRequest::default())
        .await
        .unwrap();
    // `/visible-not` shares a prefix string with `/visible` but is not beneath
    // it, and the listing of the root is above it.
    assert_eq!(paths(&response), [visible.as_str()]);
    assert!(response.next_cursor.is_empty());

    let whole = query(
        &service,
        &reader_of(ROOT),
        QueryAuditTrailRequest::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        paths(&whole),
        [ROOT, beside.as_str(), hidden.as_str(), visible.as_str()]
    );

    let nobody = query(&service, &caller(&[]), QueryAuditTrailRequest::default())
        .await
        .unwrap();
    assert!(nobody.events.is_empty());

    clear_trail(&pool, ROOT).await;
}

/// Keyset paging returns every event exactly once, however the table changes
/// under a scroll: new events land above the cursor and a coalesced window
/// that is bumped mid-scroll keeps its place.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn paging_returns_each_event_exactly_once_while_events_are_written() {
    let pool = pool().await;
    let service = audit(&pool, 100);
    let reader = reader_of(ROOT);
    let values: Vec<String> = (0..25).map(|index| format!("{ROOT}/v{index:02}")).collect();
    for (index, path) in values.iter().enumerate() {
        record(&pool, i64::try_from(index).unwrap() * 10, created(path)).await;
    }
    // A coalescing access, near the bottom of the order.
    let revealed = format!("{ROOT}/secret");
    record(
        &pool,
        5,
        AuditEvent::secret_revealed(&actor("v4"), &revealed),
    )
    .await;

    let mut seen: Vec<u64> = Vec::new();
    let mut cursor = String::new();
    let mut pages = 0;
    loop {
        let page = query(
            &service,
            &reader,
            QueryAuditTrailRequest {
                page_size: 7,
                cursor: cursor.clone(),
                ..QueryAuditTrailRequest::default()
            },
        )
        .await
        .unwrap();
        seen.extend(page.events.iter().map(|event| event.id));
        pages += 1;
        if pages == 1 {
            // Written while the scroll is under way: a new event, and a repeat
            // of the not-yet-seen reveal that moves its row's `occurred_at`
            // above the cursor. Paged on `occurred_at`, that row would now be
            // skipped; paged on `first_occurred_at`, it keeps its place.
            record(&pool, 1_000, created(&format!("{ROOT}/late"))).await;
            record(
                &pool,
                900,
                AuditEvent::secret_revealed(&actor("v4"), &revealed),
            )
            .await;
        }
        if page.next_cursor.is_empty() {
            break;
        }
        cursor = page.next_cursor;
    }

    let distinct: BTreeSet<u64> = seen.iter().copied().collect();
    assert_eq!(seen.len(), distinct.len(), "an event was returned twice");
    assert_eq!(seen.len(), 26, "every event present at the start, once");
    assert_eq!(pages, 4);

    let trail = super::test_support::trail(&pool, &revealed).await;
    assert_eq!(trail.len(), 1);
    assert_eq!(
        trail[0].event_count, 2,
        "the reveal was bumped, not duplicated"
    );

    clear_trail(&pool, ROOT).await;
}

/// One value's history: what happened to it, and the only ways a plain value
/// is ever read — a subtree read of an ancestor or a listing of its parent.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn an_element_query_includes_ancestor_reads_and_parent_listings() {
    let pool = pool().await;
    let service = audit(&pool, 100);
    let parent = format!("{ROOT}/app");
    let element = format!("{parent}/key");
    let sibling = format!("{parent}/other");
    let v4 = actor("v4");
    record(&pool, 1, created(&element)).await;
    record(&pool, 2, AuditEvent::subtree_read(&v4, ROOT, 3)).await;
    record(&pool, 3, AuditEvent::subtree_read(&v4, &parent, 2)).await;
    record(&pool, 4, AuditEvent::values_listed(&v4, &parent, 2)).await;
    // Not how the element is read: a listing of its grandparent does not
    // include it, and a read of a sibling does not reach it.
    record(&pool, 5, AuditEvent::values_listed(&v4, ROOT, 0)).await;
    record(&pool, 6, AuditEvent::subtree_read(&v4, &sibling, 1)).await;
    record(&pool, 7, created(&sibling)).await;
    // A change to an ancestor is not a change to the element.
    record(
        &pool,
        8,
        AuditEvent::subtree_replaced(&v4, &parent, 0, 1, 0, 0),
    )
    .await;

    let response = query(
        &service,
        &reader_of(ROOT),
        QueryAuditTrailRequest {
            element_path: element.to_uppercase().replace("/TESTS", "/tests"),
            ..QueryAuditTrailRequest::default()
        },
    )
    .await
    .unwrap();

    let kinds: Vec<(&str, i32)> = response
        .events
        .iter()
        .map(|event| (event.path.as_str(), event.kind))
        .collect();
    assert_eq!(
        kinds,
        [
            (parent.as_str(), v4::AuditEventKind::ValuesListed as i32),
            (parent.as_str(), v4::AuditEventKind::SubtreeRead as i32),
            (ROOT, v4::AuditEventKind::SubtreeRead as i32),
            (element.as_str(), v4::AuditEventKind::ValueCreated as i32),
        ]
    );

    clear_trail(&pool, ROOT).await;
}

/// The configured page size is both the default and the ceiling.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn the_page_size_is_capped_at_the_configured_size() {
    let pool = pool().await;
    let service = audit(&pool, 3);
    for index in 0..5 {
        record(&pool, index, created(&format!("{ROOT}/v{index}"))).await;
    }

    for (requested, returned) in [(0, 3), (2, 2), (3, 3), (500, 3)] {
        let response = query(
            &service,
            &reader_of(ROOT),
            QueryAuditTrailRequest {
                page_size: requested,
                ..QueryAuditTrailRequest::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(response.events.len(), returned, "asked for {requested}");
        assert!(!response.next_cursor.is_empty(), "asked for {requested}");
    }

    clear_trail(&pool, ROOT).await;
}

/// Each filter narrows the result, and a fragment is matched as text, never
/// as a pattern: `_` is a legal path character and matches only itself.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn every_filter_narrows_and_fragments_match_literally() {
    let pool = pool().await;
    let service = audit(&pool, 100);
    let reader = reader_of(ROOT);
    let underscored = format!("{ROOT}/DB_URL");
    let lookalike = format!("{ROOT}/dbxurl");
    record_as(&pool, 10, "v3", created(&underscored)).await;
    record_as(&pool, 20, "v4", created(&lookalike)).await;
    record(
        &pool,
        30,
        AuditEvent::secret_revealed(&actor("v4"), &lookalike),
    )
    .await;

    let matching = |message: QueryAuditTrailRequest| {
        let service = &service;
        let reader = &reader;
        async move {
            let response = query(service, reader, message).await.unwrap();
            response
                .events
                .iter()
                .map(|event| (event.path.clone(), event.kind))
                .collect::<Vec<_>>()
        }
    };
    let created_kind = v4::AuditEventKind::ValueCreated as i32;
    let revealed_kind = v4::AuditEventKind::SecretRevealed as i32;

    assert_eq!(
        matching(QueryAuditTrailRequest {
            path_filter: "db_url".into(),
            ..QueryAuditTrailRequest::default()
        })
        .await,
        [(underscored.clone(), created_kind)]
    );
    assert_eq!(
        matching(QueryAuditTrailRequest {
            text_filter: "REVEALED SECRET".into(),
            ..QueryAuditTrailRequest::default()
        })
        .await,
        [(lookalike.clone(), revealed_kind)]
    );
    assert_eq!(
        matching(QueryAuditTrailRequest {
            protocol_version: "v3".into(),
            ..QueryAuditTrailRequest::default()
        })
        .await,
        [(underscored.clone(), created_kind)]
    );
    assert_eq!(
        matching(QueryAuditTrailRequest {
            kinds: vec![revealed_kind],
            ..QueryAuditTrailRequest::default()
        })
        .await,
        [(lookalike.clone(), revealed_kind)]
    );
    assert_eq!(
        matching(QueryAuditTrailRequest {
            from: Some(prost_types::Timestamp {
                seconds: at(15).unix_timestamp(),
                nanos: 0,
            }),
            until: Some(prost_types::Timestamp {
                seconds: at(25).unix_timestamp(),
                nanos: 0,
            }),
            ..QueryAuditTrailRequest::default()
        })
        .await,
        [(lookalike.clone(), created_kind)]
    );

    clear_trail(&pool, ROOT).await;
}

/// A coalesced window is served with its count and period, and every column a
/// client is owed arrives intact.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn a_coalesced_event_is_served_with_its_count_and_period() {
    let pool = pool().await;
    let service = audit(&pool, 100);
    let path = format!("{ROOT}/secret");
    for when in [0, 60, 120] {
        record(
            &pool,
            when,
            AuditEvent::secret_revealed(&actor("v4"), &path),
        )
        .await;
    }

    let response = query(
        &service,
        &reader_of(ROOT),
        QueryAuditTrailRequest::default(),
    )
    .await
    .unwrap();
    let [event] = response.events.as_slice() else {
        panic!("one coalesced event expected: {:?}", response.events);
    };
    assert_eq!(event.event_count, 3);
    assert_eq!(event.kind, v4::AuditEventKind::SecretRevealed as i32);
    assert_eq!(event.actor_subject, "query-subject");
    assert_eq!(event.actor_name.as_deref(), Some("Query Tester"));
    assert_eq!(event.protocol_version, "v4");
    assert_eq!(
        event.first_occurred_at.as_ref().map(|at| at.seconds),
        Some(at(0).unix_timestamp())
    );
    assert_eq!(
        event.occurred_at.as_ref().map(|at| at.seconds),
        Some(at(120).unix_timestamp())
    );
    assert!(
        event.narrative.starts_with("Query Tester revealed secret ")
            && event.narrative.contains(" — 3 times between "),
        "{}",
        event.narrative
    );
    assert_eq!(
        (event.old_value.as_ref(), event.new_value.as_ref()),
        (None, None)
    );

    clear_trail(&pool, ROOT).await;
}

/// A malformed query is refused before anything is read, and a kind with no
/// version-free form is malformed.
#[tokio::test]
async fn a_malformed_query_is_invalid_before_it_is_authorized() {
    let pool = PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(50))
        .connect_lazy("postgresql://unused@127.0.0.1:1/unused")
        .unwrap();
    let service = audit(&pool, 100);
    for message in [
        QueryAuditTrailRequest {
            kinds: vec![v4::AuditEventKind::Unspecified as i32],
            ..QueryAuditTrailRequest::default()
        },
        QueryAuditTrailRequest {
            kinds: vec![999],
            ..QueryAuditTrailRequest::default()
        },
        QueryAuditTrailRequest {
            cursor: "not-a-cursor".into(),
            ..QueryAuditTrailRequest::default()
        },
        QueryAuditTrailRequest {
            element_path: "not-rooted".into(),
            ..QueryAuditTrailRequest::default()
        },
    ] {
        // No principal at all: validation comes first.
        let status = service
            .query_audit_trail(Request::new(message))
            .await
            .expect_err("a malformed query must be refused");
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.message(), "audit query is invalid");
    }

    let status = service
        .query_audit_trail(Request::new(QueryAuditTrailRequest::default()))
        .await
        .expect_err("a well-formed query still needs a caller");
    assert_eq!(status.code(), Code::Unauthenticated);
}

/// An alias event names its other path, so it is visible only to a caller who
/// may read both — `ListValuePaths` hides an unreadable alias, and the trail
/// must not name it instead, in a result or through the narrative filter.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn an_alias_event_is_hidden_from_a_caller_who_cannot_read_both_paths() {
    let pool = pool().await;
    let service = audit(&pool, 100);
    let source = sovereign_config_core::ConfigPath::parse(format!("{ROOT}/open/src")).unwrap();
    let alias = sovereign_config_core::ConfigPath::parse(format!("{ROOT}/closed/alias")).unwrap();
    let [on_alias, on_source] = AuditEvent::path_added(&actor("v4"), &source, &alias);
    record(&pool, 1, on_alias).await;
    record(&pool, 2, on_source).await;
    record(&pool, 3, created(source.as_str())).await;

    let open_only = reader_of(&format!("{ROOT}/open"));
    let seen = query(&service, &open_only, QueryAuditTrailRequest::default())
        .await
        .unwrap();
    assert_eq!(paths(&seen), [source.as_str()], "only the plain creation");
    let probed = query(
        &service,
        &open_only,
        QueryAuditTrailRequest {
            text_filter: "closed".into(),
            ..QueryAuditTrailRequest::default()
        },
    )
    .await
    .unwrap();
    assert!(
        probed.events.is_empty(),
        "the hidden path cannot be probed for"
    );

    let both = query(
        &service,
        &reader_of(ROOT),
        QueryAuditTrailRequest::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        paths(&both),
        [source.as_str(), source.as_str(), alias.as_str()]
    );

    clear_trail(&pool, ROOT).await;
}

/// A managed connection's events need `manage` on its root — the grant that
/// lists the connection at all — and `read` alone does not show them.
#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn connection_events_need_manage_and_value_events_need_read() {
    let pool = pool().await;
    let service = audit(&pool, 100);
    let root = format!("{ROOT}/conn");
    let value = format!("{root}/key");
    record(
        &pool,
        1,
        AuditEvent::connection_created(
            &actor("v4"),
            super::ConnectionSubject {
                root: &root,
                display_name: "Shown to managers",
                connection_id: "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8",
            },
            "read",
        ),
    )
    .await;
    record(&pool, 2, created(&value)).await;

    let reader = query(
        &service,
        &reader_of(ROOT),
        QueryAuditTrailRequest::default(),
    )
    .await
    .unwrap();
    assert_eq!(paths(&reader), [value.as_str()]);

    let manager = caller(&[(ROOT, &[Permission::Manage])]);
    let as_manager = query(&service, &manager, QueryAuditTrailRequest::default())
        .await
        .unwrap();
    assert_eq!(paths(&as_manager), [root.as_str()]);
    assert_eq!(
        as_manager.events[0].kind,
        v4::AuditEventKind::ConnectionCreated as i32
    );

    clear_trail(&pool, ROOT).await;
}
