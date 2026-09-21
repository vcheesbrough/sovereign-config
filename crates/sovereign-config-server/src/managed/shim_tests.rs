//! What each version's `ManagedConnections` shim does before the shared
//! implementation sees a request: `v3` nothing, `v4` its own basic validation.
//!
//! Both shims run over one shared implementation, as `main.rs` registers them.
//! Nothing here reaches storage or Authentik, so it runs without either.

use std::{sync::Arc, time::Duration};

use sovereign_config_core::Secret;
use sovereign_config_proto::sovereign::config::{v3, v4};
use sqlx::postgres::PgPoolOptions;
use tonic::{Code, Request};

use super::{
    ManagedConnectionsService, ManagedSettings, V3ManagedConnections, V4ManagedConnections,
};
use crate::audit::AuditRecorder;
use crate::authentik::AuthentikAdminClient;
use crate::metrics::ManagedConnectionMetrics;

fn shims(metrics: Arc<ManagedConnectionMetrics>) -> (V3ManagedConnections, V4ManagedConnections) {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://unused@127.0.0.1:1/unused")
        .expect("a lazy pool must build without connecting");
    let admin = AuthentikAdminClient::new(
        "http://127.0.0.1:1/"
            .parse()
            .expect("a loopback origin parses"),
        Secret::new("unused-api-token"),
        Duration::from_millis(50),
    )
    .expect("a loopback admin client must build");
    let shared = Arc::new(ManagedConnectionsService::new(
        pool,
        admin,
        ManagedSettings {
            public_origin: "https://config.example.test".to_owned(),
            issuer: "https://auth.example.test/application/o/sovereign-config/".to_owned(),
            client_id: "sovereign-config".to_owned(),
            grants_attribute: "sovereign_config_grants".to_owned(),
            managed_group: "sovereign-config-connections".to_owned(),
            rotation_lease: Duration::from_secs(60),
        },
        metrics,
        AuditRecorder::for_tests(),
    ));
    (
        V3ManagedConnections::new(Arc::clone(&shared)),
        V4ManagedConnections::new(shared),
    )
}

/// An empty permission selection from a request carrying no principal at all.
/// `v3` asks who is calling before it looks at the selection, as it always
/// has; `v4` refuses the selection first. The authentication layer never lets
/// such a request reach a handler, which is exactly why this is the case that
/// tells the two orders apart without changing anything a client can see.
#[tokio::test]
async fn an_empty_permission_selection_is_refused_by_v4_before_anything_else() {
    use v3::managed_connections_server::ManagedConnections as _;
    use v4::managed_connections_server::ManagedConnections as _;
    let metrics = Arc::new(ManagedConnectionMetrics::default());
    let (v3_shim, v4_shim) = shims(Arc::clone(&metrics));

    let on_v3 = v3_shim
        .create_managed_connection(Request::new(v3::CreateManagedConnectionRequest {
            display_name: "Shim".into(),
            root: "/apps".into(),
            permissions: vec![],
        }))
        .await
        .expect_err("no principal is attached");
    let on_v4 = v4_shim
        .create_managed_connection(Request::new(v4::CreateManagedConnectionRequest {
            display_name: "Shim".into(),
            root: "/apps".into(),
            permissions: vec![v4::ManagedPermission::Unspecified as i32],
        }))
        .await
        .expect_err("an unspecified permission is malformed");

    assert_eq!(on_v3.code(), Code::Unauthenticated);
    assert_eq!(on_v4.code(), Code::InvalidArgument);
    assert_eq!(on_v4.message(), "managed connection request is invalid");

    // A refusal in the shim is counted exactly as one in the shared
    // implementation would be: the operation metric cannot tell them apart.
    let rendered = metrics.render();
    for (result, count) in [("invalid_request", 1), ("unauthenticated", 1)] {
        let series = format!(
            "sovereign_config_managed_connection_operations_total{{operation=\"create\",result=\"{result}\"}} {count}"
        );
        assert!(
            rendered.contains(&series),
            "{series} missing from:\n{rendered}"
        );
    }
}
