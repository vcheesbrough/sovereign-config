//! What each version's `Configuration` shim does before the shared
//! implementation sees a request: `v3` nothing, `v4` its own basic validation.
//!
//! Both shims here run over **one** shared implementation, the way `main.rs`
//! registers them, so any difference in what they answer is the shim's alone.
//! None of these requests reaches storage — every one is refused first — so
//! they run in a plain `cargo test` over a pool that never connects.

use std::{collections::BTreeSet, sync::Arc};

use sovereign_config_proto::sovereign::config::{v3, v4};
use sqlx::postgres::PgPoolOptions;
use tonic::{Code, Request, Status};

use super::{ConfigurationService, V3Configuration, V4Configuration};
use crate::audit::AuditRecorder;
use crate::auth::{AuthenticatedPrincipal, Grant, Permission};
use crate::encryption::ValueCipher;

fn shims() -> (V3Configuration, V4Configuration) {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://unused@127.0.0.1:1/unused")
        .expect("a lazy pool must build without connecting");
    let mut key = [0x5A; 32];
    let shared = Arc::new(ConfigurationService::new(
        pool,
        Arc::new(ValueCipher::new(&mut key)),
        AuditRecorder::for_tests(),
    ));
    (
        V3Configuration::new(Arc::clone(&shared)),
        V4Configuration::new(shared),
    )
}

/// A caller who may read `/apps` but write nothing: every write below is one
/// they are not permitted to make, whatever its content.
fn reader<T>(message: T) -> Request<T> {
    let mut request = Request::new(message);
    request.extensions_mut().insert(AuthenticatedPrincipal {
        subject: "shim-reader".into(),
        name: None,
        grants: vec![Grant {
            prefix: "/apps".into(),
            permissions: BTreeSet::from([Permission::Read]),
        }],
    });
    request
}

fn assert_status(status: &Status, code: Code, message: &str) {
    assert_eq!((status.code(), status.message()), (code, message));
}

const DENIED: &str = "configuration operation is not permitted";

/// `PutValue` with no content: `v3` authorizes first and refuses the caller,
/// as it always has; `v4` refuses the request, whoever sent it.
#[tokio::test]
async fn a_put_with_no_content_is_invalid_on_v4_and_still_denied_first_on_v3() {
    use v3::configuration_server::Configuration as _;
    use v4::configuration_server::Configuration as _;
    let (v3_shim, v4_shim) = shims();

    let on_v3 = v3_shim
        .put_value(reader(v3::PutValueRequest {
            path: "/apps/flag".into(),
            content: None,
        }))
        .await
        .expect_err("a reader may not write");
    let on_v4 = v4_shim
        .put_value(reader(v4::PutValueRequest {
            path: "/apps/flag".into(),
            content: None,
        }))
        .await
        .expect_err("a put with no content is malformed");

    assert_status(&on_v3, Code::PermissionDenied, DENIED);
    assert_status(
        &on_v4,
        Code::InvalidArgument,
        "configuration value is invalid",
    );
}

#[tokio::test]
async fn a_put_containing_nul_is_invalid_on_v4_and_still_denied_first_on_v3() {
    use v3::configuration_server::Configuration as _;
    use v4::configuration_server::Configuration as _;
    let (v3_shim, v4_shim) = shims();

    let on_v3 = v3_shim
        .put_value(reader(v3::PutValueRequest {
            path: "/apps/flag".into(),
            content: Some(v3::put_value_request::Content::SecretValue("a\0b".into())),
        }))
        .await
        .expect_err("a reader may not write");
    let on_v4 = v4_shim
        .put_value(reader(v4::PutValueRequest {
            path: "/apps/flag".into(),
            content: Some(v4::put_value_request::Content::SecretValue("a\0b".into())),
        }))
        .await
        .expect_err("a value containing NUL is malformed");

    assert_status(&on_v3, Code::PermissionDenied, DENIED);
    assert_status(
        &on_v4,
        Code::InvalidArgument,
        "configuration value contains an invalid character",
    );
}

#[tokio::test]
async fn a_subtree_entry_with_no_content_is_invalid_on_v4_and_still_denied_first_on_v3() {
    use v3::configuration_server::Configuration as _;
    use v4::configuration_server::Configuration as _;
    let (v3_shim, v4_shim) = shims();

    let on_v3 = v3_shim
        .replace_sub_tree(reader(v3::ReplaceSubTreeRequest {
            path: "/apps".into(),
            values: vec![v3::SubTreeMutationValue {
                path: "/apps/flag".into(),
                content: None,
            }],
        }))
        .await
        .expect_err("a reader may not replace a subtree");
    let on_v4 = v4_shim
        .replace_sub_tree(reader(v4::ReplaceSubTreeRequest {
            path: "/apps".into(),
            values: vec![v4::SubTreeMutationValue {
                path: "/apps/flag".into(),
                content: None,
            }],
        }))
        .await
        .expect_err("an entry with no content is malformed");

    assert_status(&on_v3, Code::PermissionDenied, DENIED);
    assert_status(
        &on_v4,
        Code::InvalidArgument,
        "configuration subtree is invalid",
    );
}

/// `v4`'s checks refuse only what is malformed: a well-formed write reaches
/// the shared implementation, which denies it exactly as it does on `v3`.
#[tokio::test]
async fn a_well_formed_request_passes_v4s_checks_to_the_shared_implementation() {
    use v3::configuration_server::Configuration as _;
    use v4::configuration_server::Configuration as _;
    let (v3_shim, v4_shim) = shims();

    let on_v3 = v3_shim
        .put_value(reader(v3::PutValueRequest {
            path: "/apps/flag".into(),
            content: Some(v3::put_value_request::Content::PlainValue("on".into())),
        }))
        .await
        .expect_err("a reader may not write");
    let on_v4 = v4_shim
        .put_value(reader(v4::PutValueRequest {
            path: "/apps/flag".into(),
            content: Some(v4::put_value_request::Content::PlainValue("on".into())),
        }))
        .await
        .expect_err("a reader may not write");

    assert_status(&on_v3, Code::PermissionDenied, DENIED);
    assert_status(&on_v4, Code::PermissionDenied, DENIED);
}
