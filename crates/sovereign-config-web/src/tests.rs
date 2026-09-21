use prost::Message;
use sovereign_config_core::ErrorKind;
use sovereign_config_proto::sovereign::config::v3::GetIdentityResponse;

use std::collections::BTreeSet;

use sovereign_config_core::ConfigPath;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::configuration::parse_absolute_path;
use crate::route::{Route, route_from_path, route_url};
use crate::session::{classify_refresh_error, identity_display_name};
use crate::transport::{decode_grpc_web, decode_grpc_web_response};
use crate::tree::TreeGuide::{Blank, Branch, Corner, Trunk};
use crate::tree::{TreeNode, build_tree, namespace_labels, tree_guides, value_parents_of};

fn paths(values: &[&str]) -> Vec<ConfigPath> {
    values
        .iter()
        .map(|path| ConfigPath::parse(*path).unwrap())
        .collect()
}

fn roots(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|root| (*root).to_owned()).collect()
}

#[test]
fn value_paths_imply_every_namespace_and_the_root() {
    let labels = namespace_labels(&paths(&[
        "/apps/api/enabled",
        "/apps/api/nested/message",
        "/top-level",
    ]));

    assert_eq!(
        labels.into_keys().collect::<Vec<_>>(),
        ["/", "/apps", "/apps/api", "/apps/api/nested"]
    );
}

#[test]
fn namespace_labels_use_the_fold_smallest_contributing_path() {
    // `/Apps/API/enabled` and `/apps/api/other` share the fold ancestor
    // `/apps/api`; "/Apps/API" (uppercase) sorts before "/apps/api"
    // (lowercase) as a fold key, so its case wins the ancestor's label —
    // deterministic without needing a creation timestamp, which
    // `GetSubTree` does not carry.
    let mixed = vec![
        ConfigPath::parse_operation("/apps/api/other").unwrap(),
        ConfigPath::parse_operation("/Apps/API/enabled").unwrap(),
    ];
    let labels = namespace_labels(&mixed);
    assert_eq!(labels.get("/apps").map(String::as_str), Some("/Apps"));
    assert_eq!(
        labels.get("/apps/api").map(String::as_str),
        Some("/Apps/API")
    );
}

#[test]
fn only_namespaces_directly_holding_values_are_bold() {
    // `/apps` is an ancestor of two values but holds none itself, which is
    // exactly the distinction `ListValues.paths` cannot express.
    let value_paths = paths(&["/apps/api/enabled", "/apps/api/nested/message", "/loose"]);

    let parents = value_parents_of(&value_paths);

    assert_eq!(
        parents.into_iter().collect::<Vec<_>>(),
        ["/", "/apps/api", "/apps/api/nested"]
    );
}

#[test]
fn tree_orders_subtrees_contiguously_and_marks_access_urls() {
    // `-` sorts before `/`, so a raw string sort would wedge `/apps-legacy`
    // between `/apps` and its own children.
    let value_paths = paths(&["/apps/api/enabled", "/apps-legacy/flag", "/apps/web/theme"]);
    let labels = namespace_labels(&value_paths);
    let parents = value_parents_of(&value_paths);

    let tree = build_tree(&labels, &parents, &roots(&["/apps/api", "/absent"]));

    let rendered = tree
        .iter()
        .map(|node| {
            (
                node.path.as_str(),
                node.depth,
                node.has_values,
                node.has_connection,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        rendered,
        [
            ("/", 0, false, false),
            ("/apps", 1, false, false),
            ("/apps/api", 2, true, true),
            ("/apps/web", 2, true, false),
            ("/apps-legacy", 1, true, false),
        ]
    );
}

#[test]
fn an_empty_estate_still_offers_the_root_node() {
    let tree = build_tree(&namespace_labels(&[]), &BTreeSet::new(), &BTreeSet::new());

    assert_eq!(tree.len(), 1);
    assert_eq!(tree[0].path.as_str(), "/");
    assert!(!tree[0].has_values);
}

#[test]
fn absolute_configuration_paths_retain_case() {
    assert_eq!(parse_absolute_path("/").unwrap().as_str(), "/");
    assert_eq!(
        parse_absolute_path("/Apps/API").unwrap().as_str(),
        "/Apps/API"
    );
    // `_` became a legal segment character in 2.15.0; `.` did not.
    assert_eq!(
        parse_absolute_path("/Woodpecker/Global/GitHub_Token")
            .unwrap()
            .as_str(),
        "/Woodpecker/Global/GitHub_Token"
    );
    for invalid in ["", "apps/api", "/apps/", "/apps/bad.name", "//apps"] {
        assert!(
            parse_absolute_path(invalid).is_err(),
            "accepted {invalid:?}"
        );
    }
    // Routes retain the case the operator navigated to, same as the path
    // field: this is card #294's whole point, not lossy canonicalization.
    let route = route_from_path("/configuration/Apps/API");
    assert_eq!(route_url(&route), "/configuration/Apps/API");
    // With the System view gone, anything unrecognized lands on the
    // configuration root rather than a page of its own.
    assert_eq!(route_url(&route_from_path("/unknown")), "/configuration/");
    assert_eq!(route_url(&route_from_path("/")), "/configuration/");
}

#[test]
fn connection_routes_are_canonical() {
    assert!(matches!(
        route_from_path("/connections"),
        Route::Connections
    ));
    assert!(matches!(
        route_from_path("/connections/"),
        Route::Connections
    ));
    assert_eq!(route_url(&Route::Connections), "/connections/");
    assert_eq!(
        route_url(&route_from_path("/connections/extra")),
        "/configuration/"
    );
}

#[test]
fn audit_routes_are_canonical_and_keep_a_values_case() {
    for path in ["/audit", "/audit/"] {
        assert!(matches!(route_from_path(path), Route::Audit(None)));
    }
    assert_eq!(route_url(&Route::Audit(None)), "/audit/");
    let Route::Audit(Some(element)) = route_from_path("/audit/Apps/API/Key") else {
        panic!("a value path should open that value's history");
    };
    assert_eq!(element.as_str(), "/Apps/API/Key");
    assert_eq!(
        route_url(&route_from_path("/audit/Apps/API/Key")),
        "/audit/Apps/API/Key"
    );
    // A suffix that names no value falls back to the whole trail rather than
    // leaving the audit view.
    assert_eq!(route_url(&route_from_path("/audit/bad.name")), "/audit/");
}

fn node(path: &str, depth: usize) -> TreeNode {
    TreeNode {
        path: ConfigPath::parse(path).unwrap(),
        display: path.rsplit('/').next().unwrap_or("/").to_owned(),
        depth,
        has_values: false,
        has_connection: false,
    }
}

fn id_token(claims: &str) -> String {
    format!(
        "header.{}.signature",
        URL_SAFE_NO_PAD.encode(claims.as_bytes())
    )
}

#[test]
fn tree_guides_close_the_last_branch_at_every_level() {
    // /
    // ├─ apps
    // │  ├─ api
    // │  │  └─ db
    // │  └─ worker
    // └─ infra
    let nodes = [
        node("/", 0),
        node("/apps", 1),
        node("/apps/api", 2),
        node("/apps/api/db", 3),
        node("/apps/worker", 2),
        node("/infra", 1),
    ];

    assert_eq!(
        tree_guides(&nodes),
        [
            vec![],
            vec![Branch],
            vec![Trunk, Branch],
            vec![Trunk, Trunk, Corner],
            vec![Trunk, Corner],
            vec![Corner],
        ]
    );
}

#[test]
fn tree_guides_blank_the_trunk_below_a_closed_branch() {
    // A deeper node under the *last* child must not keep drawing its
    // parent's trunk — that is the one case a naive depth-only indent gets
    // wrong.
    let nodes = [
        node("/", 0),
        node("/apps", 1),
        node("/apps/api", 2),
        node("/apps/api/db", 3),
    ];

    assert_eq!(
        tree_guides(&nodes),
        [
            vec![],
            vec![Corner],
            vec![Blank, Corner],
            vec![Blank, Blank, Corner],
        ]
    );
}

#[test]
fn tree_guides_handle_the_empty_and_root_only_cases() {
    assert!(tree_guides(&[]).is_empty());
    assert_eq!(tree_guides(&[node("/", 0)]), [Vec::new()]);
}

#[test]
fn identity_prefers_the_most_human_claim_available() {
    assert_eq!(
        identity_display_name(&id_token(
            r#"{"sub":"abc","email":"a@b.test","preferred_username":"avc","name":"A Vincent"}"#
        ))
        .as_deref(),
        Some("A Vincent")
    );
    assert_eq!(
        identity_display_name(&id_token(
            r#"{"sub":"abc","email":"a@b.test","preferred_username":"avc"}"#
        ))
        .as_deref(),
        Some("avc")
    );
    assert_eq!(
        identity_display_name(&id_token(r#"{"sub":"abc","email":"a@b.test"}"#)).as_deref(),
        Some("a@b.test")
    );
    // `sub` is the provider's hashed identifier, never a name: a token
    // carrying nothing else leaves the header unlabelled rather than
    // pinning a digest to the session.
    assert_eq!(identity_display_name(&id_token(r#"{"sub":"abc"}"#)), None);
}

#[test]
fn identity_skips_blank_and_non_string_claims() {
    assert_eq!(
        identity_display_name(&id_token(r#"{"name":"   ","preferred_username":"avc"}"#)).as_deref(),
        Some("avc")
    );
    assert_eq!(
        identity_display_name(&id_token(r#"{"name":42,"email":"a@b.test"}"#)).as_deref(),
        Some("a@b.test")
    );
    assert_eq!(identity_display_name(&id_token("{}")), None);
}

#[test]
fn identity_rejects_tokens_it_cannot_read() {
    // A malformed token labels nothing rather than labelling it wrongly;
    // the header is the only thing this name ever drives.
    for malformed in [
        "",
        "header",
        "header.signature",
        "header.!!!not-base64!!!.signature",
        &id_token("not json"),
    ] {
        assert_eq!(identity_display_name(malformed), None, "read {malformed:?}");
    }
}

#[test]
fn refresh_error_rejects_only_invalid_grant() {
    let error = classify_refresh_error(400, Some("invalid_grant"));

    assert_eq!(error.kind, ErrorKind::Unauthenticated);
    assert_eq!(error.message(), "login has expired");
}

#[test]
fn refresh_error_preserves_sessions_for_provider_failures() {
    for (status, oauth_error) in [
        (429, Some("slow_down")),
        (500, Some("server_error")),
        (503, None),
        (400, Some("invalid_request")),
        (400, None),
    ] {
        let error = classify_refresh_error(status, oauth_error);
        assert_eq!(error.kind, ErrorKind::Unavailable);
        assert_eq!(error.message(), "identity provider is unavailable");
    }
}

#[test]
fn grpc_web_decoder_reads_data_and_success_trailer() {
    let message = GetIdentityResponse {
        authenticated: true,
    }
    .encode_to_vec();
    let mut response = vec![0];
    response.extend_from_slice(&u32::try_from(message.len()).unwrap().to_be_bytes());
    response.extend_from_slice(&message);
    let trailer = b"grpc-status: 0\r\n";
    response.push(0x80);
    response.extend_from_slice(&u32::try_from(trailer.len()).unwrap().to_be_bytes());
    response.extend_from_slice(trailer);
    let decoded: GetIdentityResponse = decode_grpc_web(&response).unwrap();
    assert!(decoded.authenticated);
}

#[test]
fn grpc_web_decoder_rejects_responses_without_a_status_trailer() {
    let message = GetIdentityResponse {
        authenticated: true,
    }
    .encode_to_vec();
    let mut data_only = vec![0];
    data_only.extend_from_slice(&u32::try_from(message.len()).unwrap().to_be_bytes());
    data_only.extend_from_slice(&message);

    let mut missing_status = data_only.clone();
    let trailer = b"grpc-message: missing status\r\n";
    missing_status.push(0x80);
    missing_status.extend_from_slice(&u32::try_from(trailer.len()).unwrap().to_be_bytes());
    missing_status.extend_from_slice(trailer);

    for response in [data_only, missing_status] {
        let error = decode_grpc_web::<GetIdentityResponse>(&response).unwrap_err();
        assert_eq!(error.kind, ErrorKind::Internal);
        assert_eq!(error.message(), "request failed");
    }
}

#[test]
fn grpc_web_decoder_accepts_trailers_only_status_headers() {
    let error = decode_grpc_web_response::<GetIdentityResponse>(&[], Some(7), None).unwrap_err();
    assert_eq!(error.kind, ErrorKind::PermissionDenied);
    assert_eq!(error.message(), "permission denied");
}

/// gRPC status 12 (`UNIMPLEMENTED`) is what the browser sees once the server
/// stops routing the protocol version it was built against. It must read as an
/// incompatibility, not as the opaque failure every unmapped status becomes.
#[test]
fn grpc_web_decoder_reports_an_unimplemented_route_as_an_incompatible_protocol() {
    let error = decode_grpc_web_response::<GetIdentityResponse>(&[], Some(12), None).unwrap_err();
    assert_eq!(error.kind, ErrorKind::IncompatibleProtocol);
}
