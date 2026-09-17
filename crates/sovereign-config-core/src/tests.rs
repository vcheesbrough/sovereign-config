use super::{
    ConfigPath, ErrorKind, MASKED_SECRET_TEXT, MaskedSecret, PROTOCOL_VERSION, PlainValue,
    RevealedSecret, Secret, SecretInput, ServiceStatus, SubTreeMutationContent,
    SubTreeMutationValue, SubTreeValue, ValueContent, parse_subtree_json, render_subtree_json,
};

#[test]
fn paths_are_canonical_and_root_is_explicit() {
    assert_eq!(ConfigPath::root().as_str(), "/");
    assert!(ConfigPath::parse("/apps/api-v2").is_ok());
    for valid in [
        "/apps_api",
        "/woodpecker/global/github_token",
        "/apps/_leading",
        "/apps/trailing_",
        "/apps/__",
    ] {
        assert!(ConfigPath::parse(valid).is_ok(), "rejected {valid:?}");
    }
    for invalid in [
        "",
        "apps",
        "/apps/",
        "/apps//api",
        "/Apps",
        "/apps.api",
        "/apps+api",
        "/apps api",
    ] {
        assert!(ConfigPath::parse(invalid).is_err(), "accepted {invalid:?}");
    }
}

#[test]
fn operation_paths_normalize_ascii_case_and_join_to_roots() {
    let root = ConfigPath::parse("/teams/platform").unwrap();
    assert_eq!(
        root.join_name("Apps-API-V2").unwrap().fold(),
        "/teams/platform/apps-api-v2"
    );
    assert_eq!(
        root.join_name("Zot_CI_User").unwrap().fold(),
        "/teams/platform/zot_ci_user"
    );
    assert_eq!(
        ConfigPath::parse_operation("/Woodpecker/Global/GitHub_Token")
            .unwrap()
            .fold(),
        "/woodpecker/global/github_token"
    );
    for invalid in [
        "",
        "/",
        "apps",
        "apps/",
        "apps//api",
        ".",
        "..",
        "a%2fb",
        "caf\u{e9}",
        "/apps.api",
    ] {
        assert!(
            ConfigPath::parse_operation(invalid).is_err(),
            "accepted {invalid:?}"
        );
    }
    assert!(root.join_name("apps/api").is_err());
    assert_eq!(
        ConfigPath::parse_selection("/").unwrap(),
        ConfigPath::root()
    );
    assert_eq!(
        ConfigPath::parse_selection("/Apps/API").unwrap().fold(),
        "/apps/api"
    );
    assert!(
        ConfigPath::parse("/apps/api/key")
            .unwrap()
            .is_at_or_below(&ConfigPath::parse("/apps/api").unwrap())
    );
    assert!(
        !ConfigPath::parse("/apps/api-v2/key")
            .unwrap()
            .is_at_or_below(&ConfigPath::parse("/apps/api").unwrap())
    );
    assert!(
        !ConfigPath::parse("/foo/second/abc")
            .unwrap()
            .is_at_or_below(&ConfigPath::parse("/foo/s").unwrap())
    );
}

#[test]
fn paths_retain_display_case_while_folding_for_comparison() {
    let mixed = ConfigPath::parse_operation("/Apps/serverIP").unwrap();
    assert_eq!(mixed.as_str(), "/Apps/serverIP");
    assert_eq!(mixed.fold(), "/apps/serverip");
    assert_eq!(mixed.name(), Some("serverIP"));

    let lower = ConfigPath::parse_operation("/apps/serverip").unwrap();
    assert_eq!(mixed, lower, "fold-equal paths must compare equal");
    assert_eq!(lower.as_str(), "/apps/serverip");

    let root_selection = ConfigPath::parse_selection("/Apps").unwrap();
    assert_eq!(root_selection.as_str(), "/Apps");
    assert_eq!(root_selection.fold(), "/apps");

    let joined = root_selection.join_name("Server_IP").unwrap();
    assert_eq!(joined.as_str(), "/Apps/Server_IP");
    assert_eq!(joined.fold(), "/apps/server_ip");

    let mut ordered = [
        ConfigPath::parse_operation("/b").unwrap(),
        ConfigPath::parse_operation("/A").unwrap(),
    ];
    ordered.sort();
    assert_eq!(
        ordered.iter().map(ConfigPath::fold).collect::<Vec<_>>(),
        ["/a", "/b"],
        "ordering must follow the fold key, not the display form"
    );
}

fn subtree_value(path: &str, value: &str) -> SubTreeValue {
    SubTreeValue {
        path: ConfigPath::parse(path).unwrap(),
        value: ValueContent::Plain(PlainValue::new(value)),
    }
}

fn mutation_value(path: &str, value: &str) -> SubTreeMutationValue {
    SubTreeMutationValue {
        path: ConfigPath::parse(path).unwrap(),
        value: SubTreeMutationContent::Plain(PlainValue::new(value)),
    }
}

#[test]
fn subtree_json_round_trips_exact_nested_root_and_empty_values() {
    let selected = ConfigPath::parse("/apps/api").unwrap();
    let values = vec![
        subtree_value("/apps/api/enabled", "true"),
        subtree_value("/apps/api/nested/message", "line one\nline two"),
    ];
    let json = render_subtree_json(&selected, &values).unwrap();
    assert_eq!(
        json,
        "{\n  \"enabled\": \"true\",\n  \"nested\": {\n    \"message\": \"line one\\nline two\"\n  }\n}\n"
    );
    assert_eq!(
        parse_subtree_json(&selected, &json).unwrap(),
        vec![
            mutation_value("/apps/api/enabled", "true"),
            mutation_value("/apps/api/nested/message", "line one\nline two"),
        ]
    );

    let exact = vec![subtree_value("/apps/api", "value")];
    assert_eq!(
        render_subtree_json(&selected, &exact).unwrap(),
        "\"value\"\n"
    );
    assert_eq!(
        parse_subtree_json(&selected, "\"value\"").unwrap(),
        vec![mutation_value("/apps/api", "value")]
    );

    let same_name_child = vec![subtree_value("/apps/api/api", "child")];
    assert_eq!(
        render_subtree_json(&selected, &same_name_child).unwrap(),
        "{\n  \"api\": \"child\"\n}\n"
    );
    assert_eq!(
        parse_subtree_json(&selected, "{\"api\":\"child\"}").unwrap(),
        vec![mutation_value("/apps/api/api", "child")]
    );

    // Underscore keys round-trip: Woodpecker `from_secret:` names such as
    // `github_token` are stored verbatim as path segments.
    let underscored = vec![subtree_value("/apps/api/github_token", "value")];
    assert_eq!(
        render_subtree_json(&selected, &underscored).unwrap(),
        "{\n  \"github_token\": \"value\"\n}\n"
    );
    assert_eq!(
        parse_subtree_json(&selected, "{\"github_token\":\"value\"}").unwrap(),
        vec![mutation_value("/apps/api/github_token", "value")]
    );

    let root = ConfigPath::root();
    assert_eq!(
        parse_subtree_json(&root, "{\"apps\":{\"enabled\":\"yes\"}}").unwrap(),
        vec![mutation_value("/apps/enabled", "yes")]
    );
    assert_eq!(render_subtree_json(&selected, &[]).unwrap(), "{}\n");
    assert!(parse_subtree_json(&selected, "{}").unwrap().is_empty());
}

#[test]
fn subtree_json_keys_retain_display_case() {
    let selected = ConfigPath::parse_operation("/Apps/API").unwrap();
    let leaf = selected.join_name("serverIP").unwrap();
    let values = vec![SubTreeValue {
        path: leaf,
        value: ValueContent::Plain(PlainValue::new("value")),
    }];
    let json = render_subtree_json(&selected, &values).unwrap();
    assert_eq!(json, "{\n  \"serverIP\": \"value\"\n}\n");

    let parsed = parse_subtree_json(&selected, &json).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].path.as_str(), "/Apps/API/serverIP");
    assert_eq!(parsed[0].path.fold(), "/apps/api/serverip");

    // A lowercase key still resolves to the same established fold key.
    let refolded = parse_subtree_json(&selected, "{\"serverip\":\"value\"}").unwrap();
    assert_eq!(refolded[0].path, parsed[0].path);
}

#[test]
fn subtree_json_object_keys_order_by_fold_not_display_bytes() {
    // Byte order would put "Signing-Key" (uppercase 'S') before
    // "api-token" (lowercase 'a'); fold order — what every other JSON key
    // comparison in this system uses — puts it after, matching the order
    // an operator actually expects.
    let selected = ConfigPath::parse_operation("/apps/api").unwrap();
    let values = vec![
        SubTreeValue {
            path: ConfigPath::parse_operation("/apps/api/Signing-Key").unwrap(),
            value: ValueContent::Plain(PlainValue::new("one")),
        },
        SubTreeValue {
            path: ConfigPath::parse_operation("/apps/api/api-token").unwrap(),
            value: ValueContent::Plain(PlainValue::new("two")),
        },
    ];
    let json = render_subtree_json(&selected, &values).unwrap();
    assert_eq!(
        json,
        "{\n  \"api-token\": \"two\",\n  \"Signing-Key\": \"one\"\n}\n"
    );
}

#[test]
fn subtree_json_rejects_case_variant_duplicate_keys() {
    let selected = ConfigPath::parse("/apps/api").unwrap();
    assert!(parse_subtree_json(&selected, "{\"Foo\":\"a\",\"foo\":\"b\"}").is_err());
}

#[test]
fn subtree_json_rejects_lossy_or_invalid_shapes() {
    let selected = ConfigPath::parse("/apps/api").unwrap();
    let collisions = vec![
        subtree_value("/apps/api", "parent"),
        subtree_value("/apps/api/child", "child"),
    ];
    assert!(render_subtree_json(&selected, &collisions).is_err());
    assert!(
        render_subtree_json(&selected, &[subtree_value("/apps/api-v2/child", "outside")]).is_err()
    );
    assert!(
        render_subtree_json(
            &ConfigPath::root(),
            &[SubTreeValue {
                path: ConfigPath::root(),
                value: ValueContent::Plain(PlainValue::new("invalid-root-value")),
            }]
        )
        .is_err()
    );
    for invalid in [
        "[]",
        "true",
        "null",
        "{\"enabled\":true}",
        "{\"enabled\":null}",
        "{\"enabled\":[\"value\"]}",
        "{\"nested\":{\"bad.key\":\"value\"}}",
        "{\"enabled\":\"first\",\"enabled\":\"second\"}",
        "{\"enabled\":\"bad\\u0000value\"}",
    ] {
        assert!(
            parse_subtree_json(&selected, invalid).is_err(),
            "accepted {invalid}"
        );
    }
    assert!(parse_subtree_json(&ConfigPath::root(), "\"root-value\"").is_err());
}

#[test]
fn plain_values_are_redacted_in_formatters() {
    let value = PlainValue::new("value-sentinel");
    assert_eq!(value.expose(), "value-sentinel");
    assert_eq!(value.to_string(), "[REDACTED]");
    assert_eq!(format!("{value:?}"), "PlainValue([REDACTED])");
}

#[test]
fn secret_types_and_json_masks_are_safe_by_construction() {
    let input = SecretInput::new("secret-sentinel");
    let revealed = RevealedSecret::new("secret-sentinel");
    assert_eq!(input.expose(), "secret-sentinel");
    assert_eq!(revealed.expose(), "secret-sentinel");
    assert_eq!(format!("{input:?}"), "SecretInput([REDACTED])");
    assert_eq!(format!("{revealed:?}"), "RevealedSecret([REDACTED])");
    assert_eq!(MaskedSecret.to_string(), MASKED_SECRET_TEXT);

    let selected = ConfigPath::parse("/apps/api").unwrap();
    let masked = SubTreeValue {
        path: ConfigPath::parse("/apps/api/credential").unwrap(),
        value: ValueContent::Secret(MaskedSecret),
    };
    let json = render_subtree_json(&selected, &[masked]).unwrap();
    assert!(!json.contains("secret-sentinel"));
    assert_eq!(
        parse_subtree_json(&selected, &json).unwrap(),
        vec![SubTreeMutationValue {
            path: ConfigPath::parse("/apps/api/credential").unwrap(),
            value: SubTreeMutationContent::PreserveSecret,
        }]
    );
}

#[test]
fn protocol_negotiation_is_exact() {
    assert!(ServiceStatus::negotiate("1.5.0".into(), PROTOCOL_VERSION.into()).compatible);
    assert!(!ServiceStatus::negotiate("1.5.0".into(), "v1".into()).compatible);
}

#[test]
fn secrets_are_redacted_in_all_formatters() {
    let secret = Secret::new("credential-sentinel");
    assert_eq!(secret.to_string(), "[REDACTED]");
    assert_eq!(format!("{secret:?}"), "Secret([REDACTED])");
    assert_eq!(secret.expose(), "credential-sentinel");
}

#[test]
fn errors_expose_only_bounded_messages() {
    let error = super::ClientError::new(ErrorKind::Unavailable, "service unavailable");
    assert_eq!(error.to_string(), "service unavailable");
}
