use super::{
    ConfigPath, ErrorKind, MASKED_SECRET_TEXT, MaskedSecret, PlainValue, ProtocolVersion,
    RevealedSecret, Secret, SecretInput, ServiceStatus, SubTreeMutationContent,
    SubTreeMutationValue, SubTreeValue, ValueContent, parse_subtree_json, render_subtree_json,
    render_subtree_plain,
};

/// The versions a server advertises, as `GetVersionResponse` carries them.
fn advertised(versions: &[&str]) -> Vec<String> {
    versions
        .iter()
        .map(|version| (*version).to_owned())
        .collect()
}

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
fn protocol_negotiation_selects_a_version_inside_the_advertised_range() {
    let status = ServiceStatus::negotiate("1.5.0".into(), "v3", &advertised(&["v3"]))
        .expect("a server serving v3 must negotiate");
    assert_eq!(status.protocol_version, ProtocolVersion::V3);
    assert_eq!(status.application_version, "1.5.0");
}

#[test]
fn protocol_negotiation_accepts_a_server_newer_than_this_client() {
    // The outage this mechanism exists to prevent: the server has gained a
    // version this build has never heard of and still serves the one it speaks.
    let status = ServiceStatus::negotiate("9.0.0".into(), "v3", &advertised(&["v3", "v4"]))
        .expect("a newer server still serving v3 must negotiate");
    assert_eq!(status.protocol_version, ProtocolVersion::V3);
}

#[test]
fn protocol_negotiation_rejects_a_server_outside_the_range() {
    // Both boundaries: a server too new (v3 retired) and one too old.
    for offered in [advertised(&["v4", "v5"]), advertised(&["v1", "v2"])] {
        let error = ServiceStatus::negotiate("9.0.0".into(), "v4", &offered)
            .expect_err("a server with no version in common must be rejected");
        assert_eq!(error.kind, ErrorKind::IncompatibleProtocol);
    }
}

#[test]
fn protocol_negotiation_falls_back_to_the_echo_when_no_set_is_advertised() {
    // A server older than 2.25.0 sends no `supported_protocol_versions`.
    let status = ServiceStatus::negotiate("2.24.0".into(), "v3", &[])
        .expect("a pre-2.25.0 server must still negotiate on its echo alone");
    assert_eq!(status.protocol_version, ProtocolVersion::V3);

    let error = ServiceStatus::negotiate("2.24.0".into(), "v1", &[])
        .expect_err("an echo this build does not speak must be rejected");
    assert_eq!(error.kind, ErrorKind::IncompatibleProtocol);
}

#[test]
fn protocol_version_ordering_is_declaration_order_not_lexicographic() {
    // The hazard this ordering exists to avoid: a tenth version sorts *below* a
    // third one as a string, so comparing version strings would negotiate the
    // older session.
    assert!("v10" < "v3");

    // `ALL` is oldest-first and strictly ascending, which is what makes
    // selecting the highest mutual version a reverse scan.
    assert!(
        ProtocolVersion::ALL
            .windows(2)
            .all(|pair| pair[0] < pair[1]),
        "ProtocolVersion::ALL must be declared oldest-first"
    );
    assert_eq!(
        ProtocolVersion::ALL.last().copied(),
        Some(ProtocolVersion::PREFERRED),
        "PREFERRED must be the newest version in ALL"
    );
}

#[test]
fn protocol_version_parsing_ignores_versions_this_build_does_not_speak() {
    assert_eq!(ProtocolVersion::parse("v3"), Some(ProtocolVersion::V3));
    for unknown in ["v1", "v4", "v10", "V3", "3", ""] {
        assert_eq!(ProtocolVersion::parse(unknown), None, "{unknown:?}");
    }
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
fn secret_value(path: &str) -> SubTreeValue {
    SubTreeValue {
        path: ConfigPath::parse(path).unwrap(),
        value: ValueContent::Secret(MaskedSecret),
    }
}

/// The JSON object keys a rendered subtree visits, in order — the flattened
/// shape a plain rendering has to agree with.
fn json_key_order(json: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let mut prefix: Vec<String> = Vec::new();
    for line in json.lines() {
        let trimmed = line.trim();
        let Some((key, rest)) = trimmed.split_once("\": ") else {
            if trimmed.starts_with('}') {
                prefix.pop();
            }
            continue;
        };
        let key = key.trim_start_matches('"').to_owned();
        if rest.starts_with('{') {
            prefix.push(key);
        } else {
            let mut path = prefix.clone();
            path.push(key);
            keys.push(path.join("/"));
        }
    }
    keys
}

#[test]
fn subtree_plain_renders_one_escaped_line_per_absolute_path() {
    let selected = ConfigPath::parse("/apps/api").unwrap();
    let values = vec![
        subtree_value("/apps/api/enabled", "true"),
        subtree_value("/apps/api/db/host", "pg.internal"),
        secret_value("/apps/api/db/password"),
    ];
    assert_eq!(
        render_subtree_plain(&selected, &values).unwrap(),
        "/apps/api/db/host=pg.internal\n\
         /apps/api/db/password=********\n\
         /apps/api/enabled=true\n"
    );
}

#[test]
fn subtree_plain_orders_exactly_as_the_json_renderer_does() {
    let selected = ConfigPath::root();
    // `-` (0x2D) sorts below `/` (0x2F), so whole-path byte ordering would put
    // `/a-c` first; segment ordering — which JSON uses — puts `/a/b` first.
    let values = vec![
        subtree_value("/a-c", "second"),
        subtree_value("/a/b", "first"),
        subtree_value("/a/b-d", "third"),
        subtree_value("/ab", "fourth"),
    ];
    let plain = render_subtree_plain(&selected, &values).unwrap();
    let plain_paths: Vec<&str> = plain
        .lines()
        .map(|line| line.split_once('=').unwrap().0)
        .collect();
    assert_eq!(plain_paths, ["/a/b", "/a/b-d", "/a-c", "/ab"]);

    let json_paths: Vec<String> = json_key_order(&render_subtree_json(&selected, &values).unwrap())
        .into_iter()
        .map(|key| format!("/{key}"))
        .collect();
    assert_eq!(plain_paths, json_paths);
}

#[test]
fn subtree_plain_escapes_only_the_separators_that_would_split_a_line() {
    let selected = ConfigPath::parse("/apps/api").unwrap();
    let values = vec![
        subtree_value("/apps/api/multiline", "line one\nline two\r\nline three"),
        subtree_value("/apps/api/windows-path", r"C:\temp\file"),
        subtree_value("/apps/api/equals", "key=value=more"),
        subtree_value("/apps/api/quoted", "he said \"hi\"\ttabbed"),
    ];
    assert_eq!(
        render_subtree_plain(&selected, &values).unwrap(),
        "/apps/api/equals=key=value=more\n\
         /apps/api/multiline=line one\\nline two\\r\\nline three\n\
         /apps/api/quoted=he said \"hi\"\ttabbed\n\
         /apps/api/windows-path=C:\\\\temp\\\\file\n"
    );
}

#[test]
fn subtree_plain_masks_secrets_until_the_caller_replaces_them() {
    let selected = ConfigPath::parse("/apps/api").unwrap();
    let masked = vec![secret_value("/apps/api/credential")];
    assert_eq!(
        render_subtree_plain(&selected, &masked).unwrap(),
        format!("/apps/api/credential={MASKED_SECRET_TEXT}\n")
    );

    // Revealing replaces the content before rendering, exactly as the CLI does.
    let revealed = vec![subtree_value("/apps/api/credential", "plaintext-sentinel")];
    assert_eq!(
        render_subtree_plain(&selected, &revealed).unwrap(),
        "/apps/api/credential=plaintext-sentinel\n"
    );
}

#[test]
fn subtree_plain_renders_an_exact_value_and_its_descendants_together() {
    let selected = ConfigPath::parse("/apps/api").unwrap();
    assert_eq!(
        render_subtree_plain(&selected, &[subtree_value("/apps/api", "exact")]).unwrap(),
        "/apps/api=exact\n"
    );

    // JSON cannot represent a value that is also an object; plain simply lists
    // both, the shorter path first.
    let collision = vec![
        subtree_value("/apps/api/child", "below"),
        subtree_value("/apps/api", "exact"),
    ];
    assert_eq!(
        render_subtree_plain(&selected, &collision).unwrap(),
        "/apps/api=exact\n/apps/api/child=below\n"
    );
    assert!(render_subtree_json(&selected, &collision).is_err());
}

#[test]
fn subtree_plain_renders_nothing_for_an_empty_subtree_and_rejects_foreign_paths() {
    let selected = ConfigPath::parse("/apps/api").unwrap();
    assert_eq!(render_subtree_plain(&selected, &[]).unwrap(), "");

    for foreign in [
        subtree_value("/apps/api-v2/leaked", "outside"),
        subtree_value("/other", "outside"),
    ] {
        let error = render_subtree_plain(&selected, &[foreign]).unwrap_err();
        assert_eq!(error.kind, ErrorKind::InvalidRequest);
        assert_eq!(
            error.message(),
            "configuration subtree cannot be represented as JSON"
        );
    }
}
