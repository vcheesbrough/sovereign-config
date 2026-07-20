use std::{collections::BTreeSet, fs, path::Path};

use serde_yaml::{Mapping, Value};

struct Environment<'a> {
    blueprint: &'a str,
    mapping: &'a str,
    provider: &'a str,
    group: &'a str,
    source_attribute: &'a str,
    other_attribute: &'a str,
    manager: &'a str,
    manager_token_variable: &'a str,
}

#[test]
fn blueprints_emit_isolated_granular_grants() {
    assert_environment(&Environment {
        blueprint: "blueprint-dev.yaml",
        mapping: "sovereign-config development grants",
        provider: "sovereign-config-dev",
        group: "sovereign-config-development-config-contributor",
        source_attribute: "sovereign_config_dev_grants",
        other_attribute: "sovereign_config_prod_grants",
        manager: "sovereign-config-dev-connection-manager",
        manager_token_variable: "${AUTHENTIK_SOVEREIGN_CONFIG_DEV_MANAGER_API_TOKEN}",
    });
    assert_environment(&Environment {
        blueprint: "blueprint.yaml",
        mapping: "sovereign-config production grants",
        provider: "sovereign-config",
        group: "sovereign-config-production-config-contributor",
        source_attribute: "sovereign_config_prod_grants",
        other_attribute: "sovereign_config_dev_grants",
        manager: "sovereign-config-connection-manager",
        manager_token_variable: "${AUTHENTIK_SOVEREIGN_CONFIG_MANAGER_API_TOKEN}",
    });
}

fn assert_environment(environment: &Environment<'_>) {
    let blueprint = load_blueprint(environment.blueprint);
    let entries = sequence(field(mapping(&blueprint), "entries"));

    let scope_mapping = present_entry(
        entries,
        "authentik_providers_oauth2.scopemapping",
        environment.mapping,
    );
    let expression = string(field(mapping(field(scope_mapping, "attrs")), "expression"));
    assert!(expression.contains(environment.source_attribute));
    assert!(!expression.contains(environment.other_attribute));
    assert!(expression.contains("return {\"sovereign_config_grants\": grants}"));
    assert!(!expression.contains("config-contributor"));

    let group = present_entry(entries, "authentik_core.group", environment.group);
    let attributes = mapping(field(mapping(field(group, "attrs")), "attributes"));
    let grants = sequence(field(attributes, environment.source_attribute));
    assert_eq!(grants.len(), 1);
    let grant = mapping(&grants[0]);
    assert_eq!(string(field(grant, "prefix")), "/");
    let permissions = sequence(field(grant, "permissions"))
        .iter()
        .map(string)
        .collect::<BTreeSet<_>>();
    assert_eq!(permissions, BTreeSet::from(["manage", "read", "write"]));

    let provider = present_entry(
        entries,
        "authentik_providers_oauth2.oauth2provider",
        environment.provider,
    );
    let property_mappings = field(mapping(field(provider, "attrs")), "property_mappings");
    assert!(contains_string(property_mappings, environment.mapping));

    assert_connection_manager(entries, environment);
}

/// The connection manager may only create users and tokens globally, and
/// administer just the objects it creates. Anything broader would let a
/// compromised manager token read or mutate unrelated Authentik state.
fn assert_connection_manager(entries: &[Value], environment: &Environment<'_>) {
    let role = present_entry(entries, "authentik_rbac.role", environment.manager);
    let permissions = sequence(field(mapping(field(role, "attrs")), "permissions"))
        .iter()
        .map(string)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        permissions,
        BTreeSet::from(["authentik_core.add_token", "authentik_core.add_user"]),
        "the manager role must hold only global create permissions"
    );

    let initial = present_entry(
        entries,
        "authentik_rbac.initialpermissions",
        &format!("{}-objects", environment.manager),
    );
    let initial_attrs = mapping(field(initial, "attrs"));
    assert_eq!(string(field(initial_attrs, "mode")), "role");
    // Initial permissions are resolved to primary keys, so each entry is a
    // `!Find` on the exact codename within `authentik_core`.
    let object_permissions = sequence(field(initial_attrs, "permissions"))
        .iter()
        .map(found_permission_codename)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        object_permissions,
        BTreeSet::from([
            "change_user",
            "delete_user",
            "set_token_key",
            "view_token",
            "view_user",
        ]),
        "the manager must receive only object-level permissions on what it creates"
    );

    let group = present_entry(entries, "authentik_core.group", environment.manager);
    let group_attrs = mapping(field(group, "attrs"));
    assert_eq!(field(group_attrs, "is_superuser"), &Value::Bool(false));
    assert!(contains_string(
        field(group_attrs, "roles"),
        environment.manager
    ));

    let user = mapping(entry_by(
        entries,
        "authentik_core.user",
        "username",
        environment.manager,
    ));
    let user_attrs = mapping(field(user, "attrs"));
    assert_eq!(string(field(user_attrs, "type")), "service_account");
    assert!(contains_string(
        field(user_attrs, "groups"),
        environment.manager
    ));

    let token = mapping(entry_by(
        entries,
        "authentik_core.token",
        "identifier",
        &format!("{}-api", environment.manager),
    ));
    let token_attrs = mapping(field(token, "attrs"));
    assert_eq!(string(field(token_attrs, "intent")), "api");
    // The key must come from an environment-specific secret, never a literal.
    assert_eq!(
        string(field(token_attrs, "key")),
        environment.manager_token_variable
    );

    // These must never appear anywhere in the blueprint: viewing a token key
    // would expose managed app passwords, and the others would let the manager
    // escalate beyond the objects it creates.
    let blueprint_text = blueprint_source(environment.blueprint);
    for forbidden in [
        "view_token_key",
        "is_superuser: true",
        "authentik_rbac.add_role",
        "authentik_rbac.change_role",
        "authentik_core.delete_token",
    ] {
        assert!(
            !blueprint_text.contains(forbidden),
            "blueprint must never reference {forbidden}"
        );
    }
}

/// Extracts the codename from a `!Find [auth.permission, [codename, X],
/// [content_type__app_label, authentik_core]]` lookup, asserting the shape.
fn found_permission_codename(value: &Value) -> &str {
    let Value::Tagged(tagged) = value else {
        panic!("initial permissions must be resolved with !Find")
    };
    assert_eq!(tagged.tag.to_string(), "!Find");
    let lookup = sequence(&tagged.value);
    assert_eq!(string(&lookup[0]), "auth.permission");
    let codename = sequence(&lookup[1]);
    assert_eq!(string(&codename[0]), "codename");
    let scope = sequence(&lookup[2]);
    assert_eq!(string(&scope[0]), "content_type__app_label");
    assert_eq!(
        string(&scope[1]),
        "authentik_core",
        "permissions must be scoped to authentik_core so no other app's codename can match"
    );
    string(&codename[1])
}

fn entry_by<'a>(entries: &'a [Value], model: &str, key: &str, value: &str) -> &'a Value {
    entries
        .iter()
        .find(|candidate| {
            let candidate = mapping(candidate);
            string(field(candidate, "model")) == model
                && mapping(field(candidate, "identifiers"))
                    .get(Value::String(key.to_owned()))
                    .and_then(Value::as_str)
                    == Some(value)
        })
        .expect("blueprint entry should exist")
}

fn blueprint_source(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../authentik")
        .join(name);
    fs::read_to_string(path).expect("blueprint should be readable")
}

fn load_blueprint(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../authentik")
        .join(name);
    let contents = fs::read_to_string(path).expect("blueprint should be readable");
    serde_yaml::from_str(&contents).expect("blueprint should be valid YAML")
}

fn present_entry<'a>(entries: &'a [Value], model: &str, name: &str) -> &'a Mapping {
    let entry = mapping(entry(entries, model, name));
    assert_eq!(string(field(entry, "state")), "present");
    entry
}

fn entry<'a>(entries: &'a [Value], model: &str, name: &str) -> &'a Value {
    entries
        .iter()
        .find(|candidate| {
            let candidate = mapping(candidate);
            string(field(candidate, "model")) == model
                && string(field(mapping(field(candidate, "identifiers")), "name")) == name
        })
        .expect("blueprint entry should exist")
}

fn contains_string(value: &Value, expected: &str) -> bool {
    match value {
        Value::String(value) => value == expected,
        Value::Sequence(values) => values.iter().any(|value| contains_string(value, expected)),
        Value::Mapping(values) => values
            .iter()
            .any(|(key, value)| contains_string(key, expected) || contains_string(value, expected)),
        Value::Tagged(value) => contains_string(&value.value, expected),
        _ => false,
    }
}

fn field<'a>(mapping: &'a Mapping, name: &str) -> &'a Value {
    mapping
        .get(Value::String(name.to_owned()))
        .expect("YAML field should exist")
}

fn mapping(value: &Value) -> &Mapping {
    value.as_mapping().expect("YAML value should be a mapping")
}

fn sequence(value: &Value) -> &[Value] {
    value
        .as_sequence()
        .expect("YAML value should be a sequence")
}

fn string(value: &Value) -> &str {
    value.as_str().expect("YAML value should be a string")
}
