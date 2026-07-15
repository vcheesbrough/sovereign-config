use std::{collections::BTreeSet, fs, path::Path};

use serde_yaml::{Mapping, Value};

struct Environment<'a> {
    blueprint: &'a str,
    mapping: &'a str,
    provider: &'a str,
    group: &'a str,
    source_attribute: &'a str,
    other_attribute: &'a str,
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
    });
    assert_environment(&Environment {
        blueprint: "blueprint.yaml",
        mapping: "sovereign-config production grants",
        provider: "sovereign-config",
        group: "sovereign-config-production-config-contributor",
        source_attribute: "sovereign_config_prod_grants",
        other_attribute: "sovereign_config_dev_grants",
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
