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
    managed_group: &'a str,
}

#[test]
fn blueprints_emit_isolated_granular_grants() {
    assert_environment(&Environment {
        blueprint: "blueprint-dev.yaml",
        mapping: "sovereign-config development grants",
        provider: "sovereign-config-dev",
        group: "sovereign-config-dev-admins",
        source_attribute: "sovereign_config_dev_grants",
        other_attribute: "sovereign_config_prod_grants",
        manager: "sovereign-config-dev-connection-manager",
        manager_token_variable: "${AUTHENTIK_SOVEREIGN_CONFIG_DEV_MANAGER_API_TOKEN}",
        managed_group: "sovereign-config-dev-connections",
    });
    assert_environment(&Environment {
        blueprint: "blueprint.yaml",
        mapping: "sovereign-config production grants",
        provider: "sovereign-config",
        group: "sovereign-config-admins",
        source_attribute: "sovereign_config_prod_grants",
        other_attribute: "sovereign_config_dev_grants",
        manager: "sovereign-config-connection-manager",
        manager_token_variable: "${AUTHENTIK_SOVEREIGN_CONFIG_MANAGER_API_TOKEN}",
        managed_group: "sovereign-config-connections",
    });
}

/// The web UI's provider grants `telemetry:write`, which the client-telemetry
/// ingest requires, and `profile`, which puts the `preferred_username` it
/// also requires on the access token. Losing either stops client telemetry
/// in silence (docs/observability.md).
#[test]
fn the_web_ui_provider_carries_the_telemetry_scope() {
    for (blueprint, provider, telemetry_mapping) in [
        (
            "blueprint-dev.yaml",
            "sovereign-config-dev",
            "sovereign-config development telemetry",
        ),
        (
            "blueprint.yaml",
            "sovereign-config",
            "sovereign-config production telemetry",
        ),
    ] {
        let blueprint = load_blueprint(blueprint);
        let entries = sequence(field(mapping(&blueprint), "entries"));

        let scope = present_entry(
            entries,
            "authentik_providers_oauth2.scopemapping",
            telemetry_mapping,
        );
        let attrs = mapping(field(scope, "attrs"));
        assert_eq!(string(field(attrs, "scope_name")), "telemetry:write");
        // Being granted the scope is the permission; it adds no claim.
        assert_eq!(string(field(attrs, "expression")).trim(), "return {}");

        let provider = present_entry(
            entries,
            "authentik_providers_oauth2.oauth2provider",
            provider,
        );
        let property_mappings = field(mapping(field(provider, "attrs")), "property_mappings");
        assert!(contains_string(property_mappings, telemetry_mapping));
        assert!(contains_string(property_mappings, "profile"));
    }
}

/// Sign-in to each application is gated on two groups, as the live
/// Authentik has it (#588): the environment's own admins group for
/// operators and the connections group for managed accounts, either one
/// sufficing. The blueprint creates both before binding them, so every
/// reference resolves; the bindings carry the live values, so applying a
/// blueprint changes nothing live; and the connections group is the one the
/// server is told to add accounts to.
#[test]
fn the_applications_admit_only_operators_and_managed_accounts() {
    for (blueprint, application, admins_group, managed_group) in [
        (
            "blueprint-dev.yaml",
            "sovereign-config-dev",
            "sovereign-config-dev-admins",
            "sovereign-config-dev-connections",
        ),
        (
            "blueprint.yaml",
            "sovereign-config",
            "sovereign-config-admins",
            "sovereign-config-connections",
        ),
    ] {
        let document = load_blueprint(blueprint);
        let entries = sequence(field(mapping(&document), "entries"));

        let app = mapping(entry_by(
            entries,
            "authentik_core.application",
            "slug",
            application,
        ));
        assert_eq!(string(field(app, "state")), "present");
        assert_eq!(
            string(field(mapping(field(app, "attrs")), "policy_engine_mode")),
            "any",
            "{blueprint}: any one binding admits"
        );
        let app_position = position(entries, app);
        let group_positions = [admins_group, managed_group].map(|group| {
            position(
                entries,
                present_entry(entries, "authentik_core.group", group),
            )
        });

        let bindings = entries
            .iter()
            .map(mapping)
            .filter(|entry| string(field(entry, "model")) == "authentik_policies.policybinding")
            .collect::<Vec<_>>();
        let mut bound = Vec::new();
        for binding in &bindings {
            assert_eq!(string(field(binding, "state")), "present");
            let identifiers = mapping(field(binding, "identifiers"));
            assert_eq!(
                identifiers.len(),
                2,
                "{blueprint}: a binding is identified by its target and group alone"
            );
            assert_eq!(
                found(field(identifiers, "target")),
                ("authentik_core.application", "slug", application),
                "{blueprint}: every binding targets this environment's application"
            );
            let (model, key, group) = found(field(identifiers, "group"));
            assert_eq!((model, key), ("authentik_core.group", "name"));

            let attrs = mapping(field(binding, "attrs"));
            assert_eq!(field(attrs, "enabled"), &Value::Bool(true));
            assert_eq!(field(attrs, "negate"), &Value::Bool(false));
            assert_eq!(field(attrs, "timeout"), &Value::from(30));
            assert_eq!(field(attrs, "failure_result"), &Value::Bool(false));
            for absent in ["policy", "user"] {
                assert!(
                    attrs.get(Value::String(absent.to_owned())).is_none()
                        && identifiers.get(Value::String(absent.to_owned())).is_none(),
                    "{blueprint}: a group binding names no {absent}"
                );
            }
            // `!Find` resolves when its entry is applied, so a binding must
            // come after the application and the group it names.
            let binding_position = position(entries, binding);
            assert!(
                binding_position > app_position
                    && group_positions
                        .iter()
                        .all(|&group| binding_position > group),
                "{blueprint}: every binding comes after the groups it names"
            );

            let order = field(attrs, "order")
                .as_u64()
                .expect("a binding's order is a number");
            bound.push((order, group));
        }
        assert_eq!(
            bound,
            [(0, admins_group), (1, managed_group)],
            "{blueprint}: operators at order 0, managed accounts at order 1, nothing else"
        );
    }
}

/// The position of `entry` among `entries`, by identity.
fn position(entries: &[Value], entry: &Mapping) -> usize {
    entries
        .iter()
        .position(|candidate| std::ptr::eq(mapping(candidate), entry))
        .expect("the entry is one of the entries")
}

/// A `!Find [model, [key, value]]` lookup, as `(model, key, value)`.
fn found(value: &Value) -> (&str, &str, &str) {
    let Value::Tagged(tagged) = value else {
        panic!("a reference to another object must be a !Find")
    };
    assert_eq!(tagged.tag.to_string(), "!Find");
    let lookup = sequence(&tagged.value);
    assert_eq!(lookup.len(), 2, "one lookup field");
    let field = sequence(&lookup[1]);
    (string(&lookup[0]), string(&field[0]), string(&field[1]))
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
    assert!(expression.contains("claims = {\"sovereign_config_grants\": grants}"));
    assert!(expression.contains("return claims"));
    // Every token is named, whichever scopes its client asked for (#440): a
    // managed connection's account by its connection's name, marked as an
    // access URL's so it never reads as a person; anyone else by their
    // username, as `profile` names them.
    assert!(expression.contains(
        "if request.user.attributes.get(\"sovereign_config_managed\"):\n    claims[\"preferred_username\"] = f\"{request.user.name} (access URL)\"\nelse:\n    claims[\"preferred_username\"] = request.user.username"
    ));
    assert!(!expression.contains(environment.group));

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
    // `view_token` is global because Authentik's service-account endpoint
    // creates the app password with a direct ORM call, so object-level
    // permissions never attach and the manager could otherwise not discover or
    // rotate the credential it just created. It exposes token metadata only —
    // `view_token_key` stays ungranted, so no key is ever readable.
    assert_eq!(
        permissions,
        BTreeSet::from([
            "authentik_core.add_token",
            "authentik_core.add_user",
            "authentik_core.view_token",
            "authentik_core.view_group",
        ]),
        "the manager role must hold only the documented global permissions"
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

    // The connections group is a distinct, plain group: no roles and no grant
    // attribute, separate from the manager's own RBAC group above. It gates
    // sign-in through the application's bindings, checked above.
    assert_ne!(environment.managed_group, environment.manager);
    let managed_group = present_entry(entries, "authentik_core.group", environment.managed_group);
    let managed_group_attrs = mapping(field(managed_group, "attrs"));
    assert_eq!(
        field(managed_group_attrs, "is_superuser"),
        &Value::Bool(false)
    );
    assert!(
        managed_group_attrs
            .get(Value::String("roles".to_owned()))
            .is_none(),
        "the connections group must carry no roles"
    );

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

    // These must never be granted: viewing a token key would expose managed app
    // passwords, and the others would let the manager escalate beyond the
    // objects it creates. Comments are stripped so documenting *why* a
    // permission is withheld cannot trip the check.
    let blueprint_text = blueprint_source(environment.blueprint)
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
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
