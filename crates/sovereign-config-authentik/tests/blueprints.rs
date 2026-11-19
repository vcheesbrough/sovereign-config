//! The setup files Authentik ships with — `authentik/blueprint.yaml` and
//! `authentik/blueprint-dev.yaml` — held to the terms of the realm contract
//! the server relies on whatever its provider
//! (`sovereign_config_identity::contract`).

use sovereign_config_identity::contract::{
    ACCESS_TOKEN_LIFETIME, ACCESS_URL_NAME_MARKER, REFRESH_TOKEN_LIFETIME, REQUIRED_SCOPE,
};

const BLUEPRINTS: [&str; 2] = [
    include_str!("../../../authentik/blueprint.yaml"),
    include_str!("../../../authentik/blueprint-dev.yaml"),
];

#[test]
fn the_blueprints_mark_a_managed_name_as_the_contract_says() {
    assert_eq!(ACCESS_URL_NAME_MARKER, " (access URL)");
    let signed = format!(
        "claims[\"preferred_username\"] = f\"{{request.user.name}}{ACCESS_URL_NAME_MARKER}\""
    );
    for blueprint in BLUEPRINTS {
        assert!(blueprint.contains(&signed), "{signed}");
    }
}

#[test]
fn the_blueprints_tokens_live_as_long_as_the_contract_says() {
    let access = format!(
        "access_token_validity: minutes={}",
        ACCESS_TOKEN_LIFETIME.as_secs() / 60
    );
    let refresh = format!(
        "refresh_token_validity: hours={}",
        REFRESH_TOKEN_LIFETIME.as_secs() / 3600
    );
    assert_eq!(access, "access_token_validity: minutes=5");
    assert_eq!(refresh, "refresh_token_validity: hours=8");
    for blueprint in BLUEPRINTS {
        assert!(blueprint.contains(&access), "{access}");
        assert!(blueprint.contains(&refresh), "{refresh}");
    }
}

/// The grants mapping is the scope every client requests, and signs the
/// claim the verification rules read.
#[test]
fn the_blueprints_sign_the_grants_under_the_required_scope() {
    let rules = sovereign_config_authentik::verification_rules(
        "https://auth.example.test/application/o/sovereign-config/",
        "sovereign-config",
    );
    let scope = format!("scope_name: {REQUIRED_SCOPE}\n");
    let claim = format!("claims = {{\"{}\": grants}}", rules.grants_claim);
    for blueprint in BLUEPRINTS {
        assert!(blueprint.contains(&scope), "{scope}");
        assert!(blueprint.contains(&claim), "{claim}");
    }
}
