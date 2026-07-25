use std::process::{Command, Output};

const SECRET: &str = "startup-redaction-sentinel-4d9a9fd8";
const INTROSPECTION_SECRET: &str = "introspection-redaction-sentinel-a91c5e72";
const MANAGER_SECRET: &str = "manager-redaction-sentinel-e3b7c1f4";
// A real 32-byte key, base64-encoded, so the server gets past key validation
// on the paths that are meant to fail somewhere else.
const VALUE_ENCRYPTION_KEY: &str = "dmFsdWUtZW5jcnlwdGlvbi1zZW50aW5lbC1rZXktMDE=";

fn run_server(environment: &[(&str, String)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sovereign-config-server"));
    command.env_clear();
    for (name, value) in environment {
        command.env(name, value);
    }
    command.output().expect("server process must start")
}

fn assert_secret_is_redacted(output: &Output) {
    assert!(!output.status.success(), "invalid startup must fail");

    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output.contains(SECRET),
        "startup output exposed the database credential: {output}"
    );
    assert!(
        !output.contains(INTROSPECTION_SECRET),
        "startup output exposed the introspection credential: {output}"
    );
    assert!(
        !output.contains(MANAGER_SECRET),
        "startup output exposed the manager credential: {output}"
    );
    assert!(
        !output.contains(VALUE_ENCRYPTION_KEY),
        "startup output exposed the value encryption key: {output}"
    );
}

fn database_url() -> String {
    format!("postgresql://sovereign_config:{SECRET}@127.0.0.1:1/sovereign_config")
}

fn authentication_environment() -> [(&'static str, String); 5] {
    [
        (
            "SOVEREIGN_CONFIG_OIDC_INTROSPECTION_URL",
            "https://auth.example.test/application/o/introspect/".to_owned(),
        ),
        (
            "SOVEREIGN_CONFIG_OIDC_ISSUER",
            "https://auth.example.test/application/o/sovereign-config/".to_owned(),
        ),
        (
            "SOVEREIGN_CONFIG_OIDC_AUDIENCE",
            "sovereign-config".to_owned(),
        ),
        (
            "SOVEREIGN_CONFIG_OIDC_INTROSPECTION_CLIENT_ID",
            "sovereign-config-introspection".to_owned(),
        ),
        (
            "SOVEREIGN_CONFIG_OIDC_INTROSPECTION_CLIENT_SECRET",
            INTROSPECTION_SECRET.to_owned(),
        ),
    ]
}

fn configured_environment(grpc_addr: &str) -> Vec<(&'static str, String)> {
    let mut environment = vec![
        ("SOVEREIGN_CONFIG_DATABASE_URL", database_url()),
        ("SOVEREIGN_CONFIG_GRPC_ADDR", grpc_addr.to_owned()),
        ("SOVEREIGN_CONFIG_METRICS_ADDR", "127.0.0.1:9090".to_owned()),
        (
            "SOVEREIGN_CONFIG_PUBLIC_ORIGIN",
            "https://config.example.test".to_owned(),
        ),
        (
            "SOVEREIGN_CONFIG_MANAGER_GRANTS_ATTRIBUTE",
            "sovereign_config_test_grants".to_owned(),
        ),
        (
            "SOVEREIGN_CONFIG_MANAGER_GROUP",
            "sovereign-config-test-connections".to_owned(),
        ),
        (
            "SOVEREIGN_CONFIG_MANAGER_API_TOKEN",
            MANAGER_SECRET.to_owned(),
        ),
        (
            "SOVEREIGN_CONFIG_VALUE_ENCRYPTION_KEY",
            VALUE_ENCRYPTION_KEY.to_owned(),
        ),
    ];
    environment.extend(authentication_environment());
    environment
}

#[test]
fn invalid_configuration_does_not_expose_database_credentials() {
    let output = run_server(&configured_environment("not-a-socket-address"));

    assert_secret_is_redacted(&output);
}

#[test]
fn database_startup_failure_does_not_expose_database_credentials() {
    let output = run_server(&configured_environment("127.0.0.1:50051"));

    assert_secret_is_redacted(&output);
}

#[test]
fn missing_manager_credential_fails_startup_without_echoing_values() {
    let environment = configured_environment("127.0.0.1:50051")
        .into_iter()
        .filter(|(name, _)| *name != "SOVEREIGN_CONFIG_MANAGER_API_TOKEN")
        .collect::<Vec<_>>();
    let output = run_server(&environment);

    assert_secret_is_redacted(&output);
}

#[test]
fn invalid_public_origin_fails_startup_without_echoing_values() {
    let mut environment = configured_environment("127.0.0.1:50051");
    for entry in &mut environment {
        if entry.0 == "SOVEREIGN_CONFIG_PUBLIC_ORIGIN" {
            entry.1 = "https://config.example.test/nested/path".to_owned();
        }
    }
    let output = run_server(&environment);

    assert_secret_is_redacted(&output);
}

#[test]
fn missing_value_encryption_key_fails_startup_without_echoing_values() {
    let environment = configured_environment("127.0.0.1:50051")
        .into_iter()
        .filter(|(name, _)| *name != "SOVEREIGN_CONFIG_VALUE_ENCRYPTION_KEY")
        .collect::<Vec<_>>();
    let output = run_server(&environment);

    assert_secret_is_redacted(&output);
}

#[test]
fn malformed_value_encryption_key_fails_startup_without_echoing_values() {
    // A key of the wrong length must be rejected before it is ever used, and
    // the rejection must describe the shape rather than quote the key.
    let short_key = "c2hvcnQta2V5";
    let mut environment = configured_environment("127.0.0.1:50051");
    for entry in &mut environment {
        if entry.0 == "SOVEREIGN_CONFIG_VALUE_ENCRYPTION_KEY" {
            entry.1 = short_key.to_owned();
        }
    }
    let output = run_server(&environment);

    assert_secret_is_redacted(&output);
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !rendered.contains(short_key),
        "startup output echoed the supplied key: {rendered}"
    );
}
