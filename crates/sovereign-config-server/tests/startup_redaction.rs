use std::process::{Command, Output};

const SECRET: &str = "startup-redaction-sentinel-4d9a9fd8";
const INTROSPECTION_SECRET: &str = "introspection-redaction-sentinel-a91c5e72";

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
