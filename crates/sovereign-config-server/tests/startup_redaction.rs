use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

const SECRET: &str = "startup-redaction-sentinel-4d9a9fd8";
const INTROSPECTION_SECRET: &str = "introspection-redaction-sentinel-a91c5e72";
const MANAGER_SECRET: &str = "manager-redaction-sentinel-e3b7c1f4";

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
}

fn database_url() -> String {
    format!("postgresql://sovereign_config:{SECRET}@127.0.0.1:1/sovereign_config")
}

fn write_manager_secret(directory: &Path, mode: u32) -> String {
    let path = directory.join("manager-api-token");
    std::fs::write(&path, format!("{MANAGER_SECRET}\n")).expect("secret file must be writable");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
        .expect("secret file mode must be settable");
    path.to_string_lossy().into_owned()
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

fn configured_environment(
    grpc_addr: &str,
    manager_token_file: String,
) -> Vec<(&'static str, String)> {
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
            "SOVEREIGN_CONFIG_MANAGER_API_TOKEN_FILE",
            manager_token_file,
        ),
    ];
    environment.extend(authentication_environment());
    environment
}

#[test]
fn invalid_configuration_does_not_expose_database_credentials() {
    let directory = tempfile::tempdir().expect("temporary directory must be creatable");
    let manager_token_file = write_manager_secret(directory.path(), 0o400);
    let output = run_server(&configured_environment(
        "not-a-socket-address",
        manager_token_file,
    ));

    assert_secret_is_redacted(&output);
}

#[test]
fn database_startup_failure_does_not_expose_database_credentials() {
    let directory = tempfile::tempdir().expect("temporary directory must be creatable");
    let manager_token_file = write_manager_secret(directory.path(), 0o400);
    let output = run_server(&configured_environment(
        "127.0.0.1:50051",
        manager_token_file,
    ));

    assert_secret_is_redacted(&output);
}

#[test]
fn unsafe_manager_secret_file_fails_startup_without_echoing_values() {
    let directory = tempfile::tempdir().expect("temporary directory must be creatable");
    let manager_token_file = write_manager_secret(directory.path(), 0o644);
    let output = run_server(&configured_environment(
        "127.0.0.1:50051",
        manager_token_file,
    ));

    assert_secret_is_redacted(&output);
}

#[test]
fn missing_manager_secret_file_fails_startup_without_echoing_values() {
    let directory = tempfile::tempdir().expect("temporary directory must be creatable");
    let manager_token_file = directory
        .path()
        .join("missing")
        .to_string_lossy()
        .into_owned();
    let output = run_server(&configured_environment(
        "127.0.0.1:50051",
        manager_token_file,
    ));

    assert_secret_is_redacted(&output);
}
