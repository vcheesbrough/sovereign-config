use std::process::{Command, Output};

const SECRET: &str = "startup-redaction-sentinel-4d9a9fd8";

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
}

fn database_url() -> String {
    format!("postgresql://sovereign_config:{SECRET}@127.0.0.1:1/sovereign_config")
}

#[test]
fn invalid_configuration_does_not_expose_database_credentials() {
    let output = run_server(&[
        ("SOVEREIGN_CONFIG_DATABASE_URL", database_url()),
        (
            "SOVEREIGN_CONFIG_GRPC_ADDR",
            "not-a-socket-address".to_owned(),
        ),
        ("SOVEREIGN_CONFIG_METRICS_ADDR", "127.0.0.1:9090".to_owned()),
    ]);

    assert_secret_is_redacted(&output);
}

#[test]
fn database_startup_failure_does_not_expose_database_credentials() {
    let output = run_server(&[
        ("SOVEREIGN_CONFIG_DATABASE_URL", database_url()),
        ("SOVEREIGN_CONFIG_GRPC_ADDR", "127.0.0.1:50051".to_owned()),
        ("SOVEREIGN_CONFIG_METRICS_ADDR", "127.0.0.1:9090".to_owned()),
    ]);

    assert_secret_is_redacted(&output);
}
