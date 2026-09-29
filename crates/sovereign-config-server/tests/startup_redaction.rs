use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    process::{Command, Output},
    sync::{Arc, Mutex},
};

const SECRET: &str = "startup-redaction-sentinel-4d9a9fd8";
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

fn authentication_environment() -> [(&'static str, String); 2] {
    [
        (
            "SOVEREIGN_CONFIG_OIDC_ISSUER",
            "https://auth.example.test/application/o/sovereign-config/".to_owned(),
        ),
        (
            "SOVEREIGN_CONFIG_OIDC_AUDIENCE",
            "sovereign-config".to_owned(),
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

/// Telemetry configuration can carry a credential (`OTEL_EXPORTER_OTLP_HEADERS`)
/// and names internal addresses, so no `OTEL_*` value may reach a log line —
/// on the path where telemetry starts and exports, and the server then fails
/// on its database and logs about it.
#[test]
fn telemetry_configuration_values_never_reach_the_output() {
    const HEADER_SECRET: &str = "otlp-header-sentinel-7c2d9e10";
    const ENDPOINT: &str = "http://otlp-endpoint-sentinel.invalid:4318";
    const ENVIRONMENT: &str = "environment-sentinel-31f0";

    let mut environment = configured_environment("127.0.0.1:50051");
    environment.extend([
        ("OTEL_SERVICE_NAME", "sovereign-config".to_owned()),
        (
            "OTEL_RESOURCE_ATTRIBUTES",
            format!("deployment.environment.name={ENVIRONMENT},telemetry_source=otlp"),
        ),
        ("OTEL_EXPORTER_OTLP_ENDPOINT", ENDPOINT.to_owned()),
        (
            "OTEL_EXPORTER_OTLP_HEADERS",
            format!("authorization=Bearer {HEADER_SECRET}"),
        ),
        ("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf".to_owned()),
        ("OTEL_LOGS_EXPORTER", "otlp".to_owned()),
        ("OTEL_METRICS_EXPORTER", "none".to_owned()),
        ("OTEL_TRACES_EXPORTER", "none".to_owned()),
        // Verbose, so a value the product or the exporter logs at any level
        // an operator would plausibly run at shows here. (At `trace` the HTTP
        // client library names the host it dials; that level is a deliberate
        // debugging choice, not a deployment setting.)
        ("RUST_LOG", "debug".to_owned()),
    ]);
    let output = run_server(&environment);

    assert_secret_is_redacted(&output);
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(rendered.contains("telemetry on"), "{rendered}");
    for value in [HEADER_SECRET, "otlp-endpoint-sentinel", ENVIRONMENT] {
        assert!(
            !rendered.contains(value),
            "startup output exposed an OTEL_* value ({value}): {rendered}"
        );
    }
}

/// Every request an OTLP/HTTP collector stand-in received, as `(path, body)`.
type Received = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

/// Answers one keep-alive connection's requests with `200`, recording each.
fn serve_otlp_connection(stream: TcpStream, received: &Received) {
    let mut reader = BufReader::new(stream.try_clone().expect("stream clones"));
    let mut writer = stream;
    loop {
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
            return;
        }
        let path = request_line
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .to_owned();
        let mut length = 0usize;
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header).unwrap_or(0) == 0 {
                return;
            }
            let header = header.trim_end();
            if header.is_empty() {
                break;
            }
            if let Some((name, value)) = header.split_once(':')
                && name.eq_ignore_ascii_case("content-length")
            {
                length = value.trim().parse().unwrap_or(0);
            }
        }
        let mut body = vec![0; length];
        if reader.read_exact(&mut body).is_err() {
            return;
        }
        received.lock().unwrap().push((path, body));
        if writer
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
            .is_err()
        {
            return;
        }
    }
}

/// An OTLP/HTTP collector on an ephemeral port, recording what it receives.
fn fake_collector() -> (String, Received) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a port binds");
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let received: Received = Arc::default();
    let recorder = Arc::clone(&received);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let recorder = Arc::clone(&recorder);
            std::thread::spawn(move || serve_otlp_connection(stream, &recorder));
        }
    });
    (endpoint, received)
}

/// Exported telemetry is published, not private: none of the startup
/// secrets may reach a span, a log record or a metric that leaves the
/// process. The server runs with every secret configured and every signal exporting to a
/// collector stand-in, spans its startup, fails on the unreachable database
/// (whose URL carries one of the secrets), and flushes on the way out; the
/// test then searches what the collector received.
#[test]
fn no_startup_secret_reaches_an_exported_span_or_log_record() {
    let (endpoint, received) = fake_collector();
    let mut environment = configured_environment("127.0.0.1:50051");
    environment.extend([
        ("OTEL_SERVICE_NAME", "sovereign-config".to_owned()),
        (
            "OTEL_RESOURCE_ATTRIBUTES",
            "deployment.environment.name=test,telemetry_source=otlp".to_owned(),
        ),
        ("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint),
        ("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf".to_owned()),
        ("OTEL_LOGS_EXPORTER", "otlp".to_owned()),
        ("OTEL_TRACES_EXPORTER", "otlp".to_owned()),
        ("OTEL_METRICS_EXPORTER", "otlp".to_owned()),
        ("RUST_LOG", "debug".to_owned()),
    ]);
    let output = run_server(&environment);
    assert_secret_is_redacted(&output);

    let received = received.lock().unwrap().clone();
    let bodies = |path: &str| -> Vec<&[u8]> {
        received
            .iter()
            .filter(|(received_path, _)| received_path == path)
            .map(|(_, body)| body.as_slice())
            .collect()
    };
    let contains = |haystack: &[u8], needle: &str| {
        haystack
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
    };
    let traces = bodies("/v1/traces");
    let logs = bodies("/v1/logs");
    assert!(
        traces.iter().any(|body| contains(body, "migrate")),
        "the startup span must have been exported: {:?}",
        received.iter().map(|(path, _)| path).collect::<Vec<_>>()
    );
    assert!(!logs.is_empty(), "log records must have been exported");
    // Whatever metrics left before the failed start are searched too.
    let metrics = bodies("/v1/metrics");
    for body in traces.iter().chain(&logs).chain(&metrics) {
        for secret in [SECRET, MANAGER_SECRET, VALUE_ENCRYPTION_KEY] {
            assert!(
                !contains(body, secret),
                "an exported span or log record carries a startup secret"
            );
        }
    }
}
