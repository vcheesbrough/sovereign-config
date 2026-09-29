//! The server process under each telemetry state (`observability` skill §7):
//! run as the real binary, because "telemetry never harms the product" is a
//! claim about the process, not about the module in isolation.
//!
//! The fast tests stop the server at its first configuration check, which
//! runs after telemetry has started: enough to see the startup line, the
//! validation failure, and a bounded exit. The two `#[ignore]`d tests need
//! `SOVEREIGN_CONFIG_TEST_DATABASE_URL` and prove the server actually serves
//! and stops with no variables set and with the collector unreachable.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

const VALUE_ENCRYPTION_KEY: &str = "dmFsdWUtZW5jcnlwdGlvbi1zZW50aW5lbC1rZXktMDE=";

/// How long a stopping server may take: the telemetry flush bound (5s) plus
/// slack for a loaded CI host.
const EXIT_BOUND: Duration = Duration::from_secs(12);

/// The variables a dev deployment carries.
fn deployed_telemetry(endpoint: &str) -> Vec<(&'static str, String)> {
    vec![
        ("OTEL_SERVICE_NAME", "sovereign-config".to_owned()),
        (
            "OTEL_RESOURCE_ATTRIBUTES",
            "deployment.environment.name=test,telemetry_source=otlp".to_owned(),
        ),
        ("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint.to_owned()),
        ("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf".to_owned()),
        ("OTEL_LOGS_EXPORTER", "otlp".to_owned()),
        ("OTEL_TRACES_EXPORTER", "otlp".to_owned()),
        ("OTEL_METRICS_EXPORTER", "otlp".to_owned()),
    ]
}

/// A complete server configuration, apart from what the caller varies.
fn server_environment(
    database_url: &str,
    grpc_addr: &str,
    metrics_addr: &str,
) -> Vec<(&'static str, String)> {
    [
        ("SOVEREIGN_CONFIG_DATABASE_URL", database_url),
        ("SOVEREIGN_CONFIG_GRPC_ADDR", grpc_addr),
        ("SOVEREIGN_CONFIG_METRICS_ADDR", metrics_addr),
        (
            "SOVEREIGN_CONFIG_PUBLIC_ORIGIN",
            "https://config.example.test",
        ),
        (
            "SOVEREIGN_CONFIG_MANAGER_GRANTS_ATTRIBUTE",
            "sovereign_config_test_grants",
        ),
        (
            "SOVEREIGN_CONFIG_MANAGER_GROUP",
            "sovereign-config-test-connections",
        ),
        ("SOVEREIGN_CONFIG_MANAGER_API_TOKEN", "manager-token"),
        (
            "SOVEREIGN_CONFIG_VALUE_ENCRYPTION_KEY",
            VALUE_ENCRYPTION_KEY,
        ),
        (
            "SOVEREIGN_CONFIG_OIDC_INTROSPECTION_URL",
            "https://auth.example.test/application/o/introspect/",
        ),
        (
            "SOVEREIGN_CONFIG_OIDC_ISSUER",
            "https://auth.example.test/application/o/sovereign-config/",
        ),
        ("SOVEREIGN_CONFIG_OIDC_AUDIENCE", "sovereign-config"),
        (
            "SOVEREIGN_CONFIG_OIDC_INTROSPECTION_CLIENT_ID",
            "sovereign-config-introspection",
        ),
        (
            "SOVEREIGN_CONFIG_OIDC_INTROSPECTION_CLIENT_SECRET",
            "introspection-secret",
        ),
    ]
    .into_iter()
    .map(|(name, value)| (name, value.to_owned()))
    .collect()
}

/// A configuration that telemetry accepts and the server then rejects at once
/// (an unparseable gRPC address), so the run ends right after startup.
fn stops_after_telemetry(extra: Vec<(&'static str, String)>) -> Vec<(&'static str, String)> {
    let mut environment = server_environment(
        "postgresql://sovereign_config:password@127.0.0.1:1/sovereign_config",
        "not-a-socket-address",
        "127.0.0.1:0",
    );
    environment.extend(extra);
    environment
}

fn run(environment: &[(&'static str, String)]) -> (Output, Duration) {
    let started = Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_sovereign-config-server"))
        .env_clear()
        .envs(environment.iter().map(|(name, value)| (name, value)))
        .output()
        .expect("server process must start");
    (output, started.elapsed())
}

fn text(output: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn count(haystack: &str, needle: &str) -> usize {
    haystack
        .lines()
        .filter(|line| line.contains(needle))
        .count()
}

fn unused_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn with_no_otel_variable_the_server_says_telemetry_is_off_once() {
    let (output, _) = run(&stops_after_telemetry(Vec::new()));
    let (stdout, stderr) = text(&output);

    assert_eq!(count(&stdout, "telemetry off"), 1, "{stdout}");
    assert_eq!(count(&stdout, "no OTEL_* variable is set"), 1, "{stdout}");
    // It went on to its own configuration, which is what stopped it.
    assert!(stderr.contains("SOVEREIGN_CONFIG_GRPC_ADDR"), "{stderr}");
}

#[test]
fn sdk_disabled_turns_a_configured_deployment_off() {
    let mut telemetry = deployed_telemetry("http://collector.example.test:4318");
    telemetry.push(("OTEL_SDK_DISABLED", "true".to_owned()));
    let (output, _) = run(&stops_after_telemetry(telemetry));
    let (stdout, stderr) = text(&output);

    assert_eq!(count(&stdout, "telemetry off"), 1, "{stdout}");
    assert_eq!(count(&stdout, "OTEL_SDK_DISABLED is true"), 1, "{stdout}");
    assert!(stderr.contains("SOVEREIGN_CONFIG_GRPC_ADDR"), "{stderr}");
}

/// Each half-configured or malformed set stops the server before anything
/// else happens, naming the variable and never its value.
#[test]
fn an_invalid_otel_set_fails_startup_naming_the_variable_but_not_the_value() {
    let sentinel = "otel-sentinel-5b1e0c";
    let cases: Vec<(&str, Vec<(&'static str, String)>)> = vec![
        (
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            vec![
                ("OTEL_SERVICE_NAME", sentinel.to_owned()),
                (
                    "OTEL_RESOURCE_ATTRIBUTES",
                    "deployment.environment.name=test".to_owned(),
                ),
            ],
        ),
        ("OTEL_EXPORTER_OTLP_ENDPOINT", {
            let mut set = deployed_telemetry("http://collector:4318");
            set.retain(|(name, _)| *name != "OTEL_EXPORTER_OTLP_ENDPOINT");
            set.push((
                "OTEL_EXPORTER_OTLP_HEADERS",
                format!("authorization=Bearer {sentinel}"),
            ));
            set
        }),
        ("OTEL_EXPORTER_OTLP_PROTOCOL", {
            let mut set = deployed_telemetry("http://collector:4318");
            set.push(("OTEL_EXPORTER_OTLP_PROTOCOL", sentinel.to_owned()));
            set
        }),
        ("OTEL_LOGS_EXPORTER", {
            let mut set = deployed_telemetry("http://collector:4318");
            set.push(("OTEL_LOGS_EXPORTER", sentinel.to_owned()));
            set
        }),
        ("OTEL_PROPAGATORS", {
            let mut set = deployed_telemetry("http://collector:4318");
            set.push(("OTEL_PROPAGATORS", sentinel.to_owned()));
            set
        }),
        ("OTEL_EXPORTER_OTLP_ENDPOINT", {
            let mut set = deployed_telemetry(&format!("{sentinel}:4318"));
            set.push((
                "OTEL_EXPORTER_OTLP_HEADERS",
                format!("authorization=Bearer {sentinel}"),
            ));
            set
        }),
    ];

    for (variable, telemetry) in cases {
        // Later entries win in `Command::envs`, so a pushed override replaces
        // the deployed value.
        let (output, _) = run(&stops_after_telemetry(telemetry));
        let (stdout, stderr) = text(&output);

        assert!(!output.status.success(), "{variable}: startup must fail");
        assert!(stderr.contains(variable), "{variable}: {stderr}");
        assert!(
            !stderr.contains("SOVEREIGN_CONFIG_GRPC_ADDR"),
            "{variable}: telemetry must fail before the server's own config: {stderr}"
        );
        assert!(
            !stdout.contains(sentinel) && !stderr.contains(sentinel),
            "{variable}: a value was echoed:\n{stdout}\n{stderr}"
        );
    }
}

/// Whether stdout carries the SDK's report of a failed export — the only
/// signal of dropped records, since the SDK exports no counter (AGENTS.md
/// deviations register).
fn reports_export_failure(stdout: &str) -> bool {
    stdout.lines().any(|line| {
        line.contains("\"target\":\"opentelemetry")
            && (line.contains("\"level\":\"ERROR\"") || line.contains("\"level\":\"WARN\""))
    }) || stdout.contains("telemetry did not flush cleanly")
}

#[test]
fn an_unreachable_collector_neither_fails_startup_nor_delays_exit() {
    let endpoint = format!("http://127.0.0.1:{}", unused_port());
    let (output, elapsed) = run(&stops_after_telemetry(deployed_telemetry(&endpoint)));
    let (stdout, stderr) = text(&output);

    assert_eq!(count(&stdout, "telemetry on"), 1, "{stdout}");
    assert!(stderr.contains("SOVEREIGN_CONFIG_GRPC_ADDR"), "{stderr}");
    assert!(elapsed < EXIT_BOUND, "exit took {elapsed:?}");
    assert!(!stdout.contains(&endpoint), "{stdout}");
    // The records flushed at exit went to a dead port, and that must show.
    assert!(
        reports_export_failure(&stdout),
        "an export failure must be visible on stdout: {stdout}"
    );
}

/// Sends SIGTERM, as `docker stop` does.
fn terminate(child: &std::process::Child) {
    rustix::process::kill_process(
        rustix::process::Pid::from_child(child),
        rustix::process::Signal::TERM,
    )
    .expect("SIGTERM must be deliverable");
}

/// The status line of `GET path` on the internal listener, or `None`.
fn internal_get(port: u16, path: &str) -> Option<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .ok()?;
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    response.lines().next().map(str::to_owned)
}

fn ready(metrics_port: u16) -> bool {
    internal_get(metrics_port, "/readyz").is_some_and(|status| status.starts_with("HTTP/1.1 200"))
}

/// A schema of the test database's own, so this server's migrations and its
/// startup secret-encryption pass cannot meet another test's rows. `public`
/// stays on the path after it, where an extension another test already
/// installed (`pg_trgm`) lives; if none has, the migration installs it into
/// this schema and the next setup's `CASCADE` removes it again.
async fn isolated_database_url() -> String {
    const SCHEMA: &str = "telemetry_startup";

    use sqlx::{Connection, PgConnection};

    let database_url = std::env::var("SOVEREIGN_CONFIG_TEST_DATABASE_URL")
        .expect("SOVEREIGN_CONFIG_TEST_DATABASE_URL must be configured");
    let mut connection = PgConnection::connect(&database_url)
        .await
        .expect("the test database must accept connections");
    for statement in [
        format!("DROP SCHEMA IF EXISTS {SCHEMA} CASCADE"),
        format!("CREATE SCHEMA {SCHEMA}"),
    ] {
        sqlx::query(&statement)
            .execute(&mut connection)
            .await
            .expect("schema setup must succeed");
    }
    let separator = if database_url.contains('?') { '&' } else { '?' };
    format!("{database_url}{separator}options=-c%20search_path%3D{SCHEMA}%2Cpublic")
}

/// Starts the real server, waits until it serves, stops it with SIGTERM and
/// returns its stdout and how long it took to exit.
fn serve_then_stop(
    database_url: &str,
    telemetry: Vec<(&'static str, String)>,
) -> (String, Duration) {
    let metrics_port = unused_port();
    let mut environment = server_environment(
        database_url,
        &format!("127.0.0.1:{}", unused_port()),
        &format!("127.0.0.1:{metrics_port}"),
    );
    environment.extend(telemetry);
    let mut child = Command::new(env!("CARGO_BIN_EXE_sovereign-config-server"))
        .env_clear()
        .envs(environment.iter().map(|(name, value)| (name, value)))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("server process must start");

    let deadline = Instant::now() + Duration::from_secs(60);
    while !ready(metrics_port) {
        if let Some(status) = child.try_wait().unwrap() {
            let output = child.wait_with_output().unwrap();
            panic!(
                "server exited with {status} before serving: {:?}",
                text(&output)
            );
        }
        assert!(Instant::now() < deadline, "server never became ready");
        std::thread::sleep(Duration::from_millis(200));
    }
    // Serving with the collector down: a few more requests do not fail.
    for _ in 0..5 {
        assert!(ready(metrics_port));
    }
    // Metrics are pushed over OTLP; there is nothing to scrape.
    assert_eq!(
        internal_get(metrics_port, "/metrics").as_deref(),
        Some("HTTP/1.1 404 Not Found")
    );

    let stopping = Instant::now();
    terminate(&child);
    let output = child.wait_with_output().unwrap();
    let elapsed = stopping.elapsed();
    assert!(
        output.status.success(),
        "clean exit expected: {:?}",
        text(&output)
    );
    (text(&output).0, elapsed)
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn with_no_otel_variable_the_server_serves_and_stops_as_before() {
    let database_url = isolated_database_url().await;
    let (stdout, elapsed) =
        tokio::task::spawn_blocking(move || serve_then_stop(&database_url, Vec::new()))
            .await
            .unwrap();

    assert_eq!(count(&stdout, "telemetry off"), 1, "{stdout}");
    assert!(stdout.contains("sovereign-config started"), "{stdout}");
    assert!(stdout.contains("shutdown signal received"), "{stdout}");
    assert!(elapsed < EXIT_BOUND, "exit took {elapsed:?}");
}

#[tokio::test]
#[ignore = "requires SOVEREIGN_CONFIG_TEST_DATABASE_URL"]
async fn with_the_collector_unreachable_the_server_serves_and_stops_within_the_bound() {
    let database_url = isolated_database_url().await;
    let endpoint = format!("http://127.0.0.1:{}", unused_port());
    let telemetry = deployed_telemetry(&endpoint);
    let (stdout, elapsed) =
        tokio::task::spawn_blocking(move || serve_then_stop(&database_url, telemetry))
            .await
            .unwrap();

    assert_eq!(count(&stdout, "telemetry on"), 1, "{stdout}");
    assert!(stdout.contains("sovereign-config started"), "{stdout}");
    assert!(elapsed < EXIT_BOUND, "exit took {elapsed:?}");
    assert!(!stdout.contains(&endpoint), "{stdout}");
    // The records flushed at exit went to a dead port, and that must show.
    assert!(
        reports_export_failure(&stdout),
        "an export failure must be visible on stdout: {stdout}"
    );
}
