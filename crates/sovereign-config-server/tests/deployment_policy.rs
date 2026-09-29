#[test]
fn compose_requires_an_operator_provisioned_volume() {
    let compose = include_str!("../../../compose.yaml");
    let readme = include_str!("../../../README.md");

    // Compose must never conjure a volume of its own: an anonymous one would
    // silently strand the data an operator believes they provisioned.
    assert!(compose.contains("external: true"));
    assert!(compose.contains(
        "name: ${POSTGRES_DATA_VOLUME:?Set POSTGRES_DATA_VOLUME to a pre-created external volume holding the PostgreSQL data directory}"
    ));
    assert!(!compose.contains("POSTGRES_DATA_VOLUME:-"));
    assert!(readme.contains("pre-create the external volume"));

    // Encrypting secret values did not remove the need for encrypted storage:
    // plain values, the path tree, and connection metadata are still verbatim
    // in that volume, so the requirement has to survive this change.
    assert!(readme.contains("on encrypted storage"));
    assert!(readme.contains("All backup and staging storage must be encrypted too."));
}

#[test]
fn compose_delivers_the_value_encryption_key_like_every_other_secret() {
    let compose = include_str!("../../../compose.yaml");

    // Same dual-mode shape as the database URL and the manager token: the
    // direct variable wins, the file is the fallback, and the file-backed
    // secret resolves to /dev/null so Compose still parses when the key is
    // injected through the environment instead.
    assert!(compose.contains(
        "SOVEREIGN_CONFIG_VALUE_ENCRYPTION_KEY: ${SOVEREIGN_CONFIG_VALUE_ENCRYPTION_KEY:-}"
    ));
    assert!(compose.contains(
        "SOVEREIGN_CONFIG_VALUE_ENCRYPTION_KEY_FILE: ${SOVEREIGN_CONFIG_VALUE_ENCRYPTION_KEY_FILE-/run/secrets/value_encryption_key}"
    ));
    assert!(
        compose
            .contains("  value_encryption_key:\n    file: ${VALUE_ENCRYPTION_KEY_FILE:-/dev/null}")
    );
    assert!(compose.contains("      - value_encryption_key"));
}

/// Both containers must be discoverable as one service in two environments.
///
/// The database's labels are the whole reason this test exists: an unlabelled
/// container still ships logs, so nothing fails — Loki just files them under
/// the container name, and `{deployment_environment="prod"}` quietly misses the
/// database. The failure mode is an absence, which only a test asserting the
/// presence catches. The labels serve the stdout path only: metrics are
/// pushed over OTLP with the process's own identity.
#[test]
fn every_container_is_labelled_for_log_discovery() {
    let compose = include_str!("../../../compose.yaml");

    for (service, expected) in [
        ("postgres", "sovereign-config-postgres"),
        ("sovereign-config", "sovereign-config"),
        ("otlp-ingest", "sovereign-config-otlp-ingest"),
    ] {
        assert!(
            compose.contains(&format!("\"observability.service.name={expected}\"")),
            "{service} must name itself for Loki and Prometheus"
        );
    }
    assert_eq!(
        compose
            .matches("\"observability.deployment.environment=${SOVEREIGN_CONFIG_ENV:-dev}\"")
            .count(),
        3,
        "every container must carry the environment, from the same variable"
    );
}

/// Metrics leave over OTLP (#421): nothing may ask the platform to scrape the
/// server any more, or Alloy would keep a target whose `/metrics` answers 404.
///
/// The client-telemetry ingest is the one exception, recorded in AGENTS.md's
/// deviations register: the published image serves its own metrics on
/// `:8888` for scraping, and pushes none.
#[test]
fn compose_asks_for_no_metrics_scrape() {
    for service in ["postgres", "sovereign-config"] {
        let labels = serde_yaml::to_string(&compose_service(service)["labels"]).unwrap();
        assert!(
            !labels.contains("observability.metrics"),
            "{service}: no scrape labels"
        );
        assert!(!labels.contains("/metrics"), "{service}: no scrape path");
    }
    let ingest = serde_yaml::to_string(&compose_service("otlp-ingest")["labels"]).unwrap();
    assert!(ingest.contains("observability.metrics.port=8888"));
}

/// Build identity belongs on `sovereign_config_build_info`, not on every series.
///
/// Alloy stopped reading these labels, so leaving them here would be dead
/// configuration that still reads as the supported way to report a release —
/// and the release they carried was a per-deploy value that started a fresh
/// series set each time.
#[test]
fn compose_does_not_stamp_build_identity_onto_discovery_labels() {
    let compose = include_str!("../../../compose.yaml");

    assert!(!compose.contains("observability.release"));
    assert!(!compose.contains("observability.protocol"));
}

#[test]
fn readme_documents_the_value_encryption_boundary() {
    let readme = include_str!("../../../README.md");

    // The release used to claim volume encryption was the only boundary. It
    // now encrypts secrets itself, and the key is unrecoverable if lost, so
    // both facts have to stay documented.
    assert!(readme.contains("applies application-level encryption"));
    assert!(readme.contains("VALUE_ENCRYPTION_KEY_FILE"));
    assert!(readme.contains("SOVEREIGN_CONFIG_VALUE_ENCRYPTION_KEY"));
    assert!(readme.contains("Back up the value encryption key"));
    assert!(!readme.contains("does not add application-level encryption"));

    // Pin the scope positively. Stating what encryption covers is what stops
    // a reader concluding the whole database is sealed; banning the old
    // sentence alone let a second, contradictory posture sit elsewhere in the
    // document and still pass.
    assert!(readme.contains("to secret-classified configuration values, and to nothing else"));
    assert!(readme.contains("**Everything else in the database is stored verbatim**"));
    assert!(!readme.contains("PostgreSQL only ever holds ciphertext"));

    // The storage contract has to agree with the section above it.
    assert!(!readme.contains("plaintext content, and service-generated UTC"));
    assert!(readme.contains("sealed as an `enc:v1:` AEAD envelope"));
}

#[test]
fn readme_lists_every_production_secret_the_deployment_consumes() {
    let readme = include_str!("../../../README.md");
    let pipeline = include_str!("../../../.woodpecker/deploy-prod.yml");

    // A missing entry here is not cosmetic: the deploy step recreates the
    // running container before the server validates its configuration, so an
    // unprovisioned secret takes production down rather than failing the
    // pipeline.
    for secret in [
        "sovereign_config_prod_postgres_password",
        "sovereign_config_prod_manager_api_token",
        "sovereign_config_prod_value_encryption_key",
    ] {
        assert!(pipeline.contains(secret), "{secret} missing from pipeline");
        assert!(readme.contains(secret), "{secret} missing from README");
    }
}

/// Access tokens are verified against the issuer's JWKS (#450), so nothing
/// deploys an introspection endpoint, client or secret any more. A leftover
/// would be a credential provisioned for nothing — or a sign that something
/// started introspecting again without the README saying so.
#[test]
fn nothing_deploys_introspection_configuration() {
    for (file, text) in [
        ("compose.yaml", include_str!("../../../compose.yaml")),
        (
            ".woodpecker/deploy-dev.yml",
            include_str!("../../../.woodpecker/deploy-dev.yml"),
        ),
        (
            ".woodpecker/deploy-prod.yml",
            include_str!("../../../.woodpecker/deploy-prod.yml"),
        ),
    ] {
        assert!(
            !text.to_ascii_lowercase().contains("introspect"),
            "{file} still carries introspection configuration"
        );
    }
    // The blueprints name each retired provider once more, to delete it: a
    // blueprint that merely stopped mentioning it would leave it in Authentik.
    for (file, text, provider) in [
        (
            "authentik/blueprint.yaml",
            include_str!("../../../authentik/blueprint.yaml"),
            "sovereign-config-introspection",
        ),
        (
            "authentik/blueprint-dev.yaml",
            include_str!("../../../authentik/blueprint-dev.yaml"),
            "sovereign-config-introspection-dev",
        ),
    ] {
        let retirement = format!(
            "  - model: authentik_providers_oauth2.oauth2provider\n    state: absent\n    \
             identifiers:\n      name: {provider}\n"
        );
        assert!(
            text.contains(&retirement),
            "{file} does not delete {provider}"
        );
        assert_eq!(
            text.matches(provider).count(),
            1,
            "{file} names {provider} anywhere but its deletion"
        );
    }
}

fn compose_service(name: &str) -> serde_yaml::Mapping {
    let compose: serde_yaml::Value =
        serde_yaml::from_str(include_str!("../../../compose.yaml")).expect("compose parses");
    compose["services"][name]
        .as_mapping()
        .unwrap_or_else(|| panic!("compose has a {name} service"))
        .clone()
}

fn environment(service: &serde_yaml::Mapping) -> serde_yaml::Mapping {
    service["environment"]
        .as_mapping()
        .expect("environment is a mapping")
        .clone()
}

/// Telemetry is configured by the standard `OTEL_*` variables, whose values
/// belong to the deploy step (README "Observability"). The compose file names
/// them so they reach the server, and holds no value: a value here would be a
/// second place to retarget telemetry, and one that needs a commit to change.
///
/// The client-telemetry ingest takes the same upstream the same way. Its one
/// literal is its own `service.name`, which is a fact of this file rather
/// than of a deployment, and which the server's value must not become.
#[test]
fn compose_passes_the_otel_names_and_no_value() {
    let compose = include_str!("../../../compose.yaml");
    let server = environment(&compose_service("sovereign-config"));
    for name in [
        "OTEL_SERVICE_NAME",
        "OTEL_RESOURCE_ATTRIBUTES",
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "OTEL_EXPORTER_OTLP_PROTOCOL",
        "OTEL_LOGS_EXPORTER",
        "OTEL_METRICS_EXPORTER",
        "OTEL_TRACES_EXPORTER",
        "OTEL_SDK_DISABLED",
    ] {
        assert!(
            server.get(name).is_some_and(serde_yaml::Value::is_null),
            "compose must pass {name} through to the server without a value"
        );
    }
    let ingest = environment(&compose_service("otlp-ingest"));
    for name in [
        "OTEL_RESOURCE_ATTRIBUTES",
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "OTEL_EXPORTER_OTLP_PROTOCOL",
    ] {
        assert!(
            ingest.get(name).is_some_and(serde_yaml::Value::is_null),
            "compose must pass {name} through to the ingest without a value"
        );
    }
    assert_eq!(
        ingest["OTEL_SERVICE_NAME"].as_str(),
        Some("sovereign-config-otlp-ingest")
    );
    for (key, value) in server.iter().chain(ingest.iter()) {
        let key = key.as_str().unwrap_or_default();
        if key.starts_with("OTEL_") && key != "OTEL_SERVICE_NAME" {
            assert!(value.is_null(), "{key} must be passed by name only");
        }
    }
    assert!(
        !compose.contains("${OTEL_"),
        "no OTEL_* interpolation (and so no default) in compose"
    );
}

/// The web UI's ingest (README "Observability", *Client telemetry*) faces the
/// public edge with an operator's token in every request, so it runs as the
/// published image hardened, on the edge network only, and outside every
/// health gate: in its own profile, so a plain `up --wait` never includes it,
/// and in no service's `depends_on`.
#[test]
fn the_client_telemetry_ingest_is_hardened_and_never_a_dependency() {
    let ingest = compose_service("otlp-ingest");
    let image = ingest["image"].as_str().unwrap();
    assert!(image.starts_with("ghcr.io/vcheesbrough/otlp-collector-oidc:"));
    assert!(
        image.contains("@sha256:"),
        "the ingest image is pinned by digest"
    );
    assert!(
        ingest.get("ports").is_none(),
        "the ingest publishes no port"
    );
    assert!(ingest.get("expose").is_none());
    assert_eq!(
        ingest["profiles"],
        serde_yaml::Value::Sequence(vec!["client-telemetry".into()])
    );
    assert_eq!(ingest["user"].as_str(), Some("10001:10001"));
    assert_eq!(
        ingest["cap_drop"],
        serde_yaml::Value::Sequence(vec!["ALL".into()])
    );
    assert_eq!(ingest["read_only"].as_bool(), Some(true));
    assert_eq!(
        ingest["security_opt"],
        serde_yaml::Value::Sequence(vec!["no-new-privileges:true".into()])
    );
    assert!(ingest["mem_limit"].as_str().is_some());
    assert_eq!(
        ingest["networks"],
        serde_yaml::Value::Sequence(vec!["traefik".into()]),
        "on the edge network only, never beside the database"
    );
    assert!(ingest.get("depends_on").is_none());

    let compose: serde_yaml::Value =
        serde_yaml::from_str(include_str!("../../../compose.yaml")).unwrap();
    for (name, service) in compose["services"].as_mapping().unwrap() {
        let depends = serde_yaml::to_string(&service["depends_on"]).unwrap();
        assert!(
            !depends.contains("otlp-ingest"),
            "{name:?} must not depend on the ingest"
        );
    }

    // Same provider, same audience as the server: a token minted for any
    // other client is refused, and identity joins with the server's spans.
    let environment = environment(&ingest);
    assert_eq!(
        environment["OIDC_ISSUER_URL"].as_str(),
        Some("${SOVEREIGN_CONFIG_OIDC_ISSUER:?Set SOVEREIGN_CONFIG_OIDC_ISSUER}")
    );
    assert_eq!(
        environment["OIDC_AUDIENCE"].as_str(),
        Some("${SOVEREIGN_CONFIG_OIDC_AUDIENCE:?Set SOVEREIGN_CONFIG_OIDC_AUDIENCE}")
    );
    assert_eq!(
        environment["ALLOWED_SERVICE_NAMES"].as_str(),
        Some("sovereign-config-web")
    );
    assert_eq!(
        environment["CLIENT_RESOURCE_ATTRIBUTES"].as_str(),
        Some("deployment.environment.name=${SOVEREIGN_CONFIG_ENV:-dev},telemetry_source=client")
    );

    // Routed on the app's own hostname, OTLP/HTTP's `/v1/` only, behind the
    // same edge controls as the app plus a body cap.
    let labels = serde_yaml::to_string(&ingest["labels"]).unwrap();
    for expected in [
        "-otlp.rule=Host(`${SOVEREIGN_CONFIG_HOST:?Set SOVEREIGN_CONFIG_HOST}`) && PathPrefix(`/v1/`)",
        "-otlp.middlewares=lan-vpn-only@docker,rate-limit@docker,crowdsec@docker,",
        "-otlp-body.buffering.maxRequestBodyBytes=1048576",
        "-otlp.loadbalancer.server.port=4318",
        "-otlp.loadbalancer.server.scheme=https",
    ] {
        assert!(
            labels.contains(expected),
            "ingest labels must contain {expected}"
        );
    }
}

/// `service.instance.id` is derived from the hostname, which must therefore
/// survive a redeploy: Docker's default is the container id, new each time.
#[test]
fn the_server_hostname_is_its_stable_container_name() {
    let compose = include_str!("../../../compose.yaml");
    assert!(compose.contains(
        "    hostname: ${SOVEREIGN_CONFIG_CONTAINER_NAME:?Set SOVEREIGN_CONFIG_CONTAINER_NAME}\n"
    ));
}

/// Every deployment that sets telemetry sets the whole working set, with its
/// own environment's name, and never names a backend behind the collector.
#[test]
fn deploys_set_the_telemetry_values_for_their_environment() {
    for (workflow, environment) in [("deploy-dev", "dev"), ("deploy-prod", "prod")] {
        let path = format!(
            "{}/../../.woodpecker/{workflow}.yml",
            env!("CARGO_MANIFEST_DIR")
        );
        let text = std::fs::read_to_string(&path).expect("workflow readable");
        for expected in [
            "export OTEL_SERVICE_NAME=sovereign-config".to_owned(),
            format!(
                "export OTEL_RESOURCE_ATTRIBUTES=deployment.environment.name={environment},telemetry_source=otlp\n"
            ),
            "export OTEL_EXPORTER_OTLP_ENDPOINT=http://monitor-alloy:4318\n".to_owned(),
            "export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf\n".to_owned(),
            "export OTEL_LOGS_EXPORTER=otlp\n".to_owned(),
            "export OTEL_TRACES_EXPORTER=otlp\n".to_owned(),
            "export OTEL_METRICS_EXPORTER=otlp\n".to_owned(),
        ] {
            assert!(text.contains(&expected), "{workflow} must set `{expected}`");
        }
        assert!(!text.contains("loki"), "{workflow} must not name a backend");
        // The docker CLI replaces OTEL_RESOURCE_ATTRIBUTES when it execs the
        // compose plugin, so the deploy must run the plugin binary itself.
        assert!(
            !text.contains("docker compose -p"),
            "{workflow} must not deploy through `docker compose`"
        );
        assert!(text.contains("COMPOSE=/usr/local/libexec/docker/cli-plugins/docker-compose\n"));
    }
}

/// Each deployment hands its page exactly its own origin as the ingest, and
/// starts that ingest.
#[test]
fn deploys_turn_client_telemetry_on_for_their_own_origin() {
    for (workflow, host) in [
        ("deploy-dev", "sovereign-config-dev.desync.link"),
        ("deploy-prod", "sovereign-config.desync.link"),
    ] {
        let path = format!(
            "{}/../../.woodpecker/{workflow}.yml",
            env!("CARGO_MANIFEST_DIR")
        );
        let text = std::fs::read_to_string(&path).expect("workflow readable");
        assert!(text.contains(&format!(
            " SOVEREIGN_CONFIG_PUBLIC_ORIGIN=https://{host} SOVEREIGN_CONFIG_CLIENT_TELEMETRY_ENDPOINT=https://{host} "
        )));
        assert!(text.contains("--profile client-telemetry up -d --no-deps otlp-ingest"));
    }
    let compose = include_str!("../../../compose.yaml");
    assert!(compose.contains(
        "SOVEREIGN_CONFIG_CLIENT_TELEMETRY_ENDPOINT: ${SOVEREIGN_CONFIG_CLIENT_TELEMETRY_ENDPOINT:-}"
    ));
}
