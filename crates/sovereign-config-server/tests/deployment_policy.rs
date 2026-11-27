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

/// The credentials each container is given, as `/run/secrets/<name>` files,
/// and the variable it reads each from. Nothing else carries a credential.
const CREDENTIALS: [(&str, &[(&str, &str)]); 3] = [
    (
        "postgres",
        &[("postgres_password", "POSTGRES_PASSWORD_FILE")],
    ),
    (
        "migrate",
        &[
            ("owner_database_url", "SOVEREIGN_CONFIG_DATABASE_URL_FILE"),
            (
                "runtime_database_password",
                "SOVEREIGN_CONFIG_RUNTIME_DATABASE_PASSWORD_FILE",
            ),
            (
                "authentik_admin_token",
                "SOVEREIGN_CONFIG_AUTHENTIK_ADMIN_TOKEN_FILE",
            ),
            (
                "manager_api_token",
                "SOVEREIGN_CONFIG_MANAGER_API_TOKEN_FILE",
            ),
            (
                "value_encryption_key",
                "SOVEREIGN_CONFIG_VALUE_ENCRYPTION_KEY_FILE",
            ),
        ],
    ),
    (
        "sovereign-config",
        &[
            ("runtime_database_url", "SOVEREIGN_CONFIG_DATABASE_URL_FILE"),
            (
                "manager_api_token",
                "SOVEREIGN_CONFIG_MANAGER_API_TOKEN_FILE",
            ),
            (
                "value_encryption_key",
                "SOVEREIGN_CONFIG_VALUE_ENCRYPTION_KEY_FILE",
            ),
        ],
    ),
];

/// A service's secrets, each as `(source, uid)`: long syntax, `uid` unset
/// for one Postgres reads as root.
fn secret_grants(service: &serde_yaml::Mapping) -> Vec<(String, Option<String>)> {
    service["secrets"]
        .as_sequence()
        .expect("secrets is a list")
        .iter()
        .map(|grant| {
            let source = grant["source"]
                .as_str()
                .expect("every secret is long syntax, naming its source")
                .to_owned();
            assert_eq!(
                grant.get("uid").map(|uid| uid.as_str()),
                grant.get("gid").map(|gid| gid.as_str()),
                "{source}: uid and gid go together"
            );
            (
                source,
                grant
                    .get("uid")
                    .and_then(serde_yaml::Value::as_str)
                    .map(str::to_owned),
            )
        })
        .collect()
}

/// Every credential reaches its container as a file, never as one of its
/// variables (#615): an exited container — `migrate`, after every deploy —
/// keeps its environment in `docker inspect`. Compose reads each from the
/// environment of whatever runs it and writes it into the containers given
/// it (#617), so a stack can be started from variables alone, with no deploy
/// step writing files. An unset variable fails `up`.
#[test]
fn compose_delivers_every_credential_from_the_environment_as_a_file() {
    let text = include_str!("../../../compose.yaml");
    let compose: serde_yaml::Value = serde_yaml::from_str(text).expect("compose parses");
    for (service, credentials) in CREDENTIALS {
        let definition = compose_service(service);
        let environment = environment(&definition);
        let owner = (service != "postgres").then(|| "10001".to_owned());
        let mut expected: Vec<(String, Option<String>)> = credentials
            .iter()
            .map(|(secret, _)| ((*secret).to_owned(), owner.clone()))
            .collect();
        let mut given = secret_grants(&definition);
        expected.sort_unstable();
        given.sort_unstable();
        assert_eq!(
            given, expected,
            "{service} is given exactly its credentials, owned by the user that reads them"
        );
        for (secret, variable) in credentials {
            assert_eq!(
                environment[*variable].as_str(),
                Some(format!("/run/secrets/{secret}").as_str()),
                "{service} reads {secret} from its file, at a path no deploy overrides"
            );
            let direct = variable.trim_end_matches("_FILE");
            assert!(
                environment.get(direct).is_none(),
                "{service} must not take {direct} as a variable"
            );
        }
    }
    // Every grant is readable by its owner alone.
    let grants: usize = CREDENTIALS
        .iter()
        .map(|(_, credentials)| credentials.len())
        .sum();
    assert_eq!(text.matches("        mode: 0400\n").count(), grants);
    let secrets = compose["secrets"].as_mapping().expect("secrets");
    for (secret, variable) in [
        ("postgres_password", "POSTGRES_PASSWORD"),
        ("owner_database_url", "OWNER_DATABASE_URL"),
        ("runtime_database_password", "RUNTIME_DATABASE_PASSWORD"),
        ("runtime_database_url", "RUNTIME_DATABASE_URL"),
        ("manager_api_token", "MANAGER_API_TOKEN"),
        ("value_encryption_key", "VALUE_ENCRYPTION_KEY"),
        ("authentik_admin_token", "AUTHENTIK_ADMIN_TOKEN"),
    ] {
        assert_eq!(
            secrets[secret],
            serde_yaml::from_str::<serde_yaml::Value>(&format!("environment: {variable}")).unwrap(),
            "{secret} is read from {variable}, and from nowhere else"
        );
    }
    assert_eq!(secrets.len(), 7, "a credential was added or removed");
}

/// Only `migrate` holds the Authentik admin token: the server that runs for
/// weeks never could configure Authentik, whatever it was made to do.
#[test]
fn only_migrate_is_given_the_authentik_admin_token() {
    let compose: serde_yaml::Value =
        serde_yaml::from_str(include_str!("../../../compose.yaml")).expect("compose parses");
    for (name, service) in compose["services"].as_mapping().expect("services") {
        let name = name.as_str().unwrap();
        let holds = service.get("secrets").is_some_and(|_| {
            secret_grants(service.as_mapping().unwrap())
                .iter()
                .any(|(source, _)| source == "authentik_admin_token")
        }) || serde_yaml::to_string(&service["environment"])
            .unwrap()
            .contains("AUTHENTIK_ADMIN_TOKEN");
        assert_eq!(holds, name == "migrate", "{name}");
    }
}

/// The database owner's password reaches PostgreSQL and `migrate` alone: the
/// server logs in as the runtime role `migrate` creates, which owns nothing,
/// so a compromised server can read and write rows but create, alter, drop
/// or truncate nothing (#616). Only `migrate` holds the runtime password it
/// sets, and only the server the URL that carries it.
#[test]
fn the_server_holds_no_owner_password() {
    let compose: serde_yaml::Value =
        serde_yaml::from_str(include_str!("../../../compose.yaml")).expect("compose parses");
    for (secret, holders) in [
        ("postgres_password", &["postgres"][..]),
        ("owner_database_url", &["migrate"][..]),
        ("runtime_database_password", &["migrate"][..]),
        ("runtime_database_url", &["sovereign-config"][..]),
    ] {
        let mut held: Vec<&str> = compose["services"]
            .as_mapping()
            .expect("services")
            .iter()
            .filter(|(_, service)| {
                service.get("secrets").is_some_and(|_| {
                    secret_grants(service.as_mapping().unwrap())
                        .iter()
                        .any(|(source, _)| source == secret)
                })
            })
            .map(|(name, _)| name.as_str().unwrap())
            .collect();
        held.sort_unstable();
        assert_eq!(held, holders, "who is given {secret}");
    }
    let server =
        serde_yaml::to_string(&compose_service("sovereign-config")["environment"]).unwrap();
    for owner in [
        "POSTGRES_PASSWORD",
        "OWNER_DATABASE_URL",
        "owner_database_url",
        "postgres_password",
    ] {
        assert!(!server.contains(owner), "the server names {owner}");
    }
    // The owner is PostgreSQL's own user, which `migrate`'s URL names.
    assert_eq!(
        environment(&compose_service("postgres"))["POSTGRES_USER"].as_str(),
        Some("sovereign_config")
    );
}

/// `migrate` is the same image as the server, run once per `up` and never
/// restarted, and the server starts only once it has exited 0 (#615).
#[test]
fn migrate_runs_once_from_the_servers_image_before_the_server() {
    let migrate = compose_service("migrate");
    let server = compose_service("sovereign-config");
    assert_eq!(migrate["image"], server["image"]);
    assert_eq!(strings(&migrate["command"]), ["migrate"]);
    assert_eq!(migrate["restart"].as_str(), Some("no"));
    assert_eq!(migrate["healthcheck"]["disable"].as_bool(), Some(true));
    assert_eq!(
        migrate["depends_on"]["postgres"]["condition"].as_str(),
        Some("service_healthy")
    );
    assert_eq!(
        server["depends_on"]["migrate"]["condition"].as_str(),
        Some("service_completed_successfully")
    );
    assert!(
        environment(&migrate)["SOVEREIGN_CONFIG_AUTHENTIK_BLUEPRINT"]
            .as_str()
            .is_some_and(|value| value.contains(":?")),
        "a deploy must choose its blueprint; none set would skip Authentik silently"
    );
}

/// Every container must be discoverable as one service in two environments.
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
        // Part of the server's service, as its telemetry is.
        ("migrate", "sovereign-config"),
        ("sovereign-config", "sovereign-config"),
        ("otlp-ingest", "sovereign-config-otlp-ingest"),
    ] {
        assert!(
            strings(&compose_service(service)["labels"])
                .contains(&format!("observability.service.name={expected}").as_str()),
            "{service} must name itself for Loki and Prometheus"
        );
    }
    assert_eq!(
        compose
            .matches("\"observability.deployment.environment=${SOVEREIGN_CONFIG_ENV:-dev}\"")
            .count(),
        4,
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
    assert!(readme.contains("| `VALUE_ENCRYPTION_KEY` |"));
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

/// Production's credentials live with its deployer, mini-config (its card
/// #614), and nowhere in this repository's pipelines: a promotion holding them
/// would be a second deployer, and production could not come back without
/// Woodpecker and the broker. The doc says where they are.
#[test]
fn production_credentials_live_with_its_deployer_not_here() {
    let doc = include_str!("../../../docs/project-deployment.md");
    let promotion = include_str!("../../../.woodpecker/promote-prod.yml");
    for secret in [
        "sovereign_config_prod_postgres_password",
        "sovereign_config_prod_manager_api_token",
        "sovereign_config_prod_value_encryption_key",
        "authentik_api_token",
    ] {
        assert!(
            !promotion.contains(secret),
            "the prod promotion must not hold {secret}"
        );
    }
    assert!(
        doc.contains("`sovereign-config-stack`") && doc.contains("`secrets.env.enc`"),
        "docs/project-deployment.md must say where production's credentials live"
    );
}

/// Production runs mini-config's mirror of `compose.yaml`
/// (`sovereign-config-stack/docker-compose.yml`, its card #614), not this
/// file, so a change here reaches production only if it is carried there. This
/// pins the file: when it fails, put the change into the mirror in the
/// release's pin-bump PR (AGENTS.md §1), then set the new hash here. A server
/// started on a stale mirror fails its checks after `migrate` has run.
#[test]
fn a_compose_change_is_carried_to_productions_mirror() {
    use sha2::{Digest, Sha256};
    let digest = format!(
        "{:x}",
        Sha256::digest(include_bytes!("../../../compose.yaml"))
    );
    assert_eq!(
        digest, "da2a8073b0d02700982fd9709393f075b12aadbfd48e6963952ffe40c0eb70ea",
        "compose.yaml changed: carry the change into mini-config's \
         sovereign-config-stack/docker-compose.yml in the release's pin-bump PR, \
         then update this hash"
    );
}

/// Access tokens are verified against the issuer's JWKS (#450), so nothing
/// deploys an introspection endpoint, client or secret any more. A leftover
/// would be a credential provisioned for nothing — or a sign that something
/// started introspecting again without `docs/authentication.md` saying so.
#[test]
fn nothing_deploys_introspection_configuration() {
    for (file, text) in [
        ("compose.yaml", include_str!("../../../compose.yaml")),
        (
            ".woodpecker/deploy-dev.yml",
            include_str!("../../../.woodpecker/deploy-dev.yml"),
        ),
        (
            ".woodpecker/promote-prod.yml",
            include_str!("../../../.woodpecker/promote-prod.yml"),
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
/// belong to the deploy step (docs/project-deployment.md). The compose file names
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
    let migrate = environment(&compose_service("migrate"));
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
        for (service, environment) in [("the server", &server), ("migrate", &migrate)] {
            assert!(
                environment
                    .get(name)
                    .is_some_and(serde_yaml::Value::is_null),
                "compose must pass {name} through to {service} without a value"
            );
        }
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
    for (key, value) in server.iter().chain(migrate.iter()).chain(ingest.iter()) {
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

/// The web UI's ingest (docs/observability.md, *Client telemetry*) faces the
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
/// `migrate` is an instance of its own.
#[test]
fn the_server_hostname_is_its_stable_container_name() {
    let compose = include_str!("../../../compose.yaml");
    assert!(compose.contains(
        "    hostname: ${SOVEREIGN_CONFIG_CONTAINER_NAME:?Set SOVEREIGN_CONFIG_CONTAINER_NAME}\n"
    ));
    assert!(compose.contains(
        "    hostname: ${SOVEREIGN_CONFIG_CONTAINER_NAME:?Set SOVEREIGN_CONFIG_CONTAINER_NAME}-migrate\n"
    ));
}

/// Every deployment that sets telemetry sets the whole working set, with its
/// own environment's name, and never names a backend behind the collector.
/// Production's are set by its deployer, mini-config.
#[test]
fn deploys_set_the_telemetry_values_for_their_environment() {
    {
        let (workflow, environment) = ("deploy-dev", "dev");
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
/// starts that ingest. Production's is set by its deployer, mini-config.
#[test]
fn deploys_turn_client_telemetry_on_for_their_own_origin() {
    {
        let (workflow, host) = ("deploy-dev", "sovereign-config-dev.desync.link");
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

/// The user every image this repository builds runs as, and the group a
/// shared volume is owned by (docs/project-deployment.md, *Container users*).
const CONTAINER_USER: &str = "10001:10001";

/// The services that run without a `user:` line, each with its reason. An
/// entry is a decision recorded in docs/project-deployment.md, not a waiver.
const SERVICES_WITHOUT_A_USER: [(&str, &str); 1] = [(
    "postgres",
    "the upstream entrypoint starts as root to own the data directory, then drops to postgres",
)];

/// The services that run as [`CONTAINER_USER`] on a writable root
/// filesystem, each with its reason. Compose writes an `environment:`-sourced
/// secret into the container and refuses to for a read-only one (#617).
const SERVICES_WITH_A_WRITABLE_ROOT: [(&str, &str); 2] = [
    ("migrate", "Compose writes its secrets into the container"),
    (
        "sovereign-config",
        "Compose writes its secrets into the container",
    ),
];

/// What the root part of the Postgres entrypoint uses: taking ownership of
/// the data directory (`CHOWN`, `FOWNER`), reading a password file and
/// writing a directory it does not own (`DAC_OVERRIDE`), and dropping to
/// `postgres` (`SETGID`, `SETUID`).
const POSTGRES_CAPABILITIES: [&str; 5] = ["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"];

fn strings(value: &serde_yaml::Value) -> Vec<&str> {
    value
        .as_sequence()
        .map(|items| items.iter().filter_map(serde_yaml::Value::as_str).collect())
        .unwrap_or_default()
}

/// Whether `user` is `uid:gid` with both numeric and neither root. A name
/// would be resolved inside the image, which is the dependency `user:` is
/// here to remove.
fn is_unprivileged(user: &str) -> bool {
    user.split_once(':').is_some_and(|(uid, gid)| {
        [uid, gid]
            .iter()
            .all(|id| id.parse::<u32>().is_ok_and(|id| id != 0))
    })
}

/// No service may run with more privilege than it was decided it needs
/// (bored card #579). Before this, the server's user came only from its
/// image, so a Dockerfile change could have made it root with nothing here
/// noticing.
#[test]
fn every_service_runs_unprivileged_with_no_capabilities() {
    let compose: serde_yaml::Value =
        serde_yaml::from_str(include_str!("../../../compose.yaml")).expect("compose parses");
    let services = compose["services"].as_mapping().expect("services");
    for (name, service) in services {
        let name = name.as_str().expect("service name");
        assert_eq!(
            strings(&service["cap_drop"]),
            ["ALL"],
            "{name} must drop every capability"
        );
        assert!(
            strings(&service["security_opt"]).contains(&"no-new-privileges:true"),
            "{name} must set no-new-privileges"
        );
        assert!(
            service.get("privileged").is_none(),
            "{name} must not be privileged"
        );
        let excepted = SERVICES_WITHOUT_A_USER
            .iter()
            .any(|(service, _)| *service == name);
        match service.get("user").and_then(serde_yaml::Value::as_str) {
            Some(user) => {
                assert!(
                    !excepted,
                    "{name} sets a user, so it no longer belongs in SERVICES_WITHOUT_A_USER"
                );
                assert!(
                    is_unprivileged(user),
                    "{name} must run as a numeric non-root uid:gid, not {user:?}"
                );
                assert_eq!(
                    user, CONTAINER_USER,
                    "{name} must run as the documented {CONTAINER_USER}"
                );
                let writable = SERVICES_WITH_A_WRITABLE_ROOT
                    .iter()
                    .any(|(service, _)| *service == name);
                assert_eq!(
                    service["read_only"].as_bool(),
                    (!writable).then_some(true),
                    "{name} runs as {CONTAINER_USER} and must have a read-only root \
                     filesystem, or be a decided exception that sets no `read_only`"
                );
                assert_eq!(
                    strings(&service["tmpfs"]),
                    ["/tmp"],
                    "{name} has a read-only root and gets a tmpfs on /tmp only"
                );
                assert!(
                    service.get("cap_add").is_none(),
                    "{name} runs unprivileged and must add no capability back"
                );
            }
            None => assert!(
                excepted,
                "{name} must set a non-root `user:`, or be a decided exception"
            ),
        }
    }
    for (service, reason) in SERVICES_WITHOUT_A_USER {
        assert!(
            services.contains_key(service),
            "{service} is excepted ({reason}) but is not a service"
        );
    }
    assert_eq!(
        strings(&compose_service("postgres")["cap_add"]),
        POSTGRES_CAPABILITIES,
        "postgres keeps exactly what its entrypoint needs before it drops to `postgres`"
    );
}

#[test]
fn only_numeric_non_root_ids_count_as_unprivileged() {
    assert!(is_unprivileged(CONTAINER_USER));
    for user in ["0:0", "10001:0", "0:10001", "10001", "root", "app:app", ""] {
        assert!(!is_unprivileged(user), "{user:?} must not pass");
    }
}

/// The server restates the image's user. Its root filesystem is writable only
/// because Compose writes its secrets into it (#617); the user, the dropped
/// capabilities and `no-new-privileges` stay.
#[test]
fn the_server_runs_as_the_documented_user() {
    let server = compose_service("sovereign-config");
    assert_eq!(server["user"].as_str(), Some(CONTAINER_USER));
    assert!(server.get("read_only").is_none());
    assert_eq!(strings(&server["tmpfs"]), ["/tmp"]);
    let doc = include_str!("../../../docs/project-deployment.md");
    assert!(
        doc.contains("## Container users") && doc.contains(CONTAINER_USER),
        "docs/project-deployment.md states the convention the compose file follows"
    );
}

/// The Dockerfiles whose last stage does not end on [`CONTAINER_USER`], each
/// with its reason.
const DOCKERFILES_WITHOUT_THE_USER: [(&str, &str); 2] = [
    (
        "cli.Dockerfile",
        "pipeline steps drive the host Docker socket and a root-owned workspace as root",
    ),
    (
        "web.Dockerfile",
        "its last stage is a scratch artifact that is exported, never run",
    ),
];

/// The `USER` in force at the end of a Dockerfile's last stage, if it sets
/// one. A stage does not inherit the `USER` of an earlier stage unless it is
/// built `FROM` it, which no runtime stage here is.
///
/// Instructions are matched in any letter case, as Docker reads them, and a
/// line ending in the default `\` escape continues onto the next one, so
/// neither `user root` nor `USER \` + `root` slips past. This is not a
/// Dockerfile parser: a parser directive changing the escape character, or a
/// heredoc, is not understood.
fn final_user(dockerfile: &str) -> Option<String> {
    let mut user = None;
    for instruction in instructions(dockerfile) {
        let mut words = instruction.split_whitespace();
        match words.next() {
            Some(word) if word.eq_ignore_ascii_case("FROM") => user = None,
            Some(word) if word.eq_ignore_ascii_case("USER") => {
                user = words.next().map(str::to_owned);
            }
            _ => {}
        }
    }
    user
}

/// A Dockerfile's logical lines: each line ending in `\` is joined to the
/// next. Comment lines are dropped wherever they appear, so a comment ending
/// in `\` never continues, and a blank line inside a continuation is
/// skipped rather than ending it, both as Docker does.
fn instructions(dockerfile: &str) -> Vec<String> {
    let mut instructions = Vec::new();
    let mut pending: Option<String> = None;
    for line in dockerfile.lines() {
        if line.trim_start().starts_with('#') || (pending.is_some() && line.trim().is_empty()) {
            continue;
        }
        let trimmed = line.trim_end();
        let (text, continues) = match trimmed.strip_suffix('\\') {
            Some(text) => (text, true),
            None => (trimmed, false),
        };
        let joined = match pending.take() {
            Some(mut so_far) => {
                so_far.push(' ');
                so_far.push_str(text);
                so_far
            }
            None => text.to_owned(),
        };
        if continues {
            pending = Some(joined);
        } else {
            instructions.push(joined);
        }
    }
    instructions.extend(pending);
    instructions
}

/// Each image that runs as a service ends on the documented numeric user
/// with an explicit group, so the image is unprivileged even where a
/// deployment sets no `user:` (the broker's, outside this repository).
#[test]
fn every_runtime_image_ends_on_the_documented_user() {
    let docker = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docker");
    let mut seen = Vec::new();
    for entry in std::fs::read_dir(&docker).expect("docker/ is readable") {
        let path = entry.expect("dir entry").path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("file name")
            .to_owned();
        if !name.ends_with(".Dockerfile") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("Dockerfile readable");
        let user = final_user(&text);
        let user = user.as_deref();
        if DOCKERFILES_WITHOUT_THE_USER
            .iter()
            .any(|(file, _)| *file == name)
        {
            assert_eq!(
                user, None,
                "{name} sets a user, so it no longer belongs in DOCKERFILES_WITHOUT_THE_USER"
            );
        } else {
            assert_eq!(
                user,
                Some(CONTAINER_USER),
                "{name} must end on `USER {CONTAINER_USER}`"
            );
            assert!(
                text.contains("groupadd --system --gid 10001 ")
                    && text.contains("useradd --system --uid 10001 --gid 10001 "),
                "{name} must create its group and user with the documented ids"
            );
        }
        seen.push(name);
    }
    for (file, reason) in DOCKERFILES_WITHOUT_THE_USER {
        assert!(
            seen.iter().any(|name| name == file),
            "{file} is excepted ({reason}) but does not exist"
        );
    }
    assert!(seen.iter().any(|name| name == "server.Dockerfile"));
    assert!(seen.iter().any(|name| name == "broker.Dockerfile"));
}

#[test]
fn the_last_stage_decides_a_dockerfiles_user() {
    assert_eq!(
        final_user("FROM a\nUSER 10001:10001\n").as_deref(),
        Some("10001:10001")
    );
    assert_eq!(
        final_user("FROM a AS b\nUSER app\nFROM c\nRUN true\n"),
        None
    );
    assert_eq!(
        final_user("FROM a\nUSER app\nUSER root\n").as_deref(),
        Some("root")
    );
    // Docker reads instructions in any letter case and after leading
    // whitespace, so a lower-case or indented `USER` or `FROM` still counts.
    assert_eq!(final_user("from a\nuser root\n").as_deref(), Some("root"));
    assert_eq!(final_user("FROM a\n  USER root\n").as_deref(), Some("root"));
    assert_eq!(
        final_user("FROM a\nUsEr app\n\tuser root\n").as_deref(),
        Some("root")
    );
    assert_eq!(final_user("FROM a\nUSER app\n  from b\n"), None);
}

/// A `USER` split by a `\` continuation still names its user, and a
/// continuation line of another instruction is never read as `USER` or
/// `FROM`.
#[test]
fn a_dockerfiles_user_follows_line_continuations() {
    assert_eq!(
        final_user("FROM a\nUSER \\\n  root\n").as_deref(),
        Some("root")
    );
    assert_eq!(
        final_user("FROM a\nUSER \\\n# a comment\n  root\n").as_deref(),
        Some("root")
    );
    assert_eq!(
        final_user("FROM a\nUSER app\nRUN true \\\n  user root\n").as_deref(),
        Some("app")
    );
    assert_eq!(
        final_user("FROM a\nUSER app\nRUN echo \\\n  from b\n").as_deref(),
        Some("app")
    );
    // A comment ending in `\` does not continue, so the instruction after it
    // is still read.
    assert_eq!(
        final_user("FROM a\nUSER 10001:10001\n# RUN apt-get install \\\n#     foo\nUSER root\n")
            .as_deref(),
        Some("root")
    );
    assert_eq!(
        final_user("FROM a\nUSER 10001:10001\n# note \\\nUSER root\n").as_deref(),
        Some("root")
    );
    // A blank line inside a continuation is skipped, not the end of it.
    assert_eq!(
        final_user("FROM a\nUSER root\nRUN x \\\n\nUSER 10001:10001\n").as_deref(),
        Some("root")
    );
    assert_eq!(
        final_user("FROM a\nUSER root\nRUN x \\\n   \nUSER 10001:10001\n").as_deref(),
        Some("root")
    );
}
