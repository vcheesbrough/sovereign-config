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
}
