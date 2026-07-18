#[test]
fn compose_requires_an_operator_provisioned_encrypted_volume() {
    let compose = include_str!("../../../compose.yaml");
    let readme = include_str!("../../../README.md");

    assert!(compose.contains("external: true"));
    assert!(compose.contains(
        "name: ${POSTGRES_DATA_VOLUME:?Set POSTGRES_DATA_VOLUME to a pre-created encrypted volume}"
    ));
    assert!(!compose.contains("POSTGRES_DATA_VOLUME:-"));
    assert!(readme.contains("pre-create the external PostgreSQL volume"));
    assert!(readme.contains("does not add application-level encryption"));
    assert!(readme.contains("PostgreSQL volume and backup encryption are the release boundary"));
}
