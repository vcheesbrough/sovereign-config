//! End-to-end check of the self-extracting installer mechanism: wrap the real
//! CLI binary with `scripts/make-installer.sh`, run the installer into a
//! throwaway bin directory, and confirm the installed binary reports the
//! expected version. Also confirms a tampered payload is refused.
//!
//! This exercises the packaging that ships the CLI (see bored #267); the Docker
//! release build additionally stamps `SOVEREIGN_CONFIG_RELEASE` and targets
//! musl, but the mechanism is identical.

use std::{fs, path::PathBuf, process::Command};

/// Absolute path to `scripts/make-installer.sh`, resolved from this crate.
fn make_installer_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/make-installer.sh")
        .canonicalize()
        .expect("make-installer.sh must exist")
}

fn build_installer(output: &std::path::Path) {
    let status = Command::new("sh")
        .arg(make_installer_script())
        .args(["--binary", env!("CARGO_BIN_EXE_sovereign-config")])
        .args(["--name", "sovereign-config"])
        .args(["--version", env!("CARGO_PKG_VERSION")])
        .arg("--output")
        .arg(output)
        .status()
        .expect("make-installer.sh must run");
    assert!(status.success(), "make-installer.sh failed");
}

#[test]
fn installer_installs_a_runnable_versioned_binary() {
    let work = tempfile::tempdir().unwrap();
    let installer = work.path().join("install-sovereign-config-cli.sh");
    build_installer(&installer);

    // The companion checksum must verify the produced installer file.
    let checksum = fs::read_to_string(format!("{}.sha256", installer.display())).unwrap();
    assert!(checksum.trim().ends_with("install-sovereign-config-cli.sh"));

    let bindir = work.path().join("bin");
    let status = Command::new("sh")
        .arg(&installer)
        .env("SOVEREIGN_CONFIG_BIN", &bindir)
        .status()
        .expect("installer must run");
    assert!(status.success(), "installer exited non-zero");

    let installed_binary = bindir.join("sovereign-config");
    assert!(installed_binary.is_file(), "binary was not installed");

    let version = Command::new(&installed_binary)
        .arg("--version")
        .output()
        .expect("installed binary must run");
    assert!(version.status.success());
    let printed = String::from_utf8_lossy(&version.stdout);
    assert!(
        printed.contains(env!("CARGO_PKG_VERSION")),
        "expected version {} in {printed:?}",
        env!("CARGO_PKG_VERSION")
    );
}

#[test]
fn tampered_payload_is_refused_and_nothing_is_installed() {
    let work = tempfile::tempdir().unwrap();
    let installer = work.path().join("install-sovereign-config-cli.sh");
    build_installer(&installer);

    // Flip the final byte, which lies inside the gzip payload, so the embedded
    // checksum no longer matches.
    let mut bytes = fs::read(&installer).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    let tampered = work.path().join("tampered.sh");
    fs::write(&tampered, &bytes).unwrap();

    let bindir = work.path().join("bin");
    let status = Command::new("sh")
        .arg(&tampered)
        .env("SOVEREIGN_CONFIG_BIN", &bindir)
        .status()
        .expect("installer must run");
    assert!(!status.success(), "tampered installer must fail");
    assert!(
        !bindir.join("sovereign-config").exists(),
        "no binary must be installed from a tampered payload"
    );
}
