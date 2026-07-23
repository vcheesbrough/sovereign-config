//! End-to-end check of the self-extracting installer for the MCP binary: wrap
//! the real `sovereign-config-mcp` binary with `scripts/make-installer.sh`, run
//! the installer into a throwaway bin directory, and confirm the installed
//! binary reports the expected version. Also confirms a tampered payload is
//! refused. Mirrors the CLI's installer test — the packaging mechanism is
//! shared; the Docker release build additionally targets musl and stamps
//! `SOVEREIGN_CONFIG_RELEASE`.

use std::{fs, path::PathBuf, process::Command};

const INSTALLED_NAME: &str = "sovereign-config-mcp";

fn make_installer_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/make-installer.sh")
        .canonicalize()
        .expect("make-installer.sh must exist")
}

fn build_installer(output: &std::path::Path) {
    let status = Command::new("sh")
        .arg(make_installer_script())
        .args(["--binary", env!("CARGO_BIN_EXE_sovereign-config-mcp")])
        .args(["--name", INSTALLED_NAME])
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
    let installer = work.path().join("install-sovereign-config-mcp.sh");
    build_installer(&installer);

    let checksum = fs::read_to_string(format!("{}.sha256", installer.display())).unwrap();
    assert!(checksum.trim().ends_with("install-sovereign-config-mcp.sh"));

    let bindir = work.path().join("bin");
    let status = Command::new("sh")
        .arg(&installer)
        .env("SOVEREIGN_CONFIG_BIN", &bindir)
        .status()
        .expect("installer must run");
    assert!(status.success(), "installer exited non-zero");

    let installed_binary = bindir.join(INSTALLED_NAME);
    assert!(installed_binary.is_file(), "binary was not installed");

    let version = Command::new(&installed_binary)
        .arg("--version")
        .output()
        .expect("installed binary must run");
    assert!(version.status.success());
    let printed = String::from_utf8_lossy(&version.stdout);
    assert!(
        printed.trim().ends_with(env!("CARGO_PKG_VERSION")),
        "installed binary reported {printed:?}, expected version {}",
        env!("CARGO_PKG_VERSION"),
    );
}

#[test]
fn installer_refuses_a_tampered_payload() {
    let work = tempfile::tempdir().unwrap();
    let installer = work.path().join("install-sovereign-config-mcp.sh");
    build_installer(&installer);

    // Flip a byte deep in the gzip payload (past the shell header) so the
    // embedded checksum no longer matches, and confirm the installer aborts.
    let mut bytes = fs::read(&installer).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    fs::write(&installer, &bytes).unwrap();

    let bindir = work.path().join("bin");
    let status = Command::new("sh")
        .arg(&installer)
        .env("SOVEREIGN_CONFIG_BIN", &bindir)
        .status()
        .expect("installer must run");
    assert!(!status.success(), "tampered installer must fail");
    assert!(
        !bindir.join(INSTALLED_NAME).exists(),
        "no binary may be installed from a tampered payload",
    );
}
