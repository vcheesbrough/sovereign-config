use std::{env, process::Command};

fn main() {
    println!("cargo:rerun-if-env-changed=SOVEREIGN_CONFIG_RELEASE");
    let release = env::var("SOVEREIGN_CONFIG_RELEASE")
        .ok()
        .filter(|value| valid_release(value))
        .or_else(git_release);
    if let Some(release) = release {
        println!("cargo:rustc-env=SOVEREIGN_CONFIG_RELEASE={release}");
    }
}

fn git_release() -> Option<String> {
    let output = Command::new("git")
        .args(["describe", "--tags", "--exact-match"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let release = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    valid_release(&release).then_some(release)
}

fn valid_release(value: &str) -> bool {
    !value.is_empty()
        && value
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}
