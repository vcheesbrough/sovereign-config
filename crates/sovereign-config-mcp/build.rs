use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=SOVEREIGN_CONFIG_RELEASE");
    let release = env::var("SOVEREIGN_CONFIG_RELEASE")
        .ok()
        .filter(|value| valid_release(value));
    if let Some(release) = release {
        println!("cargo:rustc-env=SOVEREIGN_CONFIG_RELEASE={release}");
    }
}

fn valid_release(value: &str) -> bool {
    !value.is_empty()
        && value
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}
