use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=SOVEREIGN_CONFIG_RELEASE");

    if let Ok(version) = env::var("SOVEREIGN_CONFIG_RELEASE")
        && !version.trim().is_empty()
    {
        println!("cargo:rustc-env=SOVEREIGN_CONFIG_RELEASE={version}");
    }
}
