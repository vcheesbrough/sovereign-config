use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=SOVEREIGN_CONFIG_RELEASE");
    println!("cargo:rerun-if-env-changed=SOVEREIGN_CONFIG_REVISION");

    if let Ok(version) = env::var("SOVEREIGN_CONFIG_RELEASE")
        && !version.trim().is_empty()
    {
        println!("cargo:rustc-env=SOVEREIGN_CONFIG_RELEASE={version}");
    }

    // The commit the image was built from. It reaches the image as an OCI
    // label, which the running process cannot read, so the build stamps it in
    // too — `sovereign_config_build_info` is the only place a scrape can learn
    // which commit is serving.
    if let Ok(revision) = env::var("SOVEREIGN_CONFIG_REVISION")
        && !revision.trim().is_empty()
    {
        println!("cargo:rustc-env=SOVEREIGN_CONFIG_REVISION={revision}");
    }
}
