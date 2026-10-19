use std::{env, fs, io, path::Path};

#[path = "build/web_bundle.rs"]
mod web_bundle;

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
    // too — `sovereign_config_build_info` is the only metric that says which
    // commit is serving.
    if let Ok(revision) = env::var("SOVEREIGN_CONFIG_REVISION")
        && !revision.trim().is_empty()
    {
        println!("cargo:rustc-env=SOVEREIGN_CONFIG_REVISION={revision}");
    }

    require_release_web_bundle();
}

/// `web-dist/` is untracked build output that `src/web.rs` embeds. Refuse to
/// compile without it, or with a debug bundle in it, rather than ship a
/// server whose page is missing or several times its release size.
fn require_release_web_bundle() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    let bundle = Path::new(&manifest_dir).join("../../web-dist");
    let marker_path = bundle.join(web_bundle::MARKER);
    println!("cargo:rerun-if-changed=../../web-dist");
    println!(
        "cargo:rerun-if-changed=../../web-dist/{}",
        web_bundle::MARKER
    );

    let marker = match fs::read_to_string(&marker_path) {
        Ok(contents) => Some(contents),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => panic!("cannot read {}: {error}", marker_path.display()),
    };
    // `cargo::error` takes one line, so each line of the message is its own
    // directive; cargo prints them together and fails the build.
    if let Err(message) = web_bundle::check(marker.as_deref()) {
        for line in message.lines() {
            println!("cargo::error={line}");
        }
    }
}
