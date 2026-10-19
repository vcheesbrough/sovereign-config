// The check build.rs runs before the server embeds `web-dist/`. It lives in
// its own file so `tests/web_bundle_guard.rs` can test it; a build script
// cannot have tests of its own.

/// The marker `crates/sovereign-config-web/Trunk.toml`'s `post_build` hook
/// writes into every bundle it builds, holding the trunk profile.
pub const MARKER: &str = ".trunk-profile";

const BUILD_IT: &str = "Build the release bundle with\n\
    \x20   (cd crates/sovereign-config-web && trunk build --release --dist ../../web-dist)\n\
    or, without a local trunk,\n\
    \x20   docker build -f docker/web.Dockerfile --output type=local,dest=web-dist .\n\
    See docs/development.md, \"Web bundle\".";

/// Whether `web-dist/` holds a bundle the server may embed, given the
/// marker's contents (`None` when the marker is absent). The error is the
/// whole message to show the developer.
pub fn check(marker: Option<&str>) -> Result<(), String> {
    match marker.map(str::trim) {
        Some("release") => Ok(()),
        None => Err(format!(
            "web-dist/ holds no web bundle (no web-dist/{MARKER}). The server embeds \
             web-dist/, which is a build output and not tracked in git.\n{BUILD_IT}"
        )),
        Some(profile) => Err(format!(
            "web-dist/ holds a `{profile}` web bundle, not a release one (web-dist/{MARKER}). \
             The server embeds web-dist/ as it is, and a debug bundle is several times the size.\n\
             {BUILD_IT}"
        )),
    }
}
