//! The build-script check that keeps a missing or debug web bundle out of the
//! server binary (`build/web_bundle.rs`).

#[path = "../build/web_bundle.rs"]
mod web_bundle;

use web_bundle::check;

#[test]
fn a_release_bundle_passes() {
    assert_eq!(check(Some("release")), Ok(()));
    assert_eq!(check(Some("release\n")), Ok(()));
}

#[test]
fn a_missing_bundle_names_both_ways_to_build_one() {
    let message = check(None).expect_err("a missing bundle must fail");
    assert!(message.contains("holds no web bundle"), "{message}");
    assert_build_instructions(&message);
}

#[test]
fn a_debug_bundle_is_refused() {
    let message = check(Some("debug")).expect_err("a debug bundle must fail");
    assert!(message.contains("`debug` web bundle"), "{message}");
    assert_build_instructions(&message);
}

#[test]
fn an_empty_marker_is_not_a_release() {
    assert!(check(Some("")).is_err());
}

fn assert_build_instructions(message: &str) {
    for expected in [
        "(cd crates/sovereign-config-web && trunk build --release --dist ../../web-dist)",
        "docker build -f docker/web.Dockerfile --output type=local,dest=web-dist .",
        "docs/development.md",
    ] {
        assert!(
            message.contains(expected),
            "missing {expected:?} in {message}"
        );
    }
}
