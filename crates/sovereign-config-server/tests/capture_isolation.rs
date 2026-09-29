//! A capture sees its spans even when another thread reached their callsite
//! first — the race that dropped the Authentik introspection span from
//! `auth::tests` in about one parallel run in six.
//!
//! Its own test binary with its one test, so the capture here is the first
//! dispatch the process registers: the state `Capture` must not be the only
//! one in (see `never_the_only_dispatch` in `sovereign-config-telemetry`).

use sovereign_config_telemetry::testing::Capture;

fn shared_work() {
    let _span = tracing::info_span!(target: "sovereign_config_isolation", "shared_work").entered();
}

#[test]
fn a_span_first_reached_on_another_thread_still_reaches_the_capture() {
    let capture = Capture::exporting();
    {
        // Entered first: `enter` rebuilds every *registered* callsite's
        // interest, which would otherwise hide the race.
        let _guard = capture.enter();
        // A parallel test with no subscriber reaches the callsite first.
        std::thread::spawn(shared_work).join().unwrap();
        shared_work();
    }
    let exported = capture.finish();

    assert_eq!(exported.spans_named("shared_work").len(), 1);
}
