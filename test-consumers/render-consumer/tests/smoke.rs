//! Runs the consumer as the process it is meant to be.
//!
//! This test also has a second job, and it is load bearing: requesting
//! `CARGO_BIN_EXE_render-consumer` is what makes cargo build the **real**
//! binary rather than only its unit-test harness. Without an integration test
//! in this package, `cargo test --workspace` never produces
//! `target/<profile>/render-consumer`, and the CLI's own `render` tests — which
//! exec exactly that path — all fail. Do not delete this file.

use std::process::Command;

#[test]
fn the_consumer_reports_its_environment_and_exit_status() {
    let output = Command::new(env!("CARGO_BIN_EXE_render-consumer"))
        .args(["--exit", "7"])
        .env_clear()
        .env("RENDER_CONSUMER_SENTINEL", "one two\nthree")
        .output()
        .expect("the consumer should run");

    assert_eq!(output.status.code(), Some(7));
    let reported: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout should be a JSON object");
    // Byte-exact, including the newline that makes JSON the right carrier.
    assert_eq!(reported["RENDER_CONSUMER_SENTINEL"], "one two\nthree");
}
