//! The process `sovereign-config render` execs.
//!
//! `render` replaces itself with the command it is given, so the only way to
//! observe what it produced is from inside that command. This consumer reports
//! its own environment as JSON on standard output and exits with a requested
//! status, which lets an integration test assert the three things the exec path
//! must get right:
//!
//! - configuration reaches the child **byte-exact** — quotes, `$(...)`,
//!   backticks and embedded newlines are data, never shell syntax, because
//!   there is no shell between `render` and here;
//! - the inherited environment survives, and the credential does not;
//! - the child's exit status is `render`'s exit status, which is free only
//!   because the process really was replaced rather than wrapped.
//!
//! JSON rather than `NAME=value` lines precisely because a value may contain a
//! newline, an `=`, or both. It is written to standard output, so a caller that
//! does not want configuration on its stdout should not run this.
//!
//! Arguments are positional and deliberately trivial — every one of them also
//! doubles as a check that `render` passed the argument vector through
//! untouched:
//!
//! ```text
//! render-consumer                 # print the environment, exit 0
//! render-consumer --exit 42       # print the environment, exit 42
//! ```

use std::{collections::BTreeMap, process::ExitCode};

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let status = match exit_code(&arguments) {
        Ok(status) => status,
        Err(message) => {
            eprintln!("render-consumer: {message}");
            return ExitCode::from(2);
        }
    };

    let environment: BTreeMap<String, String> = std::env::vars().collect();
    println!(
        "{}",
        serde_json::to_string(&environment).expect("a string map always serialises")
    );
    ExitCode::from(status)
}

/// The exit status the arguments ask for.
///
/// # Errors
///
/// Returns a message for an unknown argument or an unparseable status, so a
/// test that mistypes its own invocation fails loudly instead of looking like
/// a `render` bug.
fn exit_code(arguments: &[String]) -> Result<u8, String> {
    match arguments {
        [] => Ok(0),
        [flag, code] if flag == "--exit" => code
            .parse()
            .map_err(|_| format!("--exit wants a status in 0..=255, got {code:?}")),
        other => Err(format!("unexpected arguments: {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::exit_code;

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn no_arguments_is_a_successful_exit() {
        assert_eq!(exit_code(&arguments(&[])), Ok(0));
    }

    #[test]
    fn an_explicit_status_is_returned_verbatim() {
        assert_eq!(exit_code(&arguments(&["--exit", "42"])), Ok(42));
        assert_eq!(exit_code(&arguments(&["--exit", "0"])), Ok(0));
        assert_eq!(exit_code(&arguments(&["--exit", "255"])), Ok(255));
    }

    // A test that mistypes its own invocation must not look like a `render`
    // bug, so anything unrecognised is an error rather than a default.
    #[test]
    fn an_unusable_invocation_is_refused() {
        for refused in [
            arguments(&["--exit"]),
            arguments(&["--exit", "256"]),
            arguments(&["--exit", "-1"]),
            arguments(&["--exit", "not-a-number"]),
            arguments(&["--unknown"]),
            arguments(&["--exit", "1", "extra"]),
        ] {
            assert!(exit_code(&refused).is_err(), "accepted {refused:?}");
        }
    }
}
