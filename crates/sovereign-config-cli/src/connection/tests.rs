use super::parse;

const URL: &str = "https://config.example.test/team/service\
                   #v=1&issuer=https%3A%2F%2Fauth.example.test%2F&client_id=sovereign-config";

// A file written by `echo`, a heredoc, or a CI secret mount ends in a newline.
// Refusing that would be a papercut with no security value.
#[test]
fn one_trailing_line_ending_is_tolerated() {
    let expected = parse(URL).unwrap().redacted();
    for written in [format!("{URL}\n"), format!("{URL}\r\n"), URL.to_owned()] {
        assert_eq!(parse(&written).unwrap().redacted(), expected);
    }
}

// An embedded newline means the input is not one URL. Guessing which line was
// meant is how a deploy ends up pointed at the wrong service, so it is refused
// rather than resolved.
#[test]
fn an_embedded_newline_is_refused_rather_than_guessed_at() {
    for refused in [
        format!("{URL}\n{URL}"),
        format!("{URL}\n{URL}\n"),
        format!("\n{URL}"),
    ] {
        assert!(parse(&refused).is_err(), "accepted {refused:?}");
    }
}

#[test]
fn something_that_is_not_a_connection_url_is_refused() {
    for refused in ["", "\n", "not-a-url", "https://config.example.test/"] {
        assert!(parse(refused).is_err(), "accepted {refused:?}");
    }
}

// Whatever went wrong, the message must not carry the credential the URL holds
// — these errors reach logs and CI output.
#[test]
fn a_refusal_never_echoes_the_input() {
    let credential = "app-password-sentinel";
    let secret_bearing = format!(
        "https://config.example.test/team#v=1&issuer=nonsense&client_secret={credential}\nsecond"
    );
    let error = parse(&secret_bearing).unwrap_err().to_string();
    assert!(!error.contains(credential), "secret appeared in: {error}");
    assert!(
        !error.contains("config.example.test"),
        "input appeared in: {error}"
    );
}
