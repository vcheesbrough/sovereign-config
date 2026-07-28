//! The Woodpecker external-secrets wire format.
//!
//! Field names are taken from Woodpecker's own models — `server/model/repo.go`
//! and `server/model/pipeline.go` — and only the subset the broker actually
//! reads is declared. Serde ignores unknown fields by default, so a Woodpecker
//! upgrade that adds metadata does not break the broker.
//!
//! The request Woodpecker sends also carries a `netrc` object holding forge
//! credentials. This module deliberately **does not** declare it: what is never
//! deserialized can never be logged, echoed, or leaked through a `Debug`
//! formatter.

use serde::{Deserialize, Serialize};
use sovereign_config_core::RevealedSecret;

/// The events a brokered secret is exposed to.
///
/// Deliberately **excludes** `pull_request` and `pull_request_closed`. A PR
/// author controls `.woodpecker/*.yml` on their own branch, so any secret
/// offered to a PR event can be exfiltrated by a step that echoes it
/// transformed (base64, a `curl` to an external host) — Woodpecker's log
/// masking only matches the verbatim string. This is not a broker-specific
/// caution: it is Woodpecker's own default. `cli/repo/secret/secret_add.go`'s
/// `defaultSecretEvents` (v3.13.0) is exactly `push, tag, release, deployment`
/// when a secret is created without an explicit `--event` list — i.e. every
/// event that isn't PR-triggered. `cron` and `manual` are added back here
/// because, unlike a PR, neither runs attacker-supplied pipeline YAML: `cron`
/// runs the config from the repository's default branch, and `manual` requires
/// an already-authorized trigger.
///
/// Woodpecker also defines `pull_request_metadata`; it is omitted for the same
/// reason as the other PR events, not merely for parity with the `OpenBao`
/// broker. Revisit deliberately, not by accident.
pub(crate) const ALL_EVENTS: [&str; 6] = ["push", "tag", "release", "deployment", "cron", "manual"];

/// The signed request body.
///
/// `repo` and `pipeline` are mandatory; Woodpecker always sends both, and a
/// body missing either is rejected rather than resolved against a partial
/// identity.
#[derive(Debug, Deserialize)]
pub(crate) struct SecretsRequest {
    pub(crate) repo: Repo,
    pub(crate) pipeline: Pipeline,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Repo {
    #[serde(default)]
    pub(crate) owner: String,
    #[serde(default)]
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) full_name: String,
    /// `omitempty` on the wire, so genuinely optional.
    #[serde(default)]
    pub(crate) forge_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Pipeline {
    #[serde(default)]
    pub(crate) branch: String,
    #[serde(default)]
    pub(crate) event: String,
}

/// Deliberately not `Debug`: it transitively holds revealed values, and a
/// `Debug` impl is exactly how such a value ends up in a log line.
#[derive(Serialize)]
pub(crate) struct SecretsResponse {
    pub(crate) secrets: Vec<ResponseSecret>,
}

/// One secret as Woodpecker's `model.Secret` decodes it.
///
/// This is the only type in the crate that carries a configuration value as a
/// plain `String`. It exists solely to be serialized into a 200 response, is
/// never logged, and deliberately does not derive `Debug`.
#[derive(Serialize)]
pub(crate) struct ResponseSecret {
    pub(crate) name: String,
    pub(crate) value: String,
    pub(crate) events: [&'static str; ALL_EVENTS.len()],
    /// Always empty: the broker applies no image allowlist.
    pub(crate) images: Vec<String>,
}

impl SecretsResponse {
    /// Builds the response from resolved values, sorted by name.
    ///
    /// This is the single point where a revealed value crosses from the
    /// redacted [`RevealedSecret`] wrapper into plain text. Every other path
    /// through the broker keeps values wrapped.
    pub(crate) fn build(values: impl IntoIterator<Item = (String, RevealedSecret)>) -> Self {
        let mut secrets: Vec<ResponseSecret> = values
            .into_iter()
            .map(|(name, value)| ResponseSecret {
                name,
                // The one deliberate exposure in this crate.
                value: value.expose().to_owned(),
                events: ALL_EVENTS,
                images: Vec::new(),
            })
            .collect();
        secrets.sort_by(|left, right| left.name.cmp(&right.name));
        Self { secrets }
    }
}

#[cfg(test)]
mod tests {
    use sovereign_config_core::RevealedSecret;

    use super::{ALL_EVENTS, SecretsRequest, SecretsResponse};

    #[test]
    fn a_request_deserializes_the_fields_the_broker_reads() {
        let request: SecretsRequest = serde_json::from_str(
            r#"{
                "repo": {
                    "owner": "vcheesbrough",
                    "name": "sovereign-config",
                    "full_name": "vcheesbrough/sovereign-config",
                    "forge_id": 3,
                    "private": true
                },
                "pipeline": {"branch": "main", "event": "push", "number": 42},
                "netrc": {"machine": "forge", "login": "user", "password": "netrc-sentinel"}
            }"#,
        )
        .unwrap();

        assert_eq!(request.repo.full_name, "vcheesbrough/sovereign-config");
        assert_eq!(request.repo.forge_id, Some(3));
        assert_eq!(request.pipeline.event, "push");
        // netrc is not a field of the DTO, so its credential never enters the
        // process as typed data — and cannot appear in a Debug rendering.
        assert!(!format!("{request:?}").contains("netrc-sentinel"));
    }

    #[test]
    fn an_absent_forge_id_is_none_rather_than_a_default_row() {
        let request: SecretsRequest = serde_json::from_str(
            r#"{"repo": {"owner": "o", "name": "r", "full_name": "o/r"},
                "pipeline": {"branch": "main", "event": "push"}}"#,
        )
        .unwrap();
        assert_eq!(request.repo.forge_id, None);
    }

    #[test]
    fn a_body_missing_repo_or_pipeline_is_rejected() {
        for body in [
            r#"{"pipeline": {"branch": "main", "event": "push"}}"#,
            r#"{"repo": {"owner": "o", "name": "r", "full_name": "o/r"}}"#,
            r#"{"repo": null, "pipeline": {"branch": "main", "event": "push"}}"#,
        ] {
            assert!(serde_json::from_str::<SecretsRequest>(body).is_err());
        }
    }

    #[test]
    fn the_response_is_sorted_and_carries_every_event() {
        let response = SecretsResponse::build([
            ("zot_ci_user".to_owned(), RevealedSecret::new("zot")),
            ("github_token".to_owned(), RevealedSecret::new("gh")),
        ]);
        let json = serde_json::to_value(&response).unwrap();
        let secrets = json["secrets"].as_array().unwrap();

        assert_eq!(secrets[0]["name"], "github_token");
        assert_eq!(secrets[0]["value"], "gh");
        assert_eq!(secrets[1]["name"], "zot_ci_user");
        let events: Vec<&str> = secrets[0]["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        assert_eq!(events, ALL_EVENTS);
        for excluded in [
            "pull_request",
            "pull_request_closed",
            "pull_request_metadata",
        ] {
            assert!(
                !events.contains(&excluded),
                "{excluded} must not be offered a brokered secret"
            );
        }
        assert!(secrets[0]["images"].as_array().unwrap().is_empty());
    }

    #[test]
    fn an_empty_result_serializes_as_an_empty_list_not_null() {
        let json = serde_json::to_string(&SecretsResponse::build([])).unwrap();
        assert_eq!(json, r#"{"secrets":[]}"#);
    }
}
