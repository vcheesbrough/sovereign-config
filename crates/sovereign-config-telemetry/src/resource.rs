//! The one `Resource` every provider is given (`observability` skill §1.2, §4).
//!
//! It is the deployment's attributes (`OTEL_SERVICE_NAME`,
//! `OTEL_RESOURCE_ATTRIBUTES`, as validated by [`crate::config`]) plus two facts
//! that are not the deployment's to state:
//!
//! - `service.version` is the build's, and overwrites whatever the variables
//!   say: an environment can be stale, a binary cannot.
//! - `service.instance.id` is the host's — a version 5 UUID of the hostname
//!   under the semantic conventions' namespace — unless the variables already
//!   carry one. Stable across restarts, unique per container, and it does not
//!   publish the hostname itself. With no usable hostname it is left out: the
//!   contract prefers absent to a per-start random value.
//!
//! No host or process detectors: they add values such as the pid that change
//! on every restart, the instance-id mistake in another form.

use std::collections::BTreeMap;

use opentelemetry::KeyValue;
use opentelemetry_sdk::{
    Resource,
    resource::{ResourceDetector, TelemetryResourceDetector},
};
use opentelemetry_semantic_conventions::resource::{SERVICE_INSTANCE_ID, SERVICE_VERSION};
use uuid::Uuid;

/// The estate's path marker: which route a record took to the store. A bare
/// key by the estate's recorded departure from semconv's reverse-domain advice
/// (`observability` skill §4).
pub const TELEMETRY_SOURCE: &str = "telemetry_source";

/// This process exports over OTLP, so that is its path, unless the
/// deployment says otherwise.
pub const TELEMETRY_SOURCE_OTLP: &str = "otlp";

/// The namespace the semantic conventions name for deriving a
/// `service.instance.id` from a stable source.
const INSTANCE_ID_NAMESPACE: Uuid = Uuid::from_u128(0x4d63_009a_8d0f_11ee_aad7_4c79_6ed8_e320);

/// A version 5 UUID of `hostname`, or `None` when there is no usable hostname.
#[must_use]
pub fn instance_id(hostname: Option<&str>) -> Option<String> {
    let hostname = hostname.map(str::trim).filter(|name| !name.is_empty())?;
    Some(Uuid::new_v5(&INSTANCE_ID_NAMESPACE, hostname.as_bytes()).to_string())
}

/// This machine's hostname — in a container, the container's.
#[must_use]
pub fn hostname() -> Option<String> {
    let uname = rustix::system::uname();
    uname
        .nodename()
        .to_str()
        .ok()
        .map(str::to_owned)
        .filter(|name| !name.trim().is_empty())
}

/// The resource, from the deployment's validated attributes, the build's
/// version and the host's name.
#[must_use]
pub fn build(deployment: &[(String, String)], version: &str, hostname: Option<&str>) -> Resource {
    let mut attributes: BTreeMap<String, String> = deployment.iter().cloned().collect();
    attributes
        .entry(TELEMETRY_SOURCE.to_owned())
        .or_insert_with(|| TELEMETRY_SOURCE_OTLP.to_owned());
    if !attributes.contains_key(SERVICE_INSTANCE_ID)
        && let Some(id) = instance_id(hostname)
    {
        attributes.insert(SERVICE_INSTANCE_ID.to_owned(), id);
    }
    attributes.insert(SERVICE_VERSION.to_owned(), version.to_owned());

    // `telemetry.sdk.*` only: constant for a given binary, so it cannot churn.
    let sdk = TelemetryResourceDetector.detect();
    Resource::builder_empty()
        .with_attributes(
            sdk.iter()
                .map(|(key, value)| KeyValue::new(key.clone(), value.clone()))
                .chain(
                    attributes
                        .into_iter()
                        .map(|(key, value)| KeyValue::new(key, value)),
                ),
        )
        .build()
}

#[cfg(test)]
mod tests {
    use opentelemetry::Key;
    use opentelemetry_semantic_conventions::resource::{DEPLOYMENT_ENVIRONMENT_NAME, SERVICE_NAME};

    use super::*;

    fn deployment(extra: &[(&str, &str)]) -> Vec<(String, String)> {
        [
            (SERVICE_NAME, "sovereign-config"),
            (DEPLOYMENT_ENVIRONMENT_NAME, "dev"),
        ]
        .iter()
        .chain(extra)
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
    }

    fn get(resource: &Resource, key: &'static str) -> Option<String> {
        resource
            .get(&Key::from_static_str(key))
            .map(|v| v.to_string())
    }

    #[test]
    fn the_build_version_cannot_be_overridden_by_the_environment() {
        let resource = build(
            &deployment(&[(SERVICE_VERSION, "0.0.1-stale")]),
            "2.35.0",
            Some("host"),
        );
        assert_eq!(get(&resource, SERVICE_VERSION).as_deref(), Some("2.35.0"));
    }

    #[test]
    fn instance_id_is_stable_for_a_hostname_and_distinct_between_hostnames() {
        let first = build(&deployment(&[]), "2.35.0", Some("sovereign-config-dev"));
        let second = build(&deployment(&[]), "2.35.0", Some("sovereign-config-dev"));
        let other = build(
            &deployment(&[]),
            "2.35.0",
            Some("sovereign-config-production"),
        );

        let id = get(&first, SERVICE_INSTANCE_ID).expect("a hostname yields an instance id");
        assert_eq!(
            get(&second, SERVICE_INSTANCE_ID).as_deref(),
            Some(id.as_str())
        );
        assert_ne!(
            get(&other, SERVICE_INSTANCE_ID).as_deref(),
            Some(id.as_str())
        );
        assert!(
            !id.contains("sovereign-config-dev"),
            "the hostname must not be published"
        );
        let parsed = Uuid::parse_str(&id).expect("a UUID");
        assert_eq!(parsed.get_version_num(), 5);
    }

    #[test]
    fn no_hostname_means_no_instance_id_rather_than_a_random_one() {
        for hostname in [None, Some(""), Some("   ")] {
            let resource = build(&deployment(&[]), "2.35.0", hostname);
            assert_eq!(get(&resource, SERVICE_INSTANCE_ID), None);
        }
    }

    #[test]
    fn an_instance_id_from_the_deployment_is_kept() {
        let resource = build(
            &deployment(&[(SERVICE_INSTANCE_ID, "replica-a")]),
            "2.35.0",
            Some("host"),
        );
        assert_eq!(
            get(&resource, SERVICE_INSTANCE_ID).as_deref(),
            Some("replica-a")
        );
    }

    #[test]
    fn telemetry_source_defaults_to_otlp_but_the_deployment_may_state_it() {
        let resource = build(&deployment(&[]), "2.35.0", None);
        assert_eq!(get(&resource, TELEMETRY_SOURCE).as_deref(), Some("otlp"));
        let resource = build(&deployment(&[(TELEMETRY_SOURCE, "client")]), "2.35.0", None);
        assert_eq!(get(&resource, TELEMETRY_SOURCE).as_deref(), Some("client"));
    }

    #[test]
    fn no_per_restart_attributes_are_detected() {
        let resource = build(&deployment(&[]), "2.35.0", Some("host"));
        for (key, _) in &resource {
            assert!(
                !key.as_str().starts_with("process.") && !key.as_str().starts_with("host."),
                "{key} changes between restarts or publishes the host"
            );
        }
    }

    #[test]
    fn the_instance_id_namespace_is_the_semantic_conventions_one() {
        assert_eq!(
            INSTANCE_ID_NAMESPACE.to_string(),
            "4d63009a-8d0f-11ee-aad7-4c796ed8e320"
        );
    }
}
