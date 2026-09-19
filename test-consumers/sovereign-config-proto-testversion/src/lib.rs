//! A second protobuf package used **only** to test concurrent protocol serving.
//!
//! This crate is a `[dev-dependency]` of `sovereign-config-server` and is never
//! compiled into a released binary. It exists so the dual-registration
//! mechanism — two `sovereign.config.vN` packages on one tonic router — is
//! exercised before a real second version depends on it. See
//! `## Protocol versioning` in the repository `README.md`.

pub mod sovereign {
    pub mod config {
        pub mod vtest {
            tonic::include_proto!("sovereign.config.vtest");
        }
    }
}
