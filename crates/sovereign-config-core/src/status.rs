//! Service and authentication status reported to clients.

use crate::PROTOCOL_VERSION;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceStatus {
    pub application_version: String,
    pub protocol_version: String,
    pub compatible: bool,
}

impl ServiceStatus {
    #[must_use]
    pub fn negotiate(application_version: String, protocol_version: String) -> Self {
        let compatible = protocol_version == PROTOCOL_VERSION;
        Self {
            application_version,
            protocol_version,
            compatible,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticationStatus {
    pub authenticated: bool,
}
