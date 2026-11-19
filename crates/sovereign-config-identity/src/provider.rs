//! Everything the server takes from the identity provider it was started
//! with, built once at startup by the provider's own crate.

use std::{sync::Arc, time::Duration};

use crate::{ManagedIdentityProvider, VerificationRules};

/// What clients need in order to sign in. They run standard OIDC against the
/// provider themselves; the server only hands this out.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoginDescription {
    /// The issuer handed to clients: in every connection URL, and to the web
    /// UI. Clients find discovery at `<issuer>.well-known/openid-configuration`,
    /// so it ends with `/`. It need not be spelled as tokens spell `iss`
    /// ([`VerificationRules::issuer`]).
    pub issuer: String,
    /// The OAuth client the web UI signs in through.
    pub web_client_id: String,
}

/// One identity provider, as the server uses it.
pub struct IdentityProvider {
    /// The name the provider is selected by. One of a compiled-in set, so it
    /// is safe as a log field and as what the database records the
    /// deployment's provider as.
    pub name: &'static str,
    /// Managed connections' service accounts.
    pub accounts: Arc<dyn ManagedIdentityProvider>,
    /// How its access tokens are verified and read.
    pub verification: VerificationRules,
    pub login: LoginDescription,
    /// The longest one call to [`Self::accounts`] may take, which bounds how
    /// long an unfinished rotation can still be in flight.
    pub call_timeout: Duration,
}
