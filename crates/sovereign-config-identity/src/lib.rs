//! The identity-provider contract a managed connection is provisioned
//! through.
//!
//! A managed connection is a service account in an identity provider, holding
//! one credential and one grant. [`ManagedIdentityProvider`] is every
//! operation the server needs on it, phrased in what the server means rather
//! than in any provider's API; an implementation owns how each is done. The
//! contract each operation and each [`ProviderError`] class carries is
//! documented here and enforced by the `conformance` feature's suite, which
//! every implementation runs.
//!
//! Server-side only, and free of any transport: an implementation brings its
//! own.

#![forbid(unsafe_code)]

use core::fmt;

use async_trait::async_trait;
pub use sovereign_config_core::Secret;

#[cfg(feature = "conformance")]
pub mod conformance;
#[cfg(feature = "conformance")]
pub mod fake;

/// The longest identifier a provider may hand back, in bytes: what the server
/// stores (`managed_connections.provider_user_id` and its neighbours) bounds
/// them at 128 characters.
pub const MAX_IDENTIFIER_CHARS: usize = 128;

/// Bounded classification of a failed provider call.
///
/// It is the whole of what a failure reports: an implementation discards any
/// response text, so nothing the provider said can reach a log, a span or a
/// caller. Callers decide what to do — compensate, reconcile, retry later —
/// from these meanings alone, so an implementation must classify exactly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderError {
    /// The exact target (account or credential) does not exist.
    NotFound,
    /// The provider definitively refused the request without applying it.
    Rejected,
    /// The request could not be delivered, so it was definitively not applied.
    Unavailable,
    /// The outcome is unknown: the provider may have applied the request.
    Ambiguous,
    /// The response broke the implementation's strict decoding or policy.
    /// The request may have been applied: treat it as [`Self::Ambiguous`].
    Invalid,
}

impl ProviderError {
    /// Every class, for exhaustive tests.
    pub const ALL: [Self; 5] = [
        Self::NotFound,
        Self::Rejected,
        Self::Unavailable,
        Self::Ambiguous,
        Self::Invalid,
    ];

    /// The classification as a span's `error.type` and a log field.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::Rejected => "rejected",
            Self::Unavailable => "unavailable",
            Self::Ambiguous => "ambiguous",
            Self::Invalid => "invalid",
        }
    }

    /// Whether the request is known not to have been applied.
    #[must_use]
    pub const fn definitely_not_applied(self) -> bool {
        matches!(self, Self::Rejected | Self::Unavailable)
    }
}

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

impl std::error::Error for ProviderError {}

/// An identifier the provider handed back was empty, too long or not text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidIdentifier;

impl fmt::Display for InvalidIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("identity provider identifier is not permitted")
    }
}

impl std::error::Error for InvalidIdentifier {}

fn bounded(value: String) -> Result<String, InvalidIdentifier> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_CHARS || value.chars().any(char::is_control)
    {
        return Err(InvalidIdentifier);
    }
    Ok(value)
}

macro_rules! opaque_identifier {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        ///
        /// Opaque to the server: only the implementation that issued it may
        /// interpret it. Non-empty, at most [`MAX_IDENTIFIER_CHARS`] bytes and
        /// free of control characters. Its `Debug` output is redacted, since a
        /// provider's identifiers are treated as sensitive.
        #[derive(Clone, Eq, Hash, PartialEq)]
        pub struct $name(String);

        impl $name {
            /// # Errors
            ///
            /// The value is empty, longer than [`MAX_IDENTIFIER_CHARS`] or
            /// holds a control character.
            pub fn parse(value: impl Into<String>) -> Result<Self, InvalidIdentifier> {
                bounded(value.into()).map(Self)
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

opaque_identifier!(
    /// The provider's identifier for one service account.
    AccountId
);
opaque_identifier!(
    /// The provider's identifier for one credential, never the credential
    /// itself.
    CredentialId
);

/// What a client presents at the provider's token endpoint to act as an
/// account: the `client_credentials` grant's `client_id`, and the secret the
/// connection URL carries for it.
///
/// The client id is the provider's to choose. One that authenticates app
/// passwords through a shared client (Authentik) returns that client's id for
/// every account; one that makes each account its own OAuth client
/// (Keycloak) returns that client's id. The server puts it in the connection
/// URL as given, so deployed clients need no change either way.
pub struct ClientCredential {
    /// Non-empty, and only ASCII letters, digits, `-`, `.`, `_` and `~`: what
    /// a connection URL admits.
    pub client_id: String,
    pub secret: Secret,
}

/// Redacts the secret by construction; the client id is not sensitive.
impl fmt::Debug for ClientCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientCredential")
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

/// The service account [`ManagedIdentityProvider::create_account`] created.
pub struct ProvisionedAccount {
    pub account: AccountId,
    /// The subject the account's access tokens carry (`sub`): what the audit
    /// trail records its access under. Bounded like an identifier.
    pub subject: String,
    /// The account's one credential, returned only here and only once.
    pub credential: ClientCredential,
}

/// Redacts every identifier and the credential by construction, so a failed
/// assertion or diagnostic can never print them.
impl fmt::Debug for ProvisionedAccount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionedAccount")
            .finish_non_exhaustive()
    }
}

/// What a managed connection's account is allowed, and what it is called.
#[derive(Clone, Copy, Debug)]
pub struct AccountGrant<'a> {
    /// The connection the account belongs to, which the provider records on
    /// it so an operator can tell a managed account from any other.
    pub connection_id: &'a str,
    /// The connection's display name, which the account is named after: its
    /// tokens carry it, and so does the audit trail.
    pub display_name: &'a str,
    /// The configuration path the grant is scoped to.
    pub root: &'a str,
    /// The grant tokens (`read`, `write`, `manage`) on `root`.
    pub permissions: &'a [&'a str],
}

/// Every operation managed connections need from an identity provider.
///
/// # Contract
///
/// Every implementation, whatever its transport:
///
/// - **classifies every failure** as one [`ProviderError`], exactly as that
///   type documents, and never reports provider response text;
/// - **never retries on its own**: one call is at most one attempt, so a
///   caller's reconciliation reasons about exactly one request;
/// - **bounds every call** in time and in the size of what it reads back;
/// - **acts on the exact target only**: a username, account or credential
///   is matched exactly, never by prefix or pattern, and an operation never
///   touches an account it was not given;
/// - **treats identifiers and credentials as sensitive**: none reaches a log,
///   a span or an error.
///
/// The conformance suite (feature `conformance`) checks what of this a caller
/// can observe.
#[async_trait]
pub trait ManagedIdentityProvider: Send + Sync {
    /// Creates a non-expiring service account called `username`, holding one
    /// credential, and returns it with that credential.
    ///
    /// The account has no grant until [`Self::grant`]. If this fails as
    /// [`ProviderError::Ambiguous`] or [`ProviderError::Invalid`] the account
    /// may exist anyway, and only [`Self::find_account`] can tell.
    async fn create_account(&self, username: &str) -> Result<ProvisionedAccount, ProviderError>;

    /// Grants the account `grant.permissions` on `grant.root`, replacing any
    /// grant it held, records its connection, and names it after the
    /// connection. The implementation owns how a grant is represented, as
    /// long as the account's access tokens carry it. Idempotent.
    async fn grant(
        &self,
        account: &AccountId,
        grant: &AccountGrant<'_>,
    ) -> Result<(), ProviderError>;

    /// Adds the account to the group operators browse managed accounts by.
    /// Best-effort, and it never grants anything; [`ProviderError::NotFound`]
    /// when the group does not exist. Idempotent.
    async fn assign_browse_group(&self, account: &AccountId) -> Result<(), ProviderError>;

    /// Names an existing account after its connection, as [`Self::grant`]
    /// does, changing nothing else: its credential and grant are untouched.
    /// Idempotent.
    async fn rename_account(
        &self,
        account: &AccountId,
        display_name: &str,
    ) -> Result<(), ProviderError>;

    /// The account called exactly `username`, if there is one.
    ///
    /// A provider may refuse the lookup outright for an account the caller
    /// can no longer see; absence is only proven by
    /// [`Self::find_credentials`].
    async fn find_account(&self, username: &str) -> Result<Option<AccountId>, ProviderError>;

    /// The credentials of the account called exactly `username`, never their
    /// values.
    ///
    /// **An empty result is authoritative proof that no usable credential for
    /// that username survives** — revocation settles on it, so an
    /// implementation that cannot prove that must fail instead.
    async fn find_credentials(&self, username: &str) -> Result<Vec<CredentialId>, ProviderError>;

    /// Replaces the credential's value with a fresh one the implementation
    /// generates, and returns it with the client id it authenticates as —
    /// the same one [`Self::create_account`] returned. The previous value
    /// stops working: a provider that keeps a rotated secret valid for a
    /// grace period must not.
    async fn replace_credential(
        &self,
        credential: &CredentialId,
    ) -> Result<ClientCredential, ProviderError>;

    /// Deletes the account, and with it every credential it holds.
    /// [`ProviderError::NotFound`] when it no longer exists.
    ///
    /// The one operation whose failure class does not settle the outcome: a
    /// provider that checks permission on the object it acts on can apply the
    /// delete and then refuse it, or answer "not found" for an account it
    /// merely hides. After a failure on an account that may have been out of
    /// the caller's sight — one it recorded earlier, as revocation deletes —
    /// a caller confirms absence through [`Self::find_credentials`], never
    /// from the class.
    ///
    /// The exception is deleting an account the caller created moments ago in
    /// the same flow, to undo a failed provisioning: nothing can have hidden
    /// it in between, so [`ProviderError::NotFound`] is trusted there as
    /// proof it is gone.
    async fn delete_account(&self, account: &AccountId) -> Result<(), ProviderError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_bounded_non_empty_text() {
        assert!(AccountId::parse("1000").is_ok());
        assert!(AccountId::parse("x".repeat(MAX_IDENTIFIER_CHARS)).is_ok());
        assert_eq!(AccountId::parse(""), Err(InvalidIdentifier));
        assert_eq!(
            AccountId::parse("x".repeat(MAX_IDENTIFIER_CHARS + 1)),
            Err(InvalidIdentifier)
        );
        assert_eq!(CredentialId::parse("a\nb"), Err(InvalidIdentifier));
    }

    #[test]
    fn nothing_identifying_is_printed() {
        let account = AccountId::parse("account-sentinel").unwrap();
        let credential = CredentialId::parse("credential-sentinel").unwrap();
        let provisioned = ProvisionedAccount {
            account: account.clone(),
            subject: "subject-sentinel".to_owned(),
            credential: ClientCredential {
                client_id: "sovereign-config".to_owned(),
                secret: Secret::new("secret-sentinel"),
            },
        };
        let printed = format!("{account:?} {credential:?} {provisioned:?}");
        assert!(!printed.contains("sentinel"), "{printed}");
    }

    #[test]
    fn only_rejected_and_unavailable_are_definitely_not_applied() {
        let not_applied: Vec<_> = ProviderError::ALL
            .into_iter()
            .filter(|error| error.definitely_not_applied())
            .collect();
        assert_eq!(
            not_applied,
            [ProviderError::Rejected, ProviderError::Unavailable]
        );
    }
}
