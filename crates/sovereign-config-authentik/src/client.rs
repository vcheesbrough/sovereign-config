//! The Authentik administration client: one method per REST call the
//! provider makes, in Authentik's own terms.
//!
//! Every request uses the dedicated connection-manager API token over the
//! exact configured origin with redirects disabled, a short total timeout,
//! bounded response bodies, strict JSON decoding, and no automatic retries.
//! All Authentik identifiers, request bodies, and responses are treated as
//! sensitive: errors carry only a bounded classification and never any
//! Authentik response text.

use std::{net::IpAddr, time::Duration};

use reqwest::{Client, Method, StatusCode, Url, redirect::Policy};
use serde::Deserialize;
use serde_json::{Value, json};
use sovereign_config_core::Secret;
use tracing::Instrument;

use sovereign_config_identity::ProviderError;
use sovereign_config_telemetry::client::{client_span, record_error, send};

const MAX_ADMIN_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_EXTERNAL_IDENTIFIER_CHARS: usize = 128;

/// Route templates, as client spans name them: identifiers stay placeholders.
const SERVICE_ACCOUNT_ROUTE: &str = "/api/v3/core/users/service_account/";
const USER_ROUTE: &str = "/api/v3/core/users/{id}/";
const USERS_ROUTE: &str = "/api/v3/core/users/";
const GROUPS_ROUTE: &str = "/api/v3/core/groups/";
const TOKENS_ROUTE: &str = "/api/v3/core/tokens/";
const SET_KEY_ROUTE: &str = "/api/v3/core/tokens/{identifier}/set_key/";

/// The service account created for one managed connection.
pub(crate) struct CreatedServiceAccount {
    pub(crate) user_id: i64,
    pub(crate) user_uid: String,
    pub(crate) app_password: Secret,
}

/// Redacts every Authentik identifier and the app password by construction,
/// so a failed assertion or diagnostic can never print them.
impl core::fmt::Debug for CreatedServiceAccount {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CreatedServiceAccount")
            .finish_non_exhaustive()
    }
}

/// An existing Authentik user located by exact generated username.
pub(crate) struct FoundUser {
    pub(crate) user_id: i64,
}

pub(crate) struct AuthentikAdminClient {
    http: Client,
    api_origin: Url,
    api_token: Secret,
}

impl AuthentikAdminClient {
    /// Builds the administration client for the exact configured origin.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when the origin is not HTTPS (numeric loopback
    /// HTTP remains test-only) or the HTTP client cannot be constructed.
    pub(crate) fn new(
        api_origin: Url,
        api_token: Secret,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        let loopback_http = api_origin.scheme() == "http"
            && api_origin
                .host_str()
                .and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok())
                .is_some_and(|address| address.is_loopback());
        if !(api_origin.scheme() == "https" || loopback_http)
            || api_origin.host_str().is_none()
            || !api_origin.username().is_empty()
            || api_origin.password().is_some()
            || api_origin.path() != "/"
            || api_origin.query().is_some()
            || api_origin.fragment().is_some()
        {
            anyhow::bail!("managed connection API origin is not permitted");
        }
        let http = Client::builder()
            .redirect(Policy::none())
            .timeout(timeout)
            .build()
            .map_err(|_| anyhow::anyhow!("unable to build managed connection API client"))?;
        Ok(Self {
            http,
            api_origin,
            api_token,
        })
    }

    /// Creates one non-expiring service account and returns its app password.
    pub(crate) async fn create_service_account(
        &self,
        username: &str,
    ) -> Result<CreatedServiceAccount, ProviderError> {
        #[derive(Deserialize)]
        struct ServiceAccountResponse {
            username: String,
            user_uid: String,
            user_pk: i64,
            token: String,
        }

        let body = self
            .call(
                Method::POST,
                SERVICE_ACCOUNT_ROUTE,
                self.endpoint(SERVICE_ACCOUNT_ROUTE)?,
                Some(json!({
                    "name": username,
                    "create_group": false,
                    "expiring": false,
                })),
            )
            .await?;
        let decoded: ServiceAccountResponse =
            serde_json::from_slice(&body).map_err(|_| ProviderError::Invalid)?;
        if decoded.username != username
            || decoded.token.is_empty()
            || decoded.token.bytes().any(|byte| byte.is_ascii_control())
            || decoded.token.contains(':')
            || decoded.user_uid.is_empty()
            || decoded.user_uid.len() > MAX_EXTERNAL_IDENTIFIER_CHARS
        {
            return Err(ProviderError::Invalid);
        }
        Ok(CreatedServiceAccount {
            user_id: decoded.user_pk,
            user_uid: decoded.user_uid,
            app_password: Secret::new(decoded.token),
        })
    }

    /// Replaces the managed service account's attributes with the exact
    /// managed marker, grants, and preserved service-account markers, and
    /// names the account after its connection. The blueprint's grant scope
    /// mapping signs that name into the account's tokens as
    /// `preferred_username`, which is what the audit trail shows for it.
    pub(crate) async fn set_managed_attributes(
        &self,
        user_id: i64,
        connection_id: &str,
        display_name: &str,
        grants_attribute: &str,
        root: &str,
        permissions: &[&str],
    ) -> Result<(), ProviderError> {
        let mut attributes = serde_json::Map::new();
        attributes.insert(
            "goauthentik.io/user/service-account".to_owned(),
            json!(true),
        );
        attributes.insert("goauthentik.io/user/token-expires".to_owned(), json!(false));
        attributes.insert("sovereign_config_managed".to_owned(), json!(connection_id));
        attributes.insert(
            grants_attribute.to_owned(),
            json!([{ "prefix": root, "permissions": permissions }]),
        );
        self.call(
            Method::PATCH,
            USER_ROUTE,
            self.endpoint(&format!("/api/v3/core/users/{user_id}/"))?,
            Some(json!({ "name": display_name, "attributes": attributes })),
        )
        .await
        .map(|_| ())
    }

    /// Locates a group by exact name, purely to group managed service
    /// accounts together for browsing in Authentik. Never authorizes
    /// anything: authorization is granted directly on the service account.
    pub(crate) async fn find_group_by_name(
        &self,
        name: &str,
    ) -> Result<Option<String>, ProviderError> {
        #[derive(Deserialize)]
        struct GroupRecord {
            pk: String,
            name: String,
        }
        #[derive(Deserialize)]
        struct GroupListResponse {
            results: Vec<GroupRecord>,
        }

        let mut endpoint = self.endpoint(GROUPS_ROUTE)?;
        endpoint.query_pairs_mut().append_pair("name", name);
        let body = self.call(Method::GET, GROUPS_ROUTE, endpoint, None).await?;
        let decoded: GroupListResponse =
            serde_json::from_slice(&body).map_err(|_| ProviderError::Invalid)?;
        let mut matching = decoded.results.into_iter().filter(|record| {
            record.name == name
                && !record.pk.is_empty()
                && record.pk.len() <= MAX_EXTERNAL_IDENTIFIER_CHARS
        });
        let found = matching.next().map(|record| record.pk);
        if matching.next().is_some() {
            return Err(ProviderError::Invalid);
        }
        Ok(found)
    }

    /// Adds the exact managed service account to one group, replacing any
    /// existing membership. Safe because the account is freshly created with
    /// no prior group membership. Best-effort: failure here must never block
    /// or roll back connection creation.
    pub(crate) async fn add_user_to_group(
        &self,
        user_id: i64,
        group_id: &str,
    ) -> Result<(), ProviderError> {
        self.call(
            Method::PATCH,
            USER_ROUTE,
            self.endpoint(&format!("/api/v3/core/users/{user_id}/"))?,
            Some(json!({ "groups": [group_id] })),
        )
        .await
        .map(|_| ())
    }

    /// Names an existing managed service account after its connection, as
    /// [`Self::set_managed_attributes`] does for a new one. Only the name is
    /// patched, so the account's credential and grants are untouched.
    pub(crate) async fn rename_user(&self, user_id: i64, name: &str) -> Result<(), ProviderError> {
        self.call(
            Method::PATCH,
            USER_ROUTE,
            self.endpoint(&format!("/api/v3/core/users/{user_id}/"))?,
            Some(json!({ "name": name })),
        )
        .await
        .map(|_| ())
    }

    /// Locates a user by exact generated username for reconciliation only.
    ///
    /// Only usable while the manager can still see at least one managed
    /// account; Authentik refuses user reads outright otherwise. Absence must
    /// therefore be confirmed through the app password rather than the user.
    pub(crate) async fn find_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<FoundUser>, ProviderError> {
        #[derive(Deserialize)]
        struct UserRecord {
            pk: i64,
            username: String,
        }
        #[derive(Deserialize)]
        struct UserListResponse {
            results: Vec<UserRecord>,
        }

        let mut endpoint = self.endpoint(USERS_ROUTE)?;
        endpoint.query_pairs_mut().append_pair("username", username);
        let body = self.call(Method::GET, USERS_ROUTE, endpoint, None).await?;
        let decoded: UserListResponse =
            serde_json::from_slice(&body).map_err(|_| ProviderError::Invalid)?;
        let mut matching = decoded
            .results
            .into_iter()
            .filter(|record| record.username == username);
        let found = matching
            .next()
            .map(|record| FoundUser { user_id: record.pk });
        if matching.next().is_some() {
            return Err(ProviderError::Invalid);
        }
        Ok(found)
    }

    /// Discovers the single app-password token identifier for a username
    /// without viewing its key.
    pub(crate) async fn find_app_password_identifiers(
        &self,
        username: &str,
    ) -> Result<Vec<String>, ProviderError> {
        #[derive(Deserialize)]
        struct TokenRecord {
            identifier: String,
        }
        #[derive(Deserialize)]
        struct TokenListResponse {
            results: Vec<TokenRecord>,
        }

        let mut endpoint = self.endpoint(TOKENS_ROUTE)?;
        endpoint
            .query_pairs_mut()
            .append_pair("user__username", username)
            .append_pair("intent", "app_password");
        let body = self.call(Method::GET, TOKENS_ROUTE, endpoint, None).await?;
        let decoded: TokenListResponse =
            serde_json::from_slice(&body).map_err(|_| ProviderError::Invalid)?;
        let identifiers = decoded
            .results
            .into_iter()
            .map(|record| record.identifier)
            .collect::<Vec<_>>();
        if identifiers.iter().any(|identifier| {
            identifier.is_empty()
                || identifier.len() > MAX_EXTERNAL_IDENTIFIER_CHARS
                || !identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        }) {
            return Err(ProviderError::Invalid);
        }
        Ok(identifiers)
    }

    /// Replaces the key of the exact app-password token.
    pub(crate) async fn set_credential_secret(
        &self,
        identifier: &str,
        replacement: &Secret,
    ) -> Result<(), ProviderError> {
        self.call(
            Method::POST,
            SET_KEY_ROUTE,
            self.endpoint(&format!("/api/v3/core/tokens/{identifier}/set_key/"))?,
            Some(json!({ "key": replacement.expose() })),
        )
        .await
        .map(|_| ())
    }

    /// Deletes the exact managed service account.
    pub(crate) async fn delete_user(&self, user_id: i64) -> Result<(), ProviderError> {
        self.call(
            Method::DELETE,
            USER_ROUTE,
            self.endpoint(&format!("/api/v3/core/users/{user_id}/"))?,
            None,
        )
        .await
        .map(|_| ())
    }

    /// One administration call, inside its client span: the request carries
    /// the span's `traceparent`, and the span records the response status and,
    /// on failure, the bounded classification — never a body, a token or the
    /// URL actually called.
    async fn call(
        &self,
        method: Method,
        route: &'static str,
        url: Url,
        body: Option<Value>,
    ) -> Result<Vec<u8>, ProviderError> {
        let span = client_span(&method, Some(route), &self.api_origin);
        async {
            let mut request = self
                .http
                .request(method, url)
                .bearer_auth(self.api_token.expose());
            if let Some(body) = body {
                request = request.json(&body);
            }
            let result = match send(&self.http, request).await {
                Ok(response) => expect_success(response).await,
                Err(error) => Err(classify_transport(&error)),
            };
            if let Err(error) = &result {
                record_error(error.label());
            }
            result
        }
        .instrument(span)
        .await
    }

    fn endpoint(&self, path: &str) -> Result<Url, ProviderError> {
        self.api_origin
            .join(path)
            .map_err(|_| ProviderError::Invalid)
    }
}

fn classify_transport(error: &reqwest::Error) -> ProviderError {
    if error.is_timeout() {
        ProviderError::Ambiguous
    } else if error.is_connect() || error.is_builder() || error.is_request() {
        ProviderError::Unavailable
    } else if error.is_redirect() {
        ProviderError::Invalid
    } else {
        ProviderError::Ambiguous
    }
}

fn classify_status(status: StatusCode) -> ProviderError {
    if status == StatusCode::NOT_FOUND {
        ProviderError::NotFound
    } else if status.is_client_error() {
        ProviderError::Rejected
    } else if status.is_redirection() {
        ProviderError::Invalid
    } else {
        ProviderError::Ambiguous
    }
}

/// Reads a bounded successful response body, discarding any failure text.
async fn expect_success(response: reqwest::Response) -> Result<Vec<u8>, ProviderError> {
    let status = response.status();
    if !status.is_success() {
        return Err(classify_status(status));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_ADMIN_RESPONSE_BYTES as u64)
    {
        return Err(ProviderError::Invalid);
    }
    let mut body = Vec::new();
    let mut stream = response;
    while let Some(chunk) = stream.chunk().await.map_err(|error| {
        if error.is_timeout() {
            ProviderError::Ambiguous
        } else {
            ProviderError::Invalid
        }
    })? {
        if body.len() + chunk.len() > MAX_ADMIN_RESPONSE_BYTES {
            return Err(ProviderError::Invalid);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests;

/// End-to-end checks against a real Authentik instance.
///
/// These run only when `SOVEREIGN_CONFIG_LIVE_AUTHENTIK_URL` and
/// `SOVEREIGN_CONFIG_LIVE_AUTHENTIK_TOKEN` are set, which CI does after the
/// environment's blueprint has been applied. They exercise the connection
/// manager's real permission model — the layer a mock cannot reproduce, and
/// where a missing global `view_token` previously made every created app
/// password undiscoverable in production.
#[cfg(test)]
mod live_tests;
