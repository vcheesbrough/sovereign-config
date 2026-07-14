use std::time::Duration;

use reqwest::{Client, Response, Url};
use serde::Deserialize;
use sovereign_config_core::{ClientError, ErrorKind, Secret};
use tokio::time::{Instant, sleep};

const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const SCOPE: &str = "openid sovereign-config offline_access";

#[derive(Clone)]
pub struct DeviceFlowClient {
    http: Client,
    client_id: String,
    device_endpoint: Url,
    token_endpoint: Url,
}

pub struct DeviceAuthorization {
    device_code: Secret,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    interval: Duration,
    expires_at: Instant,
}

pub struct TokenSet {
    pub access_token: Secret,
    pub refresh_token: Option<Secret>,
}

#[derive(Deserialize)]
struct Discovery {
    device_authorization_endpoint: String,
    token_endpoint: String,
}

#[derive(Deserialize)]
struct DeviceResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    expires_in: u64,
    interval: Option<u64>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
}

#[derive(Deserialize)]
struct OAuthError {
    error: String,
}

impl DeviceFlowClient {
    /// Discovers same-origin device and token endpoints for an issuer.
    ///
    /// # Errors
    ///
    /// Returns a bounded configuration or availability error.
    pub async fn discover(issuer: &str, client_id: String) -> Result<Self, ClientError> {
        let issuer = Url::parse(issuer).map_err(|_| invalid())?;
        if issuer.scheme() != "https" && issuer.host_str() != Some("127.0.0.1") {
            return Err(invalid());
        }
        let discovery_url = issuer
            .join(".well-known/openid-configuration")
            .map_err(|_| invalid())?;
        let http = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| unavailable())?;
        let discovery: Discovery = decode(require_success(
            http.get(discovery_url)
                .send()
                .await
                .map_err(|_| unavailable())?,
        )?)
        .await?;
        let device_endpoint =
            Url::parse(&discovery.device_authorization_endpoint).map_err(|_| invalid())?;
        let token_endpoint = Url::parse(&discovery.token_endpoint).map_err(|_| invalid())?;
        let issuer_origin = issuer.origin().ascii_serialization();
        for endpoint in [&device_endpoint, &token_endpoint] {
            if endpoint.origin().ascii_serialization() != issuer_origin {
                return Err(invalid());
            }
        }
        Ok(Self {
            http,
            client_id,
            device_endpoint,
            token_endpoint,
        })
    }

    /// Starts a device authorization request.
    ///
    /// # Errors
    ///
    /// Returns an availability error for rejected or malformed provider responses.
    pub async fn begin(&self) -> Result<DeviceAuthorization, ClientError> {
        let response = self
            .http
            .post(self.device_endpoint.clone())
            .form(&[("client_id", self.client_id.as_str()), ("scope", SCOPE)])
            .send()
            .await
            .map_err(|_| unavailable())?;
        let response: DeviceResponse = decode(require_success(response)?).await?;
        if response.device_code.is_empty()
            || response.user_code.is_empty()
            || response.verification_uri.is_empty()
            || response.expires_in == 0
        {
            return Err(unavailable());
        }
        Ok(DeviceAuthorization {
            device_code: Secret::new(response.device_code),
            user_code: response.user_code,
            verification_uri: response.verification_uri,
            verification_uri_complete: response.verification_uri_complete,
            interval: Duration::from_secs(response.interval.unwrap_or(5).max(1)),
            expires_at: Instant::now() + Duration::from_secs(response.expires_in),
        })
    }

    /// Polls once per provider interval until authorization, denial, or expiry.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication or availability error.
    pub async fn poll(&self, authorization: DeviceAuthorization) -> Result<TokenSet, ClientError> {
        let mut interval = authorization.interval;
        loop {
            if Instant::now() + interval >= authorization.expires_at {
                return Err(ClientError::new(
                    ErrorKind::Unauthenticated,
                    "device login expired",
                ));
            }
            sleep(interval).await;
            let response = self
                .http
                .post(self.token_endpoint.clone())
                .form(&[
                    ("grant_type", DEVICE_GRANT),
                    ("device_code", authorization.device_code.expose()),
                    ("client_id", self.client_id.as_str()),
                ])
                .send()
                .await
                .map_err(|_| unavailable())?;
            if response.status().is_success() {
                let response: TokenResponse = decode(response).await?;
                if response.access_token.is_empty() {
                    return Err(unavailable());
                }
                return Ok(TokenSet {
                    access_token: Secret::new(response.access_token),
                    refresh_token: response.refresh_token.map(Secret::new),
                });
            }
            let error: OAuthError = decode(response).await?;
            match error.error.as_str() {
                "authorization_pending" => {}
                "slow_down" => interval += Duration::from_secs(5),
                "access_denied" => {
                    return Err(ClientError::new(
                        ErrorKind::Unauthenticated,
                        "device login denied",
                    ));
                }
                "expired_token" => {
                    return Err(ClientError::new(
                        ErrorKind::Unauthenticated,
                        "device login expired",
                    ));
                }
                _ => return Err(unavailable()),
            }
        }
    }

    /// Exchanges a refresh credential without persisting the returned access token.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication or availability error.
    pub async fn refresh(&self, refresh_token: &Secret) -> Result<TokenSet, ClientError> {
        let response = self
            .http
            .post(self.token_endpoint.clone())
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token.expose()),
                ("client_id", self.client_id.as_str()),
            ])
            .send()
            .await
            .map_err(|_| unavailable())?;
        if !response.status().is_success() {
            return Err(ClientError::new(
                ErrorKind::Unauthenticated,
                "login has expired",
            ));
        }
        let response: TokenResponse = decode(response).await?;
        if response.access_token.is_empty() {
            return Err(unavailable());
        }
        Ok(TokenSet {
            access_token: Secret::new(response.access_token),
            refresh_token: response.refresh_token.map(Secret::new),
        })
    }
}

fn require_success(response: Response) -> Result<Response, ClientError> {
    if response.status().is_success() {
        Ok(response)
    } else {
        Err(unavailable())
    }
}

async fn decode<T: for<'de> Deserialize<'de>>(response: Response) -> Result<T, ClientError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(unavailable());
    }
    let bytes = response.bytes().await.map_err(|_| unavailable())?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(unavailable());
    }
    serde_json::from_slice(&bytes).map_err(|_| unavailable())
}

fn invalid() -> ClientError {
    ClientError::new(ErrorKind::InvalidRequest, "OIDC configuration is invalid")
}

fn unavailable() -> ClientError {
    ClientError::new(
        ErrorKind::Unavailable,
        "authentication service is unavailable",
    )
}
