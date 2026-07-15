use std::{net::IpAddr, time::Duration};

use reqwest::{Client, Response, Url, redirect::Policy};
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
    device_endpoint: Option<Url>,
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
    device_authorization_endpoint: Option<String>,
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
        let loopback_http = issuer.scheme() == "http"
            && issuer
                .host_str()
                .and_then(|host| host.parse::<IpAddr>().ok())
                .is_some_and(|address| address.is_loopback());
        if issuer.scheme() != "https" && !loopback_http {
            return Err(invalid());
        }
        let discovery_url = issuer
            .join(".well-known/openid-configuration")
            .map_err(|_| invalid())?;
        let http = Client::builder()
            .redirect(Policy::none())
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
        let device_endpoint = discovery
            .device_authorization_endpoint
            .map(|endpoint| Url::parse(&endpoint).map_err(|_| invalid()))
            .transpose()?;
        let token_endpoint = Url::parse(&discovery.token_endpoint).map_err(|_| invalid())?;
        let issuer_origin = issuer.origin().ascii_serialization();
        for endpoint in device_endpoint.iter().chain([&token_endpoint]) {
            if endpoint.origin().ascii_serialization() != issuer_origin
                || !endpoint.username().is_empty()
                || endpoint.password().is_some()
                || endpoint.fragment().is_some()
            {
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
        let device_endpoint = self.device_endpoint.clone().ok_or_else(invalid)?;
        let response = self
            .http
            .post(device_endpoint)
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
            return Err(authentication_error(response, "login has expired").await);
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

    /// Acquires one short-lived access token using an Authentik M2M credential.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication or availability error.
    pub async fn client_credentials(
        &self,
        authentication: &Secret,
    ) -> Result<TokenSet, ClientError> {
        let response = self
            .http
            .post(self.token_endpoint.clone())
            .form(&[
                ("grant_type", "client_credentials"),
                ("scope", "sovereign-config"),
                ("client_id", self.client_id.as_str()),
                ("client_secret", authentication.expose()),
            ])
            .send()
            .await
            .map_err(|_| unavailable())?;
        if !response.status().is_success() {
            return Err(authentication_error(response, "managed authentication failed").await);
        }
        let response: TokenResponse = decode(response).await?;
        if response.access_token.is_empty() || response.refresh_token.is_some() {
            return Err(unavailable());
        }
        Ok(TokenSet {
            access_token: Secret::new(response.access_token),
            refresh_token: None,
        })
    }
}

async fn authentication_error(response: Response, message: &'static str) -> ClientError {
    if response.status().is_client_error()
        && decode::<OAuthError>(response)
            .await
            .is_ok_and(|error| matches!(error.error.as_str(), "invalid_grant" | "invalid_client"))
    {
        ClientError::new(ErrorKind::Unauthenticated, message)
    } else {
        unavailable()
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

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use axum::{
        Json, Router,
        extract::State,
        http::StatusCode,
        response::{IntoResponse, Response},
        routing::{get, post},
    };
    use serde_json::json;

    use super::{DeviceFlowClient, ErrorKind, Secret};

    struct RedirectState {
        issuer: String,
        target: String,
        status: StatusCode,
        token_requests: AtomicUsize,
    }

    #[tokio::test]
    async fn token_credentials_are_not_forwarded_through_redirects() {
        for status in [
            StatusCode::TEMPORARY_REDIRECT,
            StatusCode::PERMANENT_REDIRECT,
        ] {
            assert_redirect_not_followed(status).await;
        }
    }

    async fn assert_redirect_not_followed(status: StatusCode) {
        let captures = Arc::new(AtomicUsize::new(0));
        let capture_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let capture_address = capture_listener.local_addr().unwrap();
        let capture_app = Router::new()
            .route("/capture", post(capture))
            .with_state(captures.clone());
        let capture_task = tokio::spawn(async move {
            axum::serve(capture_listener, capture_app).await.unwrap();
        });

        let issuer_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer_address = issuer_listener.local_addr().unwrap();
        let state = Arc::new(RedirectState {
            issuer: format!("http://{issuer_address}/"),
            target: format!("http://{capture_address}/capture"),
            status,
            token_requests: AtomicUsize::new(0),
        });
        let issuer_app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/token", post(redirect_token))
            .with_state(state.clone());
        let issuer_task = tokio::spawn(async move {
            axum::serve(issuer_listener, issuer_app).await.unwrap();
        });

        let client = DeviceFlowClient::discover(&state.issuer, "client".to_owned())
            .await
            .unwrap();
        let Err(error) = client
            .client_credentials(&Secret::new("credential-sentinel"))
            .await
        else {
            panic!("redirected token request unexpectedly succeeded");
        };

        assert_eq!(error.kind, ErrorKind::Unavailable);
        assert_eq!(state.token_requests.load(Ordering::SeqCst), 1);
        assert_eq!(captures.load(Ordering::SeqCst), 0);
        issuer_task.abort();
        capture_task.abort();
    }

    async fn discovery(State(state): State<Arc<RedirectState>>) -> Json<serde_json::Value> {
        Json(json!({"token_endpoint": format!("{}token", state.issuer)}))
    }

    async fn redirect_token(State(state): State<Arc<RedirectState>>) -> Response {
        state.token_requests.fetch_add(1, Ordering::SeqCst);
        (state.status, [("location", state.target.as_str())]).into_response()
    }

    async fn capture(State(captures): State<Arc<AtomicUsize>>) -> StatusCode {
        captures.fetch_add(1, Ordering::SeqCst);
        StatusCode::NO_CONTENT
    }
}
