#![forbid(unsafe_code)]

use std::cell::RefCell;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use js_sys::{Date, Reflect, Uint8Array};
use prost::Message;
use sha2::{Digest, Sha256};
use sovereign_config_client::{
    AccessTokenProvider, Client, RpcCode, Transport, ValueTransport, VersionReply, map_rpc_status,
    timestamp,
};
use sovereign_config_core::{
    AuthenticationStatus, ClientError, ConfigPath, DeleteMetadata, ErrorKind, ExactValue,
    PlainValue, PutMetadata, Secret, Timestamp,
};
use sovereign_config_proto::sovereign::config::v1::{
    DeleteValueRequest, DeleteValueResponse, GetIdentityRequest, GetIdentityResponse,
    GetValueRequest, GetValueResponse, GetVersionRequest, GetVersionResponse, PutValueRequest,
    PutValueResponse,
};
use wasm_bindgen::{JsCast, JsValue, closure::Closure, prelude::wasm_bindgen};
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::{
    Event, Headers, HtmlButtonElement, HtmlDialogElement, HtmlInputElement, HtmlTextAreaElement,
    Request, RequestCache, RequestInit, Response, Url, UrlSearchParams, window,
};

const STATE_KEY: &str = "sovereign-config.pkce-state";
const VERIFIER_KEY: &str = "sovereign-config.pkce-verifier";
const REFRESH_TOKEN_KEY: &str = "sovereign-config.refresh-token";
const REFRESH_ENDPOINT_KEY: &str = "sovereign-config.refresh-endpoint";
const REFRESH_EXPIRES_KEY: &str = "sovereign-config.refresh-expires-at";
const REFRESH_LIFETIME_MS: f64 = 8.0 * 60.0 * 60.0 * 1000.0;

thread_local! {
    static TOKENS: RefCell<Option<MemoryTokens>> = const { RefCell::new(None) };
}

struct MemoryTokens {
    access_token: Secret,
    refresh_token: Secret,
    access_expires_at_ms: f64,
    refresh_expires_at_ms: f64,
    token_endpoint: String,
}

#[derive(Clone)]
struct AppConfig {
    issuer: String,
    client_id: String,
}

#[derive(Clone, Copy)]
struct BrowserTransport;

struct MemoryAuthentication {
    client_id: String,
}

#[async_trait(?Send)]
impl AccessTokenProvider for MemoryAuthentication {
    async fn access_token(&self) -> Result<Option<Secret>, ClientError> {
        let Some(tokens) = TOKENS.with_borrow_mut(Option::take) else {
            return Ok(None);
        };
        let now = Date::now();
        if now < tokens.access_expires_at_ms {
            let access_token = tokens.access_token.clone();
            TOKENS.with_borrow_mut(|slot| *slot = Some(tokens));
            return Ok(Some(access_token));
        }
        if now >= tokens.refresh_expires_at_ms {
            clear_persisted_refresh_token();
            return Ok(None);
        }
        match refresh_tokens(&self.client_id, &tokens).await {
            Ok(refreshed) => {
                let access_token = refreshed.access_token.clone();
                persist_refresh_token(&refreshed);
                TOKENS.with_borrow_mut(|slot| *slot = Some(refreshed));
                Ok(Some(access_token))
            }
            Err(error) if error.kind == ErrorKind::Unavailable => {
                TOKENS.with_borrow_mut(|slot| *slot = Some(tokens));
                Err(error)
            }
            Err(error) => {
                clear_persisted_refresh_token();
                Err(error)
            }
        }
    }
}

#[async_trait(?Send)]
impl Transport for BrowserTransport {
    async fn get_version(&self, protocol_version: &str) -> Result<VersionReply, ClientError> {
        let response: GetVersionResponse = grpc_unary(
            "/sovereign.config.v1.System/GetVersion",
            &GetVersionRequest {
                protocol_version: protocol_version.to_owned(),
            },
            None,
        )
        .await?;
        Ok(VersionReply {
            application_version: response.application_version,
            protocol_version: response.protocol_version,
        })
    }

    async fn get_identity(&self, bearer: &Secret) -> Result<AuthenticationStatus, ClientError> {
        let response: GetIdentityResponse = grpc_unary(
            "/sovereign.config.v1.System/GetIdentity",
            &GetIdentityRequest {},
            Some(bearer),
        )
        .await?;
        Ok(AuthenticationStatus {
            authenticated: response.authenticated,
        })
    }
}

#[async_trait(?Send)]
impl ValueTransport for BrowserTransport {
    async fn get_value(
        &self,
        path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<ExactValue, ClientError> {
        let response: GetValueResponse = grpc_unary(
            "/sovereign.config.v1.Configuration/GetValue",
            &GetValueRequest {
                path: path.as_str().to_owned(),
            },
            Some(bearer),
        )
        .await?;
        Ok(ExactValue {
            value: PlainValue::new(response.value),
            created_at: proto_timestamp(response.created_at)?,
            updated_at: proto_timestamp(response.updated_at)?,
        })
    }

    async fn put_value(
        &self,
        path: &ConfigPath,
        value: &PlainValue,
        bearer: &Secret,
    ) -> Result<PutMetadata, ClientError> {
        let response: PutValueResponse = grpc_unary(
            "/sovereign.config.v1.Configuration/PutValue",
            &PutValueRequest {
                path: path.as_str().to_owned(),
                value: value.expose().to_owned(),
            },
            Some(bearer),
        )
        .await?;
        Ok(PutMetadata {
            created_at: proto_timestamp(response.created_at)?,
            updated_at: proto_timestamp(response.updated_at)?,
        })
    }

    async fn delete_value(
        &self,
        path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<DeleteMetadata, ClientError> {
        let response: DeleteValueResponse = grpc_unary(
            "/sovereign.config.v1.Configuration/DeleteValue",
            &DeleteValueRequest {
                path: path.as_str().to_owned(),
            },
            Some(bearer),
        )
        .await?;
        Ok(DeleteMetadata {
            deleted_at: proto_timestamp(response.deleted_at)?,
        })
    }
}

fn proto_timestamp(value: Option<prost_types::Timestamp>) -> Result<Timestamp, ClientError> {
    let value = value.ok_or_else(browser_error)?;
    timestamp(value.seconds, value.nanos)
}

#[wasm_bindgen(start)]
pub fn start() {
    install_actions();
    spawn_local(async {
        match app_config() {
            Ok(config) => {
                restore_tokens();
                let callback_error =
                    if location_search().is_some_and(|search| search.contains("code=")) {
                        finish_login(&config).await.err()
                    } else {
                        None
                    };
                refresh_status(&config).await;
                if let Some(error) = callback_error {
                    show_error(error.message());
                }
            }
            Err(error) => show_error(error.message()),
        }
    });
}

fn install_actions() {
    let Some(document) = window().and_then(|window| window.document()) else {
        return;
    };
    for id in ["brand-link", "system-status-link"] {
        if let Some(link) = document.get_element_by_id(id) {
            let callback = Closure::<dyn FnMut(_)>::new(|event: Event| {
                if window()
                    .and_then(|window| window.location().pathname().ok())
                    .as_deref()
                    == Some("/")
                {
                    event.prevent_default();
                }
            });
            let _ =
                link.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
            callback.forget();
        }
    }
    if let Some(login) = document.get_element_by_id("login") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: web_sys::Event| {
            spawn_local(async {
                match app_config() {
                    Ok(config) => {
                        if let Err(error) = begin_login(&config).await {
                            show_error(error.message());
                        }
                    }
                    Err(error) => show_error(error.message()),
                }
            });
        });
        let _ = login.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(logout) = document.get_element_by_id("logout") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: web_sys::Event| {
            clear_browser_session();
            set_text("auth-value", "Logged out");
            set_hidden("login", false);
            set_hidden("logout", true);
            focus("login");
        });
        let _ = logout.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    install_value_actions(&document);
}

fn install_value_actions(document: &web_sys::Document) {
    if let Some(form) = document.get_element_by_id("value-form") {
        let callback = Closure::<dyn FnMut(_)>::new(|event: Event| {
            event.prevent_default();
            spawn_local(async { load_value().await });
        });
        let _ = form.add_event_listener_with_callback("submit", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(save) = document.get_element_by_id("save-value") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            spawn_local(async { save_value().await });
        });
        let _ = save.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(remove) = document.get_element_by_id("delete-value") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            if let Some(dialog) = element::<HtmlDialogElement>("delete-dialog") {
                let _ = dialog.show_modal();
                focus("cancel-delete");
            }
        });
        let _ = remove.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(cancel) = document.get_element_by_id("cancel-delete") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            close_delete_dialog();
            focus("delete-value");
        });
        let _ = cancel.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(confirm) = document.get_element_by_id("confirm-delete") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            spawn_local(async { delete_value().await });
        });
        let _ =
            confirm.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
}

fn value_client(config: &AppConfig) -> Client<BrowserTransport, MemoryAuthentication> {
    Client::new(
        BrowserTransport,
        MemoryAuthentication {
            client_id: config.client_id.clone(),
        },
    )
}

fn selected_path() -> Result<ConfigPath, ClientError> {
    let input = element::<HtmlInputElement>("value-path").ok_or_else(browser_error)?;
    ConfigPath::parse_operation(input.value())
        .map_err(|_| ClientError::new(ErrorKind::InvalidRequest, "configuration path is invalid"))
}

async fn load_value() {
    clear_error();
    let result = async {
        let config = app_config()?;
        value_client(&config).get_value(&selected_path()?).await
    }
    .await;
    match result {
        Ok(value) => {
            set_textarea("value-content", value.value.expose());
            set_timestamp("created-value", value.created_at);
            set_timestamp("updated-value", value.updated_at);
            set_text("value-state", "Loaded");
            set_button_disabled("delete-value", false);
            focus("value-content");
        }
        Err(error) if error.kind == ErrorKind::NotFound => {
            set_textarea("value-content", "");
            set_text("created-value", "-");
            set_text("updated-value", "-");
            set_text("value-state", "New value");
            set_button_disabled("delete-value", true);
            focus("value-content");
        }
        Err(error) => show_error(error.message()),
    }
}

async fn save_value() {
    clear_error();
    let result = async {
        let config = app_config()?;
        let path = selected_path()?;
        let value = element::<HtmlTextAreaElement>("value-content")
            .ok_or_else(browser_error)?
            .value();
        value_client(&config)
            .put_value(&path, &PlainValue::new(value))
            .await
    }
    .await;
    match result {
        Ok(metadata) => {
            set_timestamp("created-value", metadata.created_at);
            set_timestamp("updated-value", metadata.updated_at);
            set_text("value-state", "Saved");
            set_button_disabled("delete-value", false);
            focus("value-heading");
        }
        Err(error) => show_error(error.message()),
    }
}

async fn delete_value() {
    clear_error();
    let result = async {
        let config = app_config()?;
        value_client(&config).delete_value(&selected_path()?).await
    }
    .await;
    match result {
        Ok(_) => {
            close_delete_dialog();
            set_textarea("value-content", "");
            set_text("created-value", "-");
            set_text("updated-value", "-");
            set_text("value-state", "Deleted");
            set_button_disabled("delete-value", true);
            focus("value-path");
        }
        Err(error) => {
            close_delete_dialog();
            show_error(error.message());
            focus("delete-value");
        }
    }
}

fn close_delete_dialog() {
    if let Some(dialog) = element::<HtmlDialogElement>("delete-dialog") {
        dialog.close();
    }
}

async fn refresh_status(config: &AppConfig) {
    clear_error();
    let client = Client::new(
        BrowserTransport,
        MemoryAuthentication {
            client_id: config.client_id.clone(),
        },
    );
    match client.service_status().await {
        Ok(status) => {
            set_text("service-value", "Available");
            set_text("version-value", &status.application_version);
            set_text("protocol-value", &status.protocol_version);
        }
        Err(error) => {
            set_text("service-value", "Unavailable");
            show_error(error.message());
        }
    }
    match client.authentication_status().await {
        Ok(status) if status.authenticated => {
            set_text("auth-value", "Logged in");
            set_hidden("login", true);
            set_hidden("logout", false);
            focus("auth-heading");
        }
        Ok(_) => {
            set_text("auth-value", "Logged out");
            set_hidden("login", false);
            set_hidden("logout", true);
        }
        Err(error) if error.kind == ErrorKind::Unauthenticated => {
            clear_browser_session();
            set_text("auth-value", "Logged out");
            set_hidden("login", false);
            set_hidden("logout", true);
            show_error(error.message());
        }
        Err(error) => {
            set_text("auth-value", "Unavailable");
            set_hidden("login", true);
            set_hidden("logout", false);
            show_error(error.message());
        }
    }
}

async fn begin_login(config: &AppConfig) -> Result<(), ClientError> {
    let discovery = discover(&config.issuer).await?;
    let verifier = random_urlsafe()?;
    let state = random_urlsafe()?;
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let storage = session_storage()?;
    storage
        .set_item(STATE_KEY, &state)
        .map_err(|_| browser_error())?;
    storage
        .set_item(VERIFIER_KEY, &verifier)
        .map_err(|_| browser_error())?;
    let redirect_uri = redirect_uri()?;
    let url = Url::new(&discovery.authorization_endpoint).map_err(|_| oidc_error())?;
    let parameters = url.search_params();
    for (name, value) in [
        ("response_type", "code"),
        ("client_id", config.client_id.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("scope", "openid sovereign-config offline_access"),
        ("state", state.as_str()),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ] {
        parameters.append(name, value);
    }
    window()
        .ok_or_else(browser_error)?
        .location()
        .set_href(&url.href())
        .map_err(|_| browser_error())
}

async fn finish_login(config: &AppConfig) -> Result<(), ClientError> {
    let parameters = UrlSearchParams::new_with_str(&location_search().unwrap_or_default())
        .map_err(|_| oidc_error())?;
    let code = parameters.get("code").ok_or_else(oidc_error)?;
    let received_state = parameters.get("state").ok_or_else(oidc_error)?;
    let storage = session_storage()?;
    let expected_state = storage
        .get_item(STATE_KEY)
        .map_err(|_| browser_error())?
        .ok_or_else(oidc_error)?;
    let verifier = storage
        .get_item(VERIFIER_KEY)
        .map_err(|_| browser_error())?
        .ok_or_else(oidc_error)?;
    storage
        .remove_item(STATE_KEY)
        .map_err(|_| browser_error())?;
    storage
        .remove_item(VERIFIER_KEY)
        .map_err(|_| browser_error())?;
    if received_state != expected_state {
        return Err(ClientError::new(
            ErrorKind::Unauthenticated,
            "login response did not match this browser",
        ));
    }
    let discovery = discover(&config.issuer).await?;
    let form = UrlSearchParams::new().map_err(|_| browser_error())?;
    for (name, value) in [
        ("grant_type", "authorization_code"),
        ("client_id", config.client_id.as_str()),
        ("redirect_uri", redirect_uri()?.as_str()),
        ("code", code.as_str()),
        ("code_verifier", verifier.as_str()),
    ] {
        form.append(name, value);
    }
    let response = fetch(
        &discovery.token_endpoint,
        "POST",
        Some(form.to_string().into()),
        &[("content-type", "application/x-www-form-urlencoded")],
    )
    .await?;
    if !response.ok() {
        return Err(ClientError::new(
            ErrorKind::Unauthenticated,
            "login was rejected",
        ));
    }
    let json = JsFuture::from(response.json().map_err(|_| oidc_error())?)
        .await
        .map_err(|_| oidc_error())?;
    let access_token = string_property(&json, "access_token")?;
    let refresh_token = string_property(&json, "refresh_token")?;
    let expires_in = expires_in(&json);
    let now = Date::now();
    persist_refresh_token_from_parts(
        &refresh_token,
        &discovery.token_endpoint,
        now + REFRESH_LIFETIME_MS,
    );
    TOKENS.with_borrow_mut(|token| {
        *token = Some(MemoryTokens {
            access_token: Secret::new(access_token),
            refresh_token: Secret::new(refresh_token),
            access_expires_at_ms: now + expires_in * 1000.0,
            refresh_expires_at_ms: now + REFRESH_LIFETIME_MS,
            token_endpoint: discovery.token_endpoint,
        });
    });
    let window = window().ok_or_else(browser_error)?;
    window
        .history()
        .map_err(|_| browser_error())?
        .replace_state_with_url(&JsValue::NULL, "", Some("/"))
        .map_err(|_| browser_error())
}

fn restore_tokens() {
    let Ok(storage) = session_storage() else {
        return;
    };
    let (Some(refresh_token), Some(token_endpoint), Some(expires_at)) = (
        storage.get_item(REFRESH_TOKEN_KEY).ok().flatten(),
        storage.get_item(REFRESH_ENDPOINT_KEY).ok().flatten(),
        storage
            .get_item(REFRESH_EXPIRES_KEY)
            .ok()
            .flatten()
            .and_then(|value| value.parse::<f64>().ok()),
    ) else {
        return;
    };
    if Date::now() >= expires_at {
        clear_persisted_refresh_token();
        return;
    }
    TOKENS.with_borrow_mut(|slot| {
        *slot = Some(MemoryTokens {
            access_token: Secret::new(String::new()),
            refresh_token: Secret::new(refresh_token),
            access_expires_at_ms: 0.0,
            refresh_expires_at_ms: expires_at,
            token_endpoint,
        });
    });
}

fn persist_refresh_token(tokens: &MemoryTokens) {
    persist_refresh_token_from_parts(
        tokens.refresh_token.expose(),
        &tokens.token_endpoint,
        tokens.refresh_expires_at_ms,
    );
}

fn persist_refresh_token_from_parts(token: &str, endpoint: &str, expires_at: f64) {
    if let Ok(storage) = session_storage() {
        let _ = storage.set_item(REFRESH_TOKEN_KEY, token);
        let _ = storage.set_item(REFRESH_ENDPOINT_KEY, endpoint);
        let _ = storage.set_item(REFRESH_EXPIRES_KEY, &expires_at.to_string());
    }
}

fn clear_persisted_refresh_token() {
    if let Ok(storage) = session_storage() {
        let _ = storage.remove_item(REFRESH_TOKEN_KEY);
        let _ = storage.remove_item(REFRESH_ENDPOINT_KEY);
        let _ = storage.remove_item(REFRESH_EXPIRES_KEY);
    }
}

fn clear_browser_session() {
    TOKENS.with_borrow_mut(|token| *token = None);
    clear_persisted_refresh_token();
}

async fn refresh_tokens(
    client_id: &str,
    current: &MemoryTokens,
) -> Result<MemoryTokens, ClientError> {
    let form = UrlSearchParams::new().map_err(|_| browser_error())?;
    for (name, value) in [
        ("grant_type", "refresh_token"),
        ("client_id", client_id),
        ("refresh_token", current.refresh_token.expose()),
    ] {
        form.append(name, value);
    }
    let response = fetch(
        &current.token_endpoint,
        "POST",
        Some(form.to_string().into()),
        &[("content-type", "application/x-www-form-urlencoded")],
    )
    .await?;
    if !response.ok() {
        return Err(refresh_error(&response).await);
    }
    let json = JsFuture::from(response.json().map_err(|_| oidc_error())?)
        .await
        .map_err(|_| oidc_error())?;
    let access_token = string_property(&json, "access_token")?;
    let refresh_token = string_property(&json, "refresh_token")?;
    Ok(MemoryTokens {
        access_token: Secret::new(access_token),
        refresh_token: Secret::new(refresh_token),
        access_expires_at_ms: Date::now() + expires_in(&json) * 1000.0,
        refresh_expires_at_ms: current.refresh_expires_at_ms,
        token_endpoint: current.token_endpoint.clone(),
    })
}

async fn refresh_error(response: &Response) -> ClientError {
    let oauth_error = match response.json() {
        Ok(json) => JsFuture::from(json)
            .await
            .ok()
            .and_then(|json| optional_string_property(&json, "error")),
        Err(_) => None,
    };
    classify_refresh_error(response.status(), oauth_error.as_deref())
}

fn classify_refresh_error(status: u16, oauth_error: Option<&str>) -> ClientError {
    if status == 400 && oauth_error == Some("invalid_grant") {
        ClientError::new(ErrorKind::Unauthenticated, "login has expired")
    } else {
        oidc_error()
    }
}

fn expires_in(json: &JsValue) -> f64 {
    Reflect::get(json, &JsValue::from_str("expires_in"))
        .ok()
        .and_then(|value| value.as_f64())
        .filter(|value| value.is_finite() && *value > 0.0)
        .unwrap_or(300.0)
        .min(300.0)
}

struct Discovery {
    authorization_endpoint: String,
    token_endpoint: String,
}

async fn discover(issuer: &str) -> Result<Discovery, ClientError> {
    let url = format!("{issuer}.well-known/openid-configuration");
    let response = fetch(&url, "GET", None, &[]).await?;
    if !response.ok() {
        return Err(oidc_error());
    }
    let json = JsFuture::from(response.json().map_err(|_| oidc_error())?)
        .await
        .map_err(|_| oidc_error())?;
    let authorization_endpoint = string_property(&json, "authorization_endpoint")?;
    let token_endpoint = string_property(&json, "token_endpoint")?;
    require_issuer_origin(issuer, &authorization_endpoint)?;
    require_issuer_origin(issuer, &token_endpoint)?;
    Ok(Discovery {
        authorization_endpoint,
        token_endpoint,
    })
}

fn require_issuer_origin(issuer: &str, endpoint: &str) -> Result<(), ClientError> {
    let issuer = Url::new(issuer).map_err(|_| oidc_error())?;
    let endpoint = Url::new(endpoint).map_err(|_| oidc_error())?;
    if issuer.origin() != endpoint.origin() {
        return Err(oidc_error());
    }
    Ok(())
}

async fn grpc_unary<M, R>(
    path: &str,
    message: &M,
    bearer: Option<&Secret>,
) -> Result<R, ClientError>
where
    M: Message,
    R: Message + Default,
{
    let encoded = message.encode_to_vec();
    let mut framed = Vec::with_capacity(encoded.len() + 5);
    framed.push(0);
    let encoded_length = u32::try_from(encoded.len()).map_err(|_| browser_error())?;
    framed.extend_from_slice(&encoded_length.to_be_bytes());
    framed.extend_from_slice(&encoded);
    let body = Uint8Array::from(framed.as_slice());
    let mut headers = vec![
        ("content-type", "application/grpc-web+proto"),
        ("x-grpc-web", "1"),
    ];
    let authorization;
    if let Some(bearer) = bearer {
        authorization = format!("Bearer {}", bearer.expose());
        headers.push(("authorization", authorization.as_str()));
    }
    let response = fetch(path, "POST", Some(body.into()), &headers).await?;
    if !response.ok() {
        return Err(map_rpc_status(RpcCode::Unavailable));
    }
    let header_status = response
        .headers()
        .get("grpc-status")
        .ok()
        .flatten()
        .and_then(|value| value.parse::<u16>().ok());
    let buffer = JsFuture::from(response.array_buffer().map_err(|_| browser_error())?)
        .await
        .map_err(|_| browser_error())?;
    decode_grpc_web_response(&Uint8Array::new(&buffer).to_vec(), header_status)
}

#[cfg(test)]
fn decode_grpc_web<R: Message + Default>(bytes: &[u8]) -> Result<R, ClientError> {
    decode_grpc_web_response(bytes, None)
}

fn decode_grpc_web_response<R: Message + Default>(
    bytes: &[u8],
    header_status: Option<u16>,
) -> Result<R, ClientError> {
    let mut offset = 0;
    let mut payload = None;
    let mut status = None;
    while offset + 5 <= bytes.len() {
        let flags = bytes[offset];
        let length = u32::from_be_bytes(bytes[offset + 1..offset + 5].try_into().unwrap()) as usize;
        offset += 5;
        if offset + length > bytes.len() {
            return Err(map_rpc_status(RpcCode::Other));
        }
        let frame = &bytes[offset..offset + length];
        if flags & 0x80 == 0 {
            payload = Some(frame);
        } else if let Ok(trailers) = std::str::from_utf8(frame) {
            status = trailers.lines().find_map(|line| {
                line.strip_prefix("grpc-status:")
                    .and_then(|value| value.trim().parse::<u16>().ok())
            });
        }
        offset += length;
    }
    let status = status
        .or(header_status)
        .ok_or_else(|| map_rpc_status(RpcCode::Other))?;
    if status != 0 {
        return Err(map_rpc_status(grpc_status_code(status)));
    }
    R::decode(payload.ok_or_else(|| map_rpc_status(RpcCode::Other))?)
        .map_err(|_| map_rpc_status(RpcCode::Other))
}

fn grpc_status_code(status: u16) -> RpcCode {
    match status {
        3 => RpcCode::InvalidArgument,
        5 => RpcCode::NotFound,
        7 => RpcCode::PermissionDenied,
        9 => RpcCode::FailedPrecondition,
        14 => RpcCode::Unavailable,
        16 => RpcCode::Unauthenticated,
        _ => RpcCode::Other,
    }
}

async fn fetch(
    url: &str,
    method: &str,
    body: Option<JsValue>,
    headers: &[(&str, &str)],
) -> Result<Response, ClientError> {
    let request_headers = Headers::new().map_err(|_| browser_error())?;
    for (name, value) in headers {
        request_headers
            .append(name, value)
            .map_err(|_| browser_error())?;
    }
    let options = RequestInit::new();
    options.set_method(method);
    options.set_cache(RequestCache::NoStore);
    options.set_headers(&request_headers);
    if let Some(body) = body.as_ref() {
        options.set_body(body);
    }
    let request = Request::new_with_str_and_init(url, &options).map_err(|_| browser_error())?;
    let response = JsFuture::from(
        window()
            .ok_or_else(browser_error)?
            .fetch_with_request(&request),
    )
    .await
    .map_err(|_| map_rpc_status(RpcCode::Unavailable))?;
    response.dyn_into().map_err(|_| browser_error())
}

fn app_config() -> Result<AppConfig, ClientError> {
    let global = js_sys::global();
    let config = Reflect::get(&global, &JsValue::from_str("SOVEREIGN_CONFIG"))
        .map_err(|_| browser_error())?;
    Ok(AppConfig {
        issuer: string_property(&config, "issuer")?,
        client_id: string_property(&config, "clientId")?,
    })
}

fn string_property(value: &JsValue, name: &str) -> Result<String, ClientError> {
    optional_string_property(value, name).ok_or_else(oidc_error)
}

fn optional_string_property(value: &JsValue, name: &str) -> Option<String> {
    Reflect::get(value, &JsValue::from_str(name))
        .ok()
        .and_then(|value| value.as_string())
        .filter(|value| !value.is_empty())
}

fn random_urlsafe() -> Result<String, ClientError> {
    let mut bytes = [0_u8; 32];
    window()
        .ok_or_else(browser_error)?
        .crypto()
        .map_err(|_| browser_error())?
        .get_random_values_with_u8_array(&mut bytes)
        .map_err(|_| browser_error())?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn session_storage() -> Result<web_sys::Storage, ClientError> {
    window()
        .ok_or_else(browser_error)?
        .session_storage()
        .map_err(|_| browser_error())?
        .ok_or_else(browser_error)
}

fn redirect_uri() -> Result<String, ClientError> {
    let location = window().ok_or_else(browser_error)?.location();
    Ok(format!(
        "{}/auth/callback",
        location.origin().map_err(|_| browser_error())?
    ))
}

fn location_search() -> Option<String> {
    window()?.location().search().ok()
}

fn set_text(id: &str, text: &str) {
    if let Some(element) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id(id))
    {
        element.set_text_content(Some(text));
    }
}

fn element<T: JsCast>(id: &str) -> Option<T> {
    window()?
        .document()?
        .get_element_by_id(id)?
        .dyn_into::<T>()
        .ok()
}

fn set_textarea(id: &str, value: &str) {
    if let Some(element) = element::<HtmlTextAreaElement>(id) {
        element.set_value(value);
    }
}

fn set_button_disabled(id: &str, disabled: bool) {
    if let Some(element) = element::<HtmlButtonElement>(id) {
        element.set_disabled(disabled);
    }
}

#[allow(clippy::cast_precision_loss)]
fn set_timestamp(id: &str, timestamp: Timestamp) {
    let milliseconds = timestamp.seconds as f64 * 1000.0 + f64::from(timestamp.nanos) / 1_000_000.0;
    let date = Date::new(&JsValue::from_f64(milliseconds));
    let formatted = date.to_locale_string("en-GB", &JsValue::UNDEFINED);
    set_text(id, &String::from(formatted));
}

fn set_hidden(id: &str, hidden: bool) {
    if let Some(element) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id(id))
    {
        let _ = element.set_attribute("aria-hidden", if hidden { "true" } else { "false" });
        let _ = element.set_attribute("tabindex", if hidden { "-1" } else { "0" });
        if hidden {
            let _ = element.set_attribute("hidden", "");
        } else {
            let _ = element.remove_attribute("hidden");
        }
    }
}

fn focus(id: &str) {
    if let Some(element) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id(id))
        .and_then(|element| element.dyn_into::<web_sys::HtmlElement>().ok())
    {
        let _ = element.focus();
    }
}

fn show_error(message: &str) {
    set_text("error", message);
    set_hidden("error", false);
}

fn clear_error() {
    set_text("error", "");
    set_hidden("error", true);
}

fn browser_error() -> ClientError {
    ClientError::new(ErrorKind::Internal, "browser operation failed")
}

fn oidc_error() -> ClientError {
    ClientError::new(ErrorKind::Unavailable, "identity provider is unavailable")
}

#[cfg(test)]
mod tests {
    use prost::Message;
    use sovereign_config_core::ErrorKind;
    use sovereign_config_proto::sovereign::config::v1::GetIdentityResponse;

    use super::{classify_refresh_error, decode_grpc_web, decode_grpc_web_response};

    #[test]
    fn refresh_error_rejects_only_invalid_grant() {
        let error = classify_refresh_error(400, Some("invalid_grant"));

        assert_eq!(error.kind, ErrorKind::Unauthenticated);
        assert_eq!(error.message(), "login has expired");
    }

    #[test]
    fn refresh_error_preserves_sessions_for_provider_failures() {
        for (status, oauth_error) in [
            (429, Some("slow_down")),
            (500, Some("server_error")),
            (503, None),
            (400, Some("invalid_request")),
            (400, None),
        ] {
            let error = classify_refresh_error(status, oauth_error);
            assert_eq!(error.kind, ErrorKind::Unavailable);
            assert_eq!(error.message(), "identity provider is unavailable");
        }
    }

    #[test]
    fn grpc_web_decoder_reads_data_and_success_trailer() {
        let message = GetIdentityResponse {
            authenticated: true,
        }
        .encode_to_vec();
        let mut response = vec![0];
        response.extend_from_slice(&u32::try_from(message.len()).unwrap().to_be_bytes());
        response.extend_from_slice(&message);
        let trailer = b"grpc-status: 0\r\n";
        response.push(0x80);
        response.extend_from_slice(&u32::try_from(trailer.len()).unwrap().to_be_bytes());
        response.extend_from_slice(trailer);
        let decoded: GetIdentityResponse = decode_grpc_web(&response).unwrap();
        assert!(decoded.authenticated);
    }

    #[test]
    fn grpc_web_decoder_rejects_responses_without_a_status_trailer() {
        let message = GetIdentityResponse {
            authenticated: true,
        }
        .encode_to_vec();
        let mut data_only = vec![0];
        data_only.extend_from_slice(&u32::try_from(message.len()).unwrap().to_be_bytes());
        data_only.extend_from_slice(&message);

        let mut missing_status = data_only.clone();
        let trailer = b"grpc-message: missing status\r\n";
        missing_status.push(0x80);
        missing_status.extend_from_slice(&u32::try_from(trailer.len()).unwrap().to_be_bytes());
        missing_status.extend_from_slice(trailer);

        for response in [data_only, missing_status] {
            let error = decode_grpc_web::<GetIdentityResponse>(&response).unwrap_err();
            assert_eq!(error.kind, ErrorKind::Internal);
            assert_eq!(error.message(), "request failed");
        }
    }

    #[test]
    fn grpc_web_decoder_accepts_trailers_only_status_headers() {
        let error = decode_grpc_web_response::<GetIdentityResponse>(&[], Some(7)).unwrap_err();
        assert_eq!(error.kind, ErrorKind::PermissionDenied);
        assert_eq!(error.message(), "permission denied");
    }
}
