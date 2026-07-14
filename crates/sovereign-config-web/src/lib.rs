#![forbid(unsafe_code)]

use std::cell::RefCell;

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use js_sys::{Date, Reflect, Uint8Array};
use prost::Message;
use sha2::{Digest, Sha256};
use sovereign_config_client::{
    AccessTokenProvider, Client, RpcCode, Transport, VersionReply, map_rpc_status,
};
use sovereign_config_core::{AuthenticationStatus, ClientError, ErrorKind, Secret};
use sovereign_config_proto::sovereign::config::v1::{
    GetIdentityRequest, GetIdentityResponse, GetVersionRequest, GetVersionResponse,
};
use wasm_bindgen::{JsCast, JsValue, closure::Closure, prelude::wasm_bindgen};
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::{
    Headers, Request, RequestCache, RequestInit, Response, Url, UrlSearchParams, window,
};

const STATE_KEY: &str = "sovereign-config.pkce-state";
const VERIFIER_KEY: &str = "sovereign-config.pkce-verifier";

thread_local! {
    static ACCESS_TOKEN: RefCell<Option<MemoryToken>> = const { RefCell::new(None) };
}

struct MemoryToken {
    token: Secret,
    expires_at_ms: f64,
}

#[derive(Clone)]
struct AppConfig {
    issuer: String,
    client_id: String,
}

#[derive(Clone, Copy)]
struct BrowserTransport;

struct MemoryAuthentication;

#[async_trait(?Send)]
impl AccessTokenProvider for MemoryAuthentication {
    async fn access_token(&self) -> Result<Option<Secret>, ClientError> {
        ACCESS_TOKEN.with_borrow_mut(|token| {
            if token
                .as_ref()
                .is_some_and(|token| Date::now() >= token.expires_at_ms)
            {
                *token = None;
            }
            Ok(token.as_ref().map(|token| token.token.clone()))
        })
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

#[wasm_bindgen(start)]
pub fn start() {
    install_actions();
    spawn_local(async {
        match app_config() {
            Ok(config) => {
                if location_search().is_some_and(|search| search.contains("code="))
                    && let Err(error) = finish_login(&config).await
                {
                    show_error(error.message());
                }
                refresh_status(&config).await;
            }
            Err(error) => show_error(error.message()),
        }
    });
}

fn install_actions() {
    let Some(document) = window().and_then(|window| window.document()) else {
        return;
    };
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
            ACCESS_TOKEN.with_borrow_mut(|token| *token = None);
            set_text("auth-value", "Logged out");
            set_hidden("login", false);
            set_hidden("logout", true);
            focus("login");
        });
        let _ = logout.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
}

async fn refresh_status(_: &AppConfig) {
    clear_error();
    let client = Client::new(BrowserTransport, MemoryAuthentication);
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
        Ok(_) | Err(_) => {
            set_text("auth-value", "Logged out");
            set_hidden("login", false);
            set_hidden("logout", true);
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
        ("scope", "openid sovereign-config"),
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
    let expires_in = Reflect::get(&json, &JsValue::from_str("expires_in"))
        .ok()
        .and_then(|value| value.as_f64())
        .unwrap_or(300.0);
    ACCESS_TOKEN.with_borrow_mut(|token| {
        *token = Some(MemoryToken {
            token: Secret::new(access_token),
            expires_at_ms: Date::now() + expires_in * 1000.0,
        });
    });
    let window = window().ok_or_else(browser_error)?;
    window
        .history()
        .map_err(|_| browser_error())?
        .replace_state_with_url(&JsValue::NULL, "", Some("/"))
        .map_err(|_| browser_error())
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
    let buffer = JsFuture::from(response.array_buffer().map_err(|_| browser_error())?)
        .await
        .map_err(|_| browser_error())?;
    decode_grpc_web(&Uint8Array::new(&buffer).to_vec())
}

fn decode_grpc_web<R: Message + Default>(bytes: &[u8]) -> Result<R, ClientError> {
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
    if status.unwrap_or(0) != 0 {
        return Err(map_rpc_status(match status {
            Some(3) => RpcCode::InvalidArgument,
            Some(7) => RpcCode::PermissionDenied,
            Some(9) => RpcCode::FailedPrecondition,
            Some(14) => RpcCode::Unavailable,
            Some(16) => RpcCode::Unauthenticated,
            _ => RpcCode::Other,
        }));
    }
    R::decode(payload.ok_or_else(|| map_rpc_status(RpcCode::Other))?)
        .map_err(|_| map_rpc_status(RpcCode::Other))
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
    Reflect::get(value, &JsValue::from_str(name))
        .ok()
        .and_then(|value| value.as_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(oidc_error)
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
    use sovereign_config_proto::sovereign::config::v1::GetIdentityResponse;

    use super::decode_grpc_web;

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
}
