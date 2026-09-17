//! Page-level browser access: the injected application config, web storage, the
//! current location, and randomness.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use js_sys::Reflect;
use sovereign_config_core::{ClientError, ErrorKind};
use wasm_bindgen::JsValue;
use web_sys::window;

#[derive(Clone)]
pub(crate) struct AppConfig {
    pub(crate) issuer: String,
    pub(crate) client_id: String,
}

pub(crate) fn app_config() -> Result<AppConfig, ClientError> {
    let global = js_sys::global();
    let config = Reflect::get(&global, &JsValue::from_str("SOVEREIGN_CONFIG"))
        .map_err(|_| browser_error())?;
    Ok(AppConfig {
        issuer: string_property(&config, "issuer")?,
        client_id: string_property(&config, "clientId")?,
    })
}

pub(crate) fn string_property(value: &JsValue, name: &str) -> Result<String, ClientError> {
    optional_string_property(value, name).ok_or_else(oidc_error)
}

pub(crate) fn optional_string_property(value: &JsValue, name: &str) -> Option<String> {
    Reflect::get(value, &JsValue::from_str(name))
        .ok()
        .and_then(|value| value.as_string())
        .filter(|value| !value.is_empty())
}

pub(crate) fn random_urlsafe() -> Result<String, ClientError> {
    let mut bytes = [0_u8; 32];
    window()
        .ok_or_else(browser_error)?
        .crypto()
        .map_err(|_| browser_error())?
        .get_random_values_with_u8_array(&mut bytes)
        .map_err(|_| browser_error())?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub(crate) fn session_storage() -> Result<web_sys::Storage, ClientError> {
    window()
        .ok_or_else(browser_error)?
        .session_storage()
        .map_err(|_| browser_error())?
        .ok_or_else(browser_error)
}

/// Holds the sidebar width only. Nothing sensitive is ever written here: tokens
/// stay in session storage and in memory.
pub(crate) fn local_storage() -> Result<web_sys::Storage, ClientError> {
    window()
        .ok_or_else(browser_error)?
        .local_storage()
        .map_err(|_| browser_error())?
        .ok_or_else(browser_error)
}

pub(crate) fn redirect_uri() -> Result<String, ClientError> {
    let location = window().ok_or_else(browser_error)?.location();
    Ok(format!(
        "{}/auth/callback",
        location.origin().map_err(|_| browser_error())?
    ))
}

pub(crate) fn location_search() -> Option<String> {
    window()?.location().search().ok()
}

pub(crate) fn browser_error() -> ClientError {
    ClientError::new(ErrorKind::Internal, "browser operation failed")
}

pub(crate) fn oidc_error() -> ClientError {
    ClientError::new(ErrorKind::Unavailable, "identity provider is unavailable")
}
