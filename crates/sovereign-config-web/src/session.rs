//! The OIDC session: PKCE login, token refresh and persistence, identity display, and issuer discovery.

use crate::browser::AppConfig;
use crate::browser::browser_error;
use crate::browser::location_search;
use crate::browser::oidc_error;
use crate::browser::optional_string_property;
use crate::browser::random_urlsafe;
use crate::browser::redirect_uri;
use crate::browser::session_storage;
use crate::browser::string_property;
use crate::dom::clear_error;
use crate::dom::set_hidden;
use crate::dom::set_text;
use crate::dom::show_error;
use crate::route::route_from_location;
use crate::route::route_from_path;
use crate::route::route_url;
use crate::transport::BrowserTransport;
use crate::transport::MemoryAuthentication;
use crate::transport::fetch;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use js_sys::Date;
use js_sys::Reflect;
use sha2::Digest;
use sha2::Sha256;
use sovereign_config_client::Client;
use sovereign_config_core::ClientError;
use sovereign_config_core::ErrorKind;
use sovereign_config_core::Secret;
use std::cell::RefCell;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;
use web_sys::Response;
use web_sys::Url;
use web_sys::UrlSearchParams;
use web_sys::window;

thread_local! {
    pub(crate) static TOKENS: RefCell<Option<MemoryTokens>> = const { RefCell::new(None) };
}

pub(crate) const STATE_KEY: &str = "sovereign-config.pkce-state";

pub(crate) const VERIFIER_KEY: &str = "sovereign-config.pkce-verifier";

pub(crate) const REFRESH_TOKEN_KEY: &str = "sovereign-config.refresh-token";

pub(crate) const REFRESH_ENDPOINT_KEY: &str = "sovereign-config.refresh-endpoint";

pub(crate) const REFRESH_EXPIRES_KEY: &str = "sovereign-config.refresh-expires-at";

pub(crate) const RETURN_PATH_KEY: &str = "sovereign-config.return-path";

pub(crate) const IDENTITY_NAME_KEY: &str = "sovereign-config.identity-name";

pub(crate) const REFRESH_LIFETIME_MS: f64 = 8.0 * 60.0 * 60.0 * 1000.0;

pub(crate) struct MemoryTokens {
    pub(crate) access_token: Secret,
    pub(crate) refresh_token: Secret,
    pub(crate) access_expires_at_ms: f64,
    pub(crate) refresh_expires_at_ms: f64,
    pub(crate) token_endpoint: String,
}

/// The operator's display name as advertised by the OIDC ID token issued
/// alongside the access token.
///
/// The token is decoded, not verified: this name only ever labels the header.
/// Every authorization decision belongs to the service, which validates the
/// access token itself — a forged claim here buys nothing but a wrong label.
pub(crate) fn identity_display_name(id_token: &str) -> Option<String> {
    let payload = id_token.split('.').nth(1)?;
    let claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
    // Only claims a person would recognise. `sub` is deliberately not among
    // them: the provider issues it hashed, so falling back to it labels the
    // session with a hex digest that names nobody. An unlabelled header — the
    // Log out button alone — says strictly more than that.
    ["name", "preferred_username", "email"]
        .into_iter()
        .find_map(|claim| {
            let value = claims.get(claim)?.as_str()?.trim();
            (!value.is_empty()).then(|| value.to_owned())
        })
}

pub(crate) fn identity_name_from_token_response(json: &JsValue) -> Option<String> {
    identity_display_name(&optional_string_property(json, "id_token")?)
}

pub(crate) fn store_identity_name(name: Option<String>) {
    let Ok(storage) = session_storage() else {
        return;
    };
    match name {
        Some(name) => {
            let _ = storage.set_item(IDENTITY_NAME_KEY, &name);
        }
        None => {
            let _ = storage.remove_item(IDENTITY_NAME_KEY);
        }
    }
}

/// Shows the stored display name in the header, or hides the slot entirely.
/// `signed_in` is the service's answer, not the browser's: a name left over
/// from a session the service has stopped honouring must not still be on show.
pub(crate) fn render_identity(signed_in: bool) {
    let name = signed_in
        .then(|| {
            session_storage()
                .ok()
                .and_then(|storage| storage.get_item(IDENTITY_NAME_KEY).ok().flatten())
        })
        .flatten()
        .filter(|name| !name.is_empty());
    set_text("identity-name", name.as_deref().unwrap_or_default());
    set_hidden("identity-name", name.is_none());
}

pub(crate) fn logged_in() -> bool {
    TOKENS.with_borrow(Option::is_some)
}

pub(crate) async fn refresh_status(config: &AppConfig) -> bool {
    clear_error();
    let client = Client::new(
        BrowserTransport,
        MemoryAuthentication {
            client_id: config.client_id.clone(),
        },
    );
    match client.service_status().await {
        Ok(status) => {
            // A working service needs no badge saying so; the version it
            // reports is the standing evidence that it answered. The protocol
            // version it also returns is a client-compatibility concern, not
            // an operator's, so it stays out of the header.
            set_text("service-value", "");
            set_hidden("service-value", true);
            set_text("version-value", &status.application_version);
        }
        Err(error) => {
            // Unhide before setting the text: a live region only announces a
            // mutation to content already exposed in the accessibility tree,
            // so setting the text first — while still `hidden` — makes the
            // change silently, and un-hiding is not itself a text mutation
            // that would announce it after the fact.
            set_hidden("service-value", false);
            set_text("service-value", "Service unavailable");
            show_error(error.message());
        }
    }
    match client.authentication_status().await {
        Ok(status) if status.authenticated => {
            set_hidden("login", true);
            set_hidden("logout", false);
            render_identity(true);
            true
        }
        Ok(_) => {
            set_hidden("login", false);
            set_hidden("logout", true);
            render_identity(false);
            false
        }
        Err(error) if error.kind == ErrorKind::Unauthenticated => {
            clear_browser_session();
            set_hidden("login", false);
            set_hidden("logout", true);
            render_identity(false);
            show_error(error.message());
            false
        }
        Err(error) => {
            // The session may well still be good — the service is what failed —
            // so keep Log out reachable rather than offering a second login.
            //
            // The name is a different question, deliberately answered the other
            // way: `render_identity`'s own contract is that `signed_in` is what
            // the service most recently confirmed, and here it confirmed
            // nothing. Blanking the name until the next successful check is the
            // conservative reading of "could not ask" — the header shows a name
            // it can currently stand behind, not one carried over on the
            // optimistic assumption that an outage is transient. `Log out`
            // stays offered because discarding a session that turns out to
            // still be valid is the worse failure of the two; showing a name
            // that turns out to be stale is not offered the same benefit of
            // the doubt.
            set_hidden("login", true);
            set_hidden("logout", false);
            render_identity(false);
            show_error(error.message());
            false
        }
    }
}

pub(crate) async fn begin_login(config: &AppConfig) -> Result<(), ClientError> {
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
    storage
        .set_item(RETURN_PATH_KEY, &route_url(&route_from_location()))
        .map_err(|_| browser_error())?;
    let redirect_uri = redirect_uri()?;
    let url = Url::new(&discovery.authorization_endpoint).map_err(|_| oidc_error())?;
    let parameters = url.search_params();
    for (name, value) in [
        ("response_type", "code"),
        ("client_id", config.client_id.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        // `profile` and `email` are what make the header legible: without
        // them the ID token carries no claim but `sub`, which the provider
        // hashes into an opaque identifier. `identity_display_name`'s fallback
        // chain is `name` → `preferred_username` → `email`, and the first two
        // arrive under `profile` — `email` is a separate scope in standard
        // OIDC (and in Authentik's default mappings), so it has to be listed
        // too or that last fallback can never fire. Together they buy the
        // display name and nothing the service trusts.
        (
            "scope",
            "openid profile email sovereign-config offline_access",
        ),
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

pub(crate) async fn finish_login(config: &AppConfig) -> Result<(), ClientError> {
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
    let return_path = storage
        .get_item(RETURN_PATH_KEY)
        .map_err(|_| browser_error())?
        .map_or_else(|| "/".into(), |path| route_url(&route_from_path(&path)));
    storage
        .remove_item(STATE_KEY)
        .map_err(|_| browser_error())?;
    storage
        .remove_item(VERIFIER_KEY)
        .map_err(|_| browser_error())?;
    storage
        .remove_item(RETURN_PATH_KEY)
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
    store_identity_name(identity_name_from_token_response(&json));
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
        .replace_state_with_url(&JsValue::NULL, "", Some(&return_path))
        .map_err(|_| browser_error())
}

pub(crate) fn restore_tokens() {
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

pub(crate) fn persist_refresh_token(tokens: &MemoryTokens) {
    persist_refresh_token_from_parts(
        tokens.refresh_token.expose(),
        &tokens.token_endpoint,
        tokens.refresh_expires_at_ms,
    );
}

pub(crate) fn persist_refresh_token_from_parts(token: &str, endpoint: &str, expires_at: f64) {
    if let Ok(storage) = session_storage() {
        let _ = storage.set_item(REFRESH_TOKEN_KEY, token);
        let _ = storage.set_item(REFRESH_ENDPOINT_KEY, endpoint);
        let _ = storage.set_item(REFRESH_EXPIRES_KEY, &expires_at.to_string());
    }
}

pub(crate) fn clear_persisted_refresh_token() {
    if let Ok(storage) = session_storage() {
        let _ = storage.remove_item(REFRESH_TOKEN_KEY);
        let _ = storage.remove_item(REFRESH_ENDPOINT_KEY);
        let _ = storage.remove_item(REFRESH_EXPIRES_KEY);
        let _ = storage.remove_item(IDENTITY_NAME_KEY);
    }
}

pub(crate) fn clear_browser_session() {
    TOKENS.with_borrow_mut(|token| *token = None);
    clear_persisted_refresh_token();
}

pub(crate) async fn refresh_tokens(
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
    // A refresh that carries a fresh ID token is the only chance to notice the
    // operator renamed themselves; one that does not leaves the stored name be.
    if let Some(name) = identity_name_from_token_response(&json) {
        store_identity_name(Some(name));
    }
    Ok(MemoryTokens {
        access_token: Secret::new(access_token),
        refresh_token: Secret::new(refresh_token),
        access_expires_at_ms: Date::now() + expires_in(&json) * 1000.0,
        refresh_expires_at_ms: current.refresh_expires_at_ms,
        token_endpoint: current.token_endpoint.clone(),
    })
}

pub(crate) async fn refresh_error(response: &Response) -> ClientError {
    let oauth_error = match response.json() {
        Ok(json) => JsFuture::from(json)
            .await
            .ok()
            .and_then(|json| optional_string_property(&json, "error")),
        Err(_) => None,
    };
    classify_refresh_error(response.status(), oauth_error.as_deref())
}

pub(crate) fn classify_refresh_error(status: u16, oauth_error: Option<&str>) -> ClientError {
    if status == 400 && oauth_error == Some("invalid_grant") {
        ClientError::new(ErrorKind::Unauthenticated, "login has expired")
    } else {
        oidc_error()
    }
}

pub(crate) fn expires_in(json: &JsValue) -> f64 {
    Reflect::get(json, &JsValue::from_str("expires_in"))
        .ok()
        .and_then(|value| value.as_f64())
        .filter(|value| value.is_finite() && *value > 0.0)
        .unwrap_or(300.0)
        .min(300.0)
}

pub(crate) struct Discovery {
    pub(crate) authorization_endpoint: String,
    pub(crate) token_endpoint: String,
}

pub(crate) async fn discover(issuer: &str) -> Result<Discovery, ClientError> {
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

pub(crate) fn require_issuer_origin(issuer: &str, endpoint: &str) -> Result<(), ClientError> {
    let issuer = Url::new(issuer).map_err(|_| oidc_error())?;
    let endpoint = Url::new(endpoint).map_err(|_| oidc_error())?;
    if issuer.origin() != endpoint.origin() {
        return Err(oidc_error());
    }
    Ok(())
}
