//! The OIDC session: PKCE login, token refresh and persistence, identity
//! display, and issuer discovery.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use js_sys::{Date, Reflect};
use sha2::{Digest, Sha256};
use sovereign_config_client::{Client, Session};
use sovereign_config_core::{ClientError, ErrorKind, Secret};
use std::{cell::RefCell, rc::Rc};
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Response, Url, UrlSearchParams, window};

use crate::browser::{
    AppConfig, browser_error, location_search, oidc_error, optional_string_property,
    random_urlsafe, redirect_uri, session_storage, string_property,
};
use crate::dom::{clear_error, set_hidden, set_text, show_error};
use crate::route::{route_from_location, route_from_path, route_url};
use crate::transport::{BrowserHandshake, BrowserTransport, MemoryAuthentication, fetch};

thread_local! {
    pub(crate) static TOKENS: RefCell<Option<MemoryTokens>> = const { RefCell::new(None) };

    /// The session this page negotiated — and therefore the only version its
    /// requests may travel on — or the error that stopped it.
    ///
    /// Held for the life of the page: the browser negotiates once at load, like
    /// every other client. It no longer holds a bare version, because the
    /// session can now re-handshake: a page open across a retirement recovers
    /// on its next request instead of failing until someone reloads it, and
    /// what it reports afterwards follows the swap.
    ///
    /// The failure is kept, not just the absence of a session, because every
    /// request made afterwards reports it: an unreachable service surfaced as
    /// an incompatible protocol would send an operator looking at versions
    /// rather than at the service.
    static SESSION: RefCell<Result<Rc<Session<BrowserHandshake>>, ClientError>> =
        const { RefCell::new(Err(NOT_NEGOTIATED)) };
}

/// Before any handshake has run. Nothing may be dialled on it, and no request
/// should reach it: the page negotiates at load, ahead of every view.
const NOT_NEGOTIATED: ClientError = ClientError::new(
    ErrorKind::IncompatibleProtocol,
    "service protocol is incompatible",
);

/// The session negotiated at page load, or why the handshake did not get there.
pub(crate) fn negotiated_session() -> Result<Rc<Session<BrowserHandshake>>, ClientError> {
    SESSION.with_borrow(Clone::clone)
}

fn set_negotiated_session(outcome: Result<Rc<Session<BrowserHandshake>>, ClientError>) {
    SESSION.with_borrow_mut(|slot| *slot = outcome);
}

const STATE_KEY: &str = "sovereign-config.pkce-state";

const VERIFIER_KEY: &str = "sovereign-config.pkce-verifier";

const REFRESH_TOKEN_KEY: &str = "sovereign-config.refresh-token";

const REFRESH_ENDPOINT_KEY: &str = "sovereign-config.refresh-endpoint";

const REFRESH_EXPIRES_KEY: &str = "sovereign-config.refresh-expires-at";

const RETURN_PATH_KEY: &str = "sovereign-config.return-path";

const IDENTITY_NAME_KEY: &str = "sovereign-config.identity-name";

const REFRESH_LIFETIME_MS: f64 = 8.0 * 60.0 * 60.0 * 1000.0;

pub(crate) struct MemoryTokens {
    pub(crate) access_token: Secret,
    refresh_token: Secret,
    pub(crate) access_expires_at_ms: f64,
    pub(crate) refresh_expires_at_ms: f64,
    token_endpoint: String,
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

fn identity_name_from_token_response(json: &JsValue) -> Option<String> {
    identity_display_name(&optional_string_property(json, "id_token")?)
}

fn store_identity_name(name: Option<String>) {
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
    let session = match Session::open(BrowserHandshake).await {
        Ok(session) => Rc::new(session),
        Err(error) => {
            // Nothing may be dialled on a version that was never agreed, so the
            // page keeps no stale one from an earlier load — and keeps this
            // failure, which is what every later request reports.
            set_negotiated_session(Err(error.clone()));
            // Unhide before setting the text: a live region only announces a
            // mutation to content already exposed in the accessibility tree,
            // so setting the text first — while still `hidden` — makes the
            // change silently, and un-hiding is not itself a text mutation
            // that would announce it after the fact.
            set_hidden("service-value", false);
            set_text("service-value", "Service unavailable");
            show_error(error.message());
            // There is no route to ask about the session on either, so the
            // service can confirm no name and none is shown. Which button to
            // offer is not a guess, though: token state is local. A page
            // holding no session must still be able to start one — login is a
            // redirect to the identity provider and never touches this service
            // — and a page holding one keeps Log out, for the same reason a
            // failed identity check does.
            let session = logged_in();
            set_hidden("login", session);
            set_hidden("logout", !session);
            render_identity(false);
            return false;
        }
    };
    // A working service needs no badge saying so; the version it reports is
    // the standing evidence that it answered. The protocol version it also
    // returns is a client-compatibility concern, not an operator's, so it
    // stays out of the header — it governs the routes below instead.
    let deprecation_date = session.deprecation_date();
    set_negotiated_session(Ok(session));
    // A deprecation date warns and never fails, so it uses the same slot the
    // page already uses to report trouble with the service rather than an
    // error banner: the page works, and an operator is being told to plan.
    if let Some(date) = &deprecation_date {
        set_hidden("service-value", false);
        set_text(
            "service-value",
            &format!("Protocol retirement announced for {date}"),
        );
    } else {
        set_text("service-value", "");
        set_hidden("service-value", true);
    }

    // The application version is no longer a by-product of negotiating: the
    // handshake carries versions and nothing else, so it is read from
    // `System.GetVersion` on the route this page just settled on.
    let transport = BrowserTransport::for_session();
    match transport.service_version().await {
        Ok(reply) => set_text("version-value", &reply.application_version),
        // Not fatal: the header loses a version it cannot confirm, and the
        // session below is unaffected. The identity check that follows reports
        // anything genuinely wrong with the service.
        Err(_) => set_text("version-value", ""),
    }
    let client = Client::new(
        transport,
        MemoryAuthentication {
            client_id: config.client_id.clone(),
        },
    );
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

fn persist_refresh_token_from_parts(token: &str, endpoint: &str, expires_at: f64) {
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

pub(crate) fn classify_refresh_error(status: u16, oauth_error: Option<&str>) -> ClientError {
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
