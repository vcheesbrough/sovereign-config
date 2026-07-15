#![forbid(unsafe_code)]

use std::{
    cell::{Cell, RefCell},
    collections::BTreeSet,
};

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
    ListedValue, PlainValue, PutMetadata, Secret, Timestamp, ValueListing,
};
use sovereign_config_proto::sovereign::config::v1::{
    DeleteValueRequest, DeleteValueResponse, GetIdentityRequest, GetIdentityResponse,
    GetValueRequest, GetValueResponse, GetVersionRequest, GetVersionResponse, ListValuesRequest,
    ListValuesResponse, PutValueRequest, PutValueResponse,
};
use wasm_bindgen::{JsCast, JsValue, closure::Closure, prelude::wasm_bindgen};
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::{
    Document, Element, Event, Headers, HtmlButtonElement, HtmlDialogElement, HtmlInputElement,
    HtmlTextAreaElement, KeyboardEvent, Request, RequestCache, RequestInit, Response, Url,
    UrlSearchParams, window,
};

const STATE_KEY: &str = "sovereign-config.pkce-state";
const VERIFIER_KEY: &str = "sovereign-config.pkce-verifier";
const REFRESH_TOKEN_KEY: &str = "sovereign-config.refresh-token";
const REFRESH_ENDPOINT_KEY: &str = "sovereign-config.refresh-endpoint";
const REFRESH_EXPIRES_KEY: &str = "sovereign-config.refresh-expires-at";
const RETURN_PATH_KEY: &str = "sovereign-config.return-path";
const REFRESH_LIFETIME_MS: f64 = 8.0 * 60.0 * 60.0 * 1000.0;

thread_local! {
    static TOKENS: RefCell<Option<MemoryTokens>> = const { RefCell::new(None) };
    static DELETE_TARGET: RefCell<Option<DeleteTarget>> = const { RefCell::new(None) };
    static PATH_OPTIONS_REFRESHING: Cell<bool> = const { Cell::new(false) };
    static ACTIVE_PATH_OPTION: Cell<Option<usize>> = const { Cell::new(None) };
}

struct DeleteTarget {
    path: ConfigPath,
    return_focus: String,
}

#[derive(Clone)]
enum Route {
    System,
    Configuration(ConfigPath),
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
    async fn list_values(
        &self,
        path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<ValueListing, ClientError> {
        let response: ListValuesResponse = grpc_unary(
            "/sovereign.config.v1.Configuration/ListValues",
            &ListValuesRequest {
                path: path.as_str().to_owned(),
            },
            Some(bearer),
        )
        .await?;
        let values = response
            .values
            .into_iter()
            .map(|value| {
                Ok(ListedValue {
                    path: ConfigPath::parse(value.path).map_err(|_| browser_error())?,
                    value: PlainValue::new(value.value),
                    created_at: proto_timestamp(value.created_at)?,
                    updated_at: proto_timestamp(value.updated_at)?,
                })
            })
            .collect::<Result<Vec<_>, ClientError>>()?;
        let paths = response
            .paths
            .into_iter()
            .map(|path| ConfigPath::parse(path).map_err(|_| browser_error()))
            .collect::<Result<Vec<_>, ClientError>>()?;
        Ok(ValueListing { values, paths })
    }

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
    render_route(&route_from_location());
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
                render_route(&route_from_location());
                let authenticated = refresh_status(&config).await;
                if let Some(error) = callback_error {
                    show_error(error.message());
                } else if authenticated {
                    load_current_configuration().await;
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
    install_route_link(&document, "brand-link", Route::System);
    install_route_link(&document, "system-status-link", Route::System);
    install_route_link(
        &document,
        "configuration-values-link",
        Route::Configuration(ConfigPath::root()),
    );
    if let Some(browser_window) = window() {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            render_route(&route_from_location());
            spawn_local(async { load_current_configuration().await });
        });
        let _ = browser_window
            .add_event_listener_with_callback("popstate", callback.as_ref().unchecked_ref());
        callback.forget();
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
            set_text("value-state", "Log in to view values");
            clear_value_rows();
            focus("login");
        });
        let _ = logout.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    install_configuration_actions(&document);
}

fn install_route_link(document: &Document, id: &str, route: Route) {
    if let Some(link) = document.get_element_by_id(id) {
        let callback = Closure::<dyn FnMut(_)>::new(move |event: Event| {
            event.prevent_default();
            navigate(&route);
        });
        let _ = link.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
}

fn install_configuration_actions(document: &Document) {
    if let Some(form) = document.get_element_by_id("path-form") {
        let callback = Closure::<dyn FnMut(_)>::new(|event: Event| {
            event.prevent_default();
            open_selected_path();
        });
        let _ = form.add_event_listener_with_callback("submit", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    install_path_selector_actions(document);
    if let Some(add) = document.get_element_by_id("add-value") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            show_new_value_row();
        });
        let _ = add.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(cancel) = document.get_element_by_id("cancel-new-value") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            hide_new_value_row();
            focus("add-value");
        });
        let _ = cancel.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(save) = document.get_element_by_id("save-new-value") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            spawn_local(async { save_new_value().await });
        });
        let _ = save.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(name) = document.get_element_by_id("new-value-name") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            validate_name_field();
            update_new_save_state();
        });
        let _ = name.add_event_listener_with_callback("input", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(value) = document.get_element_by_id("new-value-content") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            validate_value_field("new-value-content", "new-value-error");
            update_new_save_state();
        });
        let _ = value.add_event_listener_with_callback("input", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(cancel) = document.get_element_by_id("cancel-delete") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| cancel_delete());
        let _ = cancel.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(confirm) = document.get_element_by_id("confirm-delete") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            spawn_local(async { delete_selected_value().await });
        });
        let _ =
            confirm.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
}

fn install_path_selector_actions(document: &Document) {
    if let Some(path) = document.get_element_by_id("selected-path") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            validate_path_field();
            open_path_options();
            filter_path_options();
        });
        let _ = path.add_event_listener_with_callback("input", callback.as_ref().unchecked_ref());
        callback.forget();

        for event_name in ["focus", "pointerdown"] {
            let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
                open_path_options();
                spawn_local(async { refresh_path_options().await });
            });
            let _ = path
                .add_event_listener_with_callback(event_name, callback.as_ref().unchecked_ref());
            callback.forget();
        }

        let callback =
            Closure::<dyn FnMut(_)>::new(|event: KeyboardEvent| match event.key().as_str() {
                "ArrowDown" => {
                    event.prevent_default();
                    if !path_options_expanded() {
                        open_path_options();
                        filter_path_options();
                    }
                    move_active_path_option(1);
                }
                "ArrowUp" => {
                    event.prevent_default();
                    if !path_options_expanded() {
                        open_path_options();
                        filter_path_options();
                    }
                    move_active_path_option(-1);
                }
                "Enter" => {
                    event.prevent_default();
                    select_active_path_option();
                    open_selected_path();
                }
                "Escape" => {
                    event.prevent_default();
                    close_path_options();
                }
                "Tab" => close_path_options(),
                _ => {}
            });
        let _ = path.add_event_listener_with_callback("keydown", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    let callback = Closure::<dyn FnMut(_)>::new(|event: Event| {
        let inside_picker = event
            .target()
            .and_then(|target| target.dyn_into::<Element>().ok())
            .and_then(|target| target.closest(".path-picker").ok().flatten())
            .is_some();
        if !inside_picker {
            close_path_options();
        }
    });
    let _ =
        document.add_event_listener_with_callback("pointerdown", callback.as_ref().unchecked_ref());
    callback.forget();

    if let Some(browser_window) = window() {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            if !path_options_expanded() {
                return;
            }
            if let Some(input) = element::<HtmlInputElement>("selected-path")
                && let Some(options) = window()
                    .and_then(|window| window.document())
                    .and_then(|document| document.get_element_by_id("existing-paths"))
            {
                size_path_options(&input, &options);
            }
        });
        let _ = browser_window
            .add_event_listener_with_callback("resize", callback.as_ref().unchecked_ref());
        callback.forget();
    }
}

fn open_selected_path() {
    if let Ok(path) = selected_namespace() {
        close_path_options();
        navigate(&Route::Configuration(path));
    } else {
        validate_path_field();
    }
}

fn open_path_options() {
    let Some(input) = element::<HtmlInputElement>("selected-path") else {
        return;
    };
    let Some(options) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id("existing-paths"))
    else {
        return;
    };
    size_path_options(&input, &options);
    let _ = input.set_attribute("aria-expanded", "true");
    let _ = options.remove_attribute("hidden");
    for option in path_option_elements() {
        let _ = option.remove_attribute("hidden");
    }
    set_active_path_option(None);
}

fn path_options_expanded() -> bool {
    element::<HtmlInputElement>("selected-path")
        .is_some_and(|input| input.get_attribute("aria-expanded").as_deref() == Some("true"))
}

fn close_path_options() {
    if let Some(input) = element::<HtmlInputElement>("selected-path") {
        let _ = input.set_attribute("aria-expanded", "false");
        let _ = input.remove_attribute("aria-activedescendant");
    }
    set_hidden("existing-paths", true);
    set_active_path_option(None);
}

fn size_path_options(input: &HtmlInputElement, options: &Element) {
    let Some(window) = window() else {
        return;
    };
    let Some(viewport_height) = window
        .inner_height()
        .ok()
        .and_then(|height| height.as_f64())
    else {
        return;
    };
    let rect = input.get_bounding_client_rect();
    let below = (viewport_height - rect.bottom() - 12.0).max(48.0);
    let above = (rect.top() - 12.0).max(48.0);
    let opens_above = below < 240.0 && above > below;
    let available = if opens_above { above } else { below }.min(560.0);
    options.set_class_name(if opens_above {
        "path-options above"
    } else {
        "path-options"
    });
    if let Some(options) = options.dyn_ref::<web_sys::HtmlElement>() {
        let _ = options
            .style()
            .set_property("max-height", &format!("{available}px"));
    }
}

fn filter_path_options() {
    let Some(input) = element::<HtmlInputElement>("selected-path") else {
        return;
    };
    let query = input.value().to_ascii_lowercase();
    for option in path_option_elements() {
        let visible = option
            .get_attribute("data-path")
            .is_some_and(|path| path.starts_with(&query));
        if visible {
            let _ = option.remove_attribute("hidden");
        } else {
            let _ = option.set_attribute("hidden", "");
        }
    }
    set_active_path_option(None);
}

fn path_option_elements() -> Vec<Element> {
    let Some(options) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id("existing-paths"))
    else {
        return Vec::new();
    };
    let children = options.children();
    (0..children.length())
        .filter_map(|index| children.item(index))
        .collect()
}

fn move_active_path_option(direction: i32) {
    let visible = path_option_elements()
        .into_iter()
        .enumerate()
        .filter_map(|(index, option)| (!option.has_attribute("hidden")).then_some(index))
        .collect::<Vec<_>>();
    if visible.is_empty() {
        set_active_path_option(None);
        return;
    }
    let current = ACTIVE_PATH_OPTION.get();
    let position = current.and_then(|current| visible.iter().position(|index| *index == current));
    let next = match (position, direction) {
        (Some(0) | None, -1) => *visible.last().unwrap_or(&visible[0]),
        (Some(position), -1) => visible[position - 1],
        (Some(position), _) if position + 1 < visible.len() => visible[position + 1],
        _ => visible[0],
    };
    set_active_path_option(Some(next));
}

fn set_active_path_option(active_index: Option<usize>) {
    ACTIVE_PATH_OPTION.set(active_index);
    let options = path_option_elements();
    for (index, option) in options.iter().enumerate() {
        let active = Some(index) == active_index;
        option.set_class_name(if active {
            "path-option active"
        } else {
            "path-option"
        });
        let _ = option.set_attribute("aria-selected", if active { "true" } else { "false" });
    }
    let Some(input) = element::<HtmlInputElement>("selected-path") else {
        return;
    };
    if let Some(active) = active_index.and_then(|index| options.get(index)) {
        let _ = input.set_attribute("aria-activedescendant", &active.id());
        active.scroll_into_view_with_bool(false);
    } else {
        let _ = input.remove_attribute("aria-activedescendant");
    }
}

fn select_active_path_option() {
    let Some(index) = ACTIVE_PATH_OPTION.get() else {
        return;
    };
    let Some(path) = path_option_elements()
        .get(index)
        .and_then(|option| option.get_attribute("data-path"))
    else {
        return;
    };
    if let Some(input) = element::<HtmlInputElement>("selected-path") {
        input.set_value(&path);
        validate_path_field();
    }
    close_path_options();
}

fn navigate(route: &Route) {
    let url = route_url(route);
    if let Some(window) = window()
        && let Ok(history) = window.history()
    {
        let _ = history.push_state_with_url(&JsValue::NULL, "", Some(&url));
    }
    render_route(route);
    spawn_local(async { load_current_configuration().await });
}

fn render_route(route: &Route) {
    let configuration = matches!(route, Route::Configuration(_));
    set_hidden("system-page", configuration);
    set_hidden("configuration-page", !configuration);
    set_active("system-status-link", !configuration);
    set_active("configuration-values-link", configuration);
    if let Route::Configuration(path) = route {
        let canonical_url = route_url(route);
        if let Some(window) = window()
            && window.location().pathname().ok().as_deref() != Some(canonical_url.as_str())
            && let Ok(history) = window.history()
        {
            let _ = history.replace_state_with_url(&JsValue::NULL, "", Some(&canonical_url));
        }
        if let Some(input) = element::<HtmlInputElement>("selected-path") {
            input.set_value(&absolute_path(path));
        }
        validate_path_field();
    }
}

fn set_active(id: &str, active: bool) {
    if let Some(element) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id(id))
    {
        if active {
            element.set_class_name("active");
            let _ = element.set_attribute("aria-current", "page");
        } else {
            element.set_class_name("");
            let _ = element.remove_attribute("aria-current");
        }
    }
}

fn route_from_location() -> Route {
    let path = window()
        .and_then(|window| window.location().pathname().ok())
        .unwrap_or_else(|| "/".into());
    route_from_path(&path)
}

fn route_from_path(path: &str) -> Route {
    if path == "/configuration" || path == "/configuration/" {
        return Route::Configuration(ConfigPath::root());
    }
    if let Some(relative) = path.strip_prefix("/configuration/")
        && let Ok(path) = ConfigPath::parse_operation(relative)
    {
        return Route::Configuration(path);
    }
    Route::System
}

fn route_url(route: &Route) -> String {
    match route {
        Route::System => "/".into(),
        Route::Configuration(path) if path.as_str().is_empty() => "/configuration/".into(),
        Route::Configuration(path) => format!("/configuration/{}", path.as_str()),
    }
}

fn absolute_path(path: &ConfigPath) -> String {
    if path.as_str().is_empty() {
        "/".into()
    } else {
        format!("/{}", path.as_str())
    }
}

fn selected_namespace() -> Result<ConfigPath, ClientError> {
    let value = element::<HtmlInputElement>("selected-path")
        .ok_or_else(browser_error)?
        .value();
    parse_absolute_path(&value)
}

fn parse_absolute_path(value: &str) -> Result<ConfigPath, ClientError> {
    if value == "/" {
        return Ok(ConfigPath::root());
    }
    let relative = value.strip_prefix('/').ok_or_else(invalid_path)?;
    if relative.ends_with('/') {
        return Err(invalid_path());
    }
    ConfigPath::parse_operation(relative).map_err(|_| invalid_path())
}

fn invalid_path() -> ClientError {
    ClientError::new(
        ErrorKind::InvalidRequest,
        "path must begin with / and contain only letters, numbers, and hyphens",
    )
}

fn value_client(config: &AppConfig) -> Client<BrowserTransport, MemoryAuthentication> {
    Client::new(
        BrowserTransport,
        MemoryAuthentication {
            client_id: config.client_id.clone(),
        },
    )
}

async fn load_current_configuration() {
    let Route::Configuration(path) = route_from_location() else {
        return;
    };
    clear_error();
    set_text("value-state", "Loading");
    let result = async {
        let config = app_config()?;
        value_client(&config).list_values(&path).await
    }
    .await;
    match result {
        Ok(listing) => {
            if let Err(error) = render_listing(&listing) {
                show_error(error.message());
                return;
            }
            set_text("value-state", "Loaded");
        }
        Err(error) => show_error(error.message()),
    }
}

async fn refresh_path_options() {
    if PATH_OPTIONS_REFRESHING.replace(true) {
        return;
    }
    let result = async {
        let Route::Configuration(path) = route_from_location() else {
            return Ok(None);
        };
        let config = app_config()?;
        value_client(&config).list_values(&path).await.map(Some)
    }
    .await;
    PATH_OPTIONS_REFRESHING.set(false);
    match result {
        Ok(Some(listing)) => {
            if let Err(error) = render_path_options(&listing) {
                show_error(error.message());
            }
        }
        Ok(None) => {}
        Err(error) => show_error(error.message()),
    }
}

async fn save_new_value() {
    if !validate_name_field() || !validate_value_field("new-value-content", "new-value-error") {
        return;
    }
    clear_error();
    let result = async {
        let config = app_config()?;
        let namespace = selected_namespace()?;
        let name = element::<HtmlInputElement>("new-value-name")
            .ok_or_else(browser_error)?
            .value();
        let path = namespace.join_operation(name).map_err(|_| invalid_path())?;
        let value = element::<HtmlTextAreaElement>("new-value-content")
            .ok_or_else(browser_error)?
            .value();
        value_client(&config)
            .put_value(&path, &PlainValue::new(value))
            .await
    }
    .await;
    match result {
        Ok(_) => {
            hide_new_value_row();
            load_current_configuration().await;
            set_text("value-state", "Saved");
            focus("add-value");
        }
        Err(error) => show_error(error.message()),
    }
}

async fn save_existing_value(path: ConfigPath, input_id: String) {
    let error_id = format!("{input_id}-error");
    if !validate_value_field(&input_id, &error_id) {
        return;
    }
    clear_error();
    let result = async {
        let config = app_config()?;
        let value = element::<HtmlTextAreaElement>(&input_id)
            .ok_or_else(browser_error)?
            .value();
        value_client(&config)
            .put_value(&path, &PlainValue::new(value))
            .await
    }
    .await;
    match result {
        Ok(_) => {
            load_current_configuration().await;
            set_text("value-state", "Saved");
            focus("values-heading");
        }
        Err(error) => show_error(error.message()),
    }
}

fn open_delete(path: ConfigPath, return_focus: String) {
    set_text("delete-path", &absolute_path(&path));
    DELETE_TARGET.with_borrow_mut(|target| {
        *target = Some(DeleteTarget { path, return_focus });
    });
    if let Some(dialog) = element::<HtmlDialogElement>("delete-dialog") {
        let _ = dialog.show_modal();
        focus("cancel-delete");
    }
}

fn cancel_delete() {
    let return_focus = DELETE_TARGET
        .with_borrow_mut(Option::take)
        .map(|target| target.return_focus);
    close_delete_dialog();
    if let Some(return_focus) = return_focus {
        focus(&return_focus);
    }
}

async fn delete_selected_value() {
    let Some(target) = DELETE_TARGET.with_borrow_mut(Option::take) else {
        return;
    };
    clear_error();
    let result = async {
        let config = app_config()?;
        value_client(&config).delete_value(&target.path).await
    }
    .await;
    close_delete_dialog();
    match result {
        Ok(_) => {
            load_current_configuration().await;
            set_text("value-state", "Deleted");
            focus("add-value");
        }
        Err(error) => {
            show_error(error.message());
            focus(&target.return_focus);
        }
    }
}

fn close_delete_dialog() {
    if let Some(dialog) = element::<HtmlDialogElement>("delete-dialog") {
        dialog.close();
    }
}

fn render_listing(listing: &ValueListing) -> Result<(), ClientError> {
    clear_value_rows();
    hide_new_value_row();
    render_path_options(listing)?;
    let document = window()
        .and_then(|window| window.document())
        .ok_or_else(browser_error)?;
    let body = document
        .get_element_by_id("values-body")
        .ok_or_else(browser_error)?;
    for (index, value) in listing.values.iter().enumerate() {
        let row = render_value_row(&document, value, index)?;
        append(&body, &row)?;
    }
    let count = listing.values.len();
    set_text(
        "value-count",
        &format!("{count} {}", if count == 1 { "value" } else { "values" }),
    );
    set_hidden("empty-values", count != 0);
    Ok(())
}

fn render_path_options(listing: &ValueListing) -> Result<(), ClientError> {
    let document = window()
        .and_then(|window| window.document())
        .ok_or_else(browser_error)?;
    let options = document
        .get_element_by_id("existing-paths")
        .ok_or_else(browser_error)?;
    options.set_text_content(None);
    let mut paths = listing
        .paths
        .iter()
        .map(absolute_path)
        .collect::<BTreeSet<_>>();
    paths.insert("/".into());
    if let Ok(selected) = selected_namespace() {
        paths.insert(absolute_path(&selected));
    }
    for (index, path) in paths.into_iter().enumerate() {
        let option = document
            .create_element("div")
            .map_err(|_| browser_error())?;
        option.set_class_name("path-option");
        option
            .set_attribute("id", &format!("existing-path-{index}"))
            .map_err(|_| browser_error())?;
        option
            .set_attribute("role", "option")
            .map_err(|_| browser_error())?;
        option
            .set_attribute("aria-selected", "false")
            .map_err(|_| browser_error())?;
        option
            .set_attribute("data-path", &path)
            .map_err(|_| browser_error())?;
        option.set_text_content(Some(&path));
        let selected_path = path;
        let callback = Closure::<dyn FnMut(_)>::new(move |event: Event| {
            event.prevent_default();
            if let Some(input) = element::<HtmlInputElement>("selected-path") {
                input.set_value(&selected_path);
                validate_path_field();
                close_path_options();
                focus("selected-path");
            }
        });
        option
            .add_event_listener_with_callback("pointerdown", callback.as_ref().unchecked_ref())
            .map_err(|_| browser_error())?;
        callback.forget();
        options.append_child(&option).map_err(|_| browser_error())?;
    }
    if path_options_expanded() {
        open_path_options();
    }
    Ok(())
}

fn render_value_row(
    document: &Document,
    value: &ListedValue,
    index: usize,
) -> Result<Element, ClientError> {
    let row = create_element(document, "tr", None)?;
    row.set_attribute("data-value-row", "")
        .map_err(|_| browser_error())?;

    let name_cell = create_element(document, "th", None)?;
    name_cell
        .set_attribute("scope", "row")
        .map_err(|_| browser_error())?;
    let name = value
        .path
        .as_str()
        .rsplit_once('/')
        .map_or(value.path.as_str(), |(_, name)| name);
    let name_text = create_element(document, "span", Some("value-name"))?;
    name_text.set_text_content(Some(name));
    let full_path = create_element(document, "span", Some("full-path"))?;
    full_path.set_text_content(Some(&absolute_path(&value.path)));
    append(&name_cell, &name_text)?;
    append(&name_cell, &full_path)?;

    let value_cell = create_element(document, "td", None)?;
    let input_id = format!("listed-value-{index}");
    let error_id = format!("{input_id}-error");
    let editor = create_element(document, "textarea", None)?;
    editor
        .set_attribute("id", &input_id)
        .map_err(|_| browser_error())?;
    editor
        .set_attribute("rows", "2")
        .map_err(|_| browser_error())?;
    editor
        .set_attribute("spellcheck", "false")
        .map_err(|_| browser_error())?;
    editor
        .set_attribute("aria-label", &format!("Value for {name}"))
        .map_err(|_| browser_error())?;
    editor
        .set_attribute("aria-describedby", &error_id)
        .map_err(|_| browser_error())?;
    editor
        .clone()
        .dyn_into::<HtmlTextAreaElement>()
        .map_err(|_| browser_error())?
        .set_value(value.value.expose());
    let field_error = create_element(document, "p", Some("field-error"))?;
    field_error
        .set_attribute("id", &error_id)
        .map_err(|_| browser_error())?;
    field_error
        .set_attribute("hidden", "")
        .map_err(|_| browser_error())?;
    field_error
        .set_attribute("aria-live", "polite")
        .map_err(|_| browser_error())?;
    append(&value_cell, &editor)?;
    append(&value_cell, &field_error)?;

    let updated = create_element(document, "td", Some("updated-time"))?;
    updated.set_text_content(Some(&format_timestamp(value.updated_at)));

    let actions_cell = create_element(document, "td", None)?;
    let actions = create_element(document, "div", Some("row-actions"))?;
    let save_id = format!("save-listed-value-{index}");
    let save = create_button(document, &save_id, "Save", None)?;
    let remove_id = format!("delete-listed-value-{index}");
    let remove = create_button(document, &remove_id, "Delete", Some("danger"))?;
    append(&actions, &save)?;
    append(&actions, &remove)?;
    append(&actions_cell, &actions)?;

    let save_path = value.path.clone();
    let save_input = input_id.clone();
    let callback = Closure::<dyn FnMut(_)>::new(move |_: Event| {
        let path = save_path.clone();
        let input = save_input.clone();
        spawn_local(async move { save_existing_value(path, input).await });
    });
    save.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())
        .map_err(|_| browser_error())?;
    callback.forget();

    let validation_input = input_id.clone();
    let validation_error = error_id.clone();
    let validation_save = save_id.clone();
    let callback = Closure::<dyn FnMut(_)>::new(move |_: Event| {
        let valid = validate_value_field(&validation_input, &validation_error);
        set_button_disabled(&validation_save, !valid);
    });
    editor
        .add_event_listener_with_callback("input", callback.as_ref().unchecked_ref())
        .map_err(|_| browser_error())?;
    callback.forget();

    let delete_path = value.path.clone();
    let delete_focus = remove_id;
    let callback = Closure::<dyn FnMut(_)>::new(move |_: Event| {
        open_delete(delete_path.clone(), delete_focus.clone());
    });
    remove
        .add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())
        .map_err(|_| browser_error())?;
    callback.forget();

    append(&row, &name_cell)?;
    append(&row, &value_cell)?;
    append(&row, &updated)?;
    append(&row, &actions_cell)?;
    Ok(row)
}

fn create_element(
    document: &Document,
    tag: &str,
    class_name: Option<&str>,
) -> Result<Element, ClientError> {
    let element = document.create_element(tag).map_err(|_| browser_error())?;
    if let Some(class_name) = class_name {
        element.set_class_name(class_name);
    }
    Ok(element)
}

fn create_button(
    document: &Document,
    id: &str,
    label: &str,
    class_name: Option<&str>,
) -> Result<Element, ClientError> {
    let button = create_element(document, "button", class_name)?;
    button
        .set_attribute("id", id)
        .map_err(|_| browser_error())?;
    button
        .set_attribute("type", "button")
        .map_err(|_| browser_error())?;
    button.set_text_content(Some(label));
    Ok(button)
}

fn append(parent: &Element, child: &Element) -> Result<(), ClientError> {
    parent
        .append_child(child)
        .map(|_| ())
        .map_err(|_| browser_error())
}

fn clear_value_rows() {
    let Some(body) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id("values-body"))
    else {
        return;
    };
    while let Some(row) = body.last_element_child() {
        if row.id() == "new-value-row" {
            break;
        }
        row.remove();
    }
    set_text("value-count", "0 values");
    set_hidden("empty-values", false);
}

fn show_new_value_row() {
    set_textarea("new-value-content", "");
    if let Some(name) = element::<HtmlInputElement>("new-value-name") {
        name.set_value("");
    }
    set_hidden("new-value-row", false);
    validate_name_field();
    validate_value_field("new-value-content", "new-value-error");
    update_new_save_state();
    focus("new-value-name");
}

fn hide_new_value_row() {
    set_hidden("new-value-row", true);
    set_validation("new-value-name", "new-name-error", None);
    set_validation("new-value-content", "new-value-error", None);
}

fn validate_path_field() -> bool {
    let Some(input) = element::<HtmlInputElement>("selected-path") else {
        return false;
    };
    let message = parse_absolute_path(&input.value())
        .err()
        .map(|error| error.message());
    set_validation("selected-path", "path-error", message);
    message.is_none()
}

fn validate_name_field() -> bool {
    let Some(input) = element::<HtmlInputElement>("new-value-name") else {
        return false;
    };
    let message =
        if ConfigPath::parse_operation(input.value()).is_ok() && !input.value().contains('/') {
            None
        } else {
            Some("Name must contain only letters, numbers, and hyphens")
        };
    set_validation("new-value-name", "new-name-error", message);
    message.is_none()
}

fn validate_value_field(input_id: &str, error_id: &str) -> bool {
    let Some(input) = element::<HtmlTextAreaElement>(input_id) else {
        return false;
    };
    let message = input
        .value()
        .contains('\0')
        .then_some("Value cannot contain a null character");
    set_validation(input_id, error_id, message);
    message.is_none()
}

fn set_validation(input_id: &str, error_id: &str, message: Option<&str>) {
    if let Some(input) = element::<HtmlInputElement>(input_id) {
        input.set_custom_validity(message.unwrap_or_default());
        let _ = input.set_attribute(
            "aria-invalid",
            if message.is_some() { "true" } else { "false" },
        );
    } else if let Some(input) = element::<HtmlTextAreaElement>(input_id) {
        input.set_custom_validity(message.unwrap_or_default());
        let _ = input.set_attribute(
            "aria-invalid",
            if message.is_some() { "true" } else { "false" },
        );
    }
    set_text(error_id, message.unwrap_or_default());
    set_hidden(error_id, message.is_none());
}

fn update_new_save_state() {
    let name_valid = element::<HtmlInputElement>("new-value-name")
        .is_some_and(|input| !input.value().is_empty() && input.check_validity());
    let value_valid = element::<HtmlTextAreaElement>("new-value-content")
        .is_some_and(|input| input.check_validity());
    set_button_disabled("save-new-value", !(name_valid && value_valid));
}

#[allow(clippy::cast_precision_loss)]
fn format_timestamp(timestamp: Timestamp) -> String {
    let milliseconds = timestamp.seconds as f64 * 1000.0 + f64::from(timestamp.nanos) / 1_000_000.0;
    let date = Date::new(&JsValue::from_f64(milliseconds));
    String::from(date.to_locale_string("en-GB", &JsValue::UNDEFINED))
}

async fn refresh_status(config: &AppConfig) -> bool {
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
            true
        }
        Ok(_) => {
            set_text("auth-value", "Logged out");
            set_hidden("login", false);
            set_hidden("logout", true);
            false
        }
        Err(error) if error.kind == ErrorKind::Unauthenticated => {
            clear_browser_session();
            set_text("auth-value", "Logged out");
            set_hidden("login", false);
            set_hidden("logout", true);
            show_error(error.message());
            false
        }
        Err(error) => {
            set_text("auth-value", "Unavailable");
            set_hidden("login", true);
            set_hidden("logout", false);
            show_error(error.message());
            false
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

fn set_hidden(id: &str, hidden: bool) {
    if let Some(element) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id(id))
    {
        let _ = element.set_attribute("aria-hidden", if hidden { "true" } else { "false" });
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

    use super::{
        Route, classify_refresh_error, decode_grpc_web, decode_grpc_web_response,
        parse_absolute_path, route_from_path, route_url,
    };

    #[test]
    fn absolute_configuration_paths_drive_canonical_routes() {
        assert_eq!(parse_absolute_path("/").unwrap().as_str(), "");
        assert_eq!(
            parse_absolute_path("/Apps/API").unwrap().as_str(),
            "apps/api"
        );
        for invalid in ["", "apps/api", "/apps/", "/apps/bad_name", "//apps"] {
            assert!(
                parse_absolute_path(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
        let route = route_from_path("/configuration/Apps/API");
        assert_eq!(route_url(&route), "/configuration/apps/api");
        assert!(matches!(route_from_path("/unknown"), Route::System));
    }

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
