//! The Configuration view: loading a path, JSON mode, saving, deleting and aliasing values, and field validation.

use crate::browser::app_config;
use crate::browser::browser_error;
use crate::dom::clear_error;
use crate::dom::element;
use crate::dom::focus;
use crate::dom::set_button_disabled;
use crate::dom::set_hidden;
use crate::dom::set_loaded_textarea;
use crate::dom::set_text;
use crate::dom::set_textarea;
use crate::dom::show_error;
use crate::path_selector::install_path_selector_actions;
use crate::path_selector::open_selected_path;
use crate::route::Route;
use crate::route::reload_configuration;
use crate::route::route_from_location;
use crate::transport::value_client;
use crate::value_rows::clear_value_rows;
use crate::value_rows::lock_secret_field;
use crate::value_rows::render_listing;
use crate::value_rows::set_secret_toggle;
use crate::value_rows::toggle_secret_input;
use js_sys::Date;
use sovereign_config_core::ClientError;
use sovereign_config_core::ConfigPath;
use sovereign_config_core::ErrorKind;
use sovereign_config_core::PlainValue;
use sovereign_config_core::SecretInput;
use sovereign_config_core::Timestamp;
use sovereign_config_core::ValueListing;
use sovereign_config_core::ValueSubTree;
use sovereign_config_core::parse_subtree_json;
use sovereign_config_core::render_subtree_json;
use std::cell::Cell;
use std::cell::RefCell;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen::closure::Closure;
use wasm_bindgen_futures::spawn_local;
use web_sys::Document;
use web_sys::Event;
use web_sys::HtmlDialogElement;
use web_sys::HtmlInputElement;
use web_sys::HtmlTextAreaElement;

thread_local! {
    pub(crate) static DELETE_TARGET: RefCell<Option<DeleteTarget>> = const { RefCell::new(None) };
    pub(crate) static ADD_PATH_TARGET: RefCell<Option<AddPathTarget>> = const { RefCell::new(None) };
    pub(crate) static JSON_MODE: Cell<bool> = const { Cell::new(false) };
    pub(crate) static CONFIGURATION_LOAD_GENERATION: Cell<u64> = const { Cell::new(0) };
}

pub(crate) struct DeleteTarget {
    pub(crate) path: ConfigPath,
    pub(crate) return_focus: String,
}

/// The value selected for a pending "add path" confirmation. The source path
/// identifies the stored value; the new path is read from the dialog input.
#[derive(Clone)]
pub(crate) struct AddPathTarget {
    pub(crate) source: ConfigPath,
    pub(crate) return_focus: String,
}

pub(crate) fn install_configuration_actions(document: &Document) {
    if let Some(form) = document.get_element_by_id("path-form") {
        let callback = Closure::<dyn FnMut(_)>::new(|event: Event| {
            event.prevent_default();
            open_selected_path();
        });
        let _ = form.add_event_listener_with_callback("submit", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    install_path_selector_actions(document);
    if let Some(mode) = document.get_element_by_id("json-mode") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            let enabled =
                element::<HtmlInputElement>("json-mode").is_some_and(|input| input.checked());
            JSON_MODE.set(enabled);
            update_configuration_mode();
            spawn_local(async { load_current_configuration().await });
        });
        let _ = mode.add_event_listener_with_callback("change", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(save) = document.get_element_by_id("save-json") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            spawn_local(async { save_json_subtree().await });
        });
        let _ = save.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(editor) = document.get_element_by_id("json-content") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            CONFIGURATION_LOAD_GENERATION.set(CONFIGURATION_LOAD_GENERATION.get().wrapping_add(1));
            set_text("value-state", "Edited");
            validate_json_editor();
        });
        let _ = editor.add_event_listener_with_callback("input", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(add) = document.get_element_by_id("add-value") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            show_new_value_row();
        });
        let _ = add.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(classification) = document.get_element_by_id("new-value-secret") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            update_new_value_classification();
        });
        let _ = classification
            .add_event_listener_with_callback("change", callback.as_ref().unchecked_ref());
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
    if let Some(value) = document.get_element_by_id("new-secret-content") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            validate_secret_field("new-secret-content", "new-value-error");
            update_new_save_state();
        });
        let _ = value.add_event_listener_with_callback("input", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(toggle) = document.get_element_by_id("toggle-new-secret") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            toggle_secret_input("new-secret-content", "toggle-new-secret");
        });
        let _ = toggle.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
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
    if let Some(cancel) = document.get_element_by_id("cancel-add-path") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| cancel_add_path());
        let _ = cancel.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(confirm) = document.get_element_by_id("confirm-add-path") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            spawn_local(async { add_selected_path().await });
        });
        let _ =
            confirm.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
}

pub(crate) fn absolute_path(path: &ConfigPath) -> String {
    path.as_str().to_owned()
}

pub(crate) fn selected_namespace() -> Result<ConfigPath, ClientError> {
    let value = element::<HtmlInputElement>("selected-path")
        .ok_or_else(browser_error)?
        .value();
    parse_absolute_path(&value)
}

pub(crate) fn parse_absolute_path(value: &str) -> Result<ConfigPath, ClientError> {
    if value == "/" {
        return Ok(ConfigPath::root());
    }
    ConfigPath::parse_operation(value).map_err(|_| invalid_path())
}

pub(crate) fn invalid_path() -> ClientError {
    ClientError::new(
        ErrorKind::InvalidRequest,
        "path must begin with / and contain only letters, numbers, hyphens, and underscores",
    )
}

pub(crate) async fn load_current_configuration() {
    let generation = CONFIGURATION_LOAD_GENERATION.get().wrapping_add(1);
    CONFIGURATION_LOAD_GENERATION.set(generation);
    hide_new_value_row();
    clear_value_rows();
    set_loaded_textarea("json-content", "");
    let Route::Configuration(path) = route_from_location() else {
        return;
    };
    clear_error();
    set_text("value-state", "Loading");
    let json_mode = JSON_MODE.get();
    update_configuration_mode();
    if json_mode {
        set_loaded_textarea("json-content", "");
        set_validation("json-content", "json-error", None);
        set_text("value-count", "0 values");
    }
    let result = async {
        let config = app_config()?;
        if json_mode {
            value_client(&config)
                .get_subtree(&path)
                .await
                .map(ConfigurationData::SubTree)
        } else {
            value_client(&config)
                .list_values(&path)
                .await
                .map(ConfigurationData::Listing)
        }
    }
    .await;
    if CONFIGURATION_LOAD_GENERATION.get() != generation {
        return;
    }
    match result {
        Ok(ConfigurationData::Listing(listing)) => {
            if let Err(error) = render_listing(&listing) {
                show_error(error.message());
                return;
            }
            set_text("value-state", "Loaded");
        }
        Ok(ConfigurationData::SubTree(subtree)) => {
            match render_subtree_json(&path, &subtree.values) {
                Ok(json) => {
                    set_loaded_textarea("json-content", &json);
                    set_validation("json-content", "json-error", None);
                    let count = subtree.values.len();
                    set_text(
                        "value-count",
                        &format!("{count} {}", if count == 1 { "value" } else { "values" }),
                    );
                    set_text("value-state", "Loaded");
                }
                Err(error) => show_error(error.message()),
            }
        }
        Err(error) => show_error(error.message()),
    }
}

pub(crate) enum ConfigurationData {
    Listing(ValueListing),
    SubTree(ValueSubTree),
}

pub(crate) fn update_configuration_mode() {
    let json = JSON_MODE.get();
    set_hidden("value-table", json);
    set_hidden("json-editor", !json);
    set_hidden("add-value", json);
    if json {
        set_hidden("empty-values", true);
        hide_new_value_row();
    }
}

pub(crate) fn validate_json_editor() -> bool {
    let result = (|| {
        let Route::Configuration(path) = route_from_location() else {
            return Err(browser_error());
        };
        let json = element::<HtmlTextAreaElement>("json-content")
            .ok_or_else(browser_error)?
            .value();
        parse_subtree_json(&path, &json).map(|_| ())
    })();
    match result {
        Ok(()) => {
            set_validation("json-content", "json-error", None);
            set_button_disabled("save-json", false);
            true
        }
        Err(error) => {
            set_validation("json-content", "json-error", Some(error.message()));
            set_button_disabled("save-json", true);
            false
        }
    }
}

pub(crate) async fn save_json_subtree() {
    if !validate_json_editor() {
        return;
    }
    clear_error();
    set_button_disabled("save-json", true);
    let result = async {
        let Route::Configuration(path) = route_from_location() else {
            return Err(browser_error());
        };
        let json = element::<HtmlTextAreaElement>("json-content")
            .ok_or_else(browser_error)?
            .value();
        let values = parse_subtree_json(&path, &json)?;
        let config = app_config()?;
        value_client(&config).replace_subtree(&path, &values).await
    }
    .await;
    match result {
        Ok(_) => {
            reload_configuration().await;
            set_text("value-state", "Saved");
            focus("json-content");
        }
        Err(error) => {
            set_button_disabled("save-json", false);
            show_error(error.message());
        }
    }
}

pub(crate) async fn save_new_value() {
    let secret =
        element::<HtmlInputElement>("new-value-secret").is_some_and(|input| input.checked());
    let value_valid = if secret {
        validate_secret_field("new-secret-content", "new-value-error")
    } else {
        validate_value_field("new-value-content", "new-value-error")
    };
    if !validate_name_field() || !value_valid {
        return;
    }
    clear_error();
    let result = async {
        let config = app_config()?;
        let namespace = selected_namespace()?;
        let name = element::<HtmlInputElement>("new-value-name")
            .ok_or_else(browser_error)?
            .value();
        let path = namespace.join_name(name).map_err(|_| invalid_path())?;
        if secret {
            let value = element::<HtmlInputElement>("new-secret-content")
                .ok_or_else(browser_error)?
                .value();
            value_client(&config)
                .put_secret(&path, &SecretInput::new(value))
                .await
        } else {
            let value = element::<HtmlTextAreaElement>("new-value-content")
                .ok_or_else(browser_error)?
                .value();
            value_client(&config)
                .put_value(&path, &PlainValue::new(value))
                .await
        }
    }
    .await;
    match result {
        Ok(_) => {
            hide_new_value_row();
            reload_configuration().await;
            set_text("value-state", "Saved");
            focus("add-value");
        }
        Err(error) => {
            if let Some(input) = element::<HtmlInputElement>("new-secret-content") {
                input.set_value("");
            }
            show_error(error.message());
        }
    }
}

pub(crate) async fn save_existing_value(path: ConfigPath, input_id: String) {
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
            reload_configuration().await;
            set_text("value-state", "Saved");
            focus("values-heading");
        }
        Err(error) => show_error(error.message()),
    }
}

/// Writes whatever the padlocked field holds as the value's new secret. The
/// field is cleared before the request goes out, so a failure cannot leave the
/// typed secret sitting in the DOM.
pub(crate) async fn save_existing_secret(path: ConfigPath, input_id: String) {
    clear_error();
    let result = async {
        let config = app_config()?;
        let input = element::<HtmlInputElement>(&input_id).ok_or_else(browser_error)?;
        let value = input.value();
        // A locked box reads as filled — its placeholder is `********` — but it
        // holds nothing until the padlock is opened or a replacement is typed.
        // The server accepts an empty secret without complaint, so a stray
        // click on Save must not turn that emptiness into the stored value.
        if value.is_empty() {
            return Err(ClientError::new(
                ErrorKind::InvalidRequest,
                "type a replacement secret before saving",
            ));
        }
        input.set_value("");
        value_client(&config)
            .put_secret(&path, &SecretInput::new(value))
            .await
    }
    .await;
    match result {
        Ok(_) => {
            reload_configuration().await;
            set_text("value-state", "Saved");
            focus("values-heading");
        }
        Err(error) => {
            if let Some(input) = element::<HtmlInputElement>(&input_id) {
                input.set_value("");
            }
            show_error(error.message());
        }
    }
}

/// Opens a secret's padlock: fetches the stored value into the field and leaves
/// it unmasked and editable, so a replacement is typed over what is there.
pub(crate) async fn reveal_existing_secret(path: ConfigPath, input_id: String, button_id: String) {
    let generation = CONFIGURATION_LOAD_GENERATION.get();
    let route_path = match route_from_location() {
        Route::Configuration(path) => path,
        Route::Connections | Route::Downloads => return,
    };
    clear_error();
    lock_secret_field(&input_id, &button_id);
    let result = async {
        let config = app_config()?;
        value_client(&config).reveal_secret(&path).await
    }
    .await;
    let current_path = match route_from_location() {
        Route::Configuration(path) => path,
        Route::Connections | Route::Downloads => return,
    };
    if generation != CONFIGURATION_LOAD_GENERATION.get() || current_path != route_path {
        return;
    }
    match result {
        Ok(value) => {
            let Some(input) = element::<HtmlInputElement>(&input_id) else {
                return;
            };
            input.set_value(value.expose());
            input.set_type("text");
            let _ = input.set_attribute("data-secret-state", "revealed");
            // What the field now holds is exactly what the service holds, so an
            // untouched revealed box is not an unsaved edit.
            //
            // Accepted tradeoff: unlike `.value`, an attribute serializes into
            // `outerHTML`, so a revealed secret is briefly readable through
            // DOM-inspection tooling (devtools, a snapshot, `page.content()`) in
            // a way the old textarea-based control never was. Not remotely
            // reachable — CSP is `script-src 'self' 'wasm-unsafe-eval'`, and the
            // plaintext is already on screen at this point regardless — and
            // `lock_secret_field` scrubs it back to `""` on close, error,
            // logout, reload and navigation, same as the field itself. Judged
            // not worth a Rust-side baseline map to close a window this narrow.
            let _ = input.set_attribute("data-loaded", value.expose());
            set_secret_toggle(&button_id, true);
            focus(&input_id);
        }
        Err(error) => {
            lock_secret_field(&input_id, &button_id);
            show_error(error.message());
        }
    }
}

pub(crate) fn open_delete(path: ConfigPath, return_focus: String) {
    set_text("delete-path", &absolute_path(&path));
    DELETE_TARGET.with_borrow_mut(|target| {
        *target = Some(DeleteTarget { path, return_focus });
    });
    if let Some(dialog) = element::<HtmlDialogElement>("delete-dialog") {
        let _ = dialog.show_modal();
        focus("cancel-delete");
    }
}

pub(crate) fn cancel_delete() {
    let return_focus = DELETE_TARGET
        .with_borrow_mut(Option::take)
        .map(|target| target.return_focus);
    close_delete_dialog();
    if let Some(return_focus) = return_focus {
        focus(&return_focus);
    }
}

pub(crate) async fn delete_selected_value() {
    let Some(target) = DELETE_TARGET.with_borrow_mut(Option::take) else {
        return;
    };
    clear_error();
    let result = async {
        let config = app_config()?;
        value_client(&config)
            .delete_values(&target.path, false)
            .await
    }
    .await;
    close_delete_dialog();
    match result {
        Ok(_) => {
            reload_configuration().await;
            set_text("value-state", "Deleted");
            focus("add-value");
        }
        Err(error) => {
            show_error(error.message());
            focus(&target.return_focus);
        }
    }
}

pub(crate) fn close_delete_dialog() {
    if let Some(dialog) = element::<HtmlDialogElement>("delete-dialog") {
        dialog.close();
    }
}

pub(crate) fn open_add_path(source: ConfigPath, return_focus: String) {
    set_text("add-path-source", &absolute_path(&source));
    if let Some(input) = element::<HtmlInputElement>("add-path-input") {
        input.set_value("");
    }
    set_hidden("add-path-error", true);
    ADD_PATH_TARGET.with_borrow_mut(|target| {
        *target = Some(AddPathTarget {
            source,
            return_focus,
        });
    });
    if let Some(dialog) = element::<HtmlDialogElement>("add-path-dialog") {
        let _ = dialog.show_modal();
        focus("add-path-input");
    }
}

pub(crate) fn cancel_add_path() {
    let return_focus = ADD_PATH_TARGET
        .with_borrow_mut(Option::take)
        .map(|target| target.return_focus);
    close_add_path_dialog();
    if let Some(return_focus) = return_focus {
        focus(&return_focus);
    }
}

pub(crate) async fn add_selected_path() {
    // Inspect the target without consuming it so a malformed path can be
    // corrected in place, then take it before awaiting: a second activation
    // while the request is in flight would otherwise send the same alias twice,
    // and the duplicate's conflict would report a failure for a mutation that
    // actually succeeded.
    let Some(target) = ADD_PATH_TARGET.with_borrow(Clone::clone) else {
        return;
    };
    let entered = element::<HtmlInputElement>("add-path-input")
        .map(|input| input.value())
        .unwrap_or_default();
    let Ok(new_path) = ConfigPath::parse_operation(entered.trim()) else {
        set_text(
            "add-path-error",
            "Enter an absolute path such as /apps/worker/database-url.",
        );
        set_hidden("add-path-error", false);
        focus("add-path-input");
        return;
    };
    ADD_PATH_TARGET.with_borrow_mut(Option::take);
    set_button_disabled("confirm-add-path", true);
    clear_error();
    let result = async {
        let config = app_config()?;
        value_client(&config)
            .add_value_path(&target.source, &new_path)
            .await
    }
    .await;
    // Re-enable for the next time the dialog opens; the target stays consumed so
    // a retry starts from the row, as a failed delete does.
    set_button_disabled("confirm-add-path", false);
    close_add_path_dialog();
    match result {
        Ok(_) => {
            reload_configuration().await;
            set_text("value-state", "Path added");
            focus("add-value");
        }
        Err(error) => {
            show_error(error.message());
            focus(&target.return_focus);
        }
    }
}

pub(crate) fn close_add_path_dialog() {
    if let Some(dialog) = element::<HtmlDialogElement>("add-path-dialog") {
        dialog.close();
    }
}

pub(crate) fn show_new_value_row() {
    set_textarea("new-value-content", "");
    if let Some(secret) = element::<HtmlInputElement>("new-value-secret") {
        secret.set_checked(false);
    }
    lock_secret_field("new-secret-content", "toggle-new-secret");
    update_new_value_classification();
    if let Some(name) = element::<HtmlInputElement>("new-value-name") {
        name.set_value("");
    }
    set_hidden("new-value-row", false);
    validate_name_field();
    validate_value_field("new-value-content", "new-value-error");
    update_new_save_state();
    focus("new-value-name");
}

pub(crate) fn hide_new_value_row() {
    set_hidden("new-value-row", true);
    set_textarea("new-value-content", "");
    lock_secret_field("new-secret-content", "toggle-new-secret");
    set_validation("new-value-name", "new-name-error", None);
    set_validation("new-value-content", "new-value-error", None);
}

pub(crate) fn update_new_value_classification() {
    let secret =
        element::<HtmlInputElement>("new-value-secret").is_some_and(|input| input.checked());
    set_hidden("new-value-content", secret);
    set_hidden("new-secret-field", !secret);
    set_validation("new-value-content", "new-value-error", None);
    set_validation("new-secret-content", "new-value-error", None);
    update_new_save_state();
}

pub(crate) fn validate_path_field() -> bool {
    let Some(input) = element::<HtmlInputElement>("selected-path") else {
        return false;
    };
    let message = parse_absolute_path(&input.value())
        .err()
        .map(|error| error.message());
    set_validation("selected-path", "path-error", message);
    message.is_none()
}

pub(crate) fn validate_name_field() -> bool {
    let Some(input) = element::<HtmlInputElement>("new-value-name") else {
        return false;
    };
    let message = if ConfigPath::root().join_name(input.value()).is_ok() {
        None
    } else {
        Some("Name must contain only letters, numbers, hyphens, and underscores")
    };
    set_validation("new-value-name", "new-name-error", message);
    message.is_none()
}

pub(crate) fn validate_value_field(input_id: &str, error_id: &str) -> bool {
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

pub(crate) fn validate_secret_field(input_id: &str, error_id: &str) -> bool {
    let Some(input) = element::<HtmlInputElement>(input_id) else {
        return false;
    };
    let message = input
        .value()
        .contains('\0')
        .then_some("Secret cannot contain a null character");
    set_validation(input_id, error_id, message);
    message.is_none()
}

pub(crate) fn set_validation(input_id: &str, error_id: &str, message: Option<&str>) {
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

pub(crate) fn update_new_save_state() {
    let name_valid = element::<HtmlInputElement>("new-value-name")
        .is_some_and(|input| !input.value().is_empty() && input.check_validity());
    let secret =
        element::<HtmlInputElement>("new-value-secret").is_some_and(|input| input.checked());
    let value_valid = if secret {
        element::<HtmlInputElement>("new-secret-content")
            .is_some_and(|input| input.check_validity())
    } else {
        element::<HtmlTextAreaElement>("new-value-content")
            .is_some_and(|input| input.check_validity())
    };
    set_button_disabled("save-new-value", !(name_valid && value_valid));
}

#[allow(clippy::cast_precision_loss)]
pub(crate) fn format_timestamp(timestamp: Timestamp) -> String {
    let milliseconds = timestamp.seconds as f64 * 1000.0 + f64::from(timestamp.nanos) / 1_000_000.0;
    let date = Date::new(&JsValue::from_f64(milliseconds));
    String::from(date.to_locale_string("en-GB", &JsValue::UNDEFINED))
}
