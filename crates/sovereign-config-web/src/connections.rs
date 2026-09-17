//! Access URLs: the estate-wide and per-path connection tables, create/rotate/revoke dialogs, and the one-time URL reveal.

use crate::browser::app_config;
use crate::browser::browser_error;
use crate::configuration::parse_absolute_path;
use crate::configuration::set_validation;
use crate::dom::append;
use crate::dom::clear_error;
use crate::dom::close_dialog;
use crate::dom::create_element;
use crate::dom::element;
use crate::dom::element_is_hidden;
use crate::dom::focus;
use crate::dom::set_button_disabled;
use crate::dom::set_hidden;
use crate::dom::set_text;
use crate::dom::show_error;
use crate::icons::Icon;
use crate::icons::create_icon_button;
use crate::route::Route;
use crate::route::route_from_location;
use crate::transport::value_client;
use crate::tree::load_tree;
use crate::tree::selected_tree_path;
use sovereign_config_core::ClientError;
use sovereign_config_core::ConfigPath;
use sovereign_config_core::ConnectionId;
use sovereign_config_core::DisplayName;
use sovereign_config_core::ManagedConnectionMetadata;
use sovereign_config_core::ManagedConnectionState;
use sovereign_config_core::ManagedPermission;
use sovereign_config_core::ManagedPermissions;
use sovereign_config_core::ProvisionedManagedConnection;
use sovereign_config_core::Secret;
use std::cell::Cell;
use std::cell::RefCell;
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_futures::spawn_local;
use web_sys::Document;
use web_sys::Element;
use web_sys::Event;
use web_sys::HtmlDialogElement;
use web_sys::HtmlInputElement;
use web_sys::HtmlTextAreaElement;
use web_sys::window;

thread_local! {
    pub(crate) static CONNECTIONS_LOAD_GENERATION: Cell<u64> = const { Cell::new(0) };
    pub(crate) static CONNECTION_TARGET: RefCell<Option<ConnectionTarget>> = const { RefCell::new(None) };
    pub(crate) static CONNECTION_URL_SECRET: RefCell<Option<Secret>> = const { RefCell::new(None) };
    pub(crate) static CONNECTION_URL_RETURN_FOCUS: RefCell<Option<String>> = const { RefCell::new(None) };
    pub(crate) static CONNECTION_PENDING: Cell<bool> = const { Cell::new(false) };
    pub(crate) static PENDING_CONNECTION: RefCell<Option<PendingConnection>> = const { RefCell::new(None) };
    pub(crate) static CONNECTIONS: RefCell<Vec<ManagedConnectionMetadata>> = const { RefCell::new(Vec::new()) };
}

/// The connection selected for a pending rotate or revoke confirmation.
pub(crate) struct ConnectionTarget {
    pub(crate) connection_id: ConnectionId,
    pub(crate) return_focus: String,
}

/// A validated create-connection request awaiting its confirmation. Both the
/// estate-wide form and the per-path form on the Configuration view fill this
/// in, so the confirmation dialog and the mutation itself stay single-sourced.
pub(crate) struct PendingConnection {
    pub(crate) display_name: DisplayName,
    pub(crate) root: ConfigPath,
    pub(crate) permissions: ManagedPermissions,
    /// Cleared once the connection is created, so the operator does not
    /// accidentally create a second connection under the same name.
    pub(crate) name_input_id: String,
    pub(crate) return_focus: String,
}

pub(crate) fn install_connections_actions(document: &Document) {
    for form in [&ESTATE_CONNECTION_FORM, &PATH_CONNECTION_FORM] {
        if let Some(element) = document.get_element_by_id(form.form_id) {
            let callback = Closure::<dyn FnMut(_)>::new(move |event: Event| {
                event.prevent_default();
                open_create_connection(form);
            });
            let _ = element
                .add_event_listener_with_callback("submit", callback.as_ref().unchecked_ref());
            callback.forget();
        }
        if let Some(name) = document.get_element_by_id(form.name_id) {
            let callback = Closure::<dyn FnMut(_)>::new(move |_: Event| {
                validate_connection_name_field(form);
            });
            let _ =
                name.add_event_listener_with_callback("input", callback.as_ref().unchecked_ref());
            callback.forget();
        }
    }
    if let Some(root) = document.get_element_by_id("connection-root") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            validate_connection_root_field();
        });
        let _ = root.add_event_listener_with_callback("input", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(cancel) = document.get_element_by_id("cancel-create-connection") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            let return_focus = PENDING_CONNECTION
                .with_borrow_mut(Option::take)
                .map_or_else(
                    || "create-connection".to_owned(),
                    |pending| pending.return_focus,
                );
            close_dialog("create-connection-dialog");
            focus(&return_focus);
        });
        let _ = cancel.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(confirm) = document.get_element_by_id("confirm-create-connection") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            spawn_local(async { create_connection().await });
        });
        let _ =
            confirm.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(cancel) = document.get_element_by_id("cancel-rotate-connection") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            cancel_connection_dialog("rotate-connection-dialog");
        });
        let _ = cancel.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(confirm) = document.get_element_by_id("confirm-rotate-connection") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            spawn_local(async { rotate_connection().await });
        });
        let _ =
            confirm.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(cancel) = document.get_element_by_id("cancel-revoke-connection") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            cancel_connection_dialog("revoke-connection-dialog");
        });
        let _ = cancel.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(confirm) = document.get_element_by_id("confirm-revoke-connection") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            spawn_local(async { revoke_connection().await });
        });
        let _ =
            confirm.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(dialog) = document.get_element_by_id("create-connection-dialog") {
        // Escape closes a native dialog without either button. Treat that as the
        // cancel it is, so a credential draft — display name, root, and grants —
        // does not outlive the decision not to create it.
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            if let Some(pending) = PENDING_CONNECTION.with_borrow_mut(Option::take) {
                focus(&pending.return_focus);
            }
        });
        let _ = dialog.add_event_listener_with_callback("close", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(reveal) = document.get_element_by_id("reveal-connection-url") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            toggle_connection_url_reveal();
        });
        let _ = reveal.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(copy) = document.get_element_by_id("copy-connection-url") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            spawn_local(async { copy_connection_url().await });
        });
        let _ = copy.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(close) = document.get_element_by_id("close-connection-url") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            let return_focus = CONNECTION_URL_RETURN_FOCUS.with_borrow_mut(Option::take);
            discard_connection_url();
            if let Some(return_focus) = return_focus {
                focus(&return_focus);
            }
        });
        let _ = close.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(dialog) = document.get_element_by_id("connection-url-dialog") {
        // The native dialog can also close through Escape; always discard.
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            let return_focus = CONNECTION_URL_RETURN_FOCUS.with_borrow_mut(Option::take);
            discard_connection_url();
            if let Some(return_focus) = return_focus {
                focus(&return_focus);
            }
        });
        let _ = dialog.add_event_listener_with_callback("close", callback.as_ref().unchecked_ref());
        callback.forget();
    }
}

/// The identifiers of one create-connection form. The Access URLs view types a
/// root; the Configuration view takes the selected tree node instead, so its
/// `root_id` is absent.
pub(crate) struct ConnectionForm {
    pub(crate) form_id: &'static str,
    pub(crate) name_id: &'static str,
    pub(crate) name_error_id: &'static str,
    pub(crate) root_id: Option<&'static str>,
    pub(crate) permission_prefix: &'static str,
    pub(crate) permissions_field_id: &'static str,
    pub(crate) permissions_error_id: &'static str,
    pub(crate) submit_id: &'static str,
}

pub(crate) const ESTATE_CONNECTION_FORM: ConnectionForm = ConnectionForm {
    form_id: "connection-form",
    name_id: "connection-name",
    name_error_id: "connection-name-error",
    root_id: Some("connection-root"),
    permission_prefix: "connection",
    permissions_field_id: "connection-permissions",
    permissions_error_id: "connection-permissions-error",
    submit_id: "create-connection",
};

pub(crate) const PATH_CONNECTION_FORM: ConnectionForm = ConnectionForm {
    form_id: "path-connection-form",
    name_id: "path-connection-name",
    name_error_id: "path-connection-name-error",
    root_id: None,
    permission_prefix: "path-connection",
    permissions_field_id: "path-connection-permissions",
    permissions_error_id: "path-connection-permissions-error",
    submit_id: "create-path-connection",
};

pub(crate) fn validate_connection_name_field(form: &ConnectionForm) -> bool {
    let value = element::<HtmlInputElement>(form.name_id).map(|input| input.value());
    let valid = value
        .as_deref()
        .is_some_and(|value| DisplayName::parse(value).is_ok());
    set_validation(
        form.name_id,
        form.name_error_id,
        if valid {
            None
        } else {
            Some(
                "enter a display name of at most 100 characters without leading or trailing spaces",
            )
        },
    );
    valid
}

pub(crate) fn validate_connection_root_field() -> bool {
    let value = element::<HtmlInputElement>("connection-root").map(|input| input.value());
    let valid = value
        .as_deref()
        .is_some_and(|value| parse_absolute_path(value).is_ok());
    set_validation(
        "connection-root",
        "connection-root-error",
        if valid {
            None
        } else {
            Some(
                "path must begin with / and contain only letters, numbers, hyphens, and underscores",
            )
        },
    );
    valid
}

/// Validates one create-connection form and, if it holds together, records the
/// request for the shared confirmation dialog to act on.
pub(crate) fn open_create_connection(form: &ConnectionForm) {
    let name_valid = validate_connection_name_field(form);
    let root_valid = form.root_id.is_none() || validate_connection_root_field();
    let permissions_valid = validate_connection_permissions_field(form);
    if !name_valid {
        focus(form.name_id);
        return;
    }
    if !root_valid {
        focus(form.root_id.unwrap_or(form.name_id));
        return;
    }
    if !permissions_valid {
        focus(&format!("{}-permission-read", form.permission_prefix));
        return;
    }
    let Some(Ok(display_name)) =
        element::<HtmlInputElement>(form.name_id).map(|input| DisplayName::parse(input.value()))
    else {
        return;
    };
    let root = match form.root_id {
        Some(id) => element::<HtmlInputElement>(id)
            .map(|input| input.value())
            .and_then(|value| parse_absolute_path(&value).ok()),
        None => selected_tree_path(),
    };
    let (Some(root), Some(permissions)) = (root, selected_connection_permissions(form)) else {
        return;
    };
    set_text("create-connection-name", display_name.as_str());
    set_text("create-connection-root", root.as_str());
    set_text(
        "create-connection-permissions",
        &connection_permissions_phrase(&permissions),
    );
    PENDING_CONNECTION.with_borrow_mut(|pending| {
        *pending = Some(PendingConnection {
            display_name,
            root,
            permissions,
            name_input_id: form.name_id.to_owned(),
            return_focus: form.submit_id.to_owned(),
        });
    });
    if let Some(dialog) = element::<HtmlDialogElement>("create-connection-dialog") {
        let _ = dialog.show_modal();
        focus("cancel-create-connection");
    }
}

/// Reads the three permission checkboxes into a core permission set, returning
/// `None` when the operator has selected nothing.
pub(crate) fn selected_connection_permissions(form: &ConnectionForm) -> Option<ManagedPermissions> {
    let mut selected = Vec::new();
    for (name, permission) in [
        ("read", ManagedPermission::Read),
        ("write", ManagedPermission::Write),
        ("manage", ManagedPermission::Manage),
    ] {
        let id = format!("{}-permission-{name}", form.permission_prefix);
        if element::<HtmlInputElement>(&id).is_some_and(|input| input.checked()) {
            selected.push(permission);
        }
    }
    ManagedPermissions::new(selected).ok()
}

pub(crate) fn validate_connection_permissions_field(form: &ConnectionForm) -> bool {
    let valid = selected_connection_permissions(form).is_some();
    set_validation(
        form.permissions_field_id,
        form.permissions_error_id,
        if valid {
            None
        } else {
            Some("select at least one permission")
        },
    );
    valid
}

/// A natural-language list of granted permissions for the confirmation copy,
/// e.g. `read`, `read and write`, or `read, write and manage`.
pub(crate) fn connection_permissions_phrase(permissions: &ManagedPermissions) -> String {
    let words = permissions.grant_tokens();
    match words.as_slice() {
        [] => String::new(),
        [only] => (*only).to_owned(),
        [head @ .., last] => format!("{} and {last}", head.join(", ")),
    }
}

/// A capitalized, canonically ordered label for a connection's granted
/// permissions, e.g. `Read, Write`.
pub(crate) fn connection_permissions_label(permissions: &ManagedPermissions) -> String {
    permissions
        .iter()
        .map(|permission| match permission {
            ManagedPermission::Read => "Read",
            ManagedPermission::Write => "Write",
            ManagedPermission::Manage => "Manage",
        })
        .collect::<Vec<_>>()
        .join(", ")
}

pub(crate) fn cancel_connection_dialog(dialog_id: &str) {
    let return_focus = CONNECTION_TARGET
        .with_borrow_mut(Option::take)
        .map(|target| target.return_focus);
    close_dialog(dialog_id);
    if let Some(return_focus) = return_focus {
        focus(&return_focus);
    }
}

pub(crate) async fn create_connection() {
    if CONNECTION_PENDING.get() {
        return;
    }
    let Some(request) = PENDING_CONNECTION.with_borrow_mut(Option::take) else {
        close_dialog("create-connection-dialog");
        return;
    };
    CONNECTION_PENDING.set(true);
    set_button_disabled("confirm-create-connection", true);
    clear_error();
    let result = async {
        let config = app_config()?;
        value_client(&config)
            .create_managed_connection(&request.display_name, &request.root, &request.permissions)
            .await
    }
    .await;
    set_button_disabled("confirm-create-connection", false);
    CONNECTION_PENDING.set(false);
    close_dialog("create-connection-dialog");
    match result {
        Ok(provisioned) => {
            if let Some(input) = element::<HtmlInputElement>(&request.name_input_id) {
                input.set_value("");
            }
            set_text("connection-state", "Connection created");
            let generation = CONNECTIONS_LOAD_GENERATION.get();
            load_current_connections().await;
            // If the generation advanced by more than this reload's own
            // bump, a concurrent logout or navigation happened while it was
            // in flight; opening the one-time URL dialog now would resurrect
            // a credential after the user has already left.
            if CONNECTIONS_LOAD_GENERATION.get() == generation.wrapping_add(1) {
                open_connection_url_dialog(&provisioned, &request.return_focus);
            }
            // The sidebar's key marker is refreshed only after the one-time URL
            // is on screen: it is the operator's single chance to copy the
            // credential, and must not wait on a whole-estate read that could
            // also fail and paint an error banner in front of the dialog.
            load_tree().await;
        }
        Err(error) => {
            set_text("connection-state", "Error");
            show_error(error.message());
            focus(&request.return_focus);
        }
    }
}

pub(crate) async fn rotate_connection() {
    if CONNECTION_PENDING.get() {
        return;
    }
    let Some(target) = CONNECTION_TARGET.with_borrow_mut(Option::take) else {
        return;
    };
    CONNECTION_PENDING.set(true);
    set_button_disabled("confirm-rotate-connection", true);
    clear_error();
    let result = async {
        let config = app_config()?;
        value_client(&config)
            .rotate_managed_connection(&target.connection_id)
            .await
    }
    .await;
    set_button_disabled("confirm-rotate-connection", false);
    CONNECTION_PENDING.set(false);
    close_dialog("rotate-connection-dialog");
    match result {
        Ok(provisioned) => {
            set_text("connection-state", "Credential rotated");
            let generation = CONNECTIONS_LOAD_GENERATION.get();
            load_current_connections().await;
            // Same ordering hazard as create: a concurrent logout or
            // navigation while the reload was in flight must suppress the
            // one-time URL dialog rather than resurrect it afterward.
            if CONNECTIONS_LOAD_GENERATION.get() == generation.wrapping_add(1) {
                open_connection_url_dialog(&provisioned, &target.return_focus);
            }
            // The tree refresh follows the dialog, as in create.
            load_tree().await;
        }
        Err(error) => {
            // Refresh first: reloading clears the error banner, so the
            // message must be shown after the new state is rendered.
            load_current_connections().await;
            set_text("connection-state", "Error");
            show_error(error.message());
            focus(&target.return_focus);
        }
    }
}

pub(crate) async fn revoke_connection() {
    if CONNECTION_PENDING.get() {
        return;
    }
    let Some(target) = CONNECTION_TARGET.with_borrow_mut(Option::take) else {
        return;
    };
    CONNECTION_PENDING.set(true);
    set_button_disabled("confirm-revoke-connection", true);
    clear_error();
    let result = async {
        let config = app_config()?;
        value_client(&config)
            .revoke_managed_connection(&target.connection_id)
            .await
    }
    .await;
    set_button_disabled("confirm-revoke-connection", false);
    CONNECTION_PENDING.set(false);
    close_dialog("revoke-connection-dialog");
    // Refresh first: reloading clears the error banner, so any message must
    // be shown after the new state is rendered.
    load_current_connections().await;
    load_tree().await;
    match result {
        Ok(()) => {
            set_text("connection-state", "Connection revoked");
        }
        Err(error) => {
            set_text("connection-state", "Error");
            show_error(error.message());
        }
    }
    // The row the action started from is gone, so fall back to the heading of
    // whichever table it belonged to; `connections-heading` lives on the hidden
    // Access URLs page whenever the action came from the Configuration view.
    focus(connections_heading_for(&target.return_focus));
}

/// Clears the per-path access-URL draft so it cannot follow the operator to
/// another namespace.
pub(crate) fn reset_path_connection_form() {
    if let Some(name) = element::<HtmlInputElement>(PATH_CONNECTION_FORM.name_id) {
        name.set_value("");
    }
    for (suffix, checked) in [("read", true), ("write", false), ("manage", false)] {
        let id = format!(
            "{}-permission-{suffix}",
            PATH_CONNECTION_FORM.permission_prefix
        );
        if let Some(choice) = element::<HtmlInputElement>(&id) {
            choice.set_checked(checked);
        }
    }
    set_validation(
        PATH_CONNECTION_FORM.name_id,
        PATH_CONNECTION_FORM.name_error_id,
        None,
    );
    set_validation(
        PATH_CONNECTION_FORM.permissions_field_id,
        PATH_CONNECTION_FORM.permissions_error_id,
        None,
    );
}

/// The heading owning `return_focus`: the per-path table on the Configuration
/// view, or the estate-wide one on the Access URLs view.
pub(crate) fn connections_heading_for(return_focus: &str) -> &'static str {
    if return_focus.starts_with(PATH_CONNECTION_TABLE.prefix) {
        "path-connections-heading"
    } else {
        "connections-heading"
    }
}

/// Opens the one-time result surface with the URL masked; the secret lives
/// only in application memory until the surface closes.
pub(crate) fn open_connection_url_dialog(
    provisioned: &ProvisionedManagedConnection,
    return_focus: &str,
) {
    CONNECTION_URL_SECRET.with_borrow_mut(|slot| {
        *slot = Some(provisioned.connection_url.connection().canonical().clone());
    });
    CONNECTION_URL_RETURN_FOCUS.with_borrow_mut(|slot| {
        *slot = Some(return_focus.to_owned());
    });
    hide_connection_url_reveal();
    set_text("connection-url-status", "");
    if let Some(dialog) = element::<HtmlDialogElement>("connection-url-dialog") {
        let _ = dialog.show_modal();
        focus("reveal-connection-url");
    }
}

pub(crate) fn toggle_connection_url_reveal() {
    if element_is_hidden("revealed-connection-url") {
        let Some(secret) = CONNECTION_URL_SECRET.with_borrow(std::clone::Clone::clone) else {
            return;
        };
        if let Some(output) = element::<HtmlTextAreaElement>("revealed-connection-url") {
            output.set_value(secret.expose());
        }
        set_hidden("revealed-connection-url", false);
        set_hidden("connection-url-mask", true);
        set_text("reveal-connection-url", "Hide");
        if let Some(button) = window()
            .and_then(|window| window.document())
            .and_then(|document| document.get_element_by_id("reveal-connection-url"))
        {
            let _ = button.set_attribute("aria-expanded", "true");
        }
        focus("revealed-connection-url");
    } else {
        hide_connection_url_reveal();
        focus("reveal-connection-url");
    }
}

pub(crate) fn hide_connection_url_reveal() {
    if let Some(output) = element::<HtmlTextAreaElement>("revealed-connection-url") {
        output.set_value("");
    }
    set_hidden("revealed-connection-url", true);
    set_hidden("connection-url-mask", false);
    set_text("reveal-connection-url", "Reveal");
    if let Some(button) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id("reveal-connection-url"))
    {
        let _ = button.set_attribute("aria-expanded", "false");
    }
}

pub(crate) async fn copy_connection_url() {
    let Some(secret) = CONNECTION_URL_SECRET.with_borrow(std::clone::Clone::clone) else {
        return;
    };
    let Some(clipboard) = window().map(|window| window.navigator().clipboard()) else {
        set_text("connection-url-status", "Copy failed");
        return;
    };
    match JsFuture::from(clipboard.write_text(secret.expose())).await {
        Ok(_) => set_text("connection-url-status", "Copied"),
        Err(_) => set_text("connection-url-status", "Copy failed"),
    }
}

/// Discards the one-time URL from application state and the DOM.
pub(crate) fn discard_connection_url() {
    CONNECTION_URL_SECRET.with_borrow_mut(Option::take);
    hide_connection_url_reveal();
    set_text("connection-url-status", "");
    close_dialog("connection-url-dialog");
}

pub(crate) async fn load_current_connections() {
    let generation = CONNECTIONS_LOAD_GENERATION.get().wrapping_add(1);
    CONNECTIONS_LOAD_GENERATION.set(generation);
    if !matches!(route_from_location(), Route::Connections) {
        return;
    }
    clear_connection_rows(&ESTATE_CONNECTION_TABLE);
    clear_error();
    set_text("connection-state", "Loading");
    let result = async {
        let config = app_config()?;
        value_client(&config).list_managed_connections().await
    }
    .await;
    if CONNECTIONS_LOAD_GENERATION.get() != generation
        || !matches!(route_from_location(), Route::Connections)
    {
        return;
    }
    match result {
        Ok(connections) => {
            set_text("connection-state", "Loaded");
            if let Err(error) = render_connections(&connections) {
                show_error(error.message());
            }
        }
        Err(error) => {
            set_text("connection-state", "Error");
            show_error(error.message());
        }
    }
}

/// The identifiers of one connections table. The Access URLs view lists the
/// whole estate; the Configuration view lists only the selected path. Both share
/// this renderer, so their row actions must not collide on element ids.
pub(crate) struct ConnectionTable {
    pub(crate) body_id: &'static str,
    pub(crate) count_id: &'static str,
    pub(crate) empty_id: &'static str,
    pub(crate) prefix: &'static str,
}

pub(crate) const ESTATE_CONNECTION_TABLE: ConnectionTable = ConnectionTable {
    body_id: "connections-body",
    count_id: "connection-count",
    empty_id: "empty-connections",
    prefix: "",
};

pub(crate) const PATH_CONNECTION_TABLE: ConnectionTable = ConnectionTable {
    body_id: "path-connections-body",
    count_id: "path-connection-count",
    empty_id: "empty-path-connections",
    prefix: "path-",
};

pub(crate) fn render_connections(
    connections: &[ManagedConnectionMetadata],
) -> Result<(), ClientError> {
    render_connection_rows(connections, &ESTATE_CONNECTION_TABLE)
}

/// Lists the access URLs rooted at exactly the selected path beneath that
/// path's values, so an operator grants access from the same place they read it.
pub(crate) fn render_path_connections() {
    let Some(path) = selected_tree_path() else {
        return;
    };
    let scoped = CONNECTIONS.with_borrow(|connections| {
        connections
            .iter()
            .filter(|connection| connection.root == path)
            .cloned()
            .collect::<Vec<_>>()
    });
    if let Err(error) = render_connection_rows(&scoped, &PATH_CONNECTION_TABLE) {
        show_error(error.message());
    }
}

pub(crate) fn render_connection_rows(
    connections: &[ManagedConnectionMetadata],
    table: &ConnectionTable,
) -> Result<(), ClientError> {
    clear_connection_rows(table);
    let document = window()
        .and_then(|window| window.document())
        .ok_or_else(browser_error)?;
    let body = document
        .get_element_by_id(table.body_id)
        .ok_or_else(browser_error)?;
    for (index, connection) in connections.iter().enumerate() {
        let row = render_connection_row(&document, connection, index, table.prefix)?;
        append(&body, &row)?;
    }
    let count = connections.len();
    set_text(
        table.count_id,
        &format!("{count} connection{}", if count == 1 { "" } else { "s" }),
    );
    set_hidden(table.empty_id, count != 0);
    Ok(())
}

pub(crate) fn render_connection_row(
    document: &Document,
    connection: &ManagedConnectionMetadata,
    index: usize,
    prefix: &str,
) -> Result<Element, ClientError> {
    let row = create_element(document, "tr", None)?;
    let name = create_element(document, "th", None)?;
    name.set_attribute("scope", "row")
        .map_err(|_| browser_error())?;
    name.set_text_content(Some(connection.display_name.as_str()));
    append(&row, &name)?;
    let root = create_element(document, "td", None)?;
    let root_code = create_element(document, "code", None)?;
    root_code.set_text_content(Some(connection.root.as_str()));
    append(&root, &root_code)?;
    append(&row, &root)?;
    let permissions = create_element(document, "td", None)?;
    permissions.set_text_content(Some(&connection_permissions_label(&connection.permissions)));
    append(&row, &permissions)?;
    let state = create_element(document, "td", None)?;
    state.set_text_content(Some(connection_state_label(connection.state)));
    append(&row, &state)?;

    let actions_cell = create_element(document, "td", None)?;
    let actions = create_element(document, "div", Some("row-actions"))?;
    let rotate_id = format!("{prefix}rotate-connection-{index}");
    let rotate = create_icon_button(
        document,
        &rotate_id,
        &format!("Rotate credential for {}", connection.display_name.as_str()),
        Icon::Rotate,
        None,
    )?;
    if !matches!(
        connection.state,
        ManagedConnectionState::Active | ManagedConnectionState::RotationUnknown
    ) {
        rotate
            .set_attribute("disabled", "")
            .map_err(|_| browser_error())?;
    }
    let rotate_target = connection.connection_id.clone();
    let rotate_name = connection.display_name.as_str().to_owned();
    let rotate_root = connection.root.as_str().to_owned();
    let rotate_focus = rotate_id.clone();
    let callback = Closure::<dyn FnMut(_)>::new(move |_: Event| {
        open_connection_dialog(
            "rotate-connection-dialog",
            "rotate-connection-name",
            "rotate-connection-root",
            "cancel-rotate-connection",
            &rotate_target,
            &rotate_name,
            &rotate_root,
            &rotate_focus,
        );
    });
    rotate
        .add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())
        .map_err(|_| browser_error())?;
    callback.forget();
    append(&actions, &rotate)?;

    let revoke_id = format!("{prefix}revoke-connection-{index}");
    let revoke = create_icon_button(
        document,
        &revoke_id,
        &format!("Revoke {}", connection.display_name.as_str()),
        Icon::Revoke,
        Some("danger"),
    )?;
    let revoke_target = connection.connection_id.clone();
    let revoke_name = connection.display_name.as_str().to_owned();
    let revoke_root = connection.root.as_str().to_owned();
    let revoke_focus = revoke_id.clone();
    let callback = Closure::<dyn FnMut(_)>::new(move |_: Event| {
        open_connection_dialog(
            "revoke-connection-dialog",
            "revoke-connection-name",
            "revoke-connection-root",
            "cancel-revoke-connection",
            &revoke_target,
            &revoke_name,
            &revoke_root,
            &revoke_focus,
        );
    });
    revoke
        .add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())
        .map_err(|_| browser_error())?;
    callback.forget();
    append(&actions, &revoke)?;
    append(&actions_cell, &actions)?;
    append(&row, &actions_cell)?;
    Ok(row)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn open_connection_dialog(
    dialog_id: &str,
    name_id: &str,
    root_id: &str,
    cancel_id: &str,
    connection_id: &ConnectionId,
    display_name: &str,
    root: &str,
    return_focus: &str,
) {
    set_text(name_id, display_name);
    set_text(root_id, root);
    CONNECTION_TARGET.with_borrow_mut(|target| {
        *target = Some(ConnectionTarget {
            connection_id: connection_id.clone(),
            return_focus: return_focus.to_owned(),
        });
    });
    if let Some(dialog) = element::<HtmlDialogElement>(dialog_id) {
        let _ = dialog.show_modal();
        focus(cancel_id);
    }
}

pub(crate) const fn connection_state_label(state: ManagedConnectionState) -> &'static str {
    match state {
        ManagedConnectionState::Provisioning => "Provisioning",
        ManagedConnectionState::Active => "Active",
        ManagedConnectionState::RotationUnknown => "Rotation unknown",
        ManagedConnectionState::Revoking => "Revoking",
        ManagedConnectionState::CleanupRequired => "Cleanup required",
    }
}

pub(crate) fn clear_connection_rows(table: &ConnectionTable) {
    if let Some(body) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id(table.body_id))
    {
        while let Some(row) = body.last_element_child() {
            row.remove();
        }
    }
    set_text(table.count_id, "0 connections");
    set_hidden(table.empty_id, false);
}
