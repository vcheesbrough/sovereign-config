//! Routing: URL <-> `Route`, navigation with the unsaved-edit guard, and
//! rendering the active view.

use sovereign_config_core::ConfigPath;
use std::cell::{Cell, RefCell};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::spawn_local;
use web_sys::{HtmlDialogElement, HtmlElement, HtmlInputElement, HtmlTextAreaElement, window};

use crate::audit::{load_audit, render_audit_route};
use crate::configuration::{absolute_path, load_current_configuration, validate_path_field};
use crate::connections::{
    discard_connection_url, load_current_connections, render_path_connections,
    reset_path_connection_form,
};
use crate::dom::{
    close_dialog, element, element_is_hidden, focus, set_active, set_hidden, set_text, show_error,
};
use crate::downloads::load_downloads;
use crate::shell::close_brand_menu;
use crate::tree::{TREE_NODES, load_tree, render_tree};

thread_local! {
    pub(crate) static PENDING_NAVIGATION: RefCell<Option<Route>> = const { RefCell::new(None) };
    static PENDING_FROM_HISTORY: Cell<bool> = const { Cell::new(false) };
    static CURRENT_URL: RefCell<String> = const { RefCell::new(String::new()) };
}

#[derive(Clone)]
pub(crate) enum Route {
    Configuration(ConfigPath),
    Connections,
    Downloads,
    /// The audit trail: the whole of it, or one value's history.
    Audit(Option<ConfigPath>),
}

/// Every in-app route change runs through here so an unsaved value edit can
/// interpose a confirmation before the current view is torn down.
pub(crate) fn guarded_navigate(route: Route) {
    close_brand_menu();
    if has_unsaved_edits() {
        open_unsaved_dialog(route, false);
        return;
    }
    navigate(&route);
}

/// Reports whether any editor on the Configuration view holds text that has not
/// been sent to the service.
///
/// This is derived from the DOM rather than tracked in a flag: every editable
/// field either records what was loaded into it (`data-loaded`) or is empty when
/// clean, so cancelling an edit clears the condition without any bookkeeping.
pub(crate) fn has_unsaved_edits() -> bool {
    if !element_is_hidden("new-value-row")
        && (element::<HtmlInputElement>("new-value-name").is_some_and(|it| !it.value().is_empty())
            || element::<HtmlTextAreaElement>("new-value-content")
                .is_some_and(|it| !it.value().is_empty())
            || element::<HtmlInputElement>("new-secret-content")
                .is_some_and(|it| !it.value().is_empty()))
    {
        return true;
    }
    // Scoped to the value rows and the JSON editor rather than swept from the
    // document: everything editable here lives in one of those two places, and
    // the page now carries two connection forms whose fields must never be
    // mistaken for a value edit.
    if element::<HtmlTextAreaElement>("json-content")
        .as_ref()
        .is_some_and(edited_textarea)
    {
        return true;
    }
    let Some(rows) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id("values-body"))
    else {
        return false;
    };
    let editors = rows.get_elements_by_tag_name("textarea");
    for index in 0..editors.length() {
        if editors
            .item(index)
            .and_then(|editor| editor.dyn_into::<HtmlTextAreaElement>().ok())
            .as_ref()
            .is_some_and(edited_textarea)
        {
            return true;
        }
    }
    // Only the padlocked secret fields carry `data-loaded` among the inputs
    // here, and they carry it in both states: empty while locked, the revealed
    // secret once opened. Either way an edit is a value that differs from it.
    let secrets = rows.get_elements_by_tag_name("input");
    for index in 0..secrets.length() {
        if secrets
            .item(index)
            .and_then(|input| input.dyn_into::<HtmlInputElement>().ok())
            .is_some_and(|input| {
                input
                    .get_attribute("data-loaded")
                    .is_some_and(|loaded| input.value() != loaded)
            })
        {
            return true;
        }
    }
    false
}

/// A textarea holds an edit when its text differs from what was loaded into it.
/// One without a loaded marker — a revealed secret, say — is never an edit.
fn edited_textarea(editor: &HtmlTextAreaElement) -> bool {
    editor
        .get_attribute("data-loaded")
        .is_some_and(|loaded| editor.value() != loaded)
}

fn navigate(route: &Route) {
    navigate_with(route, false);
}

fn navigate_with(route: &Route, replace: bool) {
    discard_connection_url();
    let url = route_url(route);
    if let Some(window) = window()
        && let Ok(history) = window.history()
    {
        let _ = if replace {
            history.replace_state_with_url(&JsValue::NULL, "", Some(&url))
        } else {
            history.push_state_with_url(&JsValue::NULL, "", Some(&url))
        };
    }
    render_route(route);
    spawn_local(async {
        refresh_views().await;
    });
}

pub(crate) async fn refresh_views() {
    load_current_configuration().await;
    load_current_connections().await;
    load_downloads().await;
    load_audit().await;
    load_tree().await;
}

/// Re-reads the selected path after a mutation, together with the sidebar tree:
/// adding the first value under a namespace creates a node, and removing the
/// last one takes it away.
pub(crate) async fn reload_configuration() {
    load_current_configuration().await;
    load_tree().await;
}

/// Holds the route the operator asked for until they choose between discarding
/// the edit and staying put. `from_history` records that a Back or Forward press
/// asked for it, which changes how discarding has to reach the destination.
pub(crate) fn open_unsaved_dialog(route: Route, from_history: bool) {
    PENDING_NAVIGATION.with_borrow_mut(|pending| *pending = Some(route));
    PENDING_FROM_HISTORY.set(from_history);
    if let Some(dialog) = element::<HtmlDialogElement>("unsaved-dialog") {
        let _ = dialog.show_modal();
        focus("keep-editing");
    }
}

pub(crate) fn keep_editing() {
    PENDING_NAVIGATION.with_borrow_mut(Option::take);
    PENDING_FROM_HISTORY.set(false);
    close_dialog("unsaved-dialog");
}

pub(crate) fn discard_changes() {
    let pending = PENDING_NAVIGATION.with_borrow_mut(Option::take);
    let from_history = PENDING_FROM_HISTORY.replace(false);
    close_dialog("unsaved-dialog");
    // Leaving reloads the destination, which replaces every editor; the edit is
    // discarded by that reload rather than by clearing fields here.
    if let Some(route) = pending {
        // A pop already moved history; the guard then pushed the source back so
        // the operator could decide. Overwrite that restored entry rather than
        // appending a third, or the next Back would return to the page they
        // just chose to leave instead of continuing backward.
        navigate_with(&route, from_history);
    }
}

/// Re-pushes the route currently rendered. A history pop cannot be prevented,
/// so the guard restores the address bar and then asks the same question an
/// in-app link would have asked before leaving.
pub(crate) fn restore_current_url() {
    let url = CURRENT_URL.with_borrow(Clone::clone);
    if url.is_empty() {
        return;
    }
    if let Some(window) = window()
        && let Ok(history) = window.history()
    {
        let _ = history.push_state_with_url(&JsValue::NULL, "", Some(&url));
    }
}

pub(crate) fn render_route(route: &Route) {
    CURRENT_URL.with_borrow_mut(|url| *url = route_url(route));
    let configuration = matches!(route, Route::Configuration(_));
    let connections = matches!(route, Route::Connections);
    let downloads = matches!(route, Route::Downloads);
    let audit = matches!(route, Route::Audit(_));
    set_hidden("configuration-page", !configuration);
    set_hidden("connections-page", !connections);
    set_hidden("downloads-page", !downloads);
    set_hidden("audit-page", !audit);
    set_active("configuration-values-link", configuration);
    set_active("managed-connections-link", connections);
    set_active("downloads-link", downloads);
    set_active("audit-trail-link", audit);
    if configuration || audit {
        let canonical_url = route_url(route);
        if let Some(window) = window()
            && window.location().pathname().ok().as_deref() != Some(canonical_url.as_str())
            && let Ok(history) = window.history()
        {
            // The query string survives the rewrite. The OIDC callback lands on
            // an unrecognized path and so is normalized here like any other,
            // but its `?code=` has not been read yet — `finish_login` consumes
            // it moments later and clears it then.
            let search = window.location().search().unwrap_or_default();
            let _ = history.replace_state_with_url(
                &JsValue::NULL,
                "",
                Some(&format!("{canonical_url}{search}")),
            );
        }
    }
    if let Route::Audit(path) = route {
        render_audit_route(path.as_ref());
    }
    if let Route::Configuration(path) = route {
        if let Some(input) = element::<HtmlInputElement>("selected-path") {
            input.set_value(&absolute_path(path));
        }
        validate_path_field();
        if element::<HtmlElement>("path-connection-root")
            .is_some_and(|root| root.text_content().as_deref() != Some(path.as_str()))
        {
            // The form is now aimed at a different namespace. A half-filled
            // draft carried over would be armed to grant standing access to a
            // root the operator never chose it for.
            reset_path_connection_form();
        }
        set_text("path-connection-root", path.as_str());
        render_path_connections();
    }
    let nodes = TREE_NODES.with_borrow(Clone::clone);
    if let Err(error) = render_tree(&nodes) {
        show_error(error.message());
    }
}

pub(crate) fn route_from_location() -> Route {
    let path = window()
        .and_then(|window| window.location().pathname().ok())
        .unwrap_or_else(|| "/".into());
    route_from_path(&path)
}

pub(crate) fn route_from_path(path: &str) -> Route {
    if path == "/configuration" || path == "/configuration/" {
        return Route::Configuration(ConfigPath::root());
    }
    if path == "/connections" || path == "/connections/" {
        return Route::Connections;
    }
    if path == "/downloads" || path == "/downloads/" {
        return Route::Downloads;
    }
    if path == "/audit" || path == "/audit/" {
        return Route::Audit(None);
    }
    if let Some(relative) = path.strip_prefix("/audit/") {
        // A suffix that names no value is not a value's history; it falls back
        // to the whole trail, and `render_route` rewrites the address to say so.
        return Route::Audit(ConfigPath::parse_operation(format!("/{relative}")).ok());
    }
    if let Some(relative) = path.strip_prefix("/configuration/")
        && let Ok(path) = ConfigPath::parse_operation(format!("/{relative}"))
    {
        return Route::Configuration(path);
    }
    // Including `/`: with no System view left, the configuration root is the
    // landing view, and `render_route` rewrites the address to its canonical
    // `/configuration/` form.
    Route::Configuration(ConfigPath::root())
}

pub(crate) fn route_url(route: &Route) -> String {
    match route {
        Route::Configuration(path) if path.as_str() == "/" => "/configuration/".into(),
        Route::Configuration(path) => format!("/configuration{}", path.as_str()),
        Route::Connections => "/connections/".into(),
        Route::Downloads => "/downloads".into(),
        Route::Audit(None) => "/audit/".into(),
        Route::Audit(Some(path)) => format!("/audit{}", path.as_str()),
    }
}
