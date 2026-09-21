#![forbid(unsafe_code)]

//! Sovereign Config browser administration UI: a hand-rolled `web-sys` DOM
//! application compiled to WebAssembly. `start` installs every event handler
//! and renders the route in the current URL; each view and concern lives in
//! its own module.

mod audit;
mod browser;
mod configuration;
mod connections;
mod dom;
mod downloads;
mod icons;
mod path_selector;
mod route;
mod session;
mod shell;
mod transport;
mod tree;
mod value_rows;

use sovereign_config_core::ConfigPath;
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen_futures::spawn_local;
use web_sys::{Event, window};

use crate::audit::{install_audit_actions, load_audit, reset_audit};
use crate::browser::{app_config, location_search};
use crate::configuration::{
    CONFIGURATION_LOAD_GENERATION, hide_new_value_row, install_configuration_actions,
    load_current_configuration,
};
use crate::connections::{
    CONNECTIONS, CONNECTIONS_LOAD_GENERATION, ESTATE_CONNECTION_TABLE, PATH_CONNECTION_TABLE,
    clear_connection_rows, discard_connection_url, install_connections_actions,
    load_current_connections,
};
use crate::dom::{focus, on_element_id, set_hidden, set_loaded_textarea, set_text, show_error};
use crate::downloads::load_downloads;
use crate::route::{
    Route, has_unsaved_edits, open_unsaved_dialog, refresh_views, render_route,
    restore_current_url, route_from_location,
};
use crate::session::{
    begin_login, clear_browser_session, finish_login, refresh_status, render_identity,
    restore_tokens,
};
use crate::shell::{
    close_brand_menu, install_brand_menu, install_route_link, install_sidebar_resizer,
    install_unsaved_guard, restore_sidebar_width,
};
use crate::tree::{TREE_LOAD_GENERATION, TREE_NODES, install_tree_actions, load_tree, render_tree};
use crate::value_rows::clear_value_rows;

#[wasm_bindgen(start)]
pub fn start() {
    install_actions();
    render_route(&route_from_location());
    // The Downloads view needs no authentication; load it independently of the
    // login flow so it renders on a direct visit to /downloads while logged out.
    spawn_local(async {
        load_downloads().await;
    });
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
                    load_current_connections().await;
                    load_audit().await;
                    load_tree().await;
                } else {
                    // Renders the sidebar's logged-out hint in place of a tree.
                    load_tree().await;
                }
            }
            Err(error) => show_error(error.message()),
        }
    });
}

pub(crate) fn install_actions() {
    let Some(document) = window().and_then(|window| window.document()) else {
        return;
    };
    install_brand_menu(&document);
    install_route_link(
        &document,
        "configuration-values-link",
        Route::Configuration(ConfigPath::root()),
    );
    install_route_link(&document, "managed-connections-link", Route::Connections);
    install_route_link(&document, "downloads-link", Route::Downloads);
    install_route_link(&document, "audit-trail-link", Route::Audit(None));
    if let Some(browser_window) = window() {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            // Every other route change closes the menu before anything else —
            // `guarded_navigate` does it first, even ahead of its own unsaved-edits
            // check — and a history pop is a route change too. Without this the
            // panel outlives the page it was opened on, floating over whatever
            // Back or Forward lands on next.
            close_brand_menu();
            if has_unsaved_edits() {
                // A history pop cannot be cancelled, so put the address bar
                // back and ask the same question an in-app link would ask.
                let target = route_from_location();
                restore_current_url();
                open_unsaved_dialog(target, true);
                return;
            }
            discard_connection_url();
            render_route(&route_from_location());
            spawn_local(async {
                refresh_views().await;
            });
        });
        let _ = browser_window
            .add_event_listener_with_callback("popstate", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    on_element_id(&document, "login", "click", |_: web_sys::Event| {
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
    on_element_id(&document, "logout", "click", |_: web_sys::Event| {
        CONFIGURATION_LOAD_GENERATION.set(CONFIGURATION_LOAD_GENERATION.get().wrapping_add(1));
        CONNECTIONS_LOAD_GENERATION.set(CONNECTIONS_LOAD_GENERATION.get().wrapping_add(1));
        TREE_LOAD_GENERATION.set(TREE_LOAD_GENERATION.get().wrapping_add(1));
        discard_connection_url();
        clear_browser_session();
        render_identity(false);
        set_hidden("login", false);
        set_hidden("logout", true);
        set_text("value-state", "Log in to view values");
        hide_new_value_row();
        clear_value_rows();
        set_loaded_textarea("json-content", "");
        set_text("value-count", "0 values");
        clear_connection_rows(&ESTATE_CONNECTION_TABLE);
        clear_connection_rows(&PATH_CONNECTION_TABLE);
        CONNECTIONS.with_borrow_mut(Vec::clear);
        TREE_NODES.with_borrow_mut(Vec::clear);
        let _ = render_tree(&[]);
        set_text("config-tree-state", "Log in to browse");
        set_text("connection-state", "Log in to view connections");
        reset_audit();
        set_text("audit-state", "Log in to view the audit trail");
        close_brand_menu();
        focus("login");
    });
    install_configuration_actions(&document);
    install_connections_actions(&document);
    install_audit_actions(&document);
    install_tree_actions(&document);
    install_unsaved_guard(&document);
    install_sidebar_resizer(&document);
    restore_sidebar_width();
}

#[cfg(test)]
mod tests;
