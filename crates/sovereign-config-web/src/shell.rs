//! The page chrome: the resizable sidebar, the brand menu, route links, and the
//! full-page unsaved-edit guard.

use std::cell::Cell;
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use web_sys::{Document, Element, Event, HtmlElement, KeyboardEvent, PointerEvent, window};

use crate::browser::local_storage;
use crate::dom::{element, element_is_hidden, focus, on_element_id, set_hidden};
use crate::route::{
    PENDING_NAVIGATION, Route, discard_changes, guarded_navigate, has_unsaved_edits, keep_editing,
};

thread_local! {
    static SIDEBAR_DRAG_POINTER: Cell<Option<i32>> = const { Cell::new(None) };
}

const SIDEBAR_WIDTH_KEY: &str = "sovereign-config.sidebar-width";

const SIDEBAR_MIN_WIDTH: f64 = 200.0;

const SIDEBAR_MAX_WIDTH: f64 = 560.0;

const SIDEBAR_DEFAULT_WIDTH: f64 = 288.0;

const SIDEBAR_KEY_STEP: f64 = 16.0;

pub(crate) fn install_unsaved_guard(document: &Document) {
    // In-app links, tree clicks, and Back are guarded by the modal below, but a
    // reload, a tab close, or a typed URL never reaches any of them. Only the
    // browser's own prompt can interpose there; its wording is not ours to set.
    if let Some(browser_window) = window() {
        let callback = Closure::<dyn FnMut(_)>::new(|event: Event| {
            if has_unsaved_edits() {
                event.prevent_default();
            }
        });
        let _ = browser_window
            .add_event_listener_with_callback("beforeunload", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    on_element_id(document, "keep-editing", "click", |_: Event| keep_editing());
    on_element_id(document, "discard-changes", "click", |_: Event| {
        discard_changes();
    });
    // Escape closes a native dialog without either button; that is a
    // decision to stay, so drop the pending route.
    on_element_id(document, "unsaved-dialog", "close", |_: Event| {
        PENDING_NAVIGATION.with_borrow_mut(Option::take);
    });
}

/// Drag and keyboard control for the sidebar separator. The width is a CSS
/// custom property on the layout grid, so nothing else needs to know about it.
pub(crate) fn install_sidebar_resizer(document: &Document) {
    let Some(resizer) = document.get_element_by_id("sidebar-resizer") else {
        return;
    };
    let handle = resizer.clone();
    let callback = Closure::<dyn FnMut(_)>::new(move |event: PointerEvent| {
        event.prevent_default();
        let _ = handle.set_pointer_capture(event.pointer_id());
        SIDEBAR_DRAG_POINTER.set(Some(event.pointer_id()));
    });
    let _ =
        resizer.add_event_listener_with_callback("pointerdown", callback.as_ref().unchecked_ref());
    callback.forget();

    let callback = Closure::<dyn FnMut(_)>::new(move |event: PointerEvent| {
        if SIDEBAR_DRAG_POINTER.get() != Some(event.pointer_id()) {
            return;
        }
        event.prevent_default();
        // Measure from the grid's own left edge rather than the viewport's, so
        // any future gutter or centred shell does not silently offset the
        // handle from the pointer by exactly that width.
        set_sidebar_width(f64::from(event.client_x()) - layout_left());
    });
    let _ =
        resizer.add_event_listener_with_callback("pointermove", callback.as_ref().unchecked_ref());
    callback.forget();

    for event_name in ["pointerup", "pointercancel"] {
        let handle = resizer.clone();
        let callback = Closure::<dyn FnMut(_)>::new(move |event: PointerEvent| {
            if SIDEBAR_DRAG_POINTER.get() == Some(event.pointer_id()) {
                let _ = handle.release_pointer_capture(event.pointer_id());
                SIDEBAR_DRAG_POINTER.set(None);
            }
        });
        let _ =
            resizer.add_event_listener_with_callback(event_name, callback.as_ref().unchecked_ref());
        callback.forget();
    }

    let callback = Closure::<dyn FnMut(_)>::new(move |event: KeyboardEvent| {
        let step = match event.key().as_str() {
            "ArrowLeft" => -SIDEBAR_KEY_STEP,
            "ArrowRight" => SIDEBAR_KEY_STEP,
            _ => return,
        };
        event.prevent_default();
        set_sidebar_width(sidebar_width() + step);
    });
    let _ = resizer.add_event_listener_with_callback("keydown", callback.as_ref().unchecked_ref());
    callback.forget();
}

fn layout_left() -> f64 {
    element::<HtmlElement>("layout").map_or(0.0, |layout| layout.get_bounding_client_rect().left())
}

fn sidebar_width() -> f64 {
    window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id("sidebar-resizer"))
        .and_then(|resizer| resizer.get_attribute("aria-valuenow"))
        .and_then(|width| width.parse::<f64>().ok())
        .unwrap_or(SIDEBAR_DEFAULT_WIDTH)
}

fn set_sidebar_width(width: f64) {
    let width = width.clamp(SIDEBAR_MIN_WIDTH, SIDEBAR_MAX_WIDTH).round();
    if let Some(layout) = element::<HtmlElement>("layout") {
        let _ = layout
            .style()
            .set_property("--sidebar-width", &format!("{width}px"));
    }
    if let Some(resizer) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id("sidebar-resizer"))
    {
        let _ = resizer.set_attribute("aria-valuenow", &width.to_string());
    }
    if let Ok(storage) = local_storage() {
        let _ = storage.set_item(SIDEBAR_WIDTH_KEY, &width.to_string());
    }
}

pub(crate) fn restore_sidebar_width() {
    let stored = local_storage()
        .ok()
        .and_then(|storage| storage.get_item(SIDEBAR_WIDTH_KEY).ok().flatten())
        .and_then(|width| width.parse::<f64>().ok())
        .filter(|width| width.is_finite());
    if let Some(width) = stored {
        set_sidebar_width(width);
    }
}

/// The brand mark is a disclosure button for the views that are not the
/// configuration tree. Opening is a pointer or keyboard action on the button;
/// closing is anything that leaves it — Escape, a click elsewhere, or a
/// navigation.
pub(crate) fn install_brand_menu(document: &Document) {
    let Some(button) = document.get_element_by_id("brand-menu-button") else {
        return;
    };
    let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
        set_brand_menu_open(!brand_menu_open());
    });
    let _ = button.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
    callback.forget();

    // A pointerdown anywhere outside the button or the panel dismisses the
    // menu. `pointerdown` rather than `click` so the menu is already gone by
    // the time whatever was underneath it takes the press.
    let callback = Closure::<dyn FnMut(_)>::new(|event: Event| {
        if !brand_menu_open() {
            return;
        }
        let inside = event
            .target()
            .and_then(|target| target.dyn_into::<Element>().ok())
            .is_some_and(|target| {
                target
                    .closest("#brand-menu, #brand-menu-button")
                    .ok()
                    .flatten()
                    .is_some()
            });
        if !inside {
            close_brand_menu();
        }
    });
    let _ =
        document.add_event_listener_with_callback("pointerdown", callback.as_ref().unchecked_ref());
    callback.forget();

    let callback = Closure::<dyn FnMut(_)>::new(|event: KeyboardEvent| {
        if event.key() == "Escape" && brand_menu_open() {
            event.prevent_default();
            close_brand_menu();
            focus("brand-menu-button");
        }
    });
    let _ = document.add_event_listener_with_callback("keydown", callback.as_ref().unchecked_ref());
    callback.forget();
}

fn brand_menu_open() -> bool {
    !element_is_hidden("brand-menu")
}

fn set_brand_menu_open(open: bool) {
    set_hidden("brand-menu", !open);
    if let Some(button) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id("brand-menu-button"))
    {
        let _ = button.set_attribute("aria-expanded", if open { "true" } else { "false" });
    }
}

pub(crate) fn close_brand_menu() {
    if brand_menu_open() {
        set_brand_menu_open(false);
    }
}

pub(crate) fn install_route_link(document: &Document, id: &str, route: Route) {
    on_element_id(document, id, "click", move |event: Event| {
        event.prevent_default();
        guarded_navigate(route.clone());
    });
}
