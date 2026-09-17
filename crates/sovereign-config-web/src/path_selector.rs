//! The path selector combobox: options, filtering, keyboard selection, and refresh.

use crate::browser::app_config;
use crate::browser::browser_error;
use crate::configuration::selected_namespace;
use crate::configuration::validate_path_field;
use crate::dom::element;
use crate::dom::focus;
use crate::dom::set_hidden;
use crate::dom::show_error;
use crate::route::Route;
use crate::route::guarded_navigate;
use crate::route::route_from_location;
use crate::transport::value_client;
use sovereign_config_core::ClientError;
use sovereign_config_core::ValueListing;
use std::cell::Cell;
use std::collections::BTreeMap;
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use wasm_bindgen_futures::spawn_local;
use web_sys::Document;
use web_sys::Element;
use web_sys::Event;
use web_sys::HtmlInputElement;
use web_sys::KeyboardEvent;
use web_sys::window;

thread_local! {
    pub(crate) static PATH_OPTIONS_REFRESHING: Cell<bool> = const { Cell::new(false) };
    pub(crate) static ACTIVE_PATH_OPTION: Cell<Option<usize>> = const { Cell::new(None) };
}

pub(crate) fn install_path_selector_actions(document: &Document) {
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

pub(crate) fn open_selected_path() {
    if let Ok(path) = selected_namespace() {
        close_path_options();
        guarded_navigate(Route::Configuration(path));
    } else {
        validate_path_field();
    }
}

pub(crate) fn open_path_options() {
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

pub(crate) fn path_options_expanded() -> bool {
    element::<HtmlInputElement>("selected-path")
        .is_some_and(|input| input.get_attribute("aria-expanded").as_deref() == Some("true"))
}

pub(crate) fn close_path_options() {
    if let Some(input) = element::<HtmlInputElement>("selected-path") {
        let _ = input.set_attribute("aria-expanded", "false");
        let _ = input.remove_attribute("aria-activedescendant");
    }
    set_hidden("existing-paths", true);
    set_active_path_option(None);
}

pub(crate) fn size_path_options(input: &HtmlInputElement, options: &Element) {
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

pub(crate) fn filter_path_options() {
    let Some(input) = element::<HtmlInputElement>("selected-path") else {
        return;
    };
    let query = input.value().to_ascii_lowercase();
    for option in path_option_elements() {
        // `data-path` carries the display form (card #294), so the comparison
        // must fold it too, or a mixed-case namespace becomes unfindable by
        // typing its lowercase spelling.
        let visible = option
            .get_attribute("data-path")
            .is_some_and(|path| path.to_ascii_lowercase().starts_with(&query));
        if visible {
            let _ = option.remove_attribute("hidden");
        } else {
            let _ = option.set_attribute("hidden", "");
        }
    }
    set_active_path_option(None);
}

pub(crate) fn path_option_elements() -> Vec<Element> {
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

pub(crate) fn move_active_path_option(direction: i32) {
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

pub(crate) fn set_active_path_option(active_index: Option<usize>) {
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

pub(crate) fn select_active_path_option() {
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

pub(crate) async fn refresh_path_options() {
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

pub(crate) fn render_path_options(listing: &ValueListing) -> Result<(), ClientError> {
    let document = window()
        .and_then(|window| window.document())
        .ok_or_else(browser_error)?;
    let options = document
        .get_element_by_id("existing-paths")
        .ok_or_else(browser_error)?;
    options.set_text_content(None);
    // Keyed by fold, valued by display: two namespaces differing only by case
    // are one option, ordered by fold — not by the raw bytes of whichever
    // case happens to be displayed (card #294).
    let mut paths = listing
        .paths
        .iter()
        .map(|path| (path.fold(), path.as_str().to_owned()))
        .collect::<BTreeMap<_, _>>();
    paths.insert("/".to_owned(), "/".to_owned());
    if let Ok(selected) = selected_namespace() {
        // Only fills a namespace the listing doesn't already know about —
        // matches the original `BTreeSet::insert` behavior, which was a
        // no-op whenever the (then case-invariant) entry already existed.
        paths
            .entry(selected.fold())
            .or_insert_with(|| selected.as_str().to_owned());
    }
    for (index, (_, path)) in paths.into_iter().enumerate() {
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
