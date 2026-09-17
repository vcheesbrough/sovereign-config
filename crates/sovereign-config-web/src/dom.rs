//! Small typed helpers over the document: element lookup, text, visibility, focus, and the page error banner.

use crate::browser::browser_error;
use crate::value_rows::lock_all_secret_fields;
use sovereign_config_core::ClientError;
use wasm_bindgen::JsCast;
use web_sys::Document;
use web_sys::Element;
use web_sys::HtmlButtonElement;
use web_sys::HtmlDialogElement;
use web_sys::HtmlTextAreaElement;
use web_sys::window;

pub(crate) fn set_active(id: &str, active: bool) {
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

pub(crate) fn element_is_hidden(id: &str) -> bool {
    window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id(id))
        .is_none_or(|element| element.has_attribute("hidden"))
}

pub(crate) fn close_dialog(id: &str) {
    if let Some(dialog) = element::<HtmlDialogElement>(id) {
        dialog.close();
    }
}

pub(crate) fn create_element(
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

pub(crate) fn append(parent: &Element, child: &Element) -> Result<(), ClientError> {
    parent
        .append_child(child)
        .map(|_| ())
        .map_err(|_| browser_error())
}

pub(crate) fn current_text(id: &str) -> Option<String> {
    window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id(id))
        .and_then(|element| element.text_content())
}

pub(crate) fn set_text(id: &str, text: &str) {
    if let Some(element) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id(id))
    {
        element.set_text_content(Some(text));
    }
}

pub(crate) fn element<T: JsCast>(id: &str) -> Option<T> {
    window()?
        .document()?
        .get_element_by_id(id)?
        .dyn_into::<T>()
        .ok()
}

pub(crate) fn set_textarea(id: &str, value: &str) {
    if let Some(element) = element::<HtmlTextAreaElement>(id) {
        element.set_value(value);
    }
}

/// Sets a textarea and records what was loaded into it, so [`has_unsaved_edits`]
/// can tell an edit from the stored text by comparison.
pub(crate) fn set_loaded_textarea(id: &str, value: &str) {
    set_textarea(id, value);
    // Read the text back off the control rather than trusting `value`: a
    // textarea normalizes CRLF to LF, and a mismatch here would read as an
    // unsaved edit on a document nobody has touched.
    let Some(loaded) = element::<HtmlTextAreaElement>(id).map(|editor| editor.value()) else {
        return;
    };
    if let Some(element) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id(id))
    {
        let _ = element.set_attribute("data-loaded", &loaded);
    }
}

pub(crate) fn set_button_disabled(id: &str, disabled: bool) {
    if let Some(element) = element::<HtmlButtonElement>(id) {
        element.set_disabled(disabled);
    }
}

pub(crate) fn set_hidden(id: &str, hidden: bool) {
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

pub(crate) fn focus(id: &str) {
    if let Some(element) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id(id))
        .and_then(|element| element.dyn_into::<web_sys::HtmlElement>().ok())
    {
        let _ = element.focus();
    }
}

pub(crate) fn show_error(message: &str) {
    lock_all_secret_fields();
    set_text("error", message);
    set_hidden("error", false);
}

pub(crate) fn clear_error() {
    set_text("error", "");
    set_hidden("error", true);
}
