//! The Configuration grid rows: rendering plain and secret values, alias paths, and the secret padlock.

use crate::browser::browser_error;
use crate::configuration::absolute_path;
use crate::configuration::format_timestamp;
use crate::configuration::hide_new_value_row;
use crate::configuration::open_add_path;
use crate::configuration::open_delete;
use crate::configuration::reveal_existing_secret;
use crate::configuration::save_existing_secret;
use crate::configuration::save_existing_value;
use crate::configuration::validate_value_field;
use crate::dom::append;
use crate::dom::create_element;
use crate::dom::element;
use crate::dom::set_button_disabled;
use crate::dom::set_hidden;
use crate::dom::set_text;
use crate::icons::Icon;
use crate::icons::create_icon_button;
use crate::icons::set_icon_button_icon;
use crate::path_selector::render_path_options;
use sovereign_config_core::ClientError;
use sovereign_config_core::ListedValue;
use sovereign_config_core::ValueContent;
use sovereign_config_core::ValueListing;
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use wasm_bindgen_futures::spawn_local;
use web_sys::Document;
use web_sys::Element;
use web_sys::Event;
use web_sys::HtmlInputElement;
use web_sys::HtmlTextAreaElement;
use web_sys::window;

pub(crate) fn secret_field_revealed(input_id: &str) -> bool {
    element::<HtmlInputElement>(input_id).is_some_and(|input| {
        input.get_attribute("data-secret-state").as_deref() == Some("revealed")
    })
}

/// Closes a secret's padlock, discarding whatever the field held. Any plaintext
/// is dropped from both the value and the `data-loaded` marker, so nothing
/// survives in the DOM once the lock is shut.
pub(crate) fn lock_secret_field(input_id: &str, button_id: &str) {
    if let Some(input) = element::<HtmlInputElement>(input_id) {
        input.set_value("");
        input.set_type("password");
        let _ = input.set_attribute("data-secret-state", "locked");
        let _ = input.set_attribute("data-loaded", "");
    }
    set_secret_toggle(button_id, false);
}

/// Puts a padlock button into its locked or revealed state. Both labels are
/// carried on the button itself, so this serves the per-row padlocks and the
/// new-value row's alike.
pub(crate) fn set_secret_toggle(button_id: &str, revealed: bool) {
    let Some(button) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id(button_id))
    else {
        return;
    };
    let attribute = if revealed {
        "data-label-revealed"
    } else {
        "data-label-locked"
    };
    if let Some(label) = button.get_attribute(attribute) {
        let _ = button.set_attribute("aria-label", &label);
        let _ = button.set_attribute("title", &label);
    }
    let _ = button.set_attribute("aria-pressed", if revealed { "true" } else { "false" });
    let _ = set_icon_button_icon(
        &button,
        if revealed {
            Icon::LockOpen
        } else {
            Icon::LockClosed
        },
    );
}

pub(crate) fn render_listing(listing: &ValueListing) -> Result<(), ClientError> {
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

pub(crate) fn render_value_row(
    document: &Document,
    value: &ListedValue,
    index: usize,
) -> Result<Element, ClientError> {
    if matches!(&value.value, ValueContent::Secret(_)) {
        return render_secret_value_row(document, value, index);
    }
    let row = create_element(document, "tr", None)?;
    row.set_attribute("data-value-row", "")
        .map_err(|_| browser_error())?;

    let name_cell = create_element(document, "th", None)?;
    name_cell
        .set_attribute("scope", "row")
        .map_err(|_| browser_error())?;
    let name = value.path.name().unwrap_or_else(|| value.path.as_str());
    let name_text = create_element(document, "span", Some("value-name"))?;
    name_text.set_text_content(Some(name));
    let full_path = create_element(document, "span", Some("full-path"))?;
    full_path.set_text_content(Some(&absolute_path(&value.path)));
    append(&name_cell, &name_text)?;
    append(&name_cell, &full_path)?;
    append_alias_paths(document, &name_cell, value, index)?;

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
    let text = editor
        .clone()
        .dyn_into::<HtmlTextAreaElement>()
        .map_err(|_| browser_error())?;
    text.set_value(value.value.display_text());
    // Record what the control holds, not what was assigned to it: a textarea
    // normalizes CRLF to LF, so a stored value with CRLF would never compare
    // equal to its own source and every row of it would read as unsaved.
    editor
        .set_attribute("data-loaded", &text.value())
        .map_err(|_| browser_error())?;
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
    let save = create_icon_button(
        document,
        &save_id,
        &format!("Save {name}"),
        Icon::Save,
        Some("primary"),
    )?;
    let add_path_id = format!("add-path-listed-value-{index}");
    let add_path = create_icon_button(
        document,
        &add_path_id,
        &format!("Add a path to {name}"),
        Icon::AddPath,
        None,
    )?;
    let remove_id = format!("delete-listed-value-{index}");
    let remove = create_icon_button(
        document,
        &remove_id,
        &format!("Delete {name}"),
        Icon::Delete,
        Some("danger"),
    )?;
    append(&actions, &save)?;
    append(&actions, &add_path)?;
    append(&actions, &remove)?;
    append(&actions_cell, &actions)?;

    let add_path_source = value.path.clone();
    let add_path_focus = add_path_id;
    let callback = Closure::<dyn FnMut(_)>::new(move |_: Event| {
        open_add_path(add_path_source.clone(), add_path_focus.clone());
    });
    add_path
        .add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())
        .map_err(|_| browser_error())?;
    callback.forget();

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

pub(crate) fn render_secret_value_row(
    document: &Document,
    value: &ListedValue,
    index: usize,
) -> Result<Element, ClientError> {
    let row = create_element(document, "tr", None)?;
    row.set_attribute("data-value-row", "")
        .map_err(|_| browser_error())?;
    let name = value.path.name().ok_or_else(browser_error)?;

    let name_cell = create_element(document, "th", None)?;
    name_cell
        .set_attribute("scope", "row")
        .map_err(|_| browser_error())?;
    let name_text = create_element(document, "span", Some("value-name"))?;
    name_text.set_text_content(Some(name));
    let full_path = create_element(document, "span", Some("full-path"))?;
    full_path.set_text_content(Some(&absolute_path(&value.path)));
    append(&name_cell, &name_text)?;
    append(&name_cell, &full_path)?;
    append_alias_paths(document, &name_cell, value, index)?;

    // One box does both jobs: it shows the stored secret once the padlock is
    // opened, and it is where a replacement is typed. Left locked it stays
    // empty behind a masked placeholder, so writing a new secret never needs
    // the permission to read the current one.
    let value_cell = create_element(document, "td", None)?;
    let field = create_element(document, "div", Some("secret-field"))?;
    let input_id = format!("secret-value-{index}");
    let input = create_element(document, "input", None)?;
    for (attribute, attribute_value) in [
        ("id", input_id.as_str()),
        ("type", "password"),
        ("autocomplete", "new-password"),
        ("spellcheck", "false"),
        ("placeholder", value.value.display_text()),
        ("data-secret-state", "locked"),
        // Empty rather than absent: an untouched locked box is not an edit, and
        // the same comparison covers the revealed box once it holds the secret.
        ("data-loaded", ""),
        ("aria-label", &format!("Secret value for {name}")),
    ] {
        input
            .set_attribute(attribute, attribute_value)
            .map_err(|_| browser_error())?;
    }
    append(&field, &input)?;

    let toggle_id = format!("toggle-secret-{index}");
    let locked_label = format!("Reveal secret for {name}");
    let revealed_label = format!("Hide secret for {name}");
    let toggle = create_icon_button(
        document,
        &toggle_id,
        &locked_label,
        Icon::LockClosed,
        Some("secret"),
    )?;
    for (attribute, attribute_value) in [
        ("aria-controls", input_id.as_str()),
        ("aria-pressed", "false"),
        ("data-label-locked", locked_label.as_str()),
        ("data-label-revealed", revealed_label.as_str()),
    ] {
        toggle
            .set_attribute(attribute, attribute_value)
            .map_err(|_| browser_error())?;
    }
    append(&field, &toggle)?;
    append(&value_cell, &field)?;

    let updated = create_element(document, "td", Some("updated-time"))?;
    updated.set_text_content(Some(&format_timestamp(value.updated_at)));
    let actions_cell = create_element(document, "td", None)?;
    let actions = create_element(document, "div", Some("row-actions"))?;
    let save_id = format!("save-secret-{index}");
    let save = create_icon_button(
        document,
        &save_id,
        &format!("Save {name}"),
        Icon::Save,
        Some("primary"),
    )?;
    let add_path_id = format!("add-path-listed-value-{index}");
    let add_path = create_icon_button(
        document,
        &add_path_id,
        &format!("Add a path to {name}"),
        Icon::AddPath,
        None,
    )?;
    let remove_id = format!("delete-listed-value-{index}");
    let remove = create_icon_button(
        document,
        &remove_id,
        &format!("Delete {name}"),
        Icon::Delete,
        Some("danger"),
    )?;
    append(&actions, &save)?;
    append(&actions, &add_path)?;
    append(&actions, &remove)?;
    append(&actions_cell, &actions)?;

    let add_path_source = value.path.clone();
    let add_path_focus = add_path_id;
    let callback = Closure::<dyn FnMut(_)>::new(move |_: Event| {
        open_add_path(add_path_source.clone(), add_path_focus.clone());
    });
    add_path
        .add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())
        .map_err(|_| browser_error())?;
    callback.forget();

    let save_path = value.path.clone();
    let save_input = input_id.clone();
    let callback = Closure::<dyn FnMut(_)>::new(move |_: Event| {
        spawn_local(save_existing_secret(save_path.clone(), save_input.clone()));
    });
    save.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())
        .map_err(|_| browser_error())?;
    callback.forget();

    let toggle_path = value.path.clone();
    let toggle_input = input_id;
    let toggle_button = toggle_id;
    let callback = Closure::<dyn FnMut(_)>::new(move |_: Event| {
        if secret_field_revealed(&toggle_input) {
            lock_secret_field(&toggle_input, &toggle_button);
        } else {
            spawn_local(reveal_existing_secret(
                toggle_path.clone(),
                toggle_input.clone(),
                toggle_button.clone(),
            ));
        }
    });
    toggle
        .add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())
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

/// Renders the value's additional authorized paths (`alias_paths`) beneath the
/// primary path in the name cell. Each entry carries a danger "Remove" button
/// that deletes only that path via the shared delete-confirm flow; the value
/// survives through its remaining paths.
pub(crate) fn append_alias_paths(
    document: &Document,
    name_cell: &Element,
    value: &ListedValue,
    index: usize,
) -> Result<(), ClientError> {
    if value.alias_paths.is_empty() {
        return Ok(());
    }
    let list = create_element(document, "ul", Some("alias-paths"))?;
    list.set_attribute("aria-label", "Additional paths for this value")
        .map_err(|_| browser_error())?;
    for (alias_index, alias_path) in value.alias_paths.iter().enumerate() {
        let item = create_element(document, "li", Some("alias-path"))?;
        let absolute = absolute_path(alias_path);
        let path_text = create_element(document, "span", Some("full-path"))?;
        path_text.set_text_content(Some(&absolute));
        append(&item, &path_text)?;

        let remove_id = format!("remove-alias-path-{index}-{alias_index}");
        let remove = create_icon_button(
            document,
            &remove_id,
            &format!("Remove path {absolute}"),
            Icon::RemovePath,
            Some("danger small"),
        )?;
        let remove_path = alias_path.clone();
        let remove_focus = remove_id;
        let callback = Closure::<dyn FnMut(_)>::new(move |_: Event| {
            open_delete(remove_path.clone(), remove_focus.clone());
        });
        remove
            .add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())
            .map_err(|_| browser_error())?;
        callback.forget();
        append(&item, &remove)?;

        append(&list, &item)?;
    }
    append(name_cell, &list)?;
    Ok(())
}

pub(crate) fn clear_value_rows() {
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

/// Shuts every padlock on the page. Called whenever an error is raised, so a
/// failed request never leaves a revealed or half-typed secret on screen.
pub(crate) fn lock_all_secret_fields() {
    let Some(document) = window().and_then(|window| window.document()) else {
        return;
    };
    let inputs = document.get_elements_by_tag_name("input");
    for index in 0..inputs.length() {
        let Some(element) = inputs.item(index) else {
            continue;
        };
        let input_id = element.id();
        if input_id == "new-secret-content" {
            lock_secret_field(&input_id, "toggle-new-secret");
        } else if let Some(suffix) = input_id.strip_prefix("secret-value-") {
            lock_secret_field(&input_id, &format!("toggle-secret-{suffix}"));
        }
    }
}

/// Unmasks or re-masks a secret being typed. Nothing is fetched and nothing is
/// discarded — there is no stored value behind this field yet, so the padlock
/// only governs whether the operator can read back what they just entered.
pub(crate) fn toggle_secret_input(input_id: &str, button_id: &str) {
    let Some(input) = element::<HtmlInputElement>(input_id) else {
        return;
    };
    let revealed = input.type_() != "text";
    input.set_type(if revealed { "text" } else { "password" });
    set_secret_toggle(button_id, revealed);
}
