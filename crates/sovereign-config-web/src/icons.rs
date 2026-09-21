//! Inline SVG icons and icon buttons.

use sovereign_config_core::ClientError;
use web_sys::{Document, Element, window};

use crate::browser::browser_error;
use crate::dom::{append, create_element};

/// The icon set, drawn rather than imported so the app needs no icon asset and
/// no font beyond the two it already uses. Every glyph is a 16x16 stroke path
/// on `currentColor`, so a button's own colour carries through.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Icon {
    Save,
    AddPath,
    Delete,
    RemovePath,
    Rotate,
    Revoke,
    LockClosed,
    LockOpen,
    Key,
    History,
}

const fn icon_paths(icon: Icon) -> &'static [&'static str] {
    match icon {
        Icon::Save => &["m3 8.5 3.6 3.6L13 4.5"],
        Icon::AddPath => &["M8 3.5v9", "M3.5 8h9"],
        Icon::Delete => &[
            "M3 4.5h10",
            "M6.25 4.5V3.25h3.5V4.5",
            "m4.6 4.5.6 8.1a1 1 0 0 0 1 .9h3.6a1 1 0 0 0 1-.9l.6-8.1",
        ],
        Icon::RemovePath => &["M3.5 8h9"],
        Icon::Rotate => &["M13.2 8a5.2 5.2 0 1 1-1.5-3.7", "M11.7 1.8v2.7H9"],
        Icon::Revoke => &[
            "M8 2.3a5.7 5.7 0 1 0 0 11.4 5.7 5.7 0 0 0 0-11.4",
            "m4 12 8-8",
        ],
        Icon::LockClosed => &["M3.75 7.25h8.5v6h-8.5z", "M6 7.25V5.25a2 2 0 0 1 4 0v2"],
        Icon::LockOpen => &["M3.75 7.25h8.5v6h-8.5z", "M6 7.25V5.25a2 2 0 0 1 3.8-.85"],
        Icon::Key => &[
            "M5 4.8a3.2 3.2 0 1 0 0 6.4 3.2 3.2 0 0 0 0-6.4",
            "M8.2 8h6.3M12.5 8v2.4",
        ],
        // A clock face with a counter-clockwise arrow at its start: time, run
        // backwards.
        Icon::History => &[
            "M2.8 8a5.2 5.2 0 1 0 1.5-3.7",
            "M4.3 1.8v2.5H1.8",
            "M8 5.2V8l2 1.3",
        ],
    }
}

pub(crate) fn icon_svg(
    document: &Document,
    icon: Icon,
    class_name: &str,
) -> Result<Element, ClientError> {
    let svg = document
        .create_element_ns(Some("http://www.w3.org/2000/svg"), "svg")
        .map_err(|_| browser_error())?;
    for (name, value) in [
        ("class", class_name),
        ("viewBox", "0 0 16 16"),
        ("fill", "none"),
        ("stroke", "currentColor"),
        ("stroke-width", "1.5"),
        ("stroke-linecap", "round"),
        ("stroke-linejoin", "round"),
        // Decoration only: every icon button states itself in `aria-label`.
        ("aria-hidden", "true"),
        ("focusable", "false"),
    ] {
        svg.set_attribute(name, value)
            .map_err(|_| browser_error())?;
    }
    for definition in icon_paths(icon) {
        let path = document
            .create_element_ns(Some("http://www.w3.org/2000/svg"), "path")
            .map_err(|_| browser_error())?;
        path.set_attribute("d", definition)
            .map_err(|_| browser_error())?;
        append(&svg, &path)?;
    }
    Ok(svg)
}

/// An icon-only action. `label` is both the accessible name and the pointer
/// tooltip, so the two can never drift apart.
pub(crate) fn create_icon_button(
    document: &Document,
    id: &str,
    label: &str,
    icon: Icon,
    modifier: Option<&str>,
) -> Result<Element, ClientError> {
    let class = modifier.map_or_else(
        || "icon-button".to_owned(),
        |modifier| format!("icon-button {modifier}"),
    );
    let button = create_element(document, "button", Some(&class))?;
    for (name, value) in [
        ("id", id),
        ("type", "button"),
        ("aria-label", label),
        ("title", label),
    ] {
        button
            .set_attribute(name, value)
            .map_err(|_| browser_error())?;
    }
    append(&button, &icon_svg(document, icon, "icon")?)?;
    Ok(button)
}

pub(crate) fn set_icon_button_icon(button: &Element, icon: Icon) -> Result<(), ClientError> {
    let document = window()
        .and_then(|window| window.document())
        .ok_or_else(browser_error)?;
    // An icon button holds nothing but its glyph, so replacing the lot is both
    // the simplest and the only correct thing to do.
    button.set_text_content(None);
    append(button, &icon_svg(&document, icon, "icon")?)
}
