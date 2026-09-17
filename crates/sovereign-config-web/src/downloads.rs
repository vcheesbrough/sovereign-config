//! The Downloads view: the published installer manifest and its cards.

use crate::browser::browser_error;
use crate::browser::string_property;
use crate::dom::append;
use crate::dom::create_element;
use crate::dom::set_hidden;
use crate::dom::set_text;
use crate::route::Route;
use crate::route::route_from_location;
use crate::transport::fetch;
use js_sys::Reflect;
use sovereign_config_core::ClientError;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen::closure::Closure;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_futures::spawn_local;
use web_sys::Document;
use web_sys::Element;
use web_sys::Event;
use web_sys::window;

/// One installer as described by `/dist/manifest.json`.
pub(crate) struct InstallerEntry {
    pub(crate) file: String,
    pub(crate) checksum: Option<String>,
    pub(crate) size: Option<f64>,
}

/// Populates the Downloads view from the server's installer manifest. Needs no
/// authentication; the installers are public artifacts. A no-op unless the
/// Downloads route is active, so it is safe to call on every navigation.
pub(crate) async fn load_downloads() {
    if !matches!(route_from_location(), Route::Downloads) {
        return;
    }
    set_text("downloads-state", "Loading");
    if let Ok(entries) = fetch_installer_manifest().await {
        render_downloads(&entries);
    } else {
        clear_downloads_list();
        set_hidden("downloads-list", true);
        set_hidden("empty-downloads", true);
        set_text("downloads-state", "Unavailable");
    }
}

pub(crate) async fn fetch_installer_manifest() -> Result<Vec<InstallerEntry>, ClientError> {
    let response = fetch("/dist/manifest.json", "GET", None, &[]).await?;
    if !response.ok() {
        return Err(browser_error());
    }
    let json = JsFuture::from(response.json().map_err(|_| browser_error())?)
        .await
        .map_err(|_| browser_error())?;
    let installers =
        Reflect::get(&json, &JsValue::from_str("installers")).map_err(|_| browser_error())?;
    let mut entries = Vec::new();
    for item in js_sys::Array::from(&installers).iter() {
        let Ok(file) = string_property(&item, "file") else {
            continue;
        };
        let checksum = Reflect::get(&item, &JsValue::from_str("checksum"))
            .ok()
            .and_then(|value| value.as_string());
        let size = Reflect::get(&item, &JsValue::from_str("size"))
            .ok()
            .and_then(|value| value.as_f64());
        entries.push(InstallerEntry {
            file,
            checksum,
            size,
        });
    }
    Ok(entries)
}

pub(crate) fn clear_downloads_list() {
    if let Some(list) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id("downloads-list"))
    {
        list.set_text_content(Some(""));
    }
}

pub(crate) fn render_downloads(entries: &[InstallerEntry]) {
    let Some(document) = window().and_then(|window| window.document()) else {
        return;
    };
    let Some(list) = document.get_element_by_id("downloads-list") else {
        return;
    };
    list.set_text_content(Some(""));
    if entries.is_empty() {
        set_hidden("downloads-list", true);
        set_hidden("empty-downloads", false);
        set_text("downloads-state", "No installers");
        return;
    }
    set_hidden("empty-downloads", true);
    set_hidden("downloads-list", false);
    let origin = window()
        .and_then(|window| window.location().origin().ok())
        .unwrap_or_default();
    for entry in entries {
        if let Ok(card) = build_download_card(&document, entry, &origin) {
            let _ = append(&list, &card);
        }
    }
    let count = entries.len();
    set_text(
        "downloads-state",
        &format!("{count} installer{}", if count == 1 { "" } else { "s" }),
    );
}

pub(crate) fn build_download_card(
    document: &Document,
    entry: &InstallerEntry,
    origin: &str,
) -> Result<Element, ClientError> {
    let card = create_element(document, "section", Some("download-card"))?;

    let heading = create_element(document, "h2", None)?;
    let name = create_element(document, "code", None)?;
    name.set_text_content(Some(&entry.file));
    append(&heading, &name)?;
    append(&card, &heading)?;

    let meta = create_element(document, "p", Some("status-text download-meta"))?;
    meta.set_text_content(Some(&human_size(entry.size)));
    if let Some(checksum) = &entry.checksum {
        let separator = create_element(document, "span", None)?;
        separator.set_text_content(Some(" \u{00b7} "));
        append(&meta, &separator)?;
        let link = create_element(document, "a", None)?;
        link.set_attribute("href", &format!("/dist/{checksum}"))
            .map_err(|_| browser_error())?;
        link.set_text_content(Some("sha256"));
        append(&meta, &link)?;
    }
    append(&card, &meta)?;

    let actions = create_element(document, "p", Some("download-actions"))?;
    let download = create_element(document, "a", Some("button-link"))?;
    download
        .set_attribute("href", &format!("/dist/{}", entry.file))
        .map_err(|_| browser_error())?;
    download
        .set_attribute("download", "")
        .map_err(|_| browser_error())?;
    download.set_text_content(Some("Download installer"));
    append(&actions, &download)?;
    append(&card, &actions)?;

    let command_label = create_element(document, "p", None)?;
    command_label.set_text_content(Some("Or download and run in one step:"));
    append(&card, &command_label)?;

    // A readable multi-line form. Newlines inside the single-quoted `sh -c`
    // script separate statements; the trailing `\` continues the long curl line.
    // `set -e` aborts on any failure (so a failed download never runs a partial
    // installer), and the trap keeps it a self-cleaning subshell.
    let url = format!("{origin}/dist/{}", entry.file);
    let command = [
        "sh -c '".to_owned(),
        "  set -e".to_owned(),
        "  d=$(mktemp -d)".to_owned(),
        "  trap \"rm -rf \\\"$d\\\"\" EXIT".to_owned(),
        format!("  curl -fsSL \"{url}\" \\"),
        "    -o \"$d/installer.sh\"".to_owned(),
        "  sh \"$d/installer.sh\"".to_owned(),
        "'".to_owned(),
    ]
    .join("\n");

    let command_block = create_element(document, "pre", Some("download-command"))?;
    // The block scrolls, so it must be keyboard-focusable for scroll access
    // (axe scrollable-region-focusable).
    command_block
        .set_attribute("tabindex", "0")
        .map_err(|_| browser_error())?;
    command_block
        .set_attribute("aria-label", "Install command")
        .map_err(|_| browser_error())?;
    let command_code = create_element(document, "code", None)?;
    command_code.set_text_content(Some(&command));
    append(&command_block, &command_code)?;
    append(&card, &command_block)?;

    let command_actions = create_element(document, "div", Some("download-command-actions"))?;
    let copy = create_element(document, "button", Some("secondary"))?;
    copy.set_attribute("type", "button")
        .map_err(|_| browser_error())?;
    copy.set_text_content(Some("Copy command"));
    let status = create_element(document, "span", Some("download-copy-status"))?;
    status
        .set_attribute("aria-live", "polite")
        .map_err(|_| browser_error())?;
    let command_for_copy = command.clone();
    let status_for_copy = status.clone();
    let callback = Closure::<dyn FnMut(_)>::new(move |_: Event| {
        let command = command_for_copy.clone();
        let status = status_for_copy.clone();
        spawn_local(async move { copy_to_clipboard(&command, &status).await });
    });
    copy.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())
        .map_err(|_| browser_error())?;
    callback.forget();
    append(&command_actions, &copy)?;
    append(&command_actions, &status)?;
    append(&card, &command_actions)?;

    Ok(card)
}

pub(crate) async fn copy_to_clipboard(text: &str, status: &Element) {
    let Some(clipboard) = window().map(|window| window.navigator().clipboard()) else {
        status.set_text_content(Some("Copy failed"));
        return;
    };
    match JsFuture::from(clipboard.write_text(text)).await {
        Ok(_) => status.set_text_content(Some("Copied")),
        Err(_) => status.set_text_content(Some("Copy failed")),
    }
}

pub(crate) fn human_size(size: Option<f64>) -> String {
    match size {
        Some(bytes) if bytes >= 1_048_576.0 => format!("{:.1} MB", bytes / 1_048_576.0),
        Some(bytes) if bytes >= 1024.0 => format!("{:.0} KB", bytes / 1024.0),
        Some(bytes) => format!("{bytes:.0} bytes"),
        None => "installer".to_owned(),
    }
}
