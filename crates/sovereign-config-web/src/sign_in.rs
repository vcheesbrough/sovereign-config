//! The signed-out face of the app (card #565). Without a session, every view
//! but Downloads is a sign-in card that says what is being logged in to — this
//! server, its version, and the identity provider — instead of an empty editor
//! and an "authentication required" banner. The brand menu still lists every
//! view; those needing a session carry a "log in" hint, and picking one opens
//! the card.
//!
//! The session state is the browser's own token state (`session_held`): it
//! is known before anything is asked of the server, so a signed-out visit
//! never flashes the editor.

use web_sys::{Url, window};

use crate::browser::app_config;
use crate::dom::{element_is_hidden, set_hidden, set_text};
use crate::route::Route;
use crate::session::{callback_pending, session_held};

/// The brand-menu links to views that need a session.
const PROTECTED_LINKS: [&str; 3] = [
    "configuration-values-link",
    "managed-connections-link",
    "audit-trail-link",
];

/// The views the sign-in card stands in for.
const PROTECTED_PAGES: [&str; 3] = ["configuration-page", "connections-page", "audit-page"];

/// Applies the session state to the shell for `route`: the card in place of a
/// protected view, the sidebar only with a session, and the menu's protected
/// links marked as needing a login without one. Runs after the route's own page is shown.
pub(crate) fn render_sign_in(route: &Route) {
    let signed_out = !session_held();
    // An OIDC callback holds no session until `finish_login` has read its
    // code; showing the card then would flash it on every login. Once it has
    // read it, success or not, the card follows the session again.
    let show = signed_out && !callback_pending() && !matches!(route, Route::Downloads);

    set_body_state(
        "data-session",
        if signed_out {
            "signed-out"
        } else {
            "signed-in"
        },
    );
    set_body_state("data-sign-in", if show { "shown" } else { "hidden" });
    if show {
        for page in PROTECTED_PAGES {
            set_hidden(page, true);
        }
        set_text("sign-in-host", &host());
        set_text("sign-in-issuer", &issuer_host());
    }
    set_hidden("sign-in-page", !show);
    for id in PROTECTED_LINKS {
        mark_needs_login(id, signed_out);
    }
}

/// Whether the sign-in card is what the page is showing.
pub(crate) fn sign_in_shown() -> bool {
    !element_is_hidden("sign-in-page")
}

/// The server this page came from, as its address bar names it.
fn host() -> String {
    window()
        .and_then(|window| window.location().host().ok())
        .unwrap_or_default()
}

/// The identity provider's host, from the issuer the server configured. The
/// whole issuer URL is a path inside the provider, which tells a person
/// nothing they could check.
fn issuer_host() -> String {
    app_config()
        .ok()
        .and_then(|config| Url::new(&config.issuer).ok())
        .map(|url| url.host())
        .unwrap_or_default()
}

/// A protected view stays a working link without a session — it opens the
/// sign-in card — and only wears a hint that it needs a login.
fn mark_needs_login(id: &str, needs_login: bool) {
    let Some(link) = document_element(id) else {
        return;
    };
    if needs_login {
        let _ = link.set_attribute("data-needs-login", "");
        let _ = link.set_attribute("title", "Log in to open");
    } else {
        let _ = link.remove_attribute("data-needs-login");
        let _ = link.remove_attribute("title");
    }
}

fn set_body_state(name: &str, value: &str) {
    if let Some(body) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.body())
    {
        let _ = body.set_attribute(name, value);
    }
}

fn document_element(id: &str) -> Option<web_sys::Element> {
    window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id(id))
}
