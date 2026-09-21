//! The Audit trail view: its filters, the event list that loads further pages
//! as it is scrolled, and the one-value history the Configuration grid links to.
//!
//! Paging is the one part of this crate with no precedent, so its rules live in
//! [`AuditFeed`], which knows nothing of the DOM and is tested natively. The
//! rest of the module is wiring: read the form, ask the feed what to fetch, and
//! draw what comes back only when the feed says it still belongs.

use sovereign_config_core::{
    AuditEntry, AuditEventKind, AuditQuery, ClientError, ConfigPath, ProtocolVersion, Timestamp,
};
use std::cell::RefCell;
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use wasm_bindgen_futures::spawn_local;
use web_sys::{
    Document, Element, Event, HtmlInputElement, IntersectionObserver, IntersectionObserverEntry,
    IntersectionObserverInit, window,
};

use crate::browser::{app_config, browser_error};
use crate::configuration::{format_timestamp, set_validation};
use crate::dom::{append, create_element, element, on_element_id, set_hidden, set_text};
use crate::route::{Route, guarded_navigate, route_from_location};
use crate::transport::value_client;

/// How far below the viewport the next page starts loading, so a steady scroll
/// rarely reaches the end of what is already drawn.
const PREFETCH_MARGIN: &str = "0px 0px 600px 0px";

const MAX_PATH_FILTER_CHARACTERS: usize = 512;
const MAX_TEXT_FILTER_CHARACTERS: usize = 256;
const MAX_PROTOCOL_VERSION_CHARACTERS: usize = 32;

thread_local! {
    static FEED: RefCell<AuditFeed> = RefCell::new(AuditFeed::default());
    static OBSERVER: RefCell<Option<IntersectionObserver>> = const { RefCell::new(None) };
    static SHOWN_MODE: RefCell<ShownMode> = const { RefCell::new(ShownMode::NotYetShown) };
}

/// What the filter form was last set up for.
#[derive(Eq, PartialEq)]
enum ShownMode {
    NotYetShown,
    WholeTrail,
    ValueHistory(ConfigPath),
}

/// The kinds of event the view filters on, as an operator thinks of them
/// rather than as the trail labels them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KindGroup {
    Changes,
    SecretReveals,
    AccessUrls,
    Reads,
}

impl KindGroup {
    pub(crate) const ALL: [Self; 4] = [
        Self::Changes,
        Self::SecretReveals,
        Self::AccessUrls,
        Self::Reads,
    ];

    const fn checkbox_id(self) -> &'static str {
        match self {
            Self::Changes => "audit-kind-changes",
            Self::SecretReveals => "audit-kind-secrets",
            Self::AccessUrls => "audit-kind-connections",
            Self::Reads => "audit-kind-reads",
        }
    }

    pub(crate) const fn kinds(self) -> &'static [AuditEventKind] {
        match self {
            Self::Changes => &[
                AuditEventKind::ValueCreated,
                AuditEventKind::ValueUpdated,
                AuditEventKind::ValueDeleted,
                AuditEventKind::ValuePathAdded,
                AuditEventKind::SubtreeReplaced,
                AuditEventKind::SubtreeDeleted,
            ],
            Self::SecretReveals => &[AuditEventKind::SecretRevealed],
            Self::AccessUrls => &[
                AuditEventKind::ConnectionCreated,
                AuditEventKind::ConnectionRotated,
                AuditEventKind::ConnectionRevoked,
            ],
            Self::Reads => &[AuditEventKind::SubtreeRead, AuditEventKind::ValuesListed],
        }
    }

    /// What the view opens on. Reads outnumber everything else — every
    /// provider load is one — so the whole trail opens without them, or they
    /// would bury the changes people come to see. A single value's history
    /// includes them: reads of its namespaces are the only reads it ever has.
    pub(crate) const fn shown_by_default(self, element: bool) -> bool {
        element || !matches!(self, Self::Reads)
    }
}

/// What the filter form holds, already parsed where the browser had to parse
/// it.
#[derive(Clone, Debug, Default)]
pub(crate) struct FilterInput {
    pub(crate) path: String,
    pub(crate) text: String,
    pub(crate) from: Option<Timestamp>,
    pub(crate) until: Option<Timestamp>,
    pub(crate) protocol_version: String,
    pub(crate) groups: Vec<KindGroup>,
}

/// A filter the service would refuse, with the field to report it on.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct FilterError {
    pub(crate) field: &'static str,
    pub(crate) message: &'static str,
}

/// The query the form describes, validated as the service validates it so an
/// operator is told which field is wrong rather than that the query was.
pub(crate) fn build_query(
    input: &FilterInput,
    element: Option<&ConfigPath>,
) -> Result<AuditQuery, Vec<FilterError>> {
    let mut errors = Vec::new();
    let path = input.path.trim();
    // A value's history is an element query, which the service will not
    // combine with a path fragment; the field is disabled there, and ignored
    // here in case it still holds text from before.
    let path_filter = (element.is_none() && !path.is_empty()).then(|| path.to_owned());
    if path_filter.as_ref().is_some_and(|path| {
        path.len() > MAX_PATH_FILTER_CHARACTERS
            || !path
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'/'))
    }) {
        errors.push(FilterError {
            field: "audit-path-filter",
            message: "use only letters, digits, _, - and /, at most 512 of them",
        });
    }
    let text = input.text.trim();
    if text.chars().count() > MAX_TEXT_FILTER_CHARACTERS || text.contains('\0') {
        errors.push(FilterError {
            field: "audit-text-filter",
            message: "enter at most 256 characters",
        });
    }
    let protocol_version = input.protocol_version.trim();
    if protocol_version.len() > MAX_PROTOCOL_VERSION_CHARACTERS
        || !protocol_version
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        errors.push(FilterError {
            field: "audit-protocol",
            message: "enter a version label such as v4",
        });
    }
    if let (Some(from), Some(until)) = (&input.from, &input.until)
        && (from.seconds, from.nanos) > (until.seconds, until.nanos)
    {
        errors.push(FilterError {
            field: "audit-until",
            message: "choose a time after the start of the range",
        });
    }
    if input.groups.is_empty() {
        errors.push(FilterError {
            field: "audit-kinds",
            message: "choose at least one kind of event",
        });
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    // Every group ticked is every kind, which the service spells as none: a
    // kind this build does not know yet is then not silently left out.
    let kinds = if KindGroup::ALL
        .iter()
        .all(|group| input.groups.contains(group))
    {
        Vec::new()
    } else {
        KindGroup::ALL
            .iter()
            .filter(|group| input.groups.contains(group))
            .flat_map(|group| group.kinds().iter().copied())
            .collect()
    };
    Ok(AuditQuery {
        path_filter,
        element_path: element.cloned(),
        text_filter: (!text.is_empty()).then(|| text.to_owned()),
        from: input.from,
        until: input.until,
        protocol_version: (!protocol_version.is_empty()).then(|| protocol_version.to_owned()),
        kinds,
        page_size: 0,
        cursor: None,
    })
}

/// A browser instant, in milliseconds since the epoch, as a protobuf-style
/// timestamp. `None` for anything that is not a finite instant.
pub(crate) fn timestamp_from_millis(milliseconds: f64) -> Option<Timestamp> {
    if !milliseconds.is_finite() {
        return None;
    }
    let seconds = (milliseconds / 1000.0).floor();
    let nanos = ((milliseconds - seconds * 1000.0) * 1_000_000.0).round();
    #[expect(
        clippy::cast_possible_truncation,
        reason = "a datetime-local input cannot express an instant outside i64 seconds, and nanos is below 1e9 by construction"
    )]
    Some(Timestamp {
        seconds: seconds as i64,
        nanos: nanos as i32,
    })
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum FeedState {
    /// Nothing in flight; the next page, if any, may be fetched.
    #[default]
    Idle,
    Loading,
    /// The last fetch failed. Only an explicit retry fetches again, so a list
    /// that cannot load does not hammer the service every time it scrolls.
    Failed,
    /// The service said there is nothing after the last page.
    Ended,
}

/// One page to fetch, stamped with the query generation it belongs to.
#[derive(Debug)]
pub(crate) struct PageRequest {
    pub(crate) generation: u64,
    pub(crate) query: AuditQuery,
}

impl PageRequest {
    pub(crate) const fn is_first_page(&self) -> bool {
        self.query.cursor.is_none()
    }
}

pub(crate) enum PageOutcome {
    Loaded { next_cursor: Option<String> },
    Failed,
}

/// The paging rules, apart from the DOM.
///
/// Every page is fetched through [`AuditFeed::restart`], [`AuditFeed::advance`]
/// or [`AuditFeed::retry`], and every reply is admitted through
/// [`AuditFeed::settle`]. Between them they guarantee the four things an
/// infinite list gets wrong: only one page is ever in flight; nothing is asked
/// for after the last page; a failure stops the list without losing its place;
/// and a page for a query that has since changed is thrown away.
#[derive(Default)]
pub(crate) struct AuditFeed {
    generation: u64,
    active: bool,
    query: AuditQuery,
    next_cursor: Option<String>,
    state: FeedState,
}

impl AuditFeed {
    /// Starts over on `query`, returning its first page. A page still in flight
    /// belongs to the superseded query and will be refused when it lands.
    pub(crate) fn restart(&mut self, query: AuditQuery) -> PageRequest {
        self.generation = self.generation.wrapping_add(1);
        self.active = true;
        self.query = query;
        self.next_cursor = None;
        self.state = FeedState::Loading;
        self.request()
    }

    /// The next page, when the list may have one: nothing in flight, not
    /// failed, and a cursor from the service to continue from.
    pub(crate) fn advance(&mut self) -> Option<PageRequest> {
        (self.active && self.state == FeedState::Idle && self.next_cursor.is_some()).then(|| {
            self.state = FeedState::Loading;
            self.request()
        })
    }

    /// The page that failed, again — from the same cursor, so a retry neither
    /// skips nor repeats anything.
    pub(crate) fn retry(&mut self) -> Option<PageRequest> {
        (self.active && self.state == FeedState::Failed).then(|| {
            self.state = FeedState::Loading;
            self.request()
        })
    }

    /// Admits a reply. `false` means it belongs to a query that has since been
    /// replaced or abandoned, and must not be drawn.
    pub(crate) fn settle(&mut self, generation: u64, outcome: PageOutcome) -> bool {
        if !self.active || generation != self.generation || self.state != FeedState::Loading {
            return false;
        }
        match outcome {
            PageOutcome::Loaded { next_cursor } => {
                self.state = if next_cursor.is_some() {
                    FeedState::Idle
                } else {
                    FeedState::Ended
                };
                self.next_cursor = next_cursor;
            }
            PageOutcome::Failed => self.state = FeedState::Failed,
        }
        true
    }

    /// Abandons the current query: leaving the view or logging out. Whatever
    /// is in flight is refused when it lands.
    pub(crate) fn invalidate(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.active = false;
        self.next_cursor = None;
        self.state = FeedState::Idle;
    }

    /// Whether the list already shows `query`, loaded or loading, so asking
    /// for it again would only repeat the same first page.
    pub(crate) fn is_showing(&self, query: &AuditQuery) -> bool {
        self.active && self.state != FeedState::Failed && self.query == *query
    }

    pub(crate) const fn state(&self) -> FeedState {
        self.state
    }

    fn request(&self) -> PageRequest {
        PageRequest {
            generation: self.generation,
            query: AuditQuery {
                cursor: self.next_cursor.clone(),
                ..self.query.clone()
            },
        }
    }
}

pub(crate) fn install_audit_actions(document: &Document) {
    on_element_id(document, "audit-filters", "submit", |event: Event| {
        event.prevent_default();
        apply_filters();
    });
    // `change` rather than `input`: a text field settles on Enter or on
    // leaving it, not on every keystroke, and the rest settle when picked.
    on_element_id(document, "audit-filters", "change", |_: Event| {
        apply_filters();
    });
    // Errors, on the other hand, follow every keystroke. One that lingered
    // until the field was left would vanish on the press that leaves it, and
    // the form shifting under the pointer mid-click would swallow the click.
    on_element_id(document, "audit-filters", "input", |_: Event| {
        if let Route::Audit(element_path) = route_from_location() {
            clear_filter_errors();
            if let Err(errors) = build_query(&read_form(), element_path.as_ref()) {
                show_filter_errors(errors);
            }
        }
    });
    on_element_id(document, "retry-audit", "click", |_: Event| {
        if let Some(request) = FEED.with_borrow_mut(AuditFeed::retry) {
            spawn_local(fetch_page(request));
        }
    });
    on_element_id(document, "audit-whole-trail", "click", |event: Event| {
        event.prevent_default();
        guarded_navigate(Route::Audit(None));
    });
    if let Some(list) = document.get_element_by_id("audit-protocol-versions") {
        for version in ProtocolVersion::ALL {
            if let Ok(option) = create_element(document, "option", None) {
                let _ = option.set_attribute("value", version.as_str());
                let _ = append(&list, &option);
            }
        }
    }
    install_observer();
}

/// Watches the sentinel under the last row. Crossing into the prefetch margin
/// asks the feed for the next page, which it declines while one is in flight,
/// after a failure, or at the end.
fn install_observer() {
    let callback = Closure::<dyn FnMut(js_sys::Array, IntersectionObserver)>::new(
        |entries: js_sys::Array, _: IntersectionObserver| {
            let intersecting = entries.iter().any(|entry| {
                entry
                    .dyn_into::<IntersectionObserverEntry>()
                    .is_ok_and(|entry| entry.is_intersecting())
            });
            if intersecting && let Some(request) = FEED.with_borrow_mut(AuditFeed::advance) {
                spawn_local(fetch_page(request));
            }
        },
    );
    let options = IntersectionObserverInit::new();
    options.set_root_margin(PREFETCH_MARGIN);
    if let Ok(observer) =
        IntersectionObserver::new_with_options(callback.as_ref().unchecked_ref(), &options)
    {
        OBSERVER.with_borrow_mut(|slot| *slot = Some(observer));
    }
    callback.forget();
}

/// Starts watching the sentinel afresh. An observer reports only changes, so a
/// sentinel that was already in view and still is after a short page would
/// never be reported again; observing anew reports where it is now.
fn rearm_observer() {
    disarm_observer();
    if let Some(sentinel) = sentinel() {
        OBSERVER.with_borrow(|observer| {
            if let Some(observer) = observer {
                observer.observe(&sentinel);
            }
        });
    }
}

fn disarm_observer() {
    if let Some(sentinel) = sentinel() {
        OBSERVER.with_borrow(|observer| {
            if let Some(observer) = observer {
                observer.unobserve(&sentinel);
            }
        });
    }
}

fn sentinel() -> Option<Element> {
    window()?.document()?.get_element_by_id("audit-sentinel")
}

/// Sets the view up for the route: the whole trail, or one value's history.
/// The form is reset to that mode's defaults only when the mode changes, so
/// coming back to the same view keeps the filters an operator chose.
pub(crate) fn render_audit_route(element_path: Option<&ConfigPath>) {
    let mode = element_path.map_or(ShownMode::WholeTrail, |path| {
        ShownMode::ValueHistory(path.clone())
    });
    if SHOWN_MODE.with_borrow(|shown| *shown == mode) {
        return;
    }
    SHOWN_MODE.with_borrow_mut(|shown| *shown = mode);
    reset_filters(element_path.is_some());
    set_hidden("audit-element", element_path.is_none());
    set_text(
        "audit-element-path",
        element_path.map_or("", ConfigPath::as_str),
    );
    if let Some(field) = element::<HtmlInputElement>("audit-path-filter") {
        field.set_disabled(element_path.is_some());
    }
}

fn reset_filters(value_history: bool) {
    for id in [
        "audit-path-filter",
        "audit-text-filter",
        "audit-from",
        "audit-until",
        "audit-protocol",
    ] {
        if let Some(field) = element::<HtmlInputElement>(id) {
            field.set_value("");
        }
    }
    for group in KindGroup::ALL {
        if let Some(checkbox) = element::<HtmlInputElement>(group.checkbox_id()) {
            checkbox.set_checked(group.shown_by_default(value_history));
        }
    }
    clear_filter_errors();
}

/// Loads the first page for the current route and form. A no-op, beyond
/// abandoning any list in progress, unless the Audit route is active — so it is
/// safe to call on every navigation.
pub(crate) async fn load_audit() {
    let Route::Audit(element_path) = route_from_location() else {
        reset_audit();
        return;
    };
    if let Some(query) = form_query(element_path.as_ref()) {
        spawn_local(fetch_page(start_feed(query)));
    }
}

/// Re-queries after a filter change, unless the list already shows exactly
/// that — a text field that is submitted with Enter reports a change as well.
fn apply_filters() {
    let Route::Audit(element_path) = route_from_location() else {
        return;
    };
    let Some(query) = form_query(element_path.as_ref()) else {
        return;
    };
    if FEED.with_borrow(|feed| feed.is_showing(&query)) {
        return;
    }
    spawn_local(fetch_page(start_feed(query)));
}

/// Forgets the list: on leaving the view and on logging out.
pub(crate) fn reset_audit() {
    FEED.with_borrow_mut(AuditFeed::invalidate);
    disarm_observer();
    clear_audit_rows();
    set_hidden("empty-audit", true);
    hide_page_error();
}

fn start_feed(query: AuditQuery) -> PageRequest {
    let request = FEED.with_borrow_mut(|feed| feed.restart(query));
    disarm_observer();
    clear_audit_rows();
    set_hidden("empty-audit", true);
    request
}

fn form_query(element_path: Option<&ConfigPath>) -> Option<AuditQuery> {
    clear_filter_errors();
    match build_query(&read_form(), element_path) {
        Ok(query) => Some(query),
        Err(errors) => {
            show_filter_errors(errors);
            set_text("audit-state", "Check the filters");
            None
        }
    }
}

fn show_filter_errors(errors: Vec<FilterError>) {
    for error in errors {
        set_validation(
            error.field,
            &format!("{}-error", error.field),
            Some(error.message),
        );
    }
}

fn clear_filter_errors() {
    for field in [
        "audit-path-filter",
        "audit-text-filter",
        "audit-protocol",
        "audit-until",
        "audit-kinds",
    ] {
        set_validation(field, &format!("{field}-error"), None);
    }
}

fn read_form() -> FilterInput {
    let text = |id: &str| {
        element::<HtmlInputElement>(id)
            .map(|field| field.value())
            .unwrap_or_default()
    };
    // A `datetime-local` value has no zone, and the date-time form of
    // `Date.parse` reads exactly that as local time — which is what the
    // operator picked it in.
    let instant = |id: &str| {
        Some(text(id))
            .filter(|value| !value.is_empty())
            .and_then(|value| timestamp_from_millis(js_sys::Date::parse(&value)))
    };
    FilterInput {
        path: text("audit-path-filter"),
        text: text("audit-text-filter"),
        from: instant("audit-from"),
        until: instant("audit-until"),
        protocol_version: text("audit-protocol"),
        groups: KindGroup::ALL
            .into_iter()
            .filter(|group| {
                element::<HtmlInputElement>(group.checkbox_id())
                    .is_some_and(|checkbox| checkbox.checked())
            })
            .collect(),
    }
}

async fn fetch_page(request: PageRequest) {
    hide_page_error();
    set_text(
        "audit-state",
        if request.is_first_page() {
            "Loading"
        } else {
            "Loading more"
        },
    );
    let result = async {
        let config = app_config()?;
        value_client(&config)
            .query_audit_trail(&request.query)
            .await
    }
    .await;
    let outcome = match &result {
        Ok(page) => PageOutcome::Loaded {
            next_cursor: page.next_cursor.clone(),
        },
        Err(_) => PageOutcome::Failed,
    };
    if !FEED.with_borrow_mut(|feed| feed.settle(request.generation, outcome)) {
        return;
    }
    match result {
        Ok(page) => {
            if let Err(error) = append_events(&page.events) {
                show_page_error(&error);
                return;
            }
            let count = audit_row_count();
            set_hidden("empty-audit", count != 0);
            let ended = FEED.with_borrow(AuditFeed::state) == FeedState::Ended;
            let noun = if count == 1 { "event" } else { "events" };
            set_text(
                "audit-state",
                &if ended {
                    format!("{count} {noun}")
                } else {
                    format!("{count} {noun} so far")
                },
            );
            if ended {
                disarm_observer();
            } else {
                rearm_observer();
            }
        }
        Err(error) => {
            set_text("audit-state", "Error");
            show_page_error(&error);
        }
    }
}

/// The failure is reported beside the list rather than in the page banner, so
/// the rows already loaded stay where they are and the retry is next to them.
fn show_page_error(error: &ClientError) {
    disarm_observer();
    set_text("audit-page-error", error.message());
    set_hidden("audit-page-error", false);
    set_hidden("retry-audit", false);
}

fn hide_page_error() {
    set_text("audit-page-error", "");
    set_hidden("audit-page-error", true);
    set_hidden("retry-audit", true);
}

fn audit_body() -> Option<Element> {
    window()?.document()?.get_element_by_id("audit-body")
}

fn clear_audit_rows() {
    if let Some(body) = audit_body() {
        body.set_text_content(Some(""));
    }
}

fn audit_row_count() -> u32 {
    audit_body().map_or(0, |body| body.child_element_count())
}

fn append_events(events: &[AuditEntry]) -> Result<(), ClientError> {
    let document = window()
        .and_then(|window| window.document())
        .ok_or_else(browser_error)?;
    let body = audit_body().ok_or_else(browser_error)?;
    for event in events {
        append(&body, &render_event(&document, event)?)?;
    }
    Ok(())
}

fn render_event(document: &Document, event: &AuditEntry) -> Result<Element, ClientError> {
    let row = create_element(document, "tr", None)?;
    row.set_attribute("data-audit-event", &event.id.to_string())
        .map_err(|_| browser_error())?;

    // First occurrence, because that is the order the trail is in; a
    // coalesced row's narrative carries its count and the rest of its period.
    let when = create_element(document, "td", Some("updated-time"))?;
    when.set_text_content(Some(&format_timestamp(event.first_occurred_at)));

    let actor = create_element(document, "td", Some("audit-actor"))?;
    actor.set_text_content(Some(
        event.actor_name.as_deref().unwrap_or(&event.actor_subject),
    ));
    actor
        .set_attribute("title", &event.actor_subject)
        .map_err(|_| browser_error())?;

    let description = create_element(document, "td", None)?;
    let narrative = create_element(document, "span", Some("audit-narrative"))?;
    narrative.set_text_content(Some(&event.narrative));
    let detail = create_element(document, "span", Some("full-path"))?;
    detail.set_text_content(Some(&format!(
        "{} \u{00b7} {}",
        event.kind.as_str(),
        event.path.as_str()
    )));
    append(&description, &narrative)?;
    append(&description, &detail)?;

    let protocol = create_element(document, "td", Some("updated-time"))?;
    protocol.set_text_content(Some(&event.protocol_version));

    for cell in [&when, &actor, &description, &protocol] {
        append(&row, cell)?;
    }
    Ok(row)
}

#[cfg(test)]
mod tests {
    use sovereign_config_core::{AuditEventKind, AuditQuery, ConfigPath, Timestamp};

    use super::{
        AuditFeed, FeedState, FilterInput, KindGroup, PageOutcome, build_query,
        timestamp_from_millis,
    };

    fn query(text: &str) -> AuditQuery {
        AuditQuery {
            text_filter: Some(text.into()),
            ..AuditQuery::default()
        }
    }

    fn loaded(cursor: Option<&str>) -> PageOutcome {
        PageOutcome::Loaded {
            next_cursor: cursor.map(str::to_owned),
        }
    }

    fn defaults(element: bool) -> FilterInput {
        FilterInput {
            groups: KindGroup::ALL
                .into_iter()
                .filter(|group| group.shown_by_default(element))
                .collect(),
            ..FilterInput::default()
        }
    }

    #[test]
    fn pages_follow_the_cursor_one_at_a_time_and_stop_at_the_end() {
        let mut feed = AuditFeed::default();
        assert!(
            feed.advance().is_none(),
            "nothing to continue before a query"
        );

        let first = feed.restart(query("changed"));
        assert_eq!(first.query.cursor, None);
        assert!(first.is_first_page());
        assert!(
            feed.advance().is_none(),
            "a second intersection while the first page loads must not fetch"
        );

        assert!(feed.settle(first.generation, loaded(Some("page-2"))));
        let second = feed.advance().expect("a cursor means there is more");
        assert_eq!(second.query.cursor.as_deref(), Some("page-2"));
        assert_eq!(second.query.text_filter.as_deref(), Some("changed"));
        assert!(feed.advance().is_none(), "in flight again");

        assert!(feed.settle(second.generation, loaded(None)));
        assert_eq!(feed.state(), FeedState::Ended);
        assert!(feed.advance().is_none(), "no request after the end of data");
    }

    #[test]
    fn a_failed_page_waits_for_a_retry_from_the_same_cursor() {
        let mut feed = AuditFeed::default();
        let first = feed.restart(query("x"));
        assert!(feed.settle(first.generation, loaded(Some("page-2"))));
        let second = feed.advance().unwrap();
        assert!(feed.settle(second.generation, PageOutcome::Failed));

        assert_eq!(feed.state(), FeedState::Failed);
        assert!(
            feed.advance().is_none(),
            "scrolling does not retry on its own"
        );
        let retried = feed.retry().expect("a failed page can be retried");
        assert_eq!(retried.query.cursor.as_deref(), Some("page-2"));
        assert!(feed.retry().is_none(), "one retry in flight at a time");
        assert!(feed.settle(retried.generation, loaded(Some("page-3"))));
        assert_eq!(
            feed.advance().unwrap().query.cursor.as_deref(),
            Some("page-3")
        );
    }

    #[test]
    fn a_failed_first_page_retries_the_first_page() {
        let mut feed = AuditFeed::default();
        let first = feed.restart(query("x"));
        assert!(feed.settle(first.generation, PageOutcome::Failed));
        assert!(
            !feed.is_showing(&query("x")),
            "a failed list may be asked again"
        );
        assert_eq!(feed.retry().unwrap().query.cursor, None);
    }

    #[test]
    fn a_page_for_a_superseded_query_is_refused() {
        let mut feed = AuditFeed::default();
        let stale = feed.restart(query("old"));
        let current = feed.restart(query("new"));
        assert!(!feed.settle(stale.generation, loaded(Some("old-cursor"))));
        assert_eq!(
            feed.state(),
            FeedState::Loading,
            "still waiting for the new query"
        );
        assert!(feed.settle(current.generation, loaded(Some("new-cursor"))));
        assert_eq!(
            feed.advance().unwrap().query.cursor.as_deref(),
            Some("new-cursor")
        );
    }

    #[test]
    fn an_abandoned_list_refuses_its_page_and_fetches_nothing_more() {
        let mut feed = AuditFeed::default();
        let request = feed.restart(query("x"));
        feed.invalidate();
        assert!(!feed.settle(request.generation, loaded(Some("next"))));
        assert!(feed.advance().is_none());
        assert!(feed.retry().is_none());
        assert!(!feed.is_showing(&query("x")));
    }

    #[test]
    fn the_same_query_is_not_asked_twice() {
        let mut feed = AuditFeed::default();
        feed.restart(query("x"));
        assert!(feed.is_showing(&query("x")));
        assert!(!feed.is_showing(&query("y")));
    }

    #[test]
    fn every_kind_belongs_to_exactly_one_group() {
        for kind in AuditEventKind::ALL {
            let groups = KindGroup::ALL
                .iter()
                .filter(|group| group.kinds().contains(&kind))
                .count();
            assert_eq!(groups, 1, "{kind:?} is in {groups} groups");
        }
    }

    #[test]
    fn the_whole_trail_opens_without_reads_and_a_value_history_with_them() {
        let trail = build_query(&defaults(false), None).unwrap();
        assert!(!trail.kinds.is_empty());
        assert!(!trail.kinds.contains(&AuditEventKind::SubtreeRead));
        assert!(!trail.kinds.contains(&AuditEventKind::ValuesListed));
        assert!(trail.kinds.contains(&AuditEventKind::SecretRevealed));
        assert!(trail.kinds.contains(&AuditEventKind::ValueUpdated));

        let element = ConfigPath::parse_operation("/Apps/Key").unwrap();
        let history = build_query(&defaults(true), Some(&element)).unwrap();
        assert!(history.kinds.is_empty(), "every group is every kind");
        assert_eq!(history.element_path, Some(element));
        assert_eq!(history.path_filter, None);
    }

    #[test]
    fn a_value_history_ignores_a_leftover_path_fragment() {
        let element = ConfigPath::parse_operation("/Apps/Key").unwrap();
        let input = FilterInput {
            path: "apps".into(),
            ..defaults(true)
        };
        let history = build_query(&input, Some(&element)).unwrap();
        assert_eq!(
            history.path_filter, None,
            "the service refuses both at once"
        );
    }

    #[test]
    fn filled_filters_reach_the_query_trimmed() {
        let input = FilterInput {
            path: " apps/api ".into(),
            text: " revealed ".into(),
            from: Some(Timestamp {
                seconds: 10,
                nanos: 0,
            }),
            until: Some(Timestamp {
                seconds: 20,
                nanos: 0,
            }),
            protocol_version: "v3".into(),
            groups: vec![KindGroup::SecretReveals],
        };
        let query = build_query(&input, None).unwrap();
        assert_eq!(query.path_filter.as_deref(), Some("apps/api"));
        assert_eq!(query.text_filter.as_deref(), Some("revealed"));
        assert_eq!(query.from.map(|at| at.seconds), Some(10));
        assert_eq!(query.until.map(|at| at.seconds), Some(20));
        assert_eq!(query.protocol_version.as_deref(), Some("v3"));
        assert_eq!(query.kinds, [AuditEventKind::SecretRevealed]);
        assert_eq!(query.cursor, None);
    }

    #[test]
    fn filters_the_service_would_refuse_are_reported_by_field() {
        let input = FilterInput {
            path: "apps.api".into(),
            text: "x".repeat(257),
            from: Some(Timestamp {
                seconds: 20,
                nanos: 0,
            }),
            until: Some(Timestamp {
                seconds: 10,
                nanos: 0,
            }),
            protocol_version: "V4".into(),
            groups: Vec::new(),
        };
        let fields: Vec<_> = build_query(&input, None)
            .unwrap_err()
            .into_iter()
            .map(|error| error.field)
            .collect();
        assert_eq!(
            fields,
            [
                "audit-path-filter",
                "audit-text-filter",
                "audit-protocol",
                "audit-until",
                "audit-kinds"
            ]
        );
    }

    #[test]
    fn browser_instants_become_timestamps() {
        let at = timestamp_from_millis(1_700_000_000_250.0).unwrap();
        assert_eq!((at.seconds, at.nanos), (1_700_000_000, 250_000_000));
        let before_epoch = timestamp_from_millis(-1.0).unwrap();
        assert_eq!(
            (before_epoch.seconds, before_epoch.nanos),
            (-1, 999_000_000)
        );
        assert!(timestamp_from_millis(f64::NAN).is_none());
    }
}
