//! Client telemetry: the page's spans and log records, over OTLP/JSON, to
//! this environment's authenticated ingest (README "Observability", *Client
//! telemetry*; `client-export.md`).
//!
//! - **Off unless the product says otherwise.** The endpoint comes from
//!   `/app-config.js`; without it nothing here is initialised, nothing is
//!   buffered and no request is ever made. There is no compiled-in endpoint.
//! - **The operator's access token, read per request, never refreshed here.**
//!   The page's own OIDC stack refreshes it; an export that finds no current
//!   token waits for the next one. A `401` marks the token stale so the
//!   page's next call refreshes it, and a second `401` stops export — of
//!   both signals, which share one policy — for the rest of the page's life.
//! - **Never on the UI's path, never seen by the user.** Spans and records go
//!   into bounded buffers and leave on a timer; failures are console lines on
//!   transitions only.
//! - **Spans and records say what the build says** (`span.rs`, `record.rs`):
//!   compiled-in text and numbers, never a token, a value or a path.
//! - **Every user action is a trace that starts here** (`context.rs`): its
//!   root span, one client span per gRPC-Web call, and each call's
//!   `traceparent` names that call's span, so the server's spans hang
//!   beneath it. A call's log record carries the same span.

mod buffer;
pub(crate) mod context;
mod policy;
pub(crate) mod record;
pub(crate) mod span;

use std::{cell::RefCell, future::Future, rc::Rc};

use js_sys::{Date, Math, Reflect};
use sovereign_config_core::{ClientError, Secret};
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, Request, RequestCache, RequestInit, Response, console, window};

pub(crate) use self::span::ActionKind;
use self::{
    buffer::Buffer,
    context::{Action, InAction, TraceContext},
    policy::{Next, Outcome, Policy, Transition},
    record::{Record, Severity},
    span::Span,
};
use crate::{
    browser::{TelemetryConfig, browser_error},
    session::TOKENS,
};

/// The most items (records or spans) the page keeps waiting per signal, and
/// their total size.
const MAX_BUFFERED_ITEMS: usize = 500;
const MAX_BUFFERED_BYTES: usize = 256 * 1024;
/// One request's worth. The page-hide batches are smaller: the browser caps
/// the bodies of all `keepalive` requests in flight at 64 KiB together.
const MAX_BATCH_ITEMS: usize = 100;
const MAX_BATCH_BYTES: usize = 128 * 1024;
const MAX_UNLOAD_BATCH_BYTES: usize = 48 * 1024;
/// Items gather until the page has been quiet this long, so one action —
/// however many calls it makes, however slowly — is one request per signal.
const FLUSH_DELAY_MS: u32 = 1_000;
/// ...but never longer than this, so a busy page still sends.
const MAX_GATHER_MS: u32 = 5_000;
/// How often an export waiting for a current token looks again.
const TOKEN_WAIT_MS: u32 = 5_000;
/// A token this close to expiry is left for the page to refresh first.
const TOKEN_MARGIN_MS: f64 = 10_000.0;

thread_local! {
    static EXPORTER: RefCell<Option<Exporter>> = const { RefCell::new(None) };
}

/// The two signals the page sends; metrics are refused from clients by
/// design (`client-ingest.md`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Signal {
    Logs,
    Traces,
}

impl Signal {
    /// The order a flush drains them in.
    const ALL: [Self; 2] = [Self::Logs, Self::Traces];

    const fn path(self) -> &'static str {
        match self {
            Self::Logs => "/v1/logs",
            Self::Traces => "/v1/traces",
        }
    }

    /// The partial-success field that counts this signal's rejected items.
    const fn rejected_field(self) -> &'static str {
        match self {
            Self::Logs => "rejectedLogRecords",
            Self::Traces => "rejectedSpans",
        }
    }

    fn request(self, service_version: &str, batch: &[String]) -> String {
        match self {
            Self::Logs => record::logs_request(service_version, batch),
            Self::Traces => span::traces_request(service_version, batch),
        }
    }
}

struct Exporter {
    endpoint: String,
    service_version: String,
    logs: Buffer,
    traces: Buffer,
    /// A batch that has been tried and is waiting to be tried again.
    pending: Option<(Signal, Vec<String>)>,
    policy: Policy,
    /// A flush is scheduled or running; at most one of either exists.
    flushing: bool,
    /// When items began gathering for the next request, and when the latest
    /// arrived.
    gathering_since_ms: f64,
    last_item_ms: f64,
    dropped: u64,
}

impl Exporter {
    fn new(endpoint: &str, service_version: &str) -> Self {
        Self {
            endpoint: endpoint.trim_end_matches('/').to_owned(),
            service_version: service_version.to_owned(),
            logs: Buffer::new(MAX_BUFFERED_ITEMS, MAX_BUFFERED_BYTES),
            traces: Buffer::new(MAX_BUFFERED_ITEMS, MAX_BUFFERED_BYTES),
            pending: None,
            policy: Policy::default(),
            flushing: false,
            gathering_since_ms: 0.0,
            last_item_ms: 0.0,
            dropped: 0,
        }
    }

    const fn buffer(&mut self, signal: Signal) -> &mut Buffer {
        match signal {
            Signal::Logs => &mut self.logs,
            Signal::Traces => &mut self.traces,
        }
    }

    fn url(&self, signal: Signal) -> String {
        format!("{}{}", self.endpoint, signal.path())
    }

    fn clear(&mut self) {
        self.logs.clear();
        self.traces.clear();
        self.pending = None;
    }
}

/// Starts telemetry for this page, or says once that there is none.
pub(crate) fn init(config: Option<&TelemetryConfig>) {
    let Some(config) = config else {
        console::info_1(&JsValue::from_str(
            "sovereign-config: client telemetry is off (this deployment configures no ingest)",
        ));
        return;
    };
    EXPORTER.with_borrow_mut(|slot| {
        *slot = Some(Exporter::new(&config.endpoint, &config.service_version));
    });
    install_page_hide_flush();
}

/// Runs `future` as part of the action that is current, or as a new action
/// of `kind` when none is: an event handler starting work is a new action,
/// and work that action spawns belongs to it (and `kind` is then unused).
///
/// Every `spawn_local` in the app goes through here, which is what gives each
/// action one trace without a view knowing about it.
pub(crate) fn spawn_local<F>(kind: ActionKind, future: F)
where
    F: Future<Output = ()> + 'static,
{
    let action =
        context::current().unwrap_or_else(|| Action::new(new_context(), kind, Date::now()));
    wasm_bindgen_futures::spawn_local(InAction::new(action, future));
}

/// One gRPC-Web call in flight: its own span in its action's trace.
pub(crate) struct Call {
    route: &'static str,
    started_ms: f64,
    action: Option<Rc<Action>>,
    context: Option<TraceContext>,
    /// Whether `context` is a span of this call's own, or — past an
    /// action's bound on call spans — the action's root.
    own_span: bool,
}

impl Call {
    /// The `traceparent` the call carries: its action's trace, and **this
    /// call's** span as the parent, so the server's span is its child.
    pub(crate) fn traceparent(&self) -> Option<String> {
        self.context.map(|context| context.traceparent())
    }
}

/// Starts a call as part of the current action. Outside any action there is
/// no trace to join, and the call carries no `traceparent`.
pub(crate) fn begin_call(route: &'static str) -> Call {
    let action = context::current();
    let (context, own_span) = match &action {
        Some(action) if action.reserve_span() => (Some(action.context.child(random_bytes())), true),
        Some(action) => (Some(action.context), false),
        None => (None, false),
    };
    Call {
        route,
        started_ms: Date::now(),
        action,
        context,
        own_span,
    }
}

/// Ends a call: its log record (by route and error kind; never its content)
/// and its span, which leaves with its action's root when the action ends.
/// `status` is the gRPC status the server answered with, if one came back.
pub(crate) fn end_call(call: Call, status: Option<u16>, error: Option<&ClientError>) {
    if !enabled() {
        return;
    }
    let now = Date::now();
    let kind = error.map(|error| error.kind);
    emit(&Record::rpc(
        now,
        call.route,
        now - call.started_ms,
        kind,
        call.context,
    ));
    if let (Some(action), Some(context)) = (call.action, call.context) {
        action.add_call(
            Span::rpc(
                call.route,
                context,
                action.context,
                call.started_ms,
                now,
                status,
                kind,
            ),
            call.own_span,
        );
    }
}

/// An action has ended — the last future it spawned has finished — so its
/// spans leave together.
fn end_action(action: &Action) {
    if !enabled() {
        return;
    }
    let spans = action.finish(Date::now());
    if spans.is_empty() || !crate::session::logged_in() {
        return;
    }
    let encoded = spans
        .iter()
        .map(|span| span.to_otlp().to_string())
        .collect();
    enqueue(Signal::Traces, encoded);
}

fn new_context() -> TraceContext {
    let mut trace = [0_u8; 16];
    fill_random(&mut trace);
    let mut bytes = [0_u8; 24];
    bytes[..16].copy_from_slice(&trace);
    bytes[16..].copy_from_slice(&random_bytes());
    TraceContext::from_random(bytes)
}

fn random_bytes() -> [u8; 8] {
    let mut bytes = [0_u8; 8];
    fill_random(&mut bytes);
    bytes
}

fn fill_random(bytes: &mut [u8]) {
    if let Some(crypto) = window().and_then(|window| window.crypto().ok()) {
        let _ = crypto.get_random_values_with_u8_array(bytes);
    }
}

fn enabled() -> bool {
    EXPORTER.with_borrow(|exporter| {
        exporter
            .as_ref()
            .is_some_and(|exporter| !exporter.policy.stopped())
    })
}

fn emit(record: &Record) {
    // Before a login there is no identity to send under, so nothing is sent:
    // what is worth seeing goes to the console instead, and the rest nowhere.
    if !crate::session::logged_in() {
        if record.severity >= Severity::Warn {
            console::warn_1(&JsValue::from_str(&format!(
                "sovereign-config: {} (not sent: no session)",
                record.body
            )));
        }
        return;
    }
    enqueue(Signal::Logs, vec![record.to_otlp().to_string()]);
}

fn enqueue(signal: Signal, encoded: Vec<String>) {
    let start = EXPORTER.with_borrow_mut(|exporter| {
        let Some(exporter) = exporter.as_mut() else {
            return false;
        };
        for item in encoded {
            exporter.buffer(signal).push(item);
        }
        let now = Date::now();
        exporter.last_item_ms = now;
        let start = !std::mem::replace(&mut exporter.flushing, true);
        if start {
            exporter.gathering_since_ms = now;
        }
        start
    });
    if start {
        schedule_flush(FLUSH_DELAY_MS);
    }
}

/// Discards everything waiting to be sent. Called when the session ends, so
/// one operator's telemetry is never sent under the next one's token.
///
/// A batch already in flight when the session ends is not recalled: it left
/// with its own operator's token, which is the one it belongs under. A flush
/// that finds no session afterwards discards rather than waits, and an
/// action that ends after it sends nothing.
pub(crate) fn discard() {
    EXPORTER.with_borrow_mut(|exporter| {
        if let Some(exporter) = exporter.as_mut() {
            exporter.clear();
        }
    });
}

fn schedule_flush(delay_ms: u32) {
    let Some(window) = window() else {
        return;
    };
    let callback = Closure::once_into_js(|| wasm_bindgen_futures::spawn_local(flush()));
    let delay = i32::try_from(delay_ms).unwrap_or(i32::MAX);
    if window
        .set_timeout_with_callback_and_timeout_and_arguments_0(callback.unchecked_ref(), delay)
        .is_err()
    {
        stop_flushing();
    }
}

/// Sends batches until both buffers are empty, a batch has to wait, or
/// export has stopped. Runs outside every action: it is not a user's doing,
/// and its requests carry no `traceparent`.
async fn flush() {
    // Still gathering: items are arriving, and the cap is not reached. A
    // batch waiting to be retried is not gathering and goes as scheduled.
    let gathering = EXPORTER.with_borrow(|slot| {
        slot.as_ref()
            .filter(|exporter| exporter.pending.is_none())
            .and_then(|exporter| {
                gather_wait_ms(
                    Date::now(),
                    exporter.gathering_since_ms,
                    exporter.last_item_ms,
                )
            })
    });
    if let Some(wait) = gathering {
        schedule_flush(wait);
        return;
    }
    loop {
        let Some((signal, batch, url, endpoint, version)) = EXPORTER.with_borrow_mut(|slot| {
            let exporter = slot.as_mut()?;
            if exporter.policy.stopped() {
                exporter.clear();
                exporter.flushing = false;
                return None;
            }
            let next = exporter.pending.take().or_else(|| {
                Signal::ALL.into_iter().find_map(|signal| {
                    let batch = exporter
                        .buffer(signal)
                        .take_batch(MAX_BATCH_ITEMS, MAX_BATCH_BYTES);
                    (!batch.is_empty()).then_some((signal, batch))
                })
            });
            let Some((signal, batch)) = next else {
                exporter.flushing = false;
                return None;
            };
            Some((
                signal,
                batch,
                exporter.url(signal),
                exporter.endpoint.clone(),
                exporter.service_version.clone(),
            ))
        }) else {
            return;
        };
        let Some((token, expires_at_ms)) = current_token() else {
            // No usable token yet: logged out (the batch goes), or waiting for
            // the page to refresh one (the batch waits).
            if crate::session::logged_in() {
                park(signal, batch, TOKEN_WAIT_MS);
            } else {
                discard();
                stop_flushing();
            }
            return;
        };
        let body = signal.request(&version, &batch);
        let outcome = send(signal, &url, &body, &token, false).await;
        let count = batch.len();
        let (next, transition) = EXPORTER.with_borrow_mut(|slot| {
            slot.as_mut().map_or((Next::Stop, None), |exporter| {
                exporter.policy.decide(outcome, Math::random())
            })
        });
        if let Some(transition) = transition {
            report(transition, &endpoint);
        }
        match next {
            Next::Done => {}
            Next::Drop => note_dropped(count),
            Next::RetryAfter(delay) => {
                park(signal, batch, delay);
                return;
            }
            Next::RefreshThenRetry => {
                mark_token_stale(expires_at_ms);
                park(signal, batch, TOKEN_WAIT_MS);
                return;
            }
            Next::Stop => {
                note_dropped(count);
                discard();
                stop_flushing();
                return;
            }
        }
    }
}

/// How much longer to wait before sending what has gathered, or `None` to
/// send now: until the page has been quiet for [`FLUSH_DELAY_MS`], and never
/// past [`MAX_GATHER_MS`] from the first item.
fn gather_wait_ms(now_ms: f64, gathering_since_ms: f64, last_item_ms: f64) -> Option<u32> {
    let quiet_at = last_item_ms + f64::from(FLUSH_DELAY_MS);
    let deadline = gathering_since_ms + f64::from(MAX_GATHER_MS);
    let wait = quiet_at.min(deadline) - now_ms;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let wait = (wait >= 1.0).then(|| wait.ceil() as u32);
    wait
}

fn park(signal: Signal, batch: Vec<String>, delay_ms: u32) {
    EXPORTER.with_borrow_mut(|exporter| {
        if let Some(exporter) = exporter.as_mut() {
            exporter.pending = Some((signal, batch));
        }
    });
    schedule_flush(delay_ms);
}

fn stop_flushing() {
    EXPORTER.with_borrow_mut(|exporter| {
        if let Some(exporter) = exporter.as_mut() {
            exporter.flushing = false;
        }
    });
}

fn note_dropped(count: usize) {
    EXPORTER.with_borrow_mut(|exporter| {
        if let Some(exporter) = exporter.as_mut() {
            exporter.dropped += count as u64;
        }
    });
}

/// The page's access token if it is current, without refreshing it: the
/// page's own calls refresh, and a second refresher here would race them for
/// the one refresh token.
fn current_token() -> Option<(Secret, f64)> {
    let now = Date::now();
    TOKENS.with_borrow(|tokens| {
        tokens
            .as_ref()
            .filter(|tokens| now + TOKEN_MARGIN_MS < tokens.access_expires_at_ms)
            .map(|tokens| (tokens.access_token.clone(), tokens.access_expires_at_ms))
    })
}

/// After a `401`: treat the refused token as expired, so the page's next call
/// refreshes it and the next export uses the new one. Only if it is still the
/// token that was refused — the page may have refreshed in between.
fn mark_token_stale(refused_expiry_ms: f64) {
    TOKENS.with_borrow_mut(|tokens| {
        if let Some(tokens) = tokens.as_mut()
            && (tokens.access_expires_at_ms - refused_expiry_ms).abs() < f64::EPSILON
        {
            tokens.access_expires_at_ms = 0.0;
        }
    });
}

fn report(transition: Transition, url: &str) {
    let dropped =
        EXPORTER.with_borrow(|exporter| exporter.as_ref().map_or(0, |exporter| exporter.dropped));
    let line = match transition {
        // An expired token is routine; the refusal worth a line is the one
        // that survives a refresh, reported below as giving up.
        Transition::FirstFailure(Outcome::Status { status: 401, .. }) => return,
        Transition::FirstFailure(outcome) => {
            format!(
                "client telemetry to {url} is failing ({})",
                describe(outcome)
            )
        }
        Transition::Recovered => format!("client telemetry to {url} has recovered"),
        Transition::PartiallyRejected(count) => {
            format!("client telemetry to {url}: the ingest rejected {count} items")
        }
        Transition::GaveUp(outcome) => format!(
            "client telemetry to {url} is off for this page ({}); {dropped} items dropped",
            describe(outcome)
        ),
    };
    console::warn_1(&JsValue::from_str(&format!("sovereign-config: {line}")));
}

fn describe(outcome: Outcome) -> String {
    match outcome {
        Outcome::Accepted { .. } => "accepted".to_owned(),
        Outcome::Status { status, .. } => format!("HTTP {status}"),
        Outcome::Unreachable => "unreachable".to_owned(),
    }
}

async fn send(signal: Signal, url: &str, body: &str, token: &Secret, keepalive: bool) -> Outcome {
    let Ok(request) = request(url, body, token, keepalive) else {
        return Outcome::Unreachable;
    };
    let Some(window) = window() else {
        return Outcome::Unreachable;
    };
    let Ok(response) = JsFuture::from(window.fetch_with_request(&request)).await else {
        return Outcome::Unreachable;
    };
    let Ok(response) = response.dyn_into::<Response>() else {
        return Outcome::Unreachable;
    };
    let status = response.status();
    if (200..300).contains(&status) {
        return Outcome::Accepted {
            rejected: rejected_items(&response, signal).await,
        };
    }
    Outcome::Status {
        status,
        retry_after_seconds: response
            .headers()
            .get("retry-after")
            .ok()
            .flatten()
            .and_then(|value| value.trim().parse().ok()),
    }
}

fn request(url: &str, body: &str, token: &Secret, keepalive: bool) -> Result<Request, ClientError> {
    let headers = Headers::new().map_err(|_| browser_error())?;
    headers
        .append("content-type", "application/json")
        .map_err(|_| browser_error())?;
    headers
        .append("authorization", &format!("Bearer {}", token.expose()))
        .map_err(|_| browser_error())?;
    let options = RequestInit::new();
    options.set_method("POST");
    options.set_cache(RequestCache::NoStore);
    options.set_headers(&headers);
    options.set_body(&JsValue::from_str(body));
    // `keepalive` lets the request outlive the page; web-sys has no setter
    // for it, but `RequestInit` is a plain dictionary.
    if keepalive {
        Reflect::set(&options, &JsValue::from_str("keepalive"), &JsValue::TRUE)
            .map_err(|_| browser_error())?;
    }
    Request::new_with_str_and_init(url, &options).map_err(|_| browser_error())
}

/// The partial-success count in an accepted response, or zero.
async fn rejected_items(response: &Response, signal: Signal) -> u64 {
    let Ok(promise) = response.json() else {
        return 0;
    };
    let Ok(json) = JsFuture::from(promise).await else {
        return 0;
    };
    Reflect::get(&json, &JsValue::from_str("partialSuccess"))
        .and_then(|partial| Reflect::get(&partial, &JsValue::from_str(signal.rejected_field())))
        .ok()
        .and_then(|count| {
            count
                .as_f64()
                .or_else(|| count.as_string().and_then(|text| text.parse().ok()))
        })
        .filter(|count| count.is_finite() && *count > 0.0)
        .map_or(0, |count| {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let count = count as u64;
            count
        })
}

/// On the way out, one best-effort `keepalive` request with what is waiting,
/// never awaited and never retried: the page's exit is not delayed for it.
fn install_page_hide_flush() {
    let Some(page) = window() else {
        return;
    };
    let on_page_hide = Closure::<dyn FnMut()>::new(flush_on_exit);
    let _ =
        page.add_event_listener_with_callback("pagehide", on_page_hide.as_ref().unchecked_ref());
    on_page_hide.forget();
    // A tab sent to the background may never come back: mobile browsers
    // discard hidden pages without a `pagehide`.
    if let Some(document) = page.document() {
        let on_hidden = Closure::<dyn FnMut()>::new(|| {
            if window()
                .and_then(|window| window.document())
                .is_some_and(|document| document.hidden())
            {
                flush_on_exit();
            }
        });
        let _ = document.add_event_listener_with_callback(
            "visibilitychange",
            on_hidden.as_ref().unchecked_ref(),
        );
        on_hidden.forget();
    }
}

fn flush_on_exit() {
    let Some((token, _)) = current_token() else {
        return;
    };
    let Some((batches, endpoint, version)) = EXPORTER.with_borrow_mut(|slot| {
        let exporter = slot.as_mut()?;
        if exporter.policy.stopped() {
            return None;
        }
        let batches = unload_batches(exporter);
        (!batches.is_empty()).then(|| {
            (
                batches,
                exporter.endpoint.clone(),
                exporter.service_version.clone(),
            )
        })
    }) else {
        return;
    };
    for (signal, batch) in batches {
        let url = format!("{endpoint}{}", signal.path());
        let body = signal.request(&version, &batch);
        let token = token.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let _ = send(signal, &url, &body, &token, true).await;
        });
    }
}

/// What the page-hide flush sends: one budget of [`MAX_UNLOAD_BATCH_BYTES`]
/// for every `keepalive` body together, at most [`MAX_BATCH_ITEMS`] per
/// signal. A retried batch goes first if it fits; one that does not is left
/// where it is rather than sent to certain failure. Then logs, then traces,
/// each only as far as the budget reaches — never an item that would
/// overrun it.
fn unload_batches(exporter: &mut Exporter) -> Vec<(Signal, Vec<String>)> {
    let mut budget = MAX_UNLOAD_BATCH_BYTES;
    let mut batches: Vec<(Signal, Vec<String>)> = Vec::new();
    let pending_fits = exporter
        .pending
        .as_ref()
        .is_some_and(|(_, pending)| pending.iter().map(String::len).sum::<usize>() <= budget);
    if pending_fits && let Some((signal, pending)) = exporter.pending.take() {
        budget -= pending.iter().map(String::len).sum::<usize>();
        batches.push((signal, pending));
    }
    for signal in Signal::ALL {
        let already = batches
            .iter()
            .filter(|(queued, _)| *queued == signal)
            .map(|(_, batch)| batch.len())
            .sum::<usize>();
        if budget == 0 || already >= MAX_BATCH_ITEMS {
            continue;
        }
        // `take_batch` always moves one item; only take when it fits.
        let fits = exporter
            .buffer(signal)
            .front_len()
            .is_some_and(|len| len <= budget);
        if !fits {
            continue;
        }
        let batch = exporter
            .buffer(signal)
            .take_batch(MAX_BATCH_ITEMS - already, budget);
        budget -= batch.iter().map(String::len).sum::<usize>();
        if let Some((_, queued)) = batches.iter_mut().find(|(queued, _)| *queued == signal) {
            queued.extend(batch);
        } else {
            batches.push((signal, batch));
        }
    }
    batches
}

#[cfg(test)]
mod tests {
    use super::{
        Exporter, MAX_BATCH_ITEMS, MAX_UNLOAD_BATCH_BYTES, Signal, gather_wait_ms, unload_batches,
    };

    /// An action whose calls straggle is still one request: the flush waits
    /// for a quiet second, but no more than five from the first record.
    #[test]
    fn records_gather_until_quiet_or_the_cap() {
        // First record at 0, latest at 900: quiet at 1 900.
        assert_eq!(gather_wait_ms(1_000.0, 0.0, 900.0), Some(900));
        // Quiet for a second: send.
        assert_eq!(gather_wait_ms(2_000.0, 0.0, 900.0), None);
        // Records still arriving at 4 800: the 5 000 cap wins.
        assert_eq!(gather_wait_ms(4_800.0, 0.0, 4_700.0), Some(200));
        assert_eq!(gather_wait_ms(5_000.0, 0.0, 4_900.0), None);
    }
    fn item(label: char, size: usize) -> String {
        label.to_string().repeat(size)
    }

    fn sizes(batches: &[(Signal, Vec<String>)]) -> Vec<(Signal, usize, usize)> {
        batches
            .iter()
            .map(|(signal, batch)| (*signal, batch.len(), batch.iter().map(String::len).sum()))
            .collect()
    }

    /// Page hide: logs then traces, all within one keepalive budget.
    #[test]
    fn page_hide_sends_both_signals_within_one_budget() {
        let mut exporter = Exporter::new("https://ingest.example.test/", "2.39.0");
        assert_eq!(
            exporter.url(Signal::Traces),
            "https://ingest.example.test/v1/traces"
        );
        for _ in 0..3 {
            exporter.logs.push(item('l', 10 * 1024));
            exporter.traces.push(item('t', 10 * 1024));
        }
        let batches = unload_batches(&mut exporter);
        // 48 KiB: three 10 KiB log records, then one 10 KiB span; the next
        // span would overrun the budget and waits.
        assert_eq!(
            sizes(&batches),
            [(Signal::Logs, 3, 30 * 1024), (Signal::Traces, 1, 10 * 1024)]
        );
        let total: usize = batches
            .iter()
            .flat_map(|(_, batch)| batch)
            .map(String::len)
            .sum();
        assert!(total <= MAX_UNLOAD_BATCH_BYTES);
        assert_eq!(exporter.traces.len(), 2, "what did not fit stays buffered");
    }

    /// A retried batch goes first when it fits, and joins its signal's
    /// batch; one that does not fit is left pending, and the buffers still go.
    #[test]
    fn page_hide_sends_a_fitting_retry_first_and_leaves_one_that_does_not() {
        let mut exporter = Exporter::new("https://ingest.example.test", "2.39.0");
        exporter.pending = Some((Signal::Traces, vec![item('p', 1024)]));
        exporter.traces.push(item('t', 1024));
        exporter.logs.push(item('l', 1024));
        let batches = unload_batches(&mut exporter);
        assert_eq!(
            sizes(&batches),
            [(Signal::Traces, 2, 2 * 1024), (Signal::Logs, 1, 1024)]
        );
        assert!(exporter.pending.is_none());

        let mut exporter = Exporter::new("https://ingest.example.test", "2.39.0");
        exporter.pending = Some((Signal::Logs, vec![item('p', MAX_UNLOAD_BATCH_BYTES + 1)]));
        exporter.traces.push(item('t', 1024));
        let batches = unload_batches(&mut exporter);
        assert_eq!(sizes(&batches), [(Signal::Traces, 1, 1024)]);
        assert!(exporter.pending.is_some(), "too big for a keepalive body");
    }

    /// No more than one batch's worth of items per signal.
    #[test]
    fn page_hide_sends_at_most_one_batch_of_items_per_signal() {
        let mut exporter = Exporter::new("https://ingest.example.test", "2.39.0");
        for _ in 0..MAX_BATCH_ITEMS + 5 {
            exporter.logs.push(item('l', 10));
        }
        let batches = unload_batches(&mut exporter);
        assert_eq!(
            sizes(&batches),
            [(Signal::Logs, MAX_BATCH_ITEMS, MAX_BATCH_ITEMS * 10)]
        );
    }

    /// Every action gets its trace context from `telemetry::spawn_local`, so
    /// a view that spawned work any other way would send requests with no
    /// `traceparent` and records with no trace. Only this module, whose own
    /// exports belong to no action, may use the executor directly.
    #[test]
    fn only_telemetry_spawns_outside_an_action() {
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut pending = vec![source.clone()];
        let mut checked = 0;
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(&directory).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if path != source.join("telemetry") {
                        pending.push(path);
                    }
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap();
                let imports_executor = text.contains("wasm_bindgen_futures::spawn_local")
                    || text.contains("wasm_bindgen_futures::{JsFuture, spawn_local}");
                assert!(
                    !imports_executor,
                    "{} spawns outside telemetry::spawn_local",
                    path.display()
                );
                checked += 1;
            }
        }
        assert!(checked > 10, "the walk found the crate's sources");
    }
}
