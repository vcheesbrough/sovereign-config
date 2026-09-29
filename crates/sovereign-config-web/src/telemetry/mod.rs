//! Client telemetry: the page's log records, over OTLP/JSON, to this
//! environment's authenticated ingest (README "Observability", *Client
//! telemetry*; `client-export.md`).
//!
//! - **Off unless the product says otherwise.** The endpoint comes from
//!   `/app-config.js`; without it nothing here is initialised, nothing is
//!   buffered and no request is ever made. There is no compiled-in endpoint.
//! - **The operator's access token, read per request, never refreshed here.**
//!   The page's own OIDC stack refreshes it; an export that finds no current
//!   token waits for the next one. A `401` marks the token stale so the
//!   page's next call refreshes it, and a second `401` stops export for the
//!   rest of the page's life.
//! - **Never on the UI's path, never seen by the user.** Records go into a
//!   bounded buffer and leave on a timer; failures are console lines on
//!   transitions only.
//! - **Records say what the build says** (`record.rs`): compiled-in text and
//!   numbers, never a token, a value or a path.
//! - **Every gRPC-Web call carries its action's `traceparent`**
//!   (`context.rs`), and so do that action's records.

mod buffer;
pub(crate) mod context;
mod policy;
pub(crate) mod record;

use std::{cell::RefCell, future::Future};

use js_sys::{Date, Math, Reflect};
use sovereign_config_core::{ClientError, Secret};
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, Request, RequestCache, RequestInit, Response, console, window};

use self::{
    buffer::Buffer,
    context::{InAction, TraceContext},
    policy::{Next, Outcome, Policy, Transition},
    record::{Record, Severity},
};
use crate::{
    browser::{TelemetryConfig, browser_error},
    session::TOKENS,
};

/// The most records the page keeps waiting, and their total size.
const MAX_BUFFERED_RECORDS: usize = 500;
const MAX_BUFFERED_BYTES: usize = 256 * 1024;
/// One request's worth. The page-hide batch is smaller: a `keepalive`
/// request's body is capped at 64 KiB by the browser.
const MAX_BATCH_RECORDS: usize = 100;
const MAX_BATCH_BYTES: usize = 128 * 1024;
const MAX_UNLOAD_BATCH_BYTES: usize = 48 * 1024;
/// How long records gather before a request, so one action is one request.
const FLUSH_DELAY_MS: u32 = 1_000;
/// How often an export waiting for a current token looks again.
const TOKEN_WAIT_MS: u32 = 5_000;
/// A token this close to expiry is left for the page to refresh first.
const TOKEN_MARGIN_MS: f64 = 10_000.0;

thread_local! {
    static EXPORTER: RefCell<Option<Exporter>> = const { RefCell::new(None) };
}

struct Exporter {
    logs_url: String,
    service_version: String,
    buffer: Buffer,
    /// A batch that has been tried and is waiting to be tried again.
    pending: Option<Vec<String>>,
    policy: Policy,
    /// A flush is scheduled or running; at most one of either exists.
    flushing: bool,
    dropped: u64,
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
        *slot = Some(Exporter {
            logs_url: format!("{}/v1/logs", config.endpoint.trim_end_matches('/')),
            service_version: config.service_version.clone(),
            buffer: Buffer::new(MAX_BUFFERED_RECORDS, MAX_BUFFERED_BYTES),
            pending: None,
            policy: Policy::default(),
            flushing: false,
            dropped: 0,
        });
    });
    install_page_hide_flush();
}

/// Runs `future` as part of the action that is current, or as a new action
/// when none is: an event handler starting work is a new action, and work
/// that action spawns belongs to it.
///
/// Every `spawn_local` in the app goes through here, which is what gives each
/// action one trace context without a view knowing about it.
pub(crate) fn spawn_local<F>(future: F)
where
    F: Future<Output = ()> + 'static,
{
    let context = context::current().unwrap_or_else(new_context);
    wasm_bindgen_futures::spawn_local(InAction::new(context, future));
}

/// The `traceparent` of the action this call is part of.
pub(crate) fn traceparent() -> Option<String> {
    context::current().map(|context| context.traceparent())
}

fn new_context() -> TraceContext {
    let mut bytes = [0_u8; 24];
    if let Some(crypto) = window().and_then(|window| window.crypto().ok()) {
        let _ = crypto.get_random_values_with_u8_array(&mut bytes);
    }
    TraceContext::from_random(bytes)
}

/// Records one gRPC-Web call's outcome, as part of the current action.
pub(crate) fn record_rpc(route: &'static str, started_ms: f64, error: Option<&ClientError>) {
    if !enabled() {
        return;
    }
    let now = Date::now();
    emit(&Record::rpc(
        now,
        route,
        now - started_ms,
        error.map(|error| error.kind),
        context::current(),
    ));
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
    let encoded = record.to_otlp().to_string();
    let start = EXPORTER.with_borrow_mut(|exporter| {
        let Some(exporter) = exporter.as_mut() else {
            return false;
        };
        exporter.buffer.push(encoded);
        !std::mem::replace(&mut exporter.flushing, true)
    });
    if start {
        schedule_flush(FLUSH_DELAY_MS);
    }
}

/// Discards everything waiting to be sent. Called when the session ends, so
/// one operator's records are never sent under the next one's token.
pub(crate) fn discard() {
    EXPORTER.with_borrow_mut(|exporter| {
        if let Some(exporter) = exporter.as_mut() {
            exporter.buffer.clear();
            exporter.pending = None;
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
        EXPORTER.with_borrow_mut(|exporter| {
            if let Some(exporter) = exporter.as_mut() {
                exporter.flushing = false;
            }
        });
    }
}

/// Sends batches until the buffer is empty, a batch has to wait, or export
/// has stopped. Runs outside every action: it is not a user's doing, and its
/// requests carry no `traceparent`.
async fn flush() {
    loop {
        let Some((batch, url, version)) = EXPORTER.with_borrow_mut(|slot| {
            let exporter = slot.as_mut()?;
            if exporter.policy.stopped() {
                exporter.buffer.clear();
                exporter.pending = None;
                exporter.flushing = false;
                return None;
            }
            let batch = exporter.pending.take().unwrap_or_else(|| {
                exporter
                    .buffer
                    .take_batch(MAX_BATCH_RECORDS, MAX_BATCH_BYTES)
            });
            if batch.is_empty() {
                exporter.flushing = false;
                return None;
            }
            Some((
                batch,
                exporter.logs_url.clone(),
                exporter.service_version.clone(),
            ))
        }) else {
            return;
        };
        let Some((token, expires_at_ms)) = current_token() else {
            // No usable token yet: logged out (the batch goes), or waiting for
            // the page to refresh one (the batch waits).
            if crate::session::logged_in() {
                park(batch, TOKEN_WAIT_MS);
            } else {
                discard();
                stop_flushing();
            }
            return;
        };
        let body = record::logs_request(&version, &batch);
        let outcome = send(&url, &body, &token, false).await;
        let count = batch.len();
        let (next, transition) = EXPORTER.with_borrow_mut(|slot| {
            slot.as_mut().map_or((Next::Stop, None), |exporter| {
                exporter.policy.decide(outcome, Math::random())
            })
        });
        if let Some(transition) = transition {
            report(transition, &url);
        }
        match next {
            Next::Done => {}
            Next::Drop => note_dropped(count),
            Next::RetryAfter(delay) => {
                park(batch, delay);
                return;
            }
            Next::RefreshThenRetry => {
                mark_token_stale(expires_at_ms);
                park(batch, TOKEN_WAIT_MS);
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

fn park(batch: Vec<String>, delay_ms: u32) {
    EXPORTER.with_borrow_mut(|exporter| {
        if let Some(exporter) = exporter.as_mut() {
            exporter.pending = Some(batch);
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
            format!("client telemetry to {url}: the ingest rejected {count} records")
        }
        Transition::GaveUp(outcome) => format!(
            "client telemetry to {url} is off for this page ({}); {dropped} records dropped",
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

async fn send(url: &str, body: &str, token: &Secret, keepalive: bool) -> Outcome {
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
            rejected: rejected_records(&response).await,
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
async fn rejected_records(response: &Response) -> u64 {
    let Ok(promise) = response.json() else {
        return 0;
    };
    let Ok(json) = JsFuture::from(promise).await else {
        return 0;
    };
    Reflect::get(&json, &JsValue::from_str("partialSuccess"))
        .and_then(|partial| Reflect::get(&partial, &JsValue::from_str("rejectedLogRecords")))
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
    let Some((batch, url, version)) = EXPORTER.with_borrow_mut(|slot| {
        let exporter = slot.as_mut()?;
        if exporter.policy.stopped() {
            return None;
        }
        // A retried batch goes first if it fits a `keepalive` body; one that
        // does not is left where it is rather than sent to certain failure.
        let pending_fits = exporter.pending.as_ref().is_some_and(|pending| {
            pending.iter().map(String::len).sum::<usize>() <= MAX_UNLOAD_BATCH_BYTES
        });
        let mut batch = if pending_fits {
            exporter.pending.take().unwrap_or_default()
        } else {
            Vec::new()
        };
        let size: usize = batch.iter().map(String::len).sum();
        if size < MAX_UNLOAD_BATCH_BYTES && batch.len() < MAX_BATCH_RECORDS {
            batch.extend(exporter.buffer.take_batch(
                MAX_BATCH_RECORDS - batch.len(),
                MAX_UNLOAD_BATCH_BYTES - size,
            ));
        }
        (!batch.is_empty()).then(|| {
            (
                batch,
                exporter.logs_url.clone(),
                exporter.service_version.clone(),
            )
        })
    }) else {
        return;
    };
    let body = record::logs_request(&version, &batch);
    wasm_bindgen_futures::spawn_local(async move {
        let _ = send(&url, &body, &token, true).await;
    });
}

#[cfg(test)]
mod tests {
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
