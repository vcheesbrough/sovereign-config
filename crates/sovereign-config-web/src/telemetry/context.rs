//! The W3C trace context of a user action, and which action is running.
//!
//! Every unit of asynchronous work in this app is started by
//! [`super::spawn_local`], and every one is either a user action — a click, a
//! submit, a keystroke, a history pop, the page load — or work that action
//! spawned. So an action is "one `spawn_local` from outside any action", and
//! the context it gets is carried by the future itself: [`InAction`] makes it
//! current for exactly the duration of each poll. Two actions whose requests
//! interleave therefore never see each other's context, and nothing in the
//! views passes a trace id around.
//!
//! The action is shared by every future it spawned, and it **ends when the
//! last of them does**: dropping the last [`InAction`] drops the [`Action`],
//! and that is when its root span is exported (`super::end_action`).

use std::{
    cell::{Cell, RefCell},
    fmt::Write as _,
    future::Future,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};

use super::span::{ActionKind, Span};

thread_local! {
    static CURRENT: RefCell<Option<Rc<Action>>> = const { RefCell::new(None) };
}

/// The most call spans one action exports. An action that makes more still
/// counts them on its root span, and those further calls name the root as
/// their `traceparent`'s parent, so their server spans hang under it rather
/// than under a span that is never sent; one runaway action cannot grow the
/// page's memory.
pub(crate) const MAX_CALLS_PER_ACTION: usize = 64;

/// A span's place in a trace: the trace id every span of an action shares,
/// and this span's own id — the action's root span, or one of its calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TraceContext {
    trace_id: [u8; 16],
    span_id: [u8; 8],
}

impl TraceContext {
    /// A context from 24 random bytes: the first 16 are the trace id, the
    /// rest the span id. W3C forbids an all-zero id in either place, so one
    /// that came out all zero (a 2^-64 event, or a broken random source) gets
    /// its last bit set rather than being sent and discarded by the server.
    pub(crate) fn from_random(bytes: [u8; 24]) -> Self {
        let mut trace_id = [0; 16];
        let mut span_id = [0; 8];
        trace_id.copy_from_slice(&bytes[..16]);
        span_id.copy_from_slice(&bytes[16..]);
        if trace_id == [0; 16] {
            trace_id[15] = 1;
        }
        Self {
            trace_id,
            span_id: nonzero(span_id),
        }
    }

    /// A new span in this trace, from 8 random bytes.
    pub(crate) const fn child(&self, span_id: [u8; 8]) -> Self {
        Self {
            trace_id: self.trace_id,
            span_id: nonzero(span_id),
        }
    }

    pub(crate) fn trace_id_hex(&self) -> String {
        hex(&self.trace_id)
    }

    pub(crate) fn span_id_hex(&self) -> String {
        hex(&self.span_id)
    }

    /// The `traceparent` header value, version `00`, always **sampled**.
    ///
    /// Sampled on purpose: the server's sampler is parent-based, so an
    /// unsampled parent would switch off the server's trace for every request
    /// this page makes — and that trace is the half of the join a client
    /// record exists to find.
    pub(crate) fn traceparent(&self) -> String {
        format!("00-{}-{}-01", self.trace_id_hex(), self.span_id_hex())
    }
}

const fn nonzero(mut span_id: [u8; 8]) -> [u8; 8] {
    if u64::from_ne_bytes(span_id) == 0 {
        span_id[7] = 1;
    }
    span_id
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        })
}

/// One user action: its root span's context, what it is, when it began,
/// and the calls it has made so far.
pub(crate) struct Action {
    pub(crate) context: TraceContext,
    pub(crate) kind: ActionKind,
    pub(crate) started_unix_ms: f64,
    calls: Cell<u32>,
    failed_calls: Cell<u32>,
    /// Calls begun with a span of their own, at most [`MAX_CALLS_PER_ACTION`].
    reserved: Cell<usize>,
    spans: RefCell<Vec<Span>>,
}

impl Action {
    pub(crate) fn new(context: TraceContext, kind: ActionKind, started_unix_ms: f64) -> Rc<Self> {
        Rc::new(Self {
            context,
            kind,
            started_unix_ms,
            calls: Cell::new(0),
            failed_calls: Cell::new(0),
            reserved: Cell::new(0),
            spans: RefCell::new(Vec::new()),
        })
    }

    /// Whether a call beginning now gets a span of its own: the first
    /// [`MAX_CALLS_PER_ACTION`] do, and every later one is parented on the
    /// root instead.
    pub(crate) fn reserve_span(&self) -> bool {
        let reserved = self.reserved.get();
        let granted = reserved < MAX_CALLS_PER_ACTION;
        if granted {
            self.reserved.set(reserved + 1);
        }
        granted
    }

    /// Adds one finished call to the action. Every call is counted; its span
    /// is kept only when the call was granted one ([`Self::reserve_span`]).
    pub(crate) fn add_call(&self, span: Span, own_span: bool) {
        self.calls.set(self.calls.get().saturating_add(1));
        if span.failed {
            self.failed_calls
                .set(self.failed_calls.get().saturating_add(1));
        }
        if own_span {
            self.spans.borrow_mut().push(span);
        }
    }

    /// The action's spans once it has ended at `end_unix_ms`: its root, then
    /// its calls. Nothing at all for an action that made no call — a copy to
    /// the clipboard or a local toggle has no server work to hang under it,
    /// and a trace of one span says nothing a log line could not.
    pub(crate) fn finish(&self, end_unix_ms: f64) -> Vec<Span> {
        let calls = self.calls.get();
        if calls == 0 {
            return Vec::new();
        }
        let mut spans = vec![Span::action(
            self.kind,
            self.context,
            self.started_unix_ms,
            end_unix_ms,
            calls,
            self.failed_calls.get(),
        )];
        spans.append(&mut self.spans.borrow_mut());
        spans
    }
}

impl Drop for Action {
    fn drop(&mut self) {
        super::end_action(self);
    }
}

/// The action being polled right now, if any.
pub(crate) fn current() -> Option<Rc<Action>> {
    CURRENT.with_borrow(Clone::clone)
}

/// A future that runs as part of one action: the action is current while,
/// and only while, it is being polled.
pub(crate) struct InAction {
    action: Rc<Action>,
    inner: Pin<Box<dyn Future<Output = ()>>>,
}

impl InAction {
    pub(crate) fn new(action: Rc<Action>, inner: impl Future<Output = ()> + 'static) -> Self {
        Self {
            action,
            inner: Box::pin(inner),
        }
    }
}

impl Future for InAction {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        let action = self.action.clone();
        let previous = CURRENT.replace(Some(action));
        let outcome = self.inner.as_mut().poll(context);
        CURRENT.set(previous);
        outcome
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };

    use super::{Action, InAction, MAX_CALLS_PER_ACTION, TraceContext, current};
    use crate::telemetry::span::{ActionKind, Span};

    fn context(seed: u8) -> TraceContext {
        TraceContext::from_random([seed; 24])
    }

    fn action(seed: u8) -> std::rc::Rc<Action> {
        Action::new(context(seed), ActionKind::Navigate, 0.0)
    }

    fn seen() -> Option<TraceContext> {
        current().map(|action| action.context)
    }

    fn call(action: &Action, seed: u8, failed: bool) -> Span {
        Span::rpc(
            "/sovereign.config.v4.Configuration/ListValues",
            action.context.child([seed; 8]),
            action.context,
            1.0,
            2.0,
            Some(if failed { 14 } else { 0 }),
            None,
        )
    }

    #[test]
    fn traceparent_is_w3c_version_00_and_sampled() {
        let mut bytes = [0_u8; 24];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::try_from(index).unwrap();
        }
        let context = TraceContext::from_random(bytes);
        assert_eq!(
            context.traceparent(),
            "00-000102030405060708090a0b0c0d0e0f-1011121314151617-01"
        );
        assert_eq!(context.trace_id_hex(), "000102030405060708090a0b0c0d0e0f");
        assert_eq!(context.span_id_hex(), "1011121314151617");
    }

    #[test]
    fn an_all_zero_id_is_never_produced() {
        let context = TraceContext::from_random([0; 24]);
        assert_ne!(context.trace_id_hex(), "0".repeat(32));
        assert_ne!(context.span_id_hex(), "0".repeat(16));
        assert_ne!(context.child([0; 8]).span_id_hex(), "0".repeat(16));
    }

    /// A call's context is a new span in its action's trace.
    #[test]
    fn a_child_shares_the_trace_and_has_its_own_span() {
        let parent = context(1);
        let child = parent.child([9; 8]);
        assert_eq!(child.trace_id_hex(), parent.trace_id_hex());
        assert_eq!(child.span_id_hex(), "09".repeat(8));
        assert_ne!(child.span_id_hex(), parent.span_id_hex());
    }

    /// The span tree an action exports: its root first, then every call
    /// under it; counts on the root; and nothing for an action with no call.
    #[test]
    fn an_action_exports_its_root_and_its_calls() {
        let quiet = action(1);
        assert!(quiet.finish(5.0).is_empty(), "no call, no trace");

        let busy = action(2);
        busy.add_call(call(&busy, 3, false), busy.reserve_span());
        busy.add_call(call(&busy, 4, true), busy.reserve_span());
        let spans = busy.finish(5.0);
        assert_eq!(spans.len(), 3);
        let root = spans[0].to_otlp();
        assert_eq!(root["name"], "navigate");
        assert_eq!(root["spanId"], context(2).span_id_hex());
        assert_eq!(root["status"]["code"], 2, "one call failed");
        for child in &spans[1..] {
            let child = child.to_otlp();
            assert_eq!(child["traceId"], root["traceId"]);
            assert_eq!(child["parentSpanId"], root["spanId"]);
        }
    }

    /// A runaway action is counted in full but keeps a bounded set of spans.
    #[test]
    fn an_actions_call_spans_are_bounded() {
        let busy = action(5);
        let extra = 10;
        let granted: Vec<bool> = (0..MAX_CALLS_PER_ACTION + extra)
            .map(|_| busy.reserve_span())
            .collect();
        assert!(granted[..MAX_CALLS_PER_ACTION].iter().all(|own| *own));
        assert!(
            granted[MAX_CALLS_PER_ACTION..].iter().all(|own| !*own),
            "calls past the bound are parented on the root"
        );
        for (seed, own) in granted.into_iter().enumerate() {
            busy.add_call(call(&busy, u8::try_from(seed % 250).unwrap(), false), own);
        }
        let spans = busy.finish(5.0);
        assert_eq!(spans.len(), MAX_CALLS_PER_ACTION + 1);
        let root = spans[0].to_otlp();
        let count = root["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|attribute| attribute["key"] == "sovereign_config.client.rpc_count")
            .unwrap()["value"]["intValue"]
            .clone();
        assert_eq!(count, (MAX_CALLS_PER_ACTION + extra).to_string());
    }

    /// The context is the action's while it is polled, and nobody's between
    /// polls — which is when a second action's event handler would run.
    #[test]
    fn an_action_is_current_only_while_it_is_polled() {
        let seen = std::rc::Rc::new(std::cell::Cell::new(None));
        let observed = seen.clone();
        let mut running = pin!(InAction::new(action(7), async move {
            observed.set(super::current().map(|action| action.context));
        }));
        assert_eq!(super::current().map(|action| action.context), None);
        let mut task = Context::from_waker(Waker::noop());
        assert_eq!(running.as_mut().poll(&mut task), Poll::Ready(()));
        assert_eq!(seen.get(), Some(context(7)));
        assert!(super::current().is_none(), "restored once the poll returns");
    }

    /// Two actions whose awaits interleave each keep their own context.
    #[test]
    fn interleaved_actions_keep_their_own_contexts() {
        let (first_seen, second_seen) = (
            std::rc::Rc::new(std::cell::RefCell::new(Vec::new())),
            std::rc::Rc::new(std::cell::RefCell::new(Vec::new())),
        );
        let (first_log, second_log) = (first_seen.clone(), second_seen.clone());
        let mut first = pin!(InAction::new(action(1), async move {
            first_log.borrow_mut().push(seen());
            yield_once().await;
            first_log.borrow_mut().push(seen());
        }));
        let mut second = pin!(InAction::new(action(2), async move {
            second_log.borrow_mut().push(seen());
            yield_once().await;
            second_log.borrow_mut().push(seen());
        }));
        let mut task = Context::from_waker(Waker::noop());
        assert!(first.as_mut().poll(&mut task).is_pending());
        assert!(second.as_mut().poll(&mut task).is_pending());
        assert!(first.as_mut().poll(&mut task).is_ready());
        assert!(second.as_mut().poll(&mut task).is_ready());
        assert_eq!(*first_seen.borrow(), [Some(context(1)); 2]);
        assert_eq!(*second_seen.borrow(), [Some(context(2)); 2]);
    }

    async fn yield_once() {
        let mut yielded = false;
        std::future::poll_fn(move |_| {
            if yielded {
                Poll::Ready(())
            } else {
                yielded = true;
                Poll::Pending
            }
        })
        .await;
    }
}
