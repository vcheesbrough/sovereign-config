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

use std::{
    cell::Cell,
    fmt::Write as _,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

thread_local! {
    static CURRENT: Cell<Option<TraceContext>> = const { Cell::new(None) };
}

/// One action's trace: the id the server's spans join, and the id of the
/// action itself, which is the parent the server's request span names.
///
/// The client exports no spans, so that parent is never stored; it is still
/// what ties a client record (which carries it as `span_id`) to the server
/// span beneath it.
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
        if span_id == [0; 8] {
            span_id[7] = 1;
        }
        Self { trace_id, span_id }
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

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        })
}

/// The action being polled right now, if any.
pub(crate) fn current() -> Option<TraceContext> {
    CURRENT.get()
}

/// A future that runs as one action: its context is current while, and only
/// while, it is being polled.
pub(crate) struct InAction {
    context: TraceContext,
    inner: Pin<Box<dyn Future<Output = ()>>>,
}

impl InAction {
    pub(crate) fn new(context: TraceContext, inner: impl Future<Output = ()> + 'static) -> Self {
        Self {
            context,
            inner: Box::pin(inner),
        }
    }
}

impl Future for InAction {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        let action = self.context;
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

    use super::{InAction, TraceContext, current};

    fn context(seed: u8) -> TraceContext {
        TraceContext::from_random([seed; 24])
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
    }

    /// The context is the action's while it is polled, and nobody's between
    /// polls — which is when a second action's event handler would run.
    #[test]
    fn an_action_is_current_only_while_it_is_polled() {
        let seen = std::rc::Rc::new(std::cell::Cell::new(None));
        let observed = seen.clone();
        let mut action = pin!(InAction::new(context(7), async move {
            observed.set(current());
        }));
        assert_eq!(current(), None);
        let mut task = Context::from_waker(Waker::noop());
        assert_eq!(action.as_mut().poll(&mut task), Poll::Ready(()));
        assert_eq!(seen.get(), Some(context(7)));
        assert_eq!(current(), None, "restored once the poll returns");
    }

    /// Two actions whose awaits interleave each keep their own context.
    #[test]
    fn interleaved_actions_keep_their_own_contexts() {
        let (first_seen, second_seen) = (
            std::rc::Rc::new(std::cell::RefCell::new(Vec::new())),
            std::rc::Rc::new(std::cell::RefCell::new(Vec::new())),
        );
        let (first_log, second_log) = (first_seen.clone(), second_seen.clone());
        let mut first = pin!(InAction::new(context(1), async move {
            first_log.borrow_mut().push(current());
            yield_once().await;
            first_log.borrow_mut().push(current());
        }));
        let mut second = pin!(InAction::new(context(2), async move {
            second_log.borrow_mut().push(current());
            yield_once().await;
            second_log.borrow_mut().push(current());
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
