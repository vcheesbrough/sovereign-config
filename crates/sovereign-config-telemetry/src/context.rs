//! Trace context for the transport layer: adopting an inbound W3C
//! `traceparent`, and injecting the current one into an outbound request
//! (`observability` skill §5, `references/rust.md` *Propagation*). Both need
//! the span bridge's extension, which only this crate may name.
//!
//! Everything here works on the **current `tracing` span**, never on the
//! SDK's own current context, which is empty unless the span layer activated
//! it — an empty context injects nothing and reports no error.
//!
//! **Propagation runs whether or not anything exports.** With telemetry off
//! the span layer is still installed, over a no-op tracer that hands each span
//! its parent's context: an inbound `traceparent` reaches the outbound request
//! unchanged, as the specification asks of a disabled SDK, so a silent service
//! does not break the trace passing through it.

use http::HeaderMap;
use opentelemetry::{
    Context,
    propagation::TextMapPropagator,
    trace::{SpanContext, TraceContextExt},
};
use opentelemetry_http::{HeaderExtractor, HeaderInjector};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// Makes the W3C trace context in `headers`, if there is a valid one, the
/// parent of `span`. Call it before the span is first entered. Without one —
/// no header, or a malformed one — `span` starts a new trace.
///
/// **The caller's sampling decision is not adopted.** The header comes from
/// the public internet, before authentication, and a parent-based sampler
/// drops every span under a parent flagged "not sampled" — so honouring the
/// flag would let any caller keep its own requests, and the `user.*` they
/// carry, out of the trace store with one header. The trace id and parent
/// span id are kept, so the caller's trace still joins; whether this server
/// records is decided here and by the collector (skill §2), never by the
/// request.
pub fn adopt_parent(span: &Span, headers: &HeaderMap) {
    let extracted = TraceContextPropagator::new().extract(&HeaderExtractor(headers));
    let remote = extracted.span().span_context().clone();
    if !remote.is_valid() {
        return;
    }
    let sampled = SpanContext::new(
        remote.trace_id(),
        remote.span_id(),
        remote.trace_flags().with_sampled(true),
        true,
        remote.trace_state().clone(),
    );
    // Fails only when no span layer is installed or the span has already
    // started; either way there is nothing to adopt into.
    let _ = span.set_parent(Context::new().with_remote_span_context(sampled));
}

/// Writes the current span's W3C trace context into `headers`, replacing any
/// `traceparent` already there. Writes nothing when there is no valid context
/// — a request made outside any span, or one whose trace started nowhere.
pub fn inject_current(headers: &mut HeaderMap) {
    let context = Span::current().context();
    TraceContextPropagator::new().inject_context(&context, &mut HeaderInjector(headers));
}
