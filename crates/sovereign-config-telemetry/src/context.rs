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
use opentelemetry::{propagation::TextMapPropagator, trace::TraceContextExt};
use opentelemetry_http::{HeaderExtractor, HeaderInjector};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// Makes the W3C trace context in `headers`, if there is a valid one, the
/// parent of `span`. Call it before the span is first entered. Without one —
/// no header, or a malformed one — `span` starts a new trace.
pub fn adopt_parent(span: &Span, headers: &HeaderMap) {
    let parent = TraceContextPropagator::new().extract(&HeaderExtractor(headers));
    if parent.span().span_context().is_valid() {
        // Fails only when no span layer is installed or the span has already
        // started; either way there is nothing to adopt into.
        let _ = span.set_parent(parent);
    }
}

/// Writes the current span's W3C trace context into `headers`, replacing any
/// `traceparent` already there. Writes nothing when there is no valid context
/// — a request made outside any span, or one whose trace started nowhere.
pub fn inject_current(headers: &mut HeaderMap) {
    let context = Span::current().context();
    TraceContextPropagator::new().inject_context(&context, &mut HeaderInjector(headers));
}
