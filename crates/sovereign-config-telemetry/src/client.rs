//! The client span and context injection for an HTTP call that leaves the
//! process (`observability` skill §1.3), shared by every crate that makes
//! one: the server's JWKS fetch and the identity provider's administration
//! calls open the same span, with the same keys, wherever they live.

use http::Method;
use tracing::{Span, field::Empty};
use url::Url;

use crate::context;

/// `http.request.method` for a method outside the standard set, as the
/// semantic conventions spell "something else".
pub const OTHER: &str = "_OTHER";

/// The span name and `http.request.method` for `method`: the method itself
/// when it is a standard one, else `HTTP` and `_OTHER`, so a caller cannot
/// mint span names.
#[must_use]
pub fn http_method(method: &Method) -> (&'static str, &'static str) {
    let standard = match method.as_str() {
        "GET" => "GET",
        "HEAD" => "HEAD",
        "POST" => "POST",
        "PUT" => "PUT",
        "DELETE" => "DELETE",
        "CONNECT" => "CONNECT",
        "OPTIONS" => "OPTIONS",
        "TRACE" => "TRACE",
        "PATCH" => "PATCH",
        _ => return ("HTTP", OTHER),
    };
    (standard, standard)
}

/// A client span for one outbound HTTP call. `template` is the route with its
/// identifiers left as placeholders (`/api/v3/core/users/{id}/`) — never the
/// URL actually called, which would put a provider's primary key in a span
/// name. `None` when the route is configuration rather than code (an
/// issuer's JWKS), which leaves the span named by its method.
/// Records the host only: no scheme, port, path, query or credential.
#[must_use]
pub fn client_span(method: &Method, template: Option<&'static str>, origin: &Url) -> Span {
    let (method_name, recorded) = http_method(method);
    let name = template.map_or_else(
        || method_name.to_owned(),
        |template| format!("{method_name} {template}"),
    );
    tracing::info_span!(
        "http.client",
        otel.name = name.as_str(),
        otel.kind = "client",
        otel.status_code = Empty,
        http.request.method = recorded,
        server.address = origin.host_str(),
        url.template = template,
        http.response.status_code = Empty,
        error.type = Empty,
    )
}

/// Sends `request` through `client` with the current span's trace context
/// injected, and records the response status on the current span. Call it
/// inside a [`client_span`].
///
/// # Errors
///
/// The request could not be built or sent.
pub async fn send(
    client: &reqwest::Client,
    request: reqwest::RequestBuilder,
) -> Result<reqwest::Response, reqwest::Error> {
    let mut request = request.build()?;
    context::inject_current(request.headers_mut());
    let response = client.execute(request).await?;
    Span::current().record("http.response.status_code", response.status().as_u16());
    Ok(response)
}

/// Marks the current span failed, with a bounded classification as its
/// `error.type`.
pub fn record_error(classification: &'static str) {
    let span = Span::current();
    span.record("otel.status_code", "error");
    span.record("error.type", classification);
}
