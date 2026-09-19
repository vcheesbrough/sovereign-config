//! Per-request protocol-version attribution.
//!
//! Each protocol version is its own protobuf package, so the version a request
//! speaks *is* its gRPC route prefix: `/sovereign.config.v3.System/GetVersion`
//! is a v3 request. This layer reads that prefix, attaches it to the request as
//! a [`NegotiatedProtocolVersion`] extension (as the authentication layer
//! attaches its principal), and counts it.
//!
//! Counting here rather than at `GetVersion` is what makes the count usable for
//! retirement: negotiation happens once at connect, so a long-lived provider
//! would otherwise register one connect and then go quiet while its traffic
//! continued.
//!
//! This layer records the `attempted` series only, because it runs before
//! authentication and cannot know the outcome — the authentication layer's
//! refusal carries its `grpc-status` in trailers, which cannot be read without
//! consuming the body. The `authenticated` series is recorded by the
//! authentication layer instead, which reads the extension this layer attached.
//! See [`ProtocolMetrics`] for why the gate needs both, and
//! `## Protocol versioning` in `README.md`.

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use http::{Request, Response};
use tonic::body::BoxBody;
use tower::{Layer, Service};

use crate::metrics::ProtocolMetrics;

/// The protocol version a request arrived on, taken from its route prefix.
///
/// Present on every request whose route names a `sovereign.config` package,
/// carrying `None` when that package is a protocol version this build does not
/// serve. Routes outside `/sovereign.config.` — health probes, gRPC reflection,
/// web assets — carry no extension at all, so absence means "not protocol
/// traffic" and `Some`/`None` distinguishes served from unserved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NegotiatedProtocolVersion(pub(crate) Option<&'static str>);

/// The version label a `/sovereign.config.<version>.<Service>/<Method>` path
/// names, or `None` for any other route.
///
/// The whole shape is required, not just the prefix: a bare
/// `/sovereign.config.v3`, or one with no method, is not a request any client
/// of that version would send, and counting it against the version would let
/// junk traffic hold the retirement gate above zero. Such a path falls through
/// to the unrecognised bucket instead.
///
/// Returns one of `recognised`'s own `'static` strings rather than a slice of
/// the path, so nothing derived from the request can reach a metric label.
fn route_version(path: &str, recognised: &[&'static str]) -> Option<&'static str> {
    let rest = path.strip_prefix("/sovereign.config.")?;
    let (qualified_service, method) = rest.split_once('/')?;
    let (version, service) = qualified_service.split_once('.')?;
    if service.is_empty() || method.is_empty() || method.contains('/') {
        return None;
    }
    recognised
        .iter()
        .copied()
        .find(|candidate| *candidate == version)
}

#[derive(Clone)]
pub(crate) struct ProtocolVersionLayer {
    metrics: Arc<ProtocolMetrics>,
    recognised: &'static [&'static str],
}

impl ProtocolVersionLayer {
    pub(crate) const fn new(
        metrics: Arc<ProtocolMetrics>,
        recognised: &'static [&'static str],
    ) -> Self {
        Self {
            metrics,
            recognised,
        }
    }
}

impl<S> Layer<S> for ProtocolVersionLayer {
    type Service = ProtocolVersionService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ProtocolVersionService {
            inner,
            metrics: Arc::clone(&self.metrics),
            recognised: self.recognised,
        }
    }
}

#[derive(Clone)]
pub(crate) struct ProtocolVersionService<S> {
    inner: S,
    metrics: Arc<ProtocolMetrics>,
    recognised: &'static [&'static str],
}

impl<S, B> Service<Request<B>> for ProtocolVersionService<S>
where
    S: Service<Request<B>, Response = Response<BoxBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    B: Send + 'static,
{
    type Response = Response<BoxBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        let replacement = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, replacement);

        let version = route_version(request.uri().path(), self.recognised);
        // A non-gRPC route — a web asset, a health probe — is not protocol
        // traffic and must not inflate the unrecognised bucket, which exists to
        // surface a *versioned* route this build does not know.
        if let Some(version) = version {
            self.metrics.record_attempted(version);
            request
                .extensions_mut()
                .insert(NegotiatedProtocolVersion(Some(version)));
        } else if request.uri().path().starts_with("/sovereign.config.") {
            self.metrics
                .record_attempted(crate::metrics::UNRECOGNISED_PROTOCOL_LABEL);
            request
                .extensions_mut()
                .insert(NegotiatedProtocolVersion(None));
        }

        Box::pin(async move { inner.call(request).await })
    }
}

#[cfg(test)]
mod serving_tests;

#[cfg(test)]
mod tests {
    use super::route_version;
    use crate::metrics::ProtocolMetrics;

    const RECOGNISED: [&str; 2] = ["v3", "vtest"];

    #[test]
    fn route_version_reads_the_package_version_from_the_path() {
        assert_eq!(
            route_version("/sovereign.config.v3.System/GetVersion", &RECOGNISED),
            Some("v3")
        );
        assert_eq!(
            route_version("/sovereign.config.v3.Configuration/GetSubTree", &RECOGNISED),
            Some("v3")
        );
        assert_eq!(
            route_version("/sovereign.config.vtest.System/GetVersion", &RECOGNISED),
            Some("vtest")
        );
    }

    #[test]
    fn route_version_ignores_routes_that_are_not_versioned_packages() {
        for path in [
            "/grpc.health.v1.Health/Check",
            "/assets/index.js",
            "/",
            "/sovereign.config",
            "/sovereign.config.",
        ] {
            assert_eq!(route_version(path, &RECOGNISED), None, "{path}");
        }
    }

    /// A recognised version is only credited with a request shaped like one its
    /// clients would send. Anything looser lets junk — a scanner probing
    /// `/sovereign.config.v3` — land in the real bucket and hold the retirement
    /// gate above zero.
    #[test]
    fn route_version_requires_the_whole_service_and_method_shape() {
        for path in [
            "/sovereign.config.v3",
            "/sovereign.config.v3.",
            "/sovereign.config.v3.System",
            "/sovereign.config.v3.System/",
            "/sovereign.config.v3./GetVersion",
            "/sovereign.config.v3/GetVersion",
            "/sovereign.config.v3.System/GetVersion/extra",
        ] {
            assert_eq!(route_version(path, &RECOGNISED), None, "{path}");
        }
    }

    #[test]
    fn route_version_never_returns_a_version_it_was_not_given() {
        // The label-injection guard: an arbitrary package segment must not
        // become a metric label.
        assert_eq!(
            route_version("/sovereign.config.v99.System/GetVersion", &RECOGNISED),
            None
        );
        assert_eq!(
            route_version(
                "/sovereign.config.v3\" injected=\".System/GetVersion",
                &RECOGNISED
            ),
            None
        );
    }

    #[test]
    fn metrics_render_every_recognised_version_and_the_unrecognised_bucket() {
        let metrics = ProtocolMetrics::new(&["v3"]);
        metrics.record_attempted("v3");
        metrics.record_attempted("v3");
        metrics.record_authenticated("v3");
        metrics.record_attempted("v99");
        // An unrecognised version has no authenticated series to land in.
        metrics.record_authenticated("v99");

        let rendered = metrics.render();

        assert!(rendered.contains(
            "sovereign_config_protocol_requests_total{version=\"v3\",outcome=\"attempted\"} 2"
        ));
        assert!(rendered.contains(
            "sovereign_config_protocol_requests_total{version=\"v3\",outcome=\"authenticated\"} 1"
        ));
        assert!(rendered.contains(
            "sovereign_config_protocol_requests_total{version=\"unrecognised\",outcome=\"attempted\"} 1"
        ));
        assert_eq!(
            rendered
                .matches("sovereign_config_protocol_requests_total{")
                .count(),
            3,
            "two series per compiled-in label plus the unrecognised bucket, and nothing else"
        );
    }
}
