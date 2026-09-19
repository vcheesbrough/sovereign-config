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

use http::{Method, Request, Response};
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

/// How a request relates to the per-version metric.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Attribution {
    /// A well-formed call on a protocol version this build serves.
    Served(&'static str),
    /// A call addressed to `sovereign.config` that names no served version, or
    /// is not shaped like a call at all.
    Unrecognised,
    /// Not protocol traffic: counted nowhere and given no extension.
    NotProtocolTraffic,
}

/// Classifies a request for the per-version metric.
///
/// Only `POST` is protocol traffic. gRPC and gRPC-Web never use another method,
/// while this port also serves web assets — so a crawler or probe issuing a
/// plain `GET` against a versioned path is not a client of that version, and
/// counting it would raise a standing false alarm in the `attempted` series
/// that operators are told to investigate.
fn attribute(method: &Method, path: &str, recognised: &[&'static str]) -> Attribution {
    if *method != Method::POST || !path.starts_with("/sovereign.config.") {
        return Attribution::NotProtocolTraffic;
    }
    route_version(path, recognised).map_or(Attribution::Unrecognised, Attribution::Served)
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

        match attribute(request.method(), request.uri().path(), self.recognised) {
            Attribution::Served(version) => {
                self.metrics.record_attempted(version);
                request
                    .extensions_mut()
                    .insert(NegotiatedProtocolVersion(Some(version)));
            }
            Attribution::Unrecognised => {
                self.metrics
                    .record_attempted(crate::metrics::UNRECOGNISED_PROTOCOL_LABEL);
                request
                    .extensions_mut()
                    .insert(NegotiatedProtocolVersion(None));
            }
            // A web asset, a health probe, a crawler's GET: not protocol traffic,
            // so it must not inflate any bucket — least of all the unrecognised
            // one, which exists to surface a *versioned* call this build does
            // not know.
            Attribution::NotProtocolTraffic => {}
        }

        Box::pin(async move { inner.call(request).await })
    }
}

#[cfg(test)]
mod serving_tests;

#[cfg(test)]
mod tests {
    use http::Method;

    use super::{Attribution, attribute, route_version};
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
    fn only_post_is_attributed_to_a_protocol_version() {
        let path = "/sovereign.config.v3.System/GetVersion";

        assert_eq!(
            attribute(&Method::POST, path, &RECOGNISED),
            Attribution::Served("v3")
        );
        // gRPC and gRPC-Web are POST-only, and this port also serves web assets,
        // so any other method on a versioned path is a crawler or a probe rather
        // than a client of that version.
        for method in [
            Method::GET,
            Method::HEAD,
            Method::OPTIONS,
            Method::PUT,
            Method::DELETE,
        ] {
            assert_eq!(
                attribute(&method, path, &RECOGNISED),
                Attribution::NotProtocolTraffic,
                "{method}"
            );
        }
    }

    #[test]
    fn a_post_to_an_unserved_or_malformed_versioned_path_is_unrecognised() {
        for path in [
            "/sovereign.config.v99.System/GetVersion",
            "/sovereign.config.v3",
            "/sovereign.config.v3.System",
        ] {
            assert_eq!(
                attribute(&Method::POST, path, &RECOGNISED),
                Attribution::Unrecognised,
                "{path}"
            );
        }
    }

    #[test]
    fn routes_outside_the_package_namespace_are_not_protocol_traffic() {
        for path in ["/grpc.health.v1.Health/Check", "/assets/index.js", "/"] {
            assert_eq!(
                attribute(&Method::POST, path, &RECOGNISED),
                Attribution::NotProtocolTraffic,
                "{path}"
            );
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
