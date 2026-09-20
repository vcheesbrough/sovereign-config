//! Per-request protocol-version attribution, and the version-not-served answer.
//!
//! Each protocol version is its own protobuf package, so the version a request
//! speaks *is* its gRPC route prefix: `/sovereign.config.v3.System/GetVersion`
//! is a v3 request. [`ProtocolVersionLayer`] reads that prefix, attaches it to
//! the request as a [`NegotiatedProtocolVersion`] extension (as the
//! authentication layer attaches its principal), and counts it.
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
//!
//! [`UnservedVersionLayer`] is the other half: a route shaped like a call on a
//! protocol version, naming one this build does not serve, gets a **distinct**
//! version-not-served error rather than the transport's generic
//! `UNIMPLEMENTED`. Retiring a version then means deleting its routes and
//! nothing else — they fall to this. Both layers classify a path with the same
//! [`classify`], so the catch-all and the metric can never disagree about what
//! is version-shaped.

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use http::{Method, Request, Response};
use sovereign_config_core::{
    ERROR_KIND_METADATA, REQUESTED_VERSION_METADATA, VERSION_NOT_SERVED_KIND,
};
use tonic::{Status, body::BoxBody};
use tower::{Layer, Service};

use crate::metrics::ProtocolMetrics;

/// How much of a request-derived version identifier is echoed back.
const ECHOED_VERSION_LENGTH: usize = 16;

/// The protocol version a request arrived on, taken from its route prefix.
///
/// Present on every request whose route names a `sovereign.config` package,
/// carrying `None` when that package is a protocol version this build does not
/// serve. Routes outside `/sovereign.config.` — health probes, gRPC reflection,
/// web assets — carry no extension at all, so absence means "not protocol
/// traffic" and `Some`/`None` distinguishes served from unserved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NegotiatedProtocolVersion(pub(crate) Option<&'static str>);

/// What a path inside the `sovereign.config` namespace names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Route<'path> {
    /// `/sovereign.config.<Service>/<Method>` — the **unversioned** package.
    ///
    /// One dotted segment fewer than a versioned route, which is the whole
    /// reason the handshake can live outside every version. Nothing else is
    /// served here, and by construction nothing else ever will be.
    Unversioned,
    /// `/sovereign.config.<version>.<Service>/<Method>` — a call on `version`,
    /// exactly as the request spelled it.
    Versioned(&'path str),
    /// Addressed to the namespace, but not shaped like a call on it.
    Malformed,
}

/// What `path` names, or `None` when it is outside the namespace entirely.
///
/// The whole shape is required, not just the prefix: a bare
/// `/sovereign.config.v3`, or one with no method, is not a request any client
/// of that version would send. Counting it against the version would let junk
/// traffic hold the retirement gate above zero, and answering it
/// version-not-served would dress a malformed path up as a retirement.
fn classify(path: &str) -> Option<Route<'_>> {
    let rest = path.strip_prefix("/sovereign.config.")?;
    let Some((qualified_service, method)) = rest.split_once('/') else {
        return Some(Route::Malformed);
    };
    if qualified_service.is_empty() || method.is_empty() || method.contains('/') {
        return Some(Route::Malformed);
    }
    match qualified_service.split_once('.') {
        None => Some(Route::Unversioned),
        Some((version, service)) if !version.is_empty() && !service.is_empty() => {
            Some(Route::Versioned(version))
        }
        Some(_) => Some(Route::Malformed),
    }
}

/// How a request relates to the per-version metric.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Attribution {
    /// A well-formed call on a protocol version this build serves.
    Served(&'static str),
    /// A well-formed call naming a protocol version this build does **not**
    /// serve: retired, or never existed.
    UnservedVersion,
    /// A call on the unversioned package — the handshake.
    ///
    /// Protocol traffic, but not *a version's* traffic. It must reach neither
    /// the per-version series nor the unrecognised bucket: a client calls it
    /// before it knows any version, so counting it as an unrecognised version
    /// would make every well-behaved connect look like junk.
    Unversioned,
    /// Addressed to `sovereign.config` but not shaped like a call at all.
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
    if *method != Method::POST {
        return Attribution::NotProtocolTraffic;
    }
    match classify(path) {
        None => Attribution::NotProtocolTraffic,
        Some(Route::Unversioned) => Attribution::Unversioned,
        Some(Route::Malformed) => Attribution::Unrecognised,
        Some(Route::Versioned(version)) => recognised
            .iter()
            .copied()
            .find(|candidate| *candidate == version)
            .map_or(Attribution::UnservedVersion, Attribution::Served),
    }
}

/// `version` reduced to something safe to echo in response metadata.
///
/// Request-derived, so it is truncated and stripped to the character set a
/// version identifier may use. gRPC metadata values are ASCII, and a newline or
/// a quote reaching a header — or an operator's log — is how a bounded echo
/// becomes an injection.
fn echoed_version(version: &str) -> String {
    version
        .chars()
        .take(ECHOED_VERSION_LENGTH)
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                character
            } else {
                '?'
            }
        })
        .collect()
}

/// The version-not-served answer for a route naming `version`.
///
/// `FAILED_PRECONDITION`, not `UNIMPLEMENTED`: a retired version is a statement
/// about *this server's* state, not about whether the route exists, and keeping
/// the two apart is what lets a client tell "your version is gone, re-negotiate"
/// from "you called a method that does not exist". A client identifies it by
/// [`ERROR_KIND_METADATA`], never by the code alone.
///
/// The code was chosen so that **already-deployed clients still behave**:
/// `map_rpc_status` in every client from 2.25 on sends `FailedPrecondition` and
/// `Unimplemented` to the same `IncompatibleProtocol`, so a client that predates
/// this fails exactly as it does today. That claim is pinned by
/// `a_client_that_predates_the_catch_all_still_reports_incompatible_protocol`.
fn version_not_served(version: &str, served: &[&'static str]) -> Status {
    let echoed = echoed_version(version);
    let mut status = Status::failed_precondition(format!(
        "protocol version \"{echoed}\" is not served; this server serves: {}",
        served.join(", "),
    ));
    let metadata = status.metadata_mut();
    if let Ok(value) = VERSION_NOT_SERVED_KIND.parse() {
        metadata.insert(ERROR_KIND_METADATA, value);
    }
    if let Ok(value) = echoed.parse() {
        metadata.insert(REQUESTED_VERSION_METADATA, value);
    }
    status
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
            Attribution::UnservedVersion | Attribution::Unrecognised => {
                self.metrics
                    .record_attempted(crate::metrics::UNRECOGNISED_PROTOCOL_LABEL);
                request
                    .extensions_mut()
                    .insert(NegotiatedProtocolVersion(None));
            }
            // Counted nowhere, for two different reasons. The handshake is how
            // a client finds out which versions exist, so it belongs to none —
            // and it must not inflate the unrecognised bucket, which exists to
            // surface a *versioned* call this build does not know; what clients
            // said they speak is recorded by the handshake service itself,
            // under compiled-in labels. A web asset, a health probe or a
            // crawler's GET is not protocol traffic at all.
            Attribution::Unversioned | Attribution::NotProtocolTraffic => {}
        }

        Box::pin(async move { inner.call(request).await })
    }
}

/// Answers every version-shaped route this build does not serve.
///
/// **Where this sits matters twice over.** It is *inside* the gRPC-Web layer,
/// so a browser receives its answer framed as gRPC-Web rather than as raw gRPC
/// it cannot decode. It is *outside* authentication, because an unserved
/// version has no authentication scheme left to apply, and a client whose token
/// has also expired should still learn the real reason its version stopped
/// working. `auth::grpc_service_layer` is what pins that order.
#[derive(Clone)]
pub(crate) struct UnservedVersionLayer {
    recognised: &'static [&'static str],
}

impl UnservedVersionLayer {
    pub(crate) const fn new(recognised: &'static [&'static str]) -> Self {
        Self { recognised }
    }
}

impl<S> Layer<S> for UnservedVersionLayer {
    type Service = UnservedVersionService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        UnservedVersionService {
            inner,
            recognised: self.recognised,
        }
    }
}

#[derive(Clone)]
pub(crate) struct UnservedVersionService<S> {
    inner: S,
    recognised: &'static [&'static str],
}

impl<S, B> Service<Request<B>> for UnservedVersionService<S>
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

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let replacement = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, replacement);

        // One parse, and the version to echo comes straight out of it. Asking
        // `attribute` and then re-reading the path would be two passes that
        // could disagree — on the one route in the system where disagreeing
        // means either answering a served version as retired, or letting a
        // retired one reach a router that no longer has it.
        if *request.method() == Method::POST
            && let Some(Route::Versioned(version)) = classify(request.uri().path())
            && !self.recognised.contains(&version)
        {
            let refusal = version_not_served(version, self.recognised).into_http();
            return Box::pin(async move { Ok(refusal) });
        }

        Box::pin(async move { inner.call(request).await })
    }
}

#[cfg(test)]
mod serving_tests;

#[cfg(test)]
mod tests {
    use http::Method;

    use sovereign_config_core::{
        ERROR_KIND_METADATA, REQUESTED_VERSION_METADATA, VERSION_NOT_SERVED_KIND,
    };

    use super::{Attribution, Route, attribute, classify, echoed_version, version_not_served};
    use crate::metrics::ProtocolMetrics;

    const RECOGNISED: [&str; 2] = ["v3", "vtest"];

    #[test]
    fn a_versioned_route_is_read_as_the_version_its_package_names() {
        for (path, version) in [
            ("/sovereign.config.v3.System/GetVersion", "v3"),
            ("/sovereign.config.v3.Configuration/GetSubTree", "v3"),
            ("/sovereign.config.vtest.System/GetVersion", "vtest"),
        ] {
            assert_eq!(classify(path), Some(Route::Versioned(version)), "{path}");
        }
    }

    #[test]
    fn routes_that_are_not_versioned_packages_name_no_version() {
        for path in ["/grpc.health.v1.Health/Check", "/assets/index.js", "/"] {
            assert_eq!(classify(path), None, "{path}");
        }
        for path in ["/sovereign.config", "/sovereign.config."] {
            assert!(
                !matches!(classify(path), Some(Route::Versioned(_))),
                "{path}"
            );
        }
    }

    /// A recognised version is only credited with a request shaped like one its
    /// clients would send. Anything looser lets junk — a scanner probing
    /// `/sovereign.config.v3` — land in the real bucket and hold the retirement
    /// gate above zero, and would have the catch-all answering malformed paths
    /// as though a version had been retired.
    #[test]
    fn a_version_is_only_read_from_the_whole_service_and_method_shape() {
        for path in [
            "/sovereign.config.v3",
            "/sovereign.config.v3.",
            "/sovereign.config.v3.System",
            "/sovereign.config.v3.System/",
            "/sovereign.config.v3./GetVersion",
            "/sovereign.config.v3.System/GetVersion/extra",
        ] {
            assert_eq!(classify(path), Some(Route::Malformed), "{path}");
        }
    }

    /// The unversioned package is one dotted segment shorter than a versioned
    /// one, and that difference is the entire mechanism keeping the handshake
    /// outside every version. If this ever stopped holding, the handshake would
    /// be answered by the catch-all that exists to reject unserved versions —
    /// and no client could ever negotiate again.
    #[test]
    fn the_handshake_route_is_not_version_shaped() {
        assert_eq!(
            classify("/sovereign.config.Handshake/Negotiate"),
            Some(Route::Unversioned)
        );
        assert_eq!(
            classify("/sovereign.config.v3.System/GetVersion"),
            Some(Route::Versioned("v3"))
        );
        assert_eq!(classify("/grpc.health.v1.Health/Check"), None);
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

    /// The distinction the catch-all rests on: a version-shaped route naming an
    /// unserved version is answered version-not-served, while a path that is
    /// merely malformed is left alone to reach the router. Collapsing the two
    /// would dress every mistyped path up as a retirement.
    #[test]
    fn an_unserved_version_is_told_apart_from_a_malformed_path() {
        assert_eq!(
            attribute(
                &Method::POST,
                "/sovereign.config.v99.System/GetVersion",
                &RECOGNISED
            ),
            Attribution::UnservedVersion
        );
        for path in [
            "/sovereign.config.v3",
            "/sovereign.config.v3.System",
            "/sovereign.config.v3.System/GetVersion/extra",
        ] {
            assert_eq!(
                attribute(&Method::POST, path, &RECOGNISED),
                Attribution::Unrecognised,
                "{path}"
            );
        }
    }

    /// The handshake is protocol traffic that belongs to no version. Counting
    /// it as unrecognised would make every healthy connect look like a call on
    /// a version this build does not know.
    #[test]
    fn the_handshake_is_neither_a_version_nor_unrecognised() {
        assert_eq!(
            attribute(
                &Method::POST,
                "/sovereign.config.Handshake/Negotiate",
                &RECOGNISED
            ),
            Attribution::Unversioned
        );
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

    /// The label-injection guard: an arbitrary package segment must never
    /// become a metric label. `Served` is the only attribution carrying a
    /// label, and it can only carry one of `recognised`'s own `'static`
    /// strings, so a version from a request has nowhere to land but the fixed
    /// unserved bucket.
    #[test]
    fn a_version_from_a_request_never_becomes_a_label() {
        for path in [
            "/sovereign.config.v99.System/GetVersion",
            "/sovereign.config.v3\" injected=\".System/GetVersion",
        ] {
            assert_eq!(
                attribute(&Method::POST, path, &RECOGNISED),
                Attribution::UnservedVersion,
                "{path}"
            );
        }
    }

    /// The echoed version comes from the request, so it is the one piece of
    /// attacker-controlled text in the answer. It is bounded and stripped
    /// before it reaches a header or a log line.
    #[test]
    fn the_echoed_version_is_bounded_and_stripped() {
        assert_eq!(echoed_version("v99"), "v99");
        assert_eq!(echoed_version("\"quoted\""), "?quoted?");
        // A CRLF header injection loses both control characters. `-` survives
        // because a version identifier may legitimately carry one, and the
        // whole thing is cut at the length bound regardless.
        assert_eq!(echoed_version("v3\r\nx-injected: 1"), "v3??x-injected??");
        assert_eq!(echoed_version(&"v".repeat(4096)).len(), 16);
    }

    #[test]
    fn the_version_not_served_status_names_its_kind_and_the_version_asked_for() {
        let status = version_not_served("v99", &["v3"]);

        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            status
                .metadata()
                .get(ERROR_KIND_METADATA)
                .map(|value| value.to_str().unwrap()),
            Some(VERSION_NOT_SERVED_KIND)
        );
        assert_eq!(
            status
                .metadata()
                .get(REQUESTED_VERSION_METADATA)
                .map(|value| value.to_str().unwrap()),
            Some("v99")
        );
        assert!(status.message().contains("v99"), "{}", status.message());
        assert!(status.message().contains("v3"), "{}", status.message());
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

    /// The handshake's client-list series is bounded the same way the request
    /// series is: one label per compiled-in version, plus one fixed bucket.
    #[test]
    fn the_client_version_series_is_bounded_to_compiled_in_labels() {
        let metrics = ProtocolMetrics::new(&["v3"]);
        metrics.record_offered("v3");
        metrics.record_offered("v9000");

        let rendered = metrics.render();

        assert!(
            rendered.contains("sovereign_config_protocol_client_versions_total{version=\"v3\"} 1")
        );
        assert!(rendered.contains(
            "sovereign_config_protocol_client_versions_total{version=\"unrecognised\"} 1"
        ));
        assert_eq!(
            rendered
                .matches("sovereign_config_protocol_client_versions_total{")
                .count(),
            2,
            "one series per compiled-in label plus the unrecognised bucket"
        );
    }
}
