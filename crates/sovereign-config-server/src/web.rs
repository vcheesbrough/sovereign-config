use std::{future::Future, pin::Pin, sync::Arc, task::Context, task::Poll};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http::{
    Method, Request, Response, StatusCode,
    header::{
        CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, HeaderValue, X_CONTENT_TYPE_OPTIONS,
    },
};
use http_body_util::Full;
use rust_embed::RustEmbed;
use sha2::{Digest, Sha256};
use tonic::body::{BoxBody, boxed, empty_body};
use tower::{Layer, Service};

use crate::config::WebConfig;

#[derive(RustEmbed)]
#[folder = "../../web-dist/"]
struct Assets;

#[derive(Clone)]
pub(crate) struct WebAssetsLayer {
    app_config: Arc<[u8]>,
    content_security_policy: HeaderValue,
}

impl WebAssetsLayer {
    pub(crate) fn new(config: &WebConfig) -> Self {
        let issuer = serde_json::to_string(&config.issuer).expect("issuer must serialize");
        let client_id = serde_json::to_string(&config.client_id).expect("client id must serialize");
        let index = Assets::get("index.html").expect("embedded administration index must exist");
        let loader_hash = inline_module_hash(index.data.as_ref());
        Self {
            app_config: format!(
                "globalThis.SOVEREIGN_CONFIG={{issuer:{issuer},clientId:{client_id}}};"
            )
            .into_bytes()
            .into(),
            content_security_policy: HeaderValue::from_str(&format!(
                "default-src 'self'; connect-src 'self' https:; img-src 'self'; style-src 'self'; script-src 'self' 'wasm-unsafe-eval' 'sha256-{loader_hash}'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
            ))
            .expect("generated content security policy must be valid"),
        }
    }
}

impl<S> Layer<S> for WebAssetsLayer {
    type Service = WebAssetsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        WebAssetsService {
            inner,
            app_config: Arc::clone(&self.app_config),
            content_security_policy: self.content_security_policy.clone(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct WebAssetsService<S> {
    inner: S,
    app_config: Arc<[u8]>,
    content_security_policy: HeaderValue,
}

impl<S, B> Service<Request<B>> for WebAssetsService<S>
where
    S: Service<Request<B>, Response = Response<BoxBody>> + Clone,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response<BoxBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response<BoxBody>, S::Error>> + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        if request.method() != Method::GET && request.method() != Method::HEAD {
            return Box::pin(self.inner.call(request));
        }
        let head = request.method() == Method::HEAD;
        let path = request.uri().path().trim_start_matches('/');
        let response = if path == "app-config.js" {
            asset_response(
                self.app_config.as_ref(),
                "text/javascript; charset=utf-8",
                false,
                head,
                &self.content_security_policy,
            )
        } else {
            let requested = if path.is_empty() || !path.contains('.') {
                "index.html"
            } else {
                path
            };
            match Assets::get(requested) {
                Some(asset) => asset_response(
                    asset.data.as_ref(),
                    mime_guess::from_path(requested)
                        .first_or_octet_stream()
                        .as_ref(),
                    requested != "index.html",
                    head,
                    &self.content_security_policy,
                ),
                None => not_found(),
            }
        };
        Box::pin(async move { Ok(response) })
    }
}

fn asset_response(
    bytes: &[u8],
    content_type: &str,
    immutable: bool,
    head: bool,
    content_security_policy: &HeaderValue,
) -> Response<BoxBody> {
    let body = if head {
        empty_body()
    } else {
        boxed(Full::new(Bytes::copy_from_slice(bytes)))
    };
    let mut response = Response::new(body);
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_str(content_type)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static(if immutable {
            "public, max-age=31536000, immutable"
        } else {
            "no-store"
        }),
    );
    response
        .headers_mut()
        .insert(CONTENT_SECURITY_POLICY, content_security_policy.clone());
    response
        .headers_mut()
        .insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    response
}

fn inline_module_hash(index: &[u8]) -> String {
    let start_marker = b"<script type=\"module\">";
    let end_marker = b"</script>";
    let start = index
        .windows(start_marker.len())
        .position(|window| window == start_marker)
        .map(|position| position + start_marker.len())
        .expect("Trunk module loader must be present");
    let end = index[start..]
        .windows(end_marker.len())
        .position(|window| window == end_marker)
        .map(|position| start + position)
        .expect("Trunk module loader must terminate");
    STANDARD.encode(Sha256::digest(&index[start..end]))
}

fn not_found() -> Response<BoxBody> {
    let mut response = Response::new(empty_body());
    *response.status_mut() = StatusCode::NOT_FOUND;
    response
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use http::{
        Request, Response,
        header::{ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_SECURITY_POLICY},
    };
    use tonic::body::{BoxBody, empty_body};
    use tower::{Layer, ServiceExt, service_fn};

    use super::WebAssetsLayer;
    use crate::config::WebConfig;

    #[tokio::test]
    async fn assets_are_same_origin_and_never_add_cors() {
        let layer = WebAssetsLayer::new(&WebConfig {
            issuer: "https://auth.example.test/application/o/browser/".into(),
            client_id: "browser".into(),
        });
        let inner = service_fn(|_: Request<()>| async {
            Ok::<_, Infallible>(Response::<BoxBody>::new(empty_body()))
        });
        let response = layer
            .layer(inner)
            .oneshot(Request::get("/app-config.js").body(()).unwrap())
            .await
            .unwrap();
        assert!(
            response
                .headers()
                .get(ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
        let policy = response
            .headers()
            .get(CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(policy.contains("script-src 'self' 'wasm-unsafe-eval' 'sha256-"));
        assert!(
            !policy
                .split_ascii_whitespace()
                .any(|source| source == "'unsafe-eval'")
        );
        for directive in [
            "default-src 'self'",
            "connect-src 'self' https:",
            "object-src 'none'",
            "base-uri 'none'",
            "frame-ancestors 'none'",
        ] {
            assert!(policy.contains(directive));
        }
    }
}
