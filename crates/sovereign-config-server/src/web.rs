use std::{
    collections::BTreeMap, fs, future::Future, path::Path, pin::Pin, sync::Arc, task::Context,
    task::Poll,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http::{
    Method, Request, Response, StatusCode,
    header::{
        CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_SECURITY_POLICY, CONTENT_TYPE, HeaderValue,
        X_CONTENT_TYPE_OPTIONS,
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

/// Prebuilt installer artifacts served unauthenticated under `/dist`, loaded
/// into memory once at startup so serving stays synchronous. Keyed by file
/// name; slashes never appear in a key, so `/dist/<name>` lookups cannot
/// traverse out of the configured directory.
#[derive(Default)]
struct DistCatalog {
    files: BTreeMap<String, Arc<[u8]>>,
    downloads_page: Arc<[u8]>,
}

#[derive(Clone)]
pub(crate) struct WebAssetsLayer {
    app_config: Arc<[u8]>,
    content_security_policy: HeaderValue,
    dist: Arc<DistCatalog>,
}

impl WebAssetsLayer {
    pub(crate) fn new(config: &WebConfig) -> Self {
        let issuer = serde_json::to_string(&config.issuer).expect("issuer must serialize");
        let client_id = serde_json::to_string(&config.client_id).expect("client id must serialize");
        let index = Assets::get("index.html").expect("embedded administration index must exist");
        let loader_hash = inline_module_hash(index.data.as_ref());
        let dist = load_dist_catalog(config.dist_dir.as_deref(), &config.public_origin);
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
            dist: Arc::new(dist),
        }
    }
}

/// Loads every regular file in `dir` into memory and renders the downloads page
/// listing the installer scripts it found. A configured-but-unreadable
/// directory yields an empty catalog rather than failing startup: installer
/// distribution is secondary to serving the API and UI.
fn load_dist_catalog(dir: Option<&Path>, public_origin: &str) -> DistCatalog {
    let mut files = BTreeMap::new();
    if let Some(dir) = dir
        && let Ok(entries) = fs::read_dir(dir)
    {
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|kind| kind.is_file())
                && let Some(name) = entry.file_name().to_str().map(str::to_owned)
                && let Ok(bytes) = fs::read(entry.path())
            {
                files.insert(name, Arc::<[u8]>::from(bytes));
            }
        }
    }
    let downloads_page = render_downloads_page(&files, public_origin)
        .into_bytes()
        .into();
    DistCatalog {
        files,
        downloads_page,
    }
}

/// Renders a CSP-clean (no inline script or style) HTML page listing each
/// installer, its checksum, and an exact self-cleaning download-then-run
/// command. Installer scripts are `install-*.sh`; their `.sha256` companions
/// are linked but not listed as separate downloads.
fn render_downloads_page(files: &BTreeMap<String, Arc<[u8]>>, public_origin: &str) -> String {
    let mut page = String::from(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>Sovereign Config downloads</title>\n</head>\n<body>\n\
         <h1>Sovereign Config downloads</h1>\n",
    );
    let installers: Vec<&String> = files
        .keys()
        .filter(|name| name.starts_with("install-") && has_extension(name, "sh"))
        .collect();
    if installers.is_empty() {
        page.push_str("<p>No installers are published by this server.</p>\n");
    } else {
        page.push_str(
            "<p>Download the installer, then run it. The command below downloads to a temporary \
             directory that is removed afterwards.</p>\n",
        );
        for name in installers {
            let href = format!("/dist/{name}");
            let command = format!(
                "sh -c 'd=$(mktemp -d); trap \"rm -rf \\\"$d\\\"\" EXIT; \
                 curl -fsSL \"{public_origin}{href}\" -o \"$d/installer.sh\" && sh \"$d/installer.sh\"'"
            );
            page.push_str("<section>\n<h2><code>");
            page.push_str(&html_escape(name));
            page.push_str("</code></h2>\n<p><a href=\"");
            page.push_str(&html_escape(&href));
            page.push_str("\">Download installer</a>");
            let checksum = format!("{name}.sha256");
            if files.contains_key(&checksum) {
                page.push_str(" &middot; <a href=\"");
                page.push_str(&html_escape(&format!("/dist/{checksum}")));
                page.push_str("\">sha256</a>");
            }
            page.push_str("</p>\n<pre><code>");
            page.push_str(&html_escape(&command));
            page.push_str("</code></pre>\n</section>\n");
        }
    }
    page.push_str("</body>\n</html>\n");
    page
}

fn html_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            other => escaped.push(other),
        }
    }
    escaped
}

fn has_extension(name: &str, extension: &str) -> bool {
    Path::new(name)
        .extension()
        .is_some_and(|found| found.eq_ignore_ascii_case(extension))
}

/// Content type for a served installer artifact, chosen by extension.
fn dist_content_type(name: &str) -> &'static str {
    if has_extension(name, "sh") {
        "application/x-shellscript; charset=utf-8"
    } else if has_extension(name, "sha256") {
        "text/plain; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

impl<S> Layer<S> for WebAssetsLayer {
    type Service = WebAssetsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        WebAssetsService {
            inner,
            app_config: Arc::clone(&self.app_config),
            content_security_policy: self.content_security_policy.clone(),
            dist: Arc::clone(&self.dist),
        }
    }
}

#[derive(Clone)]
pub(crate) struct WebAssetsService<S> {
    inner: S,
    app_config: Arc<[u8]>,
    content_security_policy: HeaderValue,
    dist: Arc<DistCatalog>,
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
        } else if path == "downloads" || path == "downloads/" {
            asset_response(
                self.dist.downloads_page.as_ref(),
                "text/html; charset=utf-8",
                false,
                head,
                &self.content_security_policy,
            )
        } else if let Some(name) = path.strip_prefix("dist/") {
            match self.dist.files.get(name) {
                Some(bytes) => download_response(
                    bytes,
                    dist_content_type(name),
                    name,
                    head,
                    &self.content_security_policy,
                ),
                None => not_found(),
            }
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

/// Serves an installer artifact as an attachment. Names carry the release
/// version, so the bytes at a given path never change and may be cached
/// immutably.
fn download_response(
    bytes: &[u8],
    content_type: &str,
    name: &str,
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
    if let Ok(disposition) = HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")) {
        response
            .headers_mut()
            .insert(CONTENT_DISPOSITION, disposition);
    }
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
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
        header::{
            ACCESS_CONTROL_ALLOW_ORIGIN, CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE,
        },
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
            public_origin: "https://config.example.test".into(),
            dist_dir: None,
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

        let inner = service_fn(|_: Request<()>| async {
            Ok::<_, Infallible>(Response::<BoxBody>::new(empty_body()))
        });
        let response = layer
            .layer(inner)
            .oneshot(Request::get("/configuration/apps/api").body(()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(response.headers().get(CACHE_CONTROL).unwrap(), "no-store");
        assert_eq!(response.headers().get(CONTENT_TYPE).unwrap(), "text/html");
    }

    const INSTALLER_NAME: &str = "install-sovereign-config-cli-9.9.9-x86_64-linux.sh";

    fn dist_layer() -> (tempfile::TempDir, WebAssetsLayer) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(INSTALLER_NAME),
            b"#!/bin/sh\necho installer\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join(format!("{INSTALLER_NAME}.sha256")),
            format!("abc123  {INSTALLER_NAME}\n"),
        )
        .unwrap();
        let layer = WebAssetsLayer::new(&WebConfig {
            issuer: "https://auth.example.test/application/o/browser/".into(),
            client_id: "browser".into(),
            public_origin: "https://config.example.test".into(),
            dist_dir: Some(dir.path().to_path_buf()),
        });
        (dir, layer)
    }

    /// A concrete inner service whose future is `Send + 'static`, as
    /// `WebAssetsService` requires. Written as a macro so each expansion keeps
    /// the nameable `service_fn` type rather than an opaque `impl Service`.
    macro_rules! passthrough {
        () => {
            service_fn(|_: Request<()>| async {
                Ok::<_, Infallible>(Response::<BoxBody>::new(empty_body()))
            })
        };
    }

    async fn body_bytes(response: Response<BoxBody>) -> Vec<u8> {
        use http_body_util::BodyExt;
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec()
    }

    #[tokio::test]
    async fn serves_installer_as_an_immutable_attachment() {
        use http::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE};

        let (_dir, layer) = dist_layer();
        let response = layer
            .layer(passthrough!())
            .oneshot(
                Request::get(format!("/dist/{INSTALLER_NAME}"))
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/x-shellscript; charset=utf-8"
        );
        assert_eq!(
            response.headers().get(CONTENT_DISPOSITION).unwrap(),
            &format!("attachment; filename=\"{INSTALLER_NAME}\"")
        );
        assert_eq!(
            response.headers().get(CACHE_CONTROL).unwrap(),
            "public, max-age=31536000, immutable"
        );
        assert_eq!(body_bytes(response).await, b"#!/bin/sh\necho installer\n");
    }

    #[tokio::test]
    async fn missing_and_traversing_dist_paths_are_not_found() {
        let (_dir, layer) = dist_layer();
        for path in ["/dist/absent.sh", "/dist/nested/install.sh", "/dist/"] {
            let response = layer
                .clone()
                .layer(passthrough!())
                .oneshot(Request::get(path).body(()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                http::StatusCode::NOT_FOUND,
                "{path} must not resolve"
            );
        }
    }

    #[tokio::test]
    async fn downloads_page_lists_installer_with_absolute_curl_command() {
        use http::header::CONTENT_TYPE;

        let (_dir, layer) = dist_layer();
        let response = layer
            .layer(passthrough!())
            .oneshot(Request::get("/downloads").body(()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        let page = String::from_utf8(body_bytes(response).await).unwrap();
        assert!(
            page.contains(INSTALLER_NAME),
            "page must name the installer"
        );
        assert!(
            page.contains(&format!(
                "https://config.example.test/dist/{INSTALLER_NAME}"
            )),
            "page must present the absolute download URL"
        );
        assert!(
            page.contains("mktemp -d") && page.contains("rm -rf"),
            "page must present the self-cleaning temp-dir command"
        );
        assert!(
            page.contains(&format!("/dist/{INSTALLER_NAME}.sha256")),
            "page must link the checksum"
        );
    }

    #[tokio::test]
    async fn downloads_page_is_empty_without_a_dist_directory() {
        let layer = WebAssetsLayer::new(&WebConfig {
            issuer: "https://auth.example.test/application/o/browser/".into(),
            client_id: "browser".into(),
            public_origin: "https://config.example.test".into(),
            dist_dir: None,
        });
        let response = layer
            .layer(passthrough!())
            .oneshot(Request::get("/downloads").body(()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        let page = String::from_utf8(body_bytes(response).await).unwrap();
        assert!(page.contains("No installers are published"));
    }
}
