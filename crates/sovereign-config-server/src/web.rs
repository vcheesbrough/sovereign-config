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
/// traverse out of the configured directory. A synthesized `manifest.json`
/// describes the installers for the single-page app's Downloads view.
#[derive(Default)]
struct DistCatalog {
    files: BTreeMap<String, Arc<[u8]>>,
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
        let dist = load_dist_catalog(config.dist_dir.as_deref());
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

/// One installer as described to the Downloads single-page view.
#[derive(serde::Serialize)]
struct InstallerManifestEntry {
    file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    checksum: Option<String>,
    size: usize,
}

#[derive(serde::Serialize)]
struct InstallerManifest {
    installers: Vec<InstallerManifestEntry>,
}

/// Loads every regular file in `dir` into memory and synthesizes a
/// `manifest.json` describing the installer scripts it found. A
/// configured-but-unreadable directory yields only an empty manifest rather
/// than failing startup: installer distribution is secondary to serving the API
/// and UI. The manifest always exists so the Downloads view can render a
/// definitive "no installers" state.
fn load_dist_catalog(dir: Option<&Path>) -> DistCatalog {
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
    let manifest = render_manifest(&files);
    files.insert(
        "manifest.json".to_owned(),
        Arc::<[u8]>::from(manifest.into_bytes()),
    );
    DistCatalog { files }
}

/// Builds the installer manifest JSON. Installer scripts are `install-*.sh`;
/// each entry links its `.sha256` companion when present and reports its size.
fn render_manifest(files: &BTreeMap<String, Arc<[u8]>>) -> String {
    let installers = files
        .iter()
        .filter(|(name, _)| name.starts_with("install-") && has_extension(name, "sh"))
        .map(|(name, bytes)| {
            let checksum = format!("{name}.sha256");
            InstallerManifestEntry {
                file: name.clone(),
                checksum: files.contains_key(&checksum).then_some(checksum),
                size: bytes.len(),
            }
        })
        .collect();
    serde_json::to_string(&InstallerManifest { installers })
        .unwrap_or_else(|_| "{\"installers\":[]}".to_owned())
}

fn has_extension(name: &str, extension: &str) -> bool {
    Path::new(name)
        .extension()
        .is_some_and(|found| found.eq_ignore_ascii_case(extension))
}

/// Content type for a served `/dist` artifact, chosen by extension.
fn dist_content_type(name: &str) -> &'static str {
    if has_extension(name, "sh") {
        "application/x-shellscript; charset=utf-8"
    } else if has_extension(name, "sha256") {
        "text/plain; charset=utf-8"
    } else if has_extension(name, "json") {
        "application/json; charset=utf-8"
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

/// Serves a `/dist` artifact. Installer scripts carry the release version in
/// their name, so their bytes never change and are cached immutably and offered
/// as a download; the synthesized `manifest.json` shares a stable URL with
/// deploy-specific content, so it is never cached and served inline.
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
    if has_extension(name, "sh")
        && let Ok(disposition) = HeaderValue::from_str(&format!("attachment; filename=\"{name}\""))
    {
        response
            .headers_mut()
            .insert(CONTENT_DISPOSITION, disposition);
    }
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static(if has_extension(name, "json") {
            "no-store"
        } else {
            "public, max-age=31536000, immutable"
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
    async fn manifest_lists_the_installer_with_checksum_and_size() {
        use http::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE};

        let (_dir, layer) = dist_layer();
        let response = layer
            .layer(passthrough!())
            .oneshot(Request::get("/dist/manifest.json").body(()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json; charset=utf-8"
        );
        // A stable URL with deploy-specific content is served inline, uncached.
        assert_eq!(response.headers().get(CACHE_CONTROL).unwrap(), "no-store");
        assert!(response.headers().get(CONTENT_DISPOSITION).is_none());

        let manifest: serde_json::Value =
            serde_json::from_slice(&body_bytes(response).await).unwrap();
        let entry = &manifest["installers"][0];
        assert_eq!(entry["file"], INSTALLER_NAME);
        assert_eq!(entry["checksum"], format!("{INSTALLER_NAME}.sha256"));
        assert_eq!(entry["size"], "#!/bin/sh\necho installer\n".len());
    }

    #[tokio::test]
    async fn manifest_is_empty_without_a_dist_directory() {
        let layer = WebAssetsLayer::new(&WebConfig {
            issuer: "https://auth.example.test/application/o/browser/".into(),
            client_id: "browser".into(),
            dist_dir: None,
        });
        let response = layer
            .layer(passthrough!())
            .oneshot(Request::get("/dist/manifest.json").body(()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        let manifest: serde_json::Value =
            serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(manifest["installers"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn downloads_path_falls_through_to_the_single_page_app() {
        use http::header::CONTENT_TYPE;

        // `/downloads` is a client-side route: the server returns the SPA shell
        // (index.html), and the app renders the Downloads view.
        let (_dir, layer) = dist_layer();
        let response = layer
            .layer(passthrough!())
            .oneshot(Request::get("/downloads").body(()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(response.headers().get(CONTENT_TYPE).unwrap(), "text/html");
    }
}
