use std::{
    collections::HashMap,
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use axum::{
    Form, Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose};
use serde_json::json;
use sovereign_config_core::{ConfigPath, ConnectionUrl, Secret};
use sovereign_config_proto::sovereign::config::v3::{
    AddValuePathRequest, AddValuePathResponse, DeleteValuesRequest, DeleteValuesResponse,
    GetIdentityRequest, GetIdentityResponse, GetSubTreeRequest, GetSubTreeResponse,
    GetVersionRequest, GetVersionResponse, ListValuePathsRequest, ListValuePathsResponse,
    ListValuesRequest, ListValuesResponse, ListedValue, MaskedSecret, PutValueRequest,
    PutValueResponse, ReplaceSubTreeRequest, ReplaceSubTreeResponse, RevealSecretRequest,
    RevealSecretResponse, SubTreeValue, ValueClassification,
    configuration_server::{Configuration, ConfigurationServer},
    listed_value, put_value_request, sub_tree_mutation_value, sub_tree_value,
    system_server::{System, SystemServer},
};
use tempfile::TempDir;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Status, transport::Server};
use url::form_urlencoded;

const DEVICE_SECRET: &str = "device-secret-sentinel";
const ACCESS_SECRET: &str = "access-secret-sentinel";
const REFRESH_SECRET: &str = "refresh-secret-sentinel";
const ROTATED_REFRESH_SECRET: &str = "rotated-refresh-secret-sentinel";
const MANAGED_CREDENTIAL: &str = "pipeline:app-password-sentinel";

#[derive(Clone, Copy)]
enum DeviceResult {
    Success,
    PendingThenSuccess,
    SlowDownThenSuccess,
    Denied,
    Expired,
    Rejected,
    Unavailable,
}

struct OidcState {
    issuer: String,
    device_result: DeviceResult,
    poll_count: AtomicUsize,
    refresh_count: AtomicUsize,
    managed_count: AtomicUsize,
    managed_credential: Mutex<String>,
    reject_refresh: AtomicBool,
    reject_managed: AtomicBool,
    unavailable: AtomicBool,
    omit_device_endpoint: AtomicBool,
    unsafe_token_endpoint: AtomicBool,
}

struct TestServices {
    issuer: String,
    endpoint: String,
    oidc_state: Arc<OidcState>,
    oidc_task: tokio::task::JoinHandle<()>,
    grpc_task: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
}

impl Drop for TestServices {
    fn drop(&mut self) {
        self.oidc_task.abort();
        self.grpc_task.abort();
    }
}

#[derive(Default)]
struct MockSystem;

#[tonic::async_trait]
impl System for MockSystem {
    async fn get_version(
        &self,
        request: Request<GetVersionRequest>,
    ) -> Result<tonic::Response<GetVersionResponse>, Status> {
        if request.into_inner().protocol_version != "v3" {
            return Err(Status::failed_precondition("protocol mismatch"));
        }
        Ok(tonic::Response::new(GetVersionResponse {
            application_version: "1.5.0-test".to_owned(),
            protocol_version: "v3".to_owned(),
        }))
    }

    async fn get_identity(
        &self,
        request: Request<GetIdentityRequest>,
    ) -> Result<tonic::Response<GetIdentityResponse>, Status> {
        let authorization = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok());
        if authorization != Some("Bearer access-secret-sentinel") {
            return Err(Status::unauthenticated("authentication required"));
        }
        Ok(tonic::Response::new(GetIdentityResponse {
            authenticated: true,
        }))
    }
}

#[derive(Clone, Default)]
struct MockConfiguration {
    values: Arc<Mutex<HashMap<String, MockStoredValue>>>,
}

struct MockStoredValue {
    /// The spelling this path was **first** written with. The map is keyed by
    /// the fold, because `/x/FOO` and `/x/foo` are one value, but every
    /// response reports this — the service has been case-retentive since
    /// 2.18.0, and a client that assumes responses are lowercase is exactly
    /// what these tests need to catch.
    path: String,
    value: String,
    created_at: prost_types::Timestamp,
    secret: bool,
}

#[tonic::async_trait]
impl Configuration for MockConfiguration {
    async fn list_values(
        &self,
        request: Request<ListValuesRequest>,
    ) -> Result<tonic::Response<ListValuesResponse>, Status> {
        require_access_token(&request)?;
        let selected = request.into_inner().path.to_ascii_lowercase();
        let values = self.values.lock().unwrap();
        // The service answers with every readable namespace in the tree, not
        // only the selected path's children — narrowing those is the client's
        // job, so the mock has to hand over the wide set.
        let mut paths: Vec<String> = values.keys().flat_map(|path| ancestors(path)).collect();
        paths.sort();
        paths.dedup();
        let values = values
            .iter()
            .filter(|(path, _)| {
                path.rsplit_once('/').map_or(
                    "",
                    |(parent, _)| if parent.is_empty() { "/" } else { parent },
                ) == selected
            })
            .map(|(_, stored)| ListedValue {
                path: stored.path.clone(),
                content: Some(if stored.secret {
                    listed_value::Content::MaskedSecret(MaskedSecret {})
                } else {
                    listed_value::Content::PlainValue(stored.value.clone())
                }),
                created_at: Some(stored.created_at),
                updated_at: Some(stored.created_at),
                classification: if stored.secret {
                    ValueClassification::Secret as i32
                } else {
                    ValueClassification::Plain as i32
                },
                alias_paths: Vec::new(),
            })
            .collect();
        Ok(tonic::Response::new(ListValuesResponse { values, paths }))
    }

    async fn get_sub_tree(
        &self,
        request: Request<GetSubTreeRequest>,
    ) -> Result<tonic::Response<GetSubTreeResponse>, Status> {
        require_access_token(&request)?;
        let path = request.into_inner().path.to_ascii_lowercase();
        let values = self.values.lock().unwrap();
        let mut subtree = values
            .iter()
            .filter(|(candidate, _)| {
                path == "/"
                    || candidate.as_str() == path
                    || candidate
                        .strip_prefix(&path)
                        .is_some_and(|suffix| suffix.starts_with('/'))
            })
            .map(|(_, stored)| SubTreeValue {
                path: stored.path.clone(),
                content: Some(if stored.secret {
                    sub_tree_value::Content::MaskedSecret(MaskedSecret {})
                } else {
                    sub_tree_value::Content::PlainValue(stored.value.clone())
                }),
                classification: if stored.secret {
                    ValueClassification::Secret as i32
                } else {
                    ValueClassification::Plain as i32
                },
            })
            .collect::<Vec<_>>();
        subtree.sort_by_key(|value| value.path.to_ascii_lowercase());
        Ok(tonic::Response::new(GetSubTreeResponse { values: subtree }))
    }

    async fn put_value(
        &self,
        request: Request<PutValueRequest>,
    ) -> Result<tonic::Response<PutValueResponse>, Status> {
        require_access_token(&request)?;
        let request = request.into_inner();
        let timestamp = prost_types::Timestamp {
            seconds: 1_700_000_000,
            nanos: 0,
        };
        let mut values = self.values.lock().unwrap();
        let established = values.get(&request.path.to_ascii_lowercase());
        let created_at = established.map_or(timestamp, |stored| stored.created_at);
        // A later write through a differently-cased spelling updates the value
        // and leaves the established case exactly as the first write set it.
        let path = established.map_or_else(|| request.path.clone(), |stored| stored.path.clone());
        let (value, secret) = match request.content {
            Some(put_value_request::Content::PlainValue(value)) => (value, false),
            Some(put_value_request::Content::SecretValue(value)) => (value, true),
            None => return Err(Status::invalid_argument("missing value")),
        };
        values.insert(
            request.path.to_ascii_lowercase(),
            MockStoredValue {
                path,
                value,
                created_at,
                secret,
            },
        );
        Ok(tonic::Response::new(PutValueResponse {
            created_at: Some(created_at),
            updated_at: Some(timestamp),
        }))
    }

    async fn replace_sub_tree(
        &self,
        request: Request<ReplaceSubTreeRequest>,
    ) -> Result<tonic::Response<ReplaceSubTreeResponse>, Status> {
        require_access_token(&request)?;
        let request = request.into_inner();
        let root = request.path.to_ascii_lowercase();
        let timestamp = prost_types::Timestamp {
            seconds: 1_700_000_002,
            nanos: 0,
        };
        let mut values = self.values.lock().unwrap();
        values.retain(|path, stored| {
            stored.secret
                || !(root == "/"
                    || path == &root
                    || path
                        .strip_prefix(&root)
                        .is_some_and(|suffix| suffix.starts_with('/')))
        });
        for value in &request.values {
            let Some(sub_tree_mutation_value::Content::PlainValue(content)) =
                value.content.as_ref()
            else {
                continue;
            };
            values.insert(
                value.path.to_ascii_lowercase(),
                MockStoredValue {
                    path: value.path.clone(),
                    value: content.clone(),
                    created_at: timestamp,
                    secret: false,
                },
            );
        }
        Ok(tonic::Response::new(ReplaceSubTreeResponse {
            updated_at: Some(timestamp),
            value_count: request.values.len() as u64,
        }))
    }

    async fn delete_values(
        &self,
        request: Request<DeleteValuesRequest>,
    ) -> Result<tonic::Response<DeleteValuesResponse>, Status> {
        require_access_token(&request)?;
        let request = request.into_inner();
        let path = request.path.to_ascii_lowercase();
        let mut values = self.values.lock().unwrap();
        let before = values.len();
        if request.recurse {
            values.retain(|candidate, _| {
                !(path == "/"
                    || candidate == &path
                    || candidate
                        .strip_prefix(&path)
                        .is_some_and(|suffix| suffix.starts_with('/')))
            });
        } else {
            values.remove(&path);
        }
        let deleted_count = (before - values.len()) as u64;
        if deleted_count == 0 {
            return Err(Status::not_found("missing"));
        }
        Ok(tonic::Response::new(DeleteValuesResponse {
            deleted_at: Some(prost_types::Timestamp {
                seconds: 1_700_000_002,
                nanos: 0,
            }),
            deleted_count,
        }))
    }

    async fn reveal_secret(
        &self,
        request: Request<RevealSecretRequest>,
    ) -> Result<tonic::Response<RevealSecretResponse>, Status> {
        require_access_token(&request)?;
        let path = request.into_inner().path.to_ascii_lowercase();
        let values = self.values.lock().unwrap();
        match values.get(&path) {
            Some(stored) if stored.secret => Ok(tonic::Response::new(RevealSecretResponse {
                value: stored.value.clone(),
            })),
            Some(_) => Err(Status::failed_precondition("not a secret")),
            None => Err(Status::not_found("missing")),
        }
    }

    async fn add_value_path(
        &self,
        request: Request<AddValuePathRequest>,
    ) -> Result<tonic::Response<AddValuePathResponse>, Status> {
        require_access_token(&request)?;
        let request = request.into_inner();
        let new_path = request.new_path.to_ascii_lowercase();
        // Sentinel path standing in for a grant the caller cannot write.
        if new_path.ends_with("/forbidden") {
            return Err(Status::permission_denied("not permitted"));
        }
        let source = request.source_path.to_ascii_lowercase();
        let timestamp = prost_types::Timestamp {
            seconds: 1_700_000_003,
            nanos: 0,
        };
        let mut values = self.values.lock().unwrap();
        let Some(stored) = values.get(&source) else {
            return Err(Status::not_found("missing"));
        };
        let (value, secret) = (stored.value.clone(), stored.secret);
        if values.contains_key(&new_path) {
            return Err(Status::already_exists("exists"));
        }
        values.insert(
            new_path.clone(),
            MockStoredValue {
                path: request.new_path.clone(),
                value,
                created_at: timestamp,
                secret,
            },
        );
        Ok(tonic::Response::new(AddValuePathResponse {
            created_at: Some(timestamp),
        }))
    }

    async fn list_value_paths(
        &self,
        request: Request<ListValuePathsRequest>,
    ) -> Result<tonic::Response<ListValuePathsResponse>, Status> {
        require_access_token(&request)?;
        let path = request.into_inner().path.to_ascii_lowercase();
        let values = self.values.lock().unwrap();
        let Some(stored) = values.get(&path) else {
            return Err(Status::not_found("missing"));
        };
        // Group by stored value: aliases carry an identical copy of the value.
        let mut paths = values
            .iter()
            .filter(|(_, candidate)| {
                candidate.secret == stored.secret && candidate.value == stored.value
            })
            .map(|(_, stored)| stored.path.clone())
            .collect::<Vec<_>>();
        paths.sort_by_key(|path| path.to_ascii_lowercase());
        Ok(tonic::Response::new(ListValuePathsResponse { paths }))
    }
}

/// Every namespace at or above `path`, root first, excluding `path` itself.
fn ancestors(path: &str) -> Vec<String> {
    let mut namespaces = vec!["/".to_owned()];
    let mut prefix = String::new();
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    for segment in &segments[..segments.len() - 1] {
        prefix.push('/');
        prefix.push_str(segment);
        namespaces.push(prefix.clone());
    }
    namespaces
}

#[allow(clippy::result_large_err)]
fn require_access_token<T>(request: &Request<T>) -> Result<(), Status> {
    let authorization = request
        .metadata()
        .get("authorization")
        .and_then(|value| value.to_str().ok());
    if authorization == Some("Bearer access-secret-sentinel") {
        Ok(())
    } else {
        Err(Status::unauthenticated("authentication required"))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn exact_value_commands_use_absolute_paths_within_profile_root_and_hard_delete() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    let connection = connection_url(&services, true, "team/service");
    let profile = run_cli_with_input(
        home.path(),
        &["profile", "add", "managed"],
        Some(&format!("{connection}\n")),
    )
    .await;
    assert_success(&profile);

    let root_put = run_cli_with_input(
        home.path(),
        &["set", "/team/service"],
        Some("root-value-sentinel"),
    )
    .await;
    assert_success(&root_put);

    let root_get = run_cli(home.path(), &["get", "/team/service"]).await;
    assert_success(&root_get);
    assert_eq!(
        String::from_utf8_lossy(&root_get.stdout),
        "root-value-sentinel"
    );

    let root_delete = run_cli(home.path(), &["delete", "/team/service", "--yes"]).await;
    assert_success(&root_delete);

    let put = run_cli_with_input(
        home.path(),
        &["set", "/team/service/Feature/Flag"],
        Some("value-sentinel\nsecond-line"),
    )
    .await;
    assert_success(&put);
    assert_eq!(String::from_utf8_lossy(&put.stdout), "Value stored\n");
    assert!(!combined(&put).contains("value-sentinel"));

    let get = run_cli(home.path(), &["get", "/TEAM/SERVICE/FEATURE/FLAG"]).await;
    assert_success(&get);
    assert_eq!(
        String::from_utf8_lossy(&get.stdout),
        "value-sentinel\nsecond-line"
    );

    let delete = run_cli(
        home.path(),
        &["delete", "/team/service/feature/flag", "--yes"],
    )
    .await;
    assert_success(&delete);
    assert_eq!(String::from_utf8_lossy(&delete.stdout), "Value deleted\n");

    let missing = run_cli(home.path(), &["get", "/team/service/feature/flag"]).await;
    assert!(!missing.status.success());
    assert!(combined(&missing).contains("configuration value not found"));

    let relative = run_cli(home.path(), &["get", "team/service/feature/flag"]).await;
    assert!(!relative.status.success());
    assert!(combined(&relative).contains("path must name a configuration value"));

    let outside_root = run_cli(home.path(), &["get", "/other/feature-flag"]).await;
    assert!(!outside_root.status.success());
    assert!(combined(&outside_root).contains("path is outside the selected profile root"));
}

#[tokio::test(flavor = "multi_thread")]
async fn value_path_aliases_are_added_listed_and_permission_checked() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    let connection = connection_url(&services, true, "team/service");
    assert_success(
        &run_cli_with_input(
            home.path(),
            &["profile", "add", "managed"],
            Some(&format!("{connection}\n")),
        )
        .await,
    );

    assert_success(
        &run_cli_with_input(
            home.path(),
            &["set", "/team/service/original"],
            Some("aliased-value-sentinel"),
        )
        .await,
    );

    let added = run_cli(
        home.path(),
        &["alias", "/team/service/original", "/team/service/Alias"],
    )
    .await;
    assert_success(&added);
    assert_eq!(String::from_utf8_lossy(&added.stdout), "Path added\n");

    let aliased = run_cli(home.path(), &["get", "/team/service/alias"]).await;
    assert_success(&aliased);
    assert_eq!(
        String::from_utf8_lossy(&aliased.stdout),
        "aliased-value-sentinel"
    );

    let listed = run_cli(
        home.path(),
        &["list", "/team/service/ORIGINAL", "--aliases"],
    )
    .await;
    assert_success(&listed);
    assert_eq!(
        String::from_utf8_lossy(&listed.stdout),
        "/team/service/Alias\n/team/service/original\n"
    );

    let relative = run_cli(
        home.path(),
        &["alias", "team/service/original", "/team/service/other"],
    )
    .await;
    assert!(!relative.status.success());
    assert!(combined(&relative).contains("path must name a configuration value"));

    let outside = run_cli(
        home.path(),
        &["alias", "/team/service/original", "/other/alias"],
    )
    .await;
    assert!(!outside.status.success());
    assert!(combined(&outside).contains("path is outside the selected profile root"));

    let denied = run_cli(
        home.path(),
        &["alias", "/team/service/original", "/team/service/forbidden"],
    )
    .await;
    assert!(!denied.status.success());
    assert!(combined(&denied).contains("permission denied"));
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn secret_commands_mask_preserve_rotate_reveal_and_delete_values() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    let connection = connection_url(&services, true, "team/service");
    assert_success(
        &run_cli_with_input(
            home.path(),
            &["profile", "add", "managed"],
            Some(&format!("{connection}\n")),
        )
        .await,
    );

    let first = "configuration-secret-sentinel-one";
    let stored = run_cli_with_input(
        home.path(),
        &["set", "/team/service/credential", "--secret"],
        Some(first),
    )
    .await;
    assert_success(&stored);
    assert_eq!(String::from_utf8_lossy(&stored.stdout), "Secret stored\n");
    assert!(!combined(&stored).contains(first));

    let masked = run_cli(home.path(), &["get", "/team/service/credential"]).await;
    assert_success(&masked);
    assert_eq!(String::from_utf8_lossy(&masked.stdout), "********");
    assert!(!combined(&masked).contains(first));
    let masked_json = run_cli(
        home.path(),
        &["get", "/team/service", "--tree", "--format", "json"],
    )
    .await;
    assert_success(&masked_json);
    assert_eq!(
        String::from_utf8_lossy(&masked_json.stdout),
        "{\n  \"credential\": \"********\"\n}\n"
    );
    assert!(!combined(&masked_json).contains(first));
    let revealed_by_get = run_cli(
        home.path(),
        &["get", "/team/service/credential", "--reveal"],
    )
    .await;
    assert_success(&revealed_by_get);
    assert_eq!(String::from_utf8_lossy(&revealed_by_get.stdout), first);
    assert!(revealed_by_get.stderr.is_empty());
    let revealed = run_cli(
        home.path(),
        &["get", "/team/service/credential", "--reveal"],
    )
    .await;
    assert_success(&revealed);
    assert_eq!(String::from_utf8_lossy(&revealed.stdout), first);
    assert!(revealed.stderr.is_empty());

    let second = "configuration-secret-sentinel-two";
    let rotated = run_cli_with_input(
        home.path(),
        &["set", "/team/service/credential", "--secret"],
        Some(second),
    )
    .await;
    assert_success(&rotated);
    assert!(!combined(&rotated).contains(second));
    let sibling =
        run_cli_with_input(home.path(), &["set", "/team/service/enabled"], Some("true")).await;
    assert_success(&sibling);
    let masked_json = run_cli(
        home.path(),
        &["get", "/team/service", "--tree", "--format", "json"],
    )
    .await;
    assert_success(&masked_json);
    assert_eq!(
        String::from_utf8_lossy(&masked_json.stdout),
        "{\n  \"credential\": \"********\",\n  \"enabled\": \"true\"\n}\n"
    );
    assert!(!combined(&masked_json).contains(second));
    let json = run_cli_with_input(
        home.path(),
        &["set", "/team/service", "--tree"],
        Some("{\"credential\":\"********\",\"enabled\":\"false\"}"),
    )
    .await;
    assert_success(&json);
    assert!(!combined(&json).contains(second));
    let revealed_json = run_cli(
        home.path(),
        &[
            "get",
            "/team/service",
            "--tree",
            "--format",
            "json",
            "--reveal",
        ],
    )
    .await;
    assert_success(&revealed_json);
    assert_eq!(
        String::from_utf8_lossy(&revealed_json.stdout),
        format!("{{\n  \"credential\": \"{second}\",\n  \"enabled\": \"false\"\n}}\n")
    );
    assert!(revealed_json.stderr.is_empty());
    let revealed = run_cli(
        home.path(),
        &["get", "/team/service/credential", "--reveal"],
    )
    .await;
    assert_eq!(String::from_utf8_lossy(&revealed.stdout), second);
    let sibling = run_cli(home.path(), &["get", "/team/service/enabled"]).await;
    assert_eq!(String::from_utf8_lossy(&sibling.stdout), "false");

    let deleted = run_cli(
        home.path(),
        &["delete", "/team/service/credential", "--yes"],
    )
    .await;
    assert_success(&deleted);
    assert!(!combined(&deleted).contains(second));
    let missing = run_cli(
        home.path(),
        &["get", "/team/service/credential", "--reveal"],
    )
    .await;
    assert!(!missing.status.success());
    assert!(combined(&missing).contains("configuration value not found"));
    assert!(!combined(&missing).contains(second));
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn json_subtrees_replace_atomically_and_recursive_delete_respects_boundaries() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    let connection = connection_url(&services, true, "team/service");
    assert_success(
        &run_cli_with_input(
            home.path(),
            &["profile", "add", "managed"],
            Some(&format!("{connection}\n")),
        )
        .await,
    );

    for (path, value) in [
        ("/team/service/apps/enabled", "true"),
        ("/team/service/apps/nested/message", "hello\nworld"),
        ("/team/service/apps-v2/kept", "boundary"),
        ("/team/service/foo/foo2/foo3/deepvalue", "deepvalue"),
        ("/team/service/foo/second/abc", "bar"),
    ] {
        assert_success(&run_cli_with_input(home.path(), &["set", path], Some(value)).await);
    }

    // An exact read of a namespace asks for the one value at that path, which
    // does not exist; the descendants below it are not an answer to it.
    let exact_namespace = run_cli(home.path(), &["get", "/team/service/apps"]).await;
    assert!(!exact_namespace.status.success());
    assert!(combined(&exact_namespace).contains("configuration value not found"));

    // `--tree` reads the same namespace, keyed by absolute path, with the
    // embedded newline escaped so one value stays one line.
    let plain_subtree = run_cli(home.path(), &["get", "/TEAM/SERVICE/APPS", "--tree"]).await;
    assert_success(&plain_subtree);
    assert_eq!(
        String::from_utf8_lossy(&plain_subtree.stdout),
        "/team/service/apps/enabled=true\n\
         /team/service/apps/nested/message=hello\\nworld\n"
    );

    let json = run_cli(
        home.path(),
        &["get", "/TEAM/SERVICE/APPS", "--tree", "--format", "json"],
    )
    .await;
    assert_success(&json);
    assert_eq!(
        String::from_utf8_lossy(&json.stdout),
        "{\n  \"enabled\": \"true\",\n  \"nested\": {\n    \"message\": \"hello\\nworld\"\n  }\n}\n"
    );

    let deep_json = run_cli(
        home.path(),
        &[
            "get",
            "/team/service/foo/foo2/foo3",
            "--tree",
            "--format",
            "json",
        ],
    )
    .await;
    assert_success(&deep_json);
    assert_eq!(deep_json.stdout, b"{\n  \"deepvalue\": \"deepvalue\"\n}\n");

    let partial_segment = run_cli(
        home.path(),
        &["get", "/team/service/foo/s", "--tree", "--format", "json"],
    )
    .await;
    assert_success(&partial_segment);
    assert_eq!(partial_segment.stdout, b"{}\n");
    assert_success(
        &run_cli_with_input(home.path(), &["set", "/team/service/foo/s"], Some("short")).await,
    );
    assert_success(&run_cli(home.path(), &["delete", "/team/service/foo/s", "--yes"]).await);
    assert_success(
        &run_cli_with_input(
            home.path(),
            &["set", "/team/service/foo/s", "--tree"],
            Some("{\"child\":\"value\"}"),
        )
        .await,
    );
    assert_success(
        &run_cli(
            home.path(),
            &["delete", "/team/service/foo/s", "--tree", "--yes"],
        )
        .await,
    );
    let completed_segment = run_cli(home.path(), &["get", "/team/service/foo/second/abc"]).await;
    assert_success(&completed_segment);
    assert_eq!(completed_segment.stdout, b"bar");

    let replacement = run_cli_with_input(
        home.path(),
        &["set", "/team/service/apps", "--tree"],
        Some("{\"enabled\":\"false\",\"new-value\":\"new\"}"),
    )
    .await;
    assert_success(&replacement);
    assert_eq!(replacement.stdout, b"Subtree replaced\n");
    let replaced = run_cli(
        home.path(),
        &["get", "/team/service/apps", "--tree", "--format", "json"],
    )
    .await;
    assert_success(&replaced);
    assert_eq!(
        String::from_utf8_lossy(&replaced.stdout),
        "{\n  \"enabled\": \"false\",\n  \"new-value\": \"new\"\n}\n"
    );

    let exact_json = run_cli(
        home.path(),
        &["get", "/team/service/apps/enabled", "--format", "json"],
    )
    .await;
    assert_success(&exact_json);
    assert_eq!(exact_json.stdout, b"\"false\"\n");
    let exact_replacement = run_cli_with_input(
        home.path(),
        &["set", "/team/service/apps/enabled", "--tree"],
        Some("\"exact-json\""),
    )
    .await;
    assert_success(&exact_replacement);
    let exact_text = run_cli(home.path(), &["get", "/team/service/apps/enabled"]).await;
    assert_success(&exact_text);
    assert_eq!(exact_text.stdout, b"exact-json");

    let invalid = run_cli_with_input(
        home.path(),
        &["set", "/team/service/apps", "--tree"],
        Some("{\"enabled\":true}"),
    )
    .await;
    assert!(!invalid.status.success());
    assert!(combined(&invalid).contains("configuration JSON is invalid"));
    let unchanged = run_cli(home.path(), &["get", "/team/service/apps/enabled"]).await;
    assert_success(&unchanged);
    assert_eq!(unchanged.stdout, b"exact-json");

    assert_success(
        &run_cli_with_input(
            home.path(),
            &["set", "/team/service/collision"],
            Some("parent"),
        )
        .await,
    );
    assert_success(
        &run_cli_with_input(
            home.path(),
            &["set", "/team/service/collision/child"],
            Some("child"),
        )
        .await,
    );
    let collision = run_cli(
        home.path(),
        &[
            "get",
            "/team/service/collision",
            "--tree",
            "--format",
            "json",
        ],
    )
    .await;
    assert!(!collision.status.success());
    assert!(combined(&collision).contains("configuration subtree cannot be represented as JSON"));

    let deleted = run_cli(
        home.path(),
        &["delete", "/team/service/apps", "--tree", "--yes"],
    )
    .await;
    assert_success(&deleted);
    assert_eq!(deleted.stdout, b"Subtree deleted\n");
    let empty = run_cli(
        home.path(),
        &["get", "/team/service/apps", "--tree", "--format", "json"],
    )
    .await;
    assert_success(&empty);
    assert_eq!(empty.stdout, b"{}\n");
    let boundary = run_cli(home.path(), &["get", "/team/service/apps-v2/kept"]).await;
    assert_success(&boundary);
    assert_eq!(boundary.stdout, b"boundary");

    let invalid_format = run_cli(
        home.path(),
        &["get", "/team/service/apps", "--format", "yaml"],
    )
    .await;
    assert!(!invalid_format.status.success());
    assert!(combined(&invalid_format).contains("invalid value 'yaml'"));
}

#[tokio::test(flavor = "multi_thread")]
async fn json_root_operations_require_a_root_profile() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    let connection = connection_url(&services, true, "team/service");
    assert_success(
        &run_cli_with_input(
            home.path(),
            &["profile", "add", "managed"],
            Some(&format!("{connection}\n")),
        )
        .await,
    );
    let outside = run_cli(home.path(), &["get", "/", "--tree", "--format", "json"]).await;
    assert!(!outside.status.success());
    assert!(combined(&outside).contains("path is outside the selected profile root"));

    let root_connection = connection_url(&services, true, "");
    assert_success(
        &run_cli_with_input(
            home.path(),
            &["profile", "add", "root"],
            Some(&format!("{root_connection}\n")),
        )
        .await,
    );
    let root_put = run_cli_with_input(
        home.path(),
        &["--profile", "root", "set", "/", "--tree"],
        Some("{\"root-value\":\"stored\"}"),
    )
    .await;
    assert_success(&root_put);
    let root_get = run_cli(
        home.path(),
        &[
            "--profile",
            "root",
            "get",
            "/",
            "--tree",
            "--format",
            "json",
        ],
    )
    .await;
    assert_success(&root_get);
    assert_eq!(
        String::from_utf8_lossy(&root_get.stdout),
        "{\n  \"root-value\": \"stored\"\n}\n"
    );
    let exact_root_delete =
        run_cli(home.path(), &["--profile", "root", "delete", "/", "--yes"]).await;
    assert!(!exact_root_delete.status.success());
    assert!(combined(&exact_root_delete).contains("path must name a configuration value"));
}

#[tokio::test(flavor = "multi_thread")]
async fn plain_subtree_reads_key_every_value_by_absolute_path() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    let connection = connection_url(&services, true, "team/service");
    assert_success(
        &run_cli_with_input(
            home.path(),
            &["profile", "add", "managed"],
            Some(&format!("{connection}\n")),
        )
        .await,
    );

    let secret = "plain-subtree-secret-sentinel";
    assert_success(
        &run_cli_with_input(
            home.path(),
            &["set", "/team/service/db/Host"],
            Some("pg.internal"),
        )
        .await,
    );
    assert_success(
        &run_cli_with_input(
            home.path(),
            &["set", "/team/service/db/password", "--secret"],
            Some(secret),
        )
        .await,
    );
    assert_success(
        &run_cli_with_input(home.path(), &["set", "/team/service/enabled"], Some("true")).await,
    );
    assert_success(
        &run_cli_with_input(
            home.path(),
            &["set", "/team/service/banner"],
            Some("first\nsecond\r\nthird\\fourth"),
        )
        .await,
    );

    let masked = run_cli(home.path(), &["get", "/team/service", "--tree"]).await;
    assert_success(&masked);
    assert_eq!(
        String::from_utf8_lossy(&masked.stdout),
        "/team/service/banner=first\\nsecond\\r\\nthird\\\\fourth\n\
         /team/service/db/Host=pg.internal\n\
         /team/service/db/password=********\n\
         /team/service/enabled=true\n"
    );
    assert!(!combined(&masked).contains(secret));

    let revealed = run_cli(
        home.path(),
        &["get", "/team/service/db", "--tree", "--reveal"],
    )
    .await;
    assert_success(&revealed);
    assert_eq!(
        String::from_utf8_lossy(&revealed.stdout),
        format!("/team/service/db/Host=pg.internal\n/team/service/db/password={secret}\n")
    );
    assert!(revealed.stderr.is_empty());

    // An emptied subtree prints nothing and still succeeds, matching JSON's `{}`.
    assert_success(&run_cli(home.path(), &["delete", "/team/service", "--tree", "--yes"]).await);
    let empty = run_cli(home.path(), &["get", "/team/service", "--tree"]).await;
    assert_success(&empty);
    assert_eq!(empty.stdout, b"");
    assert_secrets_absent(&combined(&empty));
}

#[tokio::test(flavor = "multi_thread")]
async fn list_shows_only_the_selected_paths_direct_children() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    let connection = connection_url(&services, true, "team/service");
    assert_success(
        &run_cli_with_input(
            home.path(),
            &["profile", "add", "managed"],
            Some(&format!("{connection}\n")),
        )
        .await,
    );

    for (path, value) in [
        ("/team/service/enabled", "true"),
        ("/team/service/apps/api/port", "8080"),
        ("/team/service/apps/web/port", "8081"),
        ("/team/service/elsewhere/deep/leaf", "deep"),
    ] {
        assert_success(&run_cli_with_input(home.path(), &["set", path], Some(value)).await);
    }

    // `/team/service/apps/api` and `/team/service/elsewhere/deep` are readable
    // namespaces too, but they are not children of `/team/service`.
    let listed = run_cli(home.path(), &["list", "/team/service"]).await;
    assert_success(&listed);
    assert_eq!(
        String::from_utf8_lossy(&listed.stdout),
        "/team/service/apps/\n/team/service/elsewhere/\n/team/service/enabled\n"
    );

    let nested = run_cli(
        home.path(),
        &["list", "/TEAM/SERVICE/APPS", "--format", "json"],
    )
    .await;
    assert_success(&nested);
    assert_eq!(
        String::from_utf8_lossy(&nested.stdout),
        "[\n  \"/team/service/apps/api/\",\n  \"/team/service/apps/web/\"\n]\n"
    );

    let leaf = run_cli(home.path(), &["list", "/team/service/apps/api"]).await;
    assert_success(&leaf);
    assert_eq!(leaf.stdout, b"/team/service/apps/api/port\n");

    let outside = run_cli(home.path(), &["list", "/other"]).await;
    assert!(!outside.status.success());
    assert!(combined(&outside).contains("path is outside the selected profile root"));

    assert_success(
        &run_cli(
            home.path(),
            &[
                "alias",
                "/team/service/enabled",
                "/team/service/Enabled-Too",
            ],
        )
        .await,
    );
    let aliases = run_cli(
        home.path(),
        &[
            "list",
            "/team/service/enabled",
            "--aliases",
            "--format",
            "json",
        ],
    )
    .await;
    assert_success(&aliases);
    assert_eq!(
        String::from_utf8_lossy(&aliases.stdout),
        "[\n  \"/team/service/enabled\",\n  \"/team/service/Enabled-Too\"\n]\n"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn profiles_are_listed_by_name_with_the_default_marked_and_credentials_redacted() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();

    // No configuration yet: an empty listing, not an error.
    let empty = run_cli(home.path(), &["profile", "list"]).await;
    assert_success(&empty);
    assert_eq!(empty.stdout, b"");
    let empty_json = run_cli(home.path(), &["profile", "list", "--format", "json"]).await;
    assert_success(&empty_json);
    assert_eq!(empty_json.stdout, b"[]\n");

    // Added out of alphabetical order, and the first added is the default.
    for (name, root) in [("prod", "team/service"), ("dev", "")] {
        let url = connection_url(&services, name == "prod", root);
        assert_success(
            &run_cli_with_input(
                home.path(),
                &["profile", "add", name],
                Some(&format!("{url}\n")),
            )
            .await,
        );
    }

    let listed = run_cli(home.path(), &["profile", "list"]).await;
    assert_success(&listed);
    let plain = String::from_utf8_lossy(&listed.stdout).into_owned();
    let lines: Vec<&str> = plain.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(
        lines[0].starts_with("  dev "),
        "names order ahead of the default marker: {plain}"
    );
    assert!(
        lines[1].starts_with("* prod"),
        "the default profile is marked: {plain}"
    );
    // A confined profile shows the root it is confined to; an unconfined one
    // shows only its endpoint.
    assert!(lines[1].ends_with("/team/service"), "{plain}");
    assert!(lines[0].ends_with(&services.endpoint), "{plain}");
    assert_secrets_absent(&combined(&listed));

    let json = run_cli(home.path(), &["profile", "list", "--format", "json"]).await;
    assert_success(&json);
    let parsed: serde_json::Value =
        serde_json::from_slice(&json.stdout).expect("listing must be JSON");
    let entries = parsed.as_array().expect("listing must be an array");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["name"], "dev");
    assert_eq!(entries[0]["default"], false);
    assert_eq!(entries[0]["root"], "/");
    assert_eq!(entries[1]["name"], "prod");
    assert_eq!(entries[1]["default"], true);
    assert_eq!(entries[1]["root"], "/team/service");
    // `prod` is managed, so its URL must carry the mask, never the credential.
    assert!(
        entries[1]["url"]
            .as_str()
            .unwrap()
            .ends_with("client_secret=*")
    );
    assert_secrets_absent(&combined(&json));

    assert_success(&run_cli(home.path(), &["profile", "default", "dev"]).await);
    let moved = run_cli(home.path(), &["profile", "list"]).await;
    assert_success(&moved);
    assert!(
        String::from_utf8_lossy(&moved.stdout).starts_with("* dev"),
        "the marker follows the default"
    );

    // `--profile` selects a profile for operational commands, so it is
    // rejected here exactly as it is on the other profile subcommands.
    let overridden = run_cli(home.path(), &["--profile", "dev", "profile", "list"]).await;
    assert!(!overridden.status.success());
    assert!(combined(&overridden).contains("--profile applies only to operational commands"));
}

#[tokio::test(flavor = "multi_thread")]
async fn every_value_command_teaches_the_path_before_the_options() {
    let home = TempDir::new().unwrap();
    for (verb, expected) in [
        ("get", "sovereign-config get <ABSOLUTE_PATH> [OPTIONS]"),
        ("set", "sovereign-config set <ABSOLUTE_PATH> [OPTIONS]"),
        (
            "delete",
            "sovereign-config delete <ABSOLUTE_PATH> [OPTIONS]",
        ),
        ("list", "sovereign-config list <ABSOLUTE_PATH> [OPTIONS]"),
        (
            "alias",
            "sovereign-config alias <SOURCE_ABSOLUTE_PATH> <NEW_ABSOLUTE_PATH>",
        ),
    ] {
        let help = run_cli(home.path(), &[verb, "--help"]).await;
        assert_success(&help);
        assert!(
            String::from_utf8_lossy(&help.stdout).contains(expected),
            "{verb} --help does not teach `{expected}`"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_replaced_command_spellings_no_longer_parse() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    let connection = connection_url(&services, true, "team/service");
    assert_success(
        &run_cli_with_input(
            home.path(),
            &["profile", "add", "managed"],
            Some(&format!("{connection}\n")),
        )
        .await,
    );
    assert_success(
        &run_cli_with_input(home.path(), &["set", "/team/service/value"], Some("kept")).await,
    );

    for (arguments, expected) in [
        (
            vec!["put", "/team/service/value"],
            "unrecognized subcommand",
        ),
        (
            vec!["secret", "put", "/team/service/value"],
            "unrecognized subcommand",
        ),
        (
            vec!["secret", "reveal", "/team/service/value"],
            "unrecognized subcommand",
        ),
        (
            vec!["alias", "add", "/team/service/value", "/team/service/other"],
            "unexpected argument",
        ),
        (
            vec!["delete", "/team/service/value", "--recurse", "--yes"],
            "unexpected argument \'--recurse\'",
        ),
        (
            vec!["get", "/team/service/value", "--format", "text"],
            "invalid value \'text\'",
        ),
        (
            vec!["set", "/team/service/value", "--format", "json"],
            "unexpected argument \'--format\'",
        ),
        // `alias` now takes two paths, so the old noun is read as one — and
        // rejected as a path rather than silently listing anything.
        (
            vec!["alias", "list", "/team/service/value"],
            "path must name a configuration value",
        ),
    ] {
        let output = run_cli(home.path(), &arguments).await;
        assert!(
            !output.status.success(),
            "{arguments:?} should no longer be accepted"
        );
        assert!(
            combined(&output).contains(expected),
            "{arguments:?} did not report `{expected}`: {}",
            combined(&output)
        );
    }

    // Nothing above reached the service, so the value is untouched.
    let kept = run_cli(home.path(), &["get", "/team/service/value"]).await;
    assert_success(&kept);
    assert_eq!(kept.stdout, b"kept");
}

#[tokio::test(flavor = "multi_thread")]
async fn login_status_logout_flow_is_authenticated_private_and_secret_safe() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    add_profile(home.path(), &services, "dev", false).await;

    let login = run_cli(home.path(), &["login"]).await;
    assert_success(&login);
    let login_output = combined(&login);
    assert!(login_output.contains("Code: TEST-CODE"));
    assert!(login_output.contains("Logged in"));
    assert_secrets_absent(&login_output);

    let [credential] = credential_files(home.path()).try_into().unwrap();
    assert_eq!(fs::read_to_string(&credential).unwrap(), REFRESH_SECRET);
    assert_eq!(
        fs::metadata(&credential).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let status = run_cli(home.path(), &["status"]).await;
    assert_success(&status);
    let status_output = combined(&status);
    assert!(status_output.contains("Service 1.5.0-test (protocol v3)"));
    assert!(status_output.contains("Authentication: logged in"));
    assert_secrets_absent(&status_output);
    assert_eq!(
        fs::read_to_string(&credential).unwrap(),
        ROTATED_REFRESH_SECRET
    );

    let logout = run_cli(home.path(), &["logout"]).await;
    assert_success(&logout);
    assert_eq!(String::from_utf8_lossy(&logout.stdout).trim(), "Logged out");
    assert!(!credential.exists());

    let logged_out = run_cli(home.path(), &["status"]).await;
    assert_success(&logged_out);
    assert!(combined(&logged_out).contains("Authentication: logged out"));
}

#[tokio::test(flavor = "multi_thread")]
async fn profiles_support_defaults_updates_and_global_overrides_without_revealing_secrets() {
    let development = start_services(DeviceResult::Success).await;
    let production = start_services(DeviceResult::Success).await;
    let replacement = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();

    add_profile(home.path(), &development, "dev", false).await;
    let managed_add = add_profile(home.path(), &production, "pipeline", true).await;
    assert_secrets_absent(&combined(&managed_add));

    let config = home.path().join("sovereign-config/config.toml");
    assert_eq!(
        fs::metadata(&config).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(config.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert!(
        fs::read_to_string(&config)
            .unwrap()
            .contains(&general_purpose::URL_SAFE_NO_PAD.encode(MANAGED_CREDENTIAL))
    );

    let default_status = run_cli(home.path(), &["status"]).await;
    assert_success(&default_status);
    assert!(combined(&default_status).contains("Authentication: logged out"));

    let override_status = run_cli(home.path(), &["--profile", "pipeline", "status"]).await;
    assert_success(&override_status);
    assert!(combined(&override_status).contains("Authentication: logged in"));
    assert_eq!(
        production.oidc_state.managed_count.load(Ordering::SeqCst),
        1
    );
    assert!(credential_files(home.path()).is_empty());

    let set_default = run_cli(home.path(), &["profile", "default", "pipeline"]).await;
    assert_success(&set_default);
    let unchanged =
        run_cli_with_input(home.path(), &["profile", "update", "pipeline"], Some("\n")).await;
    assert_success(&unchanged);
    assert!(combined(&unchanged).contains("Profile unchanged"));

    let replacement_url = connection_url(&replacement, true, "");
    let update = run_cli_with_input(
        home.path(),
        &["profile", "update", "pipeline"],
        Some(&format!("{replacement_url}\n")),
    )
    .await;
    assert_success(&update);
    assert_secrets_absent(&combined(&update));
    let replaced_status = run_cli(home.path(), &["status"]).await;
    assert_success(&replaced_status);
    assert_eq!(
        replacement.oidc_state.managed_count.load(Ordering::SeqCst),
        1
    );

    // `list` left this set when it was implemented; `show` and `remove` are
    // still not part of the profile surface.
    for unsupported in ["show", "remove"] {
        let output = run_cli(home.path(), &["profile", unsupported]).await;
        assert!(!output.status.success());
        assert_secrets_absent(&combined(&output));
    }
    let irrelevant_override = run_cli(
        home.path(),
        &["--profile", "dev", "profile", "default", "dev"],
    )
    .await;
    assert!(!irrelevant_override.status.success());
    assert!(
        combined(&irrelevant_override).contains("--profile applies only to operational commands")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn profile_input_is_one_bounded_redacted_line() {
    let home = TempDir::new().unwrap();
    for input in [
        "not-a-url\nsecond-line\n".to_owned(),
        format!("{}\n", "a".repeat(16 * 1024 + 1)),
        format!("https://example.test/#client_secret={MANAGED_CREDENTIAL}\n"),
    ] {
        let output =
            run_cli_with_input(home.path(), &["profile", "add", "invalid"], Some(&input)).await;
        assert!(!output.status.success());
        let output = combined(&output);
        assert!(output.contains("connection URL is invalid"));
        assert_secrets_absent(&output);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn home_fallback_uses_standard_config_and_state_directories() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    let url = connection_url(&services, false, "");
    let add = run_cli_environment(
        home.path(),
        &["profile", "add", "dev"],
        Some(&format!("{url}\n")),
        false,
        &[],
    )
    .await;
    assert_success(&add);
    assert!(
        home.path()
            .join(".config/sovereign-config/config.toml")
            .is_file()
    );

    let login = run_cli_environment(home.path(), &["login"], None, false, &[]).await;
    assert_success(&login);
    assert_eq!(
        fs::read_dir(
            home.path()
                .join(".local/state/sovereign-config/credentials")
        )
        .unwrap()
        .count(),
        1
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn human_credentials_are_isolated_by_endpoint_and_selected_profile() {
    let development = start_services(DeviceResult::Success).await;
    let production = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    add_profile(home.path(), &development, "dev", false).await;
    add_profile(home.path(), &production, "prod", false).await;

    assert_success(&run_cli(home.path(), &["login"]).await);
    assert_eq!(credential_files(home.path()).len(), 1);

    let production_status = run_cli(home.path(), &["--profile", "prod", "status"]).await;
    assert_success(&production_status);
    assert!(combined(&production_status).contains("Authentication: logged out"));
    assert_eq!(
        production.oidc_state.refresh_count.load(Ordering::SeqCst),
        0
    );

    assert_success(&run_cli(home.path(), &["--profile", "prod", "login"]).await);
    assert_eq!(credential_files(home.path()).len(), 2);
    assert_success(&run_cli(home.path(), &["--profile", "prod", "logout"]).await);
    assert_eq!(credential_files(home.path()).len(), 1);

    let development_status = run_cli(home.path(), &["status"]).await;
    assert_success(&development_status);
    assert!(combined(&development_status).contains("Authentication: logged in"));
}

#[tokio::test(flavor = "multi_thread")]
async fn profile_updates_preserve_shared_human_state_and_remove_the_last_reference() {
    let development = start_services(DeviceResult::Success).await;
    let replacement = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    add_profile(home.path(), &development, "dev", false).await;
    let alias_url = connection_url(&development, false, "apps/example");
    assert_success(
        &run_cli_with_input(
            home.path(),
            &["profile", "add", "alias"],
            Some(&format!("{alias_url}\n")),
        )
        .await,
    );
    assert_success(&run_cli(home.path(), &["login"]).await);
    assert_eq!(credential_files(home.path()).len(), 1);

    let replacement_url = connection_url(&replacement, false, "");
    let update = run_cli_with_input(
        home.path(),
        &["profile", "update", "dev"],
        Some(&format!("{replacement_url}\n")),
    )
    .await;
    assert_success(&update);
    assert_eq!(credential_files(home.path()).len(), 1);
    assert_success(&run_cli(home.path(), &["--profile", "alias", "status"]).await);

    let final_update = run_cli_with_input(
        home.path(),
        &["profile", "update", "alias"],
        Some(&format!("{replacement_url}\n")),
    )
    .await;
    assert_success(&final_update);
    assert!(credential_files(home.path()).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn changing_a_human_profile_to_managed_removes_its_refresh_credential() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    add_profile(home.path(), &services, "connection", false).await;
    assert_success(&run_cli(home.path(), &["login"]).await);
    assert_eq!(credential_files(home.path()).len(), 1);

    let managed_url = connection_url(&services, true, "");
    let update = run_cli_with_input(
        home.path(),
        &["profile", "update", "connection"],
        Some(&format!("{managed_url}\n")),
    )
    .await;
    assert_success(&update);
    assert!(credential_files(home.path()).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn definitive_refresh_rejection_deletes_the_human_credential() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    add_profile(home.path(), &services, "dev", false).await;
    assert_success(&run_cli(home.path(), &["login"]).await);
    services
        .oidc_state
        .reject_refresh
        .store(true, Ordering::SeqCst);

    let status = run_cli(home.path(), &["status"]).await;
    assert!(!status.status.success());
    assert!(combined(&status).contains("login has expired"));
    assert!(credential_files(home.path()).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn temporary_provider_failure_retains_the_human_credential() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    add_profile(home.path(), &services, "dev", false).await;
    assert_success(&run_cli(home.path(), &["login"]).await);
    services
        .oidc_state
        .unavailable
        .store(true, Ordering::SeqCst);

    let status = run_cli(home.path(), &["status"]).await;
    assert!(!status.status.success());
    assert!(combined(&status).contains("authentication service is unavailable"));
    assert_eq!(credential_files(home.path()).len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn managed_authentication_rejection_is_bounded_and_never_creates_token_state() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    add_profile(home.path(), &services, "pipeline", true).await;
    services
        .oidc_state
        .reject_managed
        .store(true, Ordering::SeqCst);
    services
        .oidc_state
        .omit_device_endpoint
        .store(true, Ordering::SeqCst);

    let status = run_cli(home.path(), &["status"]).await;
    assert!(!status.status.success());
    let output = combined(&status);
    assert!(output.contains("managed authentication failed"));
    assert_secrets_absent(&output);
    assert!(credential_files(home.path()).is_empty());
    for command in ["login", "logout"] {
        let output = run_cli(home.path(), &[command]).await;
        assert!(!output.status.success());
        assert!(combined(&output).contains("profile uses managed authentication"));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn core_managed_connection_urls_round_trip_the_stdin_profile_flow() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    let url = core_managed_url(&services, "/team/service", "app-password-sentinel");

    let add = run_cli_with_input(
        home.path(),
        &["profile", "add", "pipeline"],
        Some(&format!("{url}\n")),
    )
    .await;
    assert_success(&add);
    let put = run_cli_with_input(
        home.path(),
        &["set", "/team/service/flag"],
        Some("managed-flow-value"),
    )
    .await;
    assert_success(&put);
    let get = run_cli(home.path(), &["get", "/team/service/flag"]).await;
    assert_success(&get);
    assert_eq!(String::from_utf8_lossy(&get.stdout), "managed-flow-value");

    assert!(credential_files(home.path()).is_empty());
    for output in [&add, &put, &get] {
        let output = combined(output);
        assert_secrets_absent(&output);
        assert!(
            !output.contains(&url),
            "connection URL appeared in command output"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn rotated_managed_credentials_require_a_profile_update_with_the_new_url() {
    let services = start_services(DeviceResult::Success).await;
    "pipeline:rotation-new-password-sentinel"
        .clone_into(&mut services.oidc_state.managed_credential.lock().unwrap());
    let home = TempDir::new().unwrap();
    let superseded_url =
        core_managed_url(&services, "/team/service", "rotation-old-password-sentinel");
    assert_success(
        &run_cli_with_input(
            home.path(),
            &["profile", "add", "pipeline"],
            Some(&format!("{superseded_url}\n")),
        )
        .await,
    );

    let rejected = run_cli(home.path(), &["get", "/team/service/flag"]).await;
    assert!(!rejected.status.success());
    let rejected_output = combined(&rejected);
    assert!(rejected_output.contains("managed authentication failed"));
    for sentinel in [
        "rotation-old-password-sentinel",
        "rotation-new-password-sentinel",
    ] {
        assert!(
            !rejected_output.contains(sentinel),
            "credential appeared in command output"
        );
    }

    let config = home.path().join("sovereign-config/config.toml");
    assert_eq!(
        fs::metadata(&config).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(config.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );

    let rotated_url =
        core_managed_url(&services, "/team/service", "rotation-new-password-sentinel");
    let update = run_cli_with_input(
        home.path(),
        &["profile", "update", "pipeline"],
        Some(&format!("{rotated_url}\n")),
    )
    .await;
    assert_success(&update);

    assert_success(
        &run_cli_with_input(
            home.path(),
            &["set", "/team/service/flag"],
            Some("rotated-flow-value"),
        )
        .await,
    );
    let get = run_cli(home.path(), &["get", "/team/service/flag"]).await;
    assert_success(&get);
    assert_eq!(String::from_utf8_lossy(&get.stdout), "rotated-flow-value");
    assert!(credential_files(home.path()).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn revoked_managed_credentials_fail_authentication_once_without_retrying() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    add_profile(home.path(), &services, "pipeline", true).await;
    services
        .oidc_state
        .reject_managed
        .store(true, Ordering::SeqCst);

    let revoked = run_cli(home.path(), &["get", "/team/service/flag"]).await;
    assert!(!revoked.status.success());
    let output = combined(&revoked);
    assert!(output.contains("managed authentication failed"));
    assert_secrets_absent(&output);
    assert_eq!(services.oidc_state.managed_count.load(Ordering::SeqCst), 1);
    assert!(credential_files(home.path()).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn denied_device_login_fails_without_exposing_credentials() {
    assert_login_failure(DeviceResult::Denied, "device login denied").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_device_login_polls_until_authorized() {
    assert_eventual_login(DeviceResult::PendingThenSuccess).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn slow_down_device_login_honors_the_provider_response() {
    assert_eventual_login(DeviceResult::SlowDownThenSuccess).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn expired_device_login_returns_a_bounded_error() {
    assert_login_failure(DeviceResult::Expired, "device login expired").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn rejected_device_authorization_returns_a_bounded_error() {
    assert_login_failure(
        DeviceResult::Rejected,
        "authentication service is unavailable",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unavailable_identity_provider_returns_a_bounded_error() {
    assert_login_failure(
        DeviceResult::Unavailable,
        "authentication service is unavailable",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn credentialed_discovery_endpoint_is_rejected_without_disclosure() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    add_profile(home.path(), &services, "dev", false).await;
    services
        .oidc_state
        .unsafe_token_endpoint
        .store(true, Ordering::SeqCst);

    let output = run_cli(home.path(), &["login"]).await;
    assert!(!output.status.success());
    let output = combined(&output);
    assert!(output.contains("OIDC configuration is invalid"));
    assert!(!output.contains("discovery-user"));
    assert!(!output.contains("discovery-password"));
}

#[tokio::test(flavor = "multi_thread")]
async fn unavailable_service_returns_a_bounded_error_without_retrying() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    let unavailable = TestServices {
        issuer: services.issuer.clone(),
        endpoint: "http://127.0.0.1:1".to_owned(),
        oidc_state: services.oidc_state.clone(),
        oidc_task: tokio::spawn(async {}),
        grpc_task: tokio::spawn(async { Ok(()) }),
    };
    add_profile(home.path(), &unavailable, "dev", false).await;

    let output = run_cli(home.path(), &["status"]).await;
    assert!(!output.status.success());
    assert!(combined(&output).contains("service is unavailable"));
    assert_secrets_absent(&combined(&output));
}

#[test]
fn version_does_not_require_profile_configuration() {
    let output = Command::new(env!("CARGO_BIN_EXE_sovereign-config"))
        .arg("--version")
        .env_clear()
        .output()
        .unwrap();
    assert_success(&output);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        format!("sovereign-config {}", env!("CARGO_PKG_VERSION"))
    );
}

async fn start_services(device_result: DeviceResult) -> TestServices {
    let oidc_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let oidc_address = oidc_listener.local_addr().unwrap();
    let issuer = format!("http://{oidc_address}/");
    let oidc_state = Arc::new(OidcState {
        issuer: issuer.clone(),
        device_result,
        poll_count: AtomicUsize::new(0),
        refresh_count: AtomicUsize::new(0),
        managed_count: AtomicUsize::new(0),
        managed_credential: Mutex::new(MANAGED_CREDENTIAL.to_owned()),
        reject_refresh: AtomicBool::new(false),
        reject_managed: AtomicBool::new(false),
        unavailable: AtomicBool::new(false),
        omit_device_endpoint: AtomicBool::new(false),
        unsafe_token_endpoint: AtomicBool::new(false),
    });
    let oidc = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/device", post(device_authorization))
        .route("/token", post(token))
        .with_state(oidc_state.clone());
    let oidc_task = tokio::spawn(async move {
        axum::serve(oidc_listener, oidc).await.unwrap();
    });

    let grpc_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let grpc_address = grpc_listener.local_addr().unwrap();
    let grpc_task = tokio::spawn(
        Server::builder()
            .add_service(SystemServer::new(MockSystem))
            .add_service(ConfigurationServer::new(MockConfiguration::default()))
            .serve_with_incoming(TcpListenerStream::new(grpc_listener)),
    );

    TestServices {
        issuer,
        endpoint: format!("http://{grpc_address}"),
        oidc_state,
        oidc_task,
        grpc_task,
    }
}

async fn discovery(State(state): State<Arc<OidcState>>) -> Response {
    if matches!(state.device_result, DeviceResult::Unavailable)
        || state.unavailable.load(Ordering::SeqCst)
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let token_endpoint = if state.unsafe_token_endpoint.load(Ordering::SeqCst) {
        format!(
            "{}token",
            state
                .issuer
                .replacen("http://", "http://discovery-user:discovery-password@", 1)
        )
    } else {
        format!("{}token", state.issuer)
    };
    let mut document = json!({"token_endpoint": token_endpoint});
    if !state.omit_device_endpoint.load(Ordering::SeqCst) {
        document["device_authorization_endpoint"] = json!(format!("{}device", state.issuer));
    }
    Json(document).into_response()
}

async fn device_authorization(
    State(state): State<Arc<OidcState>>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if form.get("client_id").map(String::as_str) != Some("sovereign-config")
        || form.get("scope").map(String::as_str) != Some("openid sovereign-config offline_access")
    {
        return oauth_error("invalid_request");
    }
    if matches!(state.device_result, DeviceResult::Rejected) {
        return oauth_error("invalid_request");
    }
    Json(json!({
        "device_code": DEVICE_SECRET,
        "user_code": "TEST-CODE",
        "verification_uri": "https://auth.example.test/device",
        "verification_uri_complete": "https://auth.example.test/device?code=TEST-CODE",
        "expires_in": 30,
        "interval": 1,
    }))
    .into_response()
}

async fn token(
    State(state): State<Arc<OidcState>>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    match form.get("grant_type").map(String::as_str) {
        Some("urn:ietf:params:oauth:grant-type:device_code") => {
            if form.get("device_code").map(String::as_str) != Some(DEVICE_SECRET) {
                return oauth_error("invalid_grant");
            }
            match state.device_result {
                DeviceResult::Success => token_response(true),
                DeviceResult::PendingThenSuccess
                    if state.poll_count.fetch_add(1, Ordering::SeqCst) == 0 =>
                {
                    oauth_error("authorization_pending")
                }
                DeviceResult::SlowDownThenSuccess
                    if state.poll_count.fetch_add(1, Ordering::SeqCst) == 0 =>
                {
                    oauth_error("slow_down")
                }
                DeviceResult::PendingThenSuccess | DeviceResult::SlowDownThenSuccess => {
                    token_response(true)
                }
                DeviceResult::Denied => oauth_error("access_denied"),
                DeviceResult::Expired => oauth_error("expired_token"),
                DeviceResult::Rejected | DeviceResult::Unavailable => unreachable!(),
            }
        }
        Some("refresh_token") => {
            state.refresh_count.fetch_add(1, Ordering::SeqCst);
            if state.reject_refresh.load(Ordering::SeqCst)
                || form.get("refresh_token").map(String::as_str) != Some(REFRESH_SECRET)
            {
                return oauth_error("invalid_grant");
            }
            Json(json!({
                "access_token": ACCESS_SECRET,
                "refresh_token": ROTATED_REFRESH_SECRET,
            }))
            .into_response()
        }
        Some("client_credentials") => {
            state.managed_count.fetch_add(1, Ordering::SeqCst);
            let expected =
                general_purpose::STANDARD.encode(&*state.managed_credential.lock().unwrap());
            let valid = form.get("client_secret").map(String::as_str) == Some(expected.as_str())
                && form.get("client_id").map(String::as_str) == Some("sovereign-config")
                && form.get("scope").map(String::as_str) == Some("sovereign-config");
            if !valid || state.reject_managed.load(Ordering::SeqCst) {
                return oauth_error("invalid_client");
            }
            token_response(false)
        }
        _ => oauth_error("unsupported_grant_type"),
    }
}

fn token_response(refresh: bool) -> Response {
    if refresh {
        Json(json!({
            "access_token": ACCESS_SECRET,
            "refresh_token": REFRESH_SECRET,
        }))
        .into_response()
    } else {
        Json(json!({"access_token": ACCESS_SECRET})).into_response()
    }
}

fn oauth_error(error: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({"error": error}))).into_response()
}

async fn assert_eventual_login(result: DeviceResult) {
    let services = start_services(result).await;
    let home = TempDir::new().unwrap();
    add_profile(home.path(), &services, "dev", false).await;
    let output = run_cli(home.path(), &["login"]).await;
    assert_success(&output);
    assert!(combined(&output).contains("Logged in"));
    assert_secrets_absent(&combined(&output));
    let [credential] = credential_files(home.path()).try_into().unwrap();
    assert_eq!(fs::read_to_string(credential).unwrap(), REFRESH_SECRET);
}

async fn assert_login_failure(result: DeviceResult, expected: &str) {
    let services = start_services(result).await;
    let home = TempDir::new().unwrap();
    add_profile(home.path(), &services, "dev", false).await;
    let output = run_cli(home.path(), &["login"]).await;
    assert!(!output.status.success());
    let output = combined(&output);
    assert!(
        output.contains(expected),
        "unexpected command output: {output}"
    );
    assert_secrets_absent(&output);
    assert!(credential_files(home.path()).is_empty());
}

// `render` reads configuration and then replaces itself with the command it
// was given. Because the process is gone by then, every assertion about what
// it produced has to be made from inside that command — which is what
// `test-consumers/render-consumer` is for: it reports its own environment as
// JSON and exits with a status the test chooses.

#[tokio::test(flavor = "multi_thread")]
async fn render_hands_a_layer_to_the_command_it_execs() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    render_profile(home.path(), &services).await;
    store_plain(home.path(), "/team/service/HOST", "api.example.test").await;
    store_secret(home.path(), "/team/service/DB_PASSWORD", "db-sentinel").await;
    // Stored lowercase, so it arrives lowercase. Nothing is uppercased: the
    // variable name is the leaf, and `export lower_case=...` is what a shell
    // would have done with the same spelling.
    store_plain(home.path(), "/team/service/lower_case", "as-written").await;
    // A deeper descendant is not a direct child, so it has no variable.
    store_plain(
        home.path(),
        "/team/service/nested/IGNORED",
        "not-a-variable",
    )
    .await;

    let environment = rendered(
        home.path(),
        &["--profile", "deploy", "render", "/team/service"],
        &[],
    )
    .await;

    assert_eq!(environment["HOST"], "api.example.test");
    assert_eq!(environment["DB_PASSWORD"], "db-sentinel");
    assert_eq!(environment["lower_case"], "as-written");
    assert!(
        !environment.contains_key("LOWER_CASE"),
        "a lowercase leaf was uppercased"
    );
    assert!(
        !environment.contains_key("IGNORED"),
        "a deeper descendant became a variable"
    );
}

// The rule in one line: `/foo/AbC=bAr` rendered is `export AbC=bAr`. Paths
// have been case-retentive since 2.18.0, so the spelling written is the
// spelling stored and the spelling the command sees. Uppercasing would make
// `AbC` unreachable — no path would produce it.
#[tokio::test(flavor = "multi_thread")]
async fn a_leaf_reaches_the_command_under_its_exact_stored_spelling() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    render_profile(home.path(), &services).await;
    store_plain(home.path(), "/team/service/AbC", "bAr").await;

    let environment = rendered(
        home.path(),
        &["--profile", "deploy", "render", "/team/service"],
        &[],
    )
    .await;

    assert_eq!(environment["AbC"], "bAr");
    for other in ["ABC", "abc", "Abc"] {
        assert!(
            !environment.contains_key(other),
            "the name was transformed into {other}"
        );
    }
}

// Two layers spelling a leaf differently are two variables, not one — which is
// what the command sees too, since `AbC` and `abc` are distinct to it. Only an
// exact-name collision overrides.
#[tokio::test(flavor = "multi_thread")]
async fn layers_collide_only_on_the_exact_name() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    render_profile(home.path(), &services).await;
    store_plain(home.path(), "/team/service/AbC", "shared-mixed").await;
    store_plain(home.path(), "/team/service/token", "shared-token").await;
    store_plain(home.path(), "/team/service/prod/abc", "prod-lower").await;
    store_plain(home.path(), "/team/service/prod/token", "prod-token").await;

    let environment = rendered(
        home.path(),
        &[
            "--profile",
            "deploy",
            "render",
            "/team/service",
            "/team/service/prod",
        ],
        &[],
    )
    .await;

    assert_eq!(environment["AbC"], "shared-mixed");
    assert_eq!(environment["abc"], "prod-lower");
    assert_eq!(environment["token"], "prod-token");
}

// The connection root is the whole point of a per-consumer credential: a
// deploy step should not have to repeat a prefix the credential already
// encodes.
#[tokio::test(flavor = "multi_thread")]
async fn render_with_no_path_reads_the_connection_root() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    render_profile(home.path(), &services).await;
    store_plain(home.path(), "/team/service/HOST", "root-relative").await;

    let environment = rendered(home.path(), &["--profile", "deploy", "render"], &[]).await;
    assert_eq!(environment["HOST"], "root-relative");
}

// A deploy step routinely supplies one variable inline — an image tag, say —
// alongside everything it reads from configuration, so the inherited
// environment has to survive. Configuration wins a collision, being the more
// specific statement of intent.
#[tokio::test(flavor = "multi_thread")]
async fn the_inherited_environment_survives_and_configuration_wins_a_collision() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    render_profile(home.path(), &services).await;
    store_plain(home.path(), "/team/service/HOST", "from-configuration").await;

    let environment = rendered(
        home.path(),
        &["--profile", "deploy", "render", "/team/service"],
        &[("DEPLOY_IMAGE_TAG", "v1.2.3"), ("HOST", "from-the-caller")],
    )
    .await;

    assert_eq!(environment["DEPLOY_IMAGE_TAG"], "v1.2.3");
    assert!(environment.contains_key("HOME"), "HOME did not survive");
    assert_eq!(environment["HOST"], "from-configuration");
}

// The credential read the configuration; the command that consumes it has no
// business holding it. Stripped whether or not this invocation used it.
#[tokio::test(flavor = "multi_thread")]
async fn the_credential_never_reaches_the_executed_command() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    let url = render_profile(home.path(), &services).await;
    store_plain(home.path(), "/team/service/HOST", "api.example.test").await;

    for arguments in [
        vec!["--profile", "deploy", "render", "/team/service"],
        vec!["render", "/team/service"],
    ] {
        let environment =
            rendered(home.path(), &arguments, &[("SOVEREIGN_CONFIG_URL", &url)]).await;
        assert_eq!(environment["HOST"], "api.example.test");
        assert!(
            !environment.contains_key("SOVEREIGN_CONFIG_URL"),
            "the credential reached the command"
        );
        for value in environment.values() {
            assert!(
                !value.contains(MANAGED_CREDENTIAL),
                "the credential reached the command inside another variable"
            );
        }
    }
}

// There is no shell between `render` and the command, so a value that looks
// like shell syntax is data. This is the property that makes it safe to point
// at a production deploy.
#[tokio::test(flavor = "multi_thread")]
async fn values_reach_the_command_byte_exact_and_are_never_interpreted() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    render_profile(home.path(), &services).await;
    let hostile = [
        ("Spaces", "one two  three"),
        ("single_QUOTES", "it's 'quoted'"),
        ("double_quotes", "say \"hello\""),
        ("substitution", "$(rm -rf /) ${HOME} $HOME"),
        ("backticks", "`id`"),
        ("newlines", "first\nsecond\n\nfourth"),
        ("everything", "$(`id`) 'a' \"b\"\n\\$c"),
    ];
    for (leaf, value) in hostile {
        store_secret(home.path(), &format!("/team/service/{leaf}"), value).await;
    }

    let environment = rendered(
        home.path(),
        &["--profile", "deploy", "render", "/team/service"],
        &[],
    )
    .await;

    for (leaf, value) in hostile {
        // Indexed by the leaf itself: the name is the path segment exactly, so
        // a mixed-case leaf is a mixed-case variable.
        assert_eq!(environment[leaf], value, "{leaf} did not arrive byte-exact");
    }
}

// Layers merge in the order given, later winning — and reversing the order
// reverses the winner, so nothing is inferring specificity from path depth.
#[tokio::test(flavor = "multi_thread")]
async fn layers_merge_in_the_order_given_with_the_later_one_winning() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    render_profile(home.path(), &services).await;
    store_plain(home.path(), "/team/service/HOST", "shared-host").await;
    store_plain(home.path(), "/team/service/SHARED_ONLY", "kept").await;
    store_plain(home.path(), "/team/service/prod/HOST", "prod-host").await;

    let overlaid = rendered(
        home.path(),
        &[
            "--profile",
            "deploy",
            "render",
            "/team/service",
            "/team/service/prod",
        ],
        &[],
    )
    .await;
    assert_eq!(overlaid["HOST"], "prod-host");
    assert_eq!(overlaid["SHARED_ONLY"], "kept");

    let reversed = rendered(
        home.path(),
        &[
            "--profile",
            "deploy",
            "render",
            "/team/service/prod",
            "/team/service",
        ],
        &[],
    )
    .await;
    assert_eq!(reversed["HOST"], "shared-host");
}

// The process is replaced rather than wrapped, so the status passes through
// with nothing in between to swallow or mistranslate it.
#[tokio::test(flavor = "multi_thread")]
async fn the_executed_commands_exit_status_is_renders_own() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    render_profile(home.path(), &services).await;
    store_plain(home.path(), "/team/service/HOST", "api.example.test").await;

    for status in [0, 1, 42] {
        let output = run_cli_with_environment(
            home.path(),
            &[
                "--profile",
                "deploy",
                "render",
                "/team/service",
                "--",
                render_consumer().to_str().unwrap(),
                "--exit",
                &status.to_string(),
            ],
            &[],
        )
        .await;
        assert_eq!(
            output.status.code(),
            Some(status),
            "status did not pass through"
        );
    }
}

// Fail closed. Every read happens before the exec, so nothing that goes wrong
// can leave a command running against a half-populated environment. The
// consumer always prints JSON, so its absence proves it never ran.
#[tokio::test(flavor = "multi_thread")]
async fn a_failure_before_the_exec_means_the_command_never_runs() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    render_profile(home.path(), &services).await;
    store_plain(home.path(), "/team/service/HOST", "api.example.test").await;
    let consumer = render_consumer();
    let consumer = consumer.to_str().unwrap();

    for (arguments, expected) in [
        // Outside the connection root: refused before any read.
        (
            vec![
                "--profile",
                "deploy",
                "render",
                "/other/team",
                "--",
                consumer,
            ],
            "path is outside the selected profile root",
        ),
        // A path the service reports as empty. Absent and empty are the same
        // response, so both land here rather than silently rendering nothing.
        (
            vec![
                "--profile",
                "deploy",
                "render",
                "/team/service/typo",
                "--",
                consumer,
            ],
            "contributed no configuration",
        ),
        // Not a path at all.
        (
            vec!["--profile", "deploy", "render", "relative", "--", consumer],
            "path must name a configuration subtree",
        ),
        // No credential resolves at all.
        (vec!["--profile", "absent", "render", "--", consumer], ""),
    ] {
        let output = run_cli_with_environment(home.path(), &arguments, &[]).await;
        let combined = combined(&output);
        assert!(
            !output.status.success(),
            "{arguments:?} succeeded: {combined}"
        );
        assert!(
            !combined.contains('{'),
            "{arguments:?} ran the command anyway: {combined}"
        );
        assert!(
            combined.contains(expected),
            "{arguments:?} reported {combined:?}, wanted {expected:?}"
        );
        assert_secrets_absent(&combined);
    }
}

// A leaf whose name cannot be an environment variable is refused rather than
// exported under a name nothing can reference — passing `DB-PASSWORD` through
// would satisfy `execve` and then fail silently at the point of use.
#[tokio::test(flavor = "multi_thread")]
async fn a_leaf_that_cannot_be_a_variable_name_fails_before_the_exec() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    render_profile(home.path(), &services).await;
    store_plain(home.path(), "/team/service/db-password", "sentinel").await;

    let output = run_cli_with_environment(
        home.path(),
        &[
            "--profile",
            "deploy",
            "render",
            "/team/service",
            "--",
            render_consumer().to_str().unwrap(),
        ],
        &[],
    )
    .await;
    let combined = combined(&output);
    assert!(
        !output.status.success(),
        "unusable name accepted: {combined}"
    );
    assert!(
        combined.contains("db-password"),
        "unhelpful error: {combined}"
    );
    assert!(
        !combined.contains('{'),
        "the command ran anyway: {combined}"
    );
}

// The documented order, each step proved by making the one below it fatal:
// `--profile` beats `--url-file` beats `SOVEREIGN_CONFIG_URL`.
#[tokio::test(flavor = "multi_thread")]
async fn the_credential_precedence_is_profile_then_url_file_then_the_environment() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    let url = render_profile(home.path(), &services).await;
    store_plain(home.path(), "/team/service/HOST", "api.example.test").await;

    let usable = home.path().join("usable.url");
    fs::write(&usable, format!("{url}\n")).unwrap();
    let unusable = home.path().join("unusable.url");
    fs::write(&unusable, "not-a-connection-url\n").unwrap();

    // A profile beats both of the others, even when they would fail.
    let by_profile = rendered(
        home.path(),
        &[
            "--profile",
            "deploy",
            "--url-file",
            unusable.to_str().unwrap(),
            "render",
            "/team/service",
        ],
        &[("SOVEREIGN_CONFIG_URL", "not-a-connection-url")],
    )
    .await;
    assert_eq!(by_profile["HOST"], "api.example.test");

    // With no profile named, the file beats the variable.
    let by_file = rendered(
        home.path(),
        &[
            "--url-file",
            usable.to_str().unwrap(),
            "render",
            "/team/service",
        ],
        &[("SOVEREIGN_CONFIG_URL", "not-a-connection-url")],
    )
    .await;
    assert_eq!(by_file["HOST"], "api.example.test");

    // And a broken file is not quietly passed over in favour of the variable.
    let file_wins_even_when_broken = run_cli_with_environment(
        home.path(),
        &[
            "--url-file",
            unusable.to_str().unwrap(),
            "render",
            "/team/service",
            "--",
            render_consumer().to_str().unwrap(),
        ],
        &[("SOVEREIGN_CONFIG_URL", &url)],
    )
    .await;
    assert!(!file_wins_even_when_broken.status.success());

    // With neither, the variable is what is left.
    let by_variable = rendered(
        home.path(),
        &["render", "/team/service"],
        &[("SOVEREIGN_CONFIG_URL", &url)],
    )
    .await;
    assert_eq!(by_variable["HOST"], "api.example.test");
}

// A CI container has no profile store and no state directory to build one in,
// which must not stop an invocation that never needed either.
#[tokio::test(flavor = "multi_thread")]
async fn a_host_with_no_profile_store_can_still_render() {
    let services = start_services(DeviceResult::Success).await;
    let home = TempDir::new().unwrap();
    let url = render_profile(home.path(), &services).await;
    store_plain(home.path(), "/team/service/HOST", "api.example.test").await;

    // A different HOME entirely: no config.toml, no credentials, nothing.
    let bare = TempDir::new().unwrap();
    let environment = rendered(
        bare.path(),
        &["render", "/team/service"],
        &[("SOVEREIGN_CONFIG_URL", &url)],
    )
    .await;
    assert_eq!(environment["HOST"], "api.example.test");
}

#[tokio::test(flavor = "multi_thread")]
async fn render_teaches_the_paths_before_the_options_and_the_command_last() {
    let home = TempDir::new().unwrap();
    let help = run_cli(home.path(), &["render", "--help"]).await;
    assert_success(&help);
    assert!(
        String::from_utf8_lossy(&help.stdout)
            .contains("sovereign-config render [<ABSOLUTE_PATH>...] [OPTIONS] -- <cmd> [args...]"),
        "render --help does not teach the path-after-verb spelling"
    );
}

// `--url-file` is a global credential input, so it belongs to operational
// commands only, exactly as `--profile` does.
#[tokio::test(flavor = "multi_thread")]
async fn url_file_is_refused_on_the_profile_commands() {
    let home = TempDir::new().unwrap();
    let refused = run_cli(
        home.path(),
        &["--url-file", "/nonexistent", "profile", "list"],
    )
    .await;
    assert!(!refused.status.success());
    assert!(combined(&refused).contains("--url-file applies only to operational commands"));
}

/// The binary `render` execs in these tests, from `test-consumers/`.
///
/// `CARGO_BIN_EXE_` only names binaries of the package under test, so this
/// resolves the sibling by path: cargo uplifts every package's binary into the
/// same `target/<profile>/` directory this one came from.
///
/// It is only built when something asks cargo for it, which is why
/// `test-consumers/render-consumer/tests/smoke.rs` exists — `cargo test` on a
/// package with no integration tests compiles its bin as a unit-test harness
/// and never produces the real binary.
fn render_consumer() -> PathBuf {
    let binary = Path::new(env!("CARGO_BIN_EXE_sovereign-config"))
        .parent()
        .expect("a test binary always has a directory")
        .join("render-consumer");
    assert!(
        binary.is_file(),
        "{} is missing. These tests exec it, and it is built by \
         `cargo test --workspace` (or `cargo build -p \
         sovereign-config-render-consumer`) — not by `cargo test -p \
         sovereign-config-cli` alone.",
        binary.display()
    );
    binary
}

/// Adds the managed profile these tests render through, returning its URL so a
/// test can also supply it as a file or a variable.
async fn render_profile(home: &Path, services: &TestServices) -> String {
    let url = connection_url(services, true, "team/service");
    assert_success(
        &run_cli_with_input(
            home,
            &["profile", "add", "deploy"],
            Some(&format!("{url}\n")),
        )
        .await,
    );
    url
}

async fn store_plain(home: &Path, path: &str, value: &str) {
    assert_success(&run_cli_with_input(home, &["set", path], Some(value)).await);
}

async fn store_secret(home: &Path, path: &str, value: &str) {
    assert_success(&run_cli_with_input(home, &["set", path, "--secret"], Some(value)).await);
}

/// Runs `render`, execs the consumer, and returns the environment it was
/// handed. `arguments` carries everything up to the `--`.
async fn rendered(
    home: &Path,
    arguments: &[&str],
    environment: &[(&str, &str)],
) -> HashMap<String, String> {
    let consumer = render_consumer();
    let mut full = arguments.to_vec();
    full.push("--");
    full.push(consumer.to_str().unwrap());
    let output = run_cli_with_environment(home, &full, environment).await;
    assert_success(&output);
    serde_json::from_slice(&output.stdout).expect("the consumer prints its environment as JSON")
}

async fn add_profile(home: &Path, services: &TestServices, name: &str, managed: bool) -> Output {
    let url = connection_url(services, managed, "");
    let output =
        run_cli_with_input(home, &["profile", "add", name], Some(&format!("{url}\n"))).await;
    assert_success(&output);
    output
}

fn connection_url(services: &TestServices, managed: bool, root: &str) -> String {
    let mut fragment = form_urlencoded::Serializer::new(String::new());
    fragment
        .append_pair("v", "1")
        .append_pair("issuer", &services.issuer)
        .append_pair("client_id", "sovereign-config");
    if managed {
        fragment.append_pair(
            "client_secret",
            &general_purpose::URL_SAFE_NO_PAD.encode(MANAGED_CREDENTIAL),
        );
    }
    format!("{}/{root}#{}", services.endpoint, fragment.finish())
}

fn core_managed_url(services: &TestServices, root: &str, app_password: &str) -> String {
    ConnectionUrl::managed(
        &services.endpoint,
        &ConfigPath::parse(root).unwrap(),
        &services.issuer,
        "sovereign-config",
        "pipeline",
        &Secret::new(app_password),
    )
    .unwrap()
    .canonical()
    .expose()
    .to_owned()
}

fn credential_files(home: &Path) -> Vec<PathBuf> {
    let directory = home.join("sovereign-config/credentials");
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut paths = entries
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

async fn run_cli(home: &Path, arguments: &[&str]) -> Output {
    run_cli_with_input(home, arguments, None).await
}

async fn run_cli_with_input(home: &Path, arguments: &[&str], input: Option<&str>) -> Output {
    run_cli_environment(home, arguments, input, true, &[]).await
}

/// Runs the CLI with extra variables in its environment, which is otherwise
/// cleared. Used to supply `SOVEREIGN_CONFIG_URL` and to prove that a caller's
/// own variables survive into an exec'd command.
async fn run_cli_with_environment(
    home: &Path,
    arguments: &[&str],
    environment: &[(&str, &str)],
) -> Output {
    run_cli_environment(home, arguments, None, true, environment).await
}

async fn run_cli_environment(
    home: &Path,
    arguments: &[&str],
    input: Option<&str>,
    use_xdg: bool,
    environment: &[(&str, &str)],
) -> Output {
    let binary = env!("CARGO_BIN_EXE_sovereign-config");
    let home = home.to_owned();
    let arguments = arguments
        .iter()
        .map(|argument| (*argument).to_owned())
        .collect::<Vec<_>>();
    let input = input.map(str::to_owned);
    let environment = environment
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect::<Vec<_>>();
    tokio::task::spawn_blocking(move || {
        let mut command = Command::new(binary);
        command
            .args(arguments)
            .env_clear()
            .envs(environment)
            .env("HOME", &home)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if use_xdg {
            command
                .env("XDG_CONFIG_HOME", &home)
                .env("XDG_STATE_HOME", &home);
        }
        let mut child = command.spawn().unwrap();
        if let Some(input) = input {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
        }
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed: {}",
        combined(output)
    );
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_secrets_absent(output: &str) {
    for secret in [
        DEVICE_SECRET,
        ACCESS_SECRET,
        REFRESH_SECRET,
        ROTATED_REFRESH_SECRET,
        MANAGED_CREDENTIAL,
        "app-password-sentinel",
        &general_purpose::URL_SAFE_NO_PAD.encode(MANAGED_CREDENTIAL),
        &general_purpose::STANDARD.encode(MANAGED_CREDENTIAL),
    ] {
        assert!(
            !output.contains(secret),
            "secret appeared in command output"
        );
    }
}
