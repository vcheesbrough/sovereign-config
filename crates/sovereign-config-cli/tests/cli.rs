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
    DeleteValuesRequest, DeleteValuesResponse, GetIdentityRequest, GetIdentityResponse,
    GetSubTreeRequest, GetSubTreeResponse, GetVersionRequest, GetVersionResponse,
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
        let selected = request.into_inner().path;
        let values = self.values.lock().unwrap();
        let values = values
            .iter()
            .filter(|(path, _)| path.rsplit_once('/').map_or("", |(parent, _)| parent) == selected)
            .map(|(path, stored)| ListedValue {
                path: path.clone(),
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
            })
            .collect();
        Ok(tonic::Response::new(ListValuesResponse {
            values,
            paths: vec![selected],
        }))
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
            .map(|(path, stored)| SubTreeValue {
                path: path.clone(),
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
        subtree.sort_by(|first, second| first.path.cmp(&second.path));
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
        let created_at = values
            .get(&request.path.to_ascii_lowercase())
            .map_or(timestamp, |stored| stored.created_at);
        let (value, secret) = match request.content {
            Some(put_value_request::Content::PlainValue(value)) => (value, false),
            Some(put_value_request::Content::SecretValue(value)) => (value, true),
            None => return Err(Status::invalid_argument("missing value")),
        };
        values.insert(
            request.path.to_ascii_lowercase(),
            MockStoredValue {
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
        &["put", "/team/service"],
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
        &["put", "/team/service/Feature/Flag"],
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
    assert!(combined(&relative).contains("path must name a configuration subtree"));

    let outside_root = run_cli(home.path(), &["get", "/other/feature-flag"]).await;
    assert!(!outside_root.status.success());
    assert!(combined(&outside_root).contains("path is outside the selected profile root"));
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
        &["secret", "put", "/team/service/credential"],
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
    let masked_json = run_cli(home.path(), &["get", "/team/service", "--format", "json"]).await;
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
        &["secret", "reveal", "/team/service/credential"],
    )
    .await;
    assert_success(&revealed);
    assert_eq!(String::from_utf8_lossy(&revealed.stdout), first);
    assert!(revealed.stderr.is_empty());

    let second = "configuration-secret-sentinel-two";
    let rotated = run_cli_with_input(
        home.path(),
        &["secret", "put", "/team/service/credential"],
        Some(second),
    )
    .await;
    assert_success(&rotated);
    assert!(!combined(&rotated).contains(second));
    let sibling =
        run_cli_with_input(home.path(), &["put", "/team/service/enabled"], Some("true")).await;
    assert_success(&sibling);
    let masked_json = run_cli(home.path(), &["get", "/team/service", "--format", "json"]).await;
    assert_success(&masked_json);
    assert_eq!(
        String::from_utf8_lossy(&masked_json.stdout),
        "{\n  \"credential\": \"********\",\n  \"enabled\": \"true\"\n}\n"
    );
    assert!(!combined(&masked_json).contains(second));
    let json = run_cli_with_input(
        home.path(),
        &["put", "/team/service", "--format", "json"],
        Some("{\"credential\":\"********\",\"enabled\":\"false\"}"),
    )
    .await;
    assert_success(&json);
    assert!(!combined(&json).contains(second));
    let revealed_json = run_cli(
        home.path(),
        &["get", "/team/service", "--format", "json", "--reveal"],
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
        &["secret", "reveal", "/team/service/credential"],
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
        &["secret", "reveal", "/team/service/credential"],
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
        assert_success(&run_cli_with_input(home.path(), &["put", path], Some(value)).await);
    }

    let text_subtree = run_cli(home.path(), &["get", "/team/service/apps"]).await;
    assert!(!text_subtree.status.success());
    assert!(
        combined(&text_subtree).contains("JSON format is required to read a configuration subtree")
    );

    let json = run_cli(
        home.path(),
        &["get", "/TEAM/SERVICE/APPS", "--format", "json"],
    )
    .await;
    assert_success(&json);
    assert_eq!(
        String::from_utf8_lossy(&json.stdout),
        "{\n  \"enabled\": \"true\",\n  \"nested\": {\n    \"message\": \"hello\\nworld\"\n  }\n}\n"
    );

    let deep_json = run_cli(
        home.path(),
        &["get", "/team/service/foo/foo2/foo3", "--format", "json"],
    )
    .await;
    assert_success(&deep_json);
    assert_eq!(deep_json.stdout, b"{\n  \"deepvalue\": \"deepvalue\"\n}\n");

    let partial_segment = run_cli(
        home.path(),
        &["get", "/team/service/foo/s", "--format", "json"],
    )
    .await;
    assert_success(&partial_segment);
    assert_eq!(partial_segment.stdout, b"{}\n");
    assert_success(
        &run_cli_with_input(home.path(), &["put", "/team/service/foo/s"], Some("short")).await,
    );
    assert_success(&run_cli(home.path(), &["delete", "/team/service/foo/s", "--yes"]).await);
    assert_success(
        &run_cli_with_input(
            home.path(),
            &["put", "/team/service/foo/s", "--format", "json"],
            Some("{\"child\":\"value\"}"),
        )
        .await,
    );
    assert_success(
        &run_cli(
            home.path(),
            &["delete", "/team/service/foo/s", "--recurse", "--yes"],
        )
        .await,
    );
    let completed_segment = run_cli(home.path(), &["get", "/team/service/foo/second/abc"]).await;
    assert_success(&completed_segment);
    assert_eq!(completed_segment.stdout, b"bar");

    let replacement = run_cli_with_input(
        home.path(),
        &["put", "/team/service/apps", "--format", "json"],
        Some("{\"enabled\":\"false\",\"new-value\":\"new\"}"),
    )
    .await;
    assert_success(&replacement);
    assert_eq!(replacement.stdout, b"Subtree replaced\n");
    let replaced = run_cli(
        home.path(),
        &["get", "/team/service/apps", "--format", "json"],
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
        &["put", "/team/service/apps/enabled", "--format", "json"],
        Some("\"exact-json\""),
    )
    .await;
    assert_success(&exact_replacement);
    let exact_text = run_cli(home.path(), &["get", "/team/service/apps/enabled"]).await;
    assert_success(&exact_text);
    assert_eq!(exact_text.stdout, b"exact-json");

    let invalid = run_cli_with_input(
        home.path(),
        &["put", "/team/service/apps", "--format", "json"],
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
            &["put", "/team/service/collision"],
            Some("parent"),
        )
        .await,
    );
    assert_success(
        &run_cli_with_input(
            home.path(),
            &["put", "/team/service/collision/child"],
            Some("child"),
        )
        .await,
    );
    let collision = run_cli(
        home.path(),
        &["get", "/team/service/collision", "--format", "json"],
    )
    .await;
    assert!(!collision.status.success());
    assert!(combined(&collision).contains("configuration subtree cannot be represented as JSON"));

    let deleted = run_cli(
        home.path(),
        &["delete", "/team/service/apps", "--recurse", "--yes"],
    )
    .await;
    assert_success(&deleted);
    assert_eq!(deleted.stdout, b"Subtree deleted\n");
    let empty = run_cli(
        home.path(),
        &["get", "/team/service/apps", "--format", "json"],
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
    let outside = run_cli(home.path(), &["get", "/", "--format", "json"]).await;
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
        &["--profile", "root", "put", "/", "--format", "json"],
        Some("{\"root-value\":\"stored\"}"),
    )
    .await;
    assert_success(&root_put);
    let root_get = run_cli(
        home.path(),
        &["--profile", "root", "get", "/", "--format", "json"],
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

    for unsupported in ["list", "show", "remove"] {
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
    )
    .await;
    assert_success(&add);
    assert!(
        home.path()
            .join(".config/sovereign-config/config.toml")
            .is_file()
    );

    let login = run_cli_environment(home.path(), &["login"], None, false).await;
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
        &["put", "/team/service/flag"],
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
            &["put", "/team/service/flag"],
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
    run_cli_environment(home, arguments, input, true).await
}

async fn run_cli_environment(
    home: &Path,
    arguments: &[&str],
    input: Option<&str>,
    use_xdg: bool,
) -> Output {
    let binary = env!("CARGO_BIN_EXE_sovereign-config");
    let home = home.to_owned();
    let arguments = arguments
        .iter()
        .map(|argument| (*argument).to_owned())
        .collect::<Vec<_>>();
    let input = input.map(str::to_owned);
    tokio::task::spawn_blocking(move || {
        let mut command = Command::new(binary);
        command
            .args(arguments)
            .env_clear()
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
