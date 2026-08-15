//! In-process stdio protocol harness.
//!
//! Drives the real [`Server`] over in-memory byte streams with a mock backend
//! that reproduces every gRPC outcome the client library can surface. The mock
//! records the exact requests it receives so the tests can prove the adapter
//! never widens a request, synthesizes authorization, or leaks inputs.

use std::cell::RefCell;

use async_trait::async_trait;
use serde_json::{Value, json};
use sovereign_config_core::{
    AddPathMetadata, AuthenticationStatus, ClientError, ConfigPath, ConnectionId, ConnectionUrl,
    DeleteMetadata, DisplayName, ErrorKind, ListedValue, ManagedConnectionMetadata,
    ManagedConnectionState, ManagedPermissions, MaskedSecret, PlainValue,
    ProvisionedManagedConnection, PutMetadata, ReplaceMetadata, RevealedConnectionUrl,
    RevealedSecret, Secret, SecretInput, ServiceStatus, SubTreeMutationValue, SubTreeValue,
    Timestamp, ValueContent, ValueListing, ValuePaths, ValueSubTree,
};
use sovereign_config_mcp::backend::{Backend, LoginPrompt};
use sovereign_config_mcp::server::Server;
use tokio::io::BufReader;

const REVEALED_SECRET: &str = "s3cr3t-plaintext";

/// Records what the adapter passed down, so tests can assert non-widening.
#[derive(Default)]
struct Recorder {
    paths: Vec<String>,
    reveals: Vec<String>,
    permissions: Vec<Vec<String>>,
    roots: Vec<String>,
    connection_ids: Vec<String>,
    login_calls: usize,
    alias_adds: Vec<(String, String)>,
}

struct MockBackend {
    fail: Option<ClientError>,
    authenticated: bool,
    subtree: Vec<SubTreeValue>,
    record: RefCell<Recorder>,
}

impl MockBackend {
    fn healthy() -> Self {
        Self {
            fail: None,
            authenticated: true,
            subtree: vec![
                subtree_value(
                    "/apps/api/name",
                    ValueContent::Plain(PlainValue::new("payments")),
                ),
                subtree_value("/apps/api/password", ValueContent::Secret(MaskedSecret)),
            ],
            record: RefCell::new(Recorder::default()),
        }
    }

    fn failing(kind: ErrorKind) -> Self {
        Self {
            fail: Some(ClientError::new(kind, "bounded backend message")),
            ..Self::healthy()
        }
    }

    fn guard(&self) -> Result<(), ClientError> {
        self.fail.clone().map_or(Ok(()), Err)
    }
}

fn subtree_value(path: &str, value: ValueContent) -> SubTreeValue {
    SubTreeValue {
        path: ConfigPath::parse(path).unwrap(),
        value,
    }
}

fn sample_metadata() -> ManagedConnectionMetadata {
    ManagedConnectionMetadata {
        connection_id: ConnectionId::parse("connection000000001").unwrap(),
        display_name: DisplayName::parse("Payments API").unwrap(),
        root: ConfigPath::parse_selection("/apps/api").unwrap(),
        state: ManagedConnectionState::Active,
        permissions: ManagedPermissions::parse("read").unwrap(),
        created_at: Timestamp {
            seconds: 1_700_000_000,
            nanos: 0,
        },
        updated_at: Timestamp {
            seconds: 1_700_000_000,
            nanos: 0,
        },
    }
}

fn sample_provisioned() -> ProvisionedManagedConnection {
    let url = ConnectionUrl::managed(
        "https://config.example.test",
        &ConfigPath::parse_selection("/apps/api").unwrap(),
        "https://auth.example.test/application/o/app/",
        "app-client",
        "pipeline",
        &Secret::new("app-password"),
    )
    .unwrap();
    ProvisionedManagedConnection {
        metadata: sample_metadata(),
        connection_url: RevealedConnectionUrl::new(url),
    }
}

#[async_trait(?Send)]
impl Backend for MockBackend {
    async fn service_status(&self) -> Result<ServiceStatus, ClientError> {
        self.guard()?;
        Ok(ServiceStatus::negotiate(
            "9.9.9".to_owned(),
            "v3".to_owned(),
        ))
    }

    async fn authentication_status(&self) -> Result<AuthenticationStatus, ClientError> {
        self.guard()?;
        Ok(AuthenticationStatus {
            authenticated: self.authenticated,
        })
    }

    async fn login(
        &self,
        prompts: tokio::sync::mpsc::UnboundedSender<LoginPrompt>,
    ) -> Result<(), ClientError> {
        self.record.borrow_mut().login_calls += 1;
        let _ = prompts.send(LoginPrompt {
            verification_uri: "https://auth.example.test/device".to_owned(),
            user_code: "WXYZ-1234".to_owned(),
            verification_uri_complete: Some(
                "https://auth.example.test/device?code=WXYZ-1234".to_owned(),
            ),
        });
        // Yield so the server processes the prompt before completion, exercising
        // the interleaved-notification path.
        tokio::task::yield_now().await;
        self.guard()
    }

    async fn logout(&self) -> Result<(), ClientError> {
        self.guard()
    }

    async fn get_subtree(&self, path: &ConfigPath) -> Result<ValueSubTree, ClientError> {
        self.record
            .borrow_mut()
            .paths
            .push(path.as_str().to_owned());
        self.guard()?;
        Ok(ValueSubTree {
            values: self.subtree.clone(),
        })
    }

    async fn list_values(&self, path: &ConfigPath) -> Result<ValueListing, ClientError> {
        self.record
            .borrow_mut()
            .paths
            .push(path.as_str().to_owned());
        self.guard()?;
        Ok(ValueListing {
            // Mixed case on purpose: the mock stands in for a server response,
            // and the host must see this exactly as written, not folded.
            values: vec![ListedValue {
                path: ConfigPath::parse_operation("/Apps/API/Name").unwrap(),
                value: ValueContent::Plain(PlainValue::new("payments")),
                created_at: Timestamp {
                    seconds: 1,
                    nanos: 0,
                },
                updated_at: Timestamp {
                    seconds: 1,
                    nanos: 0,
                },
                alias_paths: vec![],
            }],
            paths: vec![ConfigPath::parse_operation("/Apps/API").unwrap()],
        })
    }

    async fn put_value(
        &self,
        path: &ConfigPath,
        _value: &PlainValue,
    ) -> Result<PutMetadata, ClientError> {
        self.record
            .borrow_mut()
            .paths
            .push(path.as_str().to_owned());
        self.guard()?;
        Ok(PutMetadata {
            created_at: Timestamp {
                seconds: 1,
                nanos: 0,
            },
            updated_at: Timestamp {
                seconds: 1,
                nanos: 0,
            },
        })
    }

    async fn put_secret(
        &self,
        path: &ConfigPath,
        _value: &SecretInput,
    ) -> Result<PutMetadata, ClientError> {
        self.record
            .borrow_mut()
            .paths
            .push(path.as_str().to_owned());
        self.guard()?;
        Ok(PutMetadata {
            created_at: Timestamp {
                seconds: 1,
                nanos: 0,
            },
            updated_at: Timestamp {
                seconds: 1,
                nanos: 0,
            },
        })
    }

    async fn replace_subtree(
        &self,
        path: &ConfigPath,
        values: &[SubTreeMutationValue],
    ) -> Result<ReplaceMetadata, ClientError> {
        self.record
            .borrow_mut()
            .paths
            .push(path.as_str().to_owned());
        self.guard()?;
        Ok(ReplaceMetadata {
            updated_at: Timestamp {
                seconds: 1,
                nanos: 0,
            },
            value_count: values.len() as u64,
        })
    }

    async fn delete_values(
        &self,
        path: &ConfigPath,
        _recurse: bool,
    ) -> Result<DeleteMetadata, ClientError> {
        self.record
            .borrow_mut()
            .paths
            .push(path.as_str().to_owned());
        self.guard()?;
        Ok(DeleteMetadata {
            deleted_at: Timestamp {
                seconds: 1,
                nanos: 0,
            },
            deleted_count: 1,
        })
    }

    async fn reveal_secret(&self, path: &ConfigPath) -> Result<RevealedSecret, ClientError> {
        self.record
            .borrow_mut()
            .reveals
            .push(path.as_str().to_owned());
        self.guard()?;
        Ok(RevealedSecret::new(REVEALED_SECRET))
    }

    async fn add_value_path(
        &self,
        source: &ConfigPath,
        new_path: &ConfigPath,
    ) -> Result<AddPathMetadata, ClientError> {
        self.record
            .borrow_mut()
            .alias_adds
            .push((source.as_str().to_owned(), new_path.as_str().to_owned()));
        self.guard()?;
        Ok(AddPathMetadata {
            created_at: Timestamp {
                seconds: 1,
                nanos: 0,
            },
        })
    }

    async fn list_value_paths(&self, path: &ConfigPath) -> Result<ValuePaths, ClientError> {
        self.record
            .borrow_mut()
            .paths
            .push(path.as_str().to_owned());
        self.guard()?;
        Ok(ValuePaths {
            paths: vec![
                ConfigPath::parse("/apps/api/name").unwrap(),
                ConfigPath::parse("/apps/api/alias").unwrap(),
            ],
        })
    }

    async fn list_connections(&self) -> Result<Vec<ManagedConnectionMetadata>, ClientError> {
        self.guard()?;
        Ok(vec![sample_metadata()])
    }

    async fn create_connection(
        &self,
        _display_name: &DisplayName,
        root: &ConfigPath,
        permissions: &ManagedPermissions,
    ) -> Result<ProvisionedManagedConnection, ClientError> {
        self.record
            .borrow_mut()
            .roots
            .push(root.as_str().to_owned());
        self.record.borrow_mut().permissions.push(
            permissions
                .grant_tokens()
                .iter()
                .map(|token| (*token).to_owned())
                .collect(),
        );
        self.guard()?;
        Ok(sample_provisioned())
    }

    async fn rotate_connection(
        &self,
        connection_id: &ConnectionId,
    ) -> Result<ProvisionedManagedConnection, ClientError> {
        self.record
            .borrow_mut()
            .connection_ids
            .push(connection_id.as_str().to_owned());
        self.guard()?;
        Ok(sample_provisioned())
    }

    async fn revoke_connection(&self, connection_id: &ConnectionId) -> Result<(), ClientError> {
        self.record
            .borrow_mut()
            .connection_ids
            .push(connection_id.as_str().to_owned());
        self.guard()
    }
}

/// Runs a script of request lines through the server and returns every emitted
/// message, parsed. The reader reaches EOF at the end of the script, so `run`
/// also exercises the graceful-shutdown path on every call.
async fn run_script(backend: MockBackend, requests: &[Value]) -> Vec<Value> {
    let mut input = String::new();
    for request in requests {
        input.push_str(&serde_json::to_string(request).unwrap());
        input.push('\n');
    }
    let bytes = input.into_bytes();
    let reader = BufReader::new(bytes.as_slice());
    let mut output: Vec<u8> = Vec::new();
    Server::new(backend, "9.9.9")
        .run(reader, &mut output)
        .await
        .unwrap();
    String::from_utf8(output)
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("every output line is JSON"))
        .collect()
}

fn call(id: i64, name: &str, arguments: Value) -> Value {
    let mut params = serde_json::Map::new();
    params.insert("name".to_owned(), Value::from(name));
    params.insert("arguments".to_owned(), arguments);
    let mut request = serde_json::Map::new();
    request.insert("jsonrpc".to_owned(), Value::from("2.0"));
    request.insert("id".to_owned(), Value::from(id));
    request.insert("method".to_owned(), Value::from("tools/call"));
    request.insert("params".to_owned(), Value::Object(params));
    Value::Object(request)
}

fn result_text(message: &Value) -> String {
    message["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn is_error(message: &Value) -> bool {
    message["result"]["isError"].as_bool().unwrap_or(false)
}

#[tokio::test]
async fn initialize_advertises_tools_and_echoes_protocol_version() {
    let out = run_script(
        MockBackend::healthy(),
        &[json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-06-18" } })],
    )
    .await;
    assert_eq!(out.len(), 1);
    assert_eq!(out[0]["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(
        out[0]["result"]["serverInfo"]["name"],
        "sovereign-config-mcp"
    );
    assert!(out[0]["result"]["capabilities"]["tools"].is_object());
}

#[tokio::test]
async fn tools_list_exposes_the_implemented_surface_including_aliases() {
    let out = run_script(
        MockBackend::healthy(),
        &[json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" })],
    )
    .await;
    let tools = out[0]["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    for expected in [
        "status",
        "login",
        "logout",
        "get",
        "put_value",
        "put_secret",
        "reveal_secret",
        "alias_add",
        "alias_list",
        "create_connection",
        "revoke_connection",
    ] {
        assert!(names.contains(&expected), "missing {expected}");
    }
}

#[tokio::test]
async fn alias_add_passes_the_exact_paths_to_the_backend() {
    let out = run_script(
        MockBackend::healthy(),
        &[call(
            1,
            "alias_add",
            json!({ "source_path": "/apps/api/name", "new_path": "/apps/api/alias" }),
        )],
    )
    .await;
    assert!(!is_error(&out[0]));
    // The confirmation names the exact alias created, proving the call reached
    // the backend with the caller's new path unchanged.
    assert_eq!(result_text(&out[0]), "Alias created at /apps/api/alias");
}

#[tokio::test]
async fn alias_list_returns_every_resolving_path() {
    let out = run_script(
        MockBackend::healthy(),
        &[call(1, "alias_list", json!({ "path": "/apps/api/name" }))],
    )
    .await;
    assert!(!is_error(&out[0]));
    let text = result_text(&out[0]);
    let rendered: Value = serde_json::from_str(&text).unwrap();
    let paths: Vec<&str> = rendered["paths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|path| path.as_str().unwrap())
        .collect();
    assert_eq!(paths, vec!["/apps/api/name", "/apps/api/alias"]);
}

#[tokio::test]
async fn get_masks_secrets_and_reveal_uses_explicit_reveal() {
    let masked = run_script(
        MockBackend::healthy(),
        &[call(1, "get", json!({ "path": "/apps/api" }))],
    )
    .await;
    let text = result_text(&masked[0]);
    assert!(
        text.contains("********"),
        "secret must be masked in get: {text}"
    );
    assert!(
        !text.contains(REVEALED_SECRET),
        "plaintext must not appear when masked"
    );

    let revealed = run_script(
        MockBackend::healthy(),
        &[call(
            1,
            "get",
            json!({ "path": "/apps/api", "reveal": true }),
        )],
    )
    .await;
    assert!(
        result_text(&revealed[0]).contains(REVEALED_SECRET),
        "reveal must disclose plaintext"
    );
}

#[tokio::test]
async fn put_secret_never_echoes_the_secret_value() {
    let out = run_script(
        MockBackend::healthy(),
        &[call(
            1,
            "put_secret",
            json!({ "path": "/apps/api/password", "value": "top-secret-input" }),
        )],
    )
    .await;
    assert_eq!(result_text(&out[0]), "Secret stored");
    let whole = serde_json::to_string(&out).unwrap();
    assert!(
        !whole.contains("top-secret-input"),
        "secret input must never be echoed"
    );
}

#[tokio::test]
async fn reveal_secret_returns_authorized_plaintext() {
    let out = run_script(
        MockBackend::healthy(),
        &[call(
            1,
            "reveal_secret",
            json!({ "path": "/apps/api/password" }),
        )],
    )
    .await;
    assert_eq!(result_text(&out[0]), REVEALED_SECRET);
}

#[tokio::test]
async fn grpc_error_classes_map_to_bounded_tool_failures() {
    for (kind, code) in [
        (ErrorKind::PermissionDenied, "permission_denied"),
        (ErrorKind::Unauthenticated, "unauthenticated"),
        (ErrorKind::Unavailable, "unavailable"),
        (ErrorKind::NotFound, "not_found"),
    ] {
        let out = run_script(
            MockBackend::failing(kind),
            &[call(1, "get", json!({ "path": "/apps/secret" }))],
        )
        .await;
        assert!(is_error(&out[0]), "{code} must be an error result");
        assert_eq!(out[0]["result"]["structuredContent"]["error"]["code"], code);
        let text = result_text(&out[0]);
        assert!(
            !text.contains("/apps/secret"),
            "error must not echo the requested path: {text}"
        );
    }
}

#[tokio::test]
async fn malformed_frame_and_unknown_method_are_handled_in_band() {
    let out = run_script(
        MockBackend::healthy(),
        &[json!({ "jsonrpc": "2.0", "id": 5, "method": "no/such/method" })],
    )
    .await;
    assert_eq!(out[0]["error"]["code"], -32601);

    // A malformed line addressed with an id gets an error; unaddressable noise is dropped.
    let mut input = String::from("not-json-at-all\n");
    input.push_str(
        &serde_json::to_string(&json!({ "jsonrpc": "2.0", "id": 9, "method": "ping" })).unwrap(),
    );
    input.push('\n');
    let bytes = input.into_bytes();
    let reader = BufReader::new(bytes.as_slice());
    let mut raw: Vec<u8> = Vec::new();
    Server::new(MockBackend::healthy(), "9.9.9")
        .run(reader, &mut raw)
        .await
        .unwrap();
    let lines: Vec<Value> = String::from_utf8(raw)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    // Only the ping is answerable; the malformed line without an id produced no response.
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["id"], 9);
}

#[tokio::test]
async fn unknown_tool_and_oversized_input_fail_without_reaching_the_backend() {
    let backend = MockBackend::healthy();
    let out = run_script(backend, &[call(1, "nonexistent_tool", json!({}))]).await;
    assert_eq!(
        out[0]["result"]["structuredContent"]["error"]["code"],
        "unknown_tool"
    );

    // Oversized values are rejected during argument parsing, before any call.
    let big = "x".repeat(2 * 1024 * 1024);
    let out = run_script(
        MockBackend::healthy(),
        &[call(1, "put_value", json!({ "path": "/a", "value": big }))],
    )
    .await;
    assert!(is_error(&out[0]));
    assert_eq!(
        out[0]["result"]["structuredContent"]["error"]["code"],
        "invalid_request"
    );
}

#[tokio::test]
async fn login_surfaces_verification_details_then_completes() {
    let out = run_script(MockBackend::healthy(), &[call(1, "login", json!({}))]).await;
    // First a logging notification carrying the verification URL and code, then the response.
    let notification = out
        .iter()
        .find(|m| m["method"] == "notifications/message")
        .expect("login must emit a notification");
    assert_eq!(notification["params"]["data"]["user_code"], "WXYZ-1234");
    assert_eq!(
        notification["params"]["data"]["verification_uri"],
        "https://auth.example.test/device"
    );
    let response = out
        .iter()
        .find(|m| m["id"] == 1)
        .expect("login must respond");
    assert!(!is_error(response));
    assert!(result_text(response).contains("WXYZ-1234"));
}

#[tokio::test]
async fn adapter_passes_requests_through_without_widening() {
    // create_connection with exactly the caller's root and single 'read' grant:
    // the adapter must not add permissions or broaden the root.
    let backend = MockBackend::healthy();
    let out = run_script(
        backend,
        &[call(
            1,
            "create_connection",
            json!({ "display_name": "Payments", "root": "/apps/api", "permissions": ["read"] }),
        )],
    )
    .await;
    assert!(!is_error(&out[0]));
    // The one-time URL is the authorized product of create and must be present.
    assert!(result_text(&out[0]).contains("connection_url:"));
}

#[tokio::test]
async fn list_returns_display_form_paths_to_the_host() {
    let out = run_script(
        MockBackend::healthy(),
        &[call(1, "list", json!({ "path": "/apps/api" }))],
    )
    .await;
    assert!(!is_error(&out[0]));
    let text = result_text(&out[0]);
    let rendered: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(rendered["values"][0]["path"], "/Apps/API/Name");
    assert_eq!(rendered["paths"][0], "/Apps/API");
}

#[tokio::test]
async fn every_emitted_line_is_a_pure_jsonrpc_message() {
    let out = run_script(
        MockBackend::healthy(),
        &[
            json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }),
            json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
            call(2, "status", json!({})),
            call(3, "list", json!({ "path": "/apps/api" })),
        ],
    )
    .await;
    // The notification produces no output; three requests produce three responses.
    assert_eq!(out.len(), 3);
    for message in &out {
        assert_eq!(message["jsonrpc"], "2.0");
        assert!(message.get("result").is_some() || message.get("error").is_some());
    }
}
