#![forbid(unsafe_code)]

use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use js_sys::{Date, Reflect, Uint8Array};
use prost::Message;
use sha2::{Digest, Sha256};
use sovereign_config_client::{
    AccessTokenProvider, Client, ManagedConnectionTransport, RpcCode, Transport, ValueTransport,
    VersionReply, map_rpc_status, timestamp,
};
use sovereign_config_core::{
    AddPathMetadata, AuthenticationStatus, ClientError, ConfigPath, ConnectionId, ConnectionUrl,
    DeleteMetadata, DisplayName, ErrorKind, ListedValue, ManagedConnectionMetadata,
    ManagedConnectionState, ManagedPermission, ManagedPermissions, MaskedSecret, PlainValue,
    ProvisionedManagedConnection, PutMetadata, ReplaceMetadata, RevealedConnectionUrl,
    RevealedSecret, Secret, SecretInput, SubTreeMutationContent, SubTreeMutationValue,
    SubTreeValue, Timestamp, ValueContent, ValueListing, ValuePaths, ValueSubTree,
    parse_subtree_json, render_subtree_json,
};
use sovereign_config_proto::sovereign::config::v3::{
    AddValuePathRequest, AddValuePathResponse, CreateManagedConnectionRequest,
    CreateManagedConnectionResponse, DeleteValuesRequest, DeleteValuesResponse, GetIdentityRequest,
    GetIdentityResponse, GetSubTreeRequest, GetSubTreeResponse, GetVersionRequest,
    GetVersionResponse, ListManagedConnectionsRequest, ListManagedConnectionsResponse,
    ListValuePathsRequest, ListValuePathsResponse, ListValuesRequest, ListValuesResponse,
    ManagedConnectionMetadata as ProtoManagedConnectionMetadata,
    ManagedConnectionState as ProtoManagedConnectionState, PreserveSecret, PutValueRequest,
    PutValueResponse, ReplaceSubTreeRequest, ReplaceSubTreeResponse, RevealSecretRequest,
    RevealSecretResponse, RevokeManagedConnectionRequest, RevokeManagedConnectionResponse,
    RotateManagedConnectionRequest, RotateManagedConnectionResponse,
    SubTreeMutationValue as ProtoSubTreeMutationValue, ValueClassification as ProtoClassification,
    listed_value, put_value_request, sub_tree_mutation_value, sub_tree_value,
};
use wasm_bindgen::{JsCast, JsValue, closure::Closure, prelude::wasm_bindgen};
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::{
    Document, Element, Event, Headers, HtmlButtonElement, HtmlDialogElement, HtmlElement,
    HtmlInputElement, HtmlTextAreaElement, KeyboardEvent, PointerEvent, Request, RequestCache,
    RequestInit, Response, Url, UrlSearchParams, window,
};

const STATE_KEY: &str = "sovereign-config.pkce-state";
const VERIFIER_KEY: &str = "sovereign-config.pkce-verifier";
const REFRESH_TOKEN_KEY: &str = "sovereign-config.refresh-token";
const REFRESH_ENDPOINT_KEY: &str = "sovereign-config.refresh-endpoint";
const REFRESH_EXPIRES_KEY: &str = "sovereign-config.refresh-expires-at";
const RETURN_PATH_KEY: &str = "sovereign-config.return-path";
const SIDEBAR_WIDTH_KEY: &str = "sovereign-config.sidebar-width";
const REFRESH_LIFETIME_MS: f64 = 8.0 * 60.0 * 60.0 * 1000.0;
const SIDEBAR_MIN_WIDTH: f64 = 200.0;
const SIDEBAR_MAX_WIDTH: f64 = 560.0;
const SIDEBAR_DEFAULT_WIDTH: f64 = 288.0;
const SIDEBAR_KEY_STEP: f64 = 16.0;

thread_local! {
    static TOKENS: RefCell<Option<MemoryTokens>> = const { RefCell::new(None) };
    static DELETE_TARGET: RefCell<Option<DeleteTarget>> = const { RefCell::new(None) };
    static ADD_PATH_TARGET: RefCell<Option<AddPathTarget>> = const { RefCell::new(None) };
    static PATH_OPTIONS_REFRESHING: Cell<bool> = const { Cell::new(false) };
    static ACTIVE_PATH_OPTION: Cell<Option<usize>> = const { Cell::new(None) };
    static JSON_MODE: Cell<bool> = const { Cell::new(false) };
    static CONFIGURATION_LOAD_GENERATION: Cell<u64> = const { Cell::new(0) };
    static CONNECTIONS_LOAD_GENERATION: Cell<u64> = const { Cell::new(0) };
    static CONNECTION_TARGET: RefCell<Option<ConnectionTarget>> = const { RefCell::new(None) };
    static CONNECTION_URL_SECRET: RefCell<Option<Secret>> = const { RefCell::new(None) };
    static CONNECTION_URL_RETURN_FOCUS: RefCell<Option<String>> = const { RefCell::new(None) };
    static CONNECTION_PENDING: Cell<bool> = const { Cell::new(false) };
    static PENDING_CONNECTION: RefCell<Option<PendingConnection>> = const { RefCell::new(None) };
    static TREE_LOAD_GENERATION: Cell<u64> = const { Cell::new(0) };
    static TREE_NODES: RefCell<Vec<TreeNode>> = const { RefCell::new(Vec::new()) };
    static CONNECTIONS: RefCell<Vec<ManagedConnectionMetadata>> = const { RefCell::new(Vec::new()) };
    static PENDING_NAVIGATION: RefCell<Option<Route>> = const { RefCell::new(None) };
    static PENDING_FROM_HISTORY: Cell<bool> = const { Cell::new(false) };
    static CURRENT_URL: RefCell<String> = const { RefCell::new(String::new()) };
    static SIDEBAR_DRAG_POINTER: Cell<Option<i32>> = const { Cell::new(None) };
}

struct DeleteTarget {
    path: ConfigPath,
    return_focus: String,
}

/// The value selected for a pending "add path" confirmation. The source path
/// identifies the stored value; the new path is read from the dialog input.
#[derive(Clone)]
struct AddPathTarget {
    source: ConfigPath,
    return_focus: String,
}

/// The connection selected for a pending rotate or revoke confirmation.
struct ConnectionTarget {
    connection_id: ConnectionId,
    return_focus: String,
}

/// A validated create-connection request awaiting its confirmation. Both the
/// estate-wide form and the per-path form on the Configuration view fill this
/// in, so the confirmation dialog and the mutation itself stay single-sourced.
struct PendingConnection {
    display_name: DisplayName,
    root: ConfigPath,
    permissions: ManagedPermissions,
    /// Cleared once the connection is created, so the operator does not
    /// accidentally create a second connection under the same name.
    name_input_id: String,
    return_focus: String,
}

/// One row of the sidebar configuration tree. The tree is always rendered fully
/// expanded, so a node carries its depth rather than a list of children.
#[derive(Clone, Debug, Eq, PartialEq)]
struct TreeNode {
    path: ConfigPath,
    /// The label to render: the last segment of whichever display form this
    /// namespace was established with, `/` for the tree root. `path` itself
    /// stays fold-only — it is what `data-path` round-trips and what every
    /// lookup against `has_values`/`has_connection` compares.
    display: String,
    depth: usize,
    /// This namespace directly holds at least one value — rendered bold.
    has_values: bool,
    /// An access URL is rooted at exactly this path — rendered with a key.
    has_connection: bool,
}

fn path_segments(path: &str) -> Vec<&str> {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .collect()
}

/// The namespace holding `path`, or the root for a top-level value.
fn parent_of(path: &ConfigPath) -> ConfigPath {
    path.as_str()
        .rsplit_once('/')
        .filter(|(parent, _)| !parent.is_empty())
        .and_then(|(parent, _)| ConfigPath::parse(parent).ok())
        .unwrap_or_else(ConfigPath::root)
}

/// The parent of `path`, in both forms. Byte offsets align between the fold
/// key and the display form because letter case never changes a segment's
/// length — `path.as_str()` and `path.display_str()` always split at the same
/// boundary.
fn parent_forms(path: &ConfigPath) -> (String, String) {
    match path.as_str().rsplit_once('/') {
        Some((parent, _)) if !parent.is_empty() => {
            let boundary = parent.len();
            (parent.to_owned(), path.display_str()[..boundary].to_owned())
        }
        _ => ("/".to_owned(), "/".to_owned()),
    }
}

/// The namespace labels a set of value paths implies: each value's parent and
/// every ancestor of that parent, plus the tree root — keyed by fold, mapped
/// to the display form contributed by whichever value path is fold-smallest
/// under it.
///
/// This deliberately mirrors the server's own derivation of `ListValues.paths`
/// (`add_parent_paths` in `sovereign-config-server`), except for the
/// tie-break: `GetSubTree` carries no creation timestamp, so "whichever row
/// was created first" — the rule the server uses — is not available here, and
/// the fold-smallest contributing path is used instead. Both rules are
/// deterministic; they can disagree only when two differently-cased writes
/// share an ancestor, which is purely a label choice with no effect on stored
/// data.
fn namespace_labels(value_paths: &[ConfigPath]) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert("/".to_owned(), "/".to_owned());
    let mut sorted = value_paths.iter().collect::<Vec<_>>();
    sorted.sort_by_key(|path| path.as_str());
    for path in sorted {
        let (fold_parent, display_parent) = parent_forms(path);
        if fold_parent == "/" {
            continue;
        }
        let fold_segments = path_segments(&fold_parent);
        let display_segments = path_segments(&display_parent);
        let mut fold_prefix = String::new();
        let mut display_prefix = String::new();
        for index in 0..fold_segments.len() {
            fold_prefix.push('/');
            fold_prefix.push_str(fold_segments[index]);
            display_prefix.push('/');
            display_prefix.push_str(display_segments[index]);
            labels
                .entry(fold_prefix.clone())
                .or_insert_with(|| display_prefix.clone());
        }
    }
    labels
}

/// The namespaces that directly hold at least one value. `ListValues.paths`
/// cannot answer this — it reports ancestors, which include namespaces holding
/// nothing but children — so it is derived from whole-tree value paths instead.
fn value_parents_of(value_paths: &[ConfigPath]) -> BTreeSet<String> {
    value_paths
        .iter()
        .map(|path| parent_of(path).as_str().to_owned())
        .collect()
}

/// Orders namespaces depth-first and decorates each with its sidebar markers.
///
/// Ordering compares segments rather than whole strings: `-` sorts before `/`,
/// so a raw string sort would place `/a-b` between `/a` and `/a/b` and split a
/// subtree in two.
fn build_tree(
    labels: &BTreeMap<String, String>,
    value_parents: &BTreeSet<String>,
    connection_roots: &BTreeSet<String>,
) -> Vec<TreeNode> {
    let mut ordered = labels.keys().cloned().collect::<Vec<_>>();
    ordered.sort_by(|left, right| path_segments(left).cmp(&path_segments(right)));
    ordered
        .into_iter()
        .filter_map(|fold| {
            let depth = path_segments(&fold).len();
            let display = labels.get(&fold).map_or(fold.as_str(), String::as_str);
            let label = display
                .rsplit('/')
                .next()
                .filter(|segment| !segment.is_empty())
                .unwrap_or("/")
                .to_owned();
            let path = ConfigPath::parse(fold).ok()?;
            Some(TreeNode {
                has_values: value_parents.contains(path.as_str()),
                has_connection: connection_roots.contains(path.as_str()),
                depth,
                display: label,
                path,
            })
        })
        .collect()
}

#[derive(Clone)]
enum Route {
    System,
    Configuration(ConfigPath),
    Connections,
    Downloads,
}

struct MemoryTokens {
    access_token: Secret,
    refresh_token: Secret,
    access_expires_at_ms: f64,
    refresh_expires_at_ms: f64,
    token_endpoint: String,
}

#[derive(Clone)]
struct AppConfig {
    issuer: String,
    client_id: String,
}

#[derive(Clone, Copy)]
struct BrowserTransport;

struct MemoryAuthentication {
    client_id: String,
}

#[async_trait(?Send)]
impl AccessTokenProvider for MemoryAuthentication {
    async fn access_token(&self) -> Result<Option<Secret>, ClientError> {
        let Some(tokens) = TOKENS.with_borrow_mut(Option::take) else {
            return Ok(None);
        };
        let now = Date::now();
        if now < tokens.access_expires_at_ms {
            let access_token = tokens.access_token.clone();
            TOKENS.with_borrow_mut(|slot| *slot = Some(tokens));
            return Ok(Some(access_token));
        }
        if now >= tokens.refresh_expires_at_ms {
            clear_persisted_refresh_token();
            return Ok(None);
        }
        match refresh_tokens(&self.client_id, &tokens).await {
            Ok(refreshed) => {
                let access_token = refreshed.access_token.clone();
                persist_refresh_token(&refreshed);
                TOKENS.with_borrow_mut(|slot| *slot = Some(refreshed));
                Ok(Some(access_token))
            }
            Err(error) if error.kind == ErrorKind::Unavailable => {
                TOKENS.with_borrow_mut(|slot| *slot = Some(tokens));
                Err(error)
            }
            Err(error) => {
                clear_persisted_refresh_token();
                Err(error)
            }
        }
    }
}

#[async_trait(?Send)]
impl Transport for BrowserTransport {
    async fn get_version(&self, protocol_version: &str) -> Result<VersionReply, ClientError> {
        let response: GetVersionResponse = grpc_unary(
            "/sovereign.config.v3.System/GetVersion",
            &GetVersionRequest {
                protocol_version: protocol_version.to_owned(),
            },
            None,
        )
        .await?;
        Ok(VersionReply {
            application_version: response.application_version,
            protocol_version: response.protocol_version,
        })
    }

    async fn get_identity(&self, bearer: &Secret) -> Result<AuthenticationStatus, ClientError> {
        let response: GetIdentityResponse = grpc_unary(
            "/sovereign.config.v3.System/GetIdentity",
            &GetIdentityRequest {},
            Some(bearer),
        )
        .await?;
        Ok(AuthenticationStatus {
            authenticated: response.authenticated,
        })
    }
}

#[async_trait(?Send)]
impl ValueTransport for BrowserTransport {
    async fn list_values(
        &self,
        path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<ValueListing, ClientError> {
        let response: ListValuesResponse = grpc_unary(
            "/sovereign.config.v3.Configuration/ListValues",
            &ListValuesRequest {
                path: path.display_str().to_owned(),
            },
            Some(bearer),
        )
        .await?;
        let values = response
            .values
            .into_iter()
            .map(|value| {
                let alias_paths = value
                    .alias_paths
                    .into_iter()
                    .map(|path| ConfigPath::parse_operation(path).map_err(|_| browser_error()))
                    .collect::<Result<Vec<_>, ClientError>>()?;
                Ok(ListedValue {
                    path: ConfigPath::parse_operation(value.path).map_err(|_| browser_error())?,
                    value: listed_content(value.classification, value.content)?,
                    created_at: proto_timestamp(value.created_at)?,
                    updated_at: proto_timestamp(value.updated_at)?,
                    alias_paths,
                })
            })
            .collect::<Result<Vec<_>, ClientError>>()?;
        let paths = response
            .paths
            .into_iter()
            .map(|path| ConfigPath::parse_selection(path).map_err(|_| browser_error()))
            .collect::<Result<Vec<_>, ClientError>>()?;
        Ok(ValueListing { values, paths })
    }

    async fn get_subtree(
        &self,
        path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<ValueSubTree, ClientError> {
        let response: GetSubTreeResponse = grpc_unary(
            "/sovereign.config.v3.Configuration/GetSubTree",
            &GetSubTreeRequest {
                path: path.display_str().to_owned(),
            },
            Some(bearer),
        )
        .await?;
        let values = response
            .values
            .into_iter()
            .map(|value| {
                let value_path =
                    ConfigPath::parse_operation(value.path).map_err(|_| browser_error())?;
                if !value_path.is_at_or_below(path) {
                    return Err(browser_error());
                }
                Ok(SubTreeValue {
                    path: value_path,
                    value: subtree_content(value.classification, value.content)?,
                })
            })
            .collect::<Result<Vec<_>, ClientError>>()?;
        Ok(ValueSubTree { values })
    }

    async fn put_value(
        &self,
        path: &ConfigPath,
        value: &PlainValue,
        bearer: &Secret,
    ) -> Result<PutMetadata, ClientError> {
        let response: PutValueResponse = grpc_unary(
            "/sovereign.config.v3.Configuration/PutValue",
            &PutValueRequest {
                path: path.display_str().to_owned(),
                content: Some(put_value_request::Content::PlainValue(
                    value.expose().to_owned(),
                )),
            },
            Some(bearer),
        )
        .await?;
        Ok(PutMetadata {
            created_at: proto_timestamp(response.created_at)?,
            updated_at: proto_timestamp(response.updated_at)?,
        })
    }

    async fn put_secret(
        &self,
        path: &ConfigPath,
        value: &SecretInput,
        bearer: &Secret,
    ) -> Result<PutMetadata, ClientError> {
        let response: PutValueResponse = grpc_unary(
            "/sovereign.config.v3.Configuration/PutValue",
            &PutValueRequest {
                path: path.display_str().to_owned(),
                content: Some(put_value_request::Content::SecretValue(
                    value.expose().to_owned(),
                )),
            },
            Some(bearer),
        )
        .await?;
        Ok(PutMetadata {
            created_at: proto_timestamp(response.created_at)?,
            updated_at: proto_timestamp(response.updated_at)?,
        })
    }

    async fn replace_subtree(
        &self,
        path: &ConfigPath,
        values: &[SubTreeMutationValue],
        bearer: &Secret,
    ) -> Result<ReplaceMetadata, ClientError> {
        let response: ReplaceSubTreeResponse = grpc_unary(
            "/sovereign.config.v3.Configuration/ReplaceSubTree",
            &ReplaceSubTreeRequest {
                path: path.display_str().to_owned(),
                values: values
                    .iter()
                    .map(|value| ProtoSubTreeMutationValue {
                        path: value.path.display_str().to_owned(),
                        content: Some(match &value.value {
                            SubTreeMutationContent::Plain(value) => {
                                sub_tree_mutation_value::Content::PlainValue(
                                    value.expose().to_owned(),
                                )
                            }
                            SubTreeMutationContent::PreserveSecret => {
                                sub_tree_mutation_value::Content::PreserveSecret(PreserveSecret {})
                            }
                        }),
                    })
                    .collect(),
            },
            Some(bearer),
        )
        .await?;
        Ok(ReplaceMetadata {
            updated_at: proto_timestamp(response.updated_at)?,
            value_count: response.value_count,
        })
    }

    async fn delete_values(
        &self,
        path: &ConfigPath,
        recurse: bool,
        bearer: &Secret,
    ) -> Result<DeleteMetadata, ClientError> {
        let response: DeleteValuesResponse = grpc_unary(
            "/sovereign.config.v3.Configuration/DeleteValues",
            &DeleteValuesRequest {
                path: path.display_str().to_owned(),
                recurse,
            },
            Some(bearer),
        )
        .await?;
        Ok(DeleteMetadata {
            deleted_at: proto_timestamp(response.deleted_at)?,
            deleted_count: response.deleted_count,
        })
    }

    async fn reveal_secret(
        &self,
        path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<RevealedSecret, ClientError> {
        let response: RevealSecretResponse = grpc_unary(
            "/sovereign.config.v3.Configuration/RevealSecret",
            &RevealSecretRequest {
                path: path.display_str().to_owned(),
            },
            Some(bearer),
        )
        .await?;
        if response.value.contains('\0') {
            return Err(browser_error());
        }
        Ok(RevealedSecret::new(response.value))
    }

    async fn add_value_path(
        &self,
        source: &ConfigPath,
        new_path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<AddPathMetadata, ClientError> {
        let response: AddValuePathResponse = grpc_unary(
            "/sovereign.config.v3.Configuration/AddValuePath",
            &AddValuePathRequest {
                source_path: source.display_str().to_owned(),
                new_path: new_path.display_str().to_owned(),
            },
            Some(bearer),
        )
        .await?;
        Ok(AddPathMetadata {
            created_at: proto_timestamp(response.created_at)?,
        })
    }

    async fn list_value_paths(
        &self,
        path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<ValuePaths, ClientError> {
        let response: ListValuePathsResponse = grpc_unary(
            "/sovereign.config.v3.Configuration/ListValuePaths",
            &ListValuePathsRequest {
                path: path.display_str().to_owned(),
            },
            Some(bearer),
        )
        .await?;
        let paths = response
            .paths
            .into_iter()
            .map(|path| ConfigPath::parse_operation(path).map_err(|_| browser_error()))
            .collect::<Result<Vec<_>, ClientError>>()?;
        Ok(ValuePaths { paths })
    }
}

#[async_trait(?Send)]
impl ManagedConnectionTransport for BrowserTransport {
    async fn list_managed_connections(
        &self,
        bearer: &Secret,
    ) -> Result<Vec<ManagedConnectionMetadata>, ClientError> {
        let response: ListManagedConnectionsResponse = grpc_unary(
            "/sovereign.config.v3.ManagedConnections/ListManagedConnections",
            &ListManagedConnectionsRequest {},
            Some(bearer),
        )
        .await?;
        response
            .connections
            .into_iter()
            .map(managed_metadata)
            .collect()
    }

    async fn create_managed_connection(
        &self,
        display_name: &DisplayName,
        root: &ConfigPath,
        permissions: &ManagedPermissions,
        bearer: &Secret,
    ) -> Result<ProvisionedManagedConnection, ClientError> {
        let response: CreateManagedConnectionResponse = grpc_unary(
            "/sovereign.config.v3.ManagedConnections/CreateManagedConnection",
            &CreateManagedConnectionRequest {
                display_name: display_name.as_str().to_owned(),
                root: root.as_str().to_owned(),
                permissions: permissions.to_proto(),
            },
            Some(bearer),
        )
        .await?;
        provisioned_connection(response.metadata, &response.connection_url)
    }

    async fn rotate_managed_connection(
        &self,
        connection_id: &ConnectionId,
        bearer: &Secret,
    ) -> Result<ProvisionedManagedConnection, ClientError> {
        let response: RotateManagedConnectionResponse = grpc_unary(
            "/sovereign.config.v3.ManagedConnections/RotateManagedConnection",
            &RotateManagedConnectionRequest {
                connection_id: connection_id.as_str().to_owned(),
            },
            Some(bearer),
        )
        .await?;
        provisioned_connection(response.metadata, &response.connection_url)
    }

    async fn revoke_managed_connection(
        &self,
        connection_id: &ConnectionId,
        bearer: &Secret,
    ) -> Result<(), ClientError> {
        let _: RevokeManagedConnectionResponse = grpc_unary(
            "/sovereign.config.v3.ManagedConnections/RevokeManagedConnection",
            &RevokeManagedConnectionRequest {
                connection_id: connection_id.as_str().to_owned(),
            },
            Some(bearer),
        )
        .await?;
        Ok(())
    }
}

fn managed_metadata(
    metadata: ProtoManagedConnectionMetadata,
) -> Result<ManagedConnectionMetadata, ClientError> {
    Ok(ManagedConnectionMetadata {
        connection_id: ConnectionId::parse(metadata.connection_id).map_err(|_| browser_error())?,
        display_name: DisplayName::parse(metadata.display_name).map_err(|_| browser_error())?,
        root: ConfigPath::parse_selection(metadata.root).map_err(|_| browser_error())?,
        state: managed_state(metadata.state)?,
        permissions: ManagedPermissions::from_proto(&metadata.permissions)
            .map_err(|_| browser_error())?,
        created_at: proto_timestamp(metadata.created_at)?,
        updated_at: proto_timestamp(metadata.updated_at)?,
    })
}

fn managed_state(state: i32) -> Result<ManagedConnectionState, ClientError> {
    match ProtoManagedConnectionState::try_from(state) {
        Ok(ProtoManagedConnectionState::Provisioning) => Ok(ManagedConnectionState::Provisioning),
        Ok(ProtoManagedConnectionState::Active) => Ok(ManagedConnectionState::Active),
        Ok(ProtoManagedConnectionState::RotationUnknown) => {
            Ok(ManagedConnectionState::RotationUnknown)
        }
        Ok(ProtoManagedConnectionState::Revoking) => Ok(ManagedConnectionState::Revoking),
        Ok(ProtoManagedConnectionState::CleanupRequired) => {
            Ok(ManagedConnectionState::CleanupRequired)
        }
        _ => Err(browser_error()),
    }
}

fn provisioned_connection(
    metadata: Option<ProtoManagedConnectionMetadata>,
    connection_url: &str,
) -> Result<ProvisionedManagedConnection, ClientError> {
    let metadata = managed_metadata(metadata.ok_or_else(browser_error)?)?;
    let connection = ConnectionUrl::parse(connection_url).map_err(|_| browser_error())?;
    if connection.client_authentication().is_none() || connection.root() != &metadata.root {
        return Err(browser_error());
    }
    Ok(ProvisionedManagedConnection {
        metadata,
        connection_url: RevealedConnectionUrl::new(connection),
    })
}

fn listed_content(
    classification: i32,
    content: Option<listed_value::Content>,
) -> Result<ValueContent, ClientError> {
    match (ProtoClassification::try_from(classification), content) {
        (Ok(ProtoClassification::Plain), Some(listed_value::Content::PlainValue(value)))
            if !value.contains('\0') =>
        {
            Ok(ValueContent::Plain(PlainValue::new(value)))
        }
        (Ok(ProtoClassification::Secret), Some(listed_value::Content::MaskedSecret(_))) => {
            Ok(ValueContent::Secret(MaskedSecret))
        }
        _ => Err(browser_error()),
    }
}

fn subtree_content(
    classification: i32,
    content: Option<sub_tree_value::Content>,
) -> Result<ValueContent, ClientError> {
    match (ProtoClassification::try_from(classification), content) {
        (Ok(ProtoClassification::Plain), Some(sub_tree_value::Content::PlainValue(value)))
            if !value.contains('\0') =>
        {
            Ok(ValueContent::Plain(PlainValue::new(value)))
        }
        (Ok(ProtoClassification::Secret), Some(sub_tree_value::Content::MaskedSecret(_))) => {
            Ok(ValueContent::Secret(MaskedSecret))
        }
        _ => Err(browser_error()),
    }
}

fn proto_timestamp(value: Option<prost_types::Timestamp>) -> Result<Timestamp, ClientError> {
    let value = value.ok_or_else(browser_error)?;
    timestamp(value.seconds, value.nanos)
}

#[wasm_bindgen(start)]
pub fn start() {
    install_actions();
    render_route(&route_from_location());
    // The Downloads view needs no authentication; load it independently of the
    // login flow so it renders on a direct visit to /downloads while logged out.
    spawn_local(async {
        load_downloads().await;
    });
    spawn_local(async {
        match app_config() {
            Ok(config) => {
                restore_tokens();
                let callback_error =
                    if location_search().is_some_and(|search| search.contains("code=")) {
                        finish_login(&config).await.err()
                    } else {
                        None
                    };
                render_route(&route_from_location());
                let authenticated = refresh_status(&config).await;
                if let Some(error) = callback_error {
                    show_error(error.message());
                } else if authenticated {
                    load_current_configuration().await;
                    load_current_connections().await;
                    load_tree().await;
                } else {
                    // Renders the sidebar's logged-out hint in place of a tree.
                    load_tree().await;
                }
            }
            Err(error) => show_error(error.message()),
        }
    });
}

fn install_actions() {
    let Some(document) = window().and_then(|window| window.document()) else {
        return;
    };
    install_route_link(&document, "brand-link", Route::System);
    install_route_link(&document, "system-status-link", Route::System);
    install_route_link(
        &document,
        "configuration-values-link",
        Route::Configuration(ConfigPath::root()),
    );
    install_route_link(&document, "managed-connections-link", Route::Connections);
    install_route_link(&document, "downloads-link", Route::Downloads);
    if let Some(browser_window) = window() {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            if has_unsaved_edits() {
                // A history pop cannot be cancelled, so put the address bar
                // back and ask the same question an in-app link would ask.
                let target = route_from_location();
                restore_current_url();
                open_unsaved_dialog(target, true);
                return;
            }
            discard_connection_url();
            render_route(&route_from_location());
            spawn_local(async {
                refresh_views().await;
            });
        });
        let _ = browser_window
            .add_event_listener_with_callback("popstate", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(login) = document.get_element_by_id("login") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: web_sys::Event| {
            spawn_local(async {
                match app_config() {
                    Ok(config) => {
                        if let Err(error) = begin_login(&config).await {
                            show_error(error.message());
                        }
                    }
                    Err(error) => show_error(error.message()),
                }
            });
        });
        let _ = login.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(logout) = document.get_element_by_id("logout") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: web_sys::Event| {
            CONFIGURATION_LOAD_GENERATION.set(CONFIGURATION_LOAD_GENERATION.get().wrapping_add(1));
            CONNECTIONS_LOAD_GENERATION.set(CONNECTIONS_LOAD_GENERATION.get().wrapping_add(1));
            TREE_LOAD_GENERATION.set(TREE_LOAD_GENERATION.get().wrapping_add(1));
            discard_connection_url();
            clear_browser_session();
            set_text("auth-value", "Logged out");
            set_hidden("login", false);
            set_hidden("logout", true);
            set_text("value-state", "Log in to view values");
            hide_new_value_row();
            clear_value_rows();
            set_loaded_textarea("json-content", "");
            set_text("value-count", "0 values");
            clear_connection_rows(&ESTATE_CONNECTION_TABLE);
            clear_connection_rows(&PATH_CONNECTION_TABLE);
            CONNECTIONS.with_borrow_mut(Vec::clear);
            TREE_NODES.with_borrow_mut(Vec::clear);
            let _ = render_tree(&[]);
            set_text("config-tree-state", "Log in to browse");
            set_text("connection-state", "Log in to view connections");
            focus("login");
        });
        let _ = logout.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    install_configuration_actions(&document);
    install_connections_actions(&document);
    install_tree_actions(&document);
    install_unsaved_guard(&document);
    install_sidebar_resizer(&document);
    restore_sidebar_width();
}

fn install_unsaved_guard(document: &Document) {
    // In-app links, tree clicks, and Back are guarded by the modal below, but a
    // reload, a tab close, or a typed URL never reaches any of them. Only the
    // browser's own prompt can interpose there; its wording is not ours to set.
    if let Some(browser_window) = window() {
        let callback = Closure::<dyn FnMut(_)>::new(|event: Event| {
            if has_unsaved_edits() {
                event.prevent_default();
            }
        });
        let _ = browser_window
            .add_event_listener_with_callback("beforeunload", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(keep) = document.get_element_by_id("keep-editing") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| keep_editing());
        let _ = keep.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(discard) = document.get_element_by_id("discard-changes") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| discard_changes());
        let _ =
            discard.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(dialog) = document.get_element_by_id("unsaved-dialog") {
        // Escape closes a native dialog without either button; that is a
        // decision to stay, so drop the pending route.
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            PENDING_NAVIGATION.with_borrow_mut(Option::take);
        });
        let _ = dialog.add_event_listener_with_callback("close", callback.as_ref().unchecked_ref());
        callback.forget();
    }
}

/// Drag and keyboard control for the sidebar separator. The width is a CSS
/// custom property on the layout grid, so nothing else needs to know about it.
fn install_sidebar_resizer(document: &Document) {
    let Some(resizer) = document.get_element_by_id("sidebar-resizer") else {
        return;
    };
    let handle = resizer.clone();
    let callback = Closure::<dyn FnMut(_)>::new(move |event: PointerEvent| {
        event.prevent_default();
        let _ = handle.set_pointer_capture(event.pointer_id());
        SIDEBAR_DRAG_POINTER.set(Some(event.pointer_id()));
    });
    let _ =
        resizer.add_event_listener_with_callback("pointerdown", callback.as_ref().unchecked_ref());
    callback.forget();

    let callback = Closure::<dyn FnMut(_)>::new(move |event: PointerEvent| {
        if SIDEBAR_DRAG_POINTER.get() != Some(event.pointer_id()) {
            return;
        }
        event.prevent_default();
        // Measure from the grid's own left edge rather than the viewport's, so
        // any future gutter or centred shell does not silently offset the
        // handle from the pointer by exactly that width.
        set_sidebar_width(f64::from(event.client_x()) - layout_left());
    });
    let _ =
        resizer.add_event_listener_with_callback("pointermove", callback.as_ref().unchecked_ref());
    callback.forget();

    for event_name in ["pointerup", "pointercancel"] {
        let handle = resizer.clone();
        let callback = Closure::<dyn FnMut(_)>::new(move |event: PointerEvent| {
            if SIDEBAR_DRAG_POINTER.get() == Some(event.pointer_id()) {
                let _ = handle.release_pointer_capture(event.pointer_id());
                SIDEBAR_DRAG_POINTER.set(None);
            }
        });
        let _ =
            resizer.add_event_listener_with_callback(event_name, callback.as_ref().unchecked_ref());
        callback.forget();
    }

    let callback = Closure::<dyn FnMut(_)>::new(move |event: KeyboardEvent| {
        let step = match event.key().as_str() {
            "ArrowLeft" => -SIDEBAR_KEY_STEP,
            "ArrowRight" => SIDEBAR_KEY_STEP,
            _ => return,
        };
        event.prevent_default();
        set_sidebar_width(sidebar_width() + step);
    });
    let _ = resizer.add_event_listener_with_callback("keydown", callback.as_ref().unchecked_ref());
    callback.forget();
}

fn layout_left() -> f64 {
    element::<HtmlElement>("layout").map_or(0.0, |layout| layout.get_bounding_client_rect().left())
}

fn sidebar_width() -> f64 {
    window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id("sidebar-resizer"))
        .and_then(|resizer| resizer.get_attribute("aria-valuenow"))
        .and_then(|width| width.parse::<f64>().ok())
        .unwrap_or(SIDEBAR_DEFAULT_WIDTH)
}

fn set_sidebar_width(width: f64) {
    let width = width.clamp(SIDEBAR_MIN_WIDTH, SIDEBAR_MAX_WIDTH).round();
    if let Some(layout) = element::<HtmlElement>("layout") {
        let _ = layout
            .style()
            .set_property("--sidebar-width", &format!("{width}px"));
    }
    if let Some(resizer) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id("sidebar-resizer"))
    {
        let _ = resizer.set_attribute("aria-valuenow", &width.to_string());
    }
    if let Ok(storage) = local_storage() {
        let _ = storage.set_item(SIDEBAR_WIDTH_KEY, &width.to_string());
    }
}

fn restore_sidebar_width() {
    let stored = local_storage()
        .ok()
        .and_then(|storage| storage.get_item(SIDEBAR_WIDTH_KEY).ok().flatten())
        .and_then(|width| width.parse::<f64>().ok())
        .filter(|width| width.is_finite());
    if let Some(width) = stored {
        set_sidebar_width(width);
    }
}

fn install_route_link(document: &Document, id: &str, route: Route) {
    if let Some(link) = document.get_element_by_id(id) {
        let callback = Closure::<dyn FnMut(_)>::new(move |event: Event| {
            event.prevent_default();
            guarded_navigate(route.clone());
        });
        let _ = link.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
}

#[allow(clippy::too_many_lines)]
fn install_configuration_actions(document: &Document) {
    if let Some(form) = document.get_element_by_id("path-form") {
        let callback = Closure::<dyn FnMut(_)>::new(|event: Event| {
            event.prevent_default();
            open_selected_path();
        });
        let _ = form.add_event_listener_with_callback("submit", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    install_path_selector_actions(document);
    if let Some(mode) = document.get_element_by_id("json-mode") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            let enabled =
                element::<HtmlInputElement>("json-mode").is_some_and(|input| input.checked());
            JSON_MODE.set(enabled);
            update_configuration_mode();
            spawn_local(async { load_current_configuration().await });
        });
        let _ = mode.add_event_listener_with_callback("change", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(save) = document.get_element_by_id("save-json") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            spawn_local(async { save_json_subtree().await });
        });
        let _ = save.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(editor) = document.get_element_by_id("json-content") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            CONFIGURATION_LOAD_GENERATION.set(CONFIGURATION_LOAD_GENERATION.get().wrapping_add(1));
            set_text("value-state", "Edited");
            validate_json_editor();
        });
        let _ = editor.add_event_listener_with_callback("input", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(add) = document.get_element_by_id("add-value") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            show_new_value_row();
        });
        let _ = add.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(classification) = document.get_element_by_id("new-value-secret") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            update_new_value_classification();
        });
        let _ = classification
            .add_event_listener_with_callback("change", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(cancel) = document.get_element_by_id("cancel-new-value") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            hide_new_value_row();
            focus("add-value");
        });
        let _ = cancel.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(save) = document.get_element_by_id("save-new-value") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            spawn_local(async { save_new_value().await });
        });
        let _ = save.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(name) = document.get_element_by_id("new-value-name") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            validate_name_field();
            update_new_save_state();
        });
        let _ = name.add_event_listener_with_callback("input", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(value) = document.get_element_by_id("new-value-content") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            validate_value_field("new-value-content", "new-value-error");
            update_new_save_state();
        });
        let _ = value.add_event_listener_with_callback("input", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(value) = document.get_element_by_id("new-secret-content") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            validate_secret_field("new-secret-content", "new-value-error");
            update_new_save_state();
        });
        let _ = value.add_event_listener_with_callback("input", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(toggle) = document.get_element_by_id("toggle-new-secret") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            toggle_secret_input("new-secret-content", "toggle-new-secret");
        });
        let _ = toggle.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(cancel) = document.get_element_by_id("cancel-delete") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| cancel_delete());
        let _ = cancel.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(confirm) = document.get_element_by_id("confirm-delete") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            spawn_local(async { delete_selected_value().await });
        });
        let _ =
            confirm.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(cancel) = document.get_element_by_id("cancel-add-path") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| cancel_add_path());
        let _ = cancel.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(confirm) = document.get_element_by_id("confirm-add-path") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            spawn_local(async { add_selected_path().await });
        });
        let _ =
            confirm.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
}

fn install_path_selector_actions(document: &Document) {
    if let Some(path) = document.get_element_by_id("selected-path") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            validate_path_field();
            open_path_options();
            filter_path_options();
        });
        let _ = path.add_event_listener_with_callback("input", callback.as_ref().unchecked_ref());
        callback.forget();

        for event_name in ["focus", "pointerdown"] {
            let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
                open_path_options();
                spawn_local(async { refresh_path_options().await });
            });
            let _ = path
                .add_event_listener_with_callback(event_name, callback.as_ref().unchecked_ref());
            callback.forget();
        }

        let callback =
            Closure::<dyn FnMut(_)>::new(|event: KeyboardEvent| match event.key().as_str() {
                "ArrowDown" => {
                    event.prevent_default();
                    if !path_options_expanded() {
                        open_path_options();
                        filter_path_options();
                    }
                    move_active_path_option(1);
                }
                "ArrowUp" => {
                    event.prevent_default();
                    if !path_options_expanded() {
                        open_path_options();
                        filter_path_options();
                    }
                    move_active_path_option(-1);
                }
                "Enter" => {
                    event.prevent_default();
                    select_active_path_option();
                    open_selected_path();
                }
                "Escape" => {
                    event.prevent_default();
                    close_path_options();
                }
                "Tab" => close_path_options(),
                _ => {}
            });
        let _ = path.add_event_listener_with_callback("keydown", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    let callback = Closure::<dyn FnMut(_)>::new(|event: Event| {
        let inside_picker = event
            .target()
            .and_then(|target| target.dyn_into::<Element>().ok())
            .and_then(|target| target.closest(".path-picker").ok().flatten())
            .is_some();
        if !inside_picker {
            close_path_options();
        }
    });
    let _ =
        document.add_event_listener_with_callback("pointerdown", callback.as_ref().unchecked_ref());
    callback.forget();

    if let Some(browser_window) = window() {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            if !path_options_expanded() {
                return;
            }
            if let Some(input) = element::<HtmlInputElement>("selected-path")
                && let Some(options) = window()
                    .and_then(|window| window.document())
                    .and_then(|document| document.get_element_by_id("existing-paths"))
            {
                size_path_options(&input, &options);
            }
        });
        let _ = browser_window
            .add_event_listener_with_callback("resize", callback.as_ref().unchecked_ref());
        callback.forget();
    }
}

fn open_selected_path() {
    if let Ok(path) = selected_namespace() {
        close_path_options();
        guarded_navigate(Route::Configuration(path));
    } else {
        validate_path_field();
    }
}

fn open_path_options() {
    let Some(input) = element::<HtmlInputElement>("selected-path") else {
        return;
    };
    let Some(options) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id("existing-paths"))
    else {
        return;
    };
    size_path_options(&input, &options);
    let _ = input.set_attribute("aria-expanded", "true");
    let _ = options.remove_attribute("hidden");
    for option in path_option_elements() {
        let _ = option.remove_attribute("hidden");
    }
    set_active_path_option(None);
}

fn path_options_expanded() -> bool {
    element::<HtmlInputElement>("selected-path")
        .is_some_and(|input| input.get_attribute("aria-expanded").as_deref() == Some("true"))
}

fn close_path_options() {
    if let Some(input) = element::<HtmlInputElement>("selected-path") {
        let _ = input.set_attribute("aria-expanded", "false");
        let _ = input.remove_attribute("aria-activedescendant");
    }
    set_hidden("existing-paths", true);
    set_active_path_option(None);
}

fn size_path_options(input: &HtmlInputElement, options: &Element) {
    let Some(window) = window() else {
        return;
    };
    let Some(viewport_height) = window
        .inner_height()
        .ok()
        .and_then(|height| height.as_f64())
    else {
        return;
    };
    let rect = input.get_bounding_client_rect();
    let below = (viewport_height - rect.bottom() - 12.0).max(48.0);
    let above = (rect.top() - 12.0).max(48.0);
    let opens_above = below < 240.0 && above > below;
    let available = if opens_above { above } else { below }.min(560.0);
    options.set_class_name(if opens_above {
        "path-options above"
    } else {
        "path-options"
    });
    if let Some(options) = options.dyn_ref::<web_sys::HtmlElement>() {
        let _ = options
            .style()
            .set_property("max-height", &format!("{available}px"));
    }
}

fn filter_path_options() {
    let Some(input) = element::<HtmlInputElement>("selected-path") else {
        return;
    };
    let query = input.value().to_ascii_lowercase();
    for option in path_option_elements() {
        let visible = option
            .get_attribute("data-path")
            .is_some_and(|path| path.starts_with(&query));
        if visible {
            let _ = option.remove_attribute("hidden");
        } else {
            let _ = option.set_attribute("hidden", "");
        }
    }
    set_active_path_option(None);
}

fn path_option_elements() -> Vec<Element> {
    let Some(options) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id("existing-paths"))
    else {
        return Vec::new();
    };
    let children = options.children();
    (0..children.length())
        .filter_map(|index| children.item(index))
        .collect()
}

fn move_active_path_option(direction: i32) {
    let visible = path_option_elements()
        .into_iter()
        .enumerate()
        .filter_map(|(index, option)| (!option.has_attribute("hidden")).then_some(index))
        .collect::<Vec<_>>();
    if visible.is_empty() {
        set_active_path_option(None);
        return;
    }
    let current = ACTIVE_PATH_OPTION.get();
    let position = current.and_then(|current| visible.iter().position(|index| *index == current));
    let next = match (position, direction) {
        (Some(0) | None, -1) => *visible.last().unwrap_or(&visible[0]),
        (Some(position), -1) => visible[position - 1],
        (Some(position), _) if position + 1 < visible.len() => visible[position + 1],
        _ => visible[0],
    };
    set_active_path_option(Some(next));
}

fn set_active_path_option(active_index: Option<usize>) {
    ACTIVE_PATH_OPTION.set(active_index);
    let options = path_option_elements();
    for (index, option) in options.iter().enumerate() {
        let active = Some(index) == active_index;
        option.set_class_name(if active {
            "path-option active"
        } else {
            "path-option"
        });
        let _ = option.set_attribute("aria-selected", if active { "true" } else { "false" });
    }
    let Some(input) = element::<HtmlInputElement>("selected-path") else {
        return;
    };
    if let Some(active) = active_index.and_then(|index| options.get(index)) {
        let _ = input.set_attribute("aria-activedescendant", &active.id());
        active.scroll_into_view_with_bool(false);
    } else {
        let _ = input.remove_attribute("aria-activedescendant");
    }
}

fn select_active_path_option() {
    let Some(index) = ACTIVE_PATH_OPTION.get() else {
        return;
    };
    let Some(path) = path_option_elements()
        .get(index)
        .and_then(|option| option.get_attribute("data-path"))
    else {
        return;
    };
    if let Some(input) = element::<HtmlInputElement>("selected-path") {
        input.set_value(&path);
        validate_path_field();
    }
    close_path_options();
}

/// Every in-app route change runs through here so an unsaved value edit can
/// interpose a confirmation before the current view is torn down.
fn guarded_navigate(route: Route) {
    if has_unsaved_edits() {
        open_unsaved_dialog(route, false);
        return;
    }
    navigate(&route);
}

/// Reports whether any editor on the Configuration view holds text that has not
/// been sent to the service.
///
/// This is derived from the DOM rather than tracked in a flag: every editable
/// field either records what was loaded into it (`data-loaded`) or is empty when
/// clean, so cancelling an edit clears the condition without any bookkeeping.
fn has_unsaved_edits() -> bool {
    if !element_is_hidden("new-value-row")
        && (element::<HtmlInputElement>("new-value-name").is_some_and(|it| !it.value().is_empty())
            || element::<HtmlTextAreaElement>("new-value-content")
                .is_some_and(|it| !it.value().is_empty())
            || element::<HtmlInputElement>("new-secret-content")
                .is_some_and(|it| !it.value().is_empty()))
    {
        return true;
    }
    // Scoped to the value rows and the JSON editor rather than swept from the
    // document: everything editable here lives in one of those two places, and
    // the page now carries two connection forms whose fields must never be
    // mistaken for a value edit.
    if element::<HtmlTextAreaElement>("json-content")
        .as_ref()
        .is_some_and(edited_textarea)
    {
        return true;
    }
    let Some(rows) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id("values-body"))
    else {
        return false;
    };
    let editors = rows.get_elements_by_tag_name("textarea");
    for index in 0..editors.length() {
        if editors
            .item(index)
            .and_then(|editor| editor.dyn_into::<HtmlTextAreaElement>().ok())
            .as_ref()
            .is_some_and(edited_textarea)
        {
            return true;
        }
    }
    let replacements = rows.get_elements_by_tag_name("input");
    for index in 0..replacements.length() {
        if replacements
            .item(index)
            .and_then(|input| input.dyn_into::<HtmlInputElement>().ok())
            .is_some_and(|input| input.type_() == "password" && !input.value().is_empty())
        {
            return true;
        }
    }
    false
}

/// A textarea holds an edit when its text differs from what was loaded into it.
/// One without a loaded marker — a revealed secret, say — is never an edit.
fn edited_textarea(editor: &HtmlTextAreaElement) -> bool {
    editor
        .get_attribute("data-loaded")
        .is_some_and(|loaded| editor.value() != loaded)
}

fn navigate(route: &Route) {
    navigate_with(route, false);
}

fn navigate_with(route: &Route, replace: bool) {
    discard_connection_url();
    let url = route_url(route);
    if let Some(window) = window()
        && let Ok(history) = window.history()
    {
        let _ = if replace {
            history.replace_state_with_url(&JsValue::NULL, "", Some(&url))
        } else {
            history.push_state_with_url(&JsValue::NULL, "", Some(&url))
        };
    }
    render_route(route);
    spawn_local(async {
        refresh_views().await;
    });
}

async fn refresh_views() {
    load_current_configuration().await;
    load_current_connections().await;
    load_downloads().await;
    load_tree().await;
}

/// Re-reads the selected path after a mutation, together with the sidebar tree:
/// adding the first value under a namespace creates a node, and removing the
/// last one takes it away.
async fn reload_configuration() {
    load_current_configuration().await;
    load_tree().await;
}

/// Holds the route the operator asked for until they choose between discarding
/// the edit and staying put. `from_history` records that a Back or Forward press
/// asked for it, which changes how discarding has to reach the destination.
fn open_unsaved_dialog(route: Route, from_history: bool) {
    PENDING_NAVIGATION.with_borrow_mut(|pending| *pending = Some(route));
    PENDING_FROM_HISTORY.set(from_history);
    if let Some(dialog) = element::<HtmlDialogElement>("unsaved-dialog") {
        let _ = dialog.show_modal();
        focus("keep-editing");
    }
}

fn keep_editing() {
    PENDING_NAVIGATION.with_borrow_mut(Option::take);
    PENDING_FROM_HISTORY.set(false);
    close_dialog("unsaved-dialog");
}

fn discard_changes() {
    let pending = PENDING_NAVIGATION.with_borrow_mut(Option::take);
    let from_history = PENDING_FROM_HISTORY.replace(false);
    close_dialog("unsaved-dialog");
    // Leaving reloads the destination, which replaces every editor; the edit is
    // discarded by that reload rather than by clearing fields here.
    if let Some(route) = pending {
        // A pop already moved history; the guard then pushed the source back so
        // the operator could decide. Overwrite that restored entry rather than
        // appending a third, or the next Back would return to the page they
        // just chose to leave instead of continuing backward.
        navigate_with(&route, from_history);
    }
}

/// Re-pushes the route currently rendered. A history pop cannot be prevented,
/// so the guard restores the address bar and then asks the same question an
/// in-app link would have asked before leaving.
fn restore_current_url() {
    let url = CURRENT_URL.with_borrow(Clone::clone);
    if url.is_empty() {
        return;
    }
    if let Some(window) = window()
        && let Ok(history) = window.history()
    {
        let _ = history.push_state_with_url(&JsValue::NULL, "", Some(&url));
    }
}

fn render_route(route: &Route) {
    CURRENT_URL.with_borrow_mut(|url| *url = route_url(route));
    let configuration = matches!(route, Route::Configuration(_));
    let connections = matches!(route, Route::Connections);
    let downloads = matches!(route, Route::Downloads);
    let system = matches!(route, Route::System);
    set_hidden("system-page", !system);
    set_hidden("configuration-page", !configuration);
    set_hidden("connections-page", !connections);
    set_hidden("downloads-page", !downloads);
    set_active("system-status-link", system);
    set_active("configuration-values-link", configuration);
    set_active("managed-connections-link", connections);
    set_active("downloads-link", downloads);
    if let Route::Configuration(path) = route {
        let canonical_url = route_url(route);
        if let Some(window) = window()
            && window.location().pathname().ok().as_deref() != Some(canonical_url.as_str())
            && let Ok(history) = window.history()
        {
            let _ = history.replace_state_with_url(&JsValue::NULL, "", Some(&canonical_url));
        }
        if let Some(input) = element::<HtmlInputElement>("selected-path") {
            input.set_value(&absolute_path(path));
        }
        validate_path_field();
        if element::<HtmlElement>("path-connection-root")
            .is_some_and(|root| root.text_content().as_deref() != Some(path.as_str()))
        {
            // The form is now aimed at a different namespace. A half-filled
            // draft carried over would be armed to grant standing access to a
            // root the operator never chose it for.
            reset_path_connection_form();
        }
        set_text("path-connection-root", path.as_str());
        render_path_connections();
    }
    let nodes = TREE_NODES.with_borrow(Clone::clone);
    if let Err(error) = render_tree(&nodes) {
        show_error(error.message());
    }
}

fn set_active(id: &str, active: bool) {
    if let Some(element) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id(id))
    {
        if active {
            element.set_class_name("active");
            let _ = element.set_attribute("aria-current", "page");
        } else {
            element.set_class_name("");
            let _ = element.remove_attribute("aria-current");
        }
    }
}

fn route_from_location() -> Route {
    let path = window()
        .and_then(|window| window.location().pathname().ok())
        .unwrap_or_else(|| "/".into());
    route_from_path(&path)
}

fn route_from_path(path: &str) -> Route {
    if path == "/configuration" || path == "/configuration/" {
        return Route::Configuration(ConfigPath::root());
    }
    if path == "/connections" || path == "/connections/" {
        return Route::Connections;
    }
    if path == "/downloads" || path == "/downloads/" {
        return Route::Downloads;
    }
    if let Some(relative) = path.strip_prefix("/configuration/")
        && let Ok(path) = ConfigPath::parse_operation(format!("/{relative}"))
    {
        return Route::Configuration(path);
    }
    Route::System
}

fn route_url(route: &Route) -> String {
    match route {
        Route::System => "/".into(),
        Route::Configuration(path) if path.as_str() == "/" => "/configuration/".into(),
        Route::Configuration(path) => format!("/configuration{}", path.as_str()),
        Route::Connections => "/connections/".into(),
        Route::Downloads => "/downloads".into(),
    }
}

fn logged_in() -> bool {
    TOKENS.with_borrow(Option::is_some)
}

/// The path the tree currently highlights, or `None` off the Configuration
/// route.
fn selected_tree_path() -> Option<ConfigPath> {
    match route_from_location() {
        Route::Configuration(path) => Some(path),
        Route::System | Route::Connections | Route::Downloads => None,
    }
}

/// Reads the whole readable configuration once per load so the sidebar can
/// render the full namespace tree and mark the namespaces that directly hold
/// values.
///
/// `ListValues.paths` already carries the namespace tree, but only as
/// *ancestors*, which cannot distinguish a namespace holding values from one
/// holding nothing but children. `GetSubTree` on the root answers that exactly;
/// a principal scoped to a prefix is refused there, so the namespace list is the
/// documented fallback and the tree simply renders without bold markers.
async fn load_tree() {
    let generation = TREE_LOAD_GENERATION.get().wrapping_add(1);
    TREE_LOAD_GENERATION.set(generation);
    if !logged_in() {
        CONNECTIONS.with_borrow_mut(Vec::clear);
        TREE_NODES.with_borrow_mut(Vec::clear);
        let _ = render_tree(&[]);
        render_path_connections();
        set_text("config-tree-state", "Log in to browse");
        return;
    }
    let Ok(config) = app_config() else {
        set_text("config-tree-state", "Tree unavailable");
        return;
    };
    // `#config-tree-state` is a live region, and the tree reloads on every
    // navigation. Announcing "Loading" each time would narrate an ambient count
    // the operator did not ask about, so only say it when there is nothing on
    // screen yet to reload.
    if TREE_NODES.with_borrow(Vec::is_empty) {
        set_text("config-tree-state", "Loading");
    }
    let selected = selected_tree_path().unwrap_or_else(ConfigPath::root);
    // A connection listing failure must not cost the operator the whole tree,
    // but it must not be reported as an empty estate either: an authoritative
    // "0 connections" at a path that actually has one invites minting a second,
    // redundant credential. Keep the last good listing and say it is stale.
    let listed = value_client(&config).list_managed_connections().await.ok();
    let model = match value_client(&config).get_subtree(&ConfigPath::root()).await {
        Ok(subtree) => {
            let paths = subtree
                .values
                .into_iter()
                .map(|value| value.path)
                .collect::<Vec<_>>();
            Some((namespace_labels(&paths), value_parents_of(&paths)))
        }
        Err(_) => value_client(&config)
            .list_values(&selected)
            .await
            .ok()
            .map(|listing| {
                // `listing.paths` already carries the server's display form for
                // each namespace (its first-created row's case), so this is a
                // direct copy, not a re-derivation.
                let mut labels = listing
                    .paths
                    .iter()
                    .map(|path| (path.as_str().to_owned(), path.display_str().to_owned()))
                    .collect::<BTreeMap<_, _>>();
                labels.insert("/".to_owned(), "/".to_owned());
                (labels, BTreeSet::new())
            }),
    };
    if TREE_LOAD_GENERATION.get() != generation {
        return;
    }
    let listed_failed = listed.is_none();
    if let Some(connections) = listed {
        CONNECTIONS.with_borrow_mut(|slot| *slot = connections);
    }
    let roots = CONNECTIONS.with_borrow(|connections| {
        connections
            .iter()
            .map(|connection| connection.root.as_str().to_owned())
            .collect::<BTreeSet<_>>()
    });
    render_path_connections();
    if listed_failed {
        set_text("path-connection-count", "Access URLs unavailable");
    }
    let Some((labels, value_parents)) = model else {
        set_text("config-tree-state", "Tree unavailable");
        return;
    };
    let nodes = build_tree(&labels, &value_parents, &roots);
    let count = nodes.len();
    TREE_NODES.with_borrow_mut(|slot| slot.clone_from(&nodes));
    if let Err(error) = render_tree(&nodes) {
        show_error(error.message());
        return;
    }
    // Only write the count when it actually changed, so an unchanged tree does
    // not re-announce itself after every click.
    let summary = format!("{count} path{}", if count == 1 { "" } else { "s" });
    if current_text("config-tree-state").as_deref() != Some(summary.as_str()) {
        set_text("config-tree-state", &summary);
    }
}

fn render_tree(nodes: &[TreeNode]) -> Result<(), ClientError> {
    let document = window()
        .and_then(|window| window.document())
        .ok_or_else(browser_error)?;
    let tree = document
        .get_element_by_id("config-tree")
        .ok_or_else(browser_error)?;
    // Rebuilding replaces every node, including whichever one holds focus.
    // Activating a node navigates and re-renders, and the tree reloads
    // asynchronously as well, so without this a keyboard user is dropped onto
    // `<body>` mid-interaction and has to tab all the way back in.
    let had_focus = document
        .active_element()
        .is_some_and(|active| tree.contains(Some(&active)));
    tree.set_text_content(None);
    let selected = selected_tree_path();
    let selected_index = nodes
        .iter()
        .position(|node| selected.as_ref() == Some(&node.path));
    // Exactly one node is ever in the tab order; without a selection that is the
    // root, which is also the node the Configuration view opens on.
    let focus_index = selected_index.or_else(|| (!nodes.is_empty()).then_some(0));
    for (index, node) in nodes.iter().enumerate() {
        // Preorder ordering means a node has children exactly when the next one
        // is deeper. The tree never collapses, so parents are always expanded.
        let has_children = nodes
            .get(index + 1)
            .is_some_and(|next| next.depth > node.depth);
        let item = build_tree_node(
            &document,
            node,
            index,
            Some(index) == selected_index,
            has_children,
        )?;
        item.set_attribute(
            "tabindex",
            if Some(index) == focus_index {
                "0"
            } else {
                "-1"
            },
        )
        .map_err(|_| browser_error())?;
        append(&tree, &item)?;
    }
    if had_focus && let Some(index) = focus_index {
        focus(&format!("tree-node-{index}"));
    }
    Ok(())
}

fn build_tree_node(
    document: &Document,
    node: &TreeNode,
    index: usize,
    selected: bool,
    has_children: bool,
) -> Result<Element, ClientError> {
    let mut class = String::from("tree-node");
    if node.has_values {
        class.push_str(" has-values");
    }
    if selected {
        class.push_str(" selected");
    }
    let item = create_element(document, "li", Some(&class))?;
    let node_id = format!("tree-node-{index}");
    let level = (node.depth + 1).to_string();
    for (name, value) in [
        ("role", "treeitem"),
        ("id", node_id.as_str()),
        ("aria-level", level.as_str()),
        ("aria-selected", if selected { "true" } else { "false" }),
        ("data-path", node.path.as_str()),
    ] {
        item.set_attribute(name, value)
            .map_err(|_| browser_error())?;
    }
    if has_children {
        item.set_attribute("aria-expanded", "true")
            .map_err(|_| browser_error())?;
    }
    if let Some(styled) = item.dyn_ref::<HtmlElement>() {
        let indent = 8 + node.depth * 14;
        let _ = styled
            .style()
            .set_property("padding-left", &format!("{indent}px"));
    }
    if node.has_connection {
        append(&item, &key_icon(document)?)?;
    }
    let label = create_element(document, "span", Some("tree-label"))?;
    label.set_text_content(Some(&node.display));
    append(&item, &label)?;
    if node.has_connection {
        let annotation = create_element(document, "span", Some("visually-hidden"))?;
        annotation.set_text_content(Some(" has an access URL"));
        append(&item, &annotation)?;
    }

    Ok(item)
}

/// Resolves the tree node an event landed on. Listeners live on the tree itself
/// rather than on each node, so a render allocates nothing: the tree is rebuilt
/// twice per navigation over the whole estate, and per-node closures would have
/// to be leaked every time to stay callable from JavaScript.
fn event_tree_node(event: &Event) -> Option<(usize, ConfigPath)> {
    let item = event
        .target()
        .and_then(|target| target.dyn_into::<Element>().ok())
        .and_then(|target| target.closest("[data-path]").ok().flatten())?;
    let path = ConfigPath::parse(item.get_attribute("data-path")?).ok()?;
    let index = item
        .id()
        .strip_prefix("tree-node-")
        .and_then(|index| index.parse::<usize>().ok())?;
    Some((index, path))
}

/// Installs the tree's two delegated listeners. Nodes carry `data-path` and a
/// positional id, which is everything either handler needs.
fn install_tree_actions(document: &Document) {
    let Some(tree) = document.get_element_by_id("config-tree") else {
        return;
    };
    let callback = Closure::<dyn FnMut(_)>::new(move |event: Event| {
        if let Some((_, path)) = event_tree_node(&event) {
            guarded_navigate(Route::Configuration(path));
        }
    });
    let _ = tree.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
    callback.forget();

    let callback = Closure::<dyn FnMut(_)>::new(move |event: KeyboardEvent| {
        let Some((index, path)) = event_tree_node(event.as_ref()) else {
            return;
        };
        match event.key().as_str() {
            "Enter" | " " => {
                event.prevent_default();
                guarded_navigate(Route::Configuration(path));
            }
            "ArrowDown" => {
                event.prevent_default();
                focus_tree_node(index.saturating_add(1));
            }
            "ArrowUp" => {
                event.prevent_default();
                // Neither direction wraps, per the WAI-ARIA tree pattern: a
                // tree is not the path-picker listbox, where wrapping is the
                // convention.
                focus_tree_node(index.saturating_sub(1));
            }
            "Home" => {
                event.prevent_default();
                focus_tree_node(0);
            }
            "End" => {
                event.prevent_default();
                focus_tree_node(usize::MAX);
            }
            _ => {}
        }
    });
    let _ = tree.add_event_listener_with_callback("keydown", callback.as_ref().unchecked_ref());
    callback.forget();
}

/// Moves the roving tab stop to `index`, clamped to the rendered nodes.
fn focus_tree_node(index: usize) {
    let count = TREE_NODES.with_borrow(Vec::len);
    if count == 0 {
        return;
    }
    let index = index.min(count - 1);
    let Some(document) = window().and_then(|window| window.document()) else {
        return;
    };
    for position in 0..count {
        if let Some(node) = document.get_element_by_id(&format!("tree-node-{position}")) {
            let _ = node.set_attribute("tabindex", if position == index { "0" } else { "-1" });
        }
    }
    focus(&format!("tree-node-{index}"));
}

/// A small key, drawn rather than imported so the sidebar needs no icon asset.
fn key_icon(document: &Document) -> Result<Element, ClientError> {
    let svg = document
        .create_element_ns(Some("http://www.w3.org/2000/svg"), "svg")
        .map_err(|_| browser_error())?;
    for (name, value) in [
        ("class", "tree-key"),
        ("viewBox", "0 0 16 16"),
        ("fill", "none"),
        ("stroke", "currentColor"),
        ("stroke-width", "1.6"),
        ("stroke-linecap", "round"),
        ("aria-hidden", "true"),
        ("focusable", "false"),
    ] {
        svg.set_attribute(name, value)
            .map_err(|_| browser_error())?;
    }
    let bow = document
        .create_element_ns(Some("http://www.w3.org/2000/svg"), "circle")
        .map_err(|_| browser_error())?;
    for (name, value) in [("cx", "5"), ("cy", "8"), ("r", "3.2")] {
        bow.set_attribute(name, value)
            .map_err(|_| browser_error())?;
    }
    append(&svg, &bow)?;
    let blade = document
        .create_element_ns(Some("http://www.w3.org/2000/svg"), "path")
        .map_err(|_| browser_error())?;
    blade
        .set_attribute("d", "M8.2 8h6.3M12.5 8v2.4")
        .map_err(|_| browser_error())?;
    append(&svg, &blade)?;
    Ok(svg)
}

/// One installer as described by `/dist/manifest.json`.
struct InstallerEntry {
    file: String,
    checksum: Option<String>,
    size: Option<f64>,
}

/// Populates the Downloads view from the server's installer manifest. Needs no
/// authentication; the installers are public artifacts. A no-op unless the
/// Downloads route is active, so it is safe to call on every navigation.
async fn load_downloads() {
    if !matches!(route_from_location(), Route::Downloads) {
        return;
    }
    set_text("downloads-state", "Loading");
    if let Ok(entries) = fetch_installer_manifest().await {
        render_downloads(&entries);
    } else {
        clear_downloads_list();
        set_hidden("downloads-list", true);
        set_hidden("empty-downloads", true);
        set_text("downloads-state", "Unavailable");
    }
}

async fn fetch_installer_manifest() -> Result<Vec<InstallerEntry>, ClientError> {
    let response = fetch("/dist/manifest.json", "GET", None, &[]).await?;
    if !response.ok() {
        return Err(browser_error());
    }
    let json = JsFuture::from(response.json().map_err(|_| browser_error())?)
        .await
        .map_err(|_| browser_error())?;
    let installers =
        Reflect::get(&json, &JsValue::from_str("installers")).map_err(|_| browser_error())?;
    let mut entries = Vec::new();
    for item in js_sys::Array::from(&installers).iter() {
        let Ok(file) = string_property(&item, "file") else {
            continue;
        };
        let checksum = Reflect::get(&item, &JsValue::from_str("checksum"))
            .ok()
            .and_then(|value| value.as_string());
        let size = Reflect::get(&item, &JsValue::from_str("size"))
            .ok()
            .and_then(|value| value.as_f64());
        entries.push(InstallerEntry {
            file,
            checksum,
            size,
        });
    }
    Ok(entries)
}

fn clear_downloads_list() {
    if let Some(list) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id("downloads-list"))
    {
        list.set_text_content(Some(""));
    }
}

fn render_downloads(entries: &[InstallerEntry]) {
    let Some(document) = window().and_then(|window| window.document()) else {
        return;
    };
    let Some(list) = document.get_element_by_id("downloads-list") else {
        return;
    };
    list.set_text_content(Some(""));
    if entries.is_empty() {
        set_hidden("downloads-list", true);
        set_hidden("empty-downloads", false);
        set_text("downloads-state", "No installers");
        return;
    }
    set_hidden("empty-downloads", true);
    set_hidden("downloads-list", false);
    let origin = window()
        .and_then(|window| window.location().origin().ok())
        .unwrap_or_default();
    for entry in entries {
        if let Ok(card) = build_download_card(&document, entry, &origin) {
            let _ = append(&list, &card);
        }
    }
    let count = entries.len();
    set_text(
        "downloads-state",
        &format!("{count} installer{}", if count == 1 { "" } else { "s" }),
    );
}

fn build_download_card(
    document: &Document,
    entry: &InstallerEntry,
    origin: &str,
) -> Result<Element, ClientError> {
    let card = create_element(document, "section", Some("download-card"))?;

    let heading = create_element(document, "h2", None)?;
    let name = create_element(document, "code", None)?;
    name.set_text_content(Some(&entry.file));
    append(&heading, &name)?;
    append(&card, &heading)?;

    let meta = create_element(document, "p", Some("status-text download-meta"))?;
    meta.set_text_content(Some(&human_size(entry.size)));
    if let Some(checksum) = &entry.checksum {
        let separator = create_element(document, "span", None)?;
        separator.set_text_content(Some(" \u{00b7} "));
        append(&meta, &separator)?;
        let link = create_element(document, "a", None)?;
        link.set_attribute("href", &format!("/dist/{checksum}"))
            .map_err(|_| browser_error())?;
        link.set_text_content(Some("sha256"));
        append(&meta, &link)?;
    }
    append(&card, &meta)?;

    let actions = create_element(document, "p", Some("download-actions"))?;
    let download = create_element(document, "a", Some("button-link"))?;
    download
        .set_attribute("href", &format!("/dist/{}", entry.file))
        .map_err(|_| browser_error())?;
    download
        .set_attribute("download", "")
        .map_err(|_| browser_error())?;
    download.set_text_content(Some("Download installer"));
    append(&actions, &download)?;
    append(&card, &actions)?;

    let command_label = create_element(document, "p", None)?;
    command_label.set_text_content(Some("Or download and run in one step:"));
    append(&card, &command_label)?;

    // A readable multi-line form. Newlines inside the single-quoted `sh -c`
    // script separate statements; the trailing `\` continues the long curl line.
    // `set -e` aborts on any failure (so a failed download never runs a partial
    // installer), and the trap keeps it a self-cleaning subshell.
    let url = format!("{origin}/dist/{}", entry.file);
    let command = [
        "sh -c '".to_owned(),
        "  set -e".to_owned(),
        "  d=$(mktemp -d)".to_owned(),
        "  trap \"rm -rf \\\"$d\\\"\" EXIT".to_owned(),
        format!("  curl -fsSL \"{url}\" \\"),
        "    -o \"$d/installer.sh\"".to_owned(),
        "  sh \"$d/installer.sh\"".to_owned(),
        "'".to_owned(),
    ]
    .join("\n");

    let command_block = create_element(document, "pre", Some("download-command"))?;
    // The block scrolls, so it must be keyboard-focusable for scroll access
    // (axe scrollable-region-focusable).
    command_block
        .set_attribute("tabindex", "0")
        .map_err(|_| browser_error())?;
    command_block
        .set_attribute("aria-label", "Install command")
        .map_err(|_| browser_error())?;
    let command_code = create_element(document, "code", None)?;
    command_code.set_text_content(Some(&command));
    append(&command_block, &command_code)?;
    append(&card, &command_block)?;

    let command_actions = create_element(document, "div", Some("download-command-actions"))?;
    let copy = create_element(document, "button", Some("secondary"))?;
    copy.set_attribute("type", "button")
        .map_err(|_| browser_error())?;
    copy.set_text_content(Some("Copy command"));
    let status = create_element(document, "span", Some("download-copy-status"))?;
    status
        .set_attribute("aria-live", "polite")
        .map_err(|_| browser_error())?;
    let command_for_copy = command.clone();
    let status_for_copy = status.clone();
    let callback = Closure::<dyn FnMut(_)>::new(move |_: Event| {
        let command = command_for_copy.clone();
        let status = status_for_copy.clone();
        spawn_local(async move { copy_to_clipboard(&command, &status).await });
    });
    copy.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())
        .map_err(|_| browser_error())?;
    callback.forget();
    append(&command_actions, &copy)?;
    append(&command_actions, &status)?;
    append(&card, &command_actions)?;

    Ok(card)
}

async fn copy_to_clipboard(text: &str, status: &Element) {
    let Some(clipboard) = window().map(|window| window.navigator().clipboard()) else {
        status.set_text_content(Some("Copy failed"));
        return;
    };
    match JsFuture::from(clipboard.write_text(text)).await {
        Ok(_) => status.set_text_content(Some("Copied")),
        Err(_) => status.set_text_content(Some("Copy failed")),
    }
}

fn human_size(size: Option<f64>) -> String {
    match size {
        Some(bytes) if bytes >= 1_048_576.0 => format!("{:.1} MB", bytes / 1_048_576.0),
        Some(bytes) if bytes >= 1024.0 => format!("{:.0} KB", bytes / 1024.0),
        Some(bytes) => format!("{bytes:.0} bytes"),
        None => "installer".to_owned(),
    }
}

fn absolute_path(path: &ConfigPath) -> String {
    path.display_str().to_owned()
}

fn selected_namespace() -> Result<ConfigPath, ClientError> {
    let value = element::<HtmlInputElement>("selected-path")
        .ok_or_else(browser_error)?
        .value();
    parse_absolute_path(&value)
}

fn parse_absolute_path(value: &str) -> Result<ConfigPath, ClientError> {
    if value == "/" {
        return Ok(ConfigPath::root());
    }
    ConfigPath::parse_operation(value).map_err(|_| invalid_path())
}

fn invalid_path() -> ClientError {
    ClientError::new(
        ErrorKind::InvalidRequest,
        "path must begin with / and contain only letters, numbers, hyphens, and underscores",
    )
}

fn value_client(config: &AppConfig) -> Client<BrowserTransport, MemoryAuthentication> {
    Client::new(
        BrowserTransport,
        MemoryAuthentication {
            client_id: config.client_id.clone(),
        },
    )
}

async fn load_current_configuration() {
    let generation = CONFIGURATION_LOAD_GENERATION.get().wrapping_add(1);
    CONFIGURATION_LOAD_GENERATION.set(generation);
    hide_new_value_row();
    clear_value_rows();
    set_loaded_textarea("json-content", "");
    let Route::Configuration(path) = route_from_location() else {
        return;
    };
    clear_error();
    set_text("value-state", "Loading");
    let json_mode = JSON_MODE.get();
    update_configuration_mode();
    if json_mode {
        set_loaded_textarea("json-content", "");
        set_validation("json-content", "json-error", None);
        set_text("value-count", "0 values");
    }
    let result = async {
        let config = app_config()?;
        if json_mode {
            value_client(&config)
                .get_subtree(&path)
                .await
                .map(ConfigurationData::SubTree)
        } else {
            value_client(&config)
                .list_values(&path)
                .await
                .map(ConfigurationData::Listing)
        }
    }
    .await;
    if CONFIGURATION_LOAD_GENERATION.get() != generation {
        return;
    }
    match result {
        Ok(ConfigurationData::Listing(listing)) => {
            if let Err(error) = render_listing(&listing) {
                show_error(error.message());
                return;
            }
            set_text("value-state", "Loaded");
        }
        Ok(ConfigurationData::SubTree(subtree)) => {
            match render_subtree_json(&path, &subtree.values) {
                Ok(json) => {
                    set_loaded_textarea("json-content", &json);
                    set_validation("json-content", "json-error", None);
                    let count = subtree.values.len();
                    set_text(
                        "value-count",
                        &format!("{count} {}", if count == 1 { "value" } else { "values" }),
                    );
                    set_text("value-state", "Loaded");
                }
                Err(error) => show_error(error.message()),
            }
        }
        Err(error) => show_error(error.message()),
    }
}

enum ConfigurationData {
    Listing(ValueListing),
    SubTree(ValueSubTree),
}

fn update_configuration_mode() {
    let json = JSON_MODE.get();
    set_hidden("value-table", json);
    set_hidden("json-editor", !json);
    set_hidden("add-value", json);
    if json {
        set_hidden("empty-values", true);
        hide_new_value_row();
    }
}

fn validate_json_editor() -> bool {
    let result = (|| {
        let Route::Configuration(path) = route_from_location() else {
            return Err(browser_error());
        };
        let json = element::<HtmlTextAreaElement>("json-content")
            .ok_or_else(browser_error)?
            .value();
        parse_subtree_json(&path, &json).map(|_| ())
    })();
    match result {
        Ok(()) => {
            set_validation("json-content", "json-error", None);
            set_button_disabled("save-json", false);
            true
        }
        Err(error) => {
            set_validation("json-content", "json-error", Some(error.message()));
            set_button_disabled("save-json", true);
            false
        }
    }
}

async fn save_json_subtree() {
    if !validate_json_editor() {
        return;
    }
    clear_error();
    set_button_disabled("save-json", true);
    let result = async {
        let Route::Configuration(path) = route_from_location() else {
            return Err(browser_error());
        };
        let json = element::<HtmlTextAreaElement>("json-content")
            .ok_or_else(browser_error)?
            .value();
        let values = parse_subtree_json(&path, &json)?;
        let config = app_config()?;
        value_client(&config).replace_subtree(&path, &values).await
    }
    .await;
    match result {
        Ok(_) => {
            reload_configuration().await;
            set_text("value-state", "Saved");
            focus("json-content");
        }
        Err(error) => {
            set_button_disabled("save-json", false);
            show_error(error.message());
        }
    }
}

async fn refresh_path_options() {
    if PATH_OPTIONS_REFRESHING.replace(true) {
        return;
    }
    let result = async {
        let Route::Configuration(path) = route_from_location() else {
            return Ok(None);
        };
        let config = app_config()?;
        value_client(&config).list_values(&path).await.map(Some)
    }
    .await;
    PATH_OPTIONS_REFRESHING.set(false);
    match result {
        Ok(Some(listing)) => {
            if let Err(error) = render_path_options(&listing) {
                show_error(error.message());
            }
        }
        Ok(None) => {}
        Err(error) => show_error(error.message()),
    }
}

async fn save_new_value() {
    let secret =
        element::<HtmlInputElement>("new-value-secret").is_some_and(|input| input.checked());
    let value_valid = if secret {
        validate_secret_field("new-secret-content", "new-value-error")
    } else {
        validate_value_field("new-value-content", "new-value-error")
    };
    if !validate_name_field() || !value_valid {
        return;
    }
    clear_error();
    let result = async {
        let config = app_config()?;
        let namespace = selected_namespace()?;
        let name = element::<HtmlInputElement>("new-value-name")
            .ok_or_else(browser_error)?
            .value();
        let path = namespace.join_name(name).map_err(|_| invalid_path())?;
        if secret {
            let value = element::<HtmlInputElement>("new-secret-content")
                .ok_or_else(browser_error)?
                .value();
            value_client(&config)
                .put_secret(&path, &SecretInput::new(value))
                .await
        } else {
            let value = element::<HtmlTextAreaElement>("new-value-content")
                .ok_or_else(browser_error)?
                .value();
            value_client(&config)
                .put_value(&path, &PlainValue::new(value))
                .await
        }
    }
    .await;
    match result {
        Ok(_) => {
            hide_new_value_row();
            reload_configuration().await;
            set_text("value-state", "Saved");
            focus("add-value");
        }
        Err(error) => {
            if let Some(input) = element::<HtmlInputElement>("new-secret-content") {
                input.set_value("");
            }
            show_error(error.message());
        }
    }
}

async fn save_existing_value(path: ConfigPath, input_id: String) {
    let error_id = format!("{input_id}-error");
    if !validate_value_field(&input_id, &error_id) {
        return;
    }
    clear_error();
    let result = async {
        let config = app_config()?;
        let value = element::<HtmlTextAreaElement>(&input_id)
            .ok_or_else(browser_error)?
            .value();
        value_client(&config)
            .put_value(&path, &PlainValue::new(value))
            .await
    }
    .await;
    match result {
        Ok(_) => {
            reload_configuration().await;
            set_text("value-state", "Saved");
            focus("values-heading");
        }
        Err(error) => show_error(error.message()),
    }
}

async fn save_existing_secret(path: ConfigPath, input_id: String) {
    clear_error();
    let result = async {
        let config = app_config()?;
        let input = element::<HtmlInputElement>(&input_id).ok_or_else(browser_error)?;
        let value = input.value();
        input.set_value("");
        value_client(&config)
            .put_secret(&path, &SecretInput::new(value))
            .await
    }
    .await;
    match result {
        Ok(_) => {
            reload_configuration().await;
            set_text("value-state", "Saved");
            focus("values-heading");
        }
        Err(error) => {
            if let Some(input) = element::<HtmlInputElement>(&input_id) {
                input.set_value("");
            }
            show_error(error.message());
        }
    }
}

async fn reveal_existing_secret(path: ConfigPath, output_id: String, button_id: String) {
    let generation = CONFIGURATION_LOAD_GENERATION.get();
    let route_path = match route_from_location() {
        Route::Configuration(path) => path,
        Route::System | Route::Connections | Route::Downloads => return,
    };
    clear_error();
    hide_revealed_secret(&output_id, &button_id);
    let result = async {
        let config = app_config()?;
        value_client(&config).reveal_secret(&path).await
    }
    .await;
    let current_path = match route_from_location() {
        Route::Configuration(path) => path,
        Route::System | Route::Connections | Route::Downloads => return,
    };
    if generation != CONFIGURATION_LOAD_GENERATION.get() || current_path != route_path {
        return;
    }
    match result {
        Ok(value) => {
            if let Some(output) = element::<HtmlTextAreaElement>(&output_id) {
                output.set_value(value.expose());
            }
            set_hidden(&output_id, false);
            set_text(&button_id, "Hide");
            if let Some(button) = window()
                .and_then(|window| window.document())
                .and_then(|document| document.get_element_by_id(&button_id))
            {
                let _ = button.set_attribute("aria-expanded", "true");
            }
            focus(&output_id);
        }
        Err(error) => {
            hide_revealed_secret(&output_id, &button_id);
            show_error(error.message());
        }
    }
}

fn hide_revealed_secret(output_id: &str, button_id: &str) {
    if let Some(output) = element::<HtmlTextAreaElement>(output_id) {
        output.set_value("");
    }
    set_hidden(output_id, true);
    set_text(button_id, "Reveal");
    if let Some(button) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id(button_id))
    {
        let _ = button.set_attribute("aria-expanded", "false");
    }
}

fn element_is_hidden(id: &str) -> bool {
    window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id(id))
        .is_none_or(|element| element.has_attribute("hidden"))
}

fn open_delete(path: ConfigPath, return_focus: String) {
    set_text("delete-path", &absolute_path(&path));
    DELETE_TARGET.with_borrow_mut(|target| {
        *target = Some(DeleteTarget { path, return_focus });
    });
    if let Some(dialog) = element::<HtmlDialogElement>("delete-dialog") {
        let _ = dialog.show_modal();
        focus("cancel-delete");
    }
}

fn cancel_delete() {
    let return_focus = DELETE_TARGET
        .with_borrow_mut(Option::take)
        .map(|target| target.return_focus);
    close_delete_dialog();
    if let Some(return_focus) = return_focus {
        focus(&return_focus);
    }
}

async fn delete_selected_value() {
    let Some(target) = DELETE_TARGET.with_borrow_mut(Option::take) else {
        return;
    };
    clear_error();
    let result = async {
        let config = app_config()?;
        value_client(&config)
            .delete_values(&target.path, false)
            .await
    }
    .await;
    close_delete_dialog();
    match result {
        Ok(_) => {
            reload_configuration().await;
            set_text("value-state", "Deleted");
            focus("add-value");
        }
        Err(error) => {
            show_error(error.message());
            focus(&target.return_focus);
        }
    }
}

fn close_delete_dialog() {
    if let Some(dialog) = element::<HtmlDialogElement>("delete-dialog") {
        dialog.close();
    }
}

fn open_add_path(source: ConfigPath, return_focus: String) {
    set_text("add-path-source", &absolute_path(&source));
    if let Some(input) = element::<HtmlInputElement>("add-path-input") {
        input.set_value("");
    }
    set_hidden("add-path-error", true);
    ADD_PATH_TARGET.with_borrow_mut(|target| {
        *target = Some(AddPathTarget {
            source,
            return_focus,
        });
    });
    if let Some(dialog) = element::<HtmlDialogElement>("add-path-dialog") {
        let _ = dialog.show_modal();
        focus("add-path-input");
    }
}

fn cancel_add_path() {
    let return_focus = ADD_PATH_TARGET
        .with_borrow_mut(Option::take)
        .map(|target| target.return_focus);
    close_add_path_dialog();
    if let Some(return_focus) = return_focus {
        focus(&return_focus);
    }
}

async fn add_selected_path() {
    // Inspect the target without consuming it so a malformed path can be
    // corrected in place, then take it before awaiting: a second activation
    // while the request is in flight would otherwise send the same alias twice,
    // and the duplicate's conflict would report a failure for a mutation that
    // actually succeeded.
    let Some(target) = ADD_PATH_TARGET.with_borrow(Clone::clone) else {
        return;
    };
    let entered = element::<HtmlInputElement>("add-path-input")
        .map(|input| input.value())
        .unwrap_or_default();
    let Ok(new_path) = ConfigPath::parse_operation(entered.trim()) else {
        set_text(
            "add-path-error",
            "Enter an absolute path such as /apps/worker/database-url.",
        );
        set_hidden("add-path-error", false);
        focus("add-path-input");
        return;
    };
    ADD_PATH_TARGET.with_borrow_mut(Option::take);
    set_button_disabled("confirm-add-path", true);
    clear_error();
    let result = async {
        let config = app_config()?;
        value_client(&config)
            .add_value_path(&target.source, &new_path)
            .await
    }
    .await;
    // Re-enable for the next time the dialog opens; the target stays consumed so
    // a retry starts from the row, as a failed delete does.
    set_button_disabled("confirm-add-path", false);
    close_add_path_dialog();
    match result {
        Ok(_) => {
            reload_configuration().await;
            set_text("value-state", "Path added");
            focus("add-value");
        }
        Err(error) => {
            show_error(error.message());
            focus(&target.return_focus);
        }
    }
}

fn close_add_path_dialog() {
    if let Some(dialog) = element::<HtmlDialogElement>("add-path-dialog") {
        dialog.close();
    }
}

#[allow(clippy::too_many_lines)]
fn install_connections_actions(document: &Document) {
    for form in [&ESTATE_CONNECTION_FORM, &PATH_CONNECTION_FORM] {
        if let Some(element) = document.get_element_by_id(form.form_id) {
            let callback = Closure::<dyn FnMut(_)>::new(move |event: Event| {
                event.prevent_default();
                open_create_connection(form);
            });
            let _ = element
                .add_event_listener_with_callback("submit", callback.as_ref().unchecked_ref());
            callback.forget();
        }
        if let Some(name) = document.get_element_by_id(form.name_id) {
            let callback = Closure::<dyn FnMut(_)>::new(move |_: Event| {
                validate_connection_name_field(form);
            });
            let _ =
                name.add_event_listener_with_callback("input", callback.as_ref().unchecked_ref());
            callback.forget();
        }
    }
    if let Some(root) = document.get_element_by_id("connection-root") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            validate_connection_root_field();
        });
        let _ = root.add_event_listener_with_callback("input", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(cancel) = document.get_element_by_id("cancel-create-connection") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            let return_focus = PENDING_CONNECTION
                .with_borrow_mut(Option::take)
                .map_or_else(
                    || "create-connection".to_owned(),
                    |pending| pending.return_focus,
                );
            close_dialog("create-connection-dialog");
            focus(&return_focus);
        });
        let _ = cancel.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(confirm) = document.get_element_by_id("confirm-create-connection") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            spawn_local(async { create_connection().await });
        });
        let _ =
            confirm.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(cancel) = document.get_element_by_id("cancel-rotate-connection") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            cancel_connection_dialog("rotate-connection-dialog");
        });
        let _ = cancel.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(confirm) = document.get_element_by_id("confirm-rotate-connection") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            spawn_local(async { rotate_connection().await });
        });
        let _ =
            confirm.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(cancel) = document.get_element_by_id("cancel-revoke-connection") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            cancel_connection_dialog("revoke-connection-dialog");
        });
        let _ = cancel.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(confirm) = document.get_element_by_id("confirm-revoke-connection") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            spawn_local(async { revoke_connection().await });
        });
        let _ =
            confirm.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(dialog) = document.get_element_by_id("create-connection-dialog") {
        // Escape closes a native dialog without either button. Treat that as the
        // cancel it is, so a credential draft — display name, root, and grants —
        // does not outlive the decision not to create it.
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            if let Some(pending) = PENDING_CONNECTION.with_borrow_mut(Option::take) {
                focus(&pending.return_focus);
            }
        });
        let _ = dialog.add_event_listener_with_callback("close", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(reveal) = document.get_element_by_id("reveal-connection-url") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            toggle_connection_url_reveal();
        });
        let _ = reveal.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(copy) = document.get_element_by_id("copy-connection-url") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            spawn_local(async { copy_connection_url().await });
        });
        let _ = copy.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(close) = document.get_element_by_id("close-connection-url") {
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            let return_focus = CONNECTION_URL_RETURN_FOCUS.with_borrow_mut(Option::take);
            discard_connection_url();
            if let Some(return_focus) = return_focus {
                focus(&return_focus);
            }
        });
        let _ = close.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
    if let Some(dialog) = document.get_element_by_id("connection-url-dialog") {
        // The native dialog can also close through Escape; always discard.
        let callback = Closure::<dyn FnMut(_)>::new(|_: Event| {
            let return_focus = CONNECTION_URL_RETURN_FOCUS.with_borrow_mut(Option::take);
            discard_connection_url();
            if let Some(return_focus) = return_focus {
                focus(&return_focus);
            }
        });
        let _ = dialog.add_event_listener_with_callback("close", callback.as_ref().unchecked_ref());
        callback.forget();
    }
}

/// The identifiers of one create-connection form. The Access URLs view types a
/// root; the Configuration view takes the selected tree node instead, so its
/// `root_id` is absent.
struct ConnectionForm {
    form_id: &'static str,
    name_id: &'static str,
    name_error_id: &'static str,
    root_id: Option<&'static str>,
    permission_prefix: &'static str,
    permissions_field_id: &'static str,
    permissions_error_id: &'static str,
    submit_id: &'static str,
}

const ESTATE_CONNECTION_FORM: ConnectionForm = ConnectionForm {
    form_id: "connection-form",
    name_id: "connection-name",
    name_error_id: "connection-name-error",
    root_id: Some("connection-root"),
    permission_prefix: "connection",
    permissions_field_id: "connection-permissions",
    permissions_error_id: "connection-permissions-error",
    submit_id: "create-connection",
};

const PATH_CONNECTION_FORM: ConnectionForm = ConnectionForm {
    form_id: "path-connection-form",
    name_id: "path-connection-name",
    name_error_id: "path-connection-name-error",
    root_id: None,
    permission_prefix: "path-connection",
    permissions_field_id: "path-connection-permissions",
    permissions_error_id: "path-connection-permissions-error",
    submit_id: "create-path-connection",
};

fn validate_connection_name_field(form: &ConnectionForm) -> bool {
    let value = element::<HtmlInputElement>(form.name_id).map(|input| input.value());
    let valid = value
        .as_deref()
        .is_some_and(|value| DisplayName::parse(value).is_ok());
    set_validation(
        form.name_id,
        form.name_error_id,
        if valid {
            None
        } else {
            Some(
                "enter a display name of at most 100 characters without leading or trailing spaces",
            )
        },
    );
    valid
}

fn validate_connection_root_field() -> bool {
    let value = element::<HtmlInputElement>("connection-root").map(|input| input.value());
    let valid = value
        .as_deref()
        .is_some_and(|value| parse_absolute_path(value).is_ok());
    set_validation(
        "connection-root",
        "connection-root-error",
        if valid {
            None
        } else {
            Some(
                "path must begin with / and contain only letters, numbers, hyphens, and underscores",
            )
        },
    );
    valid
}

/// Validates one create-connection form and, if it holds together, records the
/// request for the shared confirmation dialog to act on.
fn open_create_connection(form: &ConnectionForm) {
    let name_valid = validate_connection_name_field(form);
    let root_valid = form.root_id.is_none() || validate_connection_root_field();
    let permissions_valid = validate_connection_permissions_field(form);
    if !name_valid {
        focus(form.name_id);
        return;
    }
    if !root_valid {
        focus(form.root_id.unwrap_or(form.name_id));
        return;
    }
    if !permissions_valid {
        focus(&format!("{}-permission-read", form.permission_prefix));
        return;
    }
    let Some(Ok(display_name)) =
        element::<HtmlInputElement>(form.name_id).map(|input| DisplayName::parse(input.value()))
    else {
        return;
    };
    let root = match form.root_id {
        Some(id) => element::<HtmlInputElement>(id)
            .map(|input| input.value())
            .and_then(|value| parse_absolute_path(&value).ok()),
        None => selected_tree_path(),
    };
    let (Some(root), Some(permissions)) = (root, selected_connection_permissions(form)) else {
        return;
    };
    set_text("create-connection-name", display_name.as_str());
    set_text("create-connection-root", root.as_str());
    set_text(
        "create-connection-permissions",
        &connection_permissions_phrase(&permissions),
    );
    PENDING_CONNECTION.with_borrow_mut(|pending| {
        *pending = Some(PendingConnection {
            display_name,
            root,
            permissions,
            name_input_id: form.name_id.to_owned(),
            return_focus: form.submit_id.to_owned(),
        });
    });
    if let Some(dialog) = element::<HtmlDialogElement>("create-connection-dialog") {
        let _ = dialog.show_modal();
        focus("cancel-create-connection");
    }
}

/// Reads the three permission checkboxes into a core permission set, returning
/// `None` when the operator has selected nothing.
fn selected_connection_permissions(form: &ConnectionForm) -> Option<ManagedPermissions> {
    let mut selected = Vec::new();
    for (name, permission) in [
        ("read", ManagedPermission::Read),
        ("write", ManagedPermission::Write),
        ("manage", ManagedPermission::Manage),
    ] {
        let id = format!("{}-permission-{name}", form.permission_prefix);
        if element::<HtmlInputElement>(&id).is_some_and(|input| input.checked()) {
            selected.push(permission);
        }
    }
    ManagedPermissions::new(selected).ok()
}

fn validate_connection_permissions_field(form: &ConnectionForm) -> bool {
    let valid = selected_connection_permissions(form).is_some();
    set_validation(
        form.permissions_field_id,
        form.permissions_error_id,
        if valid {
            None
        } else {
            Some("select at least one permission")
        },
    );
    valid
}

/// A natural-language list of granted permissions for the confirmation copy,
/// e.g. `read`, `read and write`, or `read, write and manage`.
fn connection_permissions_phrase(permissions: &ManagedPermissions) -> String {
    let words = permissions.grant_tokens();
    match words.as_slice() {
        [] => String::new(),
        [only] => (*only).to_owned(),
        [head @ .., last] => format!("{} and {last}", head.join(", ")),
    }
}

/// A capitalized, canonically ordered label for a connection's granted
/// permissions, e.g. `Read, Write`.
fn connection_permissions_label(permissions: &ManagedPermissions) -> String {
    permissions
        .iter()
        .map(|permission| match permission {
            ManagedPermission::Read => "Read",
            ManagedPermission::Write => "Write",
            ManagedPermission::Manage => "Manage",
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn cancel_connection_dialog(dialog_id: &str) {
    let return_focus = CONNECTION_TARGET
        .with_borrow_mut(Option::take)
        .map(|target| target.return_focus);
    close_dialog(dialog_id);
    if let Some(return_focus) = return_focus {
        focus(&return_focus);
    }
}

fn close_dialog(id: &str) {
    if let Some(dialog) = element::<HtmlDialogElement>(id) {
        dialog.close();
    }
}

async fn create_connection() {
    if CONNECTION_PENDING.get() {
        return;
    }
    let Some(request) = PENDING_CONNECTION.with_borrow_mut(Option::take) else {
        close_dialog("create-connection-dialog");
        return;
    };
    CONNECTION_PENDING.set(true);
    set_button_disabled("confirm-create-connection", true);
    clear_error();
    let result = async {
        let config = app_config()?;
        value_client(&config)
            .create_managed_connection(&request.display_name, &request.root, &request.permissions)
            .await
    }
    .await;
    set_button_disabled("confirm-create-connection", false);
    CONNECTION_PENDING.set(false);
    close_dialog("create-connection-dialog");
    match result {
        Ok(provisioned) => {
            if let Some(input) = element::<HtmlInputElement>(&request.name_input_id) {
                input.set_value("");
            }
            set_text("connection-state", "Connection created");
            let generation = CONNECTIONS_LOAD_GENERATION.get();
            load_current_connections().await;
            // If the generation advanced by more than this reload's own
            // bump, a concurrent logout or navigation happened while it was
            // in flight; opening the one-time URL dialog now would resurrect
            // a credential after the user has already left.
            if CONNECTIONS_LOAD_GENERATION.get() == generation.wrapping_add(1) {
                open_connection_url_dialog(&provisioned, &request.return_focus);
            }
            // The sidebar's key marker is refreshed only after the one-time URL
            // is on screen: it is the operator's single chance to copy the
            // credential, and must not wait on a whole-estate read that could
            // also fail and paint an error banner in front of the dialog.
            load_tree().await;
        }
        Err(error) => {
            set_text("connection-state", "Error");
            show_error(error.message());
            focus(&request.return_focus);
        }
    }
}

async fn rotate_connection() {
    if CONNECTION_PENDING.get() {
        return;
    }
    let Some(target) = CONNECTION_TARGET.with_borrow_mut(Option::take) else {
        return;
    };
    CONNECTION_PENDING.set(true);
    set_button_disabled("confirm-rotate-connection", true);
    clear_error();
    let result = async {
        let config = app_config()?;
        value_client(&config)
            .rotate_managed_connection(&target.connection_id)
            .await
    }
    .await;
    set_button_disabled("confirm-rotate-connection", false);
    CONNECTION_PENDING.set(false);
    close_dialog("rotate-connection-dialog");
    match result {
        Ok(provisioned) => {
            set_text("connection-state", "Credential rotated");
            let generation = CONNECTIONS_LOAD_GENERATION.get();
            load_current_connections().await;
            // Same ordering hazard as create: a concurrent logout or
            // navigation while the reload was in flight must suppress the
            // one-time URL dialog rather than resurrect it afterward.
            if CONNECTIONS_LOAD_GENERATION.get() == generation.wrapping_add(1) {
                open_connection_url_dialog(&provisioned, &target.return_focus);
            }
            // The tree refresh follows the dialog, as in create.
            load_tree().await;
        }
        Err(error) => {
            // Refresh first: reloading clears the error banner, so the
            // message must be shown after the new state is rendered.
            load_current_connections().await;
            set_text("connection-state", "Error");
            show_error(error.message());
            focus(&target.return_focus);
        }
    }
}

async fn revoke_connection() {
    if CONNECTION_PENDING.get() {
        return;
    }
    let Some(target) = CONNECTION_TARGET.with_borrow_mut(Option::take) else {
        return;
    };
    CONNECTION_PENDING.set(true);
    set_button_disabled("confirm-revoke-connection", true);
    clear_error();
    let result = async {
        let config = app_config()?;
        value_client(&config)
            .revoke_managed_connection(&target.connection_id)
            .await
    }
    .await;
    set_button_disabled("confirm-revoke-connection", false);
    CONNECTION_PENDING.set(false);
    close_dialog("revoke-connection-dialog");
    // Refresh first: reloading clears the error banner, so any message must
    // be shown after the new state is rendered.
    load_current_connections().await;
    load_tree().await;
    match result {
        Ok(()) => {
            set_text("connection-state", "Connection revoked");
        }
        Err(error) => {
            set_text("connection-state", "Error");
            show_error(error.message());
        }
    }
    // The row the action started from is gone, so fall back to the heading of
    // whichever table it belonged to; `connections-heading` lives on the hidden
    // Access URLs page whenever the action came from the Configuration view.
    focus(connections_heading_for(&target.return_focus));
}

/// Clears the per-path access-URL draft so it cannot follow the operator to
/// another namespace.
fn reset_path_connection_form() {
    if let Some(name) = element::<HtmlInputElement>(PATH_CONNECTION_FORM.name_id) {
        name.set_value("");
    }
    for (suffix, checked) in [("read", true), ("write", false), ("manage", false)] {
        let id = format!(
            "{}-permission-{suffix}",
            PATH_CONNECTION_FORM.permission_prefix
        );
        if let Some(choice) = element::<HtmlInputElement>(&id) {
            choice.set_checked(checked);
        }
    }
    set_validation(
        PATH_CONNECTION_FORM.name_id,
        PATH_CONNECTION_FORM.name_error_id,
        None,
    );
    set_validation(
        PATH_CONNECTION_FORM.permissions_field_id,
        PATH_CONNECTION_FORM.permissions_error_id,
        None,
    );
}

/// The heading owning `return_focus`: the per-path table on the Configuration
/// view, or the estate-wide one on the Access URLs view.
fn connections_heading_for(return_focus: &str) -> &'static str {
    if return_focus.starts_with(PATH_CONNECTION_TABLE.prefix) {
        "path-connections-heading"
    } else {
        "connections-heading"
    }
}

/// Opens the one-time result surface with the URL masked; the secret lives
/// only in application memory until the surface closes.
fn open_connection_url_dialog(provisioned: &ProvisionedManagedConnection, return_focus: &str) {
    CONNECTION_URL_SECRET.with_borrow_mut(|slot| {
        *slot = Some(provisioned.connection_url.connection().canonical().clone());
    });
    CONNECTION_URL_RETURN_FOCUS.with_borrow_mut(|slot| {
        *slot = Some(return_focus.to_owned());
    });
    hide_connection_url_reveal();
    set_text("connection-url-status", "");
    if let Some(dialog) = element::<HtmlDialogElement>("connection-url-dialog") {
        let _ = dialog.show_modal();
        focus("reveal-connection-url");
    }
}

fn toggle_connection_url_reveal() {
    if element_is_hidden("revealed-connection-url") {
        let Some(secret) = CONNECTION_URL_SECRET.with_borrow(std::clone::Clone::clone) else {
            return;
        };
        if let Some(output) = element::<HtmlTextAreaElement>("revealed-connection-url") {
            output.set_value(secret.expose());
        }
        set_hidden("revealed-connection-url", false);
        set_hidden("connection-url-mask", true);
        set_text("reveal-connection-url", "Hide");
        if let Some(button) = window()
            .and_then(|window| window.document())
            .and_then(|document| document.get_element_by_id("reveal-connection-url"))
        {
            let _ = button.set_attribute("aria-expanded", "true");
        }
        focus("revealed-connection-url");
    } else {
        hide_connection_url_reveal();
        focus("reveal-connection-url");
    }
}

fn hide_connection_url_reveal() {
    if let Some(output) = element::<HtmlTextAreaElement>("revealed-connection-url") {
        output.set_value("");
    }
    set_hidden("revealed-connection-url", true);
    set_hidden("connection-url-mask", false);
    set_text("reveal-connection-url", "Reveal");
    if let Some(button) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id("reveal-connection-url"))
    {
        let _ = button.set_attribute("aria-expanded", "false");
    }
}

async fn copy_connection_url() {
    let Some(secret) = CONNECTION_URL_SECRET.with_borrow(std::clone::Clone::clone) else {
        return;
    };
    let Some(clipboard) = window().map(|window| window.navigator().clipboard()) else {
        set_text("connection-url-status", "Copy failed");
        return;
    };
    match JsFuture::from(clipboard.write_text(secret.expose())).await {
        Ok(_) => set_text("connection-url-status", "Copied"),
        Err(_) => set_text("connection-url-status", "Copy failed"),
    }
}

/// Discards the one-time URL from application state and the DOM.
fn discard_connection_url() {
    CONNECTION_URL_SECRET.with_borrow_mut(Option::take);
    hide_connection_url_reveal();
    set_text("connection-url-status", "");
    close_dialog("connection-url-dialog");
}

async fn load_current_connections() {
    let generation = CONNECTIONS_LOAD_GENERATION.get().wrapping_add(1);
    CONNECTIONS_LOAD_GENERATION.set(generation);
    if !matches!(route_from_location(), Route::Connections) {
        return;
    }
    clear_connection_rows(&ESTATE_CONNECTION_TABLE);
    clear_error();
    set_text("connection-state", "Loading");
    let result = async {
        let config = app_config()?;
        value_client(&config).list_managed_connections().await
    }
    .await;
    if CONNECTIONS_LOAD_GENERATION.get() != generation
        || !matches!(route_from_location(), Route::Connections)
    {
        return;
    }
    match result {
        Ok(connections) => {
            set_text("connection-state", "Loaded");
            if let Err(error) = render_connections(&connections) {
                show_error(error.message());
            }
        }
        Err(error) => {
            set_text("connection-state", "Error");
            show_error(error.message());
        }
    }
}

/// The identifiers of one connections table. The Access URLs view lists the
/// whole estate; the Configuration view lists only the selected path. Both share
/// this renderer, so their row actions must not collide on element ids.
struct ConnectionTable {
    body_id: &'static str,
    count_id: &'static str,
    empty_id: &'static str,
    prefix: &'static str,
}

const ESTATE_CONNECTION_TABLE: ConnectionTable = ConnectionTable {
    body_id: "connections-body",
    count_id: "connection-count",
    empty_id: "empty-connections",
    prefix: "",
};

const PATH_CONNECTION_TABLE: ConnectionTable = ConnectionTable {
    body_id: "path-connections-body",
    count_id: "path-connection-count",
    empty_id: "empty-path-connections",
    prefix: "path-",
};

fn render_connections(connections: &[ManagedConnectionMetadata]) -> Result<(), ClientError> {
    render_connection_rows(connections, &ESTATE_CONNECTION_TABLE)
}

/// Lists the access URLs rooted at exactly the selected path beneath that
/// path's values, so an operator grants access from the same place they read it.
fn render_path_connections() {
    let Some(path) = selected_tree_path() else {
        return;
    };
    let scoped = CONNECTIONS.with_borrow(|connections| {
        connections
            .iter()
            .filter(|connection| connection.root == path)
            .cloned()
            .collect::<Vec<_>>()
    });
    if let Err(error) = render_connection_rows(&scoped, &PATH_CONNECTION_TABLE) {
        show_error(error.message());
    }
}

fn render_connection_rows(
    connections: &[ManagedConnectionMetadata],
    table: &ConnectionTable,
) -> Result<(), ClientError> {
    clear_connection_rows(table);
    let document = window()
        .and_then(|window| window.document())
        .ok_or_else(browser_error)?;
    let body = document
        .get_element_by_id(table.body_id)
        .ok_or_else(browser_error)?;
    for (index, connection) in connections.iter().enumerate() {
        let row = render_connection_row(&document, connection, index, table.prefix)?;
        append(&body, &row)?;
    }
    let count = connections.len();
    set_text(
        table.count_id,
        &format!("{count} connection{}", if count == 1 { "" } else { "s" }),
    );
    set_hidden(table.empty_id, count != 0);
    Ok(())
}

fn render_connection_row(
    document: &Document,
    connection: &ManagedConnectionMetadata,
    index: usize,
    prefix: &str,
) -> Result<Element, ClientError> {
    let row = create_element(document, "tr", None)?;
    let name = create_element(document, "th", None)?;
    name.set_attribute("scope", "row")
        .map_err(|_| browser_error())?;
    name.set_text_content(Some(connection.display_name.as_str()));
    append(&row, &name)?;
    let root = create_element(document, "td", None)?;
    let root_code = create_element(document, "code", None)?;
    root_code.set_text_content(Some(connection.root.as_str()));
    append(&root, &root_code)?;
    append(&row, &root)?;
    let permissions = create_element(document, "td", None)?;
    permissions.set_text_content(Some(&connection_permissions_label(&connection.permissions)));
    append(&row, &permissions)?;
    let state = create_element(document, "td", None)?;
    state.set_text_content(Some(connection_state_label(connection.state)));
    append(&row, &state)?;

    let actions_cell = create_element(document, "td", None)?;
    let actions = create_element(document, "div", Some("row-actions"))?;
    let rotate_id = format!("{prefix}rotate-connection-{index}");
    let rotate = create_button(document, &rotate_id, "Rotate", Some("secondary"))?;
    rotate
        .set_attribute(
            "aria-label",
            &format!("Rotate credential for {}", connection.display_name.as_str()),
        )
        .map_err(|_| browser_error())?;
    if !matches!(
        connection.state,
        ManagedConnectionState::Active | ManagedConnectionState::RotationUnknown
    ) {
        rotate
            .set_attribute("disabled", "")
            .map_err(|_| browser_error())?;
    }
    let rotate_target = connection.connection_id.clone();
    let rotate_name = connection.display_name.as_str().to_owned();
    let rotate_root = connection.root.as_str().to_owned();
    let rotate_focus = rotate_id.clone();
    let callback = Closure::<dyn FnMut(_)>::new(move |_: Event| {
        open_connection_dialog(
            "rotate-connection-dialog",
            "rotate-connection-name",
            "rotate-connection-root",
            "cancel-rotate-connection",
            &rotate_target,
            &rotate_name,
            &rotate_root,
            &rotate_focus,
        );
    });
    rotate
        .add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())
        .map_err(|_| browser_error())?;
    callback.forget();
    append(&actions, &rotate)?;

    let revoke_id = format!("{prefix}revoke-connection-{index}");
    let revoke = create_button(document, &revoke_id, "Revoke", Some("danger"))?;
    revoke
        .set_attribute(
            "aria-label",
            &format!("Revoke {}", connection.display_name.as_str()),
        )
        .map_err(|_| browser_error())?;
    let revoke_target = connection.connection_id.clone();
    let revoke_name = connection.display_name.as_str().to_owned();
    let revoke_root = connection.root.as_str().to_owned();
    let revoke_focus = revoke_id.clone();
    let callback = Closure::<dyn FnMut(_)>::new(move |_: Event| {
        open_connection_dialog(
            "revoke-connection-dialog",
            "revoke-connection-name",
            "revoke-connection-root",
            "cancel-revoke-connection",
            &revoke_target,
            &revoke_name,
            &revoke_root,
            &revoke_focus,
        );
    });
    revoke
        .add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())
        .map_err(|_| browser_error())?;
    callback.forget();
    append(&actions, &revoke)?;
    append(&actions_cell, &actions)?;
    append(&row, &actions_cell)?;
    Ok(row)
}

#[allow(clippy::too_many_arguments)]
fn open_connection_dialog(
    dialog_id: &str,
    name_id: &str,
    root_id: &str,
    cancel_id: &str,
    connection_id: &ConnectionId,
    display_name: &str,
    root: &str,
    return_focus: &str,
) {
    set_text(name_id, display_name);
    set_text(root_id, root);
    CONNECTION_TARGET.with_borrow_mut(|target| {
        *target = Some(ConnectionTarget {
            connection_id: connection_id.clone(),
            return_focus: return_focus.to_owned(),
        });
    });
    if let Some(dialog) = element::<HtmlDialogElement>(dialog_id) {
        let _ = dialog.show_modal();
        focus(cancel_id);
    }
}

const fn connection_state_label(state: ManagedConnectionState) -> &'static str {
    match state {
        ManagedConnectionState::Provisioning => "Provisioning",
        ManagedConnectionState::Active => "Active",
        ManagedConnectionState::RotationUnknown => "Rotation unknown",
        ManagedConnectionState::Revoking => "Revoking",
        ManagedConnectionState::CleanupRequired => "Cleanup required",
    }
}

fn clear_connection_rows(table: &ConnectionTable) {
    if let Some(body) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id(table.body_id))
    {
        while let Some(row) = body.last_element_child() {
            row.remove();
        }
    }
    set_text(table.count_id, "0 connections");
    set_hidden(table.empty_id, false);
}

fn render_listing(listing: &ValueListing) -> Result<(), ClientError> {
    clear_value_rows();
    hide_new_value_row();
    render_path_options(listing)?;
    let document = window()
        .and_then(|window| window.document())
        .ok_or_else(browser_error)?;
    let body = document
        .get_element_by_id("values-body")
        .ok_or_else(browser_error)?;
    for (index, value) in listing.values.iter().enumerate() {
        let row = render_value_row(&document, value, index)?;
        append(&body, &row)?;
    }
    let count = listing.values.len();
    set_text(
        "value-count",
        &format!("{count} {}", if count == 1 { "value" } else { "values" }),
    );
    set_hidden("empty-values", count != 0);
    Ok(())
}

fn render_path_options(listing: &ValueListing) -> Result<(), ClientError> {
    let document = window()
        .and_then(|window| window.document())
        .ok_or_else(browser_error)?;
    let options = document
        .get_element_by_id("existing-paths")
        .ok_or_else(browser_error)?;
    options.set_text_content(None);
    let mut paths = listing
        .paths
        .iter()
        .map(absolute_path)
        .collect::<BTreeSet<_>>();
    paths.insert("/".into());
    if let Ok(selected) = selected_namespace() {
        paths.insert(absolute_path(&selected));
    }
    for (index, path) in paths.into_iter().enumerate() {
        let option = document
            .create_element("div")
            .map_err(|_| browser_error())?;
        option.set_class_name("path-option");
        option
            .set_attribute("id", &format!("existing-path-{index}"))
            .map_err(|_| browser_error())?;
        option
            .set_attribute("role", "option")
            .map_err(|_| browser_error())?;
        option
            .set_attribute("aria-selected", "false")
            .map_err(|_| browser_error())?;
        option
            .set_attribute("data-path", &path)
            .map_err(|_| browser_error())?;
        option.set_text_content(Some(&path));
        let selected_path = path;
        let callback = Closure::<dyn FnMut(_)>::new(move |event: Event| {
            event.prevent_default();
            if let Some(input) = element::<HtmlInputElement>("selected-path") {
                input.set_value(&selected_path);
                validate_path_field();
                close_path_options();
                focus("selected-path");
            }
        });
        option
            .add_event_listener_with_callback("pointerdown", callback.as_ref().unchecked_ref())
            .map_err(|_| browser_error())?;
        callback.forget();
        options.append_child(&option).map_err(|_| browser_error())?;
    }
    if path_options_expanded() {
        open_path_options();
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn render_value_row(
    document: &Document,
    value: &ListedValue,
    index: usize,
) -> Result<Element, ClientError> {
    if matches!(&value.value, ValueContent::Secret(_)) {
        return render_secret_value_row(document, value, index);
    }
    let row = create_element(document, "tr", None)?;
    row.set_attribute("data-value-row", "")
        .map_err(|_| browser_error())?;

    let name_cell = create_element(document, "th", None)?;
    name_cell
        .set_attribute("scope", "row")
        .map_err(|_| browser_error())?;
    let name = value
        .path
        .display_name()
        .unwrap_or_else(|| value.path.display_str());
    let name_text = create_element(document, "span", Some("value-name"))?;
    name_text.set_text_content(Some(name));
    let full_path = create_element(document, "span", Some("full-path"))?;
    full_path.set_text_content(Some(&absolute_path(&value.path)));
    append(&name_cell, &name_text)?;
    append(&name_cell, &full_path)?;
    append_alias_paths(document, &name_cell, value, index)?;

    let value_cell = create_element(document, "td", None)?;
    let input_id = format!("listed-value-{index}");
    let error_id = format!("{input_id}-error");
    let editor = create_element(document, "textarea", None)?;
    editor
        .set_attribute("id", &input_id)
        .map_err(|_| browser_error())?;
    editor
        .set_attribute("rows", "2")
        .map_err(|_| browser_error())?;
    editor
        .set_attribute("spellcheck", "false")
        .map_err(|_| browser_error())?;
    editor
        .set_attribute("aria-label", &format!("Value for {name}"))
        .map_err(|_| browser_error())?;
    editor
        .set_attribute("aria-describedby", &error_id)
        .map_err(|_| browser_error())?;
    let text = editor
        .clone()
        .dyn_into::<HtmlTextAreaElement>()
        .map_err(|_| browser_error())?;
    text.set_value(value.value.display_text());
    // Record what the control holds, not what was assigned to it: a textarea
    // normalizes CRLF to LF, so a stored value with CRLF would never compare
    // equal to its own source and every row of it would read as unsaved.
    editor
        .set_attribute("data-loaded", &text.value())
        .map_err(|_| browser_error())?;
    let field_error = create_element(document, "p", Some("field-error"))?;
    field_error
        .set_attribute("id", &error_id)
        .map_err(|_| browser_error())?;
    field_error
        .set_attribute("hidden", "")
        .map_err(|_| browser_error())?;
    field_error
        .set_attribute("aria-live", "polite")
        .map_err(|_| browser_error())?;
    append(&value_cell, &editor)?;
    append(&value_cell, &field_error)?;

    let updated = create_element(document, "td", Some("updated-time"))?;
    updated.set_text_content(Some(&format_timestamp(value.updated_at)));

    let actions_cell = create_element(document, "td", None)?;
    let actions = create_element(document, "div", Some("row-actions"))?;
    let save_id = format!("save-listed-value-{index}");
    let save = create_button(document, &save_id, "Save", None)?;
    let add_path_id = format!("add-path-listed-value-{index}");
    let add_path = create_button(document, &add_path_id, "Add path", Some("secondary"))?;
    add_path
        .set_attribute("aria-label", &format!("Add a path to {name}"))
        .map_err(|_| browser_error())?;
    let remove_id = format!("delete-listed-value-{index}");
    let remove = create_button(document, &remove_id, "Delete", Some("danger"))?;
    append(&actions, &save)?;
    append(&actions, &add_path)?;
    append(&actions, &remove)?;
    append(&actions_cell, &actions)?;

    let add_path_source = value.path.clone();
    let add_path_focus = add_path_id;
    let callback = Closure::<dyn FnMut(_)>::new(move |_: Event| {
        open_add_path(add_path_source.clone(), add_path_focus.clone());
    });
    add_path
        .add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())
        .map_err(|_| browser_error())?;
    callback.forget();

    let save_path = value.path.clone();
    let save_input = input_id.clone();
    let callback = Closure::<dyn FnMut(_)>::new(move |_: Event| {
        let path = save_path.clone();
        let input = save_input.clone();
        spawn_local(async move { save_existing_value(path, input).await });
    });
    save.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())
        .map_err(|_| browser_error())?;
    callback.forget();

    let validation_input = input_id.clone();
    let validation_error = error_id.clone();
    let validation_save = save_id.clone();
    let callback = Closure::<dyn FnMut(_)>::new(move |_: Event| {
        let valid = validate_value_field(&validation_input, &validation_error);
        set_button_disabled(&validation_save, !valid);
    });
    editor
        .add_event_listener_with_callback("input", callback.as_ref().unchecked_ref())
        .map_err(|_| browser_error())?;
    callback.forget();

    let delete_path = value.path.clone();
    let delete_focus = remove_id;
    let callback = Closure::<dyn FnMut(_)>::new(move |_: Event| {
        open_delete(delete_path.clone(), delete_focus.clone());
    });
    remove
        .add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())
        .map_err(|_| browser_error())?;
    callback.forget();

    append(&row, &name_cell)?;
    append(&row, &value_cell)?;
    append(&row, &updated)?;
    append(&row, &actions_cell)?;
    Ok(row)
}

#[allow(clippy::too_many_lines)]
fn render_secret_value_row(
    document: &Document,
    value: &ListedValue,
    index: usize,
) -> Result<Element, ClientError> {
    let row = create_element(document, "tr", None)?;
    row.set_attribute("data-value-row", "")
        .map_err(|_| browser_error())?;
    let name = value.path.display_name().ok_or_else(browser_error)?;

    let name_cell = create_element(document, "th", None)?;
    name_cell
        .set_attribute("scope", "row")
        .map_err(|_| browser_error())?;
    let name_text = create_element(document, "span", Some("value-name"))?;
    name_text.set_text_content(Some(name));
    let full_path = create_element(document, "span", Some("full-path"))?;
    full_path.set_text_content(Some(&absolute_path(&value.path)));
    append(&name_cell, &name_text)?;
    append(&name_cell, &full_path)?;
    append_alias_paths(document, &name_cell, value, index)?;

    let value_cell = create_element(document, "td", None)?;
    let kind = create_element(document, "span", Some("secret-kind"))?;
    kind.set_text_content(Some("Secret"));
    let mask = create_element(document, "span", Some("secret-mask"))?;
    mask.set_text_content(Some(value.value.display_text()));
    mask.set_attribute("aria-label", &format!("Secret value for {name} is hidden"))
        .map_err(|_| browser_error())?;
    append(&value_cell, &kind)?;
    append(&value_cell, &mask)?;

    let input_id = format!("secret-replacement-{index}");
    let input = create_element(document, "input", None)?;
    input
        .set_attribute("id", &input_id)
        .map_err(|_| browser_error())?;
    input
        .set_attribute("type", "password")
        .map_err(|_| browser_error())?;
    input
        .set_attribute("autocomplete", "new-password")
        .map_err(|_| browser_error())?;
    input
        .set_attribute("aria-label", &format!("Replacement secret for {name}"))
        .map_err(|_| browser_error())?;
    append(&value_cell, &input)?;

    let toggle_id = format!("toggle-secret-input-{index}");
    let toggle = create_button(document, &toggle_id, "Show input", Some("secondary"))?;
    toggle
        .set_attribute("aria-controls", &input_id)
        .map_err(|_| browser_error())?;
    toggle
        .set_attribute("aria-pressed", "false")
        .map_err(|_| browser_error())?;
    append(&value_cell, &toggle)?;

    let revealed_id = format!("revealed-secret-{index}");
    let revealed = create_element(document, "textarea", Some("revealed-secret"))?;
    revealed
        .set_attribute("id", &revealed_id)
        .map_err(|_| browser_error())?;
    revealed
        .set_attribute("readonly", "")
        .map_err(|_| browser_error())?;
    revealed
        .set_attribute("hidden", "")
        .map_err(|_| browser_error())?;
    revealed
        .set_attribute("aria-label", &format!("Revealed secret for {name}"))
        .map_err(|_| browser_error())?;
    append(&value_cell, &revealed)?;

    let updated = create_element(document, "td", Some("updated-time"))?;
    updated.set_text_content(Some(&format_timestamp(value.updated_at)));
    let actions_cell = create_element(document, "td", None)?;
    let actions = create_element(document, "div", Some("row-actions"))?;
    let save_id = format!("save-secret-{index}");
    let save = create_button(document, &save_id, "Replace", None)?;
    let reveal_id = format!("reveal-secret-{index}");
    let reveal = create_button(document, &reveal_id, "Reveal", Some("secondary"))?;
    reveal
        .set_attribute("aria-controls", &revealed_id)
        .map_err(|_| browser_error())?;
    reveal
        .set_attribute("aria-expanded", "false")
        .map_err(|_| browser_error())?;
    let add_path_id = format!("add-path-listed-value-{index}");
    let add_path = create_button(document, &add_path_id, "Add path", Some("secondary"))?;
    add_path
        .set_attribute("aria-label", &format!("Add a path to {name}"))
        .map_err(|_| browser_error())?;
    let remove_id = format!("delete-listed-value-{index}");
    let remove = create_button(document, &remove_id, "Delete", Some("danger"))?;
    append(&actions, &save)?;
    append(&actions, &reveal)?;
    append(&actions, &add_path)?;
    append(&actions, &remove)?;
    append(&actions_cell, &actions)?;

    let add_path_source = value.path.clone();
    let add_path_focus = add_path_id;
    let callback = Closure::<dyn FnMut(_)>::new(move |_: Event| {
        open_add_path(add_path_source.clone(), add_path_focus.clone());
    });
    add_path
        .add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())
        .map_err(|_| browser_error())?;
    callback.forget();

    let save_path = value.path.clone();
    let save_input = input_id.clone();
    let callback = Closure::<dyn FnMut(_)>::new(move |_: Event| {
        spawn_local(save_existing_secret(save_path.clone(), save_input.clone()));
    });
    save.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())
        .map_err(|_| browser_error())?;
    callback.forget();

    let toggle_input = input_id;
    let toggle_button = toggle_id;
    let callback = Closure::<dyn FnMut(_)>::new(move |_: Event| {
        toggle_secret_input(&toggle_input, &toggle_button);
    });
    toggle
        .add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())
        .map_err(|_| browser_error())?;
    callback.forget();

    let reveal_path = value.path.clone();
    let reveal_output = revealed_id;
    let reveal_button = reveal_id;
    let callback = Closure::<dyn FnMut(_)>::new(move |_: Event| {
        if element_is_hidden(&reveal_output) {
            spawn_local(reveal_existing_secret(
                reveal_path.clone(),
                reveal_output.clone(),
                reveal_button.clone(),
            ));
        } else {
            hide_revealed_secret(&reveal_output, &reveal_button);
        }
    });
    reveal
        .add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())
        .map_err(|_| browser_error())?;
    callback.forget();

    let delete_path = value.path.clone();
    let delete_focus = remove_id;
    let callback = Closure::<dyn FnMut(_)>::new(move |_: Event| {
        open_delete(delete_path.clone(), delete_focus.clone());
    });
    remove
        .add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())
        .map_err(|_| browser_error())?;
    callback.forget();

    append(&row, &name_cell)?;
    append(&row, &value_cell)?;
    append(&row, &updated)?;
    append(&row, &actions_cell)?;
    Ok(row)
}

/// Renders the value's additional authorized paths (`alias_paths`) beneath the
/// primary path in the name cell. Each entry carries a danger "Remove" button
/// that deletes only that path via the shared delete-confirm flow; the value
/// survives through its remaining paths.
fn append_alias_paths(
    document: &Document,
    name_cell: &Element,
    value: &ListedValue,
    index: usize,
) -> Result<(), ClientError> {
    if value.alias_paths.is_empty() {
        return Ok(());
    }
    let list = create_element(document, "ul", Some("alias-paths"))?;
    list.set_attribute("aria-label", "Additional paths for this value")
        .map_err(|_| browser_error())?;
    for (alias_index, alias_path) in value.alias_paths.iter().enumerate() {
        let item = create_element(document, "li", Some("alias-path"))?;
        let absolute = absolute_path(alias_path);
        let path_text = create_element(document, "span", Some("full-path"))?;
        path_text.set_text_content(Some(&absolute));
        append(&item, &path_text)?;

        let remove_id = format!("remove-alias-path-{index}-{alias_index}");
        let remove = create_button(document, &remove_id, "Remove", Some("danger"))?;
        remove
            .set_attribute("aria-label", &format!("Remove path {absolute}"))
            .map_err(|_| browser_error())?;
        let remove_path = alias_path.clone();
        let remove_focus = remove_id;
        let callback = Closure::<dyn FnMut(_)>::new(move |_: Event| {
            open_delete(remove_path.clone(), remove_focus.clone());
        });
        remove
            .add_event_listener_with_callback("click", callback.as_ref().unchecked_ref())
            .map_err(|_| browser_error())?;
        callback.forget();
        append(&item, &remove)?;

        append(&list, &item)?;
    }
    append(name_cell, &list)?;
    Ok(())
}

fn create_element(
    document: &Document,
    tag: &str,
    class_name: Option<&str>,
) -> Result<Element, ClientError> {
    let element = document.create_element(tag).map_err(|_| browser_error())?;
    if let Some(class_name) = class_name {
        element.set_class_name(class_name);
    }
    Ok(element)
}

fn create_button(
    document: &Document,
    id: &str,
    label: &str,
    class_name: Option<&str>,
) -> Result<Element, ClientError> {
    let button = create_element(document, "button", class_name)?;
    button
        .set_attribute("id", id)
        .map_err(|_| browser_error())?;
    button
        .set_attribute("type", "button")
        .map_err(|_| browser_error())?;
    button.set_text_content(Some(label));
    Ok(button)
}

fn append(parent: &Element, child: &Element) -> Result<(), ClientError> {
    parent
        .append_child(child)
        .map(|_| ())
        .map_err(|_| browser_error())
}

fn clear_value_rows() {
    let Some(body) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id("values-body"))
    else {
        return;
    };
    while let Some(row) = body.last_element_child() {
        if row.id() == "new-value-row" {
            break;
        }
        row.remove();
    }
    set_text("value-count", "0 values");
    set_hidden("empty-values", false);
}

fn clear_revealed_secrets() {
    let Some(document) = window().and_then(|window| window.document()) else {
        return;
    };
    let outputs = document.get_elements_by_class_name("revealed-secret");
    for index in 0..outputs.length() {
        let Some(output) = outputs.item(index) else {
            continue;
        };
        let output_id = output.id();
        let Some(suffix) = output_id.strip_prefix("revealed-secret-") else {
            continue;
        };
        hide_revealed_secret(&output_id, &format!("reveal-secret-{suffix}"));
    }
}

fn clear_write_only_secret_inputs() {
    let Some(document) = window().and_then(|window| window.document()) else {
        return;
    };
    let inputs = document.get_elements_by_tag_name("input");
    for index in 0..inputs.length() {
        let Some(element) = inputs.item(index) else {
            continue;
        };
        let input_id = element.id();
        if input_id != "new-secret-content" && !input_id.starts_with("secret-replacement-") {
            continue;
        }
        if let Ok(input) = element.dyn_into::<HtmlInputElement>() {
            input.set_value("");
            input.set_type("password");
        }
        let button_id = input_id.strip_prefix("secret-replacement-").map_or_else(
            || "toggle-new-secret".to_owned(),
            |suffix| format!("toggle-secret-input-{suffix}"),
        );
        set_text(&button_id, "Show input");
        if let Some(button) = document.get_element_by_id(&button_id) {
            let _ = button.set_attribute("aria-pressed", "false");
        }
    }
}

fn show_new_value_row() {
    set_textarea("new-value-content", "");
    if let Some(secret) = element::<HtmlInputElement>("new-value-secret") {
        secret.set_checked(false);
    }
    if let Some(input) = element::<HtmlInputElement>("new-secret-content") {
        input.set_value("");
        input.set_type("password");
    }
    set_text("toggle-new-secret", "Show input");
    update_new_value_classification();
    if let Some(name) = element::<HtmlInputElement>("new-value-name") {
        name.set_value("");
    }
    set_hidden("new-value-row", false);
    validate_name_field();
    validate_value_field("new-value-content", "new-value-error");
    update_new_save_state();
    focus("new-value-name");
}

fn hide_new_value_row() {
    set_hidden("new-value-row", true);
    set_textarea("new-value-content", "");
    if let Some(input) = element::<HtmlInputElement>("new-secret-content") {
        input.set_value("");
        input.set_type("password");
    }
    set_text("toggle-new-secret", "Show input");
    set_validation("new-value-name", "new-name-error", None);
    set_validation("new-value-content", "new-value-error", None);
}

fn update_new_value_classification() {
    let secret =
        element::<HtmlInputElement>("new-value-secret").is_some_and(|input| input.checked());
    set_hidden("new-value-content", secret);
    set_hidden("new-secret-content", !secret);
    set_hidden("toggle-new-secret", !secret);
    set_validation("new-value-content", "new-value-error", None);
    set_validation("new-secret-content", "new-value-error", None);
    update_new_save_state();
}

fn toggle_secret_input(input_id: &str, button_id: &str) {
    let Some(input) = element::<HtmlInputElement>(input_id) else {
        return;
    };
    let visible = input.type_() == "text";
    input.set_type(if visible { "password" } else { "text" });
    set_text(button_id, if visible { "Show input" } else { "Hide input" });
    if let Some(button) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id(button_id))
    {
        let _ = button.set_attribute("aria-pressed", if visible { "false" } else { "true" });
    }
}

fn validate_path_field() -> bool {
    let Some(input) = element::<HtmlInputElement>("selected-path") else {
        return false;
    };
    let message = parse_absolute_path(&input.value())
        .err()
        .map(|error| error.message());
    set_validation("selected-path", "path-error", message);
    message.is_none()
}

fn validate_name_field() -> bool {
    let Some(input) = element::<HtmlInputElement>("new-value-name") else {
        return false;
    };
    let message = if ConfigPath::root().join_name(input.value()).is_ok() {
        None
    } else {
        Some("Name must contain only letters, numbers, hyphens, and underscores")
    };
    set_validation("new-value-name", "new-name-error", message);
    message.is_none()
}

fn validate_value_field(input_id: &str, error_id: &str) -> bool {
    let Some(input) = element::<HtmlTextAreaElement>(input_id) else {
        return false;
    };
    let message = input
        .value()
        .contains('\0')
        .then_some("Value cannot contain a null character");
    set_validation(input_id, error_id, message);
    message.is_none()
}

fn validate_secret_field(input_id: &str, error_id: &str) -> bool {
    let Some(input) = element::<HtmlInputElement>(input_id) else {
        return false;
    };
    let message = input
        .value()
        .contains('\0')
        .then_some("Secret cannot contain a null character");
    set_validation(input_id, error_id, message);
    message.is_none()
}

fn set_validation(input_id: &str, error_id: &str, message: Option<&str>) {
    if let Some(input) = element::<HtmlInputElement>(input_id) {
        input.set_custom_validity(message.unwrap_or_default());
        let _ = input.set_attribute(
            "aria-invalid",
            if message.is_some() { "true" } else { "false" },
        );
    } else if let Some(input) = element::<HtmlTextAreaElement>(input_id) {
        input.set_custom_validity(message.unwrap_or_default());
        let _ = input.set_attribute(
            "aria-invalid",
            if message.is_some() { "true" } else { "false" },
        );
    }
    set_text(error_id, message.unwrap_or_default());
    set_hidden(error_id, message.is_none());
}

fn update_new_save_state() {
    let name_valid = element::<HtmlInputElement>("new-value-name")
        .is_some_and(|input| !input.value().is_empty() && input.check_validity());
    let secret =
        element::<HtmlInputElement>("new-value-secret").is_some_and(|input| input.checked());
    let value_valid = if secret {
        element::<HtmlInputElement>("new-secret-content")
            .is_some_and(|input| input.check_validity())
    } else {
        element::<HtmlTextAreaElement>("new-value-content")
            .is_some_and(|input| input.check_validity())
    };
    set_button_disabled("save-new-value", !(name_valid && value_valid));
}

#[allow(clippy::cast_precision_loss)]
fn format_timestamp(timestamp: Timestamp) -> String {
    let milliseconds = timestamp.seconds as f64 * 1000.0 + f64::from(timestamp.nanos) / 1_000_000.0;
    let date = Date::new(&JsValue::from_f64(milliseconds));
    String::from(date.to_locale_string("en-GB", &JsValue::UNDEFINED))
}

async fn refresh_status(config: &AppConfig) -> bool {
    clear_error();
    let client = Client::new(
        BrowserTransport,
        MemoryAuthentication {
            client_id: config.client_id.clone(),
        },
    );
    match client.service_status().await {
        Ok(status) => {
            set_text("service-value", "Available");
            set_text("version-value", &status.application_version);
            set_text("protocol-value", &status.protocol_version);
        }
        Err(error) => {
            set_text("service-value", "Unavailable");
            show_error(error.message());
        }
    }
    match client.authentication_status().await {
        Ok(status) if status.authenticated => {
            set_text("auth-value", "Logged in");
            set_hidden("login", true);
            set_hidden("logout", false);
            true
        }
        Ok(_) => {
            set_text("auth-value", "Logged out");
            set_hidden("login", false);
            set_hidden("logout", true);
            false
        }
        Err(error) if error.kind == ErrorKind::Unauthenticated => {
            clear_browser_session();
            set_text("auth-value", "Logged out");
            set_hidden("login", false);
            set_hidden("logout", true);
            show_error(error.message());
            false
        }
        Err(error) => {
            set_text("auth-value", "Unavailable");
            set_hidden("login", true);
            set_hidden("logout", false);
            show_error(error.message());
            false
        }
    }
}

async fn begin_login(config: &AppConfig) -> Result<(), ClientError> {
    let discovery = discover(&config.issuer).await?;
    let verifier = random_urlsafe()?;
    let state = random_urlsafe()?;
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let storage = session_storage()?;
    storage
        .set_item(STATE_KEY, &state)
        .map_err(|_| browser_error())?;
    storage
        .set_item(VERIFIER_KEY, &verifier)
        .map_err(|_| browser_error())?;
    storage
        .set_item(RETURN_PATH_KEY, &route_url(&route_from_location()))
        .map_err(|_| browser_error())?;
    let redirect_uri = redirect_uri()?;
    let url = Url::new(&discovery.authorization_endpoint).map_err(|_| oidc_error())?;
    let parameters = url.search_params();
    for (name, value) in [
        ("response_type", "code"),
        ("client_id", config.client_id.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("scope", "openid sovereign-config offline_access"),
        ("state", state.as_str()),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ] {
        parameters.append(name, value);
    }
    window()
        .ok_or_else(browser_error)?
        .location()
        .set_href(&url.href())
        .map_err(|_| browser_error())
}

async fn finish_login(config: &AppConfig) -> Result<(), ClientError> {
    let parameters = UrlSearchParams::new_with_str(&location_search().unwrap_or_default())
        .map_err(|_| oidc_error())?;
    let code = parameters.get("code").ok_or_else(oidc_error)?;
    let received_state = parameters.get("state").ok_or_else(oidc_error)?;
    let storage = session_storage()?;
    let expected_state = storage
        .get_item(STATE_KEY)
        .map_err(|_| browser_error())?
        .ok_or_else(oidc_error)?;
    let verifier = storage
        .get_item(VERIFIER_KEY)
        .map_err(|_| browser_error())?
        .ok_or_else(oidc_error)?;
    let return_path = storage
        .get_item(RETURN_PATH_KEY)
        .map_err(|_| browser_error())?
        .map_or_else(|| "/".into(), |path| route_url(&route_from_path(&path)));
    storage
        .remove_item(STATE_KEY)
        .map_err(|_| browser_error())?;
    storage
        .remove_item(VERIFIER_KEY)
        .map_err(|_| browser_error())?;
    storage
        .remove_item(RETURN_PATH_KEY)
        .map_err(|_| browser_error())?;
    if received_state != expected_state {
        return Err(ClientError::new(
            ErrorKind::Unauthenticated,
            "login response did not match this browser",
        ));
    }
    let discovery = discover(&config.issuer).await?;
    let form = UrlSearchParams::new().map_err(|_| browser_error())?;
    for (name, value) in [
        ("grant_type", "authorization_code"),
        ("client_id", config.client_id.as_str()),
        ("redirect_uri", redirect_uri()?.as_str()),
        ("code", code.as_str()),
        ("code_verifier", verifier.as_str()),
    ] {
        form.append(name, value);
    }
    let response = fetch(
        &discovery.token_endpoint,
        "POST",
        Some(form.to_string().into()),
        &[("content-type", "application/x-www-form-urlencoded")],
    )
    .await?;
    if !response.ok() {
        return Err(ClientError::new(
            ErrorKind::Unauthenticated,
            "login was rejected",
        ));
    }
    let json = JsFuture::from(response.json().map_err(|_| oidc_error())?)
        .await
        .map_err(|_| oidc_error())?;
    let access_token = string_property(&json, "access_token")?;
    let refresh_token = string_property(&json, "refresh_token")?;
    let expires_in = expires_in(&json);
    let now = Date::now();
    persist_refresh_token_from_parts(
        &refresh_token,
        &discovery.token_endpoint,
        now + REFRESH_LIFETIME_MS,
    );
    TOKENS.with_borrow_mut(|token| {
        *token = Some(MemoryTokens {
            access_token: Secret::new(access_token),
            refresh_token: Secret::new(refresh_token),
            access_expires_at_ms: now + expires_in * 1000.0,
            refresh_expires_at_ms: now + REFRESH_LIFETIME_MS,
            token_endpoint: discovery.token_endpoint,
        });
    });
    let window = window().ok_or_else(browser_error)?;
    window
        .history()
        .map_err(|_| browser_error())?
        .replace_state_with_url(&JsValue::NULL, "", Some(&return_path))
        .map_err(|_| browser_error())
}

fn restore_tokens() {
    let Ok(storage) = session_storage() else {
        return;
    };
    let (Some(refresh_token), Some(token_endpoint), Some(expires_at)) = (
        storage.get_item(REFRESH_TOKEN_KEY).ok().flatten(),
        storage.get_item(REFRESH_ENDPOINT_KEY).ok().flatten(),
        storage
            .get_item(REFRESH_EXPIRES_KEY)
            .ok()
            .flatten()
            .and_then(|value| value.parse::<f64>().ok()),
    ) else {
        return;
    };
    if Date::now() >= expires_at {
        clear_persisted_refresh_token();
        return;
    }
    TOKENS.with_borrow_mut(|slot| {
        *slot = Some(MemoryTokens {
            access_token: Secret::new(String::new()),
            refresh_token: Secret::new(refresh_token),
            access_expires_at_ms: 0.0,
            refresh_expires_at_ms: expires_at,
            token_endpoint,
        });
    });
}

fn persist_refresh_token(tokens: &MemoryTokens) {
    persist_refresh_token_from_parts(
        tokens.refresh_token.expose(),
        &tokens.token_endpoint,
        tokens.refresh_expires_at_ms,
    );
}

fn persist_refresh_token_from_parts(token: &str, endpoint: &str, expires_at: f64) {
    if let Ok(storage) = session_storage() {
        let _ = storage.set_item(REFRESH_TOKEN_KEY, token);
        let _ = storage.set_item(REFRESH_ENDPOINT_KEY, endpoint);
        let _ = storage.set_item(REFRESH_EXPIRES_KEY, &expires_at.to_string());
    }
}

fn clear_persisted_refresh_token() {
    if let Ok(storage) = session_storage() {
        let _ = storage.remove_item(REFRESH_TOKEN_KEY);
        let _ = storage.remove_item(REFRESH_ENDPOINT_KEY);
        let _ = storage.remove_item(REFRESH_EXPIRES_KEY);
    }
}

fn clear_browser_session() {
    TOKENS.with_borrow_mut(|token| *token = None);
    clear_persisted_refresh_token();
}

async fn refresh_tokens(
    client_id: &str,
    current: &MemoryTokens,
) -> Result<MemoryTokens, ClientError> {
    let form = UrlSearchParams::new().map_err(|_| browser_error())?;
    for (name, value) in [
        ("grant_type", "refresh_token"),
        ("client_id", client_id),
        ("refresh_token", current.refresh_token.expose()),
    ] {
        form.append(name, value);
    }
    let response = fetch(
        &current.token_endpoint,
        "POST",
        Some(form.to_string().into()),
        &[("content-type", "application/x-www-form-urlencoded")],
    )
    .await?;
    if !response.ok() {
        return Err(refresh_error(&response).await);
    }
    let json = JsFuture::from(response.json().map_err(|_| oidc_error())?)
        .await
        .map_err(|_| oidc_error())?;
    let access_token = string_property(&json, "access_token")?;
    let refresh_token = string_property(&json, "refresh_token")?;
    Ok(MemoryTokens {
        access_token: Secret::new(access_token),
        refresh_token: Secret::new(refresh_token),
        access_expires_at_ms: Date::now() + expires_in(&json) * 1000.0,
        refresh_expires_at_ms: current.refresh_expires_at_ms,
        token_endpoint: current.token_endpoint.clone(),
    })
}

async fn refresh_error(response: &Response) -> ClientError {
    let oauth_error = match response.json() {
        Ok(json) => JsFuture::from(json)
            .await
            .ok()
            .and_then(|json| optional_string_property(&json, "error")),
        Err(_) => None,
    };
    classify_refresh_error(response.status(), oauth_error.as_deref())
}

fn classify_refresh_error(status: u16, oauth_error: Option<&str>) -> ClientError {
    if status == 400 && oauth_error == Some("invalid_grant") {
        ClientError::new(ErrorKind::Unauthenticated, "login has expired")
    } else {
        oidc_error()
    }
}

fn expires_in(json: &JsValue) -> f64 {
    Reflect::get(json, &JsValue::from_str("expires_in"))
        .ok()
        .and_then(|value| value.as_f64())
        .filter(|value| value.is_finite() && *value > 0.0)
        .unwrap_or(300.0)
        .min(300.0)
}

struct Discovery {
    authorization_endpoint: String,
    token_endpoint: String,
}

async fn discover(issuer: &str) -> Result<Discovery, ClientError> {
    let url = format!("{issuer}.well-known/openid-configuration");
    let response = fetch(&url, "GET", None, &[]).await?;
    if !response.ok() {
        return Err(oidc_error());
    }
    let json = JsFuture::from(response.json().map_err(|_| oidc_error())?)
        .await
        .map_err(|_| oidc_error())?;
    let authorization_endpoint = string_property(&json, "authorization_endpoint")?;
    let token_endpoint = string_property(&json, "token_endpoint")?;
    require_issuer_origin(issuer, &authorization_endpoint)?;
    require_issuer_origin(issuer, &token_endpoint)?;
    Ok(Discovery {
        authorization_endpoint,
        token_endpoint,
    })
}

fn require_issuer_origin(issuer: &str, endpoint: &str) -> Result<(), ClientError> {
    let issuer = Url::new(issuer).map_err(|_| oidc_error())?;
    let endpoint = Url::new(endpoint).map_err(|_| oidc_error())?;
    if issuer.origin() != endpoint.origin() {
        return Err(oidc_error());
    }
    Ok(())
}

async fn grpc_unary<M, R>(
    path: &str,
    message: &M,
    bearer: Option<&Secret>,
) -> Result<R, ClientError>
where
    M: Message,
    R: Message + Default,
{
    let encoded = message.encode_to_vec();
    let mut framed = Vec::with_capacity(encoded.len() + 5);
    framed.push(0);
    let encoded_length = u32::try_from(encoded.len()).map_err(|_| browser_error())?;
    framed.extend_from_slice(&encoded_length.to_be_bytes());
    framed.extend_from_slice(&encoded);
    let body = Uint8Array::from(framed.as_slice());
    let mut headers = vec![
        ("content-type", "application/grpc-web+proto"),
        ("x-grpc-web", "1"),
    ];
    let authorization;
    if let Some(bearer) = bearer {
        authorization = format!("Bearer {}", bearer.expose());
        headers.push(("authorization", authorization.as_str()));
    }
    let response = fetch(path, "POST", Some(body.into()), &headers).await?;
    if !response.ok() {
        return Err(map_rpc_status(RpcCode::Unavailable));
    }
    let header_status = response
        .headers()
        .get("grpc-status")
        .ok()
        .flatten()
        .and_then(|value| value.parse::<u16>().ok());
    let buffer = JsFuture::from(response.array_buffer().map_err(|_| browser_error())?)
        .await
        .map_err(|_| browser_error())?;
    decode_grpc_web_response(&Uint8Array::new(&buffer).to_vec(), header_status)
}

#[cfg(test)]
fn decode_grpc_web<R: Message + Default>(bytes: &[u8]) -> Result<R, ClientError> {
    decode_grpc_web_response(bytes, None)
}

fn decode_grpc_web_response<R: Message + Default>(
    bytes: &[u8],
    header_status: Option<u16>,
) -> Result<R, ClientError> {
    let mut offset = 0;
    let mut payload = None;
    let mut status = None;
    while offset + 5 <= bytes.len() {
        let flags = bytes[offset];
        let length = u32::from_be_bytes(bytes[offset + 1..offset + 5].try_into().unwrap()) as usize;
        offset += 5;
        if offset + length > bytes.len() {
            return Err(map_rpc_status(RpcCode::Other));
        }
        let frame = &bytes[offset..offset + length];
        if flags & 0x80 == 0 {
            payload = Some(frame);
        } else if let Ok(trailers) = std::str::from_utf8(frame) {
            status = trailers.lines().find_map(|line| {
                line.strip_prefix("grpc-status:")
                    .and_then(|value| value.trim().parse::<u16>().ok())
            });
        }
        offset += length;
    }
    let status = status
        .or(header_status)
        .ok_or_else(|| map_rpc_status(RpcCode::Other))?;
    if status != 0 {
        return Err(map_rpc_status(grpc_status_code(status)));
    }
    R::decode(payload.ok_or_else(|| map_rpc_status(RpcCode::Other))?)
        .map_err(|_| map_rpc_status(RpcCode::Other))
}

fn grpc_status_code(status: u16) -> RpcCode {
    match status {
        3 => RpcCode::InvalidArgument,
        5 => RpcCode::NotFound,
        6 => RpcCode::AlreadyExists,
        7 => RpcCode::PermissionDenied,
        9 => RpcCode::FailedPrecondition,
        10 | 14 => RpcCode::Unavailable,
        16 => RpcCode::Unauthenticated,
        _ => RpcCode::Other,
    }
}

async fn fetch(
    url: &str,
    method: &str,
    body: Option<JsValue>,
    headers: &[(&str, &str)],
) -> Result<Response, ClientError> {
    let request_headers = Headers::new().map_err(|_| browser_error())?;
    for (name, value) in headers {
        request_headers
            .append(name, value)
            .map_err(|_| browser_error())?;
    }
    let options = RequestInit::new();
    options.set_method(method);
    options.set_cache(RequestCache::NoStore);
    options.set_headers(&request_headers);
    if let Some(body) = body.as_ref() {
        options.set_body(body);
    }
    let request = Request::new_with_str_and_init(url, &options).map_err(|_| browser_error())?;
    let response = JsFuture::from(
        window()
            .ok_or_else(browser_error)?
            .fetch_with_request(&request),
    )
    .await
    .map_err(|_| map_rpc_status(RpcCode::Unavailable))?;
    response.dyn_into().map_err(|_| browser_error())
}

fn app_config() -> Result<AppConfig, ClientError> {
    let global = js_sys::global();
    let config = Reflect::get(&global, &JsValue::from_str("SOVEREIGN_CONFIG"))
        .map_err(|_| browser_error())?;
    Ok(AppConfig {
        issuer: string_property(&config, "issuer")?,
        client_id: string_property(&config, "clientId")?,
    })
}

fn string_property(value: &JsValue, name: &str) -> Result<String, ClientError> {
    optional_string_property(value, name).ok_or_else(oidc_error)
}

fn optional_string_property(value: &JsValue, name: &str) -> Option<String> {
    Reflect::get(value, &JsValue::from_str(name))
        .ok()
        .and_then(|value| value.as_string())
        .filter(|value| !value.is_empty())
}

fn random_urlsafe() -> Result<String, ClientError> {
    let mut bytes = [0_u8; 32];
    window()
        .ok_or_else(browser_error)?
        .crypto()
        .map_err(|_| browser_error())?
        .get_random_values_with_u8_array(&mut bytes)
        .map_err(|_| browser_error())?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn session_storage() -> Result<web_sys::Storage, ClientError> {
    window()
        .ok_or_else(browser_error)?
        .session_storage()
        .map_err(|_| browser_error())?
        .ok_or_else(browser_error)
}

/// Holds the sidebar width only. Nothing sensitive is ever written here: tokens
/// stay in session storage and in memory.
fn local_storage() -> Result<web_sys::Storage, ClientError> {
    window()
        .ok_or_else(browser_error)?
        .local_storage()
        .map_err(|_| browser_error())?
        .ok_or_else(browser_error)
}

fn redirect_uri() -> Result<String, ClientError> {
    let location = window().ok_or_else(browser_error)?.location();
    Ok(format!(
        "{}/auth/callback",
        location.origin().map_err(|_| browser_error())?
    ))
}

fn location_search() -> Option<String> {
    window()?.location().search().ok()
}

fn current_text(id: &str) -> Option<String> {
    window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id(id))
        .and_then(|element| element.text_content())
}

fn set_text(id: &str, text: &str) {
    if let Some(element) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id(id))
    {
        element.set_text_content(Some(text));
    }
}

fn element<T: JsCast>(id: &str) -> Option<T> {
    window()?
        .document()?
        .get_element_by_id(id)?
        .dyn_into::<T>()
        .ok()
}

fn set_textarea(id: &str, value: &str) {
    if let Some(element) = element::<HtmlTextAreaElement>(id) {
        element.set_value(value);
    }
}

/// Sets a textarea and records what was loaded into it, so [`has_unsaved_edits`]
/// can tell an edit from the stored text by comparison.
fn set_loaded_textarea(id: &str, value: &str) {
    set_textarea(id, value);
    // Read the text back off the control rather than trusting `value`: a
    // textarea normalizes CRLF to LF, and a mismatch here would read as an
    // unsaved edit on a document nobody has touched.
    let Some(loaded) = element::<HtmlTextAreaElement>(id).map(|editor| editor.value()) else {
        return;
    };
    if let Some(element) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id(id))
    {
        let _ = element.set_attribute("data-loaded", &loaded);
    }
}

fn set_button_disabled(id: &str, disabled: bool) {
    if let Some(element) = element::<HtmlButtonElement>(id) {
        element.set_disabled(disabled);
    }
}

fn set_hidden(id: &str, hidden: bool) {
    if let Some(element) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id(id))
    {
        let _ = element.set_attribute("aria-hidden", if hidden { "true" } else { "false" });
        if hidden {
            let _ = element.set_attribute("hidden", "");
        } else {
            let _ = element.remove_attribute("hidden");
        }
    }
}

fn focus(id: &str) {
    if let Some(element) = window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id(id))
        .and_then(|element| element.dyn_into::<web_sys::HtmlElement>().ok())
    {
        let _ = element.focus();
    }
}

fn show_error(message: &str) {
    clear_revealed_secrets();
    clear_write_only_secret_inputs();
    set_text("error", message);
    set_hidden("error", false);
}

fn clear_error() {
    set_text("error", "");
    set_hidden("error", true);
}

fn browser_error() -> ClientError {
    ClientError::new(ErrorKind::Internal, "browser operation failed")
}

fn oidc_error() -> ClientError {
    ClientError::new(ErrorKind::Unavailable, "identity provider is unavailable")
}

#[cfg(test)]
mod tests {
    use prost::Message;
    use sovereign_config_core::ErrorKind;
    use sovereign_config_proto::sovereign::config::v3::GetIdentityResponse;

    use std::collections::BTreeSet;

    use sovereign_config_core::ConfigPath;

    use super::{
        Route, build_tree, classify_refresh_error, decode_grpc_web, decode_grpc_web_response,
        namespace_labels, parse_absolute_path, route_from_path, route_url, value_parents_of,
    };

    fn paths(values: &[&str]) -> Vec<ConfigPath> {
        values
            .iter()
            .map(|path| ConfigPath::parse(*path).unwrap())
            .collect()
    }

    fn roots(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|root| (*root).to_owned()).collect()
    }

    #[test]
    fn value_paths_imply_every_namespace_and_the_root() {
        let labels = namespace_labels(&paths(&[
            "/apps/api/enabled",
            "/apps/api/nested/message",
            "/top-level",
        ]));

        assert_eq!(
            labels.into_keys().collect::<Vec<_>>(),
            ["/", "/apps", "/apps/api", "/apps/api/nested"]
        );
    }

    #[test]
    fn namespace_labels_use_the_fold_smallest_contributing_path() {
        // `/Apps/API/enabled` and `/apps/api/other` share the fold ancestor
        // `/apps/api`; "/Apps/API" (uppercase) sorts before "/apps/api"
        // (lowercase) as a fold key, so its case wins the ancestor's label —
        // deterministic without needing a creation timestamp, which
        // `GetSubTree` does not carry.
        let mixed = vec![
            ConfigPath::parse_operation("/apps/api/other").unwrap(),
            ConfigPath::parse_operation("/Apps/API/enabled").unwrap(),
        ];
        let labels = namespace_labels(&mixed);
        assert_eq!(labels.get("/apps").map(String::as_str), Some("/Apps"));
        assert_eq!(
            labels.get("/apps/api").map(String::as_str),
            Some("/Apps/API")
        );
    }

    #[test]
    fn only_namespaces_directly_holding_values_are_bold() {
        // `/apps` is an ancestor of two values but holds none itself, which is
        // exactly the distinction `ListValues.paths` cannot express.
        let value_paths = paths(&["/apps/api/enabled", "/apps/api/nested/message", "/loose"]);

        let parents = value_parents_of(&value_paths);

        assert_eq!(
            parents.into_iter().collect::<Vec<_>>(),
            ["/", "/apps/api", "/apps/api/nested"]
        );
    }

    #[test]
    fn tree_orders_subtrees_contiguously_and_marks_access_urls() {
        // `-` sorts before `/`, so a raw string sort would wedge `/apps-legacy`
        // between `/apps` and its own children.
        let value_paths = paths(&["/apps/api/enabled", "/apps-legacy/flag", "/apps/web/theme"]);
        let labels = namespace_labels(&value_paths);
        let parents = value_parents_of(&value_paths);

        let tree = build_tree(&labels, &parents, &roots(&["/apps/api", "/absent"]));

        let rendered = tree
            .iter()
            .map(|node| {
                (
                    node.path.as_str(),
                    node.depth,
                    node.has_values,
                    node.has_connection,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            rendered,
            [
                ("/", 0, false, false),
                ("/apps", 1, false, false),
                ("/apps/api", 2, true, true),
                ("/apps/web", 2, true, false),
                ("/apps-legacy", 1, true, false),
            ]
        );
    }

    #[test]
    fn an_empty_estate_still_offers_the_root_node() {
        let tree = build_tree(&namespace_labels(&[]), &BTreeSet::new(), &BTreeSet::new());

        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].path.as_str(), "/");
        assert!(!tree[0].has_values);
    }

    #[test]
    fn absolute_configuration_paths_drive_canonical_routes() {
        assert_eq!(parse_absolute_path("/").unwrap().as_str(), "/");
        assert_eq!(
            parse_absolute_path("/Apps/API").unwrap().as_str(),
            "/apps/api"
        );
        // `_` became a legal segment character in 2.15.0; `.` did not.
        assert_eq!(
            parse_absolute_path("/Woodpecker/Global/GitHub_Token")
                .unwrap()
                .as_str(),
            "/woodpecker/global/github_token"
        );
        for invalid in ["", "apps/api", "/apps/", "/apps/bad.name", "//apps"] {
            assert!(
                parse_absolute_path(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
        let route = route_from_path("/configuration/Apps/API");
        assert_eq!(route_url(&route), "/configuration/apps/api");
        assert!(matches!(route_from_path("/unknown"), Route::System));
    }

    #[test]
    fn connection_routes_are_canonical() {
        assert!(matches!(
            route_from_path("/connections"),
            Route::Connections
        ));
        assert!(matches!(
            route_from_path("/connections/"),
            Route::Connections
        ));
        assert_eq!(route_url(&Route::Connections), "/connections/");
        assert!(matches!(
            route_from_path("/connections/extra"),
            Route::System
        ));
    }

    #[test]
    fn refresh_error_rejects_only_invalid_grant() {
        let error = classify_refresh_error(400, Some("invalid_grant"));

        assert_eq!(error.kind, ErrorKind::Unauthenticated);
        assert_eq!(error.message(), "login has expired");
    }

    #[test]
    fn refresh_error_preserves_sessions_for_provider_failures() {
        for (status, oauth_error) in [
            (429, Some("slow_down")),
            (500, Some("server_error")),
            (503, None),
            (400, Some("invalid_request")),
            (400, None),
        ] {
            let error = classify_refresh_error(status, oauth_error);
            assert_eq!(error.kind, ErrorKind::Unavailable);
            assert_eq!(error.message(), "identity provider is unavailable");
        }
    }

    #[test]
    fn grpc_web_decoder_reads_data_and_success_trailer() {
        let message = GetIdentityResponse {
            authenticated: true,
        }
        .encode_to_vec();
        let mut response = vec![0];
        response.extend_from_slice(&u32::try_from(message.len()).unwrap().to_be_bytes());
        response.extend_from_slice(&message);
        let trailer = b"grpc-status: 0\r\n";
        response.push(0x80);
        response.extend_from_slice(&u32::try_from(trailer.len()).unwrap().to_be_bytes());
        response.extend_from_slice(trailer);
        let decoded: GetIdentityResponse = decode_grpc_web(&response).unwrap();
        assert!(decoded.authenticated);
    }

    #[test]
    fn grpc_web_decoder_rejects_responses_without_a_status_trailer() {
        let message = GetIdentityResponse {
            authenticated: true,
        }
        .encode_to_vec();
        let mut data_only = vec![0];
        data_only.extend_from_slice(&u32::try_from(message.len()).unwrap().to_be_bytes());
        data_only.extend_from_slice(&message);

        let mut missing_status = data_only.clone();
        let trailer = b"grpc-message: missing status\r\n";
        missing_status.push(0x80);
        missing_status.extend_from_slice(&u32::try_from(trailer.len()).unwrap().to_be_bytes());
        missing_status.extend_from_slice(trailer);

        for response in [data_only, missing_status] {
            let error = decode_grpc_web::<GetIdentityResponse>(&response).unwrap_err();
            assert_eq!(error.kind, ErrorKind::Internal);
            assert_eq!(error.message(), "request failed");
        }
    }

    #[test]
    fn grpc_web_decoder_accepts_trailers_only_status_headers() {
        let error = decode_grpc_web_response::<GetIdentityResponse>(&[], Some(7)).unwrap_err();
        assert_eq!(error.kind, ErrorKind::PermissionDenied);
        assert_eq!(error.message(), "permission denied");
    }
}
