//! gRPC-Web transport: the browser's handshake and per-version dialers, frame
//! decoding, and the `fetch` plumbing they share.
//!
//! The browser negotiates once at page load, like every other client, and its
//! requests travel on the version that negotiation settled on. It is served by
//! the same release as the server and so rarely differs from it — but its
//! traffic is counted per version like anyone else's, and attributing it to a
//! version it is not speaking would corrupt the gate for retiring one.
//!
//! Each version's routes and mapping live in their own module, selected by
//! [`dialer`]. That match is exhaustive over [`ProtocolVersion`], so declaring
//! a version the browser cannot dial does not compile.

mod v3;

use async_trait::async_trait;
use js_sys::{Date, Uint8Array};
use prost::Message;
use sovereign_config_client::{
    AccessTokenProvider, Client, Handshake, ManagedConnectionTransport, RpcCode, SessionTransport,
    Transport, ValueTransport, VersionReply, map_rpc_status,
};
use sovereign_config_core::{
    AddPathMetadata, AuthenticationStatus, ClientError, ConfigPath, ConnectionId, DeleteMetadata,
    DisplayName, ErrorKind, ManagedConnectionMetadata, ManagedPermissions, PlainValue,
    ProtocolVersion, ProvisionedManagedConnection, PutMetadata, ReplaceMetadata, RevealedSecret,
    Secret, SecretInput, SubTreeMutationValue, ValueListing, ValuePaths, ValueSubTree,
};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, Request, RequestCache, RequestInit, Response, window};

use crate::browser::{AppConfig, browser_error};
use crate::session::{
    TOKENS, clear_persisted_refresh_token, negotiated_protocol, persist_refresh_token,
    refresh_tokens,
};

/// The routes that speak `version`.
///
/// **This is where a negotiated version becomes a dialled route.** The match is
/// exhaustive, so adding a variant to [`ProtocolVersion`] fails to compile here
/// until that version has a dialer.
fn dialer(version: ProtocolVersion) -> Box<dyn SessionTransport> {
    match version {
        ProtocolVersion::V3 => Box::new(v3::Dialer),
    }
}

/// Every route a version dials, for the test that checks each one names it.
#[cfg(test)]
fn routes(version: ProtocolVersion) -> &'static [&'static str] {
    match version {
        ProtocolVersion::V3 => v3::ROUTES,
    }
}

/// The page before it has agreed a protocol version with the service.
#[derive(Clone, Copy)]
pub(crate) struct BrowserHandshake;

#[async_trait(?Send)]
impl Handshake for BrowserHandshake {
    async fn get_version(&self, version: ProtocolVersion) -> Result<VersionReply, ClientError> {
        dialer(version).get_version().await
    }
}

/// The browser's transport for the version its session negotiated.
///
/// A session that has not negotiated has no version to dial, and says so
/// rather than guessing a route. What it says is the failure that stopped the
/// handshake, carried from the page load: an unreachable service reported as
/// an incompatible protocol would point an operator at versions rather than at
/// the service, and nothing renegotiates for the life of the page to correct
/// it.
#[derive(Clone)]
pub(crate) struct BrowserTransport {
    protocol: Result<ProtocolVersion, ClientError>,
}

impl BrowserTransport {
    /// The transport for the version this page negotiated at load.
    pub(crate) fn for_session() -> Self {
        Self {
            protocol: negotiated_protocol(),
        }
    }

    #[cfg(test)]
    pub(crate) const fn unnegotiated(failure: ClientError) -> Self {
        Self {
            protocol: Err(failure),
        }
    }

    fn dialer(&self) -> Result<Box<dyn SessionTransport>, ClientError> {
        self.protocol.clone().map(dialer)
    }
}

#[async_trait(?Send)]
impl Transport for BrowserTransport {
    async fn get_identity(&self, bearer: &Secret) -> Result<AuthenticationStatus, ClientError> {
        self.dialer()?.get_identity(bearer).await
    }
}

#[async_trait(?Send)]
impl ValueTransport for BrowserTransport {
    async fn list_values(
        &self,
        path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<ValueListing, ClientError> {
        self.dialer()?.list_values(path, bearer).await
    }

    async fn get_subtree(
        &self,
        path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<ValueSubTree, ClientError> {
        self.dialer()?.get_subtree(path, bearer).await
    }

    async fn put_value(
        &self,
        path: &ConfigPath,
        value: &PlainValue,
        bearer: &Secret,
    ) -> Result<PutMetadata, ClientError> {
        self.dialer()?.put_value(path, value, bearer).await
    }

    async fn put_secret(
        &self,
        path: &ConfigPath,
        value: &SecretInput,
        bearer: &Secret,
    ) -> Result<PutMetadata, ClientError> {
        self.dialer()?.put_secret(path, value, bearer).await
    }

    async fn replace_subtree(
        &self,
        path: &ConfigPath,
        values: &[SubTreeMutationValue],
        bearer: &Secret,
    ) -> Result<ReplaceMetadata, ClientError> {
        self.dialer()?.replace_subtree(path, values, bearer).await
    }

    async fn delete_values(
        &self,
        path: &ConfigPath,
        recurse: bool,
        bearer: &Secret,
    ) -> Result<DeleteMetadata, ClientError> {
        self.dialer()?.delete_values(path, recurse, bearer).await
    }

    async fn reveal_secret(
        &self,
        path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<RevealedSecret, ClientError> {
        self.dialer()?.reveal_secret(path, bearer).await
    }

    async fn add_value_path(
        &self,
        source: &ConfigPath,
        new_path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<AddPathMetadata, ClientError> {
        self.dialer()?
            .add_value_path(source, new_path, bearer)
            .await
    }

    async fn list_value_paths(
        &self,
        path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<ValuePaths, ClientError> {
        self.dialer()?.list_value_paths(path, bearer).await
    }
}

#[async_trait(?Send)]
impl ManagedConnectionTransport for BrowserTransport {
    async fn list_managed_connections(
        &self,
        bearer: &Secret,
    ) -> Result<Vec<ManagedConnectionMetadata>, ClientError> {
        self.dialer()?.list_managed_connections(bearer).await
    }

    async fn create_managed_connection(
        &self,
        display_name: &DisplayName,
        root: &ConfigPath,
        permissions: &ManagedPermissions,
        bearer: &Secret,
    ) -> Result<ProvisionedManagedConnection, ClientError> {
        self.dialer()?
            .create_managed_connection(display_name, root, permissions, bearer)
            .await
    }

    async fn rotate_managed_connection(
        &self,
        connection_id: &ConnectionId,
        bearer: &Secret,
    ) -> Result<ProvisionedManagedConnection, ClientError> {
        self.dialer()?
            .rotate_managed_connection(connection_id, bearer)
            .await
    }

    async fn revoke_managed_connection(
        &self,
        connection_id: &ConnectionId,
        bearer: &Secret,
    ) -> Result<(), ClientError> {
        self.dialer()?
            .revoke_managed_connection(connection_id, bearer)
            .await
    }
}

pub(crate) struct MemoryAuthentication {
    pub(crate) client_id: String,
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

pub(crate) fn value_client(config: &AppConfig) -> Client<BrowserTransport, MemoryAuthentication> {
    Client::new(
        BrowserTransport::for_session(),
        MemoryAuthentication {
            client_id: config.client_id.clone(),
        },
    )
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
pub(crate) fn decode_grpc_web<R: Message + Default>(bytes: &[u8]) -> Result<R, ClientError> {
    decode_grpc_web_response(bytes, None)
}

pub(crate) fn decode_grpc_web_response<R: Message + Default>(
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
        12 => RpcCode::Unimplemented,
        16 => RpcCode::Unauthenticated,
        _ => RpcCode::Other,
    }
}

pub(crate) async fn fetch(
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use sovereign_config_core::{ClientError, ErrorKind, ProtocolVersion};

    use super::{BrowserTransport, routes};

    /// The RPCs a version's routes have to cover: `System` (2),
    /// `Configuration` (8) and `ManagedConnections` (4). Written as the sum so
    /// a service gaining an RPC is a visible change here rather than a literal
    /// someone edits to match, and one fewer than the calls the transport
    /// offers, because plain and secret writes are the same RPC.
    const ROUTE_COUNT: usize = 2 + 8 + 4;

    /// The browser builds its requests from compiled-in gRPC-Web paths, and the
    /// server counts a request under the version the path names. A session that
    /// negotiated `vN` and posted to `vN-1` would therefore be attributed to the
    /// wrong version, inverting the gate for retiring one — so every route a
    /// version declares has to name that version, and a version has to declare
    /// a route for every RPC.
    ///
    /// Table-driven over `ProtocolVersion::ALL`: a version added to that list is
    /// covered the moment it is declared.
    ///
    /// **This asserts a declared table, not what was dialled**, which is weaker
    /// than the native crate's `protocol_dispatch.rs` — that one issues every
    /// RPC against a recording server and asserts on the path received. The
    /// browser's routes are only observable through `fetch`, which needs a
    /// browser: `cargo test` runs this crate natively, where there is no window
    /// to intercept. The on-the-wire equivalent therefore belongs in the
    /// Playwright suite, and is not built here. What this does catch is a `vN`
    /// module copied from an older one and left pointing at the older package,
    /// which is the likely mistake — the paths are plain strings, so drift is
    /// easier here than with tonic's generated routes, not harder.
    #[test]
    fn every_route_a_version_declares_names_that_version() {
        for version in ProtocolVersion::ALL.iter().copied() {
            let routes = routes(version);

            assert_eq!(
                routes.len(),
                ROUTE_COUNT,
                "{version}: every RPC the transport posts should have a route listed"
            );
            assert_eq!(
                routes.iter().collect::<BTreeSet<_>>().len(),
                ROUTE_COUNT,
                "{version}: a repeated route means an RPC's own route is missing"
            );
            let expected_package = format!("/sovereign.config.{version}.");
            for route in routes {
                assert!(
                    route.starts_with(&expected_package),
                    "{version}: dials {route}, which does not name the version"
                );
            }
        }
    }

    /// A page whose handshake failed has agreed no version, and there is no
    /// sensible guess: dialling the newest this build speaks is exactly the
    /// mis-attribution the rest of this design removes. Such a session reaches
    /// the network not at all, and reports **why** the handshake failed —
    /// reporting an unreachable service as an incompatible protocol would send
    /// an operator looking in the wrong place for the life of the page.
    #[test]
    fn a_session_that_never_negotiated_dials_nothing_and_says_why() {
        for failure in [
            ClientError::new(ErrorKind::Unavailable, "service is unavailable"),
            ClientError::new(
                ErrorKind::IncompatibleProtocol,
                "service protocol is incompatible",
            ),
        ] {
            let error = BrowserTransport::unnegotiated(failure.clone())
                .dialer()
                .err()
                .expect("an unnegotiated session must not produce a dialer");

            assert_eq!(error, failure);
        }
    }
}
