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

mod adapter;
mod v3;
mod v4;

use std::{future::Future, rc::Rc};

use async_trait::async_trait;
use js_sys::{Date, Uint8Array};
use prost::Message;
use sovereign_config_client::{
    AccessTokenProvider, AuditTransport, Client, Connection, Handshake, ManagedConnectionTransport,
    RpcCode, Session, SessionTransport, Transport, ValueTransport, VersionReply, map_rpc_status,
};
use sovereign_config_core::{
    AddPathMetadata, AuditPage, AuditQuery, AuthenticationStatus, ClientError, ConfigPath,
    ConnectionId, DeleteMetadata, DisplayName, ERROR_KIND_METADATA, ErrorKind,
    ManagedConnectionMetadata, ManagedPermissions, PlainValue, ProtocolVersion,
    ProvisionedManagedConnection, PutMetadata, ReplaceMetadata, RevealedSecret, Secret,
    SecretInput, ServedVersion, SubTreeMutationValue, VERSION_NOT_SERVED_KIND, ValueListing,
    ValuePaths, ValueSubTree,
};
use sovereign_config_proto::sovereign::config::{NegotiateRequest, NegotiateResponse};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, Request, RequestCache, RequestInit, Response, window};

use crate::browser::{AppConfig, browser_error};
use crate::session::{
    TOKENS, clear_persisted_refresh_token, negotiated_session, persist_refresh_token,
    refresh_tokens,
};

/// The routes that speak `version`.
///
/// **This is where a negotiated version becomes a dialled route.** The match is
/// exhaustive, so adding a variant to [`ProtocolVersion`] fails to compile here
/// until that version has a dialer.
fn dialer(version: ProtocolVersion) -> Box<dyn SessionTransport> {
    match version {
        ProtocolVersion::V4 => Box::new(v4::Dialer),
        ProtocolVersion::V3 => Box::new(v3::Dialer),
    }
}

/// Every route a version dials, for the test that checks each one names it.
#[cfg(test)]
fn routes(version: ProtocolVersion) -> &'static [&'static str] {
    match version {
        ProtocolVersion::V4 => v4::ROUTES,
        ProtocolVersion::V3 => v3::ROUTES,
    }
}

/// The route of the unversioned handshake.
///
/// Deliberately not in `v3.rs`: it belongs to no version, and putting it there
/// would tie the browser's ability to negotiate to the lifetime of a version.
const NEGOTIATE: &str = "/sovereign.config.Handshake/Negotiate";

/// The page before it has agreed a protocol version with the service.
#[derive(Clone, Copy)]
pub(crate) struct BrowserHandshake;

#[async_trait(?Send)]
impl Handshake for BrowserHandshake {
    async fn served_versions(
        &self,
        client_versions: &[ProtocolVersion],
    ) -> Result<Vec<ServedVersion>, ClientError> {
        let request = NegotiateRequest {
            client_protocol_versions: client_versions
                .iter()
                .map(|version| version.as_str().to_owned())
                .collect(),
        };
        let response: NegotiateResponse = grpc_unary(NEGOTIATE, &request, None).await?;
        Ok(response
            .served_protocol_versions
            .into_iter()
            .map(|entry| ServedVersion {
                version: entry.protocol_version,
                deprecation_date: entry.deprecation_date,
            })
            .collect())
    }

    async fn legacy_version(&self) -> Result<VersionReply, ClientError> {
        dialer(ProtocolVersion::LEGACY).get_version().await
    }
}

impl Connection for BrowserHandshake {
    /// The browser's dialers are stateless unit structs, so "a transport for a
    /// version" *is* the version: [`dialer`] turns one into the other with
    /// nothing carried between them. That is what lets the browser reuse the
    /// one re-handshake implementation instead of growing its own.
    type Transport = ProtocolVersion;

    fn speaking(&self, version: ProtocolVersion) -> Self::Transport {
        version
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
    session: Result<Rc<Session<BrowserHandshake>>, ClientError>,
}

impl BrowserTransport {
    /// The transport for the session this page negotiated at load.
    pub(crate) fn for_session() -> Self {
        Self {
            session: negotiated_session(),
        }
    }

    #[cfg(test)]
    pub(crate) const fn unnegotiated(failure: ClientError) -> Self {
        Self {
            session: Err(failure),
        }
    }

    /// Runs one operation on the version this page negotiated, re-handshaking
    /// once if the service has stopped serving it.
    ///
    /// The retry is the shared `Session::call`, not a second implementation:
    /// the browser is a long-lived holder like the provider and the broker, and
    /// a page open across a retirement should recover rather than break until
    /// someone reloads it.
    async fn dial<O, F, R>(&self, operation: O) -> Result<R, ClientError>
    where
        O: Fn(Box<dyn SessionTransport>) -> F,
        F: Future<Output = Result<R, ClientError>>,
    {
        let session = self.session.clone()?;
        session.call(|version| operation(dialer(version))).await
    }

    /// The service's own release version, read from `System.GetVersion` on the
    /// negotiated route.
    ///
    /// No longer a by-product of negotiating: the handshake carries versions
    /// and nothing else, so this is an ordinary versioned call like any other.
    pub(crate) async fn service_version(&self) -> Result<VersionReply, ClientError> {
        self.dial(|dialer| async move { dialer.get_version().await })
            .await
    }
}

#[async_trait(?Send)]
impl Transport for BrowserTransport {
    async fn get_identity(&self, bearer: &Secret) -> Result<AuthenticationStatus, ClientError> {
        self.dial(|dialer| async move { dialer.get_identity(bearer).await })
            .await
    }
}

#[async_trait(?Send)]
impl ValueTransport for BrowserTransport {
    async fn list_values(
        &self,
        path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<ValueListing, ClientError> {
        self.dial(|dialer| async move { dialer.list_values(path, bearer).await })
            .await
    }

    async fn get_subtree(
        &self,
        path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<ValueSubTree, ClientError> {
        self.dial(|dialer| async move { dialer.get_subtree(path, bearer).await })
            .await
    }

    async fn put_value(
        &self,
        path: &ConfigPath,
        value: &PlainValue,
        bearer: &Secret,
    ) -> Result<PutMetadata, ClientError> {
        self.dial(|dialer| async move { dialer.put_value(path, value, bearer).await })
            .await
    }

    async fn put_secret(
        &self,
        path: &ConfigPath,
        value: &SecretInput,
        bearer: &Secret,
    ) -> Result<PutMetadata, ClientError> {
        self.dial(|dialer| async move { dialer.put_secret(path, value, bearer).await })
            .await
    }

    async fn replace_subtree(
        &self,
        path: &ConfigPath,
        values: &[SubTreeMutationValue],
        bearer: &Secret,
    ) -> Result<ReplaceMetadata, ClientError> {
        self.dial(|dialer| async move { dialer.replace_subtree(path, values, bearer).await })
            .await
    }

    async fn delete_values(
        &self,
        path: &ConfigPath,
        recurse: bool,
        bearer: &Secret,
    ) -> Result<DeleteMetadata, ClientError> {
        self.dial(|dialer| async move { dialer.delete_values(path, recurse, bearer).await })
            .await
    }

    async fn reveal_secret(
        &self,
        path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<RevealedSecret, ClientError> {
        self.dial(|dialer| async move { dialer.reveal_secret(path, bearer).await })
            .await
    }

    async fn add_value_path(
        &self,
        source: &ConfigPath,
        new_path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<AddPathMetadata, ClientError> {
        self.dial(|dialer| async move { dialer.add_value_path(source, new_path, bearer).await })
            .await
    }

    async fn list_value_paths(
        &self,
        path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<ValuePaths, ClientError> {
        self.dial(|dialer| async move { dialer.list_value_paths(path, bearer).await })
            .await
    }
}

#[async_trait(?Send)]
impl ManagedConnectionTransport for BrowserTransport {
    async fn list_managed_connections(
        &self,
        bearer: &Secret,
    ) -> Result<Vec<ManagedConnectionMetadata>, ClientError> {
        self.dial(|dialer| async move { dialer.list_managed_connections(bearer).await })
            .await
    }

    async fn create_managed_connection(
        &self,
        display_name: &DisplayName,
        root: &ConfigPath,
        permissions: &ManagedPermissions,
        bearer: &Secret,
    ) -> Result<ProvisionedManagedConnection, ClientError> {
        self.dial(|dialer| async move {
            dialer
                .create_managed_connection(display_name, root, permissions, bearer)
                .await
        })
        .await
    }

    async fn rotate_managed_connection(
        &self,
        connection_id: &ConnectionId,
        bearer: &Secret,
    ) -> Result<ProvisionedManagedConnection, ClientError> {
        self.dial(|dialer| async move {
            dialer
                .rotate_managed_connection(connection_id, bearer)
                .await
        })
        .await
    }

    async fn revoke_managed_connection(
        &self,
        connection_id: &ConnectionId,
        bearer: &Secret,
    ) -> Result<(), ClientError> {
        self.dial(|dialer| async move {
            dialer
                .revoke_managed_connection(connection_id, bearer)
                .await
        })
        .await
    }
}

#[async_trait(?Send)]
impl AuditTransport for BrowserTransport {
    async fn query_audit_trail(
        &self,
        query: &AuditQuery,
        bearer: &Secret,
    ) -> Result<AuditPage, ClientError> {
        self.dial(|dialer| async move { dialer.query_audit_trail(query, bearer).await })
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
    // A trailers-only answer — which is what the version-not-served catch-all
    // produces — may arrive as headers rather than as a trailer frame.
    let header_kind = response.headers().get(ERROR_KIND_METADATA).ok().flatten();
    let buffer = JsFuture::from(response.array_buffer().map_err(|_| browser_error())?)
        .await
        .map_err(|_| browser_error())?;
    decode_grpc_web_response(
        &Uint8Array::new(&buffer).to_vec(),
        header_status,
        header_kind.as_deref(),
    )
}

#[cfg(test)]
pub(crate) fn decode_grpc_web<R: Message + Default>(bytes: &[u8]) -> Result<R, ClientError> {
    decode_grpc_web_response(bytes, None, None)
}

pub(crate) fn decode_grpc_web_response<R: Message + Default>(
    bytes: &[u8],
    header_status: Option<u16>,
    header_kind: Option<&str>,
) -> Result<R, ClientError> {
    let mut offset = 0;
    let mut payload = None;
    let mut status = None;
    let mut kind = None;
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
            kind = trailers.lines().find_map(|line| {
                line.strip_prefix(&format!("{ERROR_KIND_METADATA}:"))
                    .map(|value| value.trim().to_owned())
            });
        }
        offset += length;
    }
    let status = status
        .or(header_status)
        .ok_or_else(|| map_rpc_status(RpcCode::Other))?;
    if status != 0 {
        // The marker, never the code: a retired version is something the
        // session can recover from by re-handshaking, and nothing else that
        // shares this status code is.
        let kind = kind.as_deref().or(header_kind);
        if kind == Some(VERSION_NOT_SERVED_KIND) {
            return Err(map_rpc_status(RpcCode::VersionNotServed));
        }
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

    use super::{BrowserTransport, routes, v4};

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

    /// `v4`'s own routes — the ones no other version shares — name `v4` too.
    /// Kept apart from the shared table above, which every version must match
    /// exactly, so that table still catches a version missing a shared RPC.
    #[test]
    fn v4_audit_routes_name_v4() {
        assert_eq!(
            v4::AUDIT_ROUTES,
            ["/sovereign.config.v4.Audit/QueryAuditTrail"]
        );
    }

    /// `v3` has no audit trail, so its dialer answers an audit query itself,
    /// bounded, rather than posting to a route `v3` does not have. It would
    /// fail differently had it tried: there is no window to fetch from here.
    #[tokio::test]
    async fn a_v3_dialer_answers_an_audit_query_without_posting() {
        use sovereign_config_client::AuditTransport as _;
        use sovereign_config_core::{AuditQuery, Secret};

        let error = super::v3::Dialer
            .query_audit_trail(&AuditQuery::default(), &Secret::new("audit-token"))
            .await
            .expect_err("v3 has no audit trail");

        assert_eq!(error.kind, ErrorKind::IncompatibleProtocol);
        assert_eq!(
            error.message(),
            "the audit trail is not available on protocol v3"
        );
    }

    /// A page whose handshake failed has agreed no version, and there is no
    /// sensible guess: dialling the newest this build speaks is exactly the
    /// mis-attribution the rest of this design removes. Such a session reaches
    /// the network not at all, and reports **why** the handshake failed —
    /// reporting an unreachable service as an incompatible protocol would send
    /// an operator looking in the wrong place for the life of the page.
    #[tokio::test]
    async fn a_session_that_never_negotiated_dials_nothing_and_says_why() {
        for failure in [
            ClientError::new(ErrorKind::Unavailable, "service is unavailable"),
            ClientError::new(
                ErrorKind::IncompatibleProtocol,
                "service protocol is incompatible",
            ),
        ] {
            let error = BrowserTransport::unnegotiated(failure.clone())
                .dial(|dialer| async move { dialer.get_version().await })
                .await
                .expect_err("an unnegotiated session must not dial anything");

            assert_eq!(error, failure);
        }
    }
}
