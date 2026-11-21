//! The native transport: Connect unary for `v6` and the handshake, native gRPC
//! for `v3`–`v5` (#582).
//!
//! A connection is opened as a [`TonicChannel`], which can do exactly one
//! thing: ask a service which protocol versions it serves. It asks over
//! Connect first; a service that does not answer in Connect's shape predates
//! `v6`, and is asked again over gRPC, as every client before 3.0 asked it. Only
//! [`TonicChannel::speaking`] — handed the version negotiation settled on —
//! produces a [`TonicTransport`] that can carry configuration traffic. The
//! version an operator is shown and the version on the wire are therefore the
//! same value, rather than two values kept equal by hand.
//!
//! Each version's routes and mapping live in their own module, selected by
//! [`dialer`]. That match is exhaustive over [`ProtocolVersion`], so declaring
//! a version this transport cannot dial does not compile.

mod adapter;
mod audit_wire;
mod connect;
mod v3;
mod v4;
mod v5;
mod v6;

use std::{net::IpAddr, time::Duration};

use async_trait::async_trait;
use http::Uri;
use sovereign_config_client::{
    AuditTransport, Connection, Handshake, ManagedConnectionTransport, RpcCode, SessionTransport,
    Transport, ValueTransport, VersionReply, map_rpc_status,
};
use sovereign_config_core::{
    AddPathMetadata, AuditPage, AuditQuery, AuthenticationStatus, ClientError, ConfigPath,
    ConnectionId, DeleteMetadata, DisplayName, ERROR_KIND_METADATA, ManagedConnectionMetadata,
    ManagedPermissions, PlainValue, ProtocolVersion, ProvisionedManagedConnection, PutMetadata,
    ReplaceMetadata, RevealedSecret, Secret, SecretInput, ServedVersion, SubTreeMutationValue,
    VERSION_NOT_SERVED_KIND, ValueListing, ValuePaths, ValueSubTree,
};
use sovereign_config_proto::sovereign::config::{
    NegotiateRequest, NegotiateResponse, handshake_client::HandshakeClient,
};

use self::connect::{ConnectChannel, ConnectFailure};
use tonic::{
    Code, Request,
    metadata::MetadataValue,
    transport::{Channel, Endpoint},
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The stubs that speak `version`.
///
/// **This is where a negotiated version becomes a dialled route.** The match is
/// exhaustive, so adding a variant to [`ProtocolVersion`] fails to compile here
/// until that version has a dialer — which is the whole reason a version cannot
/// be negotiated, displayed and then silently carried on an older version's
/// routes.
///
/// The dialer reports its own version, so what a session says it speaks is read
/// from the same module that owns the routes it dials.
///
/// It is also where a version becomes a transport: `v6` dials Connect, and
/// every earlier version native gRPC.
fn dialer(version: ProtocolVersion, channels: &Channels) -> Box<dyn SessionTransport> {
    match version {
        ProtocolVersion::V6 => Box::new(v6::Dialer::new(channels.connect.clone())),
        ProtocolVersion::V5 => Box::new(v5::Dialer::new(channels.grpc.clone())),
        ProtocolVersion::V4 => Box::new(v4::Dialer::new(channels.grpc.clone())),
        ProtocolVersion::V3 => Box::new(v3::Dialer::new(channels.grpc.clone())),
    }
}

/// Whether `version` travels on Connect rather than native gRPC — the same
/// fact [`dialer`] encodes, for the handshake's gRPC fallback.
const fn speaks_connect(version: ProtocolVersion) -> bool {
    match version {
        ProtocolVersion::V6 => true,
        ProtocolVersion::V5 | ProtocolVersion::V4 | ProtocolVersion::V3 => false,
    }
}

/// The handshake's one route, which every transport serves.
const NEGOTIATE: &str = "/sovereign.config.Handshake/Negotiate";

/// Both ways of reaching one service. The gRPC channel connects lazily, on
/// its first call, so a session on `v6` never opens one — which is what lets
/// it work through a proxy that forwards HTTP/1.1 only.
#[derive(Clone)]
struct Channels {
    grpc: Channel,
    connect: ConnectChannel,
}

/// A connected channel that has not yet agreed a protocol version.
///
/// It can only negotiate: there is no route to carry configuration traffic on
/// until [`Handshake::get_version`] has said which version the service serves.
#[derive(Clone)]
pub struct TonicChannel {
    channels: Channels,
}

impl TonicChannel {
    /// Opens a connection to a service endpoint without configuring retries.
    ///
    /// Nothing is dialled until the first call: an unreachable service is
    /// reported, bounded, by the handshake.
    ///
    /// # Errors
    ///
    /// Returns a bounded invalid-request or unavailable error.
    ///
    /// Still a future, as it was when it dialled: callers await it, and a
    /// transport that dials eagerly again needs no change to them.
    pub fn connect(endpoint: String) -> impl Future<Output = Result<Self, ClientError>> {
        std::future::ready(Self::connect_with_timeouts(
            endpoint,
            CONNECT_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
    }

    /// The transport for a session that negotiated `version`.
    ///
    /// Every RPC it issues travels on `version`'s routes, and it reports
    /// `version` as the one it speaks.
    #[must_use]
    pub fn speaking(&self, version: ProtocolVersion) -> TonicTransport {
        TonicTransport {
            channels: self.channels.clone(),
            version,
        }
    }

    fn connect_with_timeouts(
        endpoint: String,
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> Result<Self, ClientError> {
        validate_service_endpoint(&endpoint)?;
        let connect = ConnectChannel::new(&endpoint, connect_timeout, request_timeout)
            .map_err(|_| map_rpc_status(RpcCode::Unavailable))?;
        let grpc = Endpoint::new(endpoint)
            .map_err(|_| map_rpc_status(RpcCode::InvalidArgument))?
            .connect_timeout(connect_timeout)
            .timeout(request_timeout)
            .connect_lazy();
        Ok(Self {
            channels: Channels { grpc, connect },
        })
    }
}

#[async_trait(?Send)]
impl Handshake for TonicChannel {
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
        let served = match self
            .channels
            .connect
            .unary::<NegotiateRequest, NegotiateResponse>(NEGOTIATE, Request::new(request.clone()))
            .await
        {
            Ok(response) => response.into_inner(),
            Err(ConnectFailure::Status(status)) => return Err(map_status(&status)),
            // A service that predates `v6` answers a Connect call in some
            // other shape. Asked over gRPC, it answers as it always has, and
            // the session selects `v5` or earlier (#594 removes this).
            //
            // A server that answers there and not over Connect may still be
            // one that serves `v6` — behind something that does not pass
            // Connect — so a version only Connect carries is no candidate.
            Err(ConnectFailure::NotConnect) => {
                let mut served = HandshakeClient::new(self.channels.grpc.clone())
                    .negotiate(Request::new(request))
                    .await
                    .map_err(|status| map_status(&status))?
                    .into_inner();
                served.served_protocol_versions.retain(|entry| {
                    ProtocolVersion::parse(&entry.protocol_version)
                        .is_none_or(|version| !speaks_connect(version))
                });
                served
            }
        };

        Ok(served
            .served_protocol_versions
            .into_iter()
            .map(|entry| ServedVersion {
                version: entry.protocol_version,
                deprecation_date: entry.deprecation_date,
            })
            .collect())
    }

    async fn legacy_version(&self) -> Result<VersionReply, ClientError> {
        dialer(ProtocolVersion::LEGACY, &self.channels)
            .get_version()
            .await
    }
}

impl Connection for TonicChannel {
    type Transport = TonicTransport;

    fn speaking(&self, version: ProtocolVersion) -> Self::Transport {
        Self::speaking(self, version)
    }
}

/// A native transport bound to one negotiated protocol version: Connect for
/// `v6`, native gRPC for every earlier version.
#[derive(Clone)]
pub struct TonicTransport {
    channels: Channels,
    version: ProtocolVersion,
}

impl TonicTransport {
    /// The version every RPC this transport issues travels on.
    ///
    /// Read from the dialer rather than from the field it was built with, so
    /// what a session reports is what its routes name.
    #[must_use]
    pub fn protocol_version(&self) -> ProtocolVersion {
        self.dialer().version()
    }

    /// The service's own release version, read from `System.GetVersion` on the
    /// negotiated route.
    ///
    /// No longer a by-product of negotiating: the handshake carries versions
    /// and nothing else, so what an operator is shown as "the service version"
    /// is an ordinary versioned call, answered by the same routes the session's
    /// traffic travels on.
    ///
    /// # Errors
    ///
    /// Returns a bounded transport error.
    pub async fn dialer_version(&self) -> Result<VersionReply, ClientError> {
        self.dialer().get_version().await
    }

    fn dialer(&self) -> Box<dyn SessionTransport> {
        dialer(self.version, &self.channels)
    }
}

#[async_trait(?Send)]
impl Transport for TonicTransport {
    async fn get_identity(&self, bearer: &Secret) -> Result<AuthenticationStatus, ClientError> {
        self.dialer().get_identity(bearer).await
    }
}

#[async_trait(?Send)]
impl ValueTransport for TonicTransport {
    async fn list_values(
        &self,
        path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<ValueListing, ClientError> {
        self.dialer().list_values(path, bearer).await
    }

    async fn get_subtree(
        &self,
        path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<ValueSubTree, ClientError> {
        self.dialer().get_subtree(path, bearer).await
    }

    async fn put_value(
        &self,
        path: &ConfigPath,
        value: &PlainValue,
        bearer: &Secret,
    ) -> Result<PutMetadata, ClientError> {
        self.dialer().put_value(path, value, bearer).await
    }

    async fn put_secret(
        &self,
        path: &ConfigPath,
        value: &SecretInput,
        bearer: &Secret,
    ) -> Result<PutMetadata, ClientError> {
        self.dialer().put_secret(path, value, bearer).await
    }

    async fn replace_subtree(
        &self,
        path: &ConfigPath,
        values: &[SubTreeMutationValue],
        bearer: &Secret,
    ) -> Result<ReplaceMetadata, ClientError> {
        self.dialer().replace_subtree(path, values, bearer).await
    }

    async fn delete_values(
        &self,
        path: &ConfigPath,
        recurse: bool,
        bearer: &Secret,
    ) -> Result<DeleteMetadata, ClientError> {
        self.dialer().delete_values(path, recurse, bearer).await
    }

    async fn reveal_secret(
        &self,
        path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<RevealedSecret, ClientError> {
        self.dialer().reveal_secret(path, bearer).await
    }

    async fn add_value_path(
        &self,
        source: &ConfigPath,
        new_path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<AddPathMetadata, ClientError> {
        self.dialer().add_value_path(source, new_path, bearer).await
    }

    async fn list_value_paths(
        &self,
        path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<ValuePaths, ClientError> {
        self.dialer().list_value_paths(path, bearer).await
    }
}

#[async_trait(?Send)]
impl ManagedConnectionTransport for TonicTransport {
    async fn list_managed_connections(
        &self,
        bearer: &Secret,
    ) -> Result<Vec<ManagedConnectionMetadata>, ClientError> {
        self.dialer().list_managed_connections(bearer).await
    }

    async fn create_managed_connection(
        &self,
        display_name: &DisplayName,
        root: &ConfigPath,
        permissions: &ManagedPermissions,
        bearer: &Secret,
    ) -> Result<ProvisionedManagedConnection, ClientError> {
        self.dialer()
            .create_managed_connection(display_name, root, permissions, bearer)
            .await
    }

    async fn rotate_managed_connection(
        &self,
        connection_id: &ConnectionId,
        bearer: &Secret,
    ) -> Result<ProvisionedManagedConnection, ClientError> {
        self.dialer()
            .rotate_managed_connection(connection_id, bearer)
            .await
    }

    async fn revoke_managed_connection(
        &self,
        connection_id: &ConnectionId,
        bearer: &Secret,
    ) -> Result<(), ClientError> {
        self.dialer()
            .revoke_managed_connection(connection_id, bearer)
            .await
    }
}

#[async_trait(?Send)]
impl AuditTransport for TonicTransport {
    async fn query_audit_trail(
        &self,
        query: &AuditQuery,
        bearer: &Secret,
    ) -> Result<AuditPage, ClientError> {
        self.dialer().query_audit_trail(query, bearer).await
    }
}

fn authenticated_request<T>(message: T, bearer: &Secret) -> Result<Request<T>, ClientError> {
    let mut request = Request::new(message);
    let authorization = MetadataValue::try_from(format!("Bearer {}", bearer.expose()))
        .map_err(|_| map_rpc_status(RpcCode::InvalidArgument))?;
    request
        .metadata_mut()
        .insert("authorization", authorization);
    Ok(request)
}

fn validate_service_endpoint(endpoint: &str) -> Result<(), ClientError> {
    let uri = endpoint
        .parse::<Uri>()
        .map_err(|_| map_rpc_status(RpcCode::InvalidArgument))?;
    let valid = match (uri.scheme_str(), uri.host()) {
        (Some("https"), Some(_)) => true,
        (Some("http"), Some(host)) => host
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback()),
        _ => false,
    };
    if !valid {
        return Err(map_rpc_status(RpcCode::InvalidArgument));
    }
    Ok(())
}

/// Whether a status is the service's **version-not-served** answer.
///
/// Read from the metadata marker, never inferred from the code: this server
/// returns `FAILED_PRECONDITION` for the retirement case, but the code alone is
/// not a protocol statement and a future one could use it for something else.
/// The marker is frozen and returned outside every version, so it is the only
/// thing safe to key on.
fn is_version_not_served(status: &tonic::Status) -> bool {
    status
        .metadata()
        .get(ERROR_KIND_METADATA)
        .and_then(|value| value.to_str().ok())
        == Some(VERSION_NOT_SERVED_KIND)
}

fn map_status(status: &tonic::Status) -> ClientError {
    if is_version_not_served(status) {
        return map_rpc_status(RpcCode::VersionNotServed);
    }
    map_rpc_status(match status.code() {
        Code::Unauthenticated => RpcCode::Unauthenticated,
        Code::PermissionDenied => RpcCode::PermissionDenied,
        Code::FailedPrecondition => RpcCode::FailedPrecondition,
        Code::Unimplemented => RpcCode::Unimplemented,
        Code::InvalidArgument => RpcCode::InvalidArgument,
        Code::NotFound => RpcCode::NotFound,
        Code::AlreadyExists => RpcCode::AlreadyExists,
        Code::Aborted | Code::Cancelled | Code::DeadlineExceeded | Code::Unavailable => {
            RpcCode::Unavailable
        }
        _ => RpcCode::Other,
    })
}

#[cfg(test)]
mod tests {
    use std::{future::pending, time::Duration};

    use sovereign_config_client::{Handshake, Transport};
    use sovereign_config_core::{ErrorKind, ProtocolVersion, Secret};
    use sovereign_config_proto::sovereign::config::{
        NegotiateRequest, NegotiateResponse,
        handshake_server::{Handshake as HandshakeService, HandshakeServer},
        v3::{
            GetIdentityRequest, GetIdentityResponse, GetVersionRequest, GetVersionResponse,
            system_server::{System, SystemServer},
        },
    };
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::{Request, Response, Status, transport::Server};

    use super::{TonicChannel, validate_service_endpoint};

    /// A handshake that never answers.
    ///
    /// Registered wherever the fixture is meant to *stall*: without it the
    /// handshake route would simply not exist and negotiation would fail fast
    /// with an incompatibility, which is a different test.
    struct HangingHandshake;

    #[tonic::async_trait]
    impl HandshakeService for HangingHandshake {
        async fn negotiate(
            &self,
            _: Request<NegotiateRequest>,
        ) -> Result<Response<NegotiateResponse>, Status> {
            pending().await
        }
    }

    struct HangingSystem;

    #[tonic::async_trait]
    impl System for HangingSystem {
        async fn get_version(
            &self,
            _: Request<GetVersionRequest>,
        ) -> Result<Response<GetVersionResponse>, Status> {
            pending().await
        }

        async fn get_identity(
            &self,
            _: Request<GetIdentityRequest>,
        ) -> Result<Response<GetIdentityResponse>, Status> {
            pending().await
        }
    }

    /// A handshake that serves `v6` and `v5`, over gRPC only.
    struct GrpcOnlyNewServer;

    #[tonic::async_trait]
    impl HandshakeService for GrpcOnlyNewServer {
        async fn negotiate(
            &self,
            _: Request<NegotiateRequest>,
        ) -> Result<Response<NegotiateResponse>, Status> {
            let entry =
                |version: &str| sovereign_config_proto::sovereign::config::ServedProtocolVersion {
                    protocol_version: version.to_owned(),
                    deprecation_date: None,
                };
            Ok(Response::new(NegotiateResponse {
                served_protocol_versions: vec![entry("v6"), entry("v5")],
            }))
        }
    }

    /// When only the gRPC fallback reached the server, a version only
    /// Connect carries is not offered for selection, even if the server lists
    /// it: the session settles on `v5`, which the fallback just proved works.
    #[tokio::test]
    async fn a_grpc_fallback_never_selects_a_connect_version() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        // HTTP/2 only, so the Connect handshake (HTTP/1.1) gets no answer.
        let server = tokio::spawn(
            Server::builder()
                .add_service(HandshakeServer::new(GrpcOnlyNewServer))
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );
        let channel = TonicChannel::connect(format!("http://{address}"))
            .await
            .unwrap();

        let offered = channel.served_versions(ProtocolVersion::ALL).await.unwrap();
        assert_eq!(
            offered
                .iter()
                .map(|entry| entry.version.as_str())
                .collect::<Vec<_>>(),
            ["v5"]
        );
        let status = sovereign_config_client::negotiate(&channel).await.unwrap();
        assert_eq!(status.protocol_version, ProtocolVersion::V5);
        server.abort();
    }

    #[test]
    fn service_endpoints_require_https_except_for_loopback() {
        assert!(validate_service_endpoint("https://config.example.test").is_ok());
        assert!(validate_service_endpoint("http://127.0.0.1:50051").is_ok());
        assert!(validate_service_endpoint("http://[::1]:50051").is_ok());
        assert!(validate_service_endpoint("http://config.example.test").is_err());
        assert!(validate_service_endpoint("ftp://config.example.test").is_err());
        assert!(validate_service_endpoint("not-a-url").is_err());
    }

    /// A transport reports the version it was built to speak, for every version
    /// this build speaks. What the CLI and MCP server display comes from the
    /// same value the routes are chosen from, so the two cannot disagree.
    #[tokio::test]
    async fn a_transport_reports_the_version_it_was_built_to_speak() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(
            Server::builder()
                .add_service(SystemServer::new(HangingSystem))
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );
        let channel = TonicChannel::connect_with_timeouts(
            format!("http://{address}"),
            Duration::from_secs(1),
            Duration::from_millis(25),
        )
        .unwrap();

        for version in ProtocolVersion::ALL.iter().copied() {
            assert_eq!(channel.speaking(version).protocol_version(), version);
        }
        server.abort();
    }

    /// Opening a channel dials nothing; a peer that accepts and then stalls is
    /// found, bounded and `Unavailable`, by the handshake that follows.
    #[tokio::test]
    async fn stalled_connection_is_bounded_and_unavailable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            pending::<()>().await;
        });

        let channel = TonicChannel::connect_with_timeouts(
            format!("https://{address}"),
            Duration::from_millis(25),
            Duration::from_secs(1),
        )
        .expect("opening a channel dials nothing");
        let error = tokio::time::timeout(
            Duration::from_secs(2),
            channel.served_versions(ProtocolVersion::ALL),
        )
        .await
        .expect("connection timeout was not enforced")
        .expect_err("stalled connection unexpectedly succeeded");

        assert_eq!(error.kind, ErrorKind::Unavailable);
        peer.abort();
    }

    #[tokio::test]
    async fn stalled_rpcs_are_bounded_and_unavailable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(
            Server::builder()
                .add_service(HandshakeServer::new(HangingHandshake))
                .add_service(SystemServer::new(HangingSystem))
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );
        let channel = TonicChannel::connect_with_timeouts(
            format!("http://{address}"),
            Duration::from_secs(1),
            Duration::from_millis(25),
        )
        .unwrap();

        let version = tokio::time::timeout(
            Duration::from_secs(1),
            channel.served_versions(ProtocolVersion::ALL),
        )
        .await
        .expect("version RPC timeout was not enforced")
        .unwrap_err();
        let identity = tokio::time::timeout(
            Duration::from_secs(1),
            channel
                // The hanging fixture is `v3`'s `System`.
                .speaking(ProtocolVersion::V3)
                .get_identity(&Secret::new("token-sentinel")),
        )
        .await
        .expect("identity RPC timeout was not enforced")
        .unwrap_err();

        assert_eq!(version.kind, ErrorKind::Unavailable);
        assert_eq!(identity.kind, ErrorKind::Unavailable);
        server.abort();
    }
}
