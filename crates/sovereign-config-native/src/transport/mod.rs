//! The native gRPC transport.
//!
//! A connection is opened as a [`TonicChannel`], which can do exactly one
//! thing: ask a service which protocol versions it serves. Only
//! [`TonicChannel::speaking`] — handed the version negotiation settled on —
//! produces a [`TonicTransport`] that can carry configuration traffic. The
//! version an operator is shown and the version on the wire are therefore the
//! same value, rather than two values kept equal by hand.
//!
//! Each version's routes and mapping live in their own module, selected by
//! [`dialer`]. That match is exhaustive over [`ProtocolVersion`], so declaring
//! a version this transport cannot dial does not compile.

mod adapter;
mod v3;
mod v4;

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
    NegotiateRequest, handshake_client::HandshakeClient,
};
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
fn dialer(version: ProtocolVersion, channel: Channel) -> Box<dyn SessionTransport> {
    match version {
        ProtocolVersion::V4 => Box::new(v4::Dialer::new(channel)),
        ProtocolVersion::V3 => Box::new(v3::Dialer::new(channel)),
    }
}

/// A connected channel that has not yet agreed a protocol version.
///
/// It can only negotiate: there is no route to carry configuration traffic on
/// until [`Handshake::get_version`] has said which version the service serves.
#[derive(Clone)]
pub struct TonicChannel {
    channel: Channel,
}

impl TonicChannel {
    /// Connects to a native gRPC endpoint without configuring retries.
    ///
    /// # Errors
    ///
    /// Returns a bounded invalid-request or unavailable error.
    pub async fn connect(endpoint: String) -> Result<Self, ClientError> {
        Self::connect_with_timeouts(endpoint, CONNECT_TIMEOUT, REQUEST_TIMEOUT).await
    }

    /// The transport for a session that negotiated `version`.
    ///
    /// Every RPC it issues travels on `version`'s routes, and it reports
    /// `version` as the one it speaks.
    #[must_use]
    pub fn speaking(&self, version: ProtocolVersion) -> TonicTransport {
        TonicTransport {
            channel: self.channel.clone(),
            version,
        }
    }

    async fn connect_with_timeouts(
        endpoint: String,
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> Result<Self, ClientError> {
        validate_service_endpoint(&endpoint)?;
        let endpoint = Endpoint::new(endpoint)
            .map_err(|_| map_rpc_status(RpcCode::InvalidArgument))?
            .connect_timeout(connect_timeout)
            .timeout(request_timeout);
        let channel = tokio::time::timeout(connect_timeout, endpoint.connect())
            .await
            .map_err(|_| map_rpc_status(RpcCode::Unavailable))?
            .map_err(|_| map_rpc_status(RpcCode::Unavailable))?;
        Ok(Self { channel })
    }
}

#[async_trait(?Send)]
impl Handshake for TonicChannel {
    async fn served_versions(
        &self,
        client_versions: &[ProtocolVersion],
    ) -> Result<Vec<ServedVersion>, ClientError> {
        let served = HandshakeClient::new(self.channel.clone())
            .negotiate(Request::new(NegotiateRequest {
                client_protocol_versions: client_versions
                    .iter()
                    .map(|version| version.as_str().to_owned())
                    .collect(),
            }))
            .await
            .map_err(|status| map_status(&status))?
            .into_inner();

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
        dialer(ProtocolVersion::LEGACY, self.channel.clone())
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

/// A native gRPC transport bound to one negotiated protocol version.
#[derive(Clone)]
pub struct TonicTransport {
    channel: Channel,
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
        dialer(self.version, self.channel.clone())
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
        .await
        .unwrap();

        for version in ProtocolVersion::ALL.iter().copied() {
            assert_eq!(channel.speaking(version).protocol_version(), version);
        }
        server.abort();
    }

    #[tokio::test]
    async fn stalled_connection_is_bounded_and_unavailable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            pending::<()>().await;
        });

        let result = tokio::time::timeout(
            Duration::from_secs(1),
            TonicChannel::connect_with_timeouts(
                format!("https://{address}"),
                Duration::from_millis(25),
                Duration::from_secs(1),
            ),
        )
        .await
        .expect("connection timeout was not enforced");
        let error = result
            .err()
            .expect("stalled connection unexpectedly succeeded");

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
        .await
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
