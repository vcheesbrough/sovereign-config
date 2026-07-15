use std::{net::IpAddr, time::Duration};

use async_trait::async_trait;
use http::Uri;
use sovereign_config_client::{RpcCode, Transport, VersionReply, map_rpc_status};
use sovereign_config_core::{AuthenticationStatus, ClientError, Secret};
use sovereign_config_proto::sovereign::config::v1::{
    GetIdentityRequest, GetVersionRequest, system_client::SystemClient,
};
use tonic::{
    Code, Request,
    metadata::MetadataValue,
    transport::{Channel, Endpoint},
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct TonicTransport {
    channel: Channel,
}

impl TonicTransport {
    /// Connects to a native gRPC endpoint without configuring retries.
    ///
    /// # Errors
    ///
    /// Returns a bounded invalid-request or unavailable error.
    pub async fn connect(endpoint: String) -> Result<Self, ClientError> {
        Self::connect_with_timeouts(endpoint, CONNECT_TIMEOUT, REQUEST_TIMEOUT).await
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

#[async_trait(?Send)]
impl Transport for TonicTransport {
    async fn get_version(&self, protocol_version: &str) -> Result<VersionReply, ClientError> {
        let mut client = SystemClient::new(self.channel.clone());
        let response = client
            .get_version(GetVersionRequest {
                protocol_version: protocol_version.to_owned(),
            })
            .await
            .map_err(|status| map_status(&status))?
            .into_inner();
        Ok(VersionReply {
            application_version: response.application_version,
            protocol_version: response.protocol_version,
        })
    }

    async fn get_identity(&self, bearer: &Secret) -> Result<AuthenticationStatus, ClientError> {
        let mut client = SystemClient::new(self.channel.clone());
        let mut request = Request::new(GetIdentityRequest {});
        let authorization = MetadataValue::try_from(format!("Bearer {}", bearer.expose()))
            .map_err(|_| map_rpc_status(RpcCode::InvalidArgument))?;
        request
            .metadata_mut()
            .insert("authorization", authorization);
        let response = client
            .get_identity(request)
            .await
            .map_err(|status| map_status(&status))?
            .into_inner();
        Ok(AuthenticationStatus {
            authenticated: response.authenticated,
        })
    }
}

fn map_status(status: &tonic::Status) -> ClientError {
    map_rpc_status(match status.code() {
        Code::Unauthenticated => RpcCode::Unauthenticated,
        Code::PermissionDenied => RpcCode::PermissionDenied,
        Code::FailedPrecondition => RpcCode::FailedPrecondition,
        Code::InvalidArgument => RpcCode::InvalidArgument,
        Code::Cancelled | Code::DeadlineExceeded | Code::Unavailable => RpcCode::Unavailable,
        _ => RpcCode::Other,
    })
}

#[cfg(test)]
mod tests {
    use std::{future::pending, time::Duration};

    use sovereign_config_client::Transport;
    use sovereign_config_core::{ErrorKind, Secret};
    use sovereign_config_proto::sovereign::config::v1::{
        GetIdentityRequest, GetIdentityResponse, GetVersionRequest, GetVersionResponse,
        system_server::{System, SystemServer},
    };
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::{Request, Response, Status, transport::Server};

    use super::{TonicTransport, validate_service_endpoint};

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
            TonicTransport::connect_with_timeouts(
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
                .add_service(SystemServer::new(HangingSystem))
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );
        let transport = TonicTransport::connect_with_timeouts(
            format!("http://{address}"),
            Duration::from_secs(1),
            Duration::from_millis(25),
        )
        .await
        .unwrap();

        let version = tokio::time::timeout(Duration::from_secs(1), transport.get_version("v1"))
            .await
            .expect("version RPC timeout was not enforced")
            .unwrap_err();
        let identity = tokio::time::timeout(
            Duration::from_secs(1),
            transport.get_identity(&Secret::new("token-sentinel")),
        )
        .await
        .expect("identity RPC timeout was not enforced")
        .unwrap_err();

        assert_eq!(version.kind, ErrorKind::Unavailable);
        assert_eq!(identity.kind, ErrorKind::Unavailable);
        server.abort();
    }
}
