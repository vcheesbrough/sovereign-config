use async_trait::async_trait;
use sovereign_config_client::{RpcCode, Transport, VersionReply, map_rpc_status};
use sovereign_config_core::{AuthenticationStatus, ClientError, Secret};
use sovereign_config_proto::sovereign::config::v1::{
    GetIdentityRequest, GetVersionRequest, system_client::SystemClient,
};
use tonic::{Code, Request, metadata::MetadataValue, transport::Channel};

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
        let channel = Channel::from_shared(endpoint)
            .map_err(|_| map_rpc_status(RpcCode::InvalidArgument))?
            .connect()
            .await
            .map_err(|_| map_rpc_status(RpcCode::Unavailable))?;
        Ok(Self { channel })
    }
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
        Code::Unavailable => RpcCode::Unavailable,
        _ => RpcCode::Other,
    })
}
