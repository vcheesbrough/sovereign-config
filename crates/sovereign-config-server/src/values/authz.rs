use sovereign_config_core::ConfigPath;
use sovereign_config_proto::sovereign::config::v3::{
    DeleteValuesRequest, GetSubTreeRequest, ListValuePathsRequest, PutValueRequest,
    ReplaceSubTreeRequest, RevealSecretRequest,
};
use tonic::{Request, Status};

use crate::auth::Permission;
use crate::rpc::principal;

#[expect(
    clippy::result_large_err,
    reason = "tonic::Status is the crate's RPC error type and is returned by value"
)]
pub(super) fn authorize<T>(
    request: &Request<T>,
    permissions: &[Permission],
    allow_root: bool,
) -> Result<ConfigPath, Status>
where
    T: ValueRequest,
{
    let path = if allow_root {
        ConfigPath::parse_selection(request.get_ref().path())
    } else {
        ConfigPath::parse_operation(request.get_ref().path())
    }
    .map_err(|_| Status::invalid_argument("configuration path is invalid"))?;
    let principal = principal(request)?;
    if permissions
        .iter()
        .any(|permission| !principal.allows(&path, *permission))
    {
        return Err(Status::permission_denied(
            "configuration operation is not permitted",
        ));
    }
    Ok(path)
}

pub(super) trait ValueRequest {
    fn path(&self) -> &str;
}

impl ValueRequest for GetSubTreeRequest {
    fn path(&self) -> &str {
        &self.path
    }
}

impl ValueRequest for PutValueRequest {
    fn path(&self) -> &str {
        &self.path
    }
}

impl ValueRequest for ReplaceSubTreeRequest {
    fn path(&self) -> &str {
        &self.path
    }
}

impl ValueRequest for DeleteValuesRequest {
    fn path(&self) -> &str {
        &self.path
    }
}

impl ValueRequest for RevealSecretRequest {
    fn path(&self) -> &str {
        &self.path
    }
}

impl ValueRequest for ListValuePathsRequest {
    fn path(&self) -> &str {
        &self.path
    }
}
