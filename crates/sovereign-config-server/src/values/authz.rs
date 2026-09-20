use sovereign_config_core::ConfigPath;
use tonic::Status;

use crate::auth::Permission;
use crate::rpc::CallContext;

#[expect(
    clippy::result_large_err,
    reason = "tonic::Status is the crate's RPC error type and is returned by value"
)]
pub(super) fn authorize(
    context: &CallContext<'_>,
    path: &str,
    permissions: &[Permission],
    allow_root: bool,
) -> Result<ConfigPath, Status> {
    let path = if allow_root {
        ConfigPath::parse_selection(path)
    } else {
        ConfigPath::parse_operation(path)
    }
    .map_err(|_| Status::invalid_argument("configuration path is invalid"))?;
    let principal = context.principal()?;
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
