#![forbid(unsafe_code)]

mod connection;
mod error;
mod json;
mod listing;
mod managed;
mod path;
mod plain;
mod status;
mod value;

pub const MASKED_SECRET_TEXT: &str = "********";

pub use connection::{ConnectionUrl, ConnectionUrlError};
pub use error::{ClientError, ErrorKind};
pub use json::{parse_subtree_json, render_subtree_json};
pub use listing::{
    AddPathMetadata, DeleteMetadata, ListedValue, PutMetadata, ReplaceMetadata,
    SubTreeMutationContent, SubTreeMutationValue, SubTreeValue, Timestamp, ValueListing,
    ValuePaths, ValueSubTree,
};
pub use managed::{
    ConnectionId, DisplayName, MAX_CONNECTION_ID_CHARS, MAX_DISPLAY_NAME_CHARS,
    MIN_CONNECTION_ID_CHARS, ManagedConnectionMetadata, ManagedConnectionState, ManagedPermission,
    ManagedPermissions, ProvisionedManagedConnection, RevealedConnectionUrl,
};
pub use path::{ConfigPath, PathError};
pub use plain::render_subtree_plain;
pub use status::{AuthenticationStatus, ProtocolVersion, ServiceStatus};
pub use value::{
    MaskedSecret, PlainValue, RevealedSecret, Secret, SecretInput, ValueClassification,
    ValueContent,
};

#[cfg(test)]
mod tests;
