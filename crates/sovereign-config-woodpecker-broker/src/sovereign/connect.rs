//! Opening the broker's one managed connection.
//!
//! The broker holds a single, long-lived, read-only managed connection. A human
//! login URL is refused outright: there is nobody at a terminal to complete a
//! device flow, and a refresh credential on disk is not what a CI extension
//! should be carrying.

use std::time::Duration;

use sovereign_config_client::negotiate;
use sovereign_config_core::{ConfigPath, ConnectionUrl, ErrorKind, Secret};
use sovereign_config_layers::{CachedTokenProvider, LayerReader, Naming, OnMissing};
use sovereign_config_native::{TonicChannel, TonicTransport};

pub(crate) type BrokerReader = LayerReader<TonicTransport, CachedTokenProvider>;

pub(crate) struct Connected {
    pub(crate) reader: BrokerReader,
    /// The configuration root this connection is confined to. Not secret.
    pub(crate) root: ConfigPath,
}

/// Parses the connection URL, opens the channel, and negotiates protocol
/// compatibility. No token is acquired here.
///
/// # Errors
///
/// Returns a bounded [`ConnectError`] for a malformed or human-login URL, an
/// unreachable service, or a protocol mismatch. Nothing derived from the URL
/// reaches the error.
pub(crate) async fn connect(url: &Secret, token_ttl: Duration) -> Result<Connected, ConnectError> {
    let connection = ConnectionUrl::parse(url.expose()).map_err(|_| ConnectError::MalformedUrl)?;
    let authentication = connection
        .client_authentication()
        .ok_or(ConnectError::UnsupportedCredential)?
        .clone();
    let channel = TonicChannel::connect(connection.endpoint().to_owned())
        .await
        .map_err(|_| ConnectError::Unavailable)?;
    let status = negotiate(&channel)
        .await
        .map_err(|error| match error.kind {
            ErrorKind::IncompatibleProtocol => ConnectError::IncompatibleProtocol,
            _ => ConnectError::Unavailable,
        })?;
    // Every layer read the broker serves for the life of this connection
    // travels on the version negotiated here, and is counted under it.
    let transport = channel.speaking(status.protocol_version);
    let tokens = CachedTokenProvider::new(
        connection.issuer().to_owned(),
        connection.client_id().to_owned(),
        authentication,
        token_ttl,
    );
    Ok(Connected {
        // `Skip`: an absent or unreadable layer is ordinary here — a repository
        // simply may have no per-repo layer — and matches the Go broker's
        // treatment of `OpenBao` 404 and 403. `Folded`: Woodpecker matches a
        // `from_secret:` reference by exact lowercase string.
        reader: LayerReader::new(transport, tokens, OnMissing::Skip, Naming::Folded),
        root: connection.root().clone(),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ConnectError {
    #[error("the connection URL is not a valid managed connection URL")]
    MalformedUrl,
    #[error("the connection URL is a human login URL, not a managed connection")]
    UnsupportedCredential,
    #[error("the configuration service is unreachable")]
    Unavailable,
    #[error("the configuration service speaks a different protocol version")]
    IncompatibleProtocol,
    #[error("the reader could not be started")]
    Runtime,
}
