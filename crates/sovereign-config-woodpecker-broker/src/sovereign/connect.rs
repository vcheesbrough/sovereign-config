//! Opening the broker's one managed connection.
//!
//! The broker holds a single, long-lived, read-only managed connection. A human
//! login URL is refused outright: there is nobody at a terminal to complete a
//! device flow, and a refresh credential on disk is not what a CI extension
//! should be carrying.

use std::{rc::Rc, time::Duration};

use sovereign_config_client::Session;
use sovereign_config_core::{ConfigPath, ConnectionUrl, ErrorKind, Secret};
use sovereign_config_layers::{CachedTokenProvider, LayerReader, Naming, OnMissing};
use sovereign_config_native::{TonicChannel, TonicTransport};

pub(crate) type BrokerReader = LayerReader<TonicTransport, Rc<CachedTokenProvider>>;

/// The broker's one long-lived connection.
///
/// It keeps the negotiated [`Session`] rather than a bare transport, so a
/// version retired under it is recovered: the session re-handshakes once and
/// the read is retried on the new version. The token provider is shared rather
/// than owned by a reader, because a reader is rebuilt whenever that happens
/// and duplicating the provider would duplicate its token cache.
pub(crate) struct Connected {
    pub(crate) session: Session<TonicChannel>,
    pub(crate) tokens: Rc<CachedTokenProvider>,
    /// The configuration root this connection is confined to. Not secret.
    pub(crate) root: ConfigPath,
}

impl Connected {
    /// A reader for one fetch, over `transport`.
    ///
    /// `Skip`: an absent or unreadable layer is ordinary here — a repository
    /// simply may have no per-repo layer — and matches the Go broker's
    /// treatment of `OpenBao` 404 and 403. `Folded`: Woodpecker matches a
    /// `from_secret:` reference by exact lowercase string.
    pub(crate) fn reader(&self, transport: TonicTransport) -> BrokerReader {
        LayerReader::new(
            transport,
            Rc::clone(&self.tokens),
            OnMissing::Skip,
            Naming::Folded,
        )
    }
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
    // Every layer read the broker serves travels on the version negotiated
    // here, and is counted under it — until the service retires that version,
    // at which point the session negotiates again and the reads follow.
    let session = Session::open(channel)
        .await
        .map_err(|error| match error.kind {
            ErrorKind::IncompatibleProtocol => ConnectError::IncompatibleProtocol,
            _ => ConnectError::Unavailable,
        })?;
    let tokens = Rc::new(CachedTokenProvider::new(
        connection.issuer().to_owned(),
        connection.client_id().to_owned(),
        authentication,
        token_ttl,
    ));
    Ok(Connected {
        session,
        tokens,
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
