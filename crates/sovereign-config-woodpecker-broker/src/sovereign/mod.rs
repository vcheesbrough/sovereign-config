//! The bridge between the `Send` HTTP world and the `!Send` Sovereign client.
//!
//! Every transport trait in this workspace is `#[async_trait(?Send)]` so the
//! same client can compile to WASM, and `axum::handler::Handler` requires
//! `Send` futures. The two cannot meet directly — and running axum on a
//! current-thread runtime does not help, because the bound is on the handler
//! type, not the runtime.
//!
//! So the `!Send` client lives on its own thread, driven by a `LocalSet`, and
//! HTTP handlers talk to it over a channel. [`SovereignHandle`] is `Send +
//! Clone` and owns no Sovereign type; everything in [`reader`] stays on the
//! reader thread.
//!
//! Requests are therefore **serialised**. For this workload — a few layers of a
//! handful of secrets, a few pipelines an hour — that is the right trade: it
//! also serialises token refresh for free, so concurrent pipelines cannot
//! stampede the issuer. The queue is bounded and sheds to 503 rather than
//! growing without limit. If pipeline concurrency ever outgrows one reader, the
//! fix is a small pool of reader threads, not a redesign.

pub(crate) mod reader;
pub(crate) mod token;

use std::{collections::BTreeMap, thread, time::Duration};

use sovereign_config_core::{ConfigPath, RevealedSecret, Secret};
use tokio::{
    runtime::Builder,
    sync::{mpsc, oneshot},
    task::LocalSet,
};

use crate::error::BrokerError;
use reader::SovereignReader;

pub(crate) enum Command {
    Fetch {
        layers: Vec<ConfigPath>,
        reply: oneshot::Sender<Result<BTreeMap<String, RevealedSecret>, BrokerError>>,
    },
}

/// A `Send` handle to the reader thread, held by axum state.
#[derive(Clone)]
pub(crate) struct SovereignHandle {
    commands: mpsc::Sender<Command>,
    root: ConfigPath,
}

impl SovereignHandle {
    /// Resolves the given layers, merging later layers over earlier ones.
    ///
    /// # Errors
    ///
    /// [`BrokerError::Overloaded`] when the reader queue is full — shedding
    /// load rather than letting the HTTP task block behind an unbounded
    /// backlog — or the reader's own error.
    pub(crate) async fn fetch(
        &self,
        layers: Vec<ConfigPath>,
    ) -> Result<BTreeMap<String, RevealedSecret>, BrokerError> {
        let (reply, response) = oneshot::channel();
        self.commands
            .try_send(Command::Fetch { layers, reply })
            .map_err(|_| BrokerError::Overloaded)?;
        response.await.map_err(|_| BrokerError::Unavailable)?
    }

    /// The configuration root this connection is confined to. Not secret.
    pub(crate) fn root(&self) -> &ConfigPath {
        &self.root
    }

    /// True while the reader thread is still accepting commands.
    pub(crate) fn is_live(&self) -> bool {
        !self.commands.is_closed()
    }
}

/// Starts the reader thread and waits for it to connect.
///
/// Returns only once the gRPC channel is up and `System.GetVersion` has agreed
/// on the protocol version, so a bad connection URL, an unreachable service, or
/// a protocol mismatch fails **startup** rather than the first pipeline.
///
/// # Errors
///
/// Propagates the connection failure, already reduced to a bounded message.
pub(crate) fn spawn(
    connection_url: Secret,
    queue_depth: usize,
    token_ttl: Duration,
) -> Result<SovereignHandle, ConnectError> {
    let (commands, mut inbox) = mpsc::channel(queue_depth);
    let (ready, connected) = std::sync::mpsc::channel();

    thread::Builder::new()
        .name("sovereign-reader".to_owned())
        .spawn(move || {
            let Ok(runtime) = Builder::new_current_thread().enable_all().build() else {
                let _ = ready.send(Err(ConnectError::Runtime));
                return;
            };
            LocalSet::new().block_on(&runtime, async move {
                let reader = match SovereignReader::connect(&connection_url, token_ttl).await {
                    Ok(reader) => {
                        if ready.send(Ok(reader.root().clone())).is_err() {
                            return;
                        }
                        reader
                    }
                    Err(error) => {
                        let _ = ready.send(Err(error));
                        return;
                    }
                };
                while let Some(command) = inbox.recv().await {
                    match command {
                        Command::Fetch { layers, reply } => {
                            // A caller that gave up is not an error; the next
                            // command is served regardless.
                            let _ = reply.send(reader.fetch(&layers).await);
                        }
                    }
                }
            });
        })
        .map_err(|_| ConnectError::Runtime)?;

    let root = connected.recv().map_err(|_| ConnectError::Runtime)??;
    Ok(SovereignHandle { commands, root })
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
