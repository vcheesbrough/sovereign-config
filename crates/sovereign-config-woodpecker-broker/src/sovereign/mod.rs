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
//! Clone` and owns no Sovereign type; the [`LayerReader`] stays on the reader
//! thread.
//!
//! Requests are therefore **serialised**. For this workload — a few layers of a
//! handful of secrets, a few pipelines an hour — that is the right trade: it
//! also serialises token refresh for free, so concurrent pipelines cannot
//! stampede the issuer. The queue is bounded and sheds to 503 rather than
//! growing without limit. If pipeline concurrency ever outgrows one reader, the
//! fix is a small pool of reader threads, not a redesign.
//!
//! The read itself — per-layer `GetSubTree`, per-secret `RevealSecret`,
//! direct-children-only naming, later-wins merge — lives in
//! `sovereign-config-layers`, shared with the CLI's `render`. What stays here
//! is the threading bridge and the connection handshake.

mod connect;

use std::{collections::BTreeMap, thread, time::Duration};

use sovereign_config_core::{ConfigPath, RevealedSecret, Secret};
use tokio::{
    runtime::Builder,
    sync::{mpsc, oneshot},
    task::LocalSet,
};

use crate::error::BrokerError;
pub(crate) use connect::ConnectError;

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
    /// backlog. [`BrokerError::ReaderGone`] when the reader thread has exited,
    /// which is a distinct failure from being merely busy: kept as a separate
    /// metric outcome so the two do not look like the same incident. Otherwise
    /// the reader's own error.
    pub(crate) async fn fetch(
        &self,
        layers: Vec<ConfigPath>,
    ) -> Result<BTreeMap<String, RevealedSecret>, BrokerError> {
        let (reply, response) = oneshot::channel();
        match self.commands.try_send(Command::Fetch { layers, reply }) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => return Err(BrokerError::Overloaded),
            Err(mpsc::error::TrySendError::Closed(_)) => return Err(BrokerError::ReaderGone),
        }
        response.await.map_err(|_| BrokerError::ReaderGone)?
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
                let reader = match connect::connect(&connection_url, token_ttl).await {
                    Ok(connected) => {
                        if ready.send(Ok(connected.root)).is_err() {
                            return;
                        }
                        connected.reader
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
                            let _ = reply.send(reader.fetch(&layers).await.map_err(Into::into));
                        }
                    }
                }
            });
        })
        .map_err(|_| ConnectError::Runtime)?;

    let root = connected.recv().map_err(|_| ConnectError::Runtime)??;
    Ok(SovereignHandle { commands, root })
}

#[cfg(test)]
mod tests {
    use sovereign_config_core::ConfigPath;
    use tokio::sync::{mpsc, oneshot};

    use super::{Command, SovereignHandle};

    fn handle(depth: usize) -> (SovereignHandle, mpsc::Receiver<Command>) {
        let (commands, inbox) = mpsc::channel(depth);
        let root = ConfigPath::parse("/woodpecker").unwrap();
        (SovereignHandle { commands, root }, inbox)
    }

    // The two ways `fetch` can fail to reach the reader are operationally
    // different — one says "wait and retry", the other says "restart the
    // container" — so they must not collapse onto the same metric outcome.
    #[tokio::test]
    async fn a_reader_that_has_exited_is_distinct_from_a_full_queue() {
        let (live_but_full, mut inbox) = handle(1);
        let (reply, _response) = oneshot::channel();
        // Fill the one slot without draining it, so the next `try_send` sees
        // `Full`, not `Closed`.
        live_but_full
            .commands
            .try_send(Command::Fetch {
                layers: Vec::new(),
                reply,
            })
            .unwrap();
        assert_eq!(
            live_but_full.fetch(Vec::new()).await.unwrap_err().outcome(),
            "overloaded"
        );
        inbox.close();

        let (gone, inbox) = handle(1);
        drop(inbox); // the reader thread has exited
        assert_eq!(
            gone.fetch(Vec::new()).await.unwrap_err().outcome(),
            "reader_gone"
        );
    }
}
