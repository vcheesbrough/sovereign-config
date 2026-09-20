#![forbid(unsafe_code)]

use std::{
    future::Future,
    sync::{Mutex, MutexGuard},
};

use async_trait::async_trait;
use sovereign_config_core::{
    AddPathMetadata, AuthenticationStatus, ClientError, ConfigPath, ConnectionId, DeleteMetadata,
    DisplayName, ErrorKind, ManagedConnectionMetadata, ManagedPermissions, PlainValue,
    ProtocolVersion, ProvisionedManagedConnection, PutMetadata, ReplaceMetadata, RevealedSecret,
    Secret, SecretInput, ServedVersion, ServiceStatus, SubTreeMutationValue, Timestamp,
    ValueListing, ValuePaths, ValueSubTree,
};
use tracing::{info, warn};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RpcCode {
    Unauthenticated,
    PermissionDenied,
    FailedPrecondition,
    /// The server has no handler for the route that was called.
    ///
    /// For a client built from one protocol version's stubs this means the
    /// server does not speak what the client speaks: either that version's
    /// package has been retired, or the server predates an RPC the client
    /// relies on. It is what an already-connected client sees on its next call
    /// after a retirement, so it must read as a protocol incompatibility rather
    /// than an opaque internal error.
    Unimplemented,
    /// The service does not serve the protocol version the route named.
    ///
    /// Distinct from [`RpcCode::Unimplemented`], and only ever produced by a
    /// transport that recognised the service's own version-not-served marker —
    /// never inferred from a status code alone. A session that sees it
    /// re-handshakes once and retries; the rejected call never executed.
    VersionNotServed,
    InvalidArgument,
    NotFound,
    AlreadyExists,
    Unavailable,
    Other,
}

#[must_use]
pub fn map_rpc_status(code: RpcCode) -> ClientError {
    match code {
        RpcCode::Unauthenticated => {
            ClientError::new(ErrorKind::Unauthenticated, "authentication required")
        }
        RpcCode::PermissionDenied => {
            ClientError::new(ErrorKind::PermissionDenied, "permission denied")
        }
        RpcCode::FailedPrecondition | RpcCode::Unimplemented => ClientError::new(
            ErrorKind::IncompatibleProtocol,
            "service protocol is incompatible",
        ),
        RpcCode::VersionNotServed => ClientError::new(
            ErrorKind::VersionNotServed,
            "the service no longer serves this protocol version",
        ),
        RpcCode::InvalidArgument => {
            ClientError::new(ErrorKind::InvalidRequest, "request is invalid")
        }
        RpcCode::NotFound => ClientError::new(ErrorKind::NotFound, "configuration value not found"),
        RpcCode::AlreadyExists => {
            ClientError::new(ErrorKind::Conflict, "configuration path already exists")
        }
        RpcCode::Unavailable => ClientError::new(ErrorKind::Unavailable, "service is unavailable"),
        RpcCode::Other => ClientError::new(ErrorKind::Internal, "request failed"),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionReply {
    pub application_version: String,
    /// The version the session will speak, echoed by the server.
    pub protocol_version: String,
    /// Every version the server serves. Empty from a server older than 2.25.0,
    /// which [`ServiceStatus::negotiate`] treats as `[protocol_version]`.
    pub supported_protocol_versions: Vec<String>,
}

/// A connection that has not yet agreed a protocol version.
///
/// It can do two things, and only these two: call the **unversioned
/// handshake**, and — for a service too old to have one — call `GetVersion` on
/// the legacy version's own route. [`negotiate`] is what turns either into a
/// session.
#[async_trait(?Send)]
pub trait Handshake {
    /// Calls `/sovereign.config.Handshake/Negotiate`, sending `client_versions`.
    ///
    /// The list is for the service's usage records: it must not change the
    /// answer, which is always the service's whole served set, most preferred
    /// first.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Unauthenticated`] or
    /// [`ErrorKind::IncompatibleProtocol`] from a service that has no
    /// handshake — see [`negotiate`] — and a bounded transport error otherwise.
    async fn served_versions(
        &self,
        client_versions: &[ProtocolVersion],
    ) -> Result<Vec<ServedVersion>, ClientError>;

    /// Calls `GetVersion` on [`ProtocolVersion::LEGACY`]'s own route.
    ///
    /// The fallback for a service that predates the handshake, and the only
    /// reason a versioned route is ever dialled before negotiation.
    ///
    /// # Errors
    ///
    /// Returns a bounded transport error.
    async fn legacy_version(&self) -> Result<VersionReply, ClientError>;
}

/// Whether a handshake failure means "this service has no handshake" rather
/// than "the handshake failed".
///
/// **This is not just `UNIMPLEMENTED`, and getting it wrong strands every
/// client against every deployed server.** Servers up to 2.27 authenticate
/// *before* they route, and exempt only the health probes and
/// `<served>.System/GetVersion`. The handshake is called with no token, so a
/// real deployed server refuses it `UNAUTHENTICATED` and the request never
/// reaches the router that would have said `UNIMPLEMENTED`. Only a bare router
/// — a test fixture, or a server behind no authentication at all — produces the
/// answer the obvious implementation would look for.
///
/// Treating `UNAUTHENTICATED` as "no handshake" cannot mask a genuine
/// authentication problem: a server that *has* the handshake exempts it, so it
/// never answers that way, and the fallback below only succeeds against a
/// server that answers the legacy route unauthenticated too.
fn predates_the_handshake(error: &ClientError) -> bool {
    matches!(
        error.kind,
        ErrorKind::Unauthenticated | ErrorKind::IncompatibleProtocol
    )
}

/// What a service that has no handshake serves.
///
/// Exactly one version: a pre-handshake server routes `GetVersion` by version,
/// so the legacy route answering *at all* is the proof that it serves that
/// version. The echo confirms it — `GetVersion` returns the version that was
/// requested whenever it is served, and falls back to another when it is not.
async fn legacy_served<H>(handshake: &H) -> Result<Vec<ServedVersion>, ClientError>
where
    H: Handshake + ?Sized,
{
    let reply = handshake.legacy_version().await?;
    if reply.protocol_version == ProtocolVersion::LEGACY.as_str() {
        return Ok(vec![ServedVersion::new(ProtocolVersion::LEGACY.as_str())]);
    }

    // It answered, but about a different version: it does not serve the legacy
    // one, and a pre-handshake server has nothing else this build could dial.
    // Hand back whatever it did advertise so selection reports both lists,
    // rather than a bare mismatch an operator cannot act on.
    Ok(if reply.supported_protocol_versions.is_empty() {
        vec![ServedVersion::new(&reply.protocol_version)]
    } else {
        reply
            .supported_protocol_versions
            .iter()
            .map(|version| ServedVersion::new(version))
            .collect()
    })
}

/// Negotiates the version a session will speak, on one unversioned handshake.
///
/// Sends every version this build speaks, and selects from the service's
/// answer in the service's own preference order — passing over a version
/// carrying a deprecation date while a version without one remains.
///
/// A service with no handshake is reached through the legacy fallback, which is
/// what lets a **newer client reach an older server**: the mirror of the
/// older-client case negotiation already covers, and the case a
/// single-version workspace never exercises by accident.
///
/// This runs once per session. A version retired under an already-connected
/// client is recovered by [`Session::call`], which re-handshakes once and
/// retries — the rejected call never executed, so the retry is safe.
///
/// # Errors
///
/// Returns a bounded transport error, or [`ErrorKind::IncompatibleProtocol`],
/// naming both lists, when no version is common to this build and the service.
pub async fn negotiate<H>(handshake: &H) -> Result<ServiceStatus, ClientError>
where
    H: Handshake + ?Sized,
{
    let served = match handshake.served_versions(ProtocolVersion::ALL).await {
        Ok(served) => served,
        Err(error) if predates_the_handshake(&error) => legacy_served(handshake).await?,
        Err(error) => return Err(error),
    };
    let status = ServiceStatus::select(&served)?;
    if let Some(date) = &status.deprecation_date {
        // Warn, never fail: a deprecation date is a statement of intent, and a
        // client that refused the version would break on the announcement
        // rather than on the retirement it is being warned about.
        warn!(
            protocol_version = status.protocol_version.as_str(),
            deprecation_date = date.as_str(),
            "the configuration service has announced a retirement date for the protocol version this session speaks"
        );
    }
    Ok(status)
}

/// A connection that can negotiate **and** produce a transport for a version.
///
/// The pair is what a re-handshake needs: somewhere to ask again, and a way to
/// obtain a transport for whatever the answer turns out to be.
pub trait Connection: Handshake {
    /// A transport bound to one protocol version.
    type Transport: Clone;

    /// The transport for a session that negotiated `version`.
    ///
    /// Always a **new** transport. Rebinding an existing one would leave every
    /// handle that had already been taken dialling the old version's routes
    /// while reporting the new one.
    fn speaking(&self, version: ProtocolVersion) -> Self::Transport;
}

struct SessionState<T> {
    version: ProtocolVersion,
    deprecation_date: Option<String>,
    transport: T,
}

/// A negotiated session that recovers from its version being retired.
///
/// **This is the one implementation of the re-handshake**, shared by every
/// long-lived holder — the provider, the browser session, the broker's layer
/// reader. The short-lived callers (the CLI, the MCP server) reconnect per
/// operation and negotiate again anyway.
pub struct Session<C: Connection> {
    connection: C,
    state: Mutex<SessionState<C::Transport>>,
}

impl<C: Connection> Session<C> {
    /// Negotiates and binds a transport to the result.
    ///
    /// # Errors
    ///
    /// Returns whatever [`negotiate`] returns.
    pub async fn open(connection: C) -> Result<Self, ClientError> {
        let status = negotiate(&connection).await?;
        let transport = connection.speaking(status.protocol_version);
        Ok(Self {
            connection,
            state: Mutex::new(SessionState {
                version: status.protocol_version,
                deprecation_date: status.deprecation_date,
                transport,
            }),
        })
    }

    fn state(&self) -> MutexGuard<'_, SessionState<C::Transport>> {
        // A poisoned lock means a previous holder panicked mid-swap. The state
        // is three independent values replaced together under this guard, so
        // there is no torn state to recover from and nothing to gain by
        // propagating the panic to every later caller.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The version this session currently speaks.
    ///
    /// Follows a re-handshake, so what an operator is shown is always the
    /// version the next call will actually travel on.
    #[must_use]
    pub fn protocol_version(&self) -> ProtocolVersion {
        self.state().version
    }

    /// The announced retirement date of the version this session speaks, if any.
    #[must_use]
    pub fn deprecation_date(&self) -> Option<String> {
        self.state().deprecation_date.clone()
    }

    /// A transport for the version this session currently speaks.
    #[must_use]
    pub fn transport(&self) -> C::Transport {
        self.state().transport.clone()
    }

    /// The connection this session negotiated over.
    pub const fn connection(&self) -> &C {
        &self.connection
    }

    /// Runs `operation`, re-handshaking **once** if the service has stopped
    /// serving this session's version.
    ///
    /// The rejected call never executed — that is what the version-not-served
    /// error means, and why the retry is safe. Anything else is returned as it
    /// is: a re-handshake is not a general-purpose retry.
    ///
    /// # Errors
    ///
    /// Returns the operation's own error, or the re-handshake's if that is what
    /// failed — an incompatible service naming both lists is more use to an
    /// operator than the version-not-served error that triggered it.
    pub async fn call<O, F, R>(&self, operation: O) -> Result<R, ClientError>
    where
        O: Fn(C::Transport) -> F,
        F: Future<Output = Result<R, ClientError>>,
    {
        match operation(self.transport()).await {
            Err(error) if error.kind == ErrorKind::VersionNotServed => {
                let transport = self.renegotiate().await?;
                operation(transport).await
            }
            outcome => outcome,
        }
    }

    /// Negotiates again and swaps in a transport for the new version.
    async fn renegotiate(&self) -> Result<C::Transport, ClientError> {
        let previous = self.protocol_version();
        let status = negotiate(&self.connection).await?;
        let transport = self.connection.speaking(status.protocol_version);
        {
            let mut state = self.state();
            state.version = status.protocol_version;
            state.deprecation_date.clone_from(&status.deprecation_date);
            state.transport = transport.clone();
        }
        // The change of version is what keeps a retirement observable, which
        // was the whole argument for failing fast instead of renegotiating.
        info!(
            previous_protocol_version = previous.as_str(),
            protocol_version = status.protocol_version.as_str(),
            "the configuration service retired this session's protocol version; renegotiated"
        );
        Ok(transport)
    }
}

/// A transport bound to the one protocol version its session negotiated.
///
/// Every RPC issued through it travels on that version's routes. There is no
/// way to obtain one without naming a version, which is what keeps the version
/// an operator is shown and the version on the wire the same thing.
#[async_trait(?Send)]
pub trait Transport {
    async fn get_identity(&self, bearer: &Secret) -> Result<AuthenticationStatus, ClientError>;
}

#[async_trait(?Send)]
pub trait ValueTransport: Transport {
    async fn list_values(
        &self,
        path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<ValueListing, ClientError>;

    async fn get_subtree(
        &self,
        path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<ValueSubTree, ClientError>;
    async fn put_value(
        &self,
        path: &ConfigPath,
        value: &PlainValue,
        bearer: &Secret,
    ) -> Result<PutMetadata, ClientError>;
    async fn put_secret(
        &self,
        path: &ConfigPath,
        value: &SecretInput,
        bearer: &Secret,
    ) -> Result<PutMetadata, ClientError>;
    async fn replace_subtree(
        &self,
        path: &ConfigPath,
        values: &[SubTreeMutationValue],
        bearer: &Secret,
    ) -> Result<ReplaceMetadata, ClientError>;
    async fn delete_values(
        &self,
        path: &ConfigPath,
        recurse: bool,
        bearer: &Secret,
    ) -> Result<DeleteMetadata, ClientError>;
    async fn reveal_secret(
        &self,
        path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<RevealedSecret, ClientError>;
    async fn add_value_path(
        &self,
        source: &ConfigPath,
        new_path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<AddPathMetadata, ClientError>;
    async fn list_value_paths(
        &self,
        path: &ConfigPath,
        bearer: &Secret,
    ) -> Result<ValuePaths, ClientError>;
}

#[async_trait(?Send)]
pub trait ManagedConnectionTransport: Transport {
    async fn list_managed_connections(
        &self,
        bearer: &Secret,
    ) -> Result<Vec<ManagedConnectionMetadata>, ClientError>;
    async fn create_managed_connection(
        &self,
        display_name: &DisplayName,
        root: &ConfigPath,
        permissions: &ManagedPermissions,
        bearer: &Secret,
    ) -> Result<ProvisionedManagedConnection, ClientError>;
    async fn rotate_managed_connection(
        &self,
        connection_id: &ConnectionId,
        bearer: &Secret,
    ) -> Result<ProvisionedManagedConnection, ClientError>;
    async fn revoke_managed_connection(
        &self,
        connection_id: &ConnectionId,
        bearer: &Secret,
    ) -> Result<(), ClientError>;
}

/// Everything one protocol version's routes can carry.
///
/// A transport holds the dialer for the version its session negotiated as a
/// single object of this trait, so selecting a version is one decision made in
/// one place rather than one per RPC surface. Each `sovereign.config.vN` client
/// module implements it, holding that version's stubs or route paths and its
/// proto↔core mapping — which is what makes retiring a version a deletion.
#[async_trait(?Send)]
pub trait SessionTransport: ValueTransport + ManagedConnectionTransport {
    /// The version whose routes this dialer dials.
    ///
    /// Declared by the same module that owns the routes, so a session reports
    /// the version it is actually speaking rather than one carried alongside.
    fn version(&self) -> ProtocolVersion;

    /// Asks the service about **this** version, on this version's route.
    ///
    /// It takes no version, deliberately. A dialer can only ask about the
    /// version whose routes it dials, so the version named in the request and
    /// the package named in the path are read from one module and cannot
    /// disagree. Choosing *which* version to ask about is [`Handshake`]'s job,
    /// and it makes that choice by selecting the dialer.
    async fn get_version(&self) -> Result<VersionReply, ClientError>;
}

#[async_trait(?Send)]
pub trait AccessTokenProvider {
    async fn access_token(&self) -> Result<Option<Secret>, ClientError>;
}

/// A shared provider is still one provider.
///
/// Holders that rebuild the object owning their provider — which is what
/// obtaining a transport for a newly negotiated protocol version amounts to —
/// would otherwise have to duplicate it, and with it whatever token cache it
/// keeps: one cached credential becomes several, and each rebuild costs a fresh
/// acquisition.
#[async_trait(?Send)]
impl<P: AccessTokenProvider + ?Sized> AccessTokenProvider for std::rc::Rc<P> {
    async fn access_token(&self) -> Result<Option<Secret>, ClientError> {
        (**self).access_token().await
    }
}

impl<T, A> Client<T, A>
where
    T: ManagedConnectionTransport,
    A: AccessTokenProvider,
{
    /// Lists safe metadata for connections rooted in manageable paths.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication, authorization, or dependency error.
    pub async fn list_managed_connections(
        &self,
    ) -> Result<Vec<ManagedConnectionMetadata>, ClientError> {
        let token = self.required_token().await?;
        self.transport.list_managed_connections(&token).await
    }

    /// Creates one managed connection with the selected permissions on its
    /// root and returns its one-time URL.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication, authorization, validation, or
    /// dependency error; no URL is returned on any failure.
    pub async fn create_managed_connection(
        &self,
        display_name: &DisplayName,
        root: &ConfigPath,
        permissions: &ManagedPermissions,
    ) -> Result<ProvisionedManagedConnection, ClientError> {
        let token = self.required_token().await?;
        self.transport
            .create_managed_connection(display_name, root, permissions, &token)
            .await
    }

    /// Rotates one managed connection credential and returns its one-time URL.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication, authorization, validation,
    /// missing-connection, or dependency error; ambiguous rotation returns an
    /// error and no URL.
    pub async fn rotate_managed_connection(
        &self,
        connection_id: &ConnectionId,
    ) -> Result<ProvisionedManagedConnection, ClientError> {
        let token = self.required_token().await?;
        self.transport
            .rotate_managed_connection(connection_id, &token)
            .await
    }

    /// Permanently revokes one managed connection without returning a secret.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication, authorization, validation,
    /// missing-connection, or dependency error.
    pub async fn revoke_managed_connection(
        &self,
        connection_id: &ConnectionId,
    ) -> Result<(), ClientError> {
        let token = self.required_token().await?;
        self.transport
            .revoke_managed_connection(connection_id, &token)
            .await
    }
}

impl<T, A> Client<T, A>
where
    T: ValueTransport,
    A: AccessTokenProvider,
{
    /// Lists readable values directly below a namespace and its existing readable paths.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication, validation, or dependency error.
    pub async fn list_values(&self, path: &ConfigPath) -> Result<ValueListing, ClientError> {
        let token = self.required_token().await?;
        self.transport.list_values(path, &token).await
    }

    /// Reads every configuration value at or below a selected path.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication, authorization, validation, missing-value,
    /// or dependency error.
    pub async fn get_subtree(&self, path: &ConfigPath) -> Result<ValueSubTree, ClientError> {
        let token = self.required_token().await?;
        self.transport.get_subtree(path, &token).await
    }

    /// Creates or replaces one exact configuration value without retrying.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication, authorization, validation, or dependency error.
    pub async fn put_value(
        &self,
        path: &ConfigPath,
        value: &PlainValue,
    ) -> Result<PutMetadata, ClientError> {
        let token = self.required_token().await?;
        self.transport.put_value(path, value, &token).await
    }

    /// Creates or replaces one exact secret without reading it back.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication, authorization, validation, or dependency error.
    pub async fn put_secret(
        &self,
        path: &ConfigPath,
        value: &SecretInput,
    ) -> Result<PutMetadata, ClientError> {
        let token = self.required_token().await?;
        self.transport.put_secret(path, value, &token).await
    }

    /// Atomically replaces every value at or below a selected path.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication, authorization, validation, or dependency error.
    pub async fn replace_subtree(
        &self,
        path: &ConfigPath,
        values: &[SubTreeMutationValue],
    ) -> Result<ReplaceMetadata, ClientError> {
        let token = self.required_token().await?;
        self.transport.replace_subtree(path, values, &token).await
    }

    /// Permanently deletes one exact value or a complete subtree without retrying.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication, authorization, validation, missing-value,
    /// or dependency error.
    pub async fn delete_values(
        &self,
        path: &ConfigPath,
        recurse: bool,
    ) -> Result<DeleteMetadata, ClientError> {
        let token = self.required_token().await?;
        self.transport.delete_values(path, recurse, &token).await
    }

    /// Explicitly reveals one secret value.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication, authorization, validation, missing-value,
    /// classification, or dependency error.
    pub async fn reveal_secret(&self, path: &ConfigPath) -> Result<RevealedSecret, ClientError> {
        let token = self.required_token().await?;
        self.transport.reveal_secret(path, &token).await
    }

    /// Exposes an existing value at an additional canonical path.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication, authorization, validation, missing-value,
    /// conflict, or dependency error.
    pub async fn add_value_path(
        &self,
        source: &ConfigPath,
        new_path: &ConfigPath,
    ) -> Result<AddPathMetadata, ClientError> {
        let token = self.required_token().await?;
        self.transport
            .add_value_path(source, new_path, &token)
            .await
    }

    /// Lists every path resolving to the same value that the caller may read.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication, authorization, validation, missing-value,
    /// or dependency error.
    pub async fn list_value_paths(&self, path: &ConfigPath) -> Result<ValuePaths, ClientError> {
        let token = self.required_token().await?;
        self.transport.list_value_paths(path, &token).await
    }
}

/// Validates a protobuf timestamp before exposing it to presentation code.
///
/// # Errors
///
/// Returns a bounded error when the timestamp is outside the supported range.
pub fn timestamp(seconds: i64, nanos: i32) -> Result<Timestamp, ClientError> {
    let timestamp = Timestamp { seconds, nanos };
    timestamp.to_system_time()?;
    Ok(timestamp)
}

pub struct Client<T, A> {
    transport: T,
    authentication: A,
}

impl<T, A> Client<T, A>
where
    T: Transport,
    A: AccessTokenProvider,
{
    pub const fn new(transport: T, authentication: A) -> Self {
        Self {
            transport,
            authentication,
        }
    }

    /// Fetches authenticated identity state with a freshly supplied access token.
    ///
    /// # Errors
    ///
    /// Returns a bounded authentication or transport error.
    pub async fn authentication_status(&self) -> Result<AuthenticationStatus, ClientError> {
        let token = self.authentication.access_token().await?.ok_or_else(|| {
            ClientError::new(ErrorKind::Unauthenticated, "authentication required")
        })?;
        self.transport.get_identity(&token).await
    }

    async fn required_token(&self) -> Result<Secret, ClientError> {
        self.authentication
            .access_token()
            .await?
            .ok_or_else(|| ClientError::new(ErrorKind::Unauthenticated, "authentication required"))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        rc::Rc,
    };

    use async_trait::async_trait;
    use sovereign_config_core::{
        AuthenticationStatus, ClientError, ErrorKind, ProtocolVersion, Secret, ServedVersion,
    };

    use super::{
        AccessTokenProvider, Client, Connection, Handshake, RpcCode, Session, Transport,
        VersionReply, map_rpc_status, negotiate,
    };

    struct CountingTransport(Rc<Cell<usize>>);

    #[async_trait(?Send)]
    impl Transport for CountingTransport {
        async fn get_identity(&self, _: &Secret) -> Result<AuthenticationStatus, ClientError> {
            self.0.set(self.0.get() + 1);
            Ok(AuthenticationStatus {
                authenticated: true,
            })
        }
    }

    /// What a scripted service does when the handshake is called.
    #[derive(Clone)]
    enum Answer {
        /// A current server: answers the handshake with these versions.
        Serving(Vec<ServedVersion>),
        /// A deployed server up to 2.27: authenticates before it routes, so an
        /// unauthenticated handshake is refused before reaching the router.
        PreHandshakeBehindAuthentication,
        /// A bare router with no authentication in front: the handshake route
        /// simply does not exist.
        PreHandshakeBareRouter,
        /// The service is unreachable.
        Unreachable,
    }

    /// A scripted service, recording what it was asked.
    struct ScriptedService {
        answer: RefCell<Answer>,
        /// The client lists the handshake was sent, in order.
        offered: RefCell<Vec<Vec<ProtocolVersion>>>,
        /// How many times the legacy `GetVersion` route was dialled.
        legacy_calls: Cell<usize>,
        /// What the legacy route answers, when it is reached at all.
        legacy: RefCell<Result<VersionReply, ClientError>>,
    }

    impl ScriptedService {
        fn new(answer: Answer) -> Self {
            Self {
                answer: RefCell::new(answer),
                offered: RefCell::new(Vec::new()),
                legacy_calls: Cell::new(0),
                legacy: RefCell::new(Ok(VersionReply {
                    application_version: "2.27.0".into(),
                    protocol_version: ProtocolVersion::LEGACY.as_str().into(),
                    supported_protocol_versions: vec![ProtocolVersion::LEGACY.as_str().into()],
                })),
            }
        }

        fn serving(versions: &[&str]) -> Self {
            Self::new(Answer::Serving(
                versions
                    .iter()
                    .map(|name| ServedVersion::new(name))
                    .collect(),
            ))
        }

        fn handshakes(&self) -> usize {
            self.offered.borrow().len()
        }
    }

    #[async_trait(?Send)]
    impl Handshake for ScriptedService {
        async fn served_versions(
            &self,
            client_versions: &[ProtocolVersion],
        ) -> Result<Vec<ServedVersion>, ClientError> {
            self.offered.borrow_mut().push(client_versions.to_vec());
            match self.answer.borrow().clone() {
                Answer::Serving(served) => Ok(served),
                Answer::PreHandshakeBehindAuthentication => {
                    Err(map_rpc_status(RpcCode::Unauthenticated))
                }
                Answer::PreHandshakeBareRouter => Err(map_rpc_status(RpcCode::Unimplemented)),
                Answer::Unreachable => Err(map_rpc_status(RpcCode::Unavailable)),
            }
        }

        async fn legacy_version(&self) -> Result<VersionReply, ClientError> {
            self.legacy_calls.set(self.legacy_calls.get() + 1);
            self.legacy.borrow().clone()
        }
    }

    /// A transport that reports which version it was built for, and answers
    /// version-not-served for as long as the connection is scripted to.
    #[derive(Clone)]
    struct VersionedTransport {
        version: ProtocolVersion,
        /// Which transport object this is, counting from the session's first.
        ///
        /// `ProtocolVersion` has one variant, so a renegotiation can never land
        /// on a *different* version and no fixture can show the reported
        /// version changing. What it can show is that a **new** transport was
        /// obtained rather than the old one rebound — which is the guarantee
        /// `Connection::speaking` actually documents, and the reason the
        /// reported version follows a swap at all.
        generation: usize,
        refusals: Rc<Cell<usize>>,
        calls: Rc<Cell<usize>>,
    }

    impl VersionedTransport {
        fn operate(&self) -> Result<ProtocolVersion, ClientError> {
            self.calls.set(self.calls.get() + 1);
            if self.refusals.get() > 0 {
                self.refusals.set(self.refusals.get() - 1);
                return Err(map_rpc_status(RpcCode::VersionNotServed));
            }
            Ok(self.version)
        }
    }

    /// A connection whose next `refusals` calls answer version-not-served.
    ///
    /// One refusal is a rolling deploy: the replica this session's transport
    /// reached has already dropped the version, while the fleet as a whole
    /// still serves it, so the re-handshake answers normally and the retry
    /// lands somewhere that works. A large number is a real retirement, where
    /// the retry fails the same way.
    struct ScriptedConnection {
        service: ScriptedService,
        refusals: Rc<Cell<usize>>,
        calls: Rc<Cell<usize>>,
        /// How many transports this connection has handed out.
        generations: Rc<Cell<usize>>,
    }

    impl ScriptedConnection {
        fn new(versions: &[&str]) -> Self {
            Self {
                service: ScriptedService::serving(versions),
                refusals: Rc::new(Cell::new(0)),
                calls: Rc::new(Cell::new(0)),
                generations: Rc::new(Cell::new(0)),
            }
        }
    }

    #[async_trait(?Send)]
    impl Handshake for ScriptedConnection {
        async fn served_versions(
            &self,
            client_versions: &[ProtocolVersion],
        ) -> Result<Vec<ServedVersion>, ClientError> {
            self.service.served_versions(client_versions).await
        }

        async fn legacy_version(&self) -> Result<VersionReply, ClientError> {
            self.service.legacy_version().await
        }
    }

    impl Connection for ScriptedConnection {
        type Transport = VersionedTransport;

        fn speaking(&self, version: ProtocolVersion) -> Self::Transport {
            self.generations.set(self.generations.get() + 1);
            VersionedTransport {
                version,
                generation: self.generations.get(),
                refusals: Rc::clone(&self.refusals),
                calls: Rc::clone(&self.calls),
            }
        }
    }

    struct Authentication;

    #[async_trait(?Send)]
    impl AccessTokenProvider for Authentication {
        async fn access_token(&self) -> Result<Option<Secret>, ClientError> {
            Ok(Some(Secret::new("token-sentinel")))
        }
    }

    #[tokio::test]
    async fn each_operation_calls_transport_without_cache_or_retry() {
        let calls = Rc::new(Cell::new(0));
        let client = Client::new(CountingTransport(Rc::clone(&calls)), Authentication);
        client.authentication_status().await.unwrap();
        client.authentication_status().await.unwrap();
        assert_eq!(calls.get(), 2);
    }

    /// One handshake, not a walk. The old negotiation dialled `GetVersion` on
    /// each version in turn because the handshake was itself routed by version;
    /// an unversioned one settles the question in a single round trip.
    #[tokio::test]
    async fn negotiation_is_one_unversioned_handshake() {
        let service = ScriptedService::serving(&["v3"]);

        let status = negotiate(&service).await.unwrap();

        assert_eq!(status.protocol_version, ProtocolVersion::PREFERRED);
        assert_eq!(service.handshakes(), 1);
        assert_eq!(
            service.legacy_calls.get(),
            0,
            "a service with a handshake must never be asked on a versioned route"
        );
    }

    /// §1.2: the client sends everything it speaks, for the service's usage
    /// records. A client that sent only its preferred version would leave the
    /// service unable to see whether a retirement is safe.
    #[tokio::test]
    async fn the_handshake_carries_every_version_this_build_speaks() {
        let service = ScriptedService::serving(&["v3"]);

        negotiate(&service).await.unwrap();

        assert_eq!(service.offered.borrow()[0], ProtocolVersion::ALL.to_vec());
    }

    /// The case a single-version workspace never exercises by accident, and the
    /// one the obvious fixture lies about: a **deployed** server authenticates
    /// before it routes, so an unauthenticated handshake comes back
    /// `UNAUTHENTICATED` and never reaches the router that would have said
    /// `UNIMPLEMENTED`. Both shapes must reach the legacy route and speak v3.
    #[tokio::test]
    async fn a_new_client_reaches_a_pre_handshake_server_and_speaks_the_legacy_version() {
        for answer in [
            Answer::PreHandshakeBehindAuthentication,
            Answer::PreHandshakeBareRouter,
        ] {
            let service = ScriptedService::new(answer);

            let status = negotiate(&service)
                .await
                .expect("the fallback must connect");

            assert_eq!(status.protocol_version, ProtocolVersion::LEGACY);
            assert_eq!(service.legacy_calls.get(), 1);
        }
    }

    /// The fallback must not swallow real failures. An unreachable service is
    /// not a question about handshakes, and dialling the legacy route as well
    /// would double a caller's wait for no possible gain.
    #[tokio::test]
    async fn a_handshake_failure_of_any_other_kind_is_reported_as_itself() {
        let service = ScriptedService::new(Answer::Unreachable);

        let error = negotiate(&service).await.unwrap_err();

        assert_eq!(error.kind, ErrorKind::Unavailable);
        assert_eq!(service.legacy_calls.get(), 0);
    }

    /// When the fallback is reached and it fails too, what comes back is the
    /// fallback's own failure — the last thing that actually happened, not the
    /// refusal that sent us there.
    #[tokio::test]
    async fn a_legacy_fallback_that_also_fails_reports_the_fallback_failure() {
        let service = ScriptedService::new(Answer::PreHandshakeBehindAuthentication);
        *service.legacy.borrow_mut() = Err(map_rpc_status(RpcCode::Unavailable));

        let error = negotiate(&service).await.unwrap_err();

        assert_eq!(error.kind, ErrorKind::Unavailable);
    }

    /// A pre-handshake server that does not serve the legacy version answers
    /// `GetVersion` about a different one — the echo falls back when the
    /// requested version is unserved. There is nothing else such a server can
    /// offer, so this is an incompatibility, and it names both lists.
    #[tokio::test]
    async fn a_pre_handshake_server_without_the_legacy_version_is_incompatible() {
        let service = ScriptedService::new(Answer::PreHandshakeBareRouter);
        *service.legacy.borrow_mut() = Ok(VersionReply {
            application_version: "9.0.0".into(),
            protocol_version: "v9".into(),
            supported_protocol_versions: vec!["v9".into()],
        });

        let error = negotiate(&service).await.unwrap_err();

        assert_eq!(error.kind, ErrorKind::IncompatibleProtocol);
        assert!(error.message().contains("v9"), "{}", error.message());
        assert!(error.message().contains("v3"), "{}", error.message());
    }

    /// A service sharing no version with this build aborts, naming both lists
    /// so an operator can tell which end has to move.
    #[tokio::test]
    async fn a_service_with_no_version_in_common_aborts_naming_both_lists() {
        let service = ScriptedService::serving(&["v9000"]);

        let error = negotiate(&service).await.unwrap_err();

        assert_eq!(error.kind, ErrorKind::IncompatibleProtocol);
        assert!(error.message().contains("v9000"), "{}", error.message());
        assert!(error.message().contains("v3"), "{}", error.message());
    }

    /// A version only the service speaks is never a candidate: there is no
    /// dialer for it, so negotiating it would produce a session that connects
    /// and then fails every call.
    #[tokio::test]
    async fn a_version_only_the_service_speaks_is_never_negotiated() {
        let service = ScriptedService::serving(&["v9000", "v3"]);

        let status = negotiate(&service).await.unwrap();

        assert_eq!(status.protocol_version, ProtocolVersion::V3);
    }

    /// §1.6, the whole point of the session: a version retired under an
    /// already-connected client is recovered rather than fatal. The rejected
    /// call never executed, so the retry is safe.
    #[tokio::test]
    async fn a_retired_version_is_renegotiated_once_and_the_call_retried() {
        let connection = ScriptedConnection::new(&["v3"]);
        let refusals = Rc::clone(&connection.refusals);
        let calls = Rc::clone(&connection.calls);
        let session = Session::open(connection).await.unwrap();

        // One refusal: the replica this transport reached has dropped the
        // version. Only the retry — against a transport obtained after a fresh
        // handshake — can succeed, so success here proves a second attempt was
        // made and that it did not reuse the refused transport.
        refusals.set(1);
        let outcome = session
            .call(|transport| async move { transport.operate() })
            .await;

        assert_eq!(outcome.unwrap(), ProtocolVersion::V3);
        assert_eq!(calls.get(), 2, "the call is attempted exactly twice");
        assert_eq!(
            session.connection().service.handshakes(),
            2,
            "one handshake at open, one to recover"
        );
    }

    /// Once. A service answering version-not-served again is a service that
    /// cannot serve this client, and looping would turn that into an outage
    /// that never returns.
    #[tokio::test]
    async fn a_retry_that_fails_the_same_way_aborts_without_a_second_renegotiation() {
        let connection = ScriptedConnection::new(&["v3"]);
        let refusals = Rc::clone(&connection.refusals);
        let calls = Rc::clone(&connection.calls);
        let session = Session::open(connection).await.unwrap();
        refusals.set(usize::MAX);

        let error = session
            .call(|transport| async move { transport.operate() })
            .await
            .unwrap_err();

        assert_eq!(error.kind, ErrorKind::VersionNotServed);
        assert_eq!(calls.get(), 2, "the call is attempted exactly twice");
        assert_eq!(
            session.connection().service.handshakes(),
            2,
            "exactly one re-handshake, however many times the version is refused"
        );
    }

    /// A re-handshake is not a general-purpose retry. Anything that is not the
    /// version going away is the caller's to see, once.
    #[tokio::test]
    async fn an_error_that_is_not_a_retirement_is_never_retried() {
        let connection = ScriptedConnection::new(&["v3"]);
        let calls = Rc::clone(&connection.calls);
        let session = Session::open(connection).await.unwrap();

        let error = session
            .call(|_| async { Err::<(), _>(map_rpc_status(RpcCode::PermissionDenied)) })
            .await
            .unwrap_err();

        assert_eq!(error.kind, ErrorKind::PermissionDenied);
        assert_eq!(calls.get(), 0);
        assert_eq!(session.connection().service.handshakes(), 1);
    }

    /// A re-handshake that finds no common version reports *that* — an
    /// incompatibility naming both lists is more use than the version-not-served
    /// error that triggered it.
    #[tokio::test]
    async fn a_renegotiation_with_nothing_in_common_reports_the_incompatibility() {
        let connection = ScriptedConnection::new(&["v3"]);
        let refusals = Rc::clone(&connection.refusals);
        let session = Session::open(connection).await.unwrap();
        refusals.set(usize::MAX);
        *session.connection().service.answer.borrow_mut() =
            Answer::Serving(vec![ServedVersion::new("v9000")]);

        let error = session
            .call(|transport| async move { transport.operate() })
            .await
            .unwrap_err();

        assert_eq!(error.kind, ErrorKind::IncompatibleProtocol);
        assert!(error.message().contains("v9000"), "{}", error.message());
    }

    /// A recovered session holds a **new** transport, not the old one rebound.
    ///
    /// This is what makes the reported version follow a swap: the session's
    /// transport is replaced, so everything read off it afterwards — the
    /// version an operator is shown, and the routes the traffic travels on —
    /// describes the version just negotiated rather than the retired one.
    ///
    /// **What this cannot cover:** that the *reported version changes*.
    /// `ProtocolVersion` has one variant, so a renegotiation always lands back
    /// on `V3` and no fixture can make it land elsewhere. Recorded as an
    /// uncovered behaviour rather than dressed up: the assertion below is the
    /// part that is testable today, and it acquires teeth on the version it is
    /// really about the day a second variant exists.
    #[tokio::test]
    async fn a_recovered_session_holds_a_new_transport_not_the_old_one_rebound() {
        let connection = ScriptedConnection::new(&["v3"]);
        let refusals = Rc::clone(&connection.refusals);
        let session = Session::open(connection).await.unwrap();

        let before = session.transport().generation;
        assert_eq!(session.protocol_version(), ProtocolVersion::V3);

        refusals.set(1);
        session
            .call(|transport| async move { transport.operate() })
            .await
            .expect("the retry must succeed");

        let after = session.transport().generation;
        assert_ne!(
            before, after,
            "the session must hold a transport obtained after the re-handshake"
        );
        assert_eq!(
            session.protocol_version(),
            ProtocolVersion::V3,
            "and it must report the version that transport dials"
        );
    }

    /// A deprecation date warns and never fails, and reaches the caller so each
    /// client can surface it the way its operator will see.
    #[tokio::test]
    async fn a_deprecated_version_still_connects_and_carries_its_date() {
        let service = ScriptedService::new(Answer::Serving(vec![ServedVersion {
            version: "v3".to_owned(),
            deprecation_date: Some("2027-01-01T00:00:00Z".to_owned()),
        }]));

        let status = negotiate(&service)
            .await
            .expect("a date never fails a client");

        assert_eq!(status.protocol_version, ProtocolVersion::V3);
        assert_eq!(
            status.deprecation_date.as_deref(),
            Some("2027-01-01T00:00:00Z")
        );
    }

    #[test]
    fn status_mapping_is_bounded() {
        assert_eq!(
            map_rpc_status(RpcCode::Unauthenticated).kind,
            ErrorKind::Unauthenticated
        );
        assert_eq!(
            map_rpc_status(RpcCode::Unavailable).to_string(),
            "service is unavailable"
        );
    }

    /// `UNIMPLEMENTED` is what a client built from one version's stubs sees
    /// against a server that never had the version-not-served answer, so it has
    /// to keep reading as a protocol incompatibility. The new answer is a
    /// *different* kind: a retirement that can be renegotiated, rather than a
    /// terminal mismatch.
    #[test]
    fn a_missing_route_and_a_retired_version_are_different_failures() {
        let missing = map_rpc_status(RpcCode::Unimplemented);

        assert_eq!(missing.kind, ErrorKind::IncompatibleProtocol);
        assert_eq!(missing, map_rpc_status(RpcCode::FailedPrecondition));
        assert_eq!(
            map_rpc_status(RpcCode::VersionNotServed).kind,
            ErrorKind::VersionNotServed
        );
        assert_ne!(missing.kind, map_rpc_status(RpcCode::VersionNotServed).kind);
    }
}
