#![forbid(unsafe_code)]

use async_trait::async_trait;
use sovereign_config_core::{
    AddPathMetadata, AuthenticationStatus, ClientError, ConfigPath, ConnectionId, DeleteMetadata,
    DisplayName, ErrorKind, ManagedConnectionMetadata, ManagedPermissions, PlainValue,
    ProtocolVersion, ProvisionedManagedConnection, PutMetadata, ReplaceMetadata, RevealedSecret,
    Secret, SecretInput, ServiceStatus, SubTreeMutationValue, Timestamp, ValueListing, ValuePaths,
    ValueSubTree,
};

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
/// `GetVersion` is the one RPC a client may issue before negotiation, and it
/// travels on a versioned route like any other — so asking for a version and
/// dialling one are the same act, and the caller names the version it is
/// dialling. [`negotiate`] is what turns a handshake into a session.
#[async_trait(?Send)]
pub trait Handshake {
    /// Issues `GetVersion` **on `version`'s own route**, asking for `version`.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::IncompatibleProtocol`] when the service has no
    /// route for `version`, and a bounded transport error otherwise.
    async fn get_version(&self, version: ProtocolVersion) -> Result<VersionReply, ClientError>;
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

/// Negotiates the version a session will speak, newest first.
///
/// Asks for the newest version this build speaks and settles on the highest
/// version the server also serves, so a server ahead of this build still works.
///
/// The walk exists because `GetVersion` is itself routed by version: a server
/// that does not serve the newest version this build speaks has no route to
/// answer on, and replies `UNIMPLEMENTED` rather than a version list. Trying
/// the next older version is what lets a **newer client reach an older
/// server** — the mirror of the older-client case negotiation already covers.
/// A pre-2.25.0 server, which rejects an unserved version outright rather than
/// answering, is reached the same way.
///
/// This runs once per session. A version retired under an already-connected
/// client is deliberately **not** renegotiated: the next call fails with
/// [`ErrorKind::IncompatibleProtocol`], which is the provider's documented
/// fail-fast contract and keeps a retirement visible rather than papered over
/// by a retry.
///
/// # Errors
///
/// Returns a bounded transport error, or [`ErrorKind::IncompatibleProtocol`]
/// when no version is common to this build and the service.
pub async fn negotiate<H>(handshake: &H) -> Result<ServiceStatus, ClientError>
where
    H: Handshake + ?Sized,
{
    let mut incompatible = ClientError::new(
        ErrorKind::IncompatibleProtocol,
        "service protocol is incompatible",
    );
    for version in ProtocolVersion::ALL.iter().rev().copied() {
        match handshake.get_version(version).await {
            // The reply carries the server's whole served set, so it settles
            // the question for every version at once: an older route could not
            // produce a better answer, and asking would only add round trips.
            Ok(reply) => {
                let status = ServiceStatus::negotiate(
                    reply.application_version,
                    &reply.protocol_version,
                    &reply.supported_protocol_versions,
                )?;
                // Never settle above the version that answered. A server can
                // advertise a version whose routes are not (yet) registered —
                // a rolling deploy looks exactly like that to a client whose
                // handshake lands on an old replica — and the walk has already
                // proved those routes absent. Taking the advertised set at its
                // word there would hand back a session that connects and then
                // fails every call, with no renegotiation to recover it. The
                // cap is a no-op whenever the selected version is the answering
                // one or older, which is every other case.
                return Ok(ServiceStatus {
                    protocol_version: status.protocol_version.min(version),
                    ..status
                });
            }
            Err(error) if error.kind == ErrorKind::IncompatibleProtocol => incompatible = error,
            Err(error) => return Err(error),
        }
    }
    Err(incompatible)
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
        AuthenticationStatus, ClientError, ErrorKind, ProtocolVersion, Secret,
    };

    use super::{
        AccessTokenProvider, Client, Handshake, RpcCode, Transport, VersionReply, map_rpc_status,
        negotiate,
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

    /// A handshake that records which versions it was asked for, in order, and
    /// answers each one however the test scripted it.
    struct ScriptedHandshake {
        asked: RefCell<Vec<ProtocolVersion>>,
        answer: Box<dyn Fn(ProtocolVersion) -> Result<VersionReply, ClientError>>,
    }

    impl ScriptedHandshake {
        fn new(
            answer: impl Fn(ProtocolVersion) -> Result<VersionReply, ClientError> + 'static,
        ) -> Self {
            Self {
                asked: RefCell::new(Vec::new()),
                answer: Box::new(answer),
            }
        }

        fn asked(&self) -> Vec<ProtocolVersion> {
            self.asked.borrow().clone()
        }
    }

    #[async_trait(?Send)]
    impl Handshake for ScriptedHandshake {
        async fn get_version(&self, version: ProtocolVersion) -> Result<VersionReply, ClientError> {
            self.asked.borrow_mut().push(version);
            (self.answer)(version)
        }
    }

    fn serving(version: ProtocolVersion) -> VersionReply {
        VersionReply {
            application_version: "1.5.0".into(),
            protocol_version: version.as_str().into(),
            supported_protocol_versions: vec![version.as_str().into()],
        }
    }

    fn incompatible() -> ClientError {
        map_rpc_status(RpcCode::Unimplemented)
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

    /// The handshake asks for the newest version this build speaks, on that
    /// version's own route, and stops as soon as one answers: a served version
    /// reports the server's whole set, so no older route can improve on it.
    #[tokio::test]
    async fn negotiation_asks_the_newest_version_first_and_stops_when_it_answers() {
        let handshake = ScriptedHandshake::new(|version| Ok(serving(version)));

        let status = negotiate(&handshake).await.unwrap();

        assert_eq!(status.protocol_version, ProtocolVersion::PREFERRED);
        assert_eq!(handshake.asked(), [ProtocolVersion::PREFERRED]);
    }

    /// A server that does not serve this build's newest version has no route to
    /// answer its `GetVersion` on, so the handshake works down the versions it
    /// speaks. Without this walk a newer client could never reach an older
    /// server, whatever the two of them have in common.
    #[tokio::test]
    async fn a_service_without_the_newest_route_is_asked_for_each_older_version() {
        let handshake = ScriptedHandshake::new(|_| Err(incompatible()));

        let error = negotiate(&handshake).await.unwrap_err();

        let oldest_first: Vec<_> = ProtocolVersion::ALL.to_vec();
        let mut newest_first = oldest_first;
        newest_first.reverse();
        assert_eq!(handshake.asked(), newest_first);
        assert_eq!(error.kind, ErrorKind::IncompatibleProtocol);
    }

    /// Only a missing route is worth trying an older version for. An
    /// unreachable service is not a compatibility question, and retrying it
    /// once per version would multiply the wait a caller was promised.
    #[tokio::test]
    async fn an_unreachable_service_is_not_asked_a_second_time() {
        let handshake = ScriptedHandshake::new(|_| Err(map_rpc_status(RpcCode::Unavailable)));

        let error = negotiate(&handshake).await.unwrap_err();

        assert_eq!(error.kind, ErrorKind::Unavailable);
        assert_eq!(handshake.asked(), [ProtocolVersion::PREFERRED]);
    }

    /// A server may serve versions from the future. They are not candidates,
    /// and nothing may be dialled on them — the session settles on the highest
    /// version *both* ends speak, or fails.
    #[tokio::test]
    async fn a_version_only_the_server_speaks_is_never_negotiated() {
        let handshake = ScriptedHandshake::new(|version| {
            Ok(VersionReply {
                supported_protocol_versions: vec![version.as_str().into(), "v9000".into()],
                ..serving(version)
            })
        });

        let status = negotiate(&handshake).await.unwrap();

        assert_eq!(status.protocol_version, ProtocolVersion::PREFERRED);
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

    /// `UNIMPLEMENTED` is what a client built from one version's stubs sees once
    /// the server stops routing that version, so it has to read as a protocol
    /// incompatibility. Left to fall through to `Other`, a retirement would
    /// surface to every still-connected client as an opaque internal error.
    #[test]
    fn a_route_the_server_does_not_implement_is_a_protocol_incompatibility() {
        let error = map_rpc_status(RpcCode::Unimplemented);

        assert_eq!(error.kind, ErrorKind::IncompatibleProtocol);
        assert_eq!(error, map_rpc_status(RpcCode::FailedPrecondition));
    }
}
