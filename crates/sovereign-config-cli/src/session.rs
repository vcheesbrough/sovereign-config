//! The authenticated session: path confinement, token acquisition, and the
//! authentication commands built directly on them.

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use sovereign_config_client::{AccessTokenProvider, Client};
use sovereign_config_core::{ClientError, ConfigPath, ConnectionUrl, ErrorKind, Secret};
use sovereign_config_layers::InvalidatableToken;
use sovereign_config_native::{
    CredentialStore, DeviceFlowClient, TonicTransport, default_credential_directory,
};

/// A client that has already proved the service is reachable and speaks this
/// protocol version, carrying a token acquired for this one invocation.
pub type OperationalClient = Client<TonicTransport, InMemoryToken>;

/// Whether a command addresses exactly one value or the subtree at a path.
/// This is the `--tree` flag, and it also selects the path grammar: the tree
/// root is a subtree but never a value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scope {
    Exact,
    Tree,
}

pub struct InMemoryToken(Secret);

#[async_trait(?Send)]
impl AccessTokenProvider for InMemoryToken {
    async fn access_token(&self) -> Result<Option<Secret>, ClientError> {
        Ok(Some(self.0.clone()))
    }
}

impl InvalidatableToken for InMemoryToken {
    /// Nothing to drop. The CLI acquires one token per invocation and exits, so
    /// there is no cache that could outlive a revocation — the retry a
    /// [`LayerReader`](sovereign_config_layers::LayerReader) performs simply
    /// replays the same token and gets the same answer.
    fn invalidate(&self) {}
}

pub struct MissingToken;

#[async_trait(?Send)]
impl AccessTokenProvider for MissingToken {
    async fn access_token(&self) -> Result<Option<Secret>, ClientError> {
        Ok(None)
    }
}

/// Parses a typed path in the grammar `scope` selects and confines it to the
/// profile's root.
///
/// # Errors
///
/// Returns an error when the path is not canonical for that scope or falls
/// outside the selected profile root.
pub fn operation_path(connection: &ConnectionUrl, path: &str, scope: Scope) -> Result<ConfigPath> {
    let path = match scope {
        Scope::Tree => {
            ConfigPath::parse_selection(path).context("path must name a configuration subtree")?
        }
        Scope::Exact => {
            ConfigPath::parse_operation(path).context("path must name a configuration value")?
        }
    };
    // The confinement check must compare folds: `path` retains whatever case
    // the caller typed, but a connection's root is always fold-only, so a
    // byte-exact comparison would reject an in-root path typed in different
    // case.
    let root = connection.root().as_str();
    let fold = path.fold();
    if root != "/"
        && fold != root
        && !fold
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
    {
        bail!("path is outside the selected profile root");
    }
    Ok(path)
}

/// Connects, verifies the protocol handshake, and acquires an access token.
///
/// # Errors
///
/// Returns an error when the service is unreachable, the protocol does not
/// match, or no credential is available.
pub async fn operational_client(connection: &ConnectionUrl) -> Result<OperationalClient> {
    let (transport, token) = operational_transport(connection).await?;
    Ok(Client::new(transport, token))
}

/// The same connection, handshake and token as [`operational_client`], with the
/// two halves left unassembled.
///
/// `render` builds a layer reader rather than a [`Client`] on them, and both
/// must come from one handshake: opening a second channel would double the
/// round trips and could land on a different backend mid-read.
///
/// # Errors
///
/// Returns an error when the service is unreachable, the protocol does not
/// match, or no credential is available.
pub async fn operational_transport(
    connection: &ConnectionUrl,
) -> Result<(TonicTransport, InMemoryToken)> {
    let transport = TonicTransport::connect(connection.endpoint().to_owned()).await?;
    Client::new(transport.clone(), MissingToken)
        .service_status()
        .await?;
    Ok((transport, InMemoryToken(access_token(connection).await?)))
}

/// Runs the OIDC device flow and stores the resulting refresh credential.
///
/// # Errors
///
/// Returns an error for a managed profile, a failed authorization, or a
/// provider that issues no refresh credential.
pub async fn login(connection: &ConnectionUrl) -> Result<()> {
    if connection.client_authentication().is_some() {
        bail!("profile uses managed authentication");
    }
    let store = credential_store(connection)?;
    let oidc =
        DeviceFlowClient::discover(connection.issuer(), connection.client_id().to_owned()).await?;
    let authorization = oidc.begin().await?;
    println!("Open: {}", authorization.verification_uri);
    println!("Code: {}", authorization.user_code);
    if let Some(complete) = &authorization.verification_uri_complete {
        println!("Direct link: {complete}");
    }
    let tokens = oidc.poll(authorization).await?;
    let refresh = tokens
        .refresh_token
        .context("identity provider did not issue a refresh credential")?;
    store.store(&refresh)?;
    println!("Logged in");
    Ok(())
}

/// Deletes the profile's stored refresh credential.
///
/// # Errors
///
/// Returns an error for a managed profile or an unusable credential store.
pub fn logout(connection: &ConnectionUrl) -> Result<()> {
    if connection.client_authentication().is_some() {
        bail!("profile uses managed authentication");
    }
    credential_store(connection)?.delete()?;
    println!("Logged out");
    Ok(())
}

/// Reports the service version and whether this profile is authenticated.
///
/// # Errors
///
/// Returns an error when the service is unreachable or reports an invalid
/// authentication status.
pub async fn status(connection: &ConnectionUrl) -> Result<()> {
    let transport = TonicTransport::connect(connection.endpoint().to_owned()).await?;
    let public_client = Client::new(transport.clone(), MissingToken);
    let service = public_client.service_status().await?;
    println!(
        "Service {} (protocol {})",
        service.application_version, service.protocol_version
    );

    let Some(access_token) = maybe_access_token(connection).await? else {
        println!("Authentication: logged out");
        return Ok(());
    };

    let client = Client::new(transport, InMemoryToken(access_token));
    let authentication = client.authentication_status().await?;
    if !authentication.authenticated {
        bail!("service returned an invalid authentication status");
    }
    println!("Authentication: logged in");
    Ok(())
}

/// The credential store for one profile, keyed by its connection identity.
///
/// # Errors
///
/// Returns an error when the state directory cannot be determined.
pub fn credential_store(connection: &ConnectionUrl) -> Result<CredentialStore> {
    Ok(CredentialStore::new(
        &default_credential_directory()?,
        connection,
    ))
}

async fn maybe_access_token(connection: &ConnectionUrl) -> Result<Option<Secret>> {
    let token = if let Some(authentication) = connection.client_authentication() {
        DeviceFlowClient::discover(connection.issuer(), connection.client_id().to_owned())
            .await?
            .client_credentials(authentication)
            .await?
            .access_token
    } else {
        let store = credential_store(connection)?;
        let Some(refresh) = store.load()? else {
            return Ok(None);
        };
        let oidc =
            DeviceFlowClient::discover(connection.issuer(), connection.client_id().to_owned())
                .await?;
        let tokens = match oidc.refresh(&refresh).await {
            Ok(tokens) => tokens,
            Err(error) if error.kind == ErrorKind::Unauthenticated => {
                store.delete()?;
                return Err(error.into());
            }
            Err(error) => return Err(error.into()),
        };
        if let Some(rotated) = &tokens.refresh_token {
            store.store(rotated)?;
        }
        tokens.access_token
    };
    Ok(Some(token))
}

async fn access_token(connection: &ConnectionUrl) -> Result<Secret> {
    maybe_access_token(connection)
        .await?
        .context("authentication required")
}
