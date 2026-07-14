use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use clap::{Parser, Subcommand};
use sovereign_config_client::{AccessTokenProvider, Client};
use sovereign_config_core::{ClientError, Secret};
use sovereign_config_native::{
    CredentialStore, DeviceFlowClient, TonicTransport, default_credential_path,
};

const APPLICATION_VERSION: &str = match option_env!("SOVEREIGN_CONFIG_RELEASE") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

#[derive(Parser)]
#[command(name = "sovereign-config", version = APPLICATION_VERSION, about)]
struct Arguments {
    #[arg(long, env = "SOVEREIGN_CONFIG_ENDPOINT")]
    endpoint: String,
    #[arg(long, env = "SOVEREIGN_CONFIG_OIDC_ISSUER")]
    issuer: String,
    #[arg(
        long,
        env = "SOVEREIGN_CONFIG_OIDC_CLI_CLIENT_ID",
        default_value = "sovereign-config-cli"
    )]
    client_id: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Login,
    Logout,
    Status,
}

struct InMemoryToken(Secret);

#[async_trait(?Send)]
impl AccessTokenProvider for InMemoryToken {
    async fn access_token(&self) -> Result<Option<Secret>, ClientError> {
        Ok(Some(self.0.clone()))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let arguments = Arguments::parse();
    let credential_store = CredentialStore::new(default_credential_path()?)?;
    match arguments.command {
        Command::Login => login(&arguments.issuer, arguments.client_id, &credential_store).await,
        Command::Logout => {
            credential_store.delete()?;
            println!("Logged out");
            Ok(())
        }
        Command::Status => {
            status(
                arguments.endpoint,
                &arguments.issuer,
                arguments.client_id,
                &credential_store,
            )
            .await
        }
    }
}

async fn login(issuer: &str, client_id: String, store: &CredentialStore) -> Result<()> {
    let oidc = DeviceFlowClient::discover(issuer, client_id).await?;
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

async fn status(
    endpoint: String,
    issuer: &str,
    client_id: String,
    store: &CredentialStore,
) -> Result<()> {
    let transport = TonicTransport::connect(endpoint).await?;
    let public_client = Client::new(transport.clone(), MissingToken);
    let service = public_client.service_status().await?;
    println!(
        "Service {} (protocol {})",
        service.application_version, service.protocol_version
    );

    let Some(refresh) = store.load()? else {
        println!("Authentication: logged out");
        return Ok(());
    };
    let oidc = DeviceFlowClient::discover(issuer, client_id).await?;
    let tokens = oidc.refresh(&refresh).await?;
    if let Some(rotated) = &tokens.refresh_token {
        store.store(rotated)?;
    }
    let client = Client::new(transport, InMemoryToken(tokens.access_token));
    let authentication = client.authentication_status().await?;
    if !authentication.authenticated {
        bail!("service returned an invalid authentication status");
    }
    println!("Authentication: logged in");
    Ok(())
}

struct MissingToken;

#[async_trait(?Send)]
impl AccessTokenProvider for MissingToken {
    async fn access_token(&self) -> Result<Option<Secret>, ClientError> {
        Ok(None)
    }
}
