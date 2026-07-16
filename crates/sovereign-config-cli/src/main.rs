use std::io::{self, IsTerminal, Read};

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use clap::{Parser, Subcommand};
use sovereign_config_client::{AccessTokenProvider, Client};
use sovereign_config_core::{
    ClientError, ConfigPath, ConnectionUrl, ErrorKind, PlainValue, Secret,
};
use sovereign_config_native::{
    CredentialStore, DeviceFlowClient, ProfileStore, TonicTransport, default_credential_directory,
    default_profile_path,
};

const APPLICATION_VERSION: &str = match option_env!("SOVEREIGN_CONFIG_RELEASE") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};
const MAX_CONNECTION_URL_BYTES: u64 = 16 * 1024;

#[derive(Parser)]
#[command(name = "sovereign-config", version = APPLICATION_VERSION, about)]
struct Arguments {
    #[arg(long, global = true)]
    profile: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    Login,
    Logout,
    Status,
    Get {
        #[arg(
            value_name = "ABSOLUTE_PATH",
            help = "Absolute configuration value path, beginning with /"
        )]
        path: String,
    },
    Put {
        #[arg(
            value_name = "ABSOLUTE_PATH",
            help = "Absolute configuration value path, beginning with /"
        )]
        path: String,
    },
    Delete {
        #[arg(
            value_name = "ABSOLUTE_PATH",
            help = "Absolute configuration value path, beginning with /"
        )]
        path: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum ProfileCommand {
    Add { name: String },
    Update { name: String },
    Default { name: String },
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
    let profiles = ProfileStore::new(default_profile_path()?);
    match arguments.command {
        Command::Profile { command } => {
            if arguments.profile.is_some() {
                bail!("--profile applies only to operational commands");
            }
            manage_profile(command, &profiles)
        }
        command => {
            let connection = profiles.connection(arguments.profile.as_deref())?;
            match command {
                Command::Login => login(&connection).await,
                Command::Logout => logout(&connection),
                Command::Status => status(&connection).await,
                Command::Get { path } => get_value(&connection, &path).await,
                Command::Put { path } => put_value(&connection, &path).await,
                Command::Delete { path, yes } => delete_value(&connection, &path, yes).await,
                Command::Profile { .. } => unreachable!(),
            }
        }
    }
}

fn manage_profile(command: ProfileCommand, profiles: &ProfileStore) -> Result<()> {
    match command {
        ProfileCommand::Add { name } => {
            let connection = read_connection(None, false)?.context("connection URL is required")?;
            profiles.add(&name, &connection)?;
            println!("Profile added");
        }
        ProfileCommand::Update { name } => {
            let current = profiles.connection(Some(&name))?;
            let Some(connection) = read_connection(Some(&current.redacted()), true)? else {
                println!("Profile unchanged");
                return Ok(());
            };
            if current.client_authentication().is_none()
                && !same_human_authentication_identity(&current, &connection)
                && !profiles.contains_other_human_identity(&name, &current)?
            {
                credential_store(&current)?.delete()?;
            }
            profiles.update(&name, &connection)?;
            println!("Profile updated");
        }
        ProfileCommand::Default { name } => {
            profiles.set_default(&name)?;
            println!("Default profile updated");
        }
    }
    Ok(())
}

fn same_human_authentication_identity(first: &ConnectionUrl, second: &ConnectionUrl) -> bool {
    second.client_authentication().is_none()
        && first.endpoint() == second.endpoint()
        && first.issuer() == second.issuer()
        && first.client_id() == second.client_id()
}

fn read_connection(
    current: Option<&str>,
    empty_is_unchanged: bool,
) -> Result<Option<ConnectionUrl>> {
    let value = if io::stdin().is_terminal() {
        if let Some(current) = current {
            println!("Current URL: {current}");
        }
        rpassword::prompt_password("New URL: ")
            .map_err(|_| anyhow!("profile input is unavailable"))?
    } else {
        let mut value = String::new();
        io::stdin()
            .take(MAX_CONNECTION_URL_BYTES + 1)
            .read_to_string(&mut value)
            .map_err(|_| anyhow!("profile input is unavailable"))?;
        if value.len() as u64 > MAX_CONNECTION_URL_BYTES {
            bail!("connection URL is invalid");
        }
        let value = value.strip_suffix('\n').unwrap_or(&value);
        let value = value.strip_suffix('\r').unwrap_or(value);
        if value.bytes().any(|byte| matches!(byte, b'\n' | b'\r')) {
            bail!("connection URL is invalid");
        }
        value.to_owned()
    };
    if value.is_empty() && empty_is_unchanged {
        return Ok(None);
    }
    Ok(Some(ConnectionUrl::parse(&value)?))
}

async fn login(connection: &ConnectionUrl) -> Result<()> {
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

fn logout(connection: &ConnectionUrl) -> Result<()> {
    if connection.client_authentication().is_some() {
        bail!("profile uses managed authentication");
    }
    credential_store(connection)?.delete()?;
    println!("Logged out");
    Ok(())
}

async fn status(connection: &ConnectionUrl) -> Result<()> {
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

async fn operational_client(
    connection: &ConnectionUrl,
) -> Result<Client<TonicTransport, InMemoryToken>> {
    let transport = TonicTransport::connect(connection.endpoint().to_owned()).await?;
    Client::new(transport.clone(), MissingToken)
        .service_status()
        .await?;
    Ok(Client::new(
        transport,
        InMemoryToken(access_token(connection).await?),
    ))
}

fn operation_path(connection: &ConnectionUrl, path: &str) -> Result<ConfigPath> {
    let path = ConfigPath::parse_operation(path).context("path must name a configuration value")?;
    let root = connection.root().as_str();
    if root != "/"
        && path.as_str() != root
        && !path
            .as_str()
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
    {
        bail!("path is outside the selected profile root");
    }
    Ok(path)
}

async fn get_value(connection: &ConnectionUrl, path: &str) -> Result<()> {
    let path = operation_path(connection, path)?;
    let value = operational_client(connection)
        .await?
        .get_value(&path)
        .await?;
    print!("{}", value.value.expose());
    Ok(())
}

async fn put_value(connection: &ConnectionUrl, path: &str) -> Result<()> {
    let path = operation_path(connection, path)?;
    let mut value = String::new();
    io::stdin()
        .read_to_string(&mut value)
        .map_err(|_| anyhow!("configuration input is unavailable"))?;
    operational_client(connection)
        .await?
        .put_value(&path, &PlainValue::new(value))
        .await?;
    println!("Value stored");
    Ok(())
}

async fn delete_value(connection: &ConnectionUrl, path: &str, yes: bool) -> Result<()> {
    let path = operation_path(connection, path)?;
    if !yes {
        if !io::stdin().is_terminal() {
            bail!("deletion requires --yes when standard input is not a terminal");
        }
        eprint!(
            "Permanently delete {}? Type 'delete' to confirm: ",
            path.as_str()
        );
        let mut confirmation = String::new();
        io::stdin()
            .read_line(&mut confirmation)
            .map_err(|_| anyhow!("deletion confirmation is unavailable"))?;
        if confirmation.trim_end() != "delete" {
            bail!("deletion cancelled");
        }
    }
    operational_client(connection)
        .await?
        .delete_value(&path)
        .await?;
    println!("Value deleted");
    Ok(())
}

fn credential_store(connection: &ConnectionUrl) -> Result<CredentialStore> {
    Ok(CredentialStore::new(
        &default_credential_directory()?,
        connection,
    ))
}

struct MissingToken;

#[async_trait(?Send)]
impl AccessTokenProvider for MissingToken {
    async fn access_token(&self) -> Result<Option<Secret>, ClientError> {
        Ok(None)
    }
}
