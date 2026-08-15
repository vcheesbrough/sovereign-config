use std::io::{self, IsTerminal, Read};

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use clap::{Parser, Subcommand, ValueEnum};
use sovereign_config_client::{AccessTokenProvider, Client};
use sovereign_config_core::{
    ClientError, ConfigPath, ConnectionUrl, ErrorKind, PlainValue, Secret, SecretInput,
    SubTreeValue, ValueContent, parse_subtree_json, render_subtree_json,
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
            help = "Absolute configuration value or subtree path, beginning with /"
        )]
        path: String,
        #[arg(long, value_enum, default_value_t = ValueFormat::Text)]
        format: ValueFormat,
        #[arg(long, help = "Reveal secret values in the requested result")]
        reveal: bool,
    },
    Put {
        #[arg(
            value_name = "ABSOLUTE_PATH",
            help = "Absolute configuration value or subtree path, beginning with /"
        )]
        path: String,
        #[arg(long, value_enum, default_value_t = ValueFormat::Text)]
        format: ValueFormat,
    },
    Secret {
        #[command(subcommand)]
        command: SecretCommand,
    },
    Alias {
        #[command(subcommand)]
        command: AliasCommand,
    },
    Delete {
        #[arg(
            value_name = "ABSOLUTE_PATH",
            help = "Absolute configuration value or subtree path, beginning with /"
        )]
        path: String,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        recurse: bool,
    },
}

#[derive(Subcommand)]
enum SecretCommand {
    Put {
        #[arg(value_name = "ABSOLUTE_PATH")]
        path: String,
    },
    Reveal {
        #[arg(value_name = "ABSOLUTE_PATH")]
        path: String,
    },
}

#[derive(Subcommand)]
enum AliasCommand {
    Add {
        #[arg(
            value_name = "SOURCE_ABSOLUTE_PATH",
            help = "Absolute path of the existing configuration value, beginning with /"
        )]
        source_path: String,
        #[arg(
            value_name = "NEW_ABSOLUTE_PATH",
            help = "Absolute path to expose the value at, beginning with /"
        )]
        new_path: String,
    },
    List {
        #[arg(
            value_name = "ABSOLUTE_PATH",
            help = "Absolute configuration value path, beginning with /"
        )]
        path: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ValueFormat {
    Text,
    Json,
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
                Command::Get {
                    path,
                    format,
                    reveal,
                } => get_value(&connection, &path, format, reveal).await,
                Command::Put { path, format } => put_value(&connection, &path, format).await,
                Command::Secret { command } => secret_value(&connection, command).await,
                Command::Alias { command } => alias_value(&connection, command).await,
                Command::Delete { path, yes, recurse } => {
                    delete_values(&connection, &path, yes, recurse).await
                }
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

fn operation_path(connection: &ConnectionUrl, path: &str, allow_root: bool) -> Result<ConfigPath> {
    let path = if allow_root {
        ConfigPath::parse_selection(path).context("path must name a configuration subtree")?
    } else {
        ConfigPath::parse_operation(path).context("path must name a configuration value")?
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

async fn get_value(
    connection: &ConnectionUrl,
    path: &str,
    format: ValueFormat,
    reveal: bool,
) -> Result<()> {
    let path = operation_path(connection, path, true)?;
    let client = operational_client(connection).await?;
    let mut subtree = client.get_subtree(&path).await?;
    if format == ValueFormat::Json {
        if reveal {
            reveal_subtree(&client, &mut subtree.values).await?;
        }
        print!("{}", render_subtree_json(&path, &subtree.values)?);
    } else if let [value] = subtree.values.as_slice()
        && value.path == path
    {
        if reveal && matches!(value.value, ValueContent::Secret(_)) {
            let revealed = client.reveal_secret(&value.path).await?;
            print!("{}", revealed.expose());
        } else {
            print!("{}", value.value.display_text());
        }
    } else if subtree.values.is_empty() {
        bail!("configuration value not found");
    } else {
        bail!("JSON format is required to read a configuration subtree");
    }
    Ok(())
}

async fn reveal_subtree(
    client: &Client<TonicTransport, InMemoryToken>,
    values: &mut [SubTreeValue],
) -> Result<()> {
    for value in values {
        if matches!(value.value, ValueContent::Secret(_)) {
            let revealed = client.reveal_secret(&value.path).await?;
            value.value = ValueContent::Plain(PlainValue::new(revealed.expose()));
        }
    }
    Ok(())
}

async fn put_value(connection: &ConnectionUrl, path: &str, format: ValueFormat) -> Result<()> {
    let path = operation_path(connection, path, format == ValueFormat::Json)?;
    let mut value = String::new();
    io::stdin()
        .read_to_string(&mut value)
        .map_err(|_| anyhow!("configuration input is unavailable"))?;
    let client = operational_client(connection).await?;
    if format == ValueFormat::Json {
        let values = parse_subtree_json(&path, &value)?;
        client.replace_subtree(&path, &values).await?;
        println!("Subtree replaced");
    } else {
        client.put_value(&path, &PlainValue::new(value)).await?;
        println!("Value stored");
    }
    Ok(())
}

async fn secret_value(connection: &ConnectionUrl, command: SecretCommand) -> Result<()> {
    match command {
        SecretCommand::Put { path } => {
            let path = operation_path(connection, &path, false)?;
            let mut value = String::new();
            io::stdin()
                .read_to_string(&mut value)
                .map_err(|_| anyhow!("secret input is unavailable"))?;
            operational_client(connection)
                .await?
                .put_secret(&path, &SecretInput::new(value))
                .await?;
            println!("Secret stored");
        }
        SecretCommand::Reveal { path } => {
            let path = operation_path(connection, &path, false)?;
            let value = operational_client(connection)
                .await?
                .reveal_secret(&path)
                .await?;
            print!("{}", value.expose());
        }
    }
    Ok(())
}

async fn alias_value(connection: &ConnectionUrl, command: AliasCommand) -> Result<()> {
    match command {
        AliasCommand::Add {
            source_path,
            new_path,
        } => {
            let source = operation_path(connection, &source_path, false)?;
            let new_path = operation_path(connection, &new_path, false)?;
            operational_client(connection)
                .await?
                .add_value_path(&source, &new_path)
                .await?;
            println!("Path added");
        }
        AliasCommand::List { path } => {
            let path = operation_path(connection, &path, false)?;
            let paths = operational_client(connection)
                .await?
                .list_value_paths(&path)
                .await?;
            for path in paths.paths {
                println!("{}", path.as_str());
            }
        }
    }
    Ok(())
}

async fn delete_values(
    connection: &ConnectionUrl,
    path: &str,
    yes: bool,
    recurse: bool,
) -> Result<()> {
    let path = operation_path(connection, path, recurse)?;
    if !yes {
        if !io::stdin().is_terminal() {
            bail!("deletion requires --yes when standard input is not a terminal");
        }
        if recurse {
            eprint!(
                "Permanently delete {} and all descendants? Type 'delete' to confirm: ",
                path.as_str()
            );
        } else {
            eprint!(
                "Permanently delete {}? Type 'delete' to confirm: ",
                path.as_str()
            );
        }
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
        .delete_values(&path, recurse)
        .await?;
    println!(
        "{}",
        if recurse {
            "Subtree deleted"
        } else {
            "Value deleted"
        }
    );
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
