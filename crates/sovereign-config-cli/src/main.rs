//! The Sovereign Config command-line client.

mod cli;
mod connection;
mod profile;
mod render;
mod session;
mod values;

use anyhow::{Result, bail};
use clap::Parser;
use sovereign_config_core::ConnectionUrl;
use sovereign_config_native::{ProfileStore, default_profile_path};

use crate::cli::{Arguments, Command};

#[tokio::main]
async fn main() -> Result<()> {
    let arguments = Arguments::parse();
    match arguments.command {
        Command::Profile { command } => {
            if arguments.profile.is_some() {
                bail!("--profile applies only to operational commands");
            }
            if arguments.url_file.is_some() {
                bail!("--url-file applies only to operational commands");
            }
            profile::manage_profile(command, &ProfileStore::new(default_profile_path()?))
        }
        command => {
            // Resolved here rather than in `main`'s preamble because a
            // profile-less host — a CI container running `render` against
            // `--url-file` or `SOVEREIGN_CONFIG_URL` — may have no state
            // directory at all, and determining the profile path would fail
            // before the command that never needed it got a chance to run.
            let connection =
                connection::resolve(arguments.profile.as_deref(), arguments.url_file.as_deref())?;
            dispatch(&connection, command).await
        }
    }
}

async fn dispatch(connection: &ConnectionUrl, command: Command) -> Result<()> {
    match command {
        Command::Login => session::login(connection).await,
        Command::Logout => session::logout(connection),
        Command::Status => session::status(connection).await,
        Command::Get {
            path,
            tree,
            reveal,
            format,
        } => values::get(connection, &path, tree, reveal, format).await,
        Command::Set { path, secret, tree } => values::set(connection, &path, secret, tree).await,
        Command::Delete { path, tree, yes } => values::delete(connection, &path, tree, yes).await,
        Command::List {
            path,
            aliases,
            format,
        } => values::list(connection, &path, aliases, format).await,
        Command::Render { paths, command } => render::render(connection, &paths, &command).await,
        Command::Alias {
            source_path,
            new_path,
        } => values::alias(connection, &source_path, &new_path).await,
        Command::Profile { .. } => unreachable!("profile commands never reach the service"),
    }
}
