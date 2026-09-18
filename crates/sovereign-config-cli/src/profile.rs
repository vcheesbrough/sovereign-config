//! Connection-profile management. These commands never reach the service and
//! never accept a URL as a process argument.

use std::io::{self, IsTerminal, Read};

use anyhow::{Result, anyhow, bail};
use sovereign_config_core::ConnectionUrl;
use sovereign_config_native::ProfileStore;

use crate::cli::ProfileCommand;
use crate::session::credential_store;

const MAX_CONNECTION_URL_BYTES: u64 = 16 * 1024;

/// Adds, updates, or re-points the default profile.
///
/// # Errors
///
/// Returns an error when the URL is unreadable or invalid, or when the profile
/// store cannot be written.
pub fn manage_profile(command: ProfileCommand, profiles: &ProfileStore) -> Result<()> {
    match command {
        ProfileCommand::Add { name } => {
            let connection = read_connection(None, false)?
                .ok_or_else(|| anyhow!("connection URL is required"))?;
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
