//! Connection-profile management. These commands never reach the service and
//! never accept a URL as a process argument.

use std::io::{self, IsTerminal, Read};

use serde_json::{Value, json};

use anyhow::{Result, anyhow, bail};
use sovereign_config_core::ConnectionUrl;
use sovereign_config_native::{ListedProfile, ProfileStore};

use crate::cli::{OutputFormat, ProfileCommand};
use crate::session::credential_store;

const MAX_CONNECTION_URL_BYTES: u64 = 16 * 1024;

/// Adds, lists, updates, or deletes a profile, or re-points the default.
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
        ProfileCommand::List { format } => list_profiles(&profiles.list()?, format)?,
        ProfileCommand::Delete { name, yes } => {
            // Refuse a missing profile, or the default while others remain,
            // before asking, so the prompt is never answered for nothing.
            let current = profiles.deletable(&name)?;
            let managed = current.client_authentication().is_some();
            if !yes {
                confirm_profile_deletion(&name, managed)?;
            }
            // The refresh credential goes first, as on `update`: a failed
            // write afterwards leaves the profile merely logged out, where the
            // reverse order would leave a credential no profile can reach.
            if !managed && !profiles.contains_other_human_identity(&name, &current)? {
                credential_store(&current)?.delete()?;
            }
            profiles.delete(&name)?;
            println!("Profile deleted");
        }
    }
    Ok(())
}

fn confirm_profile_deletion(name: &str, managed: bool) -> Result<()> {
    if !io::stdin().is_terminal() {
        bail!("profile deletion requires --yes when standard input is not a terminal");
    }
    if managed {
        // A managed profile's URL embeds its credential, which the service
        // never shows again; deleting the profile may lose the only copy.
        eprint!("Delete profile {name} and the access URL it stores? Type 'delete' to confirm: ");
    } else {
        eprint!("Delete profile {name}? Type 'delete' to confirm: ");
    }
    let mut confirmation = String::new();
    io::stdin()
        .read_line(&mut confirmation)
        .map_err(|_| anyhow!("deletion confirmation is unavailable"))?;
    if confirmation.trim_end() != "delete" {
        bail!("deletion cancelled");
    }
    Ok(())
}

/// Prints the stored profiles. Nothing here is secret: a managed profile's
/// URL arrives with its credential already replaced by `*`.
fn list_profiles(profiles: &[ListedProfile], format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Plain => {
            // Pad to the longest name so the endpoints line up, and mark the
            // default with `*` in a leading column, as `git branch` does.
            let width = profiles
                .iter()
                .map(|profile| profile.name.len())
                .max()
                .unwrap_or_default();
            for profile in profiles {
                let marker = if profile.is_default { '*' } else { ' ' };
                // A confined profile reads as its endpoint plus the root it is
                // confined to; an unconfined one is just the endpoint, since
                // a bare trailing `/` would say nothing.
                let root = if profile.root == "/" {
                    ""
                } else {
                    &profile.root
                };
                println!(
                    "{marker} {name:width$}  {endpoint}{root}",
                    name = profile.name,
                    endpoint = profile.endpoint,
                );
            }
        }
        OutputFormat::Json => {
            let rendered: Vec<Value> = profiles
                .iter()
                .map(|profile| {
                    json!({
                        "name": profile.name,
                        "default": profile.is_default,
                        "endpoint": profile.endpoint,
                        "root": profile.root,
                        "url": profile.redacted_url,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&rendered)?);
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
