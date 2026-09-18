//! Choosing which connection a command runs against.
//!
//! A stored profile is the interactive answer, but the hosts `render` exists
//! for — a CI container, a compose deploy step — have no profile store and no
//! terminal to create one at. They are handed a credential by the surrounding
//! system instead, as a file or as an environment variable.
//!
//! Resolution order is fixed and documented:
//!
//! 1. `--profile <name>` — an explicit choice always wins.
//! 2. `--url-file <path>` — a file the host placed, such as a mounted secret.
//! 3. `SOVEREIGN_CONFIG_URL` — the variable a CI step injects.
//! 4. the default profile, which is what every interactive invocation lands on.
//!
//! **A connection URL is never a process argument.** It carries the credential,
//! and process arguments are world-readable on a typical host. `--url-file`
//! names a file and `SOVEREIGN_CONFIG_URL` names a variable; neither is the URL
//! itself.

use std::{fs, path::Path};

use anyhow::{Context, Result, bail};
use sovereign_config_core::ConnectionUrl;
use sovereign_config_native::{ProfileStore, default_profile_path};

/// The environment variable a profile-less host supplies the connection URL in.
///
/// `render` strips this from the environment it hands the executed command, so
/// the credential stops here.
pub const URL_VARIABLE: &str = "SOVEREIGN_CONFIG_URL";

/// A connection URL is a bounded thing; anything larger is not one, and reading
/// an arbitrarily large file into memory to find that out is not necessary.
const MAX_CONNECTION_URL_BYTES: u64 = 16 * 1024;

/// Resolves the connection this invocation runs against.
///
/// # Errors
///
/// Returns an error when the named profile does not exist, the URL file is
/// unreadable or does not hold a valid URL, `SOVEREIGN_CONFIG_URL` is not a
/// valid URL, or no credential is available at all. No error carries any part
/// of a URL.
pub fn resolve(profile: Option<&str>, url_file: Option<&Path>) -> Result<ConnectionUrl> {
    if let Some(profile) = profile {
        return Ok(profiles()?.connection(Some(profile))?);
    }
    if let Some(path) = url_file {
        return from_file(path);
    }
    if let Some(value) = std::env::var_os(URL_VARIABLE) {
        let value = value
            .into_string()
            .map_err(|_| anyhow::anyhow!("{URL_VARIABLE} is not valid UTF-8"))?;
        return parse(&value).with_context(|| format!("{URL_VARIABLE} is not a valid URL"));
    }
    Ok(profiles()?.connection(None)?)
}

/// The profile store, opened only when a profile is actually needed.
///
/// A CI container has no state directory, so determining its path can fail.
/// That must not stop a `--url-file` or `SOVEREIGN_CONFIG_URL` invocation,
/// which never touches the store.
fn profiles() -> Result<ProfileStore> {
    Ok(ProfileStore::new(default_profile_path()?))
}

fn from_file(path: &Path) -> Result<ConnectionUrl> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("connection URL file {} is unreadable", path.display()))?;
    if metadata.len() > MAX_CONNECTION_URL_BYTES {
        bail!(
            "connection URL file {} is not a connection URL",
            path.display()
        );
    }
    let contents = fs::read_to_string(path)
        .with_context(|| format!("connection URL file {} is unreadable", path.display()))?;
    parse(&contents).with_context(|| {
        format!(
            "connection URL file {} is not a connection URL",
            path.display()
        )
    })
}

/// Parses a URL that arrived as text, tolerating one trailing line ending.
///
/// A file written by `echo` or a heredoc ends in a newline, and refusing that
/// would be a papercut with no security value. An *embedded* newline is a
/// different matter: it means the input is not one URL, and guessing which line
/// was meant is exactly the kind of guess that ends up pointing at the wrong
/// service.
fn parse(value: &str) -> Result<ConnectionUrl> {
    let value = value.strip_suffix('\n').unwrap_or(value);
    let value = value.strip_suffix('\r').unwrap_or(value);
    if value.bytes().any(|byte| matches!(byte, b'\n' | b'\r')) {
        bail!("connection URL is invalid");
    }
    Ok(ConnectionUrl::parse(value)?)
}

#[cfg(test)]
mod tests;
