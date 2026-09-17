//! Generated identifiers and credentials for a managed connection: the
//! opaque connection id, the recognizable Authentik username, and the
//! replacement app password.

use sovereign_config_core::{ConnectionId, Secret};
use tonic::Status;

use super::wire::internal_error;

const CONNECTION_ID_CHARS: usize = 32;
const APP_PASSWORD_CHARS: usize = 48;
pub(super) const USERNAME_PREFIX: &str = "sc-managed-";
pub(super) const USERNAME_SLUG_MAX_CHARS: usize = 32;

/// Builds the Authentik username for a connection, embedding a slug of the
/// display name so operators can recognize the account in Authentik, with the
/// opaque connection ID guaranteeing uniqueness regardless of display-name
/// collisions. The connection ID alone is used only when the display name
/// contains no characters that survive slugging.
pub(super) fn managed_username(connection_id: &ConnectionId, display_name: &str) -> String {
    let slug = username_slug(display_name);
    if slug.is_empty() {
        format!("{USERNAME_PREFIX}{}", connection_id.as_str())
    } else {
        format!("{USERNAME_PREFIX}{slug}-{}", connection_id.as_str())
    }
}

/// Lowercases and collapses a display name to `[a-z0-9-]`, bounded to
/// [`USERNAME_SLUG_MAX_CHARS`] characters with no leading or trailing hyphen.
pub(super) fn username_slug(display_name: &str) -> String {
    let mut slug = String::with_capacity(USERNAME_SLUG_MAX_CHARS);
    for character in display_name.chars() {
        let lower = character.to_ascii_lowercase();
        if lower.is_ascii_alphanumeric() {
            if slug.len() >= USERNAME_SLUG_MAX_CHARS {
                break;
            }
            slug.push(lower);
        } else if !slug.is_empty() && !slug.ends_with('-') && slug.len() < USERNAME_SLUG_MAX_CHARS {
            slug.push('-');
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    slug
}

/// Generates an opaque random connection identifier from the OS CSPRNG.
#[expect(
    clippy::result_large_err,
    reason = "tonic::Status is the crate's RPC error type and is returned by value"
)]
pub(super) fn generate_connection_id() -> Result<ConnectionId, Status> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let value = random_string(ALPHABET, CONNECTION_ID_CHARS)?;
    ConnectionId::parse(value).map_err(|_| internal_error())
}

/// Generates a high-entropy replacement app password from the OS CSPRNG.
#[expect(
    clippy::result_large_err,
    reason = "tonic::Status is the crate's RPC error type and is returned by value"
)]
pub(super) fn generate_app_password() -> Result<Secret, Status> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    Ok(Secret::new(random_string(ALPHABET, APP_PASSWORD_CHARS)?))
}

/// Draws unbiased characters from the OS CSPRNG with rejection sampling.
#[expect(
    clippy::result_large_err,
    reason = "tonic::Status is the crate's RPC error type and is returned by value"
)]
fn random_string(alphabet: &[u8], length: usize) -> Result<String, Status> {
    debug_assert!(alphabet.len() <= 64);
    let limit = u8::MAX - (u8::MAX % u8::try_from(alphabet.len()).map_err(|_| internal_error())?);
    let mut value = String::with_capacity(length);
    while value.len() < length {
        let mut buffer = [0_u8; 64];
        getrandom::fill(&mut buffer).map_err(|_| internal_error())?;
        for byte in buffer {
            if byte < limit && value.len() < length {
                value.push(char::from(alphabet[usize::from(byte) % alphabet.len()]));
            }
        }
    }
    Ok(value)
}
