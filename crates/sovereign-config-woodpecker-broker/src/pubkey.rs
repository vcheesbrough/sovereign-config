//! Loading the Woodpecker request-signing public key.
//!
//! Mirrors the Go broker's `utils.GetPubKey`: a live fetch from the Woodpecker
//! API wins over a mounted file, so an operator can point at a server without
//! first removing a stale PEM. The key is loaded once at startup and a failure
//! is fatal — a broker that cannot verify signatures must not serve secrets.
//!
//! The live deployment uses the file form, so the broker has no startup
//! dependency on the Woodpecker server being up.

use std::{fs, time::Duration};

use sovereign_config_core::Secret;

use crate::{
    config::PublicKeySource,
    signature::{KeyError, SignatureVerifier},
};

const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// A PEM public key is a few hundred bytes; anything larger is not one.
const MAX_KEY_BYTES: usize = 8 * 1024;

#[derive(Debug, thiserror::Error)]
pub(crate) enum PublicKeyError {
    #[error("the Woodpecker public key file could not be read")]
    Unreadable,
    #[error("the Woodpecker public key could not be fetched")]
    Unfetchable,
    #[error("the Woodpecker public key endpoint rejected the token")]
    Unauthorized,
    #[error(transparent)]
    Malformed(#[from] KeyError),
}

pub(crate) async fn load(source: &PublicKeySource) -> Result<SignatureVerifier, PublicKeyError> {
    let pem = match source {
        PublicKeySource::Fetch { url, token } => fetch(url, token).await?,
        PublicKeySource::File(path) => {
            fs::read_to_string(path).map_err(|_| PublicKeyError::Unreadable)?
        }
    };
    Ok(SignatureVerifier::from_spki_pem(&pem)?)
}

async fn fetch(base_url: &str, token: &Secret) -> Result<String, PublicKeyError> {
    let url = format!(
        "{}/api/signature/public-key",
        base_url.trim_end_matches('/')
    );
    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(FETCH_TIMEOUT)
        .build()
        .map_err(|_| PublicKeyError::Unfetchable)?
        .get(url)
        .bearer_auth(token.expose())
        .send()
        .await
        .map_err(|_| PublicKeyError::Unfetchable)?;

    if response.status() == reqwest::StatusCode::UNAUTHORIZED
        || response.status() == reqwest::StatusCode::FORBIDDEN
    {
        return Err(PublicKeyError::Unauthorized);
    }
    if !response.status().is_success() {
        return Err(PublicKeyError::Unfetchable);
    }

    let body = response
        .text()
        .await
        .map_err(|_| PublicKeyError::Unfetchable)?;
    // Woodpecker answers an unauthorized token with a 200 and this body rather
    // than a status code, so treat it as the rejection it is.
    if body.len() > MAX_KEY_BYTES || body.trim().is_empty() || body.trim() == "User not authorized"
    {
        return Err(PublicKeyError::Unauthorized);
    }
    Ok(body)
}
