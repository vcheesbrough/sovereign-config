//! The issuers' signing keys, held in memory so a request is verified without
//! a round-trip to Authentik (README "Request authentication").
//!
//! Keys come from one place only: `<issuer>jwks/` for each configured issuer —
//! the `jwks_uri` Authentik's discovery document names for a per-provider
//! issuer. A token's own `jku`, `x5u` or embedded `jwk` header is never
//! consulted, so a token cannot name the key that verifies it.
//!
//! A successful fetch **replaces** the issuer's key set, so a key Authentik
//! drops stops being trusted at the next fetch: within [`PERIODIC_REFRESH`]. A
//! failed fetch keeps the last good set, because a key that verified a token a
//! minute ago has not become less trustworthy by Authentik being unreachable.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::Method;
use reqwest::{Client, Url, redirect};
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::{Instrument, warn};

use super::read_bounded_response;
use crate::spans;

/// How often every issuer's key set is re-read while the server runs: the
/// longest a key Authentik removes is still trusted.
pub(crate) const PERIODIC_REFRESH: Duration = Duration::from_mins(10);
/// How soon a failed periodic fetch is tried again — at startup, until the
/// keys first load, and whenever Authentik is unreachable.
pub(crate) const RETRY_INTERVAL: Duration = Duration::from_secs(15);
/// The fewest seconds between two fetches of one issuer's keys prompted by
/// tokens naming a key not in the cache. Without it, a stream of tokens with
/// invented `kid`s would be a stream of requests to Authentik.
///
/// Only such a fetch starts the interval; the periodic re-read and the startup
/// retry do not, so they never delay picking up a newly rotated key. Inside
/// the interval an unknown `kid` is refused as `bad_signature` without a
/// fetch — which is also how a genuine token signed by a key rotated in during
/// those seconds is answered (README "Credential rotation").
pub(crate) const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(10);

/// What a lookup of one `kid` found.
pub(crate) enum KeyLookup {
    Found(Arc<VerifyingKey>),
    /// The issuer's current key set, fetched successfully, has no such key.
    Unknown,
    /// The key is not cached and the key set could not be fetched.
    Unavailable,
}

/// One RSA public key, as its JWK's modulus and exponent.
pub(crate) struct VerifyingKey {
    modulus: Vec<u8>,
    exponent: Vec<u8>,
}

impl VerifyingKey {
    /// Whether `signature` is this key's RS256 signature of `message`. ring
    /// refuses a modulus under 2048 bits, so a weak key in the set verifies
    /// nothing.
    pub(crate) fn verifies(&self, message: &[u8], signature: &[u8]) -> bool {
        RsaPublicKeyComponents {
            n: &self.modulus,
            e: &self.exponent,
        }
        .verify(&RSA_PKCS1_2048_8192_SHA256, message, signature)
        .is_ok()
    }
}

/// Every configured issuer's key set.
pub(crate) struct KeySets {
    client: Client,
    issuers: Vec<IssuerKeys>,
    min_refresh_interval: Duration,
}

struct IssuerKeys {
    issuer: String,
    jwks_url: Url,
    keys: RwLock<HashMap<String, Arc<VerifyingKey>>>,
    /// Held across a fetch, so concurrent misses for one issuer wait for a
    /// single fetch rather than each making their own.
    fetch: Mutex<LastFetch>,
}

#[derive(Default)]
struct LastFetch {
    /// When a token naming an uncached key last caused a fetch.
    miss: Option<Instant>,
    /// Whether the most recent fetch, of any kind, loaded the key set.
    succeeded: bool,
}

#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kty: String,
    kid: Option<String>,
    alg: Option<String>,
    #[serde(rename = "use")]
    usage: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

impl KeySets {
    pub(crate) fn new<'a>(
        issuers: impl IntoIterator<Item = &'a str>,
        timeout: Duration,
        min_refresh_interval: Duration,
    ) -> Result<Self> {
        let mut sets: Vec<IssuerKeys> = Vec::new();
        for issuer in issuers {
            if sets.iter().any(|set| set.issuer == issuer) {
                continue;
            }
            let jwks_url = issuer
                .parse::<Url>()
                .and_then(|url| url.join("jwks/"))
                .context("the issuer does not form a JWKS URL")?;
            sets.push(IssuerKeys {
                issuer: issuer.to_owned(),
                jwks_url,
                keys: RwLock::default(),
                fetch: Mutex::default(),
            });
        }
        let client = Client::builder()
            .timeout(timeout)
            .https_only(sets.iter().all(|set| set.jwks_url.scheme() == "https"))
            // The key set is read from the configured issuer and nowhere else.
            .redirect(redirect::Policy::none())
            .build()
            .context("unable to configure the JWKS client")?;
        Ok(Self {
            client,
            issuers: sets,
            min_refresh_interval,
        })
    }

    /// The key `kid` of `issuer`, fetching the issuer's key set when the key is
    /// not cached and no other miss has fetched within the refresh interval.
    ///
    /// `issuer` must be one of the configured issuers; the caller checks the
    /// token's `iss` against them first, so no request ever names the host a
    /// key is fetched from.
    pub(crate) async fn key(&self, issuer: &str, kid: &str) -> KeyLookup {
        let Some(set) = self.issuers.iter().find(|set| set.issuer == issuer) else {
            return KeyLookup::Unknown;
        };
        if let Some(key) = set.cached(kid) {
            return KeyLookup::Found(key);
        }
        let mut last = set.fetch.lock().await;
        // Another request may have fetched while this one waited for the lock.
        if let Some(key) = set.cached(kid) {
            return KeyLookup::Found(key);
        }
        if last
            .miss
            .is_some_and(|miss| miss.elapsed() < self.min_refresh_interval)
        {
            return if last.succeeded {
                KeyLookup::Unknown
            } else {
                KeyLookup::Unavailable
            };
        }
        last.miss = Some(Instant::now());
        if !self.fetch(set, &mut last).await {
            return KeyLookup::Unavailable;
        }
        set.cached(kid).map_or(KeyLookup::Unknown, KeyLookup::Found)
    }

    /// Re-reads every issuer's key set, returning whether all of them loaded.
    pub(crate) async fn refresh(&self) -> bool {
        let mut all = true;
        for set in &self.issuers {
            let mut last = set.fetch.lock().await;
            all &= self.fetch(set, &mut last).await;
        }
        all
    }

    async fn fetch(&self, set: &IssuerKeys, last: &mut LastFetch) -> bool {
        let fetched = self
            .fetch_keys(&set.jwks_url)
            .instrument(spans::client_span(&Method::GET, None, &set.jwks_url))
            .await;
        last.succeeded = fetched.is_some();
        let Some(keys) = fetched else {
            warn!("the issuer's signing keys could not be fetched");
            return false;
        };
        *set.keys.write().expect("the key set lock is not poisoned") = keys;
        true
    }

    /// The fetch itself, inside its client span. The URL is configuration, so
    /// the span is named by its method alone.
    async fn fetch_keys(&self, url: &Url) -> Option<HashMap<String, Arc<VerifyingKey>>> {
        let request = self.client.get(url.clone());
        let body = match spans::send(&self.client, request).await {
            Ok(response) if response.status().is_success() => {
                read_bounded_response(response).await.ok()
            }
            _ => None,
        };
        let keys = body.and_then(|body| parse_key_set(&body));
        if keys.is_none() {
            spans::record_error("unavailable");
        }
        keys
    }
}

impl IssuerKeys {
    fn cached(&self, kid: &str) -> Option<Arc<VerifyingKey>> {
        self.keys
            .read()
            .expect("the key set lock is not poisoned")
            .get(kid)
            .cloned()
    }
}

/// The RS256 signing keys of a JWK set, by `kid`. A document that is not a
/// JWK set is `None`; a key that is not an RS256 signing key with a `kid` is
/// skipped rather than failing the others.
fn parse_key_set(body: &[u8]) -> Option<HashMap<String, Arc<VerifyingKey>>> {
    let set: JwkSet = serde_json::from_slice(body).ok()?;
    Some(
        set.keys
            .into_iter()
            .filter(|jwk| {
                jwk.kty == "RSA"
                    && jwk.alg.as_deref().is_none_or(|alg| alg == "RS256")
                    && jwk.usage.as_deref().is_none_or(|usage| usage == "sig")
            })
            .filter_map(|jwk| {
                let modulus = URL_SAFE_NO_PAD.decode(jwk.n?).ok()?;
                let exponent = URL_SAFE_NO_PAD.decode(jwk.e?).ok()?;
                Some((
                    jwk.kid.filter(|kid| !kid.is_empty())?,
                    Arc::new(VerifyingKey { modulus, exponent }),
                ))
            })
            .collect(),
    )
}
