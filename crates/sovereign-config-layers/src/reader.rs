//! Reading configuration layers over an authenticated transport.
//!
//! One layer costs one `GetSubTree` plus one `RevealSecret` per secret leaf:
//! ordinary reads return secrets masked, so the plaintext a consumer needs must
//! be revealed explicitly. Plain-classified values come back in the subtree read
//! itself.
//!
//! `GetSubTree` is used rather than `ListValues` for two reasons: it reports
//! `PermissionDenied` explicitly, where `ListValues` silently filters and so
//! cannot distinguish "not permitted" from "not there"; and it is scoped
//! server-side to the selected root instead of scanning the whole path table.

use std::collections::BTreeMap;

use sovereign_config_client::{AccessTokenProvider, ValueTransport};
use sovereign_config_core::{
    ClientError, ConfigPath, ErrorKind, RevealedSecret, Secret, ValueContent,
};

/// A token provider whose cache can be dropped.
///
/// [`LayerReader`] retries once when the service rejects a token, which only
/// helps if the provider can be told to stop replaying the rejected one. A
/// provider that already acquires a fresh token per call implements this as a
/// no-op.
pub trait InvalidatableToken: AccessTokenProvider {
    /// Drops any cached token so the next request acquires a fresh one.
    fn invalidate(&self);
}

/// A shared token provider is still one provider.
///
/// A [`LayerReader`] owns its provider, so a holder that has to rebuild a
/// reader — which is what obtaining a transport for a newly negotiated protocol
/// version amounts to — would otherwise have to duplicate the provider and with
/// it the token cache, turning one cached credential into several and one
/// acquisition per reader. Sharing it keeps a rebuilt reader reading the same
/// cache the old one filled. The matching `AccessTokenProvider` forwarding
/// lives in `sovereign-config-client`, which owns that trait.
impl<P: InvalidatableToken> InvalidatableToken for std::rc::Rc<P> {
    fn invalidate(&self) {
        (**self).invalidate();
    }
}

/// What an *unreadable* or concurrently deleted path means to the caller.
///
/// The two consumers genuinely differ here, so the policy is theirs to choose
/// rather than something this module can decide for them.
///
/// This governs only what the service reports as an error. A layer that holds
/// no values is not an error under either policy — the service answers an
/// absent subtree with an empty list, so "absent" and "empty" are the same
/// response and neither reaches here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnMissing {
    /// Yield nothing for that layer or leaf and carry on.
    ///
    /// The broker's choice, and the Go broker's treatment of `OpenBao` 403 and
    /// 404 before it. A repository simply may have no per-repo layer, and a
    /// value may be deleted between the listing and the reveal — failing the
    /// whole request over either would be worse than serving a short one,
    /// because Woodpecker swallows a 503 and falls back to its own store,
    /// stripping every concurrent pipeline of every secret.
    Skip,
    /// Fail the whole read.
    ///
    /// `render`'s choice. A deploy that silently receives less configuration
    /// than it asked for is the failure mode `render` exists to remove, and a
    /// typo'd layer path must not look like an empty one.
    Fail,
}

/// What letter case a leaf's name is reported in.
///
/// Paths have been case-**retentive** since 2.18.0: `/x/FOO` and `/x/foo` are
/// the same value, resolved and authorized on the fold, but a response reports
/// whichever spelling the path was actually stored with. So there are two
/// different names available for one leaf, and the consumers want different
/// ones.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Naming {
    /// Lowercase the name, and merge layers on it.
    ///
    /// The broker's choice, and not a preference: Woodpecker matches a
    /// `from_secret:` reference by exact lowercase string, so a value stored as
    /// `/woodpecker/shared/Github_Token` has to be served as `github_token` or
    /// the pipeline referencing it gets nothing. Merging on the same key is
    /// what makes a per-repo layer override a shared one regardless of the case
    /// either was written with.
    Folded,
    /// Report the name exactly as stored, and merge layers on it.
    ///
    /// `render`'s choice, because an environment variable name *is* case
    /// sensitive: `/foo/AbC` holding `bAr` must reach the command as
    /// `AbC=bAr`, which is the one thing a deploy can predict without knowing
    /// this crate exists. It follows that two layers spelling a leaf
    /// differently produce two variables rather than overriding — which is
    /// right, since `AbC` and `abc` are two variables to the command as well.
    AsStored,
}

impl Naming {
    fn apply(self, name: &str) -> String {
        match self {
            Self::Folded => name.to_ascii_lowercase(),
            Self::AsStored => name.to_owned(),
        }
    }
}

/// Reads and merges ordered configuration layers.
pub struct LayerReader<T, P> {
    transport: T,
    tokens: P,
    on_missing: OnMissing,
    naming: Naming,
}

impl<T, P> LayerReader<T, P>
where
    T: ValueTransport,
    P: InvalidatableToken,
{
    pub fn new(transport: T, tokens: P, on_missing: OnMissing, naming: Naming) -> Self {
        Self {
            transport,
            tokens,
            on_missing,
            naming,
        }
    }

    /// Resolves every layer in order, merging later layers over earlier ones.
    ///
    /// Merge order is the whole point of layering: `/woodpecker/global` sets a
    /// default that `/woodpecker/repos/<owner>/<repo>` may override for one
    /// repository, and `render /apps/api /apps/api/prod` overlays the
    /// environment-specific layer on the shared one.
    ///
    /// # Errors
    ///
    /// Any transport or authentication failure. Whether an absent or unreadable
    /// path is one of those is the [`OnMissing`] policy this reader was built
    /// with.
    pub async fn fetch(
        &self,
        layers: &[ConfigPath],
    ) -> Result<BTreeMap<String, RevealedSecret>, ClientError> {
        let mut merged = BTreeMap::new();
        for layer in layers {
            for (name, value) in self.read(layer).await? {
                merged.insert(name, value);
            }
        }
        Ok(merged)
    }

    /// Reads one layer's direct children, in path order.
    ///
    /// Exposed alongside [`Self::fetch`] because a caller may need to say
    /// something about an *individual* layer that the merged map can no longer
    /// distinguish — `render` refuses a layer that contributed nothing, and the
    /// error has to name which one.
    ///
    /// # Errors
    ///
    /// Any transport or authentication failure, subject to the [`OnMissing`]
    /// policy. Note that a layer which simply holds no values is **not** one of
    /// them: the service answers an absent subtree with an empty list rather
    /// than `NotFound`, so an empty result here means "nothing there", and what
    /// that means is the caller's to decide.
    pub async fn read(
        &self,
        layer: &ConfigPath,
    ) -> Result<Vec<(String, RevealedSecret)>, ClientError> {
        let skipping = self.on_missing == OnMissing::Skip;
        let subtree = match self
            .with_token(async |token: Secret| self.transport.get_subtree(layer, &token).await)
            .await
        {
            Ok(subtree) => subtree,
            Err(error) if skipping && error.kind == ErrorKind::PermissionDenied => {
                // Paths are not secret, so naming the layer is safe and is the
                // only way an operator can tell a misconfigured grant from a
                // genuinely empty layer.
                tracing::warn!(layer = %layer.as_str(), "layer skipped: not permitted");
                return Ok(Vec::new());
            }
            Err(error) if skipping && error.kind == ErrorKind::NotFound => {
                tracing::debug!(layer = %layer.as_str(), "layer skipped: absent");
                return Ok(Vec::new());
            }
            Err(error) => return Err(error),
        };

        let mut values = Vec::new();
        for value in &subtree.values {
            let Some(name) =
                direct_child_name(layer, &value.path).map(|name| self.naming.apply(name))
            else {
                // Both consumers address a leaf by a flat name — a Woodpecker
                // `from_secret:` name, an environment variable — so a nested
                // value has no representation in the result. Skip it rather
                // than inventing a mangled name. This is not the `OnMissing`
                // policy's business: nothing is missing, the value is simply
                // not addressable at this layer, and that is true for both
                // consumers.
                tracing::warn!(
                    path = %value.path.as_str(),
                    "value skipped: not a direct child of its layer"
                );
                continue;
            };
            let revealed = match &value.value {
                ValueContent::Plain(plain) => RevealedSecret::new(plain.expose()),
                ValueContent::Secret(_) => {
                    match self
                        .with_token(async |token: Secret| {
                            self.transport.reveal_secret(&value.path, &token).await
                        })
                        .await
                    {
                        Ok(revealed) => revealed,
                        // The subtree listed this leaf a moment ago, so a
                        // NotFound here means it was deleted or re-aliased in
                        // between — a race, not a misconfiguration, which is
                        // why it follows the same policy as an absent layer.
                        Err(error) if skipping && error.kind == ErrorKind::NotFound => {
                            tracing::warn!(
                                path = %value.path.as_str(),
                                "value skipped: removed between listing and reveal"
                            );
                            continue;
                        }
                        // PermissionDenied is not a race. The layer itself was
                        // readable, so a denial on one leaf means the grant does
                        // not cover what it appears to, and silently serving a
                        // short result would hide that — so it fails under
                        // either policy.
                        Err(error) => return Err(error),
                    }
                }
            };
            values.push((name, revealed));
        }
        Ok(values)
    }

    /// Runs one RPC with the current token, retrying once on rejection.
    ///
    /// A token can be revoked before its reported lifetime ends. Without this
    /// retry a caching provider would keep replaying a dead token until the TTL
    /// lapsed, failing every request in between.
    ///
    /// The token is passed by value rather than by reference so the closure's
    /// returned future owns it; a borrowed parameter here needs a higher-ranked
    /// bound that closure inference cannot supply.
    async fn with_token<R>(
        &self,
        call: impl AsyncFn(Secret) -> Result<R, ClientError>,
    ) -> Result<R, ClientError> {
        match call(self.token().await?).await {
            Err(error) if error.kind == ErrorKind::Unauthenticated => {
                tracing::info!("access token rejected; re-acquiring");
                self.tokens.invalidate();
                call(self.token().await?).await
            }
            result => result,
        }
    }

    async fn token(&self) -> Result<Secret, ClientError> {
        self.tokens.access_token().await?.ok_or_else(|| {
            ClientError::new(ErrorKind::Unauthenticated, "no access token was issued")
        })
    }
}

/// The final segment of `path` **exactly as stored**, when `path` is a direct
/// child of `layer`.
///
/// Two different cases are in play and they must not be confused. *Matching* is
/// on the fold, because `layer` carries whatever case the caller typed and
/// `path` whatever case the value was stored with, and those are the same path
/// whenever their folds agree. *The returned name* is the stored spelling,
/// because that is the only one this function can know is right — a consumer
/// that wants the fold asks for [`Naming::Folded`], which is a choice, not a
/// property of the path.
///
/// Matching is on whole segments: `/a/b` is not a child of `/a/bc`.
///
/// The fold is computed by ASCII-lowercasing, and the grammar admits only
/// ASCII, so folding never changes a path's length. That is what lets the
/// offset found in the fold index the stored spelling.
#[must_use]
pub fn direct_child_name<'a>(layer: &ConfigPath, path: &'a ConfigPath) -> Option<&'a str> {
    let layer_fold = layer.fold();
    let path_fold = path.fold();
    debug_assert_eq!(
        path_fold.len(),
        path.as_str().len(),
        "folding resized a path"
    );
    let offset = if layer_fold == "/" {
        // Every path begins with `/`, and under the tree root the child segment
        // is everything after it.
        1
    } else {
        // `starts_with` alone would match `/a/bc` against layer `/a/b`, so the
        // byte after the prefix must be the separator.
        if !path_fold.starts_with(&layer_fold)
            || path_fold.as_bytes().get(layer_fold.len()) != Some(&b'/')
        {
            return None;
        }
        layer_fold.len() + 1
    };
    let relative = path.as_str().get(offset..)?;
    (!relative.is_empty() && !relative.contains('/')).then_some(relative)
}

#[cfg(test)]
mod tests;
