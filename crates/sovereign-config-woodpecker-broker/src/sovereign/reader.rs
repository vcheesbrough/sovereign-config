//! Reading configuration layers over native gRPC.
//!
//! Everything here is `!Send` and never leaves the reader thread.
//!
//! One layer costs one `GetSubTree` plus one `RevealSecret` per secret leaf:
//! ordinary reads return secrets masked, so the plaintext a CI pipeline needs
//! must be revealed explicitly. Plain-classified values come back in the
//! subtree read itself.
//!
//! `GetSubTree` is used rather than `ListValues` for two reasons: it reports
//! `PermissionDenied` explicitly, where `ListValues` silently filters and so
//! cannot distinguish "not permitted" from "not there"; and it is scoped
//! server-side to the selected root instead of scanning the whole path table.

use std::collections::BTreeMap;
use std::time::Duration;

use sovereign_config_client::{AccessTokenProvider, Transport, ValueTransport};
use sovereign_config_core::{
    ClientError, ConfigPath, ConnectionUrl, ErrorKind, PROTOCOL_VERSION, RevealedSecret, Secret,
    ServiceStatus, ValueContent,
};
use sovereign_config_native::TonicTransport;

use super::{ConnectError, token::CachedTokenProvider};
use crate::error::BrokerError;

pub(crate) struct SovereignReader {
    transport: TonicTransport,
    tokens: CachedTokenProvider,
    root: ConfigPath,
}

impl SovereignReader {
    /// Parses the connection URL, opens the channel, and negotiates protocol
    /// compatibility. No token is acquired here.
    pub(crate) async fn connect(url: &Secret, token_ttl: Duration) -> Result<Self, ConnectError> {
        let connection =
            ConnectionUrl::parse(url.expose()).map_err(|_| ConnectError::MalformedUrl)?;
        let authentication = connection
            .client_authentication()
            .ok_or(ConnectError::UnsupportedCredential)?
            .clone();
        let transport = TonicTransport::connect(connection.endpoint().to_owned())
            .await
            .map_err(|_| ConnectError::Unavailable)?;
        let reply = transport
            .get_version(PROTOCOL_VERSION)
            .await
            .map_err(|_| ConnectError::Unavailable)?;
        if !ServiceStatus::negotiate(reply.application_version, reply.protocol_version).compatible {
            return Err(ConnectError::IncompatibleProtocol);
        }
        Ok(Self {
            transport,
            tokens: CachedTokenProvider::new(
                connection.issuer().to_owned(),
                connection.client_id().to_owned(),
                authentication,
                token_ttl,
            ),
            root: connection.root().clone(),
        })
    }

    pub(crate) fn root(&self) -> &ConfigPath {
        &self.root
    }

    /// Resolves every layer in order, merging later layers over earlier ones.
    ///
    /// Merge order is the whole point of layering: `/woodpecker/global` sets a
    /// default that `/woodpecker/repos/<owner>/<repo>` may override for one
    /// repository.
    pub(crate) async fn fetch(
        &self,
        layers: &[ConfigPath],
    ) -> Result<BTreeMap<String, RevealedSecret>, BrokerError> {
        let mut merged = BTreeMap::new();
        for layer in layers {
            for (name, value) in self.read_layer(layer).await? {
                merged.insert(name, value);
            }
        }
        Ok(merged)
    }

    /// Reads one layer's direct children.
    ///
    /// An absent layer yields nothing; so does one this connection may not
    /// read. Both are ordinary — a repository simply may have no per-repo
    /// layer — and mirror the Go broker's treatment of `OpenBao` 404 and 403.
    async fn read_layer(
        &self,
        layer: &ConfigPath,
    ) -> Result<Vec<(String, RevealedSecret)>, BrokerError> {
        let subtree = match self
            .with_token(async |token: Secret| self.transport.get_subtree(layer, &token).await)
            .await
        {
            Ok(subtree) => subtree,
            Err(error) if error.kind == ErrorKind::PermissionDenied => {
                // Paths are not secret, so naming the layer is safe and is the
                // only way an operator can tell a misconfigured grant from a
                // genuinely empty layer.
                tracing::warn!(layer = %layer.as_str(), "layer skipped: not permitted");
                return Ok(Vec::new());
            }
            Err(error) if error.kind == ErrorKind::NotFound => {
                tracing::debug!(layer = %layer.as_str(), "layer skipped: absent");
                return Ok(Vec::new());
            }
            Err(error) => return Err(error.into()),
        };

        let mut values = Vec::new();
        for value in &subtree.values {
            let Some(name) = direct_child_name(layer, &value.path) else {
                // Woodpecker secret names are flat, so a nested value has no
                // representation in the response. Skip it rather than inventing
                // a mangled name.
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
                        // between. Dropping that one value beats failing the
                        // request: Woodpecker swallows a 503 and falls back to
                        // its own store, so one racing delete would strip every
                        // concurrent pipeline of every secret.
                        Err(error) if error.kind == ErrorKind::NotFound => {
                            tracing::warn!(
                                path = %value.path.as_str(),
                                "value skipped: removed between listing and reveal"
                            );
                            continue;
                        }
                        // PermissionDenied is not a race. The layer itself was
                        // readable, so a denial on one leaf means the grant does
                        // not cover what it appears to, and silently serving a
                        // short result would hide that.
                        Err(error) => return Err(error.into()),
                    }
                }
            };
            values.push((name, revealed));
        }
        Ok(values)
    }

    /// Runs one RPC with the cached token, retrying once on rejection.
    ///
    /// A token can be revoked before its reported lifetime ends. Without this
    /// retry the cache would keep replaying a dead token until the TTL lapsed,
    /// failing every pipeline in between.
    ///
    /// The token is passed by value rather than by reference so the closure's
    /// returned future owns it; a borrowed parameter here needs a higher-ranked
    /// bound that closure inference cannot supply.
    async fn with_token<T>(
        &self,
        call: impl AsyncFn(Secret) -> Result<T, ClientError>,
    ) -> Result<T, ClientError> {
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

/// The final segment of `path`, when `path` is a direct child of `layer`.
///
/// Comparison is on whole segments: `/a/b` is not a child of `/a/bc`.
fn direct_child_name(layer: &ConfigPath, path: &ConfigPath) -> Option<String> {
    let prefix = if layer.as_str() == "/" {
        "/"
    } else {
        layer.as_str()
    };
    let relative = if prefix == "/" {
        path.as_str().strip_prefix('/')?
    } else {
        path.as_str().strip_prefix(prefix)?.strip_prefix('/')?
    };
    (!relative.is_empty() && !relative.contains('/')).then(|| relative.to_owned())
}

#[cfg(test)]
mod tests {
    use sovereign_config_core::ConfigPath;

    use super::direct_child_name;

    fn path(value: &str) -> ConfigPath {
        ConfigPath::parse(value).unwrap()
    }

    #[test]
    fn a_direct_child_yields_its_final_segment() {
        assert_eq!(
            direct_child_name(
                &path("/woodpecker/global"),
                &path("/woodpecker/global/github_token")
            ),
            Some("github_token".to_owned())
        );
        assert_eq!(
            direct_child_name(&path("/"), &path("/github_token")),
            Some("github_token".to_owned())
        );
    }

    #[test]
    fn the_layer_itself_and_deeper_descendants_are_not_children() {
        assert_eq!(
            direct_child_name(&path("/woodpecker/global"), &path("/woodpecker/global")),
            None
        );
        assert_eq!(
            direct_child_name(
                &path("/woodpecker/global"),
                &path("/woodpecker/global/nested/token")
            ),
            None
        );
    }

    // Card #294: the server may now return a value's path in whatever case it
    // was written with (`/Stacks/Monitoring/FOO`), not always lowercase. Both
    // `layer` and `path` reach this function already folded by
    // `ConfigPath::parse_operation`/`parse_selection` at the transport
    // boundary, so `.as_str()` here is always the fold key on both sides —
    // the strip never sees mismatched case and the secret is never dropped.
    // The returned name also stays fold-cased, matching Woodpecker's
    // exact-lowercase `from_secret:` grammar.
    #[test]
    fn a_mixed_case_stored_path_under_a_lowercase_layer_still_yields_its_value() {
        let layer = ConfigPath::parse("/stacks/monitoring").unwrap();
        let mixed_case_path = ConfigPath::parse_operation("/Stacks/Monitoring/FOO").unwrap();
        assert_eq!(
            direct_child_name(&layer, &mixed_case_path),
            Some("foo".to_owned())
        );
    }

    // The same class of bug as the SQL LIKE wildcard: prefix comparison must
    // stop at a segment boundary, or a sibling layer leaks into this one.
    #[test]
    fn a_sibling_sharing_a_textual_prefix_is_not_a_child() {
        assert_eq!(
            direct_child_name(
                &path("/woodpecker/global"),
                &path("/woodpecker/globals/token")
            ),
            None
        );
        assert_eq!(
            direct_child_name(&path("/a/b_c"), &path("/a/bxc/token")),
            None
        );
        assert_eq!(
            direct_child_name(&path("/a/b_c"), &path("/a/b_c/token")),
            Some("token".to_owned())
        );
    }
}
