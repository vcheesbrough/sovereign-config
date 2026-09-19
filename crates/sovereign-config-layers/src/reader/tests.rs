use std::cell::RefCell;

use async_trait::async_trait;
use sovereign_config_client::{AccessTokenProvider, Transport, ValueTransport};
use sovereign_config_core::{
    AddPathMetadata, AuthenticationStatus, ClientError, ConfigPath, DeleteMetadata, ErrorKind,
    MaskedSecret, PlainValue, PutMetadata, ReplaceMetadata, RevealedSecret, Secret, SecretInput,
    SubTreeMutationValue, SubTreeValue, ValueContent, ValueListing, ValuePaths, ValueSubTree,
};

use super::{InvalidatableToken, LayerReader, Naming, OnMissing, direct_child_name};

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
        Some("github_token")
    );
    assert_eq!(
        direct_child_name(&path("/"), &path("/github_token")),
        Some("github_token")
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

// Card #294: the server may return a value's path in whatever case it was
// written with (`/Stacks/Monitoring/FOO`), not always lowercase, and the
// layer carries whatever case the caller typed. Matching is therefore on the
// fold — the strip never sees mismatched case and the value is never dropped —
// while the name that comes back is the **stored** spelling, which is the only
// one this function can know is right. Whether to fold it is the consumer's
// choice, made through `Naming`.
#[test]
fn a_mixed_case_stored_path_under_a_lowercase_layer_yields_its_stored_spelling() {
    let layer = ConfigPath::parse("/stacks/monitoring").unwrap();
    let mixed_case_path = ConfigPath::parse_operation("/Stacks/Monitoring/FOO").unwrap();
    assert_eq!(direct_child_name(&layer, &mixed_case_path), Some("FOO"));

    // And the other way round: a mixed-case layer — `parse_selection`, the
    // grammar a typed layer path goes through — still matches a lowercase
    // stored path, returning that path's own spelling.
    let mixed_case_layer = ConfigPath::parse_selection("/Stacks/Monitoring").unwrap();
    let stored = ConfigPath::parse_operation("/stacks/monitoring/foo").unwrap();
    assert_eq!(direct_child_name(&mixed_case_layer, &stored), Some("foo"));
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
        Some("token")
    );
}

/// What the mock should do for one path.
enum Reply {
    Plain(&'static str),
    Secret(&'static str),
    Fails(ErrorKind),
}

#[derive(Default)]
struct MockTransport {
    /// `(layer, leaf paths)` in declaration order, so a layer can be absent
    /// without an entry.
    layers: Vec<(&'static str, Vec<&'static str>)>,
    /// `(path, reply)` for every leaf, plus any layer that must fail.
    replies: Vec<(&'static str, Reply)>,
    calls: RefCell<Vec<String>>,
}

impl MockTransport {
    fn reply(&self, path: &str) -> Option<&Reply> {
        self.replies
            .iter()
            .find(|(candidate, _)| *candidate == path)
            .map(|(_, reply)| reply)
    }
}

#[async_trait(?Send)]
impl Transport for MockTransport {
    async fn get_identity(&self, _: &Secret) -> Result<AuthenticationStatus, ClientError> {
        unreachable!("the reader never checks identity")
    }
}

#[async_trait(?Send)]
impl ValueTransport for MockTransport {
    async fn get_subtree(
        &self,
        path: &ConfigPath,
        _: &Secret,
    ) -> Result<ValueSubTree, ClientError> {
        self.calls
            .borrow_mut()
            .push(format!("get_subtree {}", path.as_str()));
        if let Some(Reply::Fails(kind)) = self.reply(path.as_str()) {
            return Err(ClientError::new(*kind, "bounded"));
        }
        let Some((_, leaves)) = self
            .layers
            .iter()
            .find(|(layer, _)| *layer == path.as_str())
        else {
            return Err(ClientError::new(ErrorKind::NotFound, "bounded"));
        };
        Ok(ValueSubTree {
            values: leaves
                .iter()
                .map(|leaf| SubTreeValue {
                    path: path_of(leaf),
                    value: match self.reply(leaf) {
                        Some(Reply::Plain(value)) => ValueContent::Plain(PlainValue::new(*value)),
                        _ => ValueContent::Secret(MaskedSecret),
                    },
                })
                .collect(),
        })
    }

    async fn reveal_secret(
        &self,
        path: &ConfigPath,
        _: &Secret,
    ) -> Result<RevealedSecret, ClientError> {
        self.calls
            .borrow_mut()
            .push(format!("reveal_secret {}", path.as_str()));
        match self.reply(path.as_str()) {
            Some(Reply::Secret(value)) => Ok(RevealedSecret::new(*value)),
            Some(Reply::Fails(kind)) => Err(ClientError::new(*kind, "bounded")),
            _ => Err(ClientError::new(ErrorKind::NotFound, "bounded")),
        }
    }

    async fn list_values(&self, _: &ConfigPath, _: &Secret) -> Result<ValueListing, ClientError> {
        unreachable!("the reader uses get_subtree, never list_values")
    }

    async fn put_value(
        &self,
        _: &ConfigPath,
        _: &PlainValue,
        _: &Secret,
    ) -> Result<PutMetadata, ClientError> {
        unreachable!("the reader never writes")
    }

    async fn put_secret(
        &self,
        _: &ConfigPath,
        _: &SecretInput,
        _: &Secret,
    ) -> Result<PutMetadata, ClientError> {
        unreachable!("the reader never writes")
    }

    async fn replace_subtree(
        &self,
        _: &ConfigPath,
        _: &[SubTreeMutationValue],
        _: &Secret,
    ) -> Result<ReplaceMetadata, ClientError> {
        unreachable!("the reader never writes")
    }

    async fn delete_values(
        &self,
        _: &ConfigPath,
        _: bool,
        _: &Secret,
    ) -> Result<DeleteMetadata, ClientError> {
        unreachable!("the reader never writes")
    }

    async fn add_value_path(
        &self,
        _: &ConfigPath,
        _: &ConfigPath,
        _: &Secret,
    ) -> Result<AddPathMetadata, ClientError> {
        unreachable!("the reader never writes")
    }

    async fn list_value_paths(
        &self,
        _: &ConfigPath,
        _: &Secret,
    ) -> Result<ValuePaths, ClientError> {
        unreachable!("the reader never lists aliases")
    }
}

/// A path the server produced, so it is parsed with the operation grammar the
/// transport boundary uses.
fn path_of(value: &str) -> ConfigPath {
    ConfigPath::parse_operation(value).unwrap()
}

#[derive(Default)]
struct CountingToken {
    invalidations: RefCell<usize>,
    issued: RefCell<usize>,
}

#[async_trait(?Send)]
impl AccessTokenProvider for CountingToken {
    async fn access_token(&self) -> Result<Option<Secret>, ClientError> {
        *self.issued.borrow_mut() += 1;
        Ok(Some(Secret::new("token-sentinel")))
    }
}

impl InvalidatableToken for CountingToken {
    fn invalidate(&self) {
        *self.invalidations.borrow_mut() += 1;
    }
}

fn reader(
    transport: MockTransport,
    on_missing: OnMissing,
) -> LayerReader<MockTransport, CountingToken> {
    named(transport, on_missing, Naming::AsStored)
}

fn named(
    transport: MockTransport,
    on_missing: OnMissing,
    naming: Naming,
) -> LayerReader<MockTransport, CountingToken> {
    LayerReader::new(transport, CountingToken::default(), on_missing, naming)
}

fn merged(result: &std::collections::BTreeMap<String, RevealedSecret>) -> Vec<(String, String)> {
    result
        .iter()
        .map(|(name, value)| (name.clone(), value.expose().to_owned()))
        .collect()
}

// The point of layering: a later layer overrides an earlier one, and an
// untouched key from the earlier layer survives.
#[tokio::test]
async fn later_layers_win_and_earlier_keys_survive() {
    let transport = MockTransport {
        layers: vec![
            ("/apps/api", vec!["/apps/api/host", "/apps/api/token"]),
            ("/apps/api/prod", vec!["/apps/api/prod/token"]),
        ],
        replies: vec![
            ("/apps/api/host", Reply::Plain("api.example.test")),
            ("/apps/api/token", Reply::Secret("shared-token-sentinel")),
            ("/apps/api/prod/token", Reply::Secret("prod-token-sentinel")),
        ],
        calls: RefCell::new(Vec::new()),
    };
    let reader = reader(transport, OnMissing::Fail);
    let result = reader
        .fetch(&[path("/apps/api"), path("/apps/api/prod")])
        .await
        .unwrap();
    assert_eq!(
        merged(&result),
        vec![
            ("host".to_owned(), "api.example.test".to_owned()),
            ("token".to_owned(), "prod-token-sentinel".to_owned()),
        ]
    );
}

// Reversing the order reverses the winner — the merge is positional, not
// keyed on path depth or specificity.
#[tokio::test]
async fn reversing_the_layer_order_reverses_the_winner() {
    let transport = MockTransport {
        layers: vec![
            ("/apps/api", vec!["/apps/api/token"]),
            ("/apps/api/prod", vec!["/apps/api/prod/token"]),
        ],
        replies: vec![
            ("/apps/api/token", Reply::Secret("shared-token-sentinel")),
            ("/apps/api/prod/token", Reply::Secret("prod-token-sentinel")),
        ],
        calls: RefCell::new(Vec::new()),
    };
    let reader = reader(transport, OnMissing::Fail);
    let result = reader
        .fetch(&[path("/apps/api/prod"), path("/apps/api")])
        .await
        .unwrap();
    assert_eq!(
        merged(&result),
        vec![("token".to_owned(), "shared-token-sentinel".to_owned())]
    );
}

// Only direct children become names; a deeper descendant has no flat
// representation and is dropped rather than mangled.
#[tokio::test]
async fn deeper_descendants_are_not_named() {
    let transport = MockTransport {
        layers: vec![(
            "/apps/api",
            vec!["/apps/api/token", "/apps/api/nested/token"],
        )],
        replies: vec![
            ("/apps/api/token", Reply::Secret("token-sentinel")),
            ("/apps/api/nested/token", Reply::Secret("nested-sentinel")),
        ],
        calls: RefCell::new(Vec::new()),
    };
    let reader = reader(transport, OnMissing::Fail);
    let result = reader.fetch(&[path("/apps/api")]).await.unwrap();
    assert_eq!(
        merged(&result),
        vec![("token".to_owned(), "token-sentinel".to_owned())]
    );
}

// The two consumers diverge here, and that divergence is the whole reason
// the policy is a parameter: the broker serves a short result rather than
// stripping every concurrent pipeline, `render` refuses to launch a deploy
// that would silently be missing configuration.
#[tokio::test]
async fn an_absent_or_denied_layer_follows_the_policy() {
    for (kind, path_spec) in [
        (ErrorKind::NotFound, "/apps/missing"),
        (ErrorKind::PermissionDenied, "/apps/denied"),
    ] {
        let present = || MockTransport {
            layers: vec![("/apps/api", vec!["/apps/api/token"])],
            replies: vec![
                ("/apps/api/token", Reply::Secret("token-sentinel")),
                (
                    if kind == ErrorKind::NotFound {
                        "/apps/missing"
                    } else {
                        "/apps/denied"
                    },
                    Reply::Fails(kind),
                ),
            ],
            calls: RefCell::new(Vec::new()),
        };
        let layers = [path("/apps/api"), path(path_spec)];

        let skipped = reader(present(), OnMissing::Skip)
            .fetch(&layers)
            .await
            .unwrap();
        assert_eq!(
            merged(&skipped),
            vec![("token".to_owned(), "token-sentinel".to_owned())],
            "{kind:?} was not skipped"
        );

        let failed = reader(present(), OnMissing::Fail).fetch(&layers).await;
        assert_eq!(failed.unwrap_err().kind, kind, "{kind:?} did not fail");
    }
}

// A value deleted between the listing and the reveal is a race, so it
// follows the same policy as an absent layer.
#[tokio::test]
async fn a_value_removed_between_listing_and_reveal_follows_the_policy() {
    let racing = || MockTransport {
        layers: vec![("/apps/api", vec!["/apps/api/host", "/apps/api/gone"])],
        replies: vec![
            ("/apps/api/host", Reply::Plain("api.example.test")),
            ("/apps/api/gone", Reply::Fails(ErrorKind::NotFound)),
        ],
        calls: RefCell::new(Vec::new()),
    };
    let layers = [path("/apps/api")];

    let skipped = reader(racing(), OnMissing::Skip)
        .fetch(&layers)
        .await
        .unwrap();
    assert_eq!(
        merged(&skipped),
        vec![("host".to_owned(), "api.example.test".to_owned())]
    );

    assert_eq!(
        reader(racing(), OnMissing::Fail)
            .fetch(&layers)
            .await
            .unwrap_err()
            .kind,
        ErrorKind::NotFound
    );
}

// A denial on one leaf of a readable layer is never a race: the grant does
// not cover what it appears to, and a short result would hide that. It
// fails under either policy.
#[tokio::test]
async fn a_denied_leaf_of_a_readable_layer_fails_under_either_policy() {
    for on_missing in [OnMissing::Skip, OnMissing::Fail] {
        let transport = MockTransport {
            layers: vec![("/apps/api", vec!["/apps/api/token"])],
            replies: vec![("/apps/api/token", Reply::Fails(ErrorKind::PermissionDenied))],
            calls: RefCell::new(Vec::new()),
        };
        assert_eq!(
            reader(transport, on_missing)
                .fetch(&[path("/apps/api")])
                .await
                .unwrap_err()
                .kind,
            ErrorKind::PermissionDenied,
            "{on_missing:?} swallowed a denied leaf"
        );
    }
}

// A token can be revoked before its reported lifetime ends. The reader
// invalidates and retries exactly once rather than replaying a dead token.
#[tokio::test]
async fn a_rejected_token_is_invalidated_and_the_call_retried_once() {
    let transport = MockTransport {
        layers: vec![("/apps/api", vec![])],
        replies: vec![("/apps/api", Reply::Fails(ErrorKind::Unauthenticated))],
        calls: RefCell::new(Vec::new()),
    };
    let reader = named(transport, OnMissing::Fail, Naming::AsStored);
    let error = reader.fetch(&[path("/apps/api")]).await.unwrap_err();
    assert_eq!(error.kind, ErrorKind::Unauthenticated);
    assert_eq!(*reader.tokens.invalidations.borrow(), 1);
    // One token for the first attempt, one for the retry, and no third.
    assert_eq!(*reader.tokens.issued.borrow(), 2);
}

// A plain-classified value arrives in the subtree read itself, so revealing
// it would be a wasted round trip against a value that was never masked.
#[tokio::test]
async fn a_plain_value_is_never_revealed() {
    let transport = MockTransport {
        layers: vec![("/apps/api", vec!["/apps/api/host"])],
        replies: vec![("/apps/api/host", Reply::Plain("api.example.test"))],
        calls: RefCell::new(Vec::new()),
    };
    let reader = reader(transport, OnMissing::Fail);
    reader.fetch(&[path("/apps/api")]).await.unwrap();
    assert_eq!(
        *reader.transport.calls.borrow(),
        vec!["get_subtree /apps/api".to_owned()]
    );
}

// The two consumers want different names for one leaf, and both are right.
// Woodpecker matches a `from_secret:` reference by exact lowercase string, so
// the broker has to fold; an environment variable name is case sensitive, so
// `render` must not. A leaf stored as `/apps/api/AbC` is `abc` to one and
// `AbC` to the other.
#[tokio::test]
async fn the_naming_policy_decides_the_case_a_leaf_is_reported_under() {
    let stored = || MockTransport {
        layers: vec![("/apps/api", vec!["/apps/api/AbC"])],
        replies: vec![("/apps/api/AbC", Reply::Secret("bAr"))],
        calls: RefCell::new(Vec::new()),
    };
    let layers = [path("/apps/api")];

    assert_eq!(
        merged(
            &named(stored(), OnMissing::Fail, Naming::AsStored)
                .fetch(&layers)
                .await
                .unwrap()
        ),
        vec![("AbC".to_owned(), "bAr".to_owned())]
    );
    assert_eq!(
        merged(
            &named(stored(), OnMissing::Fail, Naming::Folded)
                .fetch(&layers)
                .await
                .unwrap()
        ),
        vec![("abc".to_owned(), "bAr".to_owned())]
    );
}

// The naming policy also decides what counts as a collision when layers merge.
// Folding, a per-repo `Github_Token` overrides a shared `github_token`, which
// is what makes layering work at all for Woodpecker. As stored, they are two
// names — and so two environment variables, exactly as they would be to the
// command that receives them.
#[tokio::test]
async fn the_naming_policy_decides_which_layers_collide() {
    let differing_case = || MockTransport {
        layers: vec![
            ("/apps/api", vec!["/apps/api/github_token"]),
            ("/apps/api/prod", vec!["/apps/api/prod/Github_Token"]),
        ],
        replies: vec![
            ("/apps/api/github_token", Reply::Secret("shared-sentinel")),
            (
                "/apps/api/prod/Github_Token",
                Reply::Secret("prod-sentinel"),
            ),
        ],
        calls: RefCell::new(Vec::new()),
    };
    let layers = [path("/apps/api"), path("/apps/api/prod")];

    assert_eq!(
        merged(
            &named(differing_case(), OnMissing::Fail, Naming::Folded)
                .fetch(&layers)
                .await
                .unwrap()
        ),
        vec![("github_token".to_owned(), "prod-sentinel".to_owned())]
    );
    assert_eq!(
        merged(
            &named(differing_case(), OnMissing::Fail, Naming::AsStored)
                .fetch(&layers)
                .await
                .unwrap()
        ),
        vec![
            ("Github_Token".to_owned(), "prod-sentinel".to_owned()),
            ("github_token".to_owned(), "shared-sentinel".to_owned()),
        ]
    );
}
