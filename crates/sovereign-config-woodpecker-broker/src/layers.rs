//! Per-request configuration layers.
//!
//! Woodpecker resolves a pipeline's secrets from an ordered list of paths that
//! depend on the repository being built. The `OpenBao` broker expresses this as
//! Go templates in `SECRET_PATH_TEMPLATES`, e.g.
//!
//! ```text
//! shared/global,woodpecker/global,woodpecker/repos/{{.Repo.FullName}}
//! ```
//!
//! rendered per request against the repo/pipeline metadata in the signed body,
//! read in declared order, and merged so that later paths win on a key
//! collision. This module reproduces that, with three deliberate differences:
//!
//! - Templates are parsed and shape-checked at **startup**, so an unknown
//!   placeholder or a malformed literal fails the process rather than every
//!   request (Go's `missingkey=error` fails per request).
//! - The placeholder set is closed and enumerable rather than arbitrary field
//!   access, so a template can only reach metadata the broker means to expose.
//! - Forge metadata that is not already a canonical path segment is **refused**,
//!   not folded into one. See [`Substitution`]: the rendered path decides whose
//!   secrets a pipeline receives, so a many-to-one mapping is an authorization
//!   bug, not a convenience.
//!
//! Layer specs are relative to the connection root, so a broker rooted at
//! `/woodpecker` with `global,repos/{repo.owner}/{repo.name}` reads
//! `/woodpecker/global` then `/woodpecker/repos/vcheesbrough/sovereign-config`.

use sovereign_config_core::ConfigPath;

use crate::model::SecretsRequest;

/// The metadata a layer template may interpolate.
///
/// Each variant names the JSON field it reads from the signed request body.
/// `repo.forge_id` is `omitempty` on the wire, so it renders as an empty
/// substitution when absent — which skips the layer rather than reading a
/// path with a hole in it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Field {
    RepoOwner,
    RepoName,
    RepoFullName,
    RepoForgeId,
    PipelineBranch,
    PipelineEvent,
}

impl Field {
    fn parse(name: &str) -> Option<Self> {
        match name {
            "repo.owner" => Some(Self::RepoOwner),
            "repo.name" => Some(Self::RepoName),
            "repo.full_name" => Some(Self::RepoFullName),
            "repo.forge_id" => Some(Self::RepoForgeId),
            "pipeline.branch" => Some(Self::PipelineBranch),
            "pipeline.event" => Some(Self::PipelineEvent),
            _ => None,
        }
    }

    /// Resolves this field to path segments.
    ///
    /// `repo.full_name` is the one field spanning two segments; each side is
    /// validated independently so a `/` inside an owner or name cannot forge an
    /// extra level.
    fn render(self, request: &SecretsRequest) -> Substitution {
        let repo = &request.repo;
        match self {
            Self::RepoOwner => Substitution::of(&repo.owner),
            Self::RepoName => Substitution::of(&repo.name),
            Self::RepoFullName => match repo.full_name.split_once('/') {
                Some((owner, name)) => match (Substitution::of(owner), Substitution::of(name)) {
                    (Substitution::Value(owner), Substitution::Value(name)) => {
                        Substitution::Value(format!("{owner}/{name}"))
                    }
                    (Substitution::Absent, _) | (_, Substitution::Absent) => Substitution::Absent,
                    _ => Substitution::Unrepresentable,
                },
                None => Substitution::of(&repo.full_name),
            },
            // Always digits, so always a valid segment.
            Self::RepoForgeId => repo.forge_id.map_or(Substitution::Absent, |id| {
                Substitution::Value(id.to_string())
            }),
            Self::PipelineBranch => Substitution::of(&request.pipeline.branch),
            Self::PipelineEvent => Substitution::of(&request.pipeline.event),
        }
    }
}

/// What a placeholder resolved to for one request.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Substitution {
    /// The forge sent nothing — an ordinary absence, such as a tag pipeline
    /// having no branch. The layer does not apply.
    Absent,
    /// The forge sent something that is not a canonical path segment. The layer
    /// is skipped rather than folded into one, because folding is many-to-one
    /// and the resulting path decides *whose* secrets are returned.
    Unrepresentable,
    Value(String),
}

impl Substitution {
    /// Accepts forge-supplied text only when it is already a canonical path
    /// segment, i.e. `[a-z0-9_-]+`.
    ///
    /// Deliberately does not normalise. Lowercasing or folding punctuation to
    /// `-` would map distinct forge identities onto one path: a branch `Main`
    /// onto `main`, a repository `a.b` onto `a-b`. Because the rendered path
    /// selects which secrets a pipeline receives, a collision hands one
    /// repository's secrets to another. Anything that does not already fit the
    /// grammar fails closed; use `{repo.forge_id}`, which is a stable integer,
    /// where forge names do not map cleanly.
    fn of(value: &str) -> Self {
        if value.is_empty() {
            Self::Absent
        } else if value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        }) {
            Self::Value(value.to_owned())
        } else {
            Self::Unrepresentable
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Segment {
    Literal(String),
    Field(Field),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum LayerError {
    #[error("no layers were configured")]
    Empty,
    #[error("layer {layer:?} has an unbalanced brace")]
    UnbalancedBrace { layer: String },
    #[error("layer {layer:?} uses unknown placeholder {{{placeholder}}}")]
    UnknownPlaceholder { layer: String, placeholder: String },
    #[error("layer {layer:?} must be relative to the connection root")]
    NotRelative { layer: String },
    #[error("layer {layer:?} has a literal segment that is not a valid path segment")]
    InvalidLiteral { layer: String },
}

/// The parsed, startup-validated layer list.
pub(crate) struct LayerTemplates {
    layers: Vec<Vec<Segment>>,
    /// The original spec strings, in declared order. Paths are not secret, so
    /// these are safe to log at startup.
    specs: Vec<String>,
}

impl LayerTemplates {
    /// Parses a comma/newline separated layer spec.
    ///
    /// # Errors
    ///
    /// Fails on an empty spec, an unbalanced brace, an unknown placeholder, an
    /// absolute or dot-segmented layer, or a literal that could never form a
    /// valid path segment.
    pub(crate) fn parse(spec: &str) -> Result<Self, LayerError> {
        let mut layers = Vec::new();
        let mut specs = Vec::new();
        for raw in spec.split([',', '\n', '\r']) {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            layers.push(parse_layer(raw)?);
            specs.push(raw.to_owned());
        }
        if layers.is_empty() {
            return Err(LayerError::Empty);
        }
        Ok(Self { layers, specs })
    }

    pub(crate) fn specs(&self) -> &[String] {
        &self.specs
    }

    /// Renders every layer under `root`, in declared order.
    ///
    /// A layer whose substitutions leave it empty or unrepresentable is
    /// **skipped**, not an error: an absent branch or forge id simply means
    /// that layer does not apply to this request, exactly as an absent path in
    /// the store does.
    pub(crate) fn render(&self, root: &ConfigPath, request: &SecretsRequest) -> Vec<ConfigPath> {
        let mut rendered = Vec::with_capacity(self.layers.len());
        for (layer, spec) in self.layers.iter().zip(&self.specs) {
            let mut relative = String::new();
            let mut usable = true;
            for segment in layer {
                match segment {
                    Segment::Literal(literal) => relative.push_str(literal),
                    Segment::Field(field) => match field.render(request) {
                        Substitution::Value(value) => relative.push_str(&value),
                        Substitution::Absent => {
                            // Ordinary: a tag pipeline has no branch.
                            tracing::debug!(
                                layer = %spec,
                                "layer skipped: no value for a placeholder"
                            );
                            usable = false;
                            break;
                        }
                        Substitution::Unrepresentable => {
                            // Not ordinary: the forge sent something real that
                            // cannot be a path segment. Loud, because the
                            // pipeline will silently run without these secrets
                            // and the fix is to use `{repo.forge_id}` or rename.
                            tracing::warn!(
                                layer = %spec,
                                "layer skipped: a placeholder value is not a valid path segment"
                            );
                            usable = false;
                            break;
                        }
                    },
                }
            }
            if !usable {
                continue;
            }
            let absolute = if root.as_str() == "/" {
                format!("/{relative}")
            } else {
                format!("{}/{relative}", root.as_str())
            };
            match ConfigPath::parse_operation(&absolute) {
                Ok(path) => rendered.push(path),
                Err(_) => {
                    tracing::debug!(layer = %spec, "layer skipped: not a canonical path");
                }
            }
        }
        rendered
    }
}

fn parse_layer(raw: &str) -> Result<Vec<Segment>, LayerError> {
    if raw.starts_with('/') || raw.split('/').any(|part| part == "." || part == "..") {
        return Err(LayerError::NotRelative {
            layer: raw.to_owned(),
        });
    }

    let mut segments = Vec::new();
    let mut literal = String::new();
    let mut rest = raw;
    while let Some(open) = rest.find('{') {
        literal.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let close = after.find('}').ok_or_else(|| LayerError::UnbalancedBrace {
            layer: raw.to_owned(),
        })?;
        let placeholder = &after[..close];
        let field = Field::parse(placeholder).ok_or_else(|| LayerError::UnknownPlaceholder {
            layer: raw.to_owned(),
            placeholder: placeholder.to_owned(),
        })?;
        if !literal.is_empty() {
            segments.push(Segment::Literal(std::mem::take(&mut literal)));
        }
        segments.push(Segment::Field(field));
        rest = &after[close + 1..];
    }
    if rest.contains('}') {
        return Err(LayerError::UnbalancedBrace {
            layer: raw.to_owned(),
        });
    }
    literal.push_str(rest);
    if !literal.is_empty() {
        segments.push(Segment::Literal(literal));
    }

    // Validate the layer's shape at startup, whether or not it is templated.
    // Substituting a stand-in segment for each placeholder reduces the layer to
    // a concrete path, so the real validator catches a bad literal (`repos.bad`)
    // or an empty segment (`repos//`) even when a placeholder follows it.
    //
    // Doing this only for all-literal layers would leave the templated layers —
    // the ones carrying the per-repo secrets — unchecked: every render would
    // fail `parse_operation`, the layer would be skipped, and the pipeline would
    // see a silently short result rather than a boot failure.
    let probe: String = segments
        .iter()
        .map(|segment| match segment {
            Segment::Literal(literal) => literal.as_str(),
            Segment::Field(_) => FIELD_PROBE,
        })
        .collect();
    if ConfigPath::parse_operation(format!("/{probe}")).is_err() {
        return Err(LayerError::InvalidLiteral {
            layer: raw.to_owned(),
        });
    }

    Ok(segments)
}

/// Stands in for a placeholder when validating a layer's shape at startup.
/// Any single valid segment character will do; what is being checked is the
/// literal text and the segment structure around it, not the substitution.
const FIELD_PROBE: &str = "x";

#[cfg(test)]
mod tests {
    use sovereign_config_core::ConfigPath;

    use super::{LayerError, LayerTemplates, Substitution};
    use crate::model::{Pipeline, Repo, SecretsRequest};

    fn request(owner: &str, name: &str, branch: &str, event: &str) -> SecretsRequest {
        SecretsRequest {
            repo: Repo {
                owner: owner.to_owned(),
                name: name.to_owned(),
                full_name: format!("{owner}/{name}"),
                forge_id: Some(7),
            },
            pipeline: Pipeline {
                branch: branch.to_owned(),
                event: event.to_owned(),
            },
        }
    }

    fn render(spec: &str, root: &str, request: &SecretsRequest) -> Vec<String> {
        LayerTemplates::parse(spec)
            .unwrap()
            .render(&ConfigPath::parse(root).unwrap(), request)
            .into_iter()
            .map(|path| path.as_str().to_owned())
            .collect()
    }

    // The behaviour the live `OpenBao` broker provides today, path for path.
    #[test]
    fn the_live_layer_spec_resolves_per_repository() {
        let spec = "shared/global,global,repos/{repo.owner}/{repo.name}";
        assert_eq!(
            render(
                spec,
                "/woodpecker",
                &request("vcheesbrough", "sovereign-config", "main", "push")
            ),
            vec![
                "/woodpecker/shared/global",
                "/woodpecker/global",
                "/woodpecker/repos/vcheesbrough/sovereign-config",
            ]
        );
        // A different repository resolves a different per-repo layer while the
        // shared layers stay put.
        assert_eq!(
            render(
                spec,
                "/woodpecker",
                &request("vcheesbrough", "bored", "main", "push")
            ),
            vec![
                "/woodpecker/shared/global",
                "/woodpecker/global",
                "/woodpecker/repos/vcheesbrough/bored",
            ]
        );
    }

    #[test]
    fn full_name_spans_two_segments() {
        assert_eq!(
            render(
                "repos/{repo.full_name}",
                "/woodpecker",
                &request("vcheesbrough", "sovereign-config", "main", "push")
            ),
            vec!["/woodpecker/repos/vcheesbrough/sovereign-config"]
        );
    }

    #[test]
    fn branch_and_event_interpolate() {
        assert_eq!(
            render(
                "branches/{pipeline.branch},events/{pipeline.event}",
                "/woodpecker",
                &request("owner", "repo", "feature-new-thing", "pull_request")
            ),
            vec![
                "/woodpecker/branches/feature-new-thing",
                "/woodpecker/events/pull_request",
            ]
        );
        // A branch containing `/` is refused, not flattened onto a sibling that
        // really is named `feature-x`. The event layer still resolves.
        assert_eq!(
            render(
                "branches/{pipeline.branch},events/{pipeline.event}",
                "/woodpecker",
                &request("owner", "repo", "feature/x", "pull_request")
            ),
            vec!["/woodpecker/events/pull_request"]
        );
    }

    #[test]
    fn a_root_of_slash_still_produces_absolute_paths() {
        assert_eq!(
            render("global", "/", &request("owner", "repo", "main", "push")),
            vec!["/global"]
        );
    }

    #[test]
    fn a_layer_with_no_value_for_a_placeholder_is_skipped_not_failed() {
        // A tag pipeline carries no branch; that layer simply does not apply.
        let rendered = render(
            "global,branches/{pipeline.branch}",
            "/woodpecker",
            &request("owner", "repo", "", "tag"),
        );
        assert_eq!(rendered, vec!["/woodpecker/global"]);

        let mut absent_forge = request("owner", "repo", "main", "push");
        absent_forge.repo.forge_id = None;
        assert_eq!(
            render("forges/{repo.forge_id}", "/woodpecker", &absent_forge),
            Vec::<String>::new()
        );
    }

    // Folding punctuation to `-` would be many-to-one, and the rendered path is
    // what decides whose secrets are returned. Anything that is not already a
    // valid segment is refused outright rather than mangled into one.
    #[test]
    fn forge_metadata_that_is_not_a_valid_segment_is_refused_not_folded() {
        let hostile = SecretsRequest {
            repo: Repo {
                owner: "../../etc".to_owned(),
                name: "pass wd".to_owned(),
                full_name: "../../etc/pass wd".to_owned(),
                forge_id: Some(1),
            },
            pipeline: Pipeline {
                branch: "main".to_owned(),
                event: "push".to_owned(),
            },
        };
        for spec in ["repos/{repo.owner}/{repo.name}", "repos/{repo.full_name}"] {
            assert_eq!(
                render(spec, "/woodpecker", &hostile),
                Vec::<String>::new(),
                "{spec} did not refuse hostile metadata"
            );
        }
        // `forge_id` is a stable integer, so it always resolves — the documented
        // escape hatch for a forge name that cannot be a path segment.
        assert_eq!(
            render("forges/{repo.forge_id}", "/woodpecker", &hostile),
            vec!["/woodpecker/forges/1"]
        );
    }

    // The collision the refusal exists to prevent: distinct forge identities
    // must never resolve to the same layer.
    #[test]
    fn names_that_would_collide_when_folded_are_refused() {
        for (owner, name) in [
            ("vcheesbrough", "sovereign.config"),
            ("vcheesbrough", "Sovereign-Config"),
            ("VCheesbrough", "sovereign-config"),
        ] {
            assert_eq!(
                render(
                    "repos/{repo.owner}/{repo.name}",
                    "/woodpecker",
                    &request(owner, name, "main", "push")
                ),
                Vec::<String>::new(),
                "{owner}/{name} was accepted and could collide"
            );
        }
        // A branch `Main` must not resolve onto the `main` layer.
        assert_eq!(
            render(
                "branches/{pipeline.branch}",
                "/woodpecker",
                &request("o", "r", "Main", "push")
            ),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_well_formed_full_name_resolves_to_two_segments() {
        assert_eq!(
            render(
                "repos/{repo.full_name}",
                "/woodpecker",
                &request("vcheesbrough", "sovereign-config", "main", "push")
            ),
            vec!["/woodpecker/repos/vcheesbrough/sovereign-config"]
        );
    }

    #[test]
    fn a_substitution_is_accepted_only_when_it_is_already_a_segment() {
        assert_eq!(
            Substitution::of("github_token"),
            Substitution::Value("github_token".to_owned())
        );
        assert_eq!(
            Substitution::of("sovereign-config"),
            Substitution::Value("sovereign-config".to_owned())
        );
        assert_eq!(Substitution::of(""), Substitution::Absent);
        // `-` alone is a legal segment, so it passes through unchanged; nothing
        // is folded onto it.
        assert_eq!(Substitution::of("-"), Substitution::Value("-".to_owned()));
        for refused in ["Main", "a.b", "a b", "a/b", "caf\u{e9}", "a+b"] {
            assert_eq!(
                Substitution::of(refused),
                Substitution::Unrepresentable,
                "accepted {refused:?}"
            );
        }
    }

    #[test]
    fn templates_are_validated_at_parse_time() {
        assert!(matches!(
            LayerTemplates::parse("repos/{repo.nickname}"),
            Err(LayerError::UnknownPlaceholder { .. })
        ));
        assert!(matches!(
            LayerTemplates::parse("repos/{repo.owner"),
            Err(LayerError::UnbalancedBrace { .. })
        ));
        assert!(matches!(
            LayerTemplates::parse("repos/repo.owner}"),
            Err(LayerError::UnbalancedBrace { .. })
        ));
        assert!(matches!(
            LayerTemplates::parse("/absolute"),
            Err(LayerError::NotRelative { .. })
        ));
        assert!(matches!(
            LayerTemplates::parse("../escape"),
            Err(LayerError::NotRelative { .. })
        ));
        assert!(matches!(
            LayerTemplates::parse("bad.literal"),
            Err(LayerError::InvalidLiteral { .. })
        ));
        // A templated layer's literal text is validated too. Without this, the
        // layer carrying the per-repo secrets would boot fine and then be
        // skipped on every request, which Woodpecker reports as no secrets
        // rather than as an error.
        for templated in [
            "repos.bad/{repo.name}",
            "repos//{repo.name}",
            "{repo.owner}/bad.name",
            "{repo.owner}//{repo.name}",
            "repos/{repo.owner} {repo.name}",
        ] {
            assert!(
                matches!(
                    LayerTemplates::parse(templated),
                    Err(LayerError::InvalidLiteral { .. })
                ),
                "accepted {templated:?}"
            );
        }
        // Legitimate shapes still parse, including a placeholder sharing a
        // segment with literal text.
        for valid in [
            "global",
            "repos/{repo.owner}/{repo.name}",
            "{repo.full_name}",
            "repo-{repo.name}",
            "shared/global",
        ] {
            assert!(LayerTemplates::parse(valid).is_ok(), "rejected {valid:?}");
        }
        assert!(matches!(
            LayerTemplates::parse("  "),
            Err(LayerError::Empty)
        ));
    }

    #[test]
    fn commas_and_newlines_both_separate_layers() {
        let spec = "shared/global\nglobal,repos/{repo.owner}/{repo.name}\r\n";
        let templates = LayerTemplates::parse(spec).unwrap();
        assert_eq!(
            templates.specs(),
            ["shared/global", "global", "repos/{repo.owner}/{repo.name}"]
        );
    }
}
