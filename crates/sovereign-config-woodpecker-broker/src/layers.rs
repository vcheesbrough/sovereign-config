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
//! collision. This module reproduces that, with two deliberate differences:
//!
//! - Templates are parsed at **startup**, so an unknown placeholder fails the
//!   process rather than every request (Go's `missingkey=error` fails per
//!   request).
//! - The placeholder set is closed and enumerable rather than arbitrary field
//!   access, so a template can only reach metadata the broker means to expose.
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

    /// Renders this field, already sanitised into path segments.
    ///
    /// `repo.full_name` is the one field that spans two segments; each side is
    /// sanitised independently so a `/` inside an owner or name cannot forge an
    /// extra level.
    fn render(self, request: &SecretsRequest) -> String {
        let repo = &request.repo;
        match self {
            Self::RepoOwner => sanitize(&repo.owner),
            Self::RepoName => sanitize(&repo.name),
            Self::RepoFullName => match repo.full_name.split_once('/') {
                Some((owner, name)) => {
                    let (owner, name) = (sanitize(owner), sanitize(name));
                    if owner.is_empty() || name.is_empty() {
                        String::new()
                    } else {
                        format!("{owner}/{name}")
                    }
                }
                None => sanitize(&repo.full_name),
            },
            Self::RepoForgeId => repo.forge_id.map(|id| id.to_string()).unwrap_or_default(),
            Self::PipelineBranch => sanitize(&request.pipeline.branch),
            Self::PipelineEvent => sanitize(&request.pipeline.event),
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
                    Segment::Field(field) => {
                        let value = field.render(request);
                        if value.is_empty() {
                            usable = false;
                            break;
                        }
                        relative.push_str(&value);
                    }
                }
            }
            if !usable {
                tracing::debug!(layer = %spec, "layer skipped: no value for a placeholder");
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

    // A layer of pure literals must already be a valid relative path; catching
    // that at startup turns a permanent typo into a boot failure instead of a
    // silently skipped layer on every request.
    if segments
        .iter()
        .all(|segment| matches!(segment, Segment::Literal(_)))
    {
        let joined: String = segments
            .iter()
            .map(|segment| match segment {
                Segment::Literal(literal) => literal.as_str(),
                Segment::Field(_) => unreachable!("checked above"),
            })
            .collect();
        if ConfigPath::parse_operation(format!("/{joined}")).is_err() {
            return Err(LayerError::InvalidLiteral {
                layer: raw.to_owned(),
            });
        }
    }

    Ok(segments)
}

/// Reduces forge-supplied text to a path segment.
///
/// Lowercases, maps anything outside `[a-z0-9_-]` to `-`, collapses runs, and
/// trims the ends. An input that reduces to nothing yields an empty string,
/// which the caller treats as "skip this layer".
fn sanitize(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        let lower = character.to_ascii_lowercase();
        if lower.is_ascii_lowercase() || lower.is_ascii_digit() || lower == '_' {
            out.push(lower);
        } else if !out.is_empty() && !out.ends_with('-') {
            // Fold every other character, including `/` and `.`, to a single
            // separator so forge metadata can never introduce a path level.
            // Leading separators are dropped rather than folded, so a segment
            // can never begin with `-`.
            out.push('-');
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

#[cfg(test)]
mod tests {
    use sovereign_config_core::ConfigPath;

    use super::{LayerError, LayerTemplates, sanitize};
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
                &request("owner", "repo", "feature/new-thing", "pull_request")
            ),
            vec![
                "/woodpecker/branches/feature-new-thing",
                "/woodpecker/events/pull_request",
            ]
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

    #[test]
    fn forge_metadata_cannot_introduce_a_path_level_or_escape_the_root() {
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
        // Separate fields fold to one segment each: the traversal is gone and
        // the result is still confined under the root.
        assert_eq!(
            render("repos/{repo.owner}/{repo.name}", "/woodpecker", &hostile),
            vec!["/woodpecker/repos/etc/pass-wd"]
        );
        // `full_name` splits at the first `/`, so a hostile value leaves an
        // owner component that sanitises to nothing. The layer is skipped
        // rather than reinterpreted — fail closed, not fold into something
        // plausible.
        assert_eq!(
            render("repos/{repo.full_name}", "/woodpecker", &hostile),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_well_formed_full_name_still_resolves_after_sanitising() {
        let request = SecretsRequest {
            repo: Repo {
                owner: "VCheesbrough".to_owned(),
                name: "Sovereign Config".to_owned(),
                full_name: "VCheesbrough/Sovereign Config".to_owned(),
                forge_id: Some(1),
            },
            pipeline: Pipeline {
                branch: "main".to_owned(),
                event: "push".to_owned(),
            },
        };
        assert_eq!(
            render("repos/{repo.full_name}", "/woodpecker", &request),
            vec!["/woodpecker/repos/vcheesbrough/sovereign-config"]
        );
    }

    #[test]
    fn underscored_names_survive_sanitising() {
        assert_eq!(sanitize("GitHub_Token"), "github_token");
        assert_eq!(sanitize("zot_ci_user"), "zot_ci_user");
        assert_eq!(sanitize("a..b"), "a-b");
        assert_eq!(sanitize("--lead-and-trail--"), "lead-and-trail");
        assert_eq!(sanitize("///"), "");
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
