//! Guards the documentation set (bored card #479).
//!
//! The README is written for someone running Sovereign Config, and the
//! reference material, development workflow and the project's own
//! infrastructure live under `docs/`. Splitting one document into many turns
//! every cross-reference into a link that can rot, so every relative link and
//! anchor is checked here; and the README is kept free of the project's own
//! deployment, which is what it had drifted into before.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every Markdown document a reader is pointed at: the README, `docs/`, and
/// each crate's own README.
fn documents() -> Vec<PathBuf> {
    let root = workspace_root();
    let mut documents = vec![root.join("README.md")];
    for dir in ["docs", "crates"] {
        for entry in fs::read_dir(root.join(dir)).expect("read documentation dir") {
            let path = entry.expect("read dir entry").path();
            if path.extension().is_some_and(|ext| ext == "md") {
                documents.push(path);
            } else if path.join("README.md").is_file() {
                documents.push(path.join("README.md"));
            }
        }
    }
    documents
}

/// The lines outside fenced code blocks, where links and headings are prose.
fn prose_lines(text: &str) -> Vec<&str> {
    let mut in_fence = false;
    text.lines()
        .filter(|line| {
            if line.trim_start().starts_with("```") {
                in_fence = !in_fence;
                return false;
            }
            !in_fence
        })
        .collect()
}

/// GitHub's anchor for a heading: lowercased, punctuation dropped, spaces to
/// hyphens, and a `-N` suffix on the Nth repeat.
fn anchors(text: &str) -> Vec<String> {
    let mut seen: HashMap<String, usize> = HashMap::new();
    prose_lines(text)
        .into_iter()
        .filter(|line| line.starts_with('#'))
        .filter_map(|line| line.trim_start_matches('#').strip_prefix(' '))
        .map(|heading| {
            let slug: String = heading
                .chars()
                .filter_map(|c| match c {
                    ' ' => Some('-'),
                    '-' | '_' => Some(c),
                    c if c.is_alphanumeric() => Some(c.to_ascii_lowercase()),
                    _ => None,
                })
                .collect();
            let count = seen.entry(slug.clone()).or_insert(0);
            let anchor = if *count == 0 {
                slug
            } else {
                format!("{slug}-{count}")
            };
            *count += 1;
            anchor
        })
        .collect()
}

/// Every inline link target `](target)` in the document's prose.
fn link_targets(text: &str) -> Vec<String> {
    prose_lines(text)
        .into_iter()
        .flat_map(|line| line.split("](").skip(1))
        .filter_map(|rest| rest.split_once(')').map(|(target, _)| target.to_owned()))
        .collect()
}

#[test]
fn every_relative_link_and_anchor_resolves() {
    let mut broken = Vec::new();
    for document in documents() {
        let text = fs::read_to_string(&document).expect("read document");
        for target in link_targets(&text) {
            if target.contains("://") || target.starts_with("mailto:") {
                continue;
            }
            let (file, anchor) = target.split_once('#').unwrap_or((&target, ""));
            let linked = if file.is_empty() {
                document.clone()
            } else {
                document.parent().expect("document dir").join(file)
            };
            if !linked.exists() {
                broken.push(format!("{}: {target} (no such file)", document.display()));
                continue;
            }
            if !anchor.is_empty() {
                let linked_text = fs::read_to_string(&linked).expect("read linked document");
                if !anchors(&linked_text).iter().any(|known| known == anchor) {
                    broken.push(format!(
                        "{}: {target} (no such heading)",
                        document.display()
                    ));
                }
            }
        }
    }
    assert!(
        broken.is_empty(),
        "broken documentation links:\n{}",
        broken.join("\n")
    );
}

#[test]
fn the_readme_leaves_the_projects_own_deployment_to_its_own_document() {
    let readme = fs::read_to_string(workspace_root().join("README.md")).expect("read README");
    for specific in [
        "monitor-alloy",
        "sovereign_config_prod_postgres_password",
        ".woodpecker/deploy",
        "sovereign-config-dev.desync.link",
        "auth.desync.link",
    ] {
        assert!(
            !readme.contains(specific),
            "README names the project's own infrastructure ({specific}); it belongs in docs/project-deployment.md"
        );
    }
    assert!(readme.contains("docs/project-deployment.md"));
}

#[test]
fn anchors_follow_githubs_rules() {
    let text = "# Title\n## 2.15.0 widens the `path` grammar\n### Production — `authentik/blueprint.yaml`\n## Title\n```sh\n# not a heading\n```\n";
    assert_eq!(
        anchors(text),
        [
            "title",
            "2150-widens-the-path-grammar",
            "production--authentikblueprintyaml",
            "title-1",
        ]
    );
}
