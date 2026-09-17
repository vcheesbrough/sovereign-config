//! The sidebar configuration tree: building the fully expanded node list,
//! drawing guides, and keyboard/mouse actions.

use sovereign_config_core::{ClientError, ConfigPath};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use web_sys::{Document, Element, Event, KeyboardEvent, window};

use crate::browser::{app_config, browser_error};
use crate::connections::{CONNECTIONS, render_path_connections};
use crate::dom::{append, create_element, current_text, focus, set_text, show_error};
use crate::icons::{Icon, icon_svg};
use crate::route::{Route, guarded_navigate, route_from_location};
use crate::session::logged_in;
use crate::transport::value_client;

thread_local! {
    pub(crate) static TREE_LOAD_GENERATION: Cell<u64> = const { Cell::new(0) };
    pub(crate) static TREE_NODES: RefCell<Vec<TreeNode>> = const { RefCell::new(Vec::new()) };
}

/// One row of the sidebar configuration tree. The tree is always rendered fully
/// expanded, so a node carries its depth rather than a list of children.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TreeNode {
    pub(crate) path: ConfigPath,
    /// The label to render: the last segment of whichever display form this
    /// namespace was established with, `/` for the tree root. `path` itself
    /// stays fold-only — it is what `data-path` round-trips and what every
    /// lookup against `has_values`/`has_connection` compares.
    pub(crate) display: String,
    pub(crate) depth: usize,
    /// This namespace directly holds at least one value — rendered bold.
    pub(crate) has_values: bool,
    /// An access URL is rooted at exactly this path — rendered with a key.
    pub(crate) has_connection: bool,
}

pub(crate) fn path_segments(path: &str) -> Vec<&str> {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .collect()
}

/// The namespace holding `path`, or the root for a top-level value.
///
/// Splits on the fold, never `as_str()` (display): `ConfigPath::parse` only
/// accepts lowercase text, so splitting on display case would fail (and
/// silently collapse to root via `.ok()`) for any mixed-case path.
pub(crate) fn parent_of(path: &ConfigPath) -> ConfigPath {
    let fold = path.fold();
    fold.rsplit_once('/')
        .filter(|(parent, _)| !parent.is_empty())
        .and_then(|(parent, _)| ConfigPath::parse(parent).ok())
        .unwrap_or_else(ConfigPath::root)
}

/// The parent of `path`, in both forms. Byte offsets align between the fold
/// key and the display form because letter case never changes a segment's
/// length — `path.fold()` and `path.as_str()` always split at the same
/// boundary.
pub(crate) fn parent_forms(path: &ConfigPath) -> (String, String) {
    let fold = path.fold();
    match fold.rsplit_once('/') {
        Some((parent, _)) if !parent.is_empty() => {
            let boundary = parent.len();
            (parent.to_owned(), path.as_str()[..boundary].to_owned())
        }
        _ => ("/".to_owned(), "/".to_owned()),
    }
}

/// The namespace labels a set of value paths implies: each value's parent and
/// every ancestor of that parent, plus the tree root — keyed by fold, mapped
/// to the display form contributed by whichever value path is fold-smallest
/// under it.
///
/// This deliberately mirrors the server's own derivation of `ListValues.paths`
/// (`add_parent_paths` in `sovereign-config-server`), except for the
/// tie-break: `GetSubTree` carries no creation timestamp, so "whichever row
/// was created first" — the rule the server uses — is not available here, and
/// the fold-smallest contributing path is used instead. Both rules are
/// deterministic; they can disagree only when two differently-cased writes
/// share an ancestor, which is purely a label choice with no effect on stored
/// data.
pub(crate) fn namespace_labels(value_paths: &[ConfigPath]) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert("/".to_owned(), "/".to_owned());
    let mut sorted = value_paths.iter().collect::<Vec<_>>();
    sorted.sort_by_key(|path| path.fold());
    for path in sorted {
        let (fold_parent, display_parent) = parent_forms(path);
        if fold_parent == "/" {
            continue;
        }
        let fold_segments = path_segments(&fold_parent);
        let display_segments = path_segments(&display_parent);
        let mut fold_prefix = String::new();
        let mut display_prefix = String::new();
        for index in 0..fold_segments.len() {
            fold_prefix.push('/');
            fold_prefix.push_str(fold_segments[index]);
            display_prefix.push('/');
            display_prefix.push_str(display_segments[index]);
            labels
                .entry(fold_prefix.clone())
                .or_insert_with(|| display_prefix.clone());
        }
    }
    labels
}

/// The namespaces that directly hold at least one value. `ListValues.paths`
/// cannot answer this — it reports ancestors, which include namespaces holding
/// nothing but children — so it is derived from whole-tree value paths instead.
pub(crate) fn value_parents_of(value_paths: &[ConfigPath]) -> BTreeSet<String> {
    value_paths
        .iter()
        .map(|path| parent_of(path).as_str().to_owned())
        .collect()
}

/// Orders namespaces depth-first and decorates each with its sidebar markers.
///
/// Ordering compares segments rather than whole strings: `-` sorts before `/`,
/// so a raw string sort would place `/a-b` between `/a` and `/a/b` and split a
/// subtree in two.
pub(crate) fn build_tree(
    labels: &BTreeMap<String, String>,
    value_parents: &BTreeSet<String>,
    connection_roots: &BTreeSet<String>,
) -> Vec<TreeNode> {
    let mut ordered = labels.keys().cloned().collect::<Vec<_>>();
    ordered.sort_by(|left, right| path_segments(left).cmp(&path_segments(right)));
    ordered
        .into_iter()
        .filter_map(|fold| {
            let depth = path_segments(&fold).len();
            let display = labels.get(&fold).map_or(fold.as_str(), String::as_str);
            let label = display
                .rsplit('/')
                .next()
                .filter(|segment| !segment.is_empty())
                .unwrap_or("/")
                .to_owned();
            let path = ConfigPath::parse(fold).ok()?;
            Some(TreeNode {
                has_values: value_parents.contains(path.as_str()),
                has_connection: connection_roots.contains(path.as_str()),
                depth,
                display: label,
                path,
            })
        })
        .collect()
}

/// The path the tree currently highlights, or `None` off the Configuration
/// route.
pub(crate) fn selected_tree_path() -> Option<ConfigPath> {
    match route_from_location() {
        Route::Configuration(path) => Some(path),
        Route::Connections | Route::Downloads => None,
    }
}

/// Reads the whole readable configuration once per load so the sidebar can
/// render the full namespace tree and mark the namespaces that directly hold
/// values.
///
/// `ListValues.paths` already carries the namespace tree, but only as
/// *ancestors*, which cannot distinguish a namespace holding values from one
/// holding nothing but children. `GetSubTree` on the root answers that exactly;
/// a principal scoped to a prefix is refused there, so the namespace list is the
/// documented fallback and the tree simply renders without bold markers.
pub(crate) async fn load_tree() {
    let generation = TREE_LOAD_GENERATION.get().wrapping_add(1);
    TREE_LOAD_GENERATION.set(generation);
    if !logged_in() {
        CONNECTIONS.with_borrow_mut(Vec::clear);
        TREE_NODES.with_borrow_mut(Vec::clear);
        let _ = render_tree(&[]);
        render_path_connections();
        set_text("config-tree-state", "Log in to browse");
        return;
    }
    let Ok(config) = app_config() else {
        set_text("config-tree-state", "Tree unavailable");
        return;
    };
    // `#config-tree-state` is a live region, and the tree reloads on every
    // navigation. Announcing "Loading" each time would narrate an ambient count
    // the operator did not ask about, so only say it when there is nothing on
    // screen yet to reload.
    if TREE_NODES.with_borrow(Vec::is_empty) {
        set_text("config-tree-state", "Loading");
    }
    let selected = selected_tree_path().unwrap_or_else(ConfigPath::root);
    // A connection listing failure must not cost the operator the whole tree,
    // but it must not be reported as an empty estate either: an authoritative
    // "0 connections" at a path that actually has one invites minting a second,
    // redundant credential. Keep the last good listing and say it is stale.
    let listed = value_client(&config).list_managed_connections().await.ok();
    let model = match value_client(&config).get_subtree(&ConfigPath::root()).await {
        Ok(subtree) => {
            let paths = subtree
                .values
                .into_iter()
                .map(|value| value.path)
                .collect::<Vec<_>>();
            Some((namespace_labels(&paths), value_parents_of(&paths)))
        }
        Err(_) => value_client(&config)
            .list_values(&selected)
            .await
            .ok()
            .map(|listing| {
                // `listing.paths` already carries the server's display form for
                // each namespace (its first-created row's case), so this is a
                // direct copy, not a re-derivation.
                let mut labels = listing
                    .paths
                    .iter()
                    .map(|path| (path.fold(), path.as_str().to_owned()))
                    .collect::<BTreeMap<_, _>>();
                labels.insert("/".to_owned(), "/".to_owned());
                (labels, BTreeSet::new())
            }),
    };
    if TREE_LOAD_GENERATION.get() != generation {
        return;
    }
    let listed_failed = listed.is_none();
    if let Some(connections) = listed {
        CONNECTIONS.with_borrow_mut(|slot| *slot = connections);
    }
    let roots = CONNECTIONS.with_borrow(|connections| {
        connections
            .iter()
            .map(|connection| connection.root.as_str().to_owned())
            .collect::<BTreeSet<_>>()
    });
    render_path_connections();
    if listed_failed {
        set_text("path-connection-count", "Access URLs unavailable");
    }
    let Some((labels, value_parents)) = model else {
        set_text("config-tree-state", "Tree unavailable");
        return;
    };
    let nodes = build_tree(&labels, &value_parents, &roots);
    let count = nodes.len();
    TREE_NODES.with_borrow_mut(|slot| slot.clone_from(&nodes));
    if let Err(error) = render_tree(&nodes) {
        show_error(error.message());
        return;
    }
    // Only write the count when it actually changed, so an unchanged tree does
    // not re-announce itself after every click.
    let summary = format!("{count} path{}", if count == 1 { "" } else { "s" });
    if current_text("config-tree-state").as_deref() != Some(summary.as_str()) {
        set_text("config-tree-state", &summary);
    }
}

pub(crate) fn render_tree(nodes: &[TreeNode]) -> Result<(), ClientError> {
    let document = window()
        .and_then(|window| window.document())
        .ok_or_else(browser_error)?;
    let tree = document
        .get_element_by_id("config-tree")
        .ok_or_else(browser_error)?;
    // Rebuilding replaces every node, including whichever one holds focus.
    // Activating a node navigates and re-renders, and the tree reloads
    // asynchronously as well, so without this a keyboard user is dropped onto
    // `<body>` mid-interaction and has to tab all the way back in.
    let had_focus = document
        .active_element()
        .is_some_and(|active| tree.contains(Some(&active)));
    tree.set_text_content(None);
    let selected = selected_tree_path();
    let selected_index = nodes
        .iter()
        .position(|node| selected.as_ref() == Some(&node.path));
    // Exactly one node is ever in the tab order; without a selection that is the
    // root, which is also the node the Configuration view opens on.
    let focus_index = selected_index.or_else(|| (!nodes.is_empty()).then_some(0));
    // `tree_guides` returns exactly one row per node (pinned by
    // `tree_guides_handle_the_empty_and_root_only_cases` and its neighbours
    // below), so `guides[index]` never runs past the end here — kept as a
    // direct index rather than a defensive `.get` because that invariant is
    // structural, not incidental: every push onto `guides` happens in the same
    // loop, over the same `nodes`, with no branch that skips one.
    let guides = tree_guides(nodes);
    for (index, node) in nodes.iter().enumerate() {
        // Preorder ordering means a node has children exactly when the next one
        // is deeper. The tree never collapses, so parents are always expanded.
        let has_children = nodes
            .get(index + 1)
            .is_some_and(|next| next.depth > node.depth);
        let item = build_tree_node(
            &document,
            node,
            index,
            Some(index) == selected_index,
            has_children,
            &guides[index],
        )?;
        item.set_attribute(
            "tabindex",
            if Some(index) == focus_index {
                "0"
            } else {
                "-1"
            },
        )
        .map_err(|_| browser_error())?;
        append(&tree, &item)?;
    }
    if had_focus && let Some(index) = focus_index {
        focus(&format!("tree-node-{index}"));
    }
    Ok(())
}

/// One cell of a node's ancestry column, one per level of depth.
///
/// These were box-drawing characters until the joins gave them away: a glyph
/// only paints inside its own line box, so a trunk assembled from `\u{2502}`
/// breaks at every row boundary by however much the row exceeds the font's em
/// box — and by how much depended on whichever monospace font the browser had
/// resolved. Each cell is now an empty span, and CSS rules it with a line
/// stretched across the whole row, so consecutive trunks meet exactly.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum TreeGuide {
    /// An ancestor whose last child has already been drawn: nothing here.
    Blank,
    /// An ancestor with siblings still to come: a trunk through the whole row.
    Trunk,
    /// This node, with siblings after it: trunk through, elbow out.
    Branch,
    /// This node, the last of its siblings: the trunk ends at the elbow.
    Corner,
}

impl TreeGuide {
    pub(crate) fn class(self) -> &'static str {
        match self {
            Self::Blank => "tree-guide",
            Self::Trunk => "tree-guide trunk",
            Self::Branch => "tree-guide branch",
            Self::Corner => "tree-guide corner",
        }
    }
}

/// Lays out each node's ancestry the way a terminal tree listing does. Nodes
/// arrive in preorder carrying their depth, which is all this needs: a node is
/// the last of its siblings when the next node at or above its depth is
/// shallower, and every level in between contributes either a continuing trunk
/// or the blank that follows a closed one.
pub(crate) fn tree_guides(nodes: &[TreeNode]) -> Vec<Vec<TreeGuide>> {
    let last: Vec<bool> = (0..nodes.len())
        .map(|index| is_last_sibling(nodes, index))
        .collect();
    let mut guides = Vec::with_capacity(nodes.len());
    // Indexed by depth: whether the node currently open at that depth was the
    // last of its siblings, and so whether its trunk is still being drawn.
    let mut ancestors: Vec<bool> = Vec::new();
    for (index, node) in nodes.iter().enumerate() {
        ancestors.truncate(node.depth);
        let mut row = Vec::with_capacity(node.depth);
        for level in 1..node.depth {
            row.push(if ancestors.get(level).copied().unwrap_or(true) {
                TreeGuide::Blank
            } else {
                TreeGuide::Trunk
            });
        }
        if node.depth > 0 {
            row.push(if last[index] {
                TreeGuide::Corner
            } else {
                TreeGuide::Branch
            });
        }
        ancestors.push(last[index]);
        guides.push(row);
    }
    guides
}

pub(crate) fn is_last_sibling(nodes: &[TreeNode], index: usize) -> bool {
    let depth = nodes[index].depth;
    !nodes[index + 1..]
        .iter()
        .take_while(|node| node.depth >= depth)
        .any(|node| node.depth == depth)
}

pub(crate) fn build_tree_node(
    document: &Document,
    node: &TreeNode,
    index: usize,
    selected: bool,
    has_children: bool,
    guides: &[TreeGuide],
) -> Result<Element, ClientError> {
    let mut class = String::from("tree-node");
    if node.has_values {
        class.push_str(" has-values");
    }
    if selected {
        class.push_str(" selected");
    }
    let item = create_element(document, "li", Some(&class))?;
    let node_id = format!("tree-node-{index}");
    let level = (node.depth + 1).to_string();
    for (name, value) in [
        ("role", "treeitem"),
        ("id", node_id.as_str()),
        ("aria-level", level.as_str()),
        ("aria-selected", if selected { "true" } else { "false" }),
        ("data-path", node.path.as_str()),
    ] {
        item.set_attribute(name, value)
            .map_err(|_| browser_error())?;
    }
    if has_children {
        item.set_attribute("aria-expanded", "true")
            .map_err(|_| browser_error())?;
    }
    if !guides.is_empty() {
        // The shape these guides draw is already in `aria-level`; repeating it
        // as punctuation would only make every node announce its own scaffold.
        let column = create_element(document, "span", Some("tree-guides"))?;
        column
            .set_attribute("aria-hidden", "true")
            .map_err(|_| browser_error())?;
        for guide in guides {
            append(
                &column,
                &create_element(document, "span", Some(guide.class()))?,
            )?;
        }
        append(&item, &column)?;
    }
    if node.has_connection {
        append(&item, &icon_svg(document, Icon::Key, "tree-key")?)?;
    }
    let label = create_element(document, "span", Some("tree-label"))?;
    label.set_text_content(Some(&node.display));
    append(&item, &label)?;
    if node.has_connection {
        let annotation = create_element(document, "span", Some("visually-hidden"))?;
        annotation.set_text_content(Some(" has an access URL"));
        append(&item, &annotation)?;
    }

    Ok(item)
}

/// Resolves the tree node an event landed on. Listeners live on the tree itself
/// rather than on each node, so a render allocates nothing: the tree is rebuilt
/// twice per navigation over the whole estate, and per-node closures would have
/// to be leaked every time to stay callable from JavaScript.
pub(crate) fn event_tree_node(event: &Event) -> Option<(usize, ConfigPath)> {
    let item = event
        .target()
        .and_then(|target| target.dyn_into::<Element>().ok())
        .and_then(|target| target.closest("[data-path]").ok().flatten())?;
    let path = ConfigPath::parse(item.get_attribute("data-path")?).ok()?;
    let index = item
        .id()
        .strip_prefix("tree-node-")
        .and_then(|index| index.parse::<usize>().ok())?;
    Some((index, path))
}

/// Installs the tree's two delegated listeners. Nodes carry `data-path` and a
/// positional id, which is everything either handler needs.
pub(crate) fn install_tree_actions(document: &Document) {
    let Some(tree) = document.get_element_by_id("config-tree") else {
        return;
    };
    let callback = Closure::<dyn FnMut(_)>::new(move |event: Event| {
        if let Some((_, path)) = event_tree_node(&event) {
            guarded_navigate(Route::Configuration(path));
        }
    });
    let _ = tree.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
    callback.forget();

    let callback = Closure::<dyn FnMut(_)>::new(move |event: KeyboardEvent| {
        let Some((index, path)) = event_tree_node(event.as_ref()) else {
            return;
        };
        match event.key().as_str() {
            "Enter" | " " => {
                event.prevent_default();
                guarded_navigate(Route::Configuration(path));
            }
            "ArrowDown" => {
                event.prevent_default();
                focus_tree_node(index.saturating_add(1));
            }
            "ArrowUp" => {
                event.prevent_default();
                // Neither direction wraps, per the WAI-ARIA tree pattern: a
                // tree is not the path-picker listbox, where wrapping is the
                // convention.
                focus_tree_node(index.saturating_sub(1));
            }
            "Home" => {
                event.prevent_default();
                focus_tree_node(0);
            }
            "End" => {
                event.prevent_default();
                focus_tree_node(usize::MAX);
            }
            _ => {}
        }
    });
    let _ = tree.add_event_listener_with_callback("keydown", callback.as_ref().unchecked_ref());
    callback.forget();
}

/// Moves the roving tab stop to `index`, clamped to the rendered nodes.
pub(crate) fn focus_tree_node(index: usize) {
    let count = TREE_NODES.with_borrow(Vec::len);
    if count == 0 {
        return;
    }
    let index = index.min(count - 1);
    let Some(document) = window().and_then(|window| window.document()) else {
        return;
    };
    for position in 0..count {
        if let Some(node) = document.get_element_by_id(&format!("tree-node-{position}")) {
            let _ = node.set_attribute("tabindex", if position == index { "0" } else { "-1" });
        }
    }
    focus(&format!("tree-node-{index}"));
}
