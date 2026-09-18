//! The value surface: `get`, `set`, `delete`, `list`, and `alias`.
//!
//! Each command takes the path immediately after the verb and acts on exactly
//! one value, unless `--tree` widens it to the subtree at that path.

use std::io::{self, IsTerminal, Read};

use anyhow::{Result, anyhow, bail};
use sovereign_config_core::{
    ConfigPath, ConnectionUrl, PlainValue, SecretInput, SubTreeValue, ValueContent, ValueListing,
    parse_subtree_json, render_subtree_json, render_subtree_plain,
};

use crate::cli::ValueFormat;
use crate::session::{OperationalClient, Scope, operation_path, operational_client};

/// Reads one value, or every value at or below the path when `tree` is set.
///
/// # Errors
///
/// Returns an error when the path is invalid or unconfined, the service is
/// unreachable, or no value exists at an exactly selected path.
pub async fn get(
    connection: &ConnectionUrl,
    path: &str,
    tree: bool,
    reveal: bool,
    format: ValueFormat,
) -> Result<()> {
    if tree {
        get_tree(connection, path, reveal, format).await
    } else {
        get_exact(connection, path, reveal, format).await
    }
}

async fn get_exact(
    connection: &ConnectionUrl,
    path: &str,
    reveal: bool,
    format: ValueFormat,
) -> Result<()> {
    let path = operation_path(connection, path, Scope::Exact)?;
    let client = operational_client(connection).await?;
    // `GetSubTree` is the only read RPC, so an exact read discards whatever
    // descendants came back with the one value the caller asked for.
    let Some(found) = client
        .get_subtree(&path)
        .await?
        .values
        .into_iter()
        .find(|value| value.path == path)
    else {
        bail!("configuration value not found");
    };
    // Reveal through the path the service reported, not the one typed: they
    // resolve to the same value, but the stored spelling is the canonical one.
    let text = if reveal && matches!(found.value, ValueContent::Secret(_)) {
        client.reveal_secret(&found.path).await?.expose().to_owned()
    } else {
        found.value.display_text().to_owned()
    };
    match format {
        ValueFormat::Plain => print!("{text}"),
        ValueFormat::Json => print!(
            "{}",
            render_subtree_json(
                &path,
                &[SubTreeValue {
                    path: path.clone(),
                    value: ValueContent::Plain(PlainValue::new(text)),
                }],
            )?
        ),
    }
    Ok(())
}

async fn get_tree(
    connection: &ConnectionUrl,
    path: &str,
    reveal: bool,
    format: ValueFormat,
) -> Result<()> {
    let path = operation_path(connection, path, Scope::Tree)?;
    let client = operational_client(connection).await?;
    let mut subtree = client.get_subtree(&path).await?;
    if reveal {
        reveal_subtree(&client, &mut subtree.values).await?;
    }
    print!(
        "{}",
        match format {
            ValueFormat::Plain => render_subtree_plain(&path, &subtree.values)?,
            ValueFormat::Json => render_subtree_json(&path, &subtree.values)?,
        }
    );
    Ok(())
}

async fn reveal_subtree(client: &OperationalClient, values: &mut [SubTreeValue]) -> Result<()> {
    for value in values {
        if matches!(value.value, ValueContent::Secret(_)) {
            let revealed = client.reveal_secret(&value.path).await?;
            value.value = ValueContent::Plain(PlainValue::new(revealed.expose()));
        }
    }
    Ok(())
}

/// Writes one value from standard input, as a plain value, a secret, or —
/// with `tree` — a JSON subtree replacing everything at or below the path.
///
/// # Errors
///
/// Returns an error when the path is invalid or unconfined, standard input is
/// unreadable, the JSON is invalid, or the write is rejected.
pub async fn set(connection: &ConnectionUrl, path: &str, secret: bool, tree: bool) -> Result<()> {
    let path = operation_path(connection, path, scope(tree))?;
    let content = read_stdin(if secret {
        "secret input is unavailable"
    } else {
        "configuration input is unavailable"
    })?;
    let client = operational_client(connection).await?;
    if tree {
        let values = parse_subtree_json(&path, &content)?;
        client.replace_subtree(&path, &values).await?;
        println!("Subtree replaced");
    } else if secret {
        client.put_secret(&path, &SecretInput::new(content)).await?;
        println!("Secret stored");
    } else {
        client.put_value(&path, &PlainValue::new(content)).await?;
        println!("Value stored");
    }
    Ok(())
}

/// Permanently deletes one value, or everything at or below the path when
/// `tree` is set.
///
/// # Errors
///
/// Returns an error when the path is invalid or unconfined, confirmation is
/// declined or unavailable, or the deletion is rejected.
pub async fn delete(connection: &ConnectionUrl, path: &str, tree: bool, yes: bool) -> Result<()> {
    let path = operation_path(connection, path, scope(tree))?;
    if !yes {
        confirm_deletion(&path, tree)?;
    }
    operational_client(connection)
        .await?
        .delete_values(&path, tree)
        .await?;
    println!(
        "{}",
        if tree {
            "Subtree deleted"
        } else {
            "Value deleted"
        }
    );
    Ok(())
}

fn confirm_deletion(path: &ConfigPath, tree: bool) -> Result<()> {
    if !io::stdin().is_terminal() {
        bail!("deletion requires --yes when standard input is not a terminal");
    }
    if tree {
        eprint!(
            "Permanently delete {} and all descendants? Type 'delete' to confirm: ",
            path.as_str()
        );
    } else {
        eprint!(
            "Permanently delete {}? Type 'delete' to confirm: ",
            path.as_str()
        );
    }
    let mut confirmation = String::new();
    io::stdin()
        .read_line(&mut confirmation)
        .map_err(|_| anyhow!("deletion confirmation is unavailable"))?;
    if confirmation.trim_end() != "delete" {
        bail!("deletion cancelled");
    }
    Ok(())
}

/// Lists the paths directly below a namespace, or — with `aliases` — every
/// path resolving to the value at an exact path.
///
/// # Errors
///
/// Returns an error when the path is invalid or unconfined, or the listing is
/// rejected.
pub async fn list(
    connection: &ConnectionUrl,
    path: &str,
    aliases: bool,
    format: ValueFormat,
) -> Result<()> {
    // `--aliases` names one value's own paths, so it takes the exact grammar;
    // a namespace listing takes the subtree grammar and may be the tree root.
    let scope = if aliases { Scope::Exact } else { Scope::Tree };
    let path = operation_path(connection, path, scope)?;
    let client = operational_client(connection).await?;
    let entries = if aliases {
        client
            .list_value_paths(&path)
            .await?
            .paths
            .iter()
            .map(|path| path.as_str().to_owned())
            .collect()
    } else {
        direct_children(&path, &client.list_values(&path).await?)
    };
    match format {
        ValueFormat::Plain => {
            for entry in &entries {
                println!("{entry}");
            }
        }
        ValueFormat::Json => println!("{}", serde_json::to_string_pretty(&entries)?),
    }
    Ok(())
}

/// The selected path's direct children: values as written, namespaces with a
/// trailing `/`.
///
/// `ListValuesResponse.values` is already restricted to direct children, but
/// `paths` carries every readable namespace in the whole tree, so the
/// namespaces are narrowed here. A path that is both a value and a namespace
/// appears twice, the value first.
fn direct_children(path: &ConfigPath, listing: &ValueListing) -> Vec<String> {
    let selected = path.fold();
    let mut entries: Vec<(&ConfigPath, bool, String)> = listing
        .values
        .iter()
        .map(|value| (&value.path, false, value.path.as_str().to_owned()))
        .collect();
    entries.extend(
        listing
            .paths
            .iter()
            .filter(|namespace| fold_parent(&namespace.fold()).as_deref() == Some(&selected))
            .map(|namespace| (namespace, true, format!("{}/", namespace.as_str()))),
    );
    // Every entry is a direct child of one parent, so ordering the paths by
    // fold orders the single differing segment by fold too.
    entries.sort_by(
        |(first, first_namespace, _), (second, second_namespace, _)| {
            first
                .cmp(second)
                .then(first_namespace.cmp(second_namespace))
        },
    );
    entries.into_iter().map(|(_, _, entry)| entry).collect()
}

/// The fold of a fold path's parent namespace, or `None` for the tree root.
fn fold_parent(fold: &str) -> Option<String> {
    if fold == "/" {
        return None;
    }
    let (parent, _) = fold.rsplit_once('/')?;
    Some(if parent.is_empty() {
        "/".to_owned()
    } else {
        parent.to_owned()
    })
}

/// Exposes an existing value at an additional absolute path.
///
/// # Errors
///
/// Returns an error when either path is invalid or unconfined, the source does
/// not exist, or the new path is taken or not writable.
pub async fn alias(connection: &ConnectionUrl, source_path: &str, new_path: &str) -> Result<()> {
    let source = operation_path(connection, source_path, Scope::Exact)?;
    let new_path = operation_path(connection, new_path, Scope::Exact)?;
    operational_client(connection)
        .await?
        .add_value_path(&source, &new_path)
        .await?;
    println!("Path added");
    Ok(())
}

const fn scope(tree: bool) -> Scope {
    if tree { Scope::Tree } else { Scope::Exact }
}

fn read_stdin(unavailable: &'static str) -> Result<String> {
    let mut content = String::new();
    io::stdin()
        .read_to_string(&mut content)
        .map_err(|_| anyhow!(unavailable))?;
    Ok(content)
}
