//! `render`: run a command with configuration subtrees as its environment.
//!
//! This is the deploy-time consumption path. A compose stack or a CI deploy
//! step keeps one narrow, read-only, centrally revocable connection rooted at
//! its own subtree, instead of carrying every value inline:
//!
//! ```sh
//! sovereign-config render -- docker compose up -d --wait
//! ```
//!
//! Three properties make that safe to point at a production deploy:
//!
//! - **No shell is involved.** Values are placed in the child's environment
//!   through `execve`, so a value containing `$(...)`, a backtick, a quote or a
//!   newline is data. There is no stage at which it could be re-parsed as
//!   syntax.
//! - **The process is replaced, not wrapped.** The child's exit status and
//!   signal disposition are `render`'s, with no supervisor in between to
//!   swallow or mistranslate either.
//! - **It fails closed.** Every read happens before the exec, so a credential,
//!   read or reveal failure means the command never runs at all — rather than
//!   running against a half-populated environment, which is the failure mode
//!   this command exists to remove.

use std::{collections::BTreeMap, os::unix::process::CommandExt, process::Command};

use anyhow::{Context, Result, bail};
use sovereign_config_core::{ConfigPath, ConnectionUrl, RevealedSecret};
use sovereign_config_layers::{LayerReader, Naming, OnMissing};

use crate::connection::URL_VARIABLE;
use crate::session::{self, Scope};

/// Reads the layers, then replaces this process with `command`.
///
/// # Errors
///
/// Returns an error for a layer outside the connection root, an unreachable or
/// unauthenticated service, a layer that cannot be read, a leaf that cannot be
/// an environment variable name, or a command that cannot be executed. On any
/// of them the command has not run.
///
/// On success this function does not return: the process is gone.
pub async fn render(
    connection: &ConnectionUrl,
    paths: &[String],
    command: &[String],
) -> Result<()> {
    let layers = layers(connection, paths)?;
    let (transport, tokens) = session::operational_transport(connection).await?;
    // `OnMissing::Fail` rather than the broker's `Skip`: the broker serves a
    // short result rather than stripping every concurrent pipeline, but a
    // deploy that silently receives less configuration than it asked for is
    // precisely what this command replaces. `Naming::AsStored` because an
    // environment variable name is case sensitive — see `variable_name`.
    let reader = LayerReader::new(transport, tokens, OnMissing::Fail, Naming::AsStored);
    let mut values = BTreeMap::new();
    for layer in &layers {
        let read = reader.read(layer).await?;
        // The service answers an absent subtree with an empty list, not
        // `NotFound`, so a mistyped layer path is indistinguishable from a real
        // but empty one at the transport. Neither is worth launching a deploy
        // over: a layer named on the command line was named because it was
        // meant to contribute something. Paths are not secret, so say which.
        if read.is_empty() {
            bail!(
                "layer {} contributed no configuration; check the path exists \
                 and holds values directly beneath it",
                layer.as_str()
            );
        }
        values.extend(read);
    }
    exec(&values, command)
}

/// The layers to read, in the order given.
///
/// No path at all means the connection's own root, which is the whole point of
/// a per-consumer rooted connection: the caller need not repeat a prefix the
/// credential already encodes.
fn layers(connection: &ConnectionUrl, paths: &[String]) -> Result<Vec<ConfigPath>> {
    if paths.is_empty() {
        return Ok(vec![connection.root().clone()]);
    }
    paths
        .iter()
        .map(|path| session::operation_path(connection, path, Scope::Tree))
        .collect()
}

/// Replaces this process with `command`, carrying the rendered values.
///
/// The inherited environment is kept: `PATH`, `HOME` and anything the caller
/// set on the command line must survive, because a deploy step routinely
/// supplies one variable inline — an image tag, say — alongside everything it
/// reads from configuration. Rendered values win a collision, since they are
/// the more specific statement of intent. A collision is byte-exact on the
/// name, as it is for the command itself: an inherited `abc` and a rendered
/// `AbC` are two variables, not one.
fn exec(values: &BTreeMap<String, RevealedSecret>, command: &[String]) -> Result<()> {
    let (program, arguments) = command
        .split_first()
        .context("a command to run is required after --")?;
    // Every name is resolved before the child is built, so the one failure that
    // could otherwise happen half-way through assembling an environment cannot.
    let variables = values
        .iter()
        .map(|(leaf, value)| Ok((variable_name(leaf)?, value.expose())))
        .collect::<Result<Vec<_>>>()?;

    let mut child = Command::new(program);
    child.args(arguments);
    // Unconditionally, whether or not this invocation used it: the variable is
    // credential-shaped, and the executed command has no business seeing the
    // credential that read its configuration.
    child.env_remove(URL_VARIABLE);
    // Applied after that removal, so configuration that genuinely holds a
    // connection URL for the executed application's own use still reaches it.
    // Only the *inherited* credential is stripped.
    child.envs(variables);
    // `exec` returns only on failure; on success this process no longer exists.
    Err(child.exec()).with_context(|| format!("could not run {program}"))
}

/// Checks that a leaf name is usable as an environment variable name.
///
/// **The name is the leaf, exactly as stored — nothing is transformed.**
/// `/foo/AbC` holding `bAr` reaches the command as `AbC=bAr`, the same as
/// `export AbC=bAr` would. Paths have been case-retentive since 2.18.0, so the
/// spelling written is the spelling stored, and it is the only spelling a
/// deploy can predict. Uppercasing would make `/foo/AbC` unreachable, since
/// there would then be no path that produces it.
///
/// It follows that the case must be got right where the value is created:
/// `/apps/api/database_url` yields `database_url`, not `DATABASE_URL`. Store
/// leaves under the exact variable names the command expects.
///
/// # Errors
///
/// A leaf that is not a usable environment variable name — one containing `-`,
/// or starting with a digit — is refused rather than exported under a name no
/// shell and no compose file can reference. Passing it through would satisfy
/// `execve` and then fail silently at the point of use, which is the one
/// outcome this command must not produce. Folding `-` to `_` is not the
/// alternative: that is many-to-one, and `db-password` and `db_password` are
/// different values.
///
/// Paths are not secret, so the refusal names the offending leaf.
fn variable_name(leaf: &str) -> Result<&str> {
    let usable = !leaf.is_empty()
        && !leaf.starts_with(|first: char| first.is_ascii_digit())
        && leaf
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
    if !usable {
        bail!(
            "configuration leaf {leaf:?} cannot be an environment variable name; \
             rename it using only letters, digits and '_', and not starting with a digit"
        );
    }
    Ok(leaf)
}

#[cfg(test)]
mod tests;
