//! The command surface.
//!
//! Two rules govern every value command:
//!
//! 1. The path comes immediately after the verb —
//!    `sovereign-config <verb> <ABSOLUTE_PATH> [OPTIONS]`. Clap still accepts a
//!    flag typed earlier, as GNU-style tools do; the rule is what the CLI
//!    teaches, which is why each command overrides its usage line.
//! 2. Every value command acts on exactly one value, and `--tree` makes it act
//!    on the subtree at that path instead.
//!
//! `--format` therefore means one thing only: how a read is rendered.

use clap::{Parser, Subcommand, ValueEnum};

const APPLICATION_VERSION: &str = match option_env!("SOVEREIGN_CONFIG_RELEASE") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

const PATH_HELP: &str = "Absolute configuration path, beginning with /";

#[derive(Parser)]
#[command(name = "sovereign-config", version = APPLICATION_VERSION, about)]
pub struct Arguments {
    #[arg(long, global = true)]
    pub profile: Option<String>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Manage connection profiles
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    /// Authenticate the selected profile
    Login,
    /// Discard the selected profile's stored credential
    Logout,
    /// Report the service and authentication status
    Status,
    /// Read one configuration value, or the subtree at that path
    #[command(override_usage = "sovereign-config get <ABSOLUTE_PATH> [OPTIONS]")]
    Get {
        #[arg(value_name = "ABSOLUTE_PATH", help = PATH_HELP)]
        path: String,
        /// Read every value at or below the path instead of the one value
        #[arg(long)]
        tree: bool,
        /// Return secret plaintext instead of the mask
        #[arg(long)]
        reveal: bool,
        #[arg(long, value_enum, default_value_t = ValueFormat::Plain)]
        format: ValueFormat,
    },
    /// Write one configuration value, or replace the subtree at that path
    #[command(override_usage = "sovereign-config set <ABSOLUTE_PATH> [OPTIONS]")]
    Set {
        #[arg(value_name = "ABSOLUTE_PATH", help = PATH_HELP)]
        path: String,
        /// Store the value as a secret; content is read from standard input
        #[arg(long, conflicts_with = "tree")]
        secret: bool,
        /// Replace every value at or below the path from a JSON subtree on
        /// standard input
        #[arg(long)]
        tree: bool,
    },
    /// Permanently delete one configuration value, or the subtree at that path
    #[command(override_usage = "sovereign-config delete <ABSOLUTE_PATH> [OPTIONS]")]
    Delete {
        #[arg(value_name = "ABSOLUTE_PATH", help = PATH_HELP)]
        path: String,
        /// Delete every value at or below the path instead of the one value
        #[arg(long)]
        tree: bool,
        /// Skip the interactive confirmation
        #[arg(long)]
        yes: bool,
    },
    /// List the paths directly below a namespace, or a value's own paths
    #[command(override_usage = "sovereign-config list <ABSOLUTE_PATH> [OPTIONS]")]
    List {
        #[arg(value_name = "ABSOLUTE_PATH", help = PATH_HELP)]
        path: String,
        /// List every path resolving to the value at this path instead
        #[arg(long)]
        aliases: bool,
        #[arg(long, value_enum, default_value_t = ValueFormat::Plain)]
        format: ValueFormat,
    },
    /// Expose an existing configuration value at an additional path
    #[command(override_usage = "sovereign-config alias <SOURCE_ABSOLUTE_PATH> <NEW_ABSOLUTE_PATH>")]
    Alias {
        #[arg(
            value_name = "SOURCE_ABSOLUTE_PATH",
            help = "Absolute path of the existing configuration value, beginning with /"
        )]
        source_path: String,
        #[arg(
            value_name = "NEW_ABSOLUTE_PATH",
            help = "Absolute path to expose the value at, beginning with /"
        )]
        new_path: String,
    },
}

/// How a read is rendered. Plain is line oriented; JSON is byte exact.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ValueFormat {
    Plain,
    Json,
}

#[derive(Subcommand)]
pub enum ProfileCommand {
    /// Add a profile from a connection URL read at a hidden prompt
    Add { name: String },
    /// Replace a profile's connection URL
    Update { name: String },
    /// Select the profile used when `--profile` is absent
    Default { name: String },
}
