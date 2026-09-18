//! Ordered configuration-layer reading and merging.
//!
//! Two consumers need the same read: the Woodpecker broker resolves a
//! pipeline's secrets from an ordered list of paths, and the CLI's `render`
//! resolves a deploy's environment from an ordered list of paths typed on the
//! command line. Both want the same thing — the **direct children** of each
//! layer, secrets revealed, merged so that a later layer wins — so it lives
//! here once rather than twice.
//!
//! What stays with each consumer is everything around that read: how the layer
//! list is arrived at (Woodpecker templates against a signed request; the CLI
//! takes positional paths), how a connection is opened and authenticated, and
//! what is done with the merged map.
//!
//! Everything here is `!Send`, like every transport in this workspace, so the
//! same client can compile to WebAssembly.

#![forbid(unsafe_code)]

mod reader;
mod token;

pub use reader::{InvalidatableToken, LayerReader, Naming, OnMissing, direct_child_name};
pub use token::CachedTokenProvider;
