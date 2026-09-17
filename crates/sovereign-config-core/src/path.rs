//! The canonical configuration path grammar: parsing, folding, and ordering.

use core::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PathError {
    #[error("path must be canonical")]
    NonCanonical,
}

/// A canonical absolute configuration path.
///
/// The grammar is `/` (the tree root) or `^/[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$`.
/// A `ConfigPath` stores exactly one string — `path`, exactly as it was
/// written — and nothing else. There is no second, independently-stored
/// "fold key" field: fold is a pure function of `path`
/// (`to_ascii_lowercase`), so storing it separately would be redundant data
/// that a future constructor could compute wrong or forget to update — as one
/// once did (`Deserialize`, before it was fixed to have nothing to forget).
/// [`ConfigPath::fold`] derives it on every call instead; comparison and
/// ordering (`Eq`, `Ord`) also derive it inline, without allocating one.
///
/// This is case-**retentive**, not case-sensitive: the service stores and
/// reports the letter case it was given, but two paths differing only in case
/// remain one value — resolution, uniqueness, and authorization all compare
/// on the fold. Case retention was added in release 2.18.0; a client built
/// before that release assumes every response path is already lowercase and
/// fails the whole response it arrived in once one is not. See the `Upgrade`
/// section of the repository README.
///
/// `_` was added to the segment character set in release 2.15.0. It is a
/// widening of the `v3` protocol's canonical path grammar: a client built before
/// that release rejects a path containing `_` and fails the whole response it
/// arrived in. See the `Upgrade` section of the repository README.
#[derive(Clone, Debug)]
pub struct ConfigPath {
    path: String,
}

impl ConfigPath {
    #[must_use]
    pub fn root() -> Self {
        Self { path: "/".into() }
    }

    /// Parses a rooted, already fold-cased (lowercase) path, including the `/`
    /// root path.
    ///
    /// Use this only for input already known to be canonical —
    /// round-tripping a stored fold key, a literal in code, a connection
    /// root — never for text a caller typed, which should go through
    /// [`ConfigPath::parse_operation`] or [`ConfigPath::parse_selection`] to
    /// retain its case.
    ///
    /// # Errors
    ///
    /// Returns [`PathError::NonCanonical`] when the path is not rooted, a segment
    /// is empty, or it contains characters outside lowercase ASCII letters,
    /// digits, `-`, and `_`.
    pub fn parse(value: impl Into<String>) -> Result<Self, PathError> {
        let value = value.into();
        if value == "/"
            || value.strip_prefix('/').is_some_and(|relative| {
                !relative.is_empty()
                    && relative.split('/').all(|segment| {
                        !segment.is_empty()
                            && segment.bytes().all(|byte| {
                                byte.is_ascii_lowercase()
                                    || byte.is_ascii_digit()
                                    || byte == b'-'
                                    || byte == b'_'
                            })
                    })
            })
        {
            Ok(Self { path: value })
        } else {
            Err(PathError::NonCanonical)
        }
    }

    /// Parses a non-root absolute operation path, retaining the case it was
    /// written with.
    ///
    /// # Errors
    ///
    /// Returns [`PathError::NonCanonical`] for root or unrooted paths, empty
    /// segments, non-ASCII text, percent encoding, or characters other than
    /// ASCII letters, digits, `-`, and `_`.
    pub fn parse_operation(value: impl AsRef<str>) -> Result<Self, PathError> {
        let value = value.as_ref();
        let Some(relative) = value.strip_prefix('/') else {
            return Err(PathError::NonCanonical);
        };
        if relative.is_empty()
            || !relative.split('/').all(|segment| {
                !segment.is_empty()
                    && segment.bytes().all(|byte| {
                        byte.is_ascii_alphabetic()
                            || byte.is_ascii_digit()
                            || byte == b'-'
                            || byte == b'_'
                    })
            })
        {
            return Err(PathError::NonCanonical);
        }
        Ok(Self {
            path: value.to_owned(),
        })
    }

    /// Parses an absolute operation selection, including the tree root,
    /// retaining case as [`ConfigPath::parse_operation`] does.
    ///
    /// # Errors
    ///
    /// Returns [`PathError::NonCanonical`] for unrooted paths, empty segments,
    /// non-ASCII text, percent encoding, or unsupported characters.
    pub fn parse_selection(value: impl AsRef<str>) -> Result<Self, PathError> {
        if value.as_ref() == "/" {
            return Ok(Self::root());
        }
        Self::parse_operation(value)
    }

    /// Appends one value name to a canonical rooted namespace, retaining the
    /// case `name` was given as that segment's display form.
    ///
    /// # Errors
    ///
    /// Returns [`PathError::NonCanonical`] when `name` is not one valid path
    /// segment.
    pub fn join_name(&self, name: impl AsRef<str>) -> Result<Self, PathError> {
        let name = name.as_ref();
        if name.is_empty()
            || !name.bytes().all(|byte| {
                byte.is_ascii_alphabetic() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
            })
        {
            return Err(PathError::NonCanonical);
        }
        let path = if self.path == "/" {
            format!("/{name}")
        } else {
            format!("{}/{name}", self.path)
        };
        Ok(Self { path })
    }

    /// The path exactly as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.path
    }

    /// The fold key: ASCII letters lowercased. Used for comparison, lookup,
    /// and every other match — never for display. Derived on every call, not
    /// stored: there is nothing here that can drift from `as_str()`.
    #[must_use]
    pub fn fold(&self) -> String {
        self.path.to_ascii_lowercase()
    }

    #[must_use]
    pub fn is_at_or_below(&self, root: &Self) -> bool {
        if root.path == "/" {
            return true;
        }
        let prefix_len = root.path.len();
        // ASCII-only by grammar, so byte indexing never splits a character.
        self.path.len() >= prefix_len
            && self.path.as_bytes()[..prefix_len].eq_ignore_ascii_case(root.path.as_bytes())
            && (self.path.len() == prefix_len || self.path.as_bytes()[prefix_len] == b'/')
    }

    /// The final segment, exactly as written.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.path.rsplit('/').next().filter(|name| !name.is_empty())
    }
}

/// Compares on the fold, derived inline byte-by-byte — no allocation, and
/// nothing stored that could disagree with `as_str()`.
impl PartialEq for ConfigPath {
    fn eq(&self, other: &Self) -> bool {
        self.path.eq_ignore_ascii_case(&other.path)
    }
}

impl Eq for ConfigPath {}

impl PartialOrd for ConfigPath {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ConfigPath {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.path
            .bytes()
            .map(|byte| byte.to_ascii_lowercase())
            .cmp(other.path.bytes().map(|byte| byte.to_ascii_lowercase()))
    }
}

/// Serializes the path exactly as written, matching this type's historical
/// `#[serde(transparent)]` wire shape.
impl Serialize for ConfigPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.path)
    }
}

/// Deserializes without validation, matching this type's historical
/// `#[serde(transparent)]` behavior — round-trips only, never for untrusted
/// text. Untrusted input must go through [`ConfigPath::parse_operation`] or
/// [`ConfigPath::parse_selection`].
impl<'de> Deserialize<'de> for ConfigPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Self {
            path: String::deserialize(deserializer)?,
        })
    }
}

impl fmt::Display for ConfigPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.path)
    }
}
