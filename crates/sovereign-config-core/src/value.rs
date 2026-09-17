//! Value newtypes: plain values, secret input and revealed secrets, bearer
//! secrets, and their classification. Secret-bearing types redact their `Debug`
//! output.

use core::fmt;

use serde::Deserialize;

use crate::MASKED_SECRET_TEXT;

/// Plain configuration text that must be exposed explicitly.
#[derive(Clone, Default, Deserialize, Eq, PartialEq)]
#[serde(transparent)]
pub struct PlainValue(String);

impl PlainValue {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Debug for PlainValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PlainValue([REDACTED])")
    }
}

impl fmt::Display for PlainValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueClassification {
    Plain,
    Secret,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MaskedSecret;

impl MaskedSecret {
    #[must_use]
    pub const fn text(self) -> &'static str {
        MASKED_SECRET_TEXT
    }
}

impl fmt::Display for MaskedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(MASKED_SECRET_TEXT)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValueContent {
    Plain(PlainValue),
    Secret(MaskedSecret),
}

impl ValueContent {
    #[must_use]
    pub const fn classification(&self) -> ValueClassification {
        match self {
            Self::Plain(_) => ValueClassification::Plain,
            Self::Secret(_) => ValueClassification::Secret,
        }
    }

    #[must_use]
    pub fn display_text(&self) -> &str {
        match self {
            Self::Plain(value) => value.expose(),
            Self::Secret(_) => MASKED_SECRET_TEXT,
        }
    }

    #[must_use]
    pub const fn plain(&self) -> Option<&PlainValue> {
        match self {
            Self::Plain(value) => Some(value),
            Self::Secret(_) => None,
        }
    }
}

/// A secret accepted only as write input. It is never serializable and all
/// formatting is redacted.
///
/// ```compile_fail
/// use serde::Serialize;
/// use sovereign_config_core::SecretInput;
///
/// fn assert_serializable<T: Serialize>() {}
/// assert_serializable::<SecretInput>();
/// ```
#[derive(Clone)]
pub struct SecretInput(String);

impl SecretInput {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretInput([REDACTED])")
    }
}

impl fmt::Display for SecretInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

/// Plaintext returned only by the explicit reveal operation.
///
/// ```compile_fail
/// use serde::Serialize;
/// use sovereign_config_core::RevealedSecret;
///
/// fn assert_serializable<T: Serialize>() {}
/// assert_serializable::<RevealedSecret>();
/// ```
#[derive(Clone)]
pub struct RevealedSecret(String);

impl RevealedSecret {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RevealedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RevealedSecret([REDACTED])")
    }
}

impl fmt::Display for RevealedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

/// An authentication or connection credential that requires explicit exposure.
///
/// Secrets deliberately do not implement Serde's serialization traits.
///
/// ```compile_fail
/// use serde::Serialize;
/// use sovereign_config_core::Secret;
///
/// fn assert_serializable<T: Serialize>() {}
/// assert_serializable::<Secret>();
/// ```
///
/// ```compile_fail
/// use serde::Deserialize;
/// use sovereign_config_core::Secret;
///
/// fn assert_deserializable<T: for<'de> Deserialize<'de>>() {}
/// assert_deserializable::<Secret>();
/// ```
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret([REDACTED])")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}
