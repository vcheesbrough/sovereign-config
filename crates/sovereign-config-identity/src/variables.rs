//! Where a provider reads its own configuration from: named variables, each
//! optionally supplied as a file. A provider parses and validates its
//! variables itself; the server only says where they are.

use std::{collections::BTreeMap, env, fs};

use anyhow::{Context, Result, bail};

/// A source of named configuration variables.
pub trait Variables {
    /// The variable's raw value, if it is set at all.
    fn get(&self, name: &str) -> Option<String>;

    /// The variable's value, when it is set and not blank.
    fn optional(&self, name: &str) -> Option<String> {
        self.get(name).filter(|value| !value.trim().is_empty())
    }

    /// # Errors
    ///
    /// The variable is unset or blank. The message names it and quotes
    /// nothing.
    fn required(&self, name: &str) -> Result<String> {
        match self.optional(name) {
            Some(value) => Ok(value),
            None => bail!("required configuration {name} is missing or empty"),
        }
    }

    /// A secret: the variable itself, or else the contents of the file
    /// `<name>_FILE` names, trimmed.
    ///
    /// # Errors
    ///
    /// Neither is set, or the file is unreadable or empty. No message quotes
    /// a value or a path.
    fn secret(&self, name: &str) -> Result<String> {
        if let Some(value) = self.optional(name) {
            return Ok(value);
        }
        let file_name = format!("{name}_FILE");
        let path = self.required(&file_name)?;
        let value =
            fs::read_to_string(&path).with_context(|| format!("unable to read {file_name}"))?;
        if value.trim().is_empty() {
            bail!("{file_name} points to an empty secret file");
        }
        Ok(value.trim().to_owned())
    }
}

/// The process environment.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessEnvironment;

impl Variables for ProcessEnvironment {
    fn get(&self, name: &str) -> Option<String> {
        env::var(name).ok()
    }
}

/// A fixed set of variables, for driving a provider's configuration in a
/// test without touching the process environment.
impl Variables for BTreeMap<&str, String> {
    fn get(&self, name: &str) -> Option<String> {
        BTreeMap::get(self, name).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_blank_variable_is_an_unset_one() {
        let variables = BTreeMap::from([("SET", "value".to_owned()), ("BLANK", "  ".to_owned())]);
        assert_eq!(variables.optional("SET").as_deref(), Some("value"));
        assert_eq!(variables.optional("BLANK"), None);
        assert_eq!(variables.required("SET").unwrap(), "value");
        for name in ["BLANK", "UNSET"] {
            let message = variables.required(name).unwrap_err().to_string();
            assert_eq!(
                message,
                format!("required configuration {name} is missing or empty")
            );
        }
    }

    #[test]
    fn a_secret_is_the_variable_or_else_its_file_and_is_never_quoted() {
        let direct = BTreeMap::from([("TOKEN", "secret-sentinel".to_owned())]);
        assert_eq!(direct.secret("TOKEN").unwrap(), "secret-sentinel");

        let missing =
            BTreeMap::from([("TOKEN_FILE", "/nonexistent/path-sentinel/token".to_owned())]);
        let message = format!("{:#}", missing.secret("TOKEN").unwrap_err());
        assert!(
            message.starts_with("unable to read TOKEN_FILE"),
            "{message}"
        );
        assert!(!message.contains("path-sentinel"), "{message}");

        let unset: BTreeMap<&str, String> = BTreeMap::new();
        let message = unset.secret("TOKEN").unwrap_err().to_string();
        assert_eq!(
            message,
            "required configuration TOKEN_FILE is missing or empty"
        );
    }
}
