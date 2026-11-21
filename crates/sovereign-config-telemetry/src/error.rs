//! A failure that carries its own `error.type`.
//!
//! A root span — a `migrate` step, the server's startup checks — records its
//! `error.type` once, where the failure leaves it, because a field recorded
//! twice is exported twice. The code that knows *why* it failed runs deeper,
//! inside that span, so it returns a [`Classified`] error instead of
//! recording, and the root reads the classification back off the error chain
//! ([`classification`]).

use std::{error::Error, fmt};

/// An error whose classification is a bounded `error.type` value.
#[derive(Debug)]
pub struct Classified {
    error_type: &'static str,
    message: String,
}

impl Classified {
    /// `message` is what the error displays; it must quote no secret, as
    /// every error message must.
    #[must_use]
    pub fn new(error_type: &'static str, message: impl Into<String>) -> Self {
        Self {
            error_type,
            message: message.into(),
        }
    }

    #[must_use]
    pub const fn error_type(&self) -> &'static str {
        self.error_type
    }
}

impl fmt::Display for Classified {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for Classified {}

/// The classification of the outermost [`Classified`] error in `error`'s
/// chain of sources, if there is one.
#[must_use]
pub fn classification(error: &(dyn Error + 'static)) -> Option<&'static str> {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(classified) = error.downcast_ref::<Classified>() {
            return Some(classified.error_type());
        }
        current = error.source();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{Classified, classification};

    #[derive(Debug)]
    struct Wrapper(Classified);

    impl std::fmt::Display for Wrapper {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("while doing something")
        }
    }

    impl std::error::Error for Wrapper {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn a_classification_is_found_through_the_sources_that_wrap_it() {
        let classified = Classified::new("wrong_key", "the key opens nothing");
        assert_eq!(classified.to_string(), "the key opens nothing");
        assert_eq!(classification(&classified), Some("wrong_key"));
        assert_eq!(
            classification(&Wrapper(Classified::new("unavailable", "down"))),
            Some("unavailable")
        );
        assert_eq!(classification(&std::fmt::Error), None);
    }
}
