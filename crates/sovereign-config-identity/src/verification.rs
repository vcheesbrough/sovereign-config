//! How an access token of one identity provider is read: the rules a provider
//! supplies once, at startup, and the server applies to every request without
//! calling the provider again.
//!
//! The rules are data — names and encodings from a small fixed set — and never
//! a function, so they can be handed across a process boundary unchanged.
//! What no provider may vary is not a rule: the token is a JWT signed with
//! RS256 by a key its header names by `kid`, its subject is `sub`, its
//! validity is `exp`, `nbf` and `iat`, and it carries the scope
//! [`crate::contract::REQUIRED_SCOPE`].

use core::fmt;

use serde::Deserialize;
use serde_json::{Map, Value};

/// A token's claims, as decoded from its payload.
pub type Claims = Map<String, Value>;

/// How one provider's access tokens are verified and read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationRules {
    /// The exact `iss` an access token carries. Compared byte for byte, so it
    /// is spelled as the provider's tokens spell it, which need not be how
    /// the issuer handed to clients ([`crate::LoginDescription::issuer`]) is
    /// spelled.
    pub issuer: String,
    /// Where the issuer's signing keys are published, as a JWK set. The only
    /// place keys are read from: a token never names its own.
    pub jwks_uri: String,
    /// The `aud` an access token must carry, alone or among others.
    pub audience: String,
    /// The claim holding the token's scopes as one space-separated string.
    /// Requiring it is also what refuses an ID token, which must not carry
    /// it.
    pub scope_claim: String,
    /// The claim holding the token's grants.
    pub grants_claim: String,
    pub grants_encoding: GrantsEncoding,
    /// The claims a display name is read from, most preferred first.
    pub name_claims: Vec<String>,
}

/// How the grants claim holds its array of `{prefix, permissions}` objects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantsEncoding {
    /// A JSON array, in the token as such.
    Array,
    /// A string holding that JSON array, for a provider whose attributes are
    /// text.
    JsonText,
}

/// One grant as a token claims it, before the server has judged it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct ClaimedGrant {
    pub prefix: String,
    pub permissions: Vec<String>,
}

/// A set of rules names nothing to verify against, or nothing to read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidRules;

impl fmt::Display for InvalidRules {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the identity provider's verification rules are incomplete")
    }
}

impl std::error::Error for InvalidRules {}

impl VerificationRules {
    /// # Errors
    ///
    /// The issuer, key location, audience or a claim name is empty, or a
    /// claim name is one the contract already gives a fixed meaning.
    pub fn validate(&self) -> Result<(), InvalidRules> {
        const FIXED: [&str; 6] = ["iss", "aud", "sub", "exp", "nbf", "iat"];
        let claims = [&self.scope_claim, &self.grants_claim]
            .into_iter()
            .chain(&self.name_claims);
        if self.issuer.is_empty()
            || self.jwks_uri.is_empty()
            || self.audience.is_empty()
            || self.scope_claim == self.grants_claim
            || claims
                .into_iter()
                .any(|claim| claim.is_empty() || FIXED.contains(&claim.as_str()))
        {
            return Err(InvalidRules);
        }
        Ok(())
    }

    /// Whether the token's scope claim names `scope`. A missing claim, or one
    /// that is not a string, names nothing.
    #[must_use]
    pub fn has_scope(&self, claims: &Claims, scope: &str) -> bool {
        claims
            .get(&self.scope_claim)
            .and_then(Value::as_str)
            .is_some_and(|scopes| scopes.split_ascii_whitespace().any(|held| held == scope))
    }

    /// The grants the token claims, or `None` when the claim is missing or
    /// is not in the encoding these rules name. An empty array is a token
    /// that claims no grant, which is not the same thing.
    #[must_use]
    pub fn grants(&self, claims: &Claims) -> Option<Vec<ClaimedGrant>> {
        let claim = claims.get(&self.grants_claim)?;
        match self.grants_encoding {
            GrantsEncoding::Array => serde_json::from_value(claim.clone()).ok(),
            GrantsEncoding::JsonText => serde_json::from_str(claim.as_str()?).ok(),
        }
    }

    /// The token's display-name claims that are present, most preferred
    /// first, whatever their type: the caller decides what makes a name.
    pub fn names<'a>(&'a self, claims: &'a Claims) -> impl Iterator<Item = &'a Value> {
        self.name_claims
            .iter()
            .filter_map(|claim| claims.get(claim))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn rules(encoding: GrantsEncoding) -> VerificationRules {
        VerificationRules {
            issuer: "https://idp.example.test/realm".to_owned(),
            jwks_uri: "https://idp.example.test/realm/keys".to_owned(),
            audience: "config".to_owned(),
            scope_claim: "scope".to_owned(),
            grants_claim: "grants".to_owned(),
            grants_encoding: encoding,
            name_claims: vec!["first".to_owned(), "second".to_owned()],
        }
    }

    fn claims(value: Value) -> Claims {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn a_scope_is_one_whole_word_of_a_string_claim() {
        let rules = rules(GrantsEncoding::Array);
        assert!(rules.has_scope(&claims(json!({"scope": "openid config"})), "config"));
        for absent in [
            json!({}),
            json!({"scope": "openid config-dev"}),
            json!({"scope": ["config"]}),
            json!({"scp": "config"}),
        ] {
            assert!(
                !rules.has_scope(&claims(absent.clone()), "config"),
                "{absent}"
            );
        }
    }

    #[test]
    fn grants_are_read_in_the_encoding_the_rules_name_and_no_other() {
        let grant = json!([{"prefix": "/apps", "permissions": ["read"], "note": "ignored"}]);
        let expected = vec![ClaimedGrant {
            prefix: "/apps".to_owned(),
            permissions: vec!["read".to_owned()],
        }];
        let array = claims(json!({"grants": grant}));
        let text = claims(json!({"grants": grant.to_string()}));

        assert_eq!(
            rules(GrantsEncoding::Array).grants(&array),
            Some(expected.clone())
        );
        assert_eq!(
            rules(GrantsEncoding::JsonText).grants(&text),
            Some(expected)
        );
        assert_eq!(rules(GrantsEncoding::Array).grants(&text), None);
        assert_eq!(rules(GrantsEncoding::JsonText).grants(&array), None);

        let array_rules = rules(GrantsEncoding::Array);
        assert_eq!(array_rules.grants(&claims(json!({}))), None);
        assert_eq!(
            array_rules.grants(&claims(json!({"grants": []}))),
            Some(Vec::new())
        );
        for malformed in [
            json!({"grants": [{"prefix": "/apps"}]}),
            json!({"grants": [{"prefix": 1, "permissions": []}]}),
            json!({"grants": [{"prefix": "/", "permissions": [1]}]}),
            json!({"grants": {"prefix": "/", "permissions": []}}),
        ] {
            assert_eq!(
                array_rules.grants(&claims(malformed.clone())),
                None,
                "{malformed}"
            );
        }
    }

    #[test]
    fn names_come_in_the_rules_order_and_skip_absent_claims() {
        let rules = rules(GrantsEncoding::Array);
        let both = claims(json!({"second": "b", "first": "a", "third": "c"}));
        assert_eq!(
            rules.names(&both).collect::<Vec<_>>(),
            [&json!("a"), &json!("b")]
        );
        let fallback = claims(json!({"second": 7}));
        assert_eq!(rules.names(&fallback).collect::<Vec<_>>(), [&json!(7)]);
    }

    #[test]
    fn rules_must_name_everything_and_leave_the_fixed_claims_alone() {
        assert_eq!(rules(GrantsEncoding::Array).validate(), Ok(()));
        let broken: [fn(&mut VerificationRules); 7] = [
            |rules| rules.issuer.clear(),
            |rules| rules.jwks_uri.clear(),
            |rules| rules.audience.clear(),
            |rules| rules.scope_claim.clear(),
            |rules| rules.grants_claim = "sub".to_owned(),
            |rules| rules.grants_claim = rules.scope_claim.clone(),
            |rules| rules.name_claims.push(String::new()),
        ];
        for (index, break_it) in broken.into_iter().enumerate() {
            let mut rules = rules(GrantsEncoding::Array);
            break_it(&mut rules);
            assert_eq!(rules.validate(), Err(InvalidRules), "case {index}");
        }
    }
}
