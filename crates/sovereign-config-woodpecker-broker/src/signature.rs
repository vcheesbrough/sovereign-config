//! RFC 9421 HTTP Message Signature verification for Woodpecker's fixed profile.
//!
//! Woodpecker signs every extension request in
//! `server/services/utils/http.go`:
//!
//! ```text
//! config := httpsign.NewClientConfig().SetSignatureName("woodpecker-ci-extensions").SetSigner(signer)
//! signer, _ := httpsign.NewEd25519Signer(key, httpsign.NewSignConfig(),
//!     httpsign.Headers("@request-target", "content-digest"))
//! ```
//!
//! so the profile is fixed and tiny:
//!
//! - one signature, labelled `woodpecker-ci-extensions`;
//! - covered components exactly `("@request-target" "content-digest")`;
//! - parameters `created` and `alg="ed25519"` — `SetKeyID` is never called, so
//!   there is no `keyid` on the wire;
//! - `created` accepted within `-10s … +2s`, matching `httpsign`'s
//!   `NewVerifyConfig` defaults.
//!
//! Rather than pull in a general-purpose signature library for two components,
//! this is a verifier for exactly that profile. Two properties matter:
//!
//! **The signature base uses the `Signature-Input` value as received.** RFC 9421
//! §3.2 requires the `@signature-params` line to be the field value verbatim,
//! and `httpsign` does the same on verification (`origSigParams`). Re-serialising
//! a parsed structured field would introduce a canonicalisation mismatch class
//! for no benefit.
//!
//! **`Content-Digest` is recomputed here.** The Go broker calls
//! `httpsign.VerifyRequest` directly, and that path never checks the digest
//! against the body — digest validation lives only in the `Handler`/`Client`
//! wrappers it does not use. A signature over an unverified digest proves
//! nothing about the body, so a captured request could be replayed with forged
//! repo/pipeline metadata inside the `created` window and be brokered secrets
//! for the wrong repository. This verifier closes that.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey, pkcs8::DecodePublicKey};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// The signature label Woodpecker uses. Also the historical key id, though the
/// current server emits no `keyid` parameter.
const SIGNATURE_LABEL: &str = "woodpecker-ci-extensions";
const COVERED_COMPONENTS: &str = "(\"@request-target\" \"content-digest\")";
/// Matches `httpsign.NewVerifyConfig()`; do not tighten without checking clock
/// skew between the Woodpecker and broker containers.
const NOT_NEWER_THAN: Duration = Duration::from_secs(2);
const NOT_OLDER_THAN: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum SignatureError {
    #[error("signature headers are missing")]
    MissingHeaders,
    #[error("signature headers are not valid text")]
    NotAscii,
    #[error("signature label is unknown")]
    UnknownLabel,
    #[error("signature input is malformed")]
    MalformedInput,
    #[error("covered components are not supported")]
    UnexpectedComponents,
    #[error("signature algorithm is not supported")]
    UnsupportedAlgorithm,
    #[error("signature creation time is out of range")]
    CreatedOutOfRange,
    #[error("content digest is missing")]
    MissingDigest,
    #[error("content digest is malformed")]
    MalformedDigest,
    #[error("content digest does not match the body")]
    DigestMismatch,
    #[error("signature is invalid")]
    BadSignature,
}

impl SignatureError {
    /// A bounded label for the failure metric. Never derived from request data.
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::MissingHeaders => "missing_headers",
            Self::NotAscii => "not_ascii",
            Self::UnknownLabel => "unknown_label",
            Self::MalformedInput => "malformed_input",
            Self::UnexpectedComponents => "unexpected_components",
            Self::UnsupportedAlgorithm => "unsupported_algorithm",
            Self::CreatedOutOfRange => "created_out_of_range",
            Self::MissingDigest => "missing_digest",
            Self::MalformedDigest => "malformed_digest",
            Self::DigestMismatch => "digest_mismatch",
            Self::BadSignature => "bad_signature",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum KeyError {
    #[error("the Woodpecker signing key is not a PEM Ed25519 public key")]
    Malformed,
}

pub(crate) struct SignatureVerifier {
    key: VerifyingKey,
}

impl SignatureVerifier {
    /// Loads an Ed25519 verifying key from a PEM SPKI document — the exact
    /// output of Woodpecker's `/api/signature/public-key`.
    ///
    /// # Errors
    ///
    /// Fails when the document is not PEM SPKI, or holds a key of another type.
    pub(crate) fn from_spki_pem(pem: &str) -> Result<Self, KeyError> {
        VerifyingKey::from_public_key_pem(pem)
            .map(|key| Self { key })
            .map_err(|_| KeyError::Malformed)
    }

    /// Verifies the signature over `request_target` and the body's digest.
    ///
    /// `request_target` is the path with its query when present, matching
    /// `httpsign`'s `scRequestTarget`. `now` is injected so tests are hermetic.
    ///
    /// # Errors
    ///
    /// Returns the specific [`SignatureError`]; callers map every variant to
    /// 401 and report only the bounded [`SignatureError::reason`].
    pub(crate) fn verify(
        &self,
        request_target: &str,
        headers: &http::HeaderMap,
        body: &[u8],
        now: SystemTime,
    ) -> Result<(), SignatureError> {
        let input = single_header(headers, "signature-input")?;
        let signature = single_header(headers, "signature")?;

        let params = dictionary_entry(input, SIGNATURE_LABEL)?;
        validate_params(params, now)?;

        let digest = single_header(headers, "content-digest").map_err(|error| match error {
            SignatureError::MissingHeaders => SignatureError::MissingDigest,
            other => other,
        })?;
        verify_digest(digest, body)?;

        let raw_signature = dictionary_entry(signature, SIGNATURE_LABEL)?;
        let bytes = decode_byte_sequence(raw_signature).ok_or(SignatureError::MalformedInput)?;
        let signature: [u8; 64] = bytes
            .try_into()
            .map_err(|_| SignatureError::MalformedInput)?;

        // Field values are folded exactly as httpsign does: trimmed of leading
        // and trailing whitespace. The @signature-params line is the received
        // value verbatim.
        let base = format!(
            "\"@request-target\": {request_target}\n\"content-digest\": {}\n\"@signature-params\": {params}",
            digest.trim()
        );

        self.key
            .verify_strict(base.as_bytes(), &Signature::from_bytes(&signature))
            .map_err(|_| SignatureError::BadSignature)
    }
}

/// Reads exactly one occurrence of a header. Two `Signature` headers would make
/// "which signature was verified" ambiguous, so that is a rejection.
fn single_header<'h>(headers: &'h http::HeaderMap, name: &str) -> Result<&'h str, SignatureError> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(SignatureError::MissingHeaders)?;
    if values.next().is_some() {
        return Err(SignatureError::MalformedInput);
    }
    value.to_str().map_err(|_| SignatureError::NotAscii)
}

/// Extracts one member's value from a structured-field dictionary, preserving
/// the raw text.
///
/// Splits on top-level commas only — commas inside quoted strings and inner
/// lists belong to the member. The profile carries exactly one member, so
/// anything else is rejected rather than searched.
fn dictionary_entry<'v>(value: &'v str, label: &str) -> Result<&'v str, SignatureError> {
    let mut members = Vec::new();
    let (mut start, mut quoted, mut depth) = (0usize, false, 0usize);
    for (index, character) in value.char_indices() {
        match character {
            '"' => quoted = !quoted,
            '(' if !quoted => depth += 1,
            ')' if !quoted => depth = depth.checked_sub(1).ok_or(SignatureError::MalformedInput)?,
            ',' if !quoted && depth == 0 => {
                members.push(&value[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    if quoted || depth != 0 {
        return Err(SignatureError::MalformedInput);
    }
    members.push(&value[start..]);

    if members.len() != 1 {
        return Err(SignatureError::MalformedInput);
    }
    let (key, rest) = members[0]
        .trim()
        .split_once('=')
        .ok_or(SignatureError::MalformedInput)?;
    if key.trim() != label {
        return Err(SignatureError::UnknownLabel);
    }
    Ok(rest.trim())
}

/// Validates the covered components and parameters of the signature input.
fn validate_params(params: &str, now: SystemTime) -> Result<(), SignatureError> {
    let rest = params
        .strip_prefix(COVERED_COMPONENTS)
        .ok_or(SignatureError::UnexpectedComponents)?;

    let (mut created, mut algorithm, mut expires) = (None, None, None);
    for parameter in rest.split(';') {
        let parameter = parameter.trim();
        if parameter.is_empty() {
            continue;
        }
        let (name, value) = parameter
            .split_once('=')
            .ok_or(SignatureError::MalformedInput)?;
        match name.trim() {
            "created" => {
                created = Some(
                    value
                        .trim()
                        .parse::<u64>()
                        .map_err(|_| SignatureError::MalformedInput)?,
                );
            }
            "expires" => {
                expires = Some(
                    value
                        .trim()
                        .parse::<u64>()
                        .map_err(|_| SignatureError::MalformedInput)?,
                );
            }
            "alg" => algorithm = Some(value.trim().trim_matches('"').to_owned()),
            // Woodpecker emits no keyid today; accept and pin it if one appears.
            "keyid" => {
                if value.trim().trim_matches('"') != SIGNATURE_LABEL {
                    return Err(SignatureError::UnknownLabel);
                }
            }
            "nonce" | "tag" => {}
            _ => return Err(SignatureError::MalformedInput),
        }
    }

    if algorithm.as_deref() != Some("ed25519") {
        return Err(SignatureError::UnsupportedAlgorithm);
    }

    let created = created.ok_or(SignatureError::MalformedInput)?;
    let now_secs = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SignatureError::CreatedOutOfRange)?
        .as_secs();
    let newest = now_secs.saturating_add(NOT_NEWER_THAN.as_secs());
    let oldest = now_secs.saturating_sub(NOT_OLDER_THAN.as_secs());
    if created > newest || created < oldest {
        return Err(SignatureError::CreatedOutOfRange);
    }
    if expires.is_some_and(|expires| expires < now_secs) {
        return Err(SignatureError::CreatedOutOfRange);
    }
    Ok(())
}

/// Recomputes the body digest and compares it in constant time.
///
/// This is the check the Go broker omits. Without it the signature only proves
/// that *some* body was signed, not that this is the body that arrived.
fn verify_digest(header: &str, body: &[u8]) -> Result<(), SignatureError> {
    let mut checked = false;
    for member in header.split(',') {
        let Some((algorithm, value)) = member.trim().split_once('=') else {
            return Err(SignatureError::MalformedDigest);
        };
        if algorithm.trim() != "sha-256" {
            // Another scheme (e.g. sha-512) is not something this profile
            // produces; ignore rather than fail, but require sha-256 present.
            continue;
        }
        let expected = decode_byte_sequence(value.trim()).ok_or(SignatureError::MalformedDigest)?;
        let actual = Sha256::digest(body);
        if actual.as_slice().ct_eq(expected.as_slice()).into() {
            checked = true;
        } else {
            return Err(SignatureError::DigestMismatch);
        }
    }
    if checked {
        Ok(())
    } else {
        Err(SignatureError::MalformedDigest)
    }
}

/// Decodes a structured-field byte sequence, `:<base64>:`.
fn decode_byte_sequence(value: &str) -> Option<Vec<u8>> {
    let inner = value.trim().strip_prefix(':')?.strip_suffix(':')?;
    STANDARD.decode(inner).ok()
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use base64::{Engine, engine::general_purpose::STANDARD};
    use ed25519_dalek::{Signer, SigningKey, pkcs8::EncodePublicKey};
    use sha2::{Digest, Sha256};

    use super::{SignatureError, SignatureVerifier};

    const BODY: &[u8] = br#"{"repo":{"owner":"vcheesbrough","name":"sovereign-config","full_name":"vcheesbrough/sovereign-config"},"pipeline":{"branch":"main","event":"push"}}"#;
    const TARGET: &str = "/secrets";

    /// A signer mirroring Woodpecker's, so the fixtures are produced the same
    /// way the real server produces them.
    struct Fixture {
        key: SigningKey,
        created: u64,
        target: String,
        body: Vec<u8>,
        components: String,
        label: String,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                key: SigningKey::from_bytes(&[7u8; 32]),
                created: 1_700_000_000,
                target: TARGET.to_owned(),
                body: BODY.to_vec(),
                components: "(\"@request-target\" \"content-digest\")".to_owned(),
                label: "woodpecker-ci-extensions".to_owned(),
            }
        }

        fn now(&self) -> SystemTime {
            UNIX_EPOCH + Duration::from_secs(self.created)
        }

        fn digest_of(bytes: &[u8]) -> String {
            format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(bytes)))
        }

        /// Signs `self.body` and returns the headers, optionally with a digest
        /// computed over different bytes so a mismatch can be exercised.
        fn headers(&self, digest_over: Option<&[u8]>) -> http::HeaderMap {
            let digest = Self::digest_of(digest_over.unwrap_or(&self.body));
            let params = format!(
                "{};created={};alg=\"ed25519\"",
                self.components, self.created
            );
            let base = format!(
                "\"@request-target\": {}\n\"content-digest\": {digest}\n\"@signature-params\": {params}",
                self.target
            );
            let signature = self.key.sign(base.as_bytes());

            let mut headers = http::HeaderMap::new();
            headers.insert("content-digest", digest.parse().unwrap());
            headers.insert(
                "signature-input",
                format!("{}={params}", self.label).parse().unwrap(),
            );
            headers.insert(
                "signature",
                format!("{}=:{}:", self.label, STANDARD.encode(signature.to_bytes()))
                    .parse()
                    .unwrap(),
            );
            headers
        }

        fn verifier(&self) -> SignatureVerifier {
            let pem = self
                .key
                .verifying_key()
                .to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
                .unwrap();
            SignatureVerifier::from_spki_pem(&pem).unwrap()
        }

        fn verify(&self, headers: &http::HeaderMap, body: &[u8]) -> Result<(), SignatureError> {
            self.verifier()
                .verify(&self.target, headers, body, self.now())
        }
    }

    #[test]
    fn a_correctly_signed_request_verifies() {
        let fixture = Fixture::new();
        assert!(fixture.verify(&fixture.headers(None), BODY).is_ok());
    }

    // The control for the hole in the Go broker: the signature is genuine and
    // its `created` is fresh, but the digest covers different bytes than the
    // body that arrived. Accepting this would let a captured request be
    // replayed with forged repo metadata.
    #[test]
    fn a_body_that_does_not_match_the_signed_digest_is_rejected() {
        let fixture = Fixture::new();
        let forged = br#"{"repo":{"owner":"attacker","name":"evil","full_name":"attacker/evil"},"pipeline":{"branch":"main","event":"push"}}"#;

        // Signature and digest are self-consistent, but the body is not the one
        // the digest describes.
        assert_eq!(
            fixture.verify(&fixture.headers(None), forged).unwrap_err(),
            SignatureError::DigestMismatch
        );
        // And the mirror image: digest computed over the forged body, so the
        // digest header no longer matches the delivered body either.
        assert_eq!(
            fixture
                .verify(&fixture.headers(Some(forged)), BODY)
                .unwrap_err(),
            SignatureError::DigestMismatch
        );
    }

    #[test]
    fn a_tampered_signature_or_wrong_key_is_rejected() {
        let fixture = Fixture::new();
        let mut headers = fixture.headers(None);
        let flipped = {
            let raw = headers.get("signature").unwrap().to_str().unwrap();
            let encoded = raw
                .trim_start_matches("woodpecker-ci-extensions=:")
                .trim_end_matches(':');
            let mut bytes = STANDARD.decode(encoded).unwrap();
            bytes[0] ^= 0x01;
            format!("woodpecker-ci-extensions=:{}:", STANDARD.encode(bytes))
        };
        headers.insert("signature", flipped.parse().unwrap());
        assert_eq!(
            fixture.verify(&headers, BODY).unwrap_err(),
            SignatureError::BadSignature
        );

        let other = Fixture {
            key: SigningKey::from_bytes(&[9u8; 32]),
            ..Fixture::new()
        };
        assert_eq!(
            other
                .verifier()
                .verify(TARGET, &fixture.headers(None), BODY, fixture.now())
                .unwrap_err(),
            SignatureError::BadSignature
        );
    }

    #[test]
    fn the_request_target_is_covered() {
        let fixture = Fixture::new();
        assert_eq!(
            fixture
                .verifier()
                .verify("/other", &fixture.headers(None), BODY, fixture.now())
                .unwrap_err(),
            SignatureError::BadSignature
        );
    }

    #[test]
    fn creation_time_must_be_fresh_in_both_directions() {
        let fixture = Fixture::new();
        let headers = fixture.headers(None);
        let verifier = fixture.verifier();

        // `offset` shifts *now* relative to `created`, so a positive offset is
        // an aged signature and a negative one is a signature from the future.
        // httpsign accepts an age of up to 10s and a skew of up to 2s ahead.
        for offset in [-2i64, -1, 0, 1, 9, 10] {
            let now = shift(fixture.now(), offset);
            assert!(
                verifier.verify(TARGET, &headers, BODY, now).is_ok(),
                "rejected offset {offset}"
            );
        }
        for offset in [-3i64, -60, 11, 3600] {
            let now = shift(fixture.now(), offset);
            assert_eq!(
                verifier.verify(TARGET, &headers, BODY, now).unwrap_err(),
                SignatureError::CreatedOutOfRange,
                "accepted offset {offset}"
            );
        }
    }

    #[test]
    fn only_this_profile_is_accepted() {
        // An extra covered component means the base is not what we rebuild.
        let extra = Fixture {
            components: "(\"@method\" \"@request-target\" \"content-digest\")".to_owned(),
            ..Fixture::new()
        };
        assert_eq!(
            extra.verify(&extra.headers(None), BODY).unwrap_err(),
            SignatureError::UnexpectedComponents
        );

        // A signature under a different label is not ours.
        let relabelled = Fixture {
            label: "some-other-extension".to_owned(),
            ..Fixture::new()
        };
        assert_eq!(
            relabelled
                .verify(&relabelled.headers(None), BODY)
                .unwrap_err(),
            SignatureError::UnknownLabel
        );
    }

    #[test]
    fn missing_or_malformed_headers_are_rejected() {
        let fixture = Fixture::new();

        assert_eq!(
            fixture.verify(&http::HeaderMap::new(), BODY).unwrap_err(),
            SignatureError::MissingHeaders
        );

        let mut without_digest = fixture.headers(None);
        without_digest.remove("content-digest");
        assert_eq!(
            fixture.verify(&without_digest, BODY).unwrap_err(),
            SignatureError::MissingDigest
        );

        let mut bad_digest = fixture.headers(None);
        bad_digest.insert(
            "content-digest",
            "sha-256=not-a-byte-sequence".parse().unwrap(),
        );
        assert_eq!(
            fixture.verify(&bad_digest, BODY).unwrap_err(),
            SignatureError::MalformedDigest
        );

        // A digest naming only an unsupported scheme leaves nothing checked.
        let mut foreign_digest = fixture.headers(None);
        foreign_digest.insert("content-digest", "sha-512=:AAAA:".parse().unwrap());
        assert_eq!(
            fixture.verify(&foreign_digest, BODY).unwrap_err(),
            SignatureError::MalformedDigest
        );

        let mut two_signatures = fixture.headers(None);
        two_signatures.append("signature", "other=:AAAA:".parse().unwrap());
        assert_eq!(
            fixture.verify(&two_signatures, BODY).unwrap_err(),
            SignatureError::MalformedInput
        );

        let mut junk_input = fixture.headers(None);
        junk_input.insert("signature-input", "not-a-dictionary".parse().unwrap());
        assert_eq!(
            fixture.verify(&junk_input, BODY).unwrap_err(),
            SignatureError::MalformedInput
        );
    }

    #[test]
    fn a_non_ed25519_algorithm_is_refused() {
        let fixture = Fixture::new();
        let mut headers = fixture.headers(None);
        let params = format!(
            "(\"@request-target\" \"content-digest\");created={};alg=\"hmac-sha256\"",
            fixture.created
        );
        headers.insert(
            "signature-input",
            format!("woodpecker-ci-extensions={params}")
                .parse()
                .unwrap(),
        );
        assert_eq!(
            fixture.verify(&headers, BODY).unwrap_err(),
            SignatureError::UnsupportedAlgorithm
        );
    }

    #[test]
    fn a_key_that_is_not_ed25519_spki_is_refused() {
        assert!(SignatureVerifier::from_spki_pem("not a pem document").is_err());
        assert!(
            SignatureVerifier::from_spki_pem(
                "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"
            )
            .is_err()
        );
    }

    // The key format the live deployment mounts (devops-stack/woodpecker-pubkey.pem).
    #[test]
    fn the_deployed_public_key_format_loads() {
        let pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAGG8cr7qLEs6Ee5mZFSx3/rKpClRncL2+A81n7SIWOe4=\n-----END PUBLIC KEY-----\n";
        assert!(SignatureVerifier::from_spki_pem(pem).is_ok());
    }

    fn shift(base: SystemTime, seconds: i64) -> SystemTime {
        if seconds >= 0 {
            base + Duration::from_secs(seconds.unsigned_abs())
        } else {
            base - Duration::from_secs(seconds.unsigned_abs())
        }
    }
}
