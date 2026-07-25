//! Application-level encryption for secret-classified configuration values.
//!
//! Secrets are encrypted here, in the server, so `PostgreSQL` only ever holds
//! ciphertext: a `pg_dump`, a backup, a replication stream, or direct SQL
//! access yields nothing readable. The deployment's data volume is operator
//! storage we cannot vouch for, so this is the at-rest boundary rather than a
//! second layer behind one.
//!
//! This module is deliberately server-only. `sovereign-config-core` is
//! wasm-compatible and ships to every client; the value encryption key must
//! never leave the server.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use zeroize::Zeroize;

/// Marks a stored value as an envelope produced by this module. The `v1`
/// component names the key that sealed it, so a future rotation can introduce
/// `v2` alongside it without a schema change or a rewrite of every row.
const ENVELOPE_PREFIX: &str = "enc:v1:";

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

/// Why a stored value could not be turned back into plaintext.
///
/// Every variant is a hard failure. Falling back to returning the stored bytes
/// would hand a caller raw ciphertext dressed up as a secret, so callers must
/// surface an error instead.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DecryptError {
    /// The stored value is not an envelope at all — legacy plaintext, or a
    /// row written by a server that predates encryption.
    NotEncrypted,
    /// The envelope is structurally broken: bad base64, or too short to hold
    /// a nonce and a tag.
    Malformed,
    /// The envelope is well-formed but did not authenticate. The key is wrong,
    /// the ciphertext was tampered with, or it was moved here from another row.
    Unauthenticated,
    /// The decrypted bytes were not UTF-8, so they cannot be a configuration
    /// value.
    NotUtf8,
}

impl fmt::Display for DecryptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self {
            Self::NotEncrypted => "value is not encrypted",
            Self::Malformed => "encrypted value is malformed",
            Self::Unauthenticated => "encrypted value failed authentication",
            Self::NotUtf8 => "decrypted value is not valid UTF-8",
        };
        formatter.write_str(reason)
    }
}

impl std::error::Error for DecryptError {}

/// Encrypting failed. Carries no detail on purpose: the only realistic cause is
/// a value larger than the AEAD can handle, and anything more specific risks
/// describing the plaintext.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct EncryptError;

impl fmt::Display for EncryptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("value could not be encrypted")
    }
}

impl std::error::Error for EncryptError {}

/// Seals and opens secret configuration values.
///
/// Holds the key for the lifetime of the process. It has no `Debug`, `Display`,
/// `Clone`, or serialization impl, so the key cannot be printed, logged, or
/// copied out by accident, and `XChaCha20Poly1305` wipes it on drop.
pub(crate) struct ValueCipher {
    cipher: XChaCha20Poly1305,
}

impl ValueCipher {
    /// Builds a cipher from raw key bytes, wiping the caller's copy.
    pub(crate) fn new(key_bytes: &mut [u8; KEY_LEN]) -> Self {
        let key = Key::from(*key_bytes);
        let cipher = XChaCha20Poly1305::new(&key);
        key_bytes.zeroize();
        Self { cipher }
    }

    /// Encrypts `plaintext` for the content row it will be stored in.
    ///
    /// XChaCha20-Poly1305's 24-byte nonce is large enough that a random nonce
    /// per write is safe without tracking a counter across restarts or
    /// replicas.
    pub(crate) fn encrypt(
        &self,
        content_id: i64,
        classification: &str,
        plaintext: &str,
    ) -> Result<String, EncryptError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce_bytes).map_err(|_| EncryptError)?;
        let nonce = XNonce::from(nonce_bytes);

        let aad = associated_data(content_id, classification);
        let ciphertext = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| EncryptError)?;

        let mut envelope = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&ciphertext);
        Ok(format!("{ENVELOPE_PREFIX}{}", STANDARD.encode(&envelope)))
    }

    /// Recovers the plaintext of a stored envelope.
    ///
    /// `content_id` and `classification` must match the row the envelope was
    /// read from. They are authenticated but not encrypted, so an envelope
    /// copied onto a different row — by anyone with SQL write access — fails
    /// here rather than revealing one value under another value's path.
    pub(crate) fn decrypt(
        &self,
        content_id: i64,
        classification: &str,
        stored: &str,
    ) -> Result<String, DecryptError> {
        let encoded = stored
            .strip_prefix(ENVELOPE_PREFIX)
            .ok_or(DecryptError::NotEncrypted)?;
        let envelope = STANDARD
            .decode(encoded)
            .map_err(|_| DecryptError::Malformed)?;
        if envelope.len() <= NONCE_LEN {
            return Err(DecryptError::Malformed);
        }
        let (nonce_bytes, ciphertext) = envelope.split_at(NONCE_LEN);
        let nonce = XNonce::try_from(nonce_bytes).map_err(|_| DecryptError::Malformed)?;

        let aad = associated_data(content_id, classification);
        let plaintext = self
            .cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| DecryptError::Unauthenticated)?;

        String::from_utf8(plaintext).map_err(|_| DecryptError::NotUtf8)
    }
}

/// True when a stored value carries this module's envelope.
///
/// Used by the startup backfill to tell an already-encrypted row from legacy
/// plaintext. It is a claim about the format only — a value that passes here
/// can still fail to authenticate.
pub(crate) fn is_envelope(stored: &str) -> bool {
    stored.starts_with(ENVELOPE_PREFIX)
}

/// Decodes the base64 key an operator supplies.
///
/// Errors name only what is wrong with the shape, never any part of the key
/// itself, so a startup failure can be logged safely.
pub(crate) fn decode_key(encoded: &str) -> Result<[u8; KEY_LEN], KeyError> {
    let mut decoded = STANDARD
        .decode(encoded.trim())
        .map_err(|_| KeyError::NotBase64)?;
    let result = <[u8; KEY_LEN]>::try_from(decoded.as_slice())
        .map_err(|_| KeyError::WrongLength(decoded.len()));
    decoded.zeroize();
    result
}

/// Why a supplied key is unusable.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum KeyError {
    NotBase64,
    WrongLength(usize),
}

impl fmt::Display for KeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotBase64 => formatter.write_str("must be standard base64"),
            Self::WrongLength(actual) => write!(
                formatter,
                "must decode to {KEY_LEN} bytes, but decoded to {actual}"
            ),
        }
    }
}

impl std::error::Error for KeyError {}

/// Binds an envelope to the row that stores it.
///
/// The content row's identity is the only stable anchor available: a value is
/// reachable from many alias paths, so a path cannot identify the row holding
/// the ciphertext.
fn associated_data(content_id: i64, classification: &str) -> String {
    format!("sovereign-config:value:v1:{content_id}:{classification}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "secret";

    fn cipher_from(seed: u8) -> ValueCipher {
        let mut key = [seed; KEY_LEN];
        ValueCipher::new(&mut key)
    }

    #[test]
    fn encrypted_values_round_trip() {
        let cipher = cipher_from(1);
        let sealed = cipher.encrypt(42, SECRET, "hunter2").unwrap();

        assert!(is_envelope(&sealed));
        assert!(!sealed.contains("hunter2"));
        assert_eq!(cipher.decrypt(42, SECRET, &sealed).unwrap(), "hunter2");
    }

    #[test]
    fn each_encryption_uses_a_fresh_nonce() {
        let cipher = cipher_from(1);
        let first = cipher.encrypt(42, SECRET, "hunter2").unwrap();
        let second = cipher.encrypt(42, SECRET, "hunter2").unwrap();

        assert_ne!(first, second);
        assert_eq!(cipher.decrypt(42, SECRET, &first).unwrap(), "hunter2");
        assert_eq!(cipher.decrypt(42, SECRET, &second).unwrap(), "hunter2");
    }

    #[test]
    fn empty_and_multibyte_values_round_trip() {
        let cipher = cipher_from(1);
        for plaintext in ["", "🔐 ünïcødé", &"x".repeat(64 * 1024)] {
            let sealed = cipher.encrypt(7, SECRET, plaintext).unwrap();
            assert_eq!(cipher.decrypt(7, SECRET, &sealed).unwrap(), plaintext);
        }
    }

    #[test]
    fn an_envelope_moved_to_another_content_row_is_rejected() {
        let cipher = cipher_from(1);
        let sealed = cipher.encrypt(42, SECRET, "hunter2").unwrap();

        assert_eq!(
            cipher.decrypt(43, SECRET, &sealed),
            Err(DecryptError::Unauthenticated)
        );
    }

    #[test]
    fn an_envelope_read_under_another_classification_is_rejected() {
        let cipher = cipher_from(1);
        let sealed = cipher.encrypt(42, SECRET, "hunter2").unwrap();

        assert_eq!(
            cipher.decrypt(42, "plain", &sealed),
            Err(DecryptError::Unauthenticated)
        );
    }

    #[test]
    fn another_key_cannot_open_the_envelope() {
        let sealed = cipher_from(1).encrypt(42, SECRET, "hunter2").unwrap();

        assert_eq!(
            cipher_from(2).decrypt(42, SECRET, &sealed),
            Err(DecryptError::Unauthenticated)
        );
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let cipher = cipher_from(1);
        let sealed = cipher.encrypt(42, SECRET, "hunter2").unwrap();
        let mut envelope = STANDARD
            .decode(sealed.strip_prefix(ENVELOPE_PREFIX).unwrap())
            .unwrap();
        let last = envelope.len() - 1;
        envelope[last] ^= 0x01;
        let tampered = format!("{ENVELOPE_PREFIX}{}", STANDARD.encode(&envelope));

        assert_eq!(
            cipher.decrypt(42, SECRET, &tampered),
            Err(DecryptError::Unauthenticated)
        );
    }

    #[test]
    fn plaintext_is_reported_as_not_encrypted() {
        let cipher = cipher_from(1);

        assert!(!is_envelope("hunter2"));
        assert_eq!(
            cipher.decrypt(42, SECRET, "hunter2"),
            Err(DecryptError::NotEncrypted)
        );
    }

    #[test]
    fn structurally_broken_envelopes_are_rejected() {
        let cipher = cipher_from(1);
        let truncated = format!("{ENVELOPE_PREFIX}{}", STANDARD.encode([0u8; NONCE_LEN]));

        assert_eq!(
            cipher.decrypt(42, SECRET, &format!("{ENVELOPE_PREFIX}not base64!")),
            Err(DecryptError::Malformed)
        );
        assert_eq!(
            cipher.decrypt(42, SECRET, &truncated),
            Err(DecryptError::Malformed)
        );
    }

    #[test]
    fn decode_key_accepts_thirty_two_bytes() {
        let encoded = STANDARD.encode([7u8; KEY_LEN]);

        assert_eq!(decode_key(&encoded).unwrap(), [7u8; KEY_LEN]);
        assert_eq!(
            decode_key(&format!("  {encoded}\n")).unwrap(),
            [7u8; KEY_LEN]
        );
    }

    #[test]
    fn decode_key_rejects_bad_shapes() {
        assert_eq!(decode_key("not base64!"), Err(KeyError::NotBase64));
        assert_eq!(
            decode_key(&STANDARD.encode([7u8; 16])),
            Err(KeyError::WrongLength(16))
        );
        assert_eq!(decode_key(""), Err(KeyError::WrongLength(0)));
    }

    #[test]
    fn key_errors_never_echo_key_material() {
        let encoded = STANDARD.encode([7u8; 16]);
        let message = decode_key(&encoded).unwrap_err().to_string();

        assert!(!message.contains(&encoded));
    }
}
