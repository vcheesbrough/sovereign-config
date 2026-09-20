use sovereign_config_core::{MaskedSecret, PlainValue, ValueContent};

use super::{PLAIN, SECRET};

/// Renders a stored value for a listing or a subtree read.
///
/// A secret's stored representation is dropped here rather than decrypted:
/// both reads mask secrets, so the ciphertext must not travel any further.
/// This runs before any protocol version's shim sees the value, so masking is
/// never something a version has to remember to do.
pub(super) fn masked_content(value: String, classification: &str) -> Option<ValueContent> {
    match classification {
        PLAIN => Some(ValueContent::Plain(PlainValue::new(value))),
        SECRET => Some(ValueContent::Secret(MaskedSecret)),
        _ => None,
    }
}
