use sovereign_config_proto::sovereign::config::v3::{
    MaskedSecret, ValueClassification, listed_value, sub_tree_value,
};

use super::{PLAIN, SECRET};

/// Renders a stored value for a listing.
///
/// A secret's stored representation is dropped here rather than decrypted:
/// listings mask secrets, so the ciphertext must not travel any further.
pub(super) fn listed_content(
    value: String,
    classification: &str,
) -> Option<(i32, listed_value::Content)> {
    match classification {
        PLAIN => Some((
            ValueClassification::Plain as i32,
            listed_value::Content::PlainValue(value),
        )),
        SECRET => Some((
            ValueClassification::Secret as i32,
            listed_value::Content::MaskedSecret(MaskedSecret {}),
        )),
        _ => None,
    }
}

/// Renders a stored value for a subtree read. Masks secrets exactly as
/// [`listed_content`] does, so ciphertext never leaves the server here either.
pub(super) fn subtree_content(
    value: String,
    classification: &str,
) -> Option<(i32, sub_tree_value::Content)> {
    match classification {
        PLAIN => Some((
            ValueClassification::Plain as i32,
            sub_tree_value::Content::PlainValue(value),
        )),
        SECRET => Some((
            ValueClassification::Secret as i32,
            sub_tree_value::Content::MaskedSecret(MaskedSecret {}),
        )),
        _ => None,
    }
}
