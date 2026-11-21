//! The `v6` wire shim over [`super::ConfigurationService`]: the shared
//! adapter in [`super::shim`], pointed at `v6`'s generated types and written
//! in `v6`'s wire form ([`JsonSafe`]: 32-bit counts, microsecond timestamps).
//!
//! `v6` validates its own input before the shared implementation authorizes
//! ([`Upfront`]), as `v4` and `v5` do. It is served over Connect only; the
//! Connect bridge (`crate::connect`) is what reaches it, and it also refuses
//! a binary request that sets two members of a `oneof`
//! ([`sets_two_members`]) — the JSON decoder refuses the same request itself.

use sovereign_config_proto::sovereign::config::v6 as proto;

use super::shim::{Upfront, configuration_shim};
use crate::rpc::JsonSafe;

configuration_shim!(V6Configuration, Upfront, JsonSafe);

/// The `content` members of `PutValueRequest` (`plain_value`, `secret_value`)
/// and of `SubTreeMutationValue` (`plain_value`, `preserve_secret`).
const CONTENT_MEMBERS: [u32; 2] = [2, 3];
/// `ReplaceSubTreeRequest.values`, each a `SubTreeMutationValue`.
const SUBTREE_VALUES: u32 = 2;

/// Which `v6` request's encoded body [`sets_two_members`] reads.
#[derive(Clone, Copy, Debug)]
pub(crate) enum OneofRequest {
    PutValue,
    ReplaceSubTree,
}

/// Whether a **binary** `PutValue` or `ReplaceSubTree` body sets more than
/// one member of a `content` oneof — counting a repeated member once per
/// time it appears.
///
/// A protobuf decoder keeps the last member it reads, so by the time the
/// shim sees the request the evidence is gone; this reads the encoded bytes
/// instead. `v6` refuses such a request `INVALID_ARGUMENT`, because the same
/// request in JSON is refused by the JSON decoder and behaviour must not
/// depend on the encoding. A body that does not parse is left to the decoder,
/// which refuses it on its own terms.
pub(crate) fn sets_two_members(request: OneofRequest, body: &[u8]) -> bool {
    match request {
        OneofRequest::PutValue => content_members(body).is_some_and(|count| count > 1),
        OneofRequest::ReplaceSubTree => {
            let mut found = false;
            let walked = walk(body, |field, value| {
                if field == SUBTREE_VALUES
                    && let Field::Bytes(entry) = value
                    && content_members(entry).is_some_and(|count| count > 1)
                {
                    found = true;
                }
            });
            walked.is_some() && found
        }
    }
}

fn content_members(message: &[u8]) -> Option<usize> {
    let mut count = 0;
    walk(message, |field, _| {
        if CONTENT_MEMBERS.contains(&field) {
            count += 1;
        }
    })?;
    Some(count)
}

enum Field<'a> {
    Scalar,
    Bytes(&'a [u8]),
}

/// Calls `visit` with every top-level field of an encoded message, or
/// returns `None` when the bytes are not a well-formed message.
fn walk<'a>(mut bytes: &'a [u8], mut visit: impl FnMut(u32, Field<'a>)) -> Option<()> {
    while !bytes.is_empty() {
        let key = varint(&mut bytes)?;
        let field = u32::try_from(key >> 3).ok()?;
        match key & 0x7 {
            0 => {
                varint(&mut bytes)?;
                visit(field, Field::Scalar);
            }
            1 => {
                bytes = bytes.get(8..)?;
                visit(field, Field::Scalar);
            }
            2 => {
                let length = usize::try_from(varint(&mut bytes)?).ok()?;
                let value = bytes.get(..length)?;
                bytes = &bytes[length..];
                visit(field, Field::Bytes(value));
            }
            5 => {
                bytes = bytes.get(4..)?;
                visit(field, Field::Scalar);
            }
            _ => return None,
        }
    }
    Some(())
}

fn varint(bytes: &mut &[u8]) -> Option<u64> {
    let mut value = 0_u64;
    for shift in (0..64).step_by(7) {
        let (&byte, rest) = bytes.split_first()?;
        *bytes = rest;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use prost::Message;
    use sovereign_config_proto::sovereign::config::v6 as proto;

    use super::{OneofRequest, sets_two_members};

    fn put(content: proto::put_value_request::Content) -> Vec<u8> {
        proto::PutValueRequest {
            path: "/apps/api/key".into(),
            content: Some(content),
        }
        .encode_to_vec()
    }

    #[test]
    fn one_member_is_not_two() {
        let body = put(proto::put_value_request::Content::PlainValue("a".into()));
        assert!(!sets_two_members(OneofRequest::PutValue, &body));
        let empty = proto::PutValueRequest::default().encode_to_vec();
        assert!(!sets_two_members(OneofRequest::PutValue, &empty));
    }

    #[test]
    fn two_members_of_a_put_value_are_found() {
        let mut body = put(proto::put_value_request::Content::PlainValue("a".into()));
        body.extend(put(proto::put_value_request::Content::SecretValue(
            "b".into(),
        )));
        assert!(sets_two_members(OneofRequest::PutValue, &body));
    }

    #[test]
    fn the_same_member_twice_is_two() {
        let mut body = put(proto::put_value_request::Content::PlainValue("a".into()));
        body.extend(put(proto::put_value_request::Content::PlainValue(
            "b".into(),
        )));
        assert!(sets_two_members(OneofRequest::PutValue, &body));
    }

    #[test]
    fn two_members_in_one_subtree_entry_are_found() {
        let entry = |content| proto::SubTreeMutationValue {
            path: "/apps/api/key".into(),
            content: Some(content),
        };
        let plain = entry(proto::sub_tree_mutation_value::Content::PlainValue(
            "a".into(),
        ));
        let preserve = entry(proto::sub_tree_mutation_value::Content::PreserveSecret(
            proto::PreserveSecret {},
        ));
        let clean = proto::ReplaceSubTreeRequest {
            path: "/apps".into(),
            values: vec![plain.clone(), preserve.clone()],
        };
        assert!(!sets_two_members(
            OneofRequest::ReplaceSubTree,
            &clean.encode_to_vec()
        ));
        let mut doubled = plain.encode_to_vec();
        doubled.extend(preserve.encode_to_vec());
        let mut body = proto::ReplaceSubTreeRequest {
            path: "/apps".into(),
            values: vec![plain],
        }
        .encode_to_vec();
        body.push(0x12);
        body.push(u8::try_from(doubled.len()).unwrap());
        body.extend(doubled);
        assert!(sets_two_members(OneofRequest::ReplaceSubTree, &body));
    }

    #[test]
    fn a_body_that_does_not_parse_is_left_to_the_decoder() {
        assert!(!sets_two_members(
            OneofRequest::PutValue,
            &[0x12, 0x05, b'a']
        ));
        assert!(!sets_two_members(OneofRequest::ReplaceSubTree, &[0xff]));
    }
}
