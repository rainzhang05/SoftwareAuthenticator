//! Canonical CBOR helpers shared by the CTAP2 command handlers.

use ciborium::{ser::into_writer, value::Value};
use std::cmp::Ordering;

use crate::ctap::constants::CTAP2_ERR_INVALID_CBOR;

/// The CBOR encoding of a map key.
fn encode_key(key: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    into_writer(key, &mut bytes).expect("serialize a map key into memory");
    bytes
}

/// The order of two map keys in the CTAP2 canonical CBOR encoding form: by
/// major type first, then by encoded length and bytes (see
/// [`canonical_key_order`]).  ciborium's `Integer::canonical_cmp` compares
/// lengths first, the older RFC 7049 rule, which would put -1 before 24.
fn canonical_key_cmp(left: &Value, right: &Value) -> Ordering {
    canonical_key_order(&encode_key(left), &encode_key(right))
}

pub(super) fn canonical_sort(entries: &mut [(Value, Value)]) {
    entries.sort_by(|(left_key, _), (right_key, _)| canonical_key_cmp(left_key, right_key));
}

pub(super) fn canonical_map(mut entries: Vec<(Value, Value)>) -> Value {
    canonical_sort(&mut entries);
    Value::Map(entries)
}

pub(super) fn map_get(map: &[(Value, Value)], key: Value) -> Option<&Value> {
    map.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
}

/// How deeply [`raw_map_value`] and [`request_parameters`] follow nested
/// arrays, maps and tags before giving up.  CTAP requests nest a handful of
/// levels.
const MAX_NESTING: usize = 16;

/// The CBOR argument of the data item header at `bytes[pos]`: the additional
/// information value and the position after the header.  `None` for a
/// truncated header, a reserved additional information value, or an
/// indefinite length, which CTAP's canonical encoding never uses.
fn header(bytes: &[u8], pos: usize) -> Option<(u8, u64, usize)> {
    let initial = *bytes.get(pos)?;
    let major = initial >> 5;
    let info = initial & 0x1f;
    let (argument, size) = match info {
        0..=23 => (u64::from(info), 0),
        24..=27 => {
            let size = 1usize << (info - 24);
            let raw = bytes.get(pos + 1..pos + 1 + size)?;
            (
                raw.iter()
                    .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte)),
                size,
            )
        }
        _ => return None,
    };
    Some((major, argument, pos + 1 + size))
}

/// The position just after the data item that starts at `bytes[pos]`.
fn item_end(bytes: &[u8], pos: usize, depth: usize) -> Option<usize> {
    if depth > MAX_NESTING {
        return None;
    }
    let (major, argument, mut end) = header(bytes, pos)?;
    match major {
        // Unsigned and negative integers, simple values and floats: the
        // header is the whole item.
        0 | 1 | 7 => {}
        // Byte and text strings.
        2 | 3 => {
            end = end.checked_add(usize::try_from(argument).ok()?)?;
            if end > bytes.len() {
                return None;
            }
        }
        // Arrays and maps.
        4 | 5 => {
            let items = if major == 4 {
                argument
            } else {
                argument.checked_mul(2)?
            };
            for _ in 0..items {
                end = item_end(bytes, end, depth + 1)?;
            }
        }
        // A tag and the item it tags.
        _ => end = item_end(bytes, end, depth + 1)?,
    }
    Some(end)
}

/// The encoded bytes, exactly as received, of the value stored under the
/// unsigned integer `key` in the CBOR map `bytes`.  `Ok(None)` if the map has
/// no such key; `Err(())` if `bytes` is not a single well-formed definite
/// length map.
///
/// authenticatorCredentialManagement authenticates `subCommandParams` as the
/// platform encoded them (CTAP 2.3 §6.8.4 to §6.8.6), which a decoded
/// [`Value`] re-encoded would not reproduce for a non-canonical encoding.
pub(super) fn raw_map_value(bytes: &[u8], key: u64) -> Result<Option<&[u8]>, ()> {
    let (major, entries, mut pos) = header(bytes, 0).ok_or(())?;
    if major != 5 {
        return Err(());
    }
    let mut found = None;
    for _ in 0..entries {
        let key_end = item_end(bytes, pos, 1).ok_or(())?;
        let value_end = item_end(bytes, key_end, 1).ok_or(())?;
        let is_key = matches!(header(bytes, pos), Some((0, argument, end)) if argument == key && end == key_end);
        if is_key && found.is_none() {
            found = Some(&bytes[key_end..value_end]);
        }
        pos = value_end;
    }
    if pos != bytes.len() {
        return Err(());
    }
    Ok(found)
}

/// The parameters of a request: `payload` decoded as a CBOR map.
///
/// "All decoders SHOULD reject CBOR that is not validly encoded in the CTAP2
/// canonical CBOR encoding form and SHOULD reject messages with duplicate map
/// keys." and "Authenticators SHOULD return the CTAP2_ERR_INVALID_CBOR error
/// if received CBOR does not conform to the requirements above." (CTAP 2.3
/// §8)  So `payload` must be exactly one data item in that form (see
/// [`canonical_item_end`]) and a map, or the request fails with
/// CTAP2_ERR_INVALID_CBOR.
pub(super) fn request_parameters(payload: &[u8]) -> Result<Vec<(Value, Value)>, u8> {
    if canonical_item_end(payload, 0, 0) != Some(payload.len()) {
        return Err(CTAP2_ERR_INVALID_CBOR);
    }
    match ciborium::de::from_reader(payload) {
        Ok(Value::Map(entries)) => Ok(entries),
        _ => Err(CTAP2_ERR_INVALID_CBOR),
    }
}

/// The position just after the data item that starts at `bytes[pos]`, if it
/// is well formed and in the CTAP2 canonical CBOR encoding form (CTAP 2.3
/// §8), `depth` being the number of arrays and maps it is nested in:
///
/// * "Integers MUST be encoded as small as possible." and "The expression of
///   lengths in major types 2 through 5 MUST be as short as possible.";
/// * "The representations of any floating-point values are not changed.", so
///   16, 32 and 64-bit floats are all accepted;
/// * "Indefinite-length items MUST be made into definite-length items.";
/// * "The keys in every map MUST be sorted lowest value to highest.", which
///   also rules out duplicate keys;
/// * "Tags as defined in Section 3.4 in \[RFC8949\] MUST NOT be present."
///
/// Arrays and maps may nest [`MAX_NESTING`] levels, more than the "at most
/// four (4) levels" platforms may send.  Whether text strings are valid UTF-8
/// is left to the decoder.
fn canonical_item_end(bytes: &[u8], pos: usize, depth: usize) -> Option<usize> {
    let initial = *bytes.get(pos)?;
    let (major, info) = (initial >> 5, initial & 0x1f);
    if major == 7 && (25..=27).contains(&info) {
        // A float: its size is part of its value.
        let end = pos + 1 + (1usize << (info - 24));
        return (end <= bytes.len()).then_some(end);
    }
    let (_, argument, mut end) = header(bytes, pos)?;
    let shortest = match info {
        24 if major == 7 => argument >= 32,
        24 => argument >= 24,
        25 => argument > 0xff,
        26 => argument > 0xffff,
        27 => argument > 0xffff_ffff,
        _ => true,
    };
    if !shortest {
        return None;
    }
    match major {
        // Unsigned and negative integers, simple values.
        0 | 1 | 7 => {}
        // Byte and text strings.
        2 | 3 => {
            end = end.checked_add(usize::try_from(argument).ok()?)?;
            if end > bytes.len() {
                return None;
            }
        }
        4 => {
            if depth >= MAX_NESTING {
                return None;
            }
            for _ in 0..argument {
                end = canonical_item_end(bytes, end, depth + 1)?;
            }
        }
        5 => {
            if depth >= MAX_NESTING {
                return None;
            }
            let mut previous_key: Option<&[u8]> = None;
            for _ in 0..argument {
                let key_end = canonical_item_end(bytes, end, depth + 1)?;
                let key = &bytes[end..key_end];
                if previous_key.is_some_and(|previous| canonical_key_order(previous, key).is_ge()) {
                    return None;
                }
                previous_key = Some(key);
                end = canonical_item_end(bytes, key_end, depth + 1)?;
            }
        }
        // Tags.
        _ => return None,
    }
    Some(end)
}

/// Whether `bytes` is exactly one data item in the CTAP2 canonical CBOR
/// encoding form.
#[cfg(test)]
pub(super) fn is_canonical(bytes: &[u8]) -> bool {
    canonical_item_end(bytes, 0, 0) == Some(bytes.len())
}

/// The order of two encoded map keys: "If the major types are different, the
/// one with the lower value in numerical order sorts earlier. If two keys have
/// different lengths, the shorter one sorts earlier; If two keys have the same
/// length, the one with the lower value in (byte-wise) lexical order sorts
/// earlier." (CTAP 2.3 §8)
fn canonical_key_order(left: &[u8], right: &[u8]) -> Ordering {
    (left[0] >> 5)
        .cmp(&(right[0] >> 5))
        .then(left.len().cmp(&right.len()))
        .then(left.cmp(right))
}
