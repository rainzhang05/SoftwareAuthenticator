//! Canonical CBOR helpers shared by the CTAP2 command handlers.

use ciborium::{ser::into_writer, value::Value};
use std::cmp::Ordering;
use zeroize::Zeroizing;

/// Decoded request parameters are wiped on every return path.
pub(super) struct Parameters(Vec<(Value, Value)>);

impl core::ops::Deref for Parameters {
    type Target = Vec<(Value, Value)>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for Parameters {
    fn drop(&mut self) {
        for (key, value) in &mut self.0 {
            crate::cbor::wipe(key);
            crate::cbor::wipe(value);
        }
    }
}

use crate::ctap::constants::{
    CTAP2_ERR_CBOR_UNEXPECTED_TYPE, CTAP2_ERR_INVALID_CBOR, CTAP2_ERR_MISSING_PARAMETER,
};

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

/// The value under `key`, which the request must have: "If the authenticator
/// does not receive mandatory parameters for this command, it returns
/// CTAP2_ERR_MISSING_PARAMETER error."
pub(super) fn required(map: &[(Value, Value)], key: impl Into<Value>) -> Result<&Value, u8> {
    map_get(map, key.into()).ok_or(CTAP2_ERR_MISSING_PARAMETER)
}

/// A required byte string.  A value of another type is
/// CTAP2_ERR_CBOR_UNEXPECTED_TYPE: "If structures in messages from the host
/// are missing required members, or the values of those members have the
/// wrong type, then the authenticator SHOULD return
/// CTAP2_ERR_CBOR_UNEXPECTED_TYPE." (CTAP 2.3 §8)
pub(super) fn required_bytes(map: &[(Value, Value)], key: impl Into<Value>) -> Result<&[u8], u8> {
    match required(map, key)? {
        Value::Bytes(bytes) => Ok(bytes),
        _ => Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
    }
}

/// A required map, typed as [`required_bytes`] is.
pub(super) fn required_map(
    map: &[(Value, Value)],
    key: impl Into<Value>,
) -> Result<&[(Value, Value)], u8> {
    match required(map, key)? {
        Value::Map(entries) => Ok(entries),
        _ => Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
    }
}

/// A required member of a structure from the host, such as
/// PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity or
/// PublicKeyCredentialDescriptor: "If structures in messages from the host are
/// missing required members, or the values of those members have the wrong
/// type, then the authenticator SHOULD return CTAP2_ERR_CBOR_UNEXPECTED_TYPE."
/// (CTAP 2.3 §8)  A missing top-level parameter of a command is
/// CTAP2_ERR_MISSING_PARAMETER instead, see [`required`].
pub(super) fn structure_member<'a>(
    structure: &'a [(Value, Value)],
    name: &str,
) -> Result<&'a Value, u8> {
    map_get(structure, Value::Text(name.into())).ok_or(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
}

/// A required text member of a structure, as [`structure_member`].
pub(super) fn structure_text<'a>(
    structure: &'a [(Value, Value)],
    name: &str,
) -> Result<&'a str, u8> {
    match structure_member(structure, name)? {
        Value::Text(text) => Ok(text),
        _ => Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
    }
}

/// A required byte string member of a structure, as [`structure_member`].
pub(super) fn structure_bytes<'a>(
    structure: &'a [(Value, Value)],
    name: &str,
) -> Result<&'a [u8], u8> {
    match structure_member(structure, name)? {
        Value::Bytes(bytes) => Ok(bytes),
        _ => Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
    }
}

/// An optional text member of a structure: `None` when absent, and
/// CTAP2_ERR_CBOR_UNEXPECTED_TYPE when present with another type (§8).
pub(super) fn optional_structure_text<'a>(
    structure: &'a [(Value, Value)],
    name: &str,
) -> Result<Option<&'a str>, u8> {
    match map_get(structure, Value::Text(name.into())) {
        None => Ok(None),
        Some(Value::Text(text)) => Ok(Some(text)),
        Some(_) => Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
    }
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
/// Credential management and authenticatorConfig authenticate
/// `subCommandParams` as sent (CTAP 2.3 §§6.8.4–6.8.6, 6.11), which a decoded
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
///
/// "If map keys are present that an implementation does not understand, they
/// MUST be ignored." (§8)  Their values may be any well-formed item, simple
/// values that CBOR leaves unassigned among them, which ciborium cannot
/// represent as a [`Value`].  So those are decoded as `undefined`, which
/// ciborium turns into [`Value::Null`]: ignored under an unknown key, and of
/// the wrong type, CTAP2_ERR_CBOR_UNEXPECTED_TYPE, under a known one.
/// [`raw_map_value`] still sees the payload exactly as received.
pub(super) fn request_parameters(payload: &[u8]) -> Result<Parameters, u8> {
    if canonical_item_end(payload, 0, 0) != Some(payload.len()) {
        return Err(CTAP2_ERR_INVALID_CBOR);
    }
    let mut decodable = Zeroizing::new(Vec::with_capacity(payload.len()));
    if copy_with_unassigned_simple_values_undefined(payload, 0, &mut decodable)
        != Some(payload.len())
    {
        return Err(CTAP2_ERR_INVALID_CBOR);
    }
    match ciborium::de::from_reader(&decodable[..]) {
        Ok(Value::Map(entries)) => Ok(Parameters(entries)),
        Ok(mut value) => {
            crate::cbor::wipe(&mut value);
            Err(CTAP2_ERR_INVALID_CBOR)
        }
        _ => Err(CTAP2_ERR_INVALID_CBOR),
    }
}

/// The simple value `undefined` (RFC 8949 §3.3).
const UNDEFINED: u8 = 0xF7;

/// Append the data item at `bytes[pos]` to `out`, with every unassigned
/// simple value replaced by `undefined`, and return the position after it.
/// RFC 8949 §3.3 leaves simple values 0 to 19 and 32 to 255 "(unassigned)";
/// 20 to 23 are false, true, null and undefined, and additional information
/// 25 to 27 are floats.  `bytes` has passed [`canonical_item_end`], so its
/// nesting is bounded and it carries no tags.
fn copy_with_unassigned_simple_values_undefined(
    bytes: &[u8],
    pos: usize,
    out: &mut Vec<u8>,
) -> Option<usize> {
    let (major, argument, header_end) = header(bytes, pos)?;
    let info = bytes[pos] & 0x1f;
    match major {
        7 if info < 20 || info == 24 => {
            out.push(UNDEFINED);
            Some(header_end)
        }
        4 | 5 => {
            out.extend_from_slice(&bytes[pos..header_end]);
            let items = if major == 4 {
                argument
            } else {
                argument.checked_mul(2)?
            };
            let mut end = header_end;
            for _ in 0..items {
                end = copy_with_unassigned_simple_values_undefined(bytes, end, out)?;
            }
            Some(end)
        }
        _ => {
            let end = item_end(bytes, pos, 0)?;
            out.extend_from_slice(&bytes[pos..end]);
            Some(end)
        }
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

/// Encode authenticator extension outputs, wiping their CBOR copies (§§12.2,
/// 12.7, 12.8). An empty map does not set the ED flag.
pub(super) fn encode_extensions(
    entries: Vec<(Value, Value)>,
) -> Result<Option<Zeroizing<Vec<u8>>>, u8> {
    if entries.is_empty() {
        return Ok(None);
    }
    let map = crate::cbor::SecretValue(canonical_map(entries));
    let mut encoded = Zeroizing::new(Vec::with_capacity(crate::cbor::encoded_len_bound(&map.0)));
    into_writer(&map.0, &mut *encoded).map_err(|_| crate::ctap::constants::CTAP2_ERR_PROCESSING)?;
    Ok(Some(encoded))
}
