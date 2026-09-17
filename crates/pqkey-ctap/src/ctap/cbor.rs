//! Canonical CBOR helpers shared by the CTAP2 command handlers.

use ciborium::{ser::into_writer, value::Value};
use std::cmp::Ordering;

fn canonical_fallback_cmp(left: &Value, right: &Value) -> Ordering {
    let mut left_bytes = Vec::new();
    into_writer(left, &mut left_bytes).expect("serialize left key for canonical ordering");
    let mut right_bytes = Vec::new();
    into_writer(right, &mut right_bytes).expect("serialize right key for canonical ordering");
    match left_bytes.len().cmp(&right_bytes.len()) {
        Ordering::Equal => left_bytes.cmp(&right_bytes),
        other => other,
    }
}

fn canonical_key_cmp(left: &Value, right: &Value) -> Ordering {
    use Value::{Integer as IntValue, Text};

    match (left, right) {
        (IntValue(left_int), IntValue(right_int)) => left_int.canonical_cmp(right_int),
        (IntValue(_), Text(_)) => Ordering::Less,
        (Text(_), IntValue(_)) => Ordering::Greater,
        (Text(left_text), Text(right_text)) => match left_text.len().cmp(&right_text.len()) {
            Ordering::Equal => left_text.cmp(right_text),
            other => other,
        },
        (Value::Bytes(left_bytes), Value::Bytes(right_bytes)) => {
            match left_bytes.len().cmp(&right_bytes.len()) {
                Ordering::Equal => left_bytes.cmp(right_bytes),
                other => other,
            }
        }
        (Value::Bool(left_bool), Value::Bool(right_bool)) => left_bool.cmp(right_bool),
        _ => canonical_fallback_cmp(left, right),
    }
}

pub(super) fn canonical_sort(entries: &mut Vec<(Value, Value)>) {
    entries.sort_by(|(left_key, _), (right_key, _)| canonical_key_cmp(left_key, right_key));
}

pub(super) fn canonical_map(mut entries: Vec<(Value, Value)>) -> Value {
    canonical_sort(&mut entries);
    Value::Map(entries)
}

pub(super) fn map_get<'a>(map: &'a [(Value, Value)], key: Value) -> Option<&'a Value> {
    map.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
}

/// How deeply [`raw_map_value`] follows nested arrays, maps and tags before
/// giving up.  CTAP requests nest a handful of levels.
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
