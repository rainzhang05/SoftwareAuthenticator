//! Arbitrary CBOR values and small helpers for building CTAP maps.

use arbitrary::{Result, Unstructured};
use ciborium::value::{Integer, Value};

/// How deeply [`arbitrary_value`] nests arrays, maps and tags.
pub const MAX_DEPTH: u32 = 4;

/// Encode `value` as CBOR.
pub fn encode(value: &Value) -> Vec<u8> {
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(value, &mut encoded).expect("a Value always encodes");
    encoded
}

pub fn int(value: i64) -> Value {
    Value::Integer(Integer::from(value))
}

pub fn text(value: &str) -> Value {
    Value::Text(value.into())
}

pub fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

/// The value under the integer `key` of a decoded map, first match, as the
/// engine looks it up.
pub fn get_int(entries: &[(Value, Value)], key: i64) -> Option<&Value> {
    entries
        .iter()
        .find(|(k, _)| *k == int(key))
        .map(|(_, value)| value)
}

/// The value under the text `key` of a decoded map, first match.
pub fn get_text<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    entries
        .iter()
        .find(|(k, _)| *k == text(key))
        .map(|(_, value)| value)
}

/// Decode `bytes` as one CBOR data item, as the engine does, and return its
/// entries if it is a map.
pub fn decode_map(bytes: &[u8]) -> Option<Vec<(Value, Value)>> {
    match ciborium::de::from_reader::<Value, _>(bytes) {
        Ok(Value::Map(entries)) => Some(entries),
        _ => None,
    }
}

/// A byte string whose length favours the sizes CTAP uses.
pub fn arbitrary_bytes(u: &mut Unstructured<'_>) -> Result<Vec<u8>> {
    let len = match u.int_in_range(0u8..=9)? {
        0 => 0,
        1 => 16,
        2 => 32,
        3 => 33,
        4 => 64,
        5 => 65,
        6 => 80,
        _ => return u.arbitrary(),
    };
    let mut out = vec![0u8; len];
    u.fill_buffer(&mut out)?;
    Ok(out)
}

/// An integer, favouring small values and the edges of the CBOR ranges.
pub fn arbitrary_integer(u: &mut Unstructured<'_>) -> Result<Integer> {
    Ok(match u.int_in_range(0u8..=5)? {
        0 => Integer::from(u.int_in_range(-64i64..=64)?),
        1 => Integer::from(u.arbitrary::<u64>()?),
        2 => Integer::from(u.arbitrary::<i64>()?),
        3 => Integer::try_from(-(1i128 << 64)).expect("the most negative CBOR integer"),
        4 => Integer::from(u64::MAX),
        _ => Integer::from(u.arbitrary::<i32>()?),
    })
}

/// Any CBOR value, nesting at most `depth` levels.
pub fn arbitrary_value(u: &mut Unstructured<'_>, depth: u32) -> Result<Value> {
    let last = if depth == 0 { 5 } else { 8 };
    Ok(match u.int_in_range(0u8..=last)? {
        0 => Value::Integer(arbitrary_integer(u)?),
        1 => Value::Bytes(arbitrary_bytes(u)?),
        2 => Value::Text(u.arbitrary()?),
        3 => Value::Bool(u.arbitrary()?),
        4 => Value::Null,
        5 => Value::Float(u.arbitrary()?),
        6 => {
            let len = u.int_in_range(0usize..=8)?;
            let mut items = Vec::with_capacity(len);
            for _ in 0..len {
                items.push(arbitrary_value(u, depth - 1)?);
            }
            Value::Array(items)
        }
        7 => {
            let len = u.int_in_range(0usize..=8)?;
            let mut entries = Vec::with_capacity(len);
            for _ in 0..len {
                entries.push((arbitrary_value(u, 0)?, arbitrary_value(u, depth - 1)?));
            }
            Value::Map(entries)
        }
        _ => Value::Tag(u.arbitrary()?, Box::new(arbitrary_value(u, depth - 1)?)),
    })
}
