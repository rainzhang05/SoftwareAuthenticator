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
