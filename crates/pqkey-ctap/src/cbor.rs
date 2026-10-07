//! CBOR buffers and values that hold secrets.

use ciborium::value::Value;
use zeroize::Zeroize;

/// An upper bound on the encoded length of `value`: no CBOR item header is
/// longer than nine bytes.
pub(crate) fn encoded_len_bound(value: &Value) -> usize {
    const HEADER: usize = 9;
    HEADER
        + match value {
            Value::Bytes(bytes) => bytes.len(),
            Value::Text(text) => text.len(),
            Value::Array(items) => items.iter().map(encoded_len_bound).sum(),
            Value::Map(entries) => entries
                .iter()
                .map(|(key, value)| encoded_len_bound(key) + encoded_len_bound(value))
                .sum(),
            Value::Tag(_, inner) => encoded_len_bound(inner),
            _ => 0,
        }
}

/// Overwrite every byte and text string inside `value`.
pub(crate) fn wipe(value: &mut Value) {
    match value {
        Value::Bytes(bytes) => bytes.zeroize(),
        Value::Text(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe),
        Value::Map(entries) => entries.iter_mut().for_each(|(key, value)| {
            wipe(key);
            wipe(value);
        }),
        Value::Tag(_, inner) => wipe(inner),
        _ => {}
    }
}

/// A CBOR value that is wiped when dropped.
pub(crate) struct SecretValue(pub(crate) Value);

impl Drop for SecretValue {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}
