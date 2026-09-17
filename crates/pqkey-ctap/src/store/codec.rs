//! The CBOR encoding of records inside an envelope.
//!
//! Each record is a CBOR map with small unsigned integer keys, written in
//! ascending key order with the shortest integer and length encodings.
//!
//! ```text
//! credential record (record type 1)
//!    1  credential_id           byte string
//!    2  rp_id                   text string
//!    3  user_id                 byte string
//!    4  user_name               text string, omitted when absent
//!    5  user_display_name       text string, omitted when absent
//!    6  alg                     integer: COSE algorithm identifier (-7, -48, -49, -50)
//!    7  private key type        unsigned integer: 1 = P-256 scalar, 2 = ML-DSA seed
//!    8  private key             byte string, 32 bytes
//!    9  cred_random_with_uv     byte string, 32 bytes
//!   10  cred_random_without_uv  byte string, 32 bytes
//!   11  cred_protect            unsigned integer, 1-3
//!   12  sign_count              unsigned integer, 32 bits
//!   13  created_at              unsigned integer, 64 bits
//!
//! PIN state record (record type 2)
//!    1  pin_hash                byte string, 16 bytes, omitted when no PIN is set
//!    2  pin_retries             unsigned integer, 8 bits
//!    3  consecutive_failures    unsigned integer, 8 bits
//!    4  pin_auth_blocked        boolean
//!
//! attestation record (record type 3)
//!    1  private_key             byte string, 32 bytes
//!    2  certificate_chain       array of byte strings, at least one, none empty
//! ```
//!
//! Decoding is strict.  Trailing bytes, a non-map, keys that are not unsigned
//! integers, duplicate or unknown keys, missing required keys, wrong types,
//! out-of-range integers, wrong lengths, an unknown `alg`, and an unknown
//! private key type are [`Corruption::Encoding`].  A record that decodes but
//! breaks an invariant checked on writes (such as `alg` disagreeing with the
//! private key type) is [`Corruption::Inconsistent`].
//!
//! Every intermediate CBOR value that held record contents is overwritten
//! before it is freed.  (While decoding, `ciborium` also copies byte and text
//! strings through a scratch buffer on the stack that this module cannot
//! reach.)

use core::mem;

use ciborium::value::{Integer, Value};
use zeroize::{Zeroize, Zeroizing};

use super::record::{AttestationRecord, CredentialRecord, PinStateRecord, PrivateKeyMaterial};
use super::{Corruption, StoreError, validate_attestation, validate_credential};
use crate::CoseAlg;

const KEY_TYPE_ES256_SCALAR: u64 = 1;
const KEY_TYPE_MLDSA_SEED: u64 = 2;

/// Encode a credential record with the given creation order.
pub(crate) fn encode_credential(
    record: &CredentialRecord,
    created_at: u64,
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let (key_type, key) = match &record.private_key {
        PrivateKeyMaterial::Es256 { scalar } => (KEY_TYPE_ES256_SCALAR, scalar),
        PrivateKeyMaterial::MlDsa { seed } => (KEY_TYPE_MLDSA_SEED, seed),
    };
    let mut entries = vec![
        (1, Value::Bytes(record.credential_id.clone())),
        (2, Value::Text(record.rp_id.clone())),
        (3, Value::Bytes(record.user_id.clone())),
    ];
    if let Some(user_name) = &record.user_name {
        entries.push((4, Value::Text(user_name.clone())));
    }
    if let Some(user_display_name) = &record.user_display_name {
        entries.push((5, Value::Text(user_display_name.clone())));
    }
    entries.extend([
        (6, Value::Integer(Integer::from(record.alg as i32))),
        (7, Value::Integer(Integer::from(key_type))),
        (8, Value::Bytes(key.to_vec())),
        (9, Value::Bytes(record.cred_random_with_uv.to_vec())),
        (10, Value::Bytes(record.cred_random_without_uv.to_vec())),
        (11, Value::Integer(Integer::from(record.cred_protect))),
        (12, Value::Integer(Integer::from(record.sign_count))),
        (13, Value::Integer(Integer::from(created_at))),
    ]);
    encode_map(entries)
}

/// Decode and validate a credential record.
pub(crate) fn decode_credential(bytes: &[u8]) -> Result<CredentialRecord, Corruption> {
    let mut fields = Fields::parse(bytes)?;
    let alg = CoseAlg::try_from(fields.int::<i32>(6)?).map_err(|_| Corruption::Encoding)?;
    let key_type = fields.uint::<u64>(7)?;
    let key = Zeroizing::new(fields.array::<32>(8)?);
    let private_key = match key_type {
        KEY_TYPE_ES256_SCALAR => PrivateKeyMaterial::Es256 { scalar: *key },
        KEY_TYPE_MLDSA_SEED => PrivateKeyMaterial::MlDsa { seed: *key },
        _ => return Err(Corruption::Encoding),
    };
    let record = CredentialRecord {
        credential_id: fields.bytes(1)?,
        rp_id: fields.text(2)?,
        user_id: fields.bytes(3)?,
        user_name: fields.optional_text(4)?,
        user_display_name: fields.optional_text(5)?,
        alg,
        private_key,
        cred_random_with_uv: fields.array(9)?,
        cred_random_without_uv: fields.array(10)?,
        cred_protect: fields.uint(11)?,
        sign_count: fields.uint(12)?,
        created_at: fields.uint(13)?,
    };
    fields.finish()?;
    validate_credential(&record).map_err(|_| Corruption::Inconsistent)?;
    Ok(record)
}

/// Encode a PIN state record.
pub(crate) fn encode_pin_state(state: &PinStateRecord) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let mut entries = Vec::with_capacity(4);
    if let Some(pin_hash) = &state.pin_hash {
        entries.push((1, Value::Bytes(pin_hash.to_vec())));
    }
    entries.extend([
        (2, Value::Integer(Integer::from(state.pin_retries))),
        (3, Value::Integer(Integer::from(state.consecutive_failures))),
        (4, Value::Bool(state.pin_auth_blocked)),
    ]);
    encode_map(entries)
}

/// Decode a PIN state record.
pub(crate) fn decode_pin_state(bytes: &[u8]) -> Result<PinStateRecord, Corruption> {
    let mut fields = Fields::parse(bytes)?;
    let state = PinStateRecord {
        pin_hash: fields.optional_array(1)?,
        pin_retries: fields.uint(2)?,
        consecutive_failures: fields.uint(3)?,
        pin_auth_blocked: fields.bool(4)?,
    };
    fields.finish()?;
    Ok(state)
}

/// Encode an attestation record.
pub(crate) fn encode_attestation(
    record: &AttestationRecord,
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let chain = record
        .certificate_chain
        .iter()
        .map(|certificate| Value::Bytes(certificate.clone()))
        .collect();
    encode_map(vec![
        (1, Value::Bytes(record.private_key.to_vec())),
        (2, Value::Array(chain)),
    ])
}

/// Decode and validate an attestation record.
pub(crate) fn decode_attestation(bytes: &[u8]) -> Result<AttestationRecord, Corruption> {
    let mut fields = Fields::parse(bytes)?;
    let record = AttestationRecord {
        private_key: fields.array(1)?,
        certificate_chain: fields.bytes_array(2)?,
    };
    fields.finish()?;
    validate_attestation(&record).map_err(|_| Corruption::Inconsistent)?;
    Ok(record)
}

fn encode_map(entries: Vec<(u64, Value)>) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let map = Item(Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (Value::Integer(Integer::from(key)), value))
            .collect(),
    ));
    // Reserve an upper bound up front so the buffer never reallocates and
    // leaves a partial copy of the record behind.
    let mut encoded = Zeroizing::new(Vec::with_capacity(encoded_len_bound(&map.0)));
    ciborium::ser::into_writer(&map.0, &mut *encoded)
        .map_err(|_| StoreError::InvalidRecord("record could not be encoded"))?;
    Ok(encoded)
}

/// An upper bound on the encoded length of `value`: no CBOR item header is
/// longer than nine bytes.
fn encoded_len_bound(value: &Value) -> usize {
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
fn wipe(value: &mut Value) {
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
struct Item(Value);

impl Drop for Item {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl Item {
    fn into_bytes(mut self) -> Result<Vec<u8>, Corruption> {
        match &mut self.0 {
            Value::Bytes(bytes) => Ok(mem::take(bytes)),
            _ => Err(Corruption::Encoding),
        }
    }

    fn into_text(mut self) -> Result<String, Corruption> {
        match &mut self.0 {
            Value::Text(text) => Ok(mem::take(text)),
            _ => Err(Corruption::Encoding),
        }
    }

    fn into_array<const N: usize>(self) -> Result<[u8; N], Corruption> {
        let bytes = Zeroizing::new(self.into_bytes()?);
        <[u8; N]>::try_from(bytes.as_slice()).map_err(|_| Corruption::Encoding)
    }

    fn into_integer(self) -> Result<Integer, Corruption> {
        match &self.0 {
            Value::Integer(integer) => Ok(*integer),
            _ => Err(Corruption::Encoding),
        }
    }
}

/// The entries of a decoded CBOR map, keyed by unsigned integer.  Entries are
/// taken out one by one; whatever is left is wiped on drop.
struct Fields(Vec<(u64, Item)>);

impl Fields {
    fn parse(bytes: &[u8]) -> Result<Self, Corruption> {
        let mut reader = bytes;
        let value: Value =
            ciborium::de::from_reader(&mut reader).map_err(|_| Corruption::Encoding)?;
        let mut value = Item(value);
        if !reader.is_empty() {
            return Err(Corruption::Encoding);
        }
        let Value::Map(entries) = &mut value.0 else {
            return Err(Corruption::Encoding);
        };
        let entries: Vec<(Item, Item)> = mem::take(entries)
            .into_iter()
            .map(|(key, value)| (Item(key), Item(value)))
            .collect();
        let mut fields = Fields(Vec::with_capacity(entries.len()));
        for (key, value) in entries {
            let key = key
                .into_integer()
                .and_then(|key| u64::try_from(key).map_err(|_| Corruption::Encoding))?;
            if fields.0.iter().any(|(existing, _)| *existing == key) {
                return Err(Corruption::Encoding);
            }
            fields.0.push((key, value));
        }
        Ok(fields)
    }

    fn take(&mut self, key: u64) -> Option<Item> {
        let index = self.0.iter().position(|(existing, _)| *existing == key)?;
        Some(self.0.swap_remove(index).1)
    }

    fn required(&mut self, key: u64) -> Result<Item, Corruption> {
        self.take(key).ok_or(Corruption::Encoding)
    }

    fn bytes(&mut self, key: u64) -> Result<Vec<u8>, Corruption> {
        self.required(key)?.into_bytes()
    }

    fn text(&mut self, key: u64) -> Result<String, Corruption> {
        self.required(key)?.into_text()
    }

    fn optional_text(&mut self, key: u64) -> Result<Option<String>, Corruption> {
        self.take(key).map(Item::into_text).transpose()
    }

    fn array<const N: usize>(&mut self, key: u64) -> Result<[u8; N], Corruption> {
        self.required(key)?.into_array()
    }

    fn optional_array<const N: usize>(&mut self, key: u64) -> Result<Option<[u8; N]>, Corruption> {
        self.take(key).map(Item::into_array).transpose()
    }

    fn uint<T: TryFrom<u64>>(&mut self, key: u64) -> Result<T, Corruption> {
        let integer = self.required(key)?.into_integer()?;
        u64::try_from(integer)
            .ok()
            .and_then(|value| T::try_from(value).ok())
            .ok_or(Corruption::Encoding)
    }

    fn int<T: TryFrom<i128>>(&mut self, key: u64) -> Result<T, Corruption> {
        let integer = self.required(key)?.into_integer()?;
        T::try_from(i128::from(integer)).map_err(|_| Corruption::Encoding)
    }

    fn bool(&mut self, key: u64) -> Result<bool, Corruption> {
        match self.required(key)?.0 {
            Value::Bool(value) => Ok(value),
            _ => Err(Corruption::Encoding),
        }
    }

    fn bytes_array(&mut self, key: u64) -> Result<Vec<Vec<u8>>, Corruption> {
        let mut item = self.required(key)?;
        let Value::Array(items) = &mut item.0 else {
            return Err(Corruption::Encoding);
        };
        mem::take(items)
            .into_iter()
            .map(|value| Item(value).into_bytes())
            .collect()
    }

    /// Succeeds only if every entry was taken, i.e. there were no unknown
    /// keys.
    fn finish(self) -> Result<(), Corruption> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Corruption::Encoding)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn credential() -> CredentialRecord {
        CredentialRecord {
            credential_id: (0..16).collect(),
            rp_id: "example.com".into(),
            user_id: vec![0x01, 0x02],
            user_name: Some("alice".into()),
            user_display_name: None,
            alg: CoseAlg::MLDSA44,
            private_key: PrivateKeyMaterial::MlDsa {
                seed: core::array::from_fn(|i| 0x20 + i as u8),
            },
            cred_random_with_uv: [0xaa; 32],
            cred_random_without_uv: [0xbb; 32],
            cred_protect: 2,
            sign_count: 300,
            created_at: 70_000,
        }
    }

    fn pin_state() -> PinStateRecord {
        PinStateRecord {
            pin_hash: Some(core::array::from_fn(|i| (i as u8) * 0x11)),
            pin_retries: 5,
            consecutive_failures: 2,
            pin_auth_blocked: true,
        }
    }

    fn attestation() -> AttestationRecord {
        AttestationRecord {
            private_key: [0x42; 32],
            certificate_chain: vec![vec![0x30, 0x82], vec![0x30, 0x83]],
        }
    }

    fn to_cbor(value: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(value, &mut out).unwrap();
        out
    }

    /// Decode `bytes` as a map, let `edit` change its entries, and re-encode.
    fn edited(bytes: &[u8], edit: impl FnOnce(&mut Vec<(Value, Value)>)) -> Vec<u8> {
        let Value::Map(mut entries) = ciborium::de::from_reader(bytes).unwrap() else {
            panic!("records are maps");
        };
        edit(&mut entries);
        to_cbor(&Value::Map(entries))
    }

    fn set(entries: &mut Vec<(Value, Value)>, key: u64, value: Value) {
        let key = Value::Integer(Integer::from(key));
        match entries.iter_mut().find(|(k, _)| *k == key) {
            Some(entry) => entry.1 = value,
            None => entries.push((key, value)),
        }
    }

    fn remove(entries: &mut Vec<(Value, Value)>, key: u64) {
        let key = Value::Integer(Integer::from(key));
        entries.retain(|(k, _)| *k != key);
    }

    /// The encodings below were written out by hand from RFC 8949 and
    /// double-checked with a minimal independent CBOR encoder in Python.
    #[test]
    fn encodings_match_the_documented_format() {
        let credential = encode_credential(&credential(), 70_000).unwrap();
        // Each line is one map key followed by its value.
        let expected = unhex(concat!(
            "ac",                                   // map with 12 entries
            "0150000102030405060708090a0b0c0d0e0f", // 1: credential_id
            "026b6578616d706c652e636f6d",           // 2: rp_id "example.com"
            "03420102",                             // 3: user_id
            "0465616c696365",                       // 4: user_name "alice"
            "06382f",                               // 6: alg -48
            "0702",                                 // 7: key type, ML-DSA seed
            // 8: the 32-byte seed
            "085820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            // 9: cred_random_with_uv
            "095820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            // 10: cred_random_without_uv
            "0a5820bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "0b02",         // 11: cred_protect 2
            "0c19012c",     // 12: sign_count 300
            "0d1a00011170", // 13: created_at 70000
        ));
        assert_eq!(credential.as_slice(), expected.as_slice());

        let pin = encode_pin_state(&pin_state()).unwrap();
        assert_eq!(
            pin.as_slice(),
            unhex("a4015000112233445566778899aabbccddeeff0205030204f5").as_slice()
        );

        let attestation = encode_attestation(&attestation()).unwrap();
        assert_eq!(
            attestation.as_slice(),
            unhex(concat!(
                "a2",
                "01",
                "58204242424242424242424242424242424242424242424242424242424242424242",
                "02",
                "82",
                "423082",
                "423083"
            ))
            .as_slice()
        );
    }

    #[test]
    fn records_round_trip() {
        let mut record = credential();
        let encoded = encode_credential(&record, 70_000).unwrap();
        assert_eq!(decode_credential(&encoded).unwrap(), record);

        record.user_name = None;
        record.user_display_name = Some("Ålice 🔑".into());
        record.alg = CoseAlg::ES256;
        record.private_key = PrivateKeyMaterial::generate(CoseAlg::ES256);
        record.sign_count = u32::MAX;
        record.cred_protect = 3;
        let encoded = encode_credential(&record, u64::MAX).unwrap();
        let mut expected = record.clone();
        expected.created_at = u64::MAX;
        assert_eq!(decode_credential(&encoded).unwrap(), expected);

        let state = pin_state();
        assert_eq!(
            decode_pin_state(&encode_pin_state(&state).unwrap()).unwrap(),
            state
        );
        let state = PinStateRecord::default();
        assert_eq!(
            decode_pin_state(&encode_pin_state(&state).unwrap()).unwrap(),
            state
        );

        let attestation = attestation();
        assert_eq!(
            decode_attestation(&encode_attestation(&attestation).unwrap()).unwrap(),
            attestation
        );
    }

    #[test]
    fn created_at_comes_from_the_argument() {
        let record = credential();
        let encoded = encode_credential(&record, 5).unwrap();
        assert_eq!(decode_credential(&encoded).unwrap().created_at, 5);
    }

    #[test]
    fn malformed_encodings_are_rejected() {
        let valid = encode_credential(&credential(), 1).unwrap();
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty input", vec![]),
            ("not a map", to_cbor(&Value::Array(vec![]))),
            ("trailing byte", [valid.as_slice(), &[0x00]].concat()),
            ("truncated", valid[..valid.len() - 1].to_vec()),
            (
                "unknown key",
                edited(&valid, |e| set(e, 14, Value::Bool(true))),
            ),
            (
                "duplicate key",
                edited(&valid, |e| {
                    e.push((Value::Integer(Integer::from(2)), Value::Text("x".into())))
                }),
            ),
            (
                "text key",
                edited(&valid, |e| e.push((Value::Text("rp".into()), Value::Null))),
            ),
            (
                "negative key",
                edited(&valid, |e| {
                    e.push((Value::Integer(Integer::from(-1)), Value::Null))
                }),
            ),
            ("missing rp_id", edited(&valid, |e| remove(e, 2))),
            ("missing created_at", edited(&valid, |e| remove(e, 13))),
            (
                "rp_id as bytes",
                edited(&valid, |e| set(e, 2, Value::Bytes(b"example.com".to_vec()))),
            ),
            (
                "user_name as null",
                edited(&valid, |e| set(e, 4, Value::Null)),
            ),
            (
                "31-byte seed",
                edited(&valid, |e| set(e, 8, Value::Bytes(vec![1; 31]))),
            ),
            (
                "33-byte cred_random",
                edited(&valid, |e| set(e, 9, Value::Bytes(vec![1; 33]))),
            ),
            (
                "cred_protect above u8",
                edited(&valid, |e| set(e, 11, Value::Integer(Integer::from(256)))),
            ),
            (
                "negative sign_count",
                edited(&valid, |e| set(e, 12, Value::Integer(Integer::from(-1)))),
            ),
            (
                "unknown alg",
                edited(&valid, |e| set(e, 6, Value::Integer(Integer::from(-8)))),
            ),
            (
                "unknown key type",
                edited(&valid, |e| set(e, 7, Value::Integer(Integer::from(3)))),
            ),
        ];
        for (name, encoding) in cases {
            assert_eq!(
                decode_credential(&encoding).err(),
                Some(Corruption::Encoding),
                "{name}"
            );
        }

        let pin = encode_pin_state(&pin_state()).unwrap();
        for (name, encoding) in [
            (
                "15-byte PIN hash",
                edited(&pin, |e| set(e, 1, Value::Bytes(vec![0; 15]))),
            ),
            (
                "retries above u8",
                edited(&pin, |e| set(e, 2, Value::Integer(Integer::from(300)))),
            ),
            (
                "blocked as integer",
                edited(&pin, |e| set(e, 4, Value::Integer(Integer::from(1)))),
            ),
            ("missing blocked flag", edited(&pin, |e| remove(e, 4))),
        ] {
            assert_eq!(
                decode_pin_state(&encoding).err(),
                Some(Corruption::Encoding),
                "{name}"
            );
        }

        let attestation = encode_attestation(&attestation()).unwrap();
        for (name, encoding) in [
            (
                "chain of text",
                edited(&attestation, |e| {
                    set(e, 2, Value::Array(vec![Value::Text("cert".into())]))
                }),
            ),
            (
                "chain not an array",
                edited(&attestation, |e| set(e, 2, Value::Bytes(vec![0x30]))),
            ),
        ] {
            assert_eq!(
                decode_attestation(&encoding).err(),
                Some(Corruption::Encoding),
                "{name}"
            );
        }
    }

    #[test]
    fn inconsistent_records_are_rejected() {
        let valid = encode_credential(&credential(), 1).unwrap();
        let int = |value: i64| Value::Integer(Integer::from(value));
        for (name, encoding) in [
            // An ML-DSA seed labelled as a P-256 scalar and vice versa.
            (
                "ES256 alg with seed",
                edited(&valid, |e| set(e, 6, int(-7))),
            ),
            (
                "ML-DSA alg with scalar",
                edited(&valid, |e| set(e, 7, int(1))),
            ),
            (
                "zero P-256 scalar",
                edited(&valid, |e| {
                    set(e, 6, int(-7));
                    set(e, 7, int(1));
                    set(e, 8, Value::Bytes(vec![0; 32]));
                }),
            ),
            ("credProtect 0", edited(&valid, |e| set(e, 11, int(0)))),
            ("credProtect 4", edited(&valid, |e| set(e, 11, int(4)))),
            (
                "empty credential ID",
                edited(&valid, |e| set(e, 1, Value::Bytes(vec![]))),
            ),
        ] {
            assert_eq!(
                decode_credential(&encoding).err(),
                Some(Corruption::Inconsistent),
                "{name}"
            );
        }

        let attestation = encode_attestation(&attestation()).unwrap();
        for (name, encoding) in [
            (
                "empty chain",
                edited(&attestation, |e| set(e, 2, Value::Array(vec![]))),
            ),
            (
                "empty certificate",
                edited(&attestation, |e| {
                    set(e, 2, Value::Array(vec![Value::Bytes(vec![])]))
                }),
            ),
            (
                "zero private key",
                edited(&attestation, |e| set(e, 1, Value::Bytes(vec![0; 32]))),
            ),
        ] {
            assert_eq!(
                decode_attestation(&encoding).err(),
                Some(Corruption::Inconsistent),
                "{name}"
            );
        }
    }

    #[test]
    fn wipe_clears_nested_contents() {
        let mut value = Value::Map(vec![(
            Value::Text("key".into()),
            Value::Array(vec![
                Value::Bytes(vec![0xaa; 4]),
                Value::Tag(1, Box::new(Value::Text("secret".into()))),
            ]),
        )]);
        wipe(&mut value);
        let Value::Map(entries) = &value else {
            unreachable!()
        };
        assert_eq!(entries[0].0, Value::Text(String::new()));
        let Value::Array(items) = &entries[0].1 else {
            unreachable!()
        };
        assert_eq!(items[0], Value::Bytes(vec![]));
        assert_eq!(
            items[1],
            Value::Tag(1, Box::new(Value::Text(String::new())))
        );
    }
}
