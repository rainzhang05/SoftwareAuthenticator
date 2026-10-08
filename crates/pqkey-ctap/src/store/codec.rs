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
//!    6  alg                     integer: COSE algorithm identifier, one of CoseAlg's
//!    7  private key type        unsigned integer: 1 = P-256 scalar, 2 = seed (ML-DSA's ξ,
//!                               an ECDSA key's seed on P-384, P-521 or
//!                               secp256k1, an Ed25519 private key, or an
//!                               Ed448 key's seed), 3 (RSA primes)
//!    8  private key             byte string, 32 bytes (types 1-2),
//!                               256 bytes (type 3, RSA primes p || q)
//!    9  cred_random_with_uv     byte string, 32 bytes
//!   10  cred_random_without_uv  byte string, 32 bytes
//!   11  cred_protect            unsigned integer, 1-3
//!   12  sign_count              unsigned integer, 32 bits
//!   13  created_at              unsigned integer, 64 bits
//!   14  cred_blob               byte string, at most 32 bytes, optional
//!   15  large_blob_key          byte string, 32 bytes, optional
//!
//! PIN state record (record type 2)
//!    1  pin_hash                byte string, 16 bytes, omitted when no PIN is set
//!    2  pin_retries             unsigned integer, 8 bits
//!    3  consecutive_failures    unsigned integer, 8 bits
//!    4  pin_auth_blocked        boolean
//!    5  min_pin_length          unsigned integer, 4-63, default 4
//!    6  min_pin_length_rp_ids   array of text strings, at most 8,
//!                               each at most 253 bytes, default empty
//!    7  force_pin_change        boolean, default false
//!    8  pin_code_point_length   unsigned integer, 4-63, default 4
//!    9  always_uv               boolean, default false
//!
//! attestation record (record type 3)
//!    1  private_key             byte string, 32 bytes
//!    2  certificate_chain       array of byte strings, at least one, none empty
//!
//! signature counter record (record type 4)
//!    1  signature_counter       unsigned integer, 32 bits
//!
//! large-blob array record (record type 5)
//!    1  serialized_array        byte string, 17–16,384 bytes, trailing hash
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

#[cfg(test)]
use crate::cbor::wipe;
use crate::cbor::{SecretValue as Item, encoded_len_bound};
use core::mem;

use ciborium::value::{Integer, Value};
use zeroize::Zeroizing;

use super::record::{AttestationRecord, CredentialRecord, PinStateRecord, PrivateKeyMaterial};
use super::{
    Corruption, StoreError, validate_attestation, validate_credential, validate_large_blob_array,
    validate_pin_state,
};
use crate::{CoseAlg, KeyKind};

/// Private key type 1: a P-256 scalar ([`KeyKind::P256Scalar`]).
const KEY_TYPE_P256_SCALAR: u64 = 1;
/// Private key type 2: a seed the record's `alg` derives its key from
/// ([`KeyKind::Seed`]): for ML-DSA the FIPS 204 seed `ξ`, for ECDSA on
/// P-384, P-521 and secp256k1 the seed its scalar is derived from, and for
/// EdDSA the RFC 8032 private key itself on Ed25519 and the seed it is
/// derived from on Ed448.
const KEY_TYPE_SEED: u64 = 2;
/// Private key type 3: RSA-2048 primes p || q ([`KeyKind::RsaPrimes`]).
const KEY_TYPE_RSA_PRIMES: u64 = 3;

/// Encode a credential record with the given creation order.
#[deny(
    clippy::wildcard_enum_match_arm,
    clippy::match_wildcard_for_single_variants
)]
pub(crate) fn encode_credential(
    record: &CredentialRecord,
    created_at: u64,
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let key_type = match record.private_key.kind() {
        KeyKind::P256Scalar => KEY_TYPE_P256_SCALAR,
        KeyKind::Seed => KEY_TYPE_SEED,
        KeyKind::RsaPrimes => KEY_TYPE_RSA_PRIMES,
    };
    let key = record.private_key.as_bytes();
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
        (6, Value::Integer(Integer::from(record.alg.identifier()))),
        (7, Value::Integer(Integer::from(key_type))),
        (8, Value::Bytes(key.to_vec())),
        (9, Value::Bytes(record.cred_random_with_uv.to_vec())),
        (10, Value::Bytes(record.cred_random_without_uv.to_vec())),
        (11, Value::Integer(Integer::from(record.cred_protect))),
        (12, Value::Integer(Integer::from(record.sign_count))),
        (13, Value::Integer(Integer::from(created_at))),
    ]);
    if let Some(blob) = &record.cred_blob {
        entries.push((14, Value::Bytes(blob.clone())));
    }
    if let Some(key) = &record.large_blob_key {
        entries.push((15, Value::Bytes(key.to_vec())));
    }
    encode_map(entries)
}

/// Decode and validate a credential record.
#[deny(
    clippy::wildcard_enum_match_arm,
    clippy::match_wildcard_for_single_variants
)]
pub(crate) fn decode_credential(bytes: &[u8]) -> Result<CredentialRecord, Corruption> {
    let mut fields = Fields::parse(bytes)?;
    let alg = CoseAlg::try_from(fields.int::<i32>(6)?).map_err(|_| Corruption::Encoding)?;
    let key_type = fields.uint::<u64>(7)?;
    let key = Zeroizing::new(fields.bytes(8)?);
    let kind = match key_type {
        KEY_TYPE_P256_SCALAR => KeyKind::P256Scalar,
        KEY_TYPE_SEED => KeyKind::Seed,
        KEY_TYPE_RSA_PRIMES => KeyKind::RsaPrimes,
        _ => return Err(Corruption::Encoding),
    };
    let private_key =
        PrivateKeyMaterial::from_bytes(kind, &key).map_err(|_| Corruption::Encoding)?;
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
        cred_blob: fields.optional_bytes(14)?,
        large_blob_key: fields.optional_array(15)?,
    };
    fields.finish()?;
    validate_credential(&record).map_err(|_| Corruption::Inconsistent)?;
    Ok(record)
}

/// Encode a PIN state record.
pub(crate) fn encode_pin_state(state: &PinStateRecord) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    validate_pin_state(state)?;
    let mut entries = Vec::with_capacity(9);
    if let Some(pin_hash) = &state.pin_hash {
        entries.push((1, Value::Bytes(pin_hash.to_vec())));
    }
    entries.extend([
        (2, Value::Integer(Integer::from(state.pin_retries))),
        (3, Value::Integer(Integer::from(state.consecutive_failures))),
        (4, Value::Bool(state.pin_auth_blocked)),
        (5, Value::Integer(Integer::from(state.min_pin_length))),
        (
            6,
            Value::Array(
                state
                    .min_pin_length_rp_ids
                    .iter()
                    .cloned()
                    .map(Value::Text)
                    .collect(),
            ),
        ),
        (7, Value::Bool(state.force_pin_change)),
        (
            8,
            Value::Integer(Integer::from(state.pin_code_point_length)),
        ),
        (9, Value::Bool(state.always_uv)),
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
        min_pin_length: fields
            .optional_uint(5)?
            .unwrap_or(PinStateRecord::DEFAULT_MIN_PIN_LENGTH),
        min_pin_length_rp_ids: fields.optional_text_array(6)?.unwrap_or_default(),
        force_pin_change: fields.optional_bool(7)?.unwrap_or(false),
        pin_code_point_length: fields
            .optional_uint(8)?
            .unwrap_or(PinStateRecord::DEFAULT_MIN_PIN_LENGTH),
        always_uv: fields.optional_bool(9)?.unwrap_or(false),
    };
    fields.finish()?;
    validate_pin_state(&state).map_err(|_| Corruption::Inconsistent)?;
    Ok(state)
}

/// Encode a valid serialized large-blob array.
pub(crate) fn encode_large_blob_array(array: &[u8]) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    validate_large_blob_array(array)?;
    encode_map(vec![(1, Value::Bytes(array.to_vec()))])
}

/// Decode a serialized large-blob array, checking only its length and hash.
pub(crate) fn decode_large_blob_array(bytes: &[u8]) -> Result<Vec<u8>, Corruption> {
    let mut fields = Fields::parse(bytes)?;
    let array = fields.bytes(1)?;
    fields.finish()?;
    validate_large_blob_array(&array).map_err(|_| Corruption::Inconsistent)?;
    Ok(array)
}

/// Encode a signature counter record.
pub(crate) fn encode_signature_counter(value: u32) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    encode_map(vec![(1, Value::Integer(Integer::from(value)))])
}

/// Decode a signature counter record.
pub(crate) fn decode_signature_counter(bytes: &[u8]) -> Result<u32, Corruption> {
    let mut fields = Fields::parse(bytes)?;
    let value = fields.uint(1)?;
    fields.finish()?;
    Ok(value)
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

    fn optional_bytes(&mut self, key: u64) -> Result<Option<Vec<u8>>, Corruption> {
        self.take(key).map(Item::into_bytes).transpose()
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

    fn optional_uint<T: TryFrom<u64>>(&mut self, key: u64) -> Result<Option<T>, Corruption> {
        self.take(key)
            .map(|item| {
                let integer = item.into_integer()?;
                u64::try_from(integer)
                    .ok()
                    .and_then(|value| T::try_from(value).ok())
                    .ok_or(Corruption::Encoding)
            })
            .transpose()
    }

    fn optional_bool(&mut self, key: u64) -> Result<Option<bool>, Corruption> {
        self.take(key)
            .map(|item| match item.0 {
                Value::Bool(value) => Ok(value),
                _ => Err(Corruption::Encoding),
            })
            .transpose()
    }

    fn optional_text_array(&mut self, key: u64) -> Result<Option<Vec<String>>, Corruption> {
        self.take(key)
            .map(|mut item| {
                let Value::Array(items) = &mut item.0 else {
                    return Err(Corruption::Encoding);
                };
                mem::take(items)
                    .into_iter()
                    .map(|value| Item(value).into_text())
                    .collect()
            })
            .transpose()
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
            private_key: PrivateKeyMaterial::Seed {
                seed: core::array::from_fn(|i| 0x20 + i as u8),
            },
            cred_random_with_uv: [0xaa; 32],
            cred_random_without_uv: [0xbb; 32],
            cred_blob: None,
            large_blob_key: None,
            cred_protect: 2,
            sign_count: 300,
            created_at: 70_000,
        }
    }

    /// Field 14, written independently from RFC 8949 as the other vectors.
    #[test]
    fn credential_blob_known_answers() {
        let mut record = credential();
        record.cred_blob = Some((0..32).collect());
        let expected = unhex(concat!(
            "ad",
            "0150000102030405060708090a0b0c0d0e0f",
            "026b6578616d706c652e636f6d",
            "03420102",
            "0465616c696365",
            "06382f0702",
            "085820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            "095820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "0a5820bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "0b020c19012c0d1a00011170",
            "0e5820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        ));
        assert_eq!(
            encode_credential(&record, 70_000).unwrap().as_slice(),
            expected
        );
        assert_eq!(decode_credential(&expected).unwrap(), record);
        record.cred_blob = Some(Vec::new());
        let mut empty = expected[..expected.len() - 35].to_vec();
        empty.extend_from_slice(&[0x0e, 0x40]);
        assert_eq!(
            encode_credential(&record, 70_000).unwrap().as_slice(),
            empty
        );
        assert_eq!(decode_credential(&empty).unwrap(), record);
        record.cred_blob = None;
        empty[0] = 0xac;
        empty.truncate(empty.len() - 2);
        assert_eq!(
            encode_credential(&record, 70_000).unwrap().as_slice(),
            empty
        );
        assert_eq!(decode_credential(&empty).unwrap(), record);
    }

    #[test]
    fn malformed_credential_blobs_are_corrupt() {
        let valid = encode_credential(&credential(), 1).unwrap();
        let wrong_type = edited(&valid, |e| set(e, 14, Value::Bool(true)));
        assert_eq!(decode_credential(&wrong_type), Err(Corruption::Encoding));
        let overlong = edited(&valid, |e| set(e, 14, Value::Bytes(vec![0x55; 33])));
        assert_eq!(decode_credential(&overlong), Err(Corruption::Inconsistent));
    }

    /// Field 15 uses an independent RFC 8949 vector; the earlier record
    /// vectors remain unchanged and decode without a large-blob key.
    #[test]
    fn large_blob_key_known_answer_and_legacy_default() {
        let mut record = credential();
        record.large_blob_key = Some(core::array::from_fn(|i| i as u8));
        let expected = unhex(concat!(
            "ad",
            "0150000102030405060708090a0b0c0d0e0f",
            "026b6578616d706c652e636f6d",
            "03420102",
            "0465616c696365",
            "06382f0702",
            "085820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            "095820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "0a5820bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "0b020c19012c0d1a00011170",
            "0f5820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        ));
        assert_eq!(
            encode_credential(&record, 70_000).unwrap().as_slice(),
            expected
        );
        assert_eq!(decode_credential(&expected).unwrap(), record);
        let legacy = edited(&expected, |entries| remove(entries, 15));
        assert!(decode_credential(&legacy).unwrap().large_blob_key.is_none());
    }

    #[test]
    fn malformed_large_blob_keys_are_corrupt() {
        let valid = encode_credential(&credential(), 1).unwrap();
        for value in std::iter::once(Value::Bool(true)).chain(
            [0, 1, 16, 31, 33, 64]
                .into_iter()
                .map(|length| Value::Bytes(vec![0; length])),
        ) {
            assert_eq!(
                decode_credential(&edited(&valid, |entries| set(entries, 15, value))),
                Err(Corruption::Encoding),
            );
        }
        let non_discoverable = edited(&valid, |entries| {
            set(entries, 1, Value::Bytes(vec![0; 33]));
            set(entries, 15, Value::Bytes(vec![0; 32]));
        });
        assert_eq!(
            decode_credential(&non_discoverable),
            Err(Corruption::Inconsistent)
        );
    }

    #[test]
    fn large_blob_array_known_answer() {
        let expected = unhex("a101518076be8b528d0075f7aae98d6fa57a6d3c");
        let array = super::super::INITIAL_LARGE_BLOB_ARRAY;
        assert_eq!(
            encode_large_blob_array(&array).unwrap().as_slice(),
            expected
        );
        assert_eq!(decode_large_blob_array(&expected).unwrap(), array);
        for value in [
            Value::Bool(true),
            Value::Bytes(vec![0; 16]),
            Value::Bytes(vec![0; 17]),
        ] {
            let malformed = edited(&expected, |entries| set(entries, 1, value));
            assert!(decode_large_blob_array(&malformed).is_err());
        }
        assert_eq!(
            decode_large_blob_array(&unhex("a0")),
            Err(Corruption::Encoding)
        );
        assert_eq!(
            decode_large_blob_array(&edited(&expected, |entries| set(entries, 2, Value::Null))),
            Err(Corruption::Encoding),
        );
    }

    fn pin_state() -> PinStateRecord {
        PinStateRecord {
            pin_hash: Some(core::array::from_fn(|i| (i as u8) * 0x11)),
            pin_retries: 5,
            consecutive_failures: 2,
            pin_auth_blocked: true,
            min_pin_length_rp_ids: Vec::new(),
            ..PinStateRecord::default()
        }
    }

    #[test]
    fn pin_policy_known_answers_and_legacy_defaults() {
        let legacy = unhex("a4015000112233445566778899aabbccddeeff0205030204f5");
        assert_eq!(decode_pin_state(&legacy).unwrap(), pin_state());
        let mut record = pin_state();
        record.min_pin_length = 8;
        record.min_pin_length_rp_ids = vec!["example.com".into(), "a".into()];
        record.force_pin_change = true;
        record.pin_code_point_length = 6;
        record.always_uv = true;
        let complete = unhex(concat!(
            "a9015000112233445566778899aabbccddeeff0205030204f5",
            "050806826b6578616d706c652e636f6d616107f5080609f5"
        ));
        assert_eq!(encode_pin_state(&record).unwrap().as_slice(), complete);
        assert_eq!(decode_pin_state(&complete).unwrap(), record);
        for key in 5..=9 {
            let missing = edited(&complete, |entries| remove(entries, key));
            assert!(decode_pin_state(&missing).is_ok(), "optional field {key}");
            let invalid = edited(&complete, |entries| set(entries, key, Value::Null));
            assert_eq!(decode_pin_state(&invalid), Err(Corruption::Encoding));
        }
    }

    #[test]
    fn invalid_pin_policy_is_corrupt_and_cannot_be_written() {
        let valid = encode_pin_state(&pin_state()).unwrap();
        for (key, value) in [
            (5, Value::Integer(3.into())),
            (5, Value::Integer(64.into())),
            (8, Value::Integer(3.into())),
            (8, Value::Integer(64.into())),
            (6, Value::Array(vec![Value::Text("a".into()); 9])),
            (6, Value::Array(vec![Value::Text("a".repeat(254))])),
        ] {
            assert_eq!(
                decode_pin_state(&edited(&valid, |e| set(e, key, value))),
                Err(Corruption::Inconsistent)
            );
        }
        assert_eq!(
            decode_pin_state(&edited(&valid, |e| {
                set(e, 6, Value::Array(vec![Value::Bool(false)]));
            })),
            Err(Corruption::Encoding)
        );
        let mut record = pin_state();
        record.min_pin_length = 3;
        assert!(matches!(
            encode_pin_state(&record),
            Err(StoreError::InvalidRecord(_))
        ));
        record.min_pin_length = 63;
        record.pin_code_point_length = 63;
        record.min_pin_length_rp_ids = vec!["a".repeat(253); 8];
        assert_eq!(
            decode_pin_state(&encode_pin_state(&record).unwrap()).unwrap(),
            record
        );
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
            unhex("a9015000112233445566778899aabbccddeeff0205030204f50504068007f4080409f4")
                .as_slice()
        );

        let counter = encode_signature_counter(70_000).unwrap();
        assert_eq!(counter.as_slice(), unhex("a1011a00011170").as_slice());
        assert_eq!(decode_signature_counter(&counter), Ok(70_000));
        assert_eq!(
            decode_signature_counter(&unhex("a1011b0000000100000000")),
            Err(Corruption::Encoding),
            "more than 32 bits"
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

    /// An ES256 credential: alg -7 and private key type 1, the P-256
    /// scalar.  Written out by hand like the vectors above; only those
    /// fields and the key differ from the ML-DSA credential there.
    #[test]
    fn an_es256_credential_matches_the_documented_format() {
        let mut record = credential();
        record.alg = CoseAlg::ES256;
        record.private_key = PrivateKeyMaterial::P256Scalar {
            scalar: core::array::from_fn(|i| 0x40 + i as u8),
        };
        let encoded = encode_credential(&record, 70_000).unwrap();
        let expected = unhex(concat!(
            "ac",                                   // map with 12 entries
            "0150000102030405060708090a0b0c0d0e0f", // 1: credential_id
            "026b6578616d706c652e636f6d",           // 2: rp_id "example.com"
            "03420102",                             // 3: user_id
            "0465616c696365",                       // 4: user_name "alice"
            "0626",                                 // 6: alg -7
            "0701",                                 // 7: key type, P-256 scalar
            // 8: the 32-byte scalar
            "085820404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            // 9: cred_random_with_uv
            "095820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            // 10: cred_random_without_uv
            "0a5820bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "0b02",         // 11: cred_protect 2
            "0c19012c",     // 12: sign_count 300
            "0d1a00011170", // 13: created_at 70000
        ));
        assert_eq!(encoded.as_slice(), expected.as_slice());
        assert_eq!(decode_credential(&expected).unwrap(), record);
    }

    /// RSA keeps p || q under key type 3. The CBOR surrounding the fixed
    /// cryptography vector is written independently of the encoder.
    #[test]
    fn an_rsa_credential_matches_the_documented_format() {
        let mut record = credential();
        record.alg = CoseAlg::RS256;
        record.private_key = PrivateKeyMaterial::RsaPrimes {
            primes: crate::rsa_fixture::PRIMES,
        };
        let expected = [
            unhex(concat!(
                "ac",
                "0150000102030405060708090a0b0c0d0e0f",
                "026b6578616d706c652e636f6d",
                "03420102",
                "0465616c696365",
                "06390100", // alg -257
                "0703",     // key type 3
                "08590100", // 256-byte key
            )),
            crate::rsa_fixture::PRIMES.to_vec(),
            unhex(concat!(
                "095820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "0a5820bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "0b02",
                "0c19012c",
                "0d1a00011170",
            )),
        ]
        .concat();
        assert_eq!(
            encode_credential(&record, 70_000)
                .expect("encode")
                .as_slice(),
            expected
        );
        assert_eq!(decode_credential(&expected).expect("decode"), record);
    }

    /// An ES384 credential: alg -35 and private key type 2, the seed its
    /// scalar is derived from.  Only those fields and the key differ from the
    /// ES256 credential above.
    #[test]
    fn an_es384_credential_matches_the_documented_format() {
        let mut record = credential();
        record.alg = CoseAlg::ES384;
        record.private_key = PrivateKeyMaterial::Seed {
            seed: core::array::from_fn(|i| 0x60 + i as u8),
        };
        let encoded = encode_credential(&record, 70_000).unwrap();
        let expected = unhex(concat!(
            "ac",                                   // map with 12 entries
            "0150000102030405060708090a0b0c0d0e0f", // 1: credential_id
            "026b6578616d706c652e636f6d",           // 2: rp_id "example.com"
            "03420102",                             // 3: user_id
            "0465616c696365",                       // 4: user_name "alice"
            "063822",                               // 6: alg -35
            "0702",                                 // 7: key type, seed
            // 8: the 32-byte seed
            "085820606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
            // 9: cred_random_with_uv
            "095820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            // 10: cred_random_without_uv
            "0a5820bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "0b02",         // 11: cred_protect 2
            "0c19012c",     // 12: sign_count 300
            "0d1a00011170", // 13: created_at 70000
        ));
        assert_eq!(encoded.as_slice(), expected.as_slice());
        assert_eq!(decode_credential(&expected).unwrap(), record);
    }

    /// An Ed448 credential: alg -53 and private key type 2, the seed its
    /// 57-byte private key is derived from.  Only those fields and the key
    /// differ from the ES384 credential above.
    #[test]
    fn an_ed448_credential_matches_the_documented_format() {
        let mut record = credential();
        record.alg = CoseAlg::Ed448;
        record.private_key = PrivateKeyMaterial::Seed {
            seed: core::array::from_fn(|i| 0x80 + i as u8),
        };
        let encoded = encode_credential(&record, 70_000).unwrap();
        let expected = unhex(concat!(
            "ac",                                   // map with 12 entries
            "0150000102030405060708090a0b0c0d0e0f", // 1: credential_id
            "026b6578616d706c652e636f6d",           // 2: rp_id "example.com"
            "03420102",                             // 3: user_id
            "0465616c696365",                       // 4: user_name "alice"
            "063834",                               // 6: alg -53
            "0702",                                 // 7: key type, seed
            // 8: the 32-byte seed
            "085820808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            // 9: cred_random_with_uv
            "095820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            // 10: cred_random_without_uv
            "0a5820bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "0b02",         // 11: cred_protect 2
            "0c19012c",     // 12: sign_count 300
            "0d1a00011170", // 13: created_at 70000
        ));
        assert_eq!(encoded.as_slice(), expected.as_slice());
        assert_eq!(decode_credential(&expected).unwrap(), record);
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
                edited(&valid, |e| set(e, 15, Value::Bool(true))),
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
                edited(&valid, |e| set(e, 6, Value::Integer(Integer::from(-260)))),
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
