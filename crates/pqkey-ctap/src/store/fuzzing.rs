//! The store's record decoders for the fuzz crate's `store_records` target,
//! built only with the `test-support` feature.
//!
//! The store promises that a corrupted or truncated record produces an
//! error, never a panic.  [`check`] runs one input through the decoder of one
//! [`Object`] and reports a broken promise through its result; the fuzz target
//! panics on it.  [`seeds`] are valid encodings for the target's seed corpus,
//! built with the store's own encoders.  Neither exposes the store's internal
//! types.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::codec::{
    decode_attestation, decode_credential, decode_large_blob_array, decode_pin_state,
    decode_signature_counter, encode_attestation, encode_credential, encode_large_blob_array,
    encode_pin_state, encode_signature_counter,
};
use super::envelope::{self, MAX_ENVELOPE_LEN, NONCE_LEN, OVERHEAD, RecordType};
use super::keys::{CredentialKeys, RootKey};
use super::manifest::{self, Location, Manifest};
use super::{
    AttestationRecord, Corruption, CredentialRecord, INITIAL_LARGE_BLOB_ARRAY,
    PersistentTokenRecord, PinStateRecord, PrivateKeyMaterial, StoreError,
};
use crate::CoseAlg;
use crate::credential_id::{
    CREDENTIAL_ID_LENGTH, DISCOVERABLE_MARKER, NON_DISCOVERABLE_MARKER, SEALED_ID_LENGTH,
    SEALED_MARKER,
};

/// An object the store decodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Object {
    /// A credential record (record type 1).
    Credential,
    /// The PIN state record (record type 2).
    PinState,
    /// The attestation record (record type 3).
    Attestation,
    /// The global signature counter record (record type 4).
    SignatureCounter,
    /// The serialized large-blob array record (record type 5).
    LargeBlobArray,
    /// The credential-set manifest, the authoritative list of active
    /// credentials (record type 6).
    Manifest,
    /// An envelope, the only object the store parses before authenticating
    /// it.
    Envelope,
}

impl Object {
    /// Every object.
    pub const ALL: [Object; 7] = [
        Object::Credential,
        Object::PinState,
        Object::Attestation,
        Object::SignatureCounter,
        Object::LargeBlobArray,
        Object::Manifest,
        Object::Envelope,
    ];
}

/// The root key whose record subkey [`check`] opens envelopes with.
const CHECK_ROOT: [u8; RootKey::LEN] = [0xc7; RootKey::LEN];

/// The root key the envelope seeds are sealed under: any key but
/// [`CHECK_ROOT`], so that they fail at the authentication tag, the furthest
/// bytes not sealed under that key get.
const SEED_ROOT: [u8; RootKey::LEN] = [0x5e; RootKey::LEN];

/// Every record type, with a logical name the store binds it to.
const RECORD_TYPES: [(RecordType, &str); 7] = [
    (
        RecordType::Credential,
        "credentials/000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    ),
    (RecordType::PinState, "pin-state"),
    (RecordType::Attestation, "attestation"),
    (RecordType::SignatureCounter, "signature-counter"),
    (RecordType::LargeBlobArray, "large-blobs"),
    (RecordType::CredentialSet, "credential-set/active"),
    (RecordType::CredentialFormat, "credential-format"),
];

/// PIN states written before the PIN policy fields existed, the known
/// answers of codec's `pin_policy_known_answers_and_legacy_defaults` test:
/// keys 1–4 only, and keys 1–9, before `pin_complexity_policy`.
const LEGACY_PIN_STATES: [&[u8]; 2] = [
    &[
        0xa4, 0x01, 0x50, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff, 0x02, 0x05, 0x03, 0x02, 0x04, 0xf5,
    ],
    &[
        0xa9, 0x01, 0x50, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff, 0x02, 0x05, 0x03, 0x02, 0x04, 0xf5, 0x05, 0x04, 0x06, 0x80, 0x07,
        0xf4, 0x08, 0x04, 0x09, 0xf4,
    ],
];

/// Run `bytes` through the decoder of `object`.
///
/// Returns `Ok(true)` if the input got as far as the decoder goes, `Ok(false)`
/// if it was rejected before that, and `Err`, saying how, if the store broke
/// its promise:
///
/// * A record or manifest that decodes must encode again, and that encoding
///   must decode to an equal value.  The bytes need not be the same: the
///   decoders accept non-canonical CBOR, and records written before later
///   optional fields existed.  `Ok(true)` means the input decoded.
/// * No envelope opens.  The input is opened as every record type, under the
///   name the store binds that type to and a fixed key, and the tag of bytes
///   not sealed under that key never verifies.  `Ok(true)` means it reached
///   the tag as some record type, `Ok(false)` that its length or header was
///   rejected every time.
///
/// Inputs longer than the largest plaintext the store decodes are `Ok(false)`
/// without being decoded.  This never panics.
pub fn check(object: Object, bytes: &[u8]) -> Result<bool, String> {
    if bytes.len() > MAX_ENVELOPE_LEN - OVERHEAD {
        return Ok(false);
    }
    match object {
        Object::Credential => round_trip(bytes, decode_credential, |record| {
            encode_credential(record, record.created_at)
        }),
        Object::PinState => round_trip(bytes, decode_pin_state, encode_pin_state),
        Object::Attestation => round_trip(bytes, decode_attestation, encode_attestation),
        Object::SignatureCounter => round_trip(bytes, decode_signature_counter, |value| {
            encode_signature_counter(*value)
        }),
        Object::LargeBlobArray => round_trip(bytes, decode_large_blob_array, |array| {
            encode_large_blob_array(array)
        }),
        Object::Manifest => round_trip(bytes, manifest::decode, manifest::encode),
        Object::Envelope => never_opens(bytes),
    }
}

/// Decode `bytes`, encode the result, and decode that again.
fn round_trip<T: PartialEq>(
    bytes: &[u8],
    decode: impl Fn(&[u8]) -> Result<T, Corruption>,
    encode: impl FnOnce(&T) -> Result<Zeroizing<Vec<u8>>, StoreError>,
) -> Result<bool, String> {
    let Ok(decoded) = decode(bytes) else {
        return Ok(false);
    };
    let encoded =
        encode(&decoded).map_err(|err| format!("a decoded record does not encode: {err}"))?;
    let again = decode(&encoded)
        .map_err(|reason| format!("a re-encoded record does not decode: {reason}"))?;
    if again == decoded {
        Ok(true)
    } else {
        Err("a re-encoded record decodes to a different one".into())
    }
}

/// Open `envelope` as every record type under the [`CHECK_ROOT`] key.
fn never_opens(envelope: &[u8]) -> Result<bool, String> {
    let keys = CredentialKeys::derive(&RootKey::from_bytes(CHECK_ROOT))
        .map_err(|err| format!("the fixed key cannot be derived: {err}"))?;
    let mut reached_tag = false;
    for (record_type, name) in RECORD_TYPES {
        match envelope::open(&keys.record, record_type, name, envelope) {
            Ok(_) => return Err(format!("an envelope opened as {name}")),
            Err(Corruption::Authentication) => reached_tag = true,
            Err(_) => {}
        }
    }
    Ok(reached_tag)
}

/// Valid encodings of every [`Object`], built with the store's own encoders,
/// for the seed corpus of the fuzz crate's `store_records` target.
///
/// They hold every kind of private key, credentials with and without their
/// optional fields under every form of credential ID, PIN states with and
/// without persistent tokens, records in the shapes written before later
/// optional fields existed, and an envelope of every record type, sealed
/// under a key other than the one [`check`] opens envelopes with.  Every seed
/// passes [`check`] with `Ok(true)`, and every call returns the same seeds.
///
/// Empty only if one of the encoders fails on these fixed values, which the
/// fuzz crate's tests catch; like [`check`], this never panics.
pub fn seeds() -> Vec<(Object, Vec<u8>)> {
    try_seeds().unwrap_or_default()
}

fn try_seeds() -> Result<Vec<(Object, Vec<u8>)>, StoreError> {
    let mut seeds = Vec::new();
    for record in credentials() {
        let encoded = encode_credential(&record, record.created_at)?;
        seeds.push((Object::Credential, encoded.to_vec()));
    }
    for state in pin_states() {
        seeds.push((Object::PinState, encode_pin_state(&state)?.to_vec()));
    }
    for legacy in LEGACY_PIN_STATES {
        seeds.push((Object::PinState, legacy.to_vec()));
    }
    seeds.push((
        Object::Attestation,
        encode_attestation(&attestation())?.to_vec(),
    ));
    for value in [70_000, u32::MAX] {
        let encoded = encode_signature_counter(value)?;
        seeds.push((Object::SignatureCounter, encoded.to_vec()));
    }
    for array in [INITIAL_LARGE_BLOB_ARRAY.to_vec(), large_blob_array()] {
        let encoded = encode_large_blob_array(&array)?;
        seeds.push((Object::LargeBlobArray, encoded.to_vec()));
    }
    for manifest in [credential_set(), Manifest::new()] {
        seeds.push((Object::Manifest, manifest::encode(&manifest)?.to_vec()));
    }
    // Each envelope holds the first seed of its record type, under a fixed
    // nonce rather than a random one so that the seeds never change.
    let keys = CredentialKeys::derive(&RootKey::from_bytes(SEED_ROOT))?;
    let mut envelopes = Vec::with_capacity(RECORD_TYPES.len());
    for (record_type, name) in RECORD_TYPES {
        let plaintext = match contents(record_type) {
            Some(object) => seeds
                .iter()
                .find(|(seed, _)| *seed == object)
                .map_or(&[][..], |(_, bytes)| bytes.as_slice()),
            None => manifest::FORMAT,
        };
        let nonce = [record_type as u8; NONCE_LEN];
        let sealed = envelope::seal_with_nonce(&keys.record, record_type, name, &nonce, plaintext)?;
        envelopes.push((Object::Envelope, sealed));
    }
    seeds.extend(envelopes);
    Ok(seeds)
}

/// The object an envelope of `record_type` holds, or `None` for the
/// credential format marker, which is bytes rather than a record.
fn contents(record_type: RecordType) -> Option<Object> {
    match record_type {
        RecordType::Credential => Some(Object::Credential),
        RecordType::PinState => Some(Object::PinState),
        RecordType::Attestation => Some(Object::Attestation),
        RecordType::SignatureCounter => Some(Object::SignatureCounter),
        RecordType::LargeBlobArray => Some(Object::LargeBlobArray),
        RecordType::CredentialSet => Some(Object::Manifest),
        RecordType::CredentialFormat => None,
    }
}

/// A stored credential's ID: `marker` and 32 bytes of `fill`.
fn stored_id(marker: u8, fill: u8) -> Vec<u8> {
    core::iter::once(marker)
        .chain([fill; CREDENTIAL_ID_LENGTH - 1])
        .collect()
}

/// Credentials of every kind of private key and form of credential ID.
fn credentials() -> Vec<CredentialRecord> {
    // Codec's known-answer record, with no optional field, as written before
    // credBlob, largeBlobKey and thirdPartyPayment existed.
    let known_answer = CredentialRecord {
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
        third_party_payment: false,
        cred_protect: 2,
        sign_count: 300,
        created_at: 70_000,
    };

    // Non-discoverable credentials keep no user ID or names.
    let mut es256 = known_answer.clone();
    es256.credential_id = stored_id(NON_DISCOVERABLE_MARKER, 0x11);
    es256.user_id = Vec::new();
    es256.user_name = None;
    es256.alg = CoseAlg::ES256;
    es256.private_key = PrivateKeyMaterial::P256Scalar {
        scalar: core::array::from_fn(|i| 0x40 + i as u8),
    };

    let mut rsa = es256.clone();
    rsa.credential_id = stored_id(NON_DISCOVERABLE_MARKER, 0x22);
    rsa.alg = CoseAlg::RS256;
    rsa.private_key = PrivateKeyMaterial::RsaPrimes {
        primes: crate::rsa_fixture::PRIMES,
    };
    rsa.third_party_payment = true;

    // The credential a sealed credential ID carries, which has no signature
    // counter or creation order of its own.
    let mut sealed = es256.clone();
    sealed.credential_id = vec![0x33; SEALED_ID_LENGTH];
    if let Some(marker) = sealed.credential_id.first_mut() {
        *marker = SEALED_MARKER;
    }
    sealed.alg = CoseAlg::ES384;
    sealed.private_key = PrivateKeyMaterial::Seed {
        seed: core::array::from_fn(|i| 0x60 + i as u8),
    };
    sealed.cred_protect = 3;
    sealed.sign_count = 0;
    sealed.created_at = 0;

    let mut complete = known_answer.clone();
    complete.credential_id = stored_id(DISCOVERABLE_MARKER, 0x44);
    complete.user_display_name = Some("Ålice 🔑".into());
    complete.alg = CoseAlg::MLDSA87;
    complete.cred_blob = Some((0..32).collect());
    complete.large_blob_key = Some(core::array::from_fn(|i| 0xd0 + i as u8));
    complete.third_party_payment = true;
    complete.cred_protect = 1;
    complete.sign_count = u32::MAX;
    complete.created_at = u64::MAX;

    // An ID of 32 random bytes, from before IDs had a marker byte.
    let mut unmarked = known_answer.clone();
    unmarked.credential_id = (0x80..0xa0).collect();
    unmarked.alg = CoseAlg::Ed448;
    unmarked.private_key = PrivateKeyMaterial::Seed {
        seed: core::array::from_fn(|i| 0x80 + i as u8),
    };
    unmarked.cred_blob = Some(Vec::new());

    vec![known_answer, es256, rsa, sealed, complete, unmarked]
}

/// The state after a reset, and one with a PIN, every policy field and both
/// persistent tokens.
fn pin_states() -> [PinStateRecord; 2] {
    let configured = PinStateRecord {
        pin_hash: Some(core::array::from_fn(|i| (i as u8) * 0x11)),
        pin_retries: 5,
        consecutive_failures: 2,
        pin_auth_blocked: false,
        min_pin_length: 8,
        min_pin_length_rp_ids: vec!["example.com".into(), "a".into()],
        force_pin_change: false,
        pin_code_point_length: 6,
        always_uv: true,
        pin_complexity_policy: true,
        persistent_tokens: [
            Some(PersistentTokenRecord {
                secret: [0x61; 32],
                granted: true,
            }),
            Some(PersistentTokenRecord {
                secret: [0x62; 32],
                granted: false,
            }),
        ],
    };
    [PinStateRecord::default(), configured]
}

fn attestation() -> AttestationRecord {
    AttestationRecord {
        private_key: [0x42; 32],
        certificate_chain: vec![vec![0x30, 0x82, 0x01, 0x0a], vec![0x30, 0x82, 0x01, 0x0b]],
    }
}

/// A 1,024-byte serialized large-blob array: opaque contents, then the first
/// 16 bytes of their SHA-256 (CTAP 2.3 §6.10.1).
fn large_blob_array() -> Vec<u8> {
    let mut array: Vec<u8> = (0..=u8::MAX).cycle().take(1_008).collect();
    let hash = Sha256::digest(&array);
    array.extend_from_slice(&hash[..16]);
    array
}

/// Credentials both where the store first kept them and in the managed
/// namespace.
fn credential_set() -> Manifest {
    [
        ("01".repeat(32), Location::Legacy),
        ("7f".repeat(32), Location::Managed),
        ("ab".repeat(32), Location::Managed),
    ]
    .into_iter()
    .collect()
}
