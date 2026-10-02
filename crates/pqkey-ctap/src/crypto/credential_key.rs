//! Credential keys: generating them, by the kind of key material, and reading
//! them back, deriving their public key and signing with them, each
//! dispatched on the algorithm's [`Scheme`] to the family that implements it.

use p256::ecdsa::SigningKey as P256SigningKey;
use rand_core::TryCryptoRng;
use zeroize::{Zeroize, Zeroizing};

use super::CryptoError;
use super::alg::{CoseAlg, KeyKind, Scheme};
use super::mldsa::MlDsaSeed;
use super::{ecdsa_p256, mldsa};

/// A credential's signing key, named by its key type: algorithms that share
/// a key type share a variant.
#[derive(Debug)]
pub enum CredentialSecretKey {
    /// An ML-DSA key held as its 32-byte FIPS 204 seed `ξ`, the form stored
    /// credentials use.  Signing expands the seed directly, so no expanded
    /// secret key encoding is produced or decoded.
    MlDsa(MlDsaSeed),
    /// A P-256 private key, for ECDSA.
    P256(P256SigningKey),
}

impl CredentialSecretKey {
    /// Serialize the secret key into a byte buffer suitable for storage.
    ///
    /// The returned buffer is wrapped in [`Zeroizing`], so the copy is wiped
    /// when the caller drops it.  An ML-DSA key serializes to its 32-byte
    /// seed, which [`try_credential_secret_from_bytes`] accepts back.
    pub fn secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        match self {
            CredentialSecretKey::MlDsa(seed) => Zeroizing::new(seed.as_bytes().to_vec()),
            CredentialSecretKey::P256(sk) => {
                let mut scalar = sk.to_bytes();
                let out = Zeroizing::new(scalar.to_vec());
                scalar.zeroize();
                out
            }
        }
    }
}

/// Fresh key material of `kind` from `rng`: a P-256 scalar, or 32 random
/// bytes.
pub(crate) fn try_generate_key<R: TryCryptoRng + ?Sized>(
    kind: KeyKind,
    rng: &mut R,
) -> Result<Zeroizing<[u8; 32]>, R::Error> {
    let mut key = Zeroizing::new([0u8; 32]);
    match kind {
        KeyKind::P256Scalar => ecdsa_p256::generate_scalar(rng, &mut key)?,
        KeyKind::Seed => rng.try_fill_bytes(&mut key[..])?,
    }
    Ok(key)
}

/// Reconstruct a credential secret key from stored bytes.
///
/// `bytes` comes from persistent storage and is therefore not trusted: a
/// corrupted or truncated record must produce an error, never a panic.
///
/// Returns [`CryptoError::InvalidKey`] when the bytes are not a valid key for
/// the requested algorithm: a P-256 scalar (non-zero and below the group
/// order) or a 32-byte ML-DSA seed.
pub fn try_credential_secret_from_bytes(
    alg: CoseAlg,
    bytes: &[u8],
) -> Result<CredentialSecretKey, CryptoError> {
    match alg.scheme() {
        Scheme::EcdsaP256Sha256 => ecdsa_p256::signing_key(bytes).map(CredentialSecretKey::P256),
        Scheme::MlDsa(_) => mldsa::seed(bytes).map(CredentialSecretKey::MlDsa),
    }
}

/// The CBOR COSE_Key of `sk`'s public key, labelled with `alg`.
///
/// Returns [`CryptoError::KeyTypeMismatch`] when `alg` signs with another
/// type of key, [`CryptoError::MlDsa`] when an ML-DSA seed cannot be
/// expanded, and [`CryptoError::CborEncoding`] when the key cannot be
/// encoded.  None of these abort.
pub fn try_cose_public_key(alg: CoseAlg, sk: &CredentialSecretKey) -> Result<Vec<u8>, CryptoError> {
    match sk {
        CredentialSecretKey::P256(key) => match alg.scheme() {
            Scheme::EcdsaP256Sha256 => ecdsa_p256::cose_public_key(alg, key),
            Scheme::MlDsa(_) => Err(CryptoError::KeyTypeMismatch),
        },
        CredentialSecretKey::MlDsa(seed) => match alg.scheme() {
            Scheme::MlDsa(param_set) => mldsa::cose_public_key(alg, param_set, seed),
            Scheme::EcdsaP256Sha256 => Err(CryptoError::KeyTypeMismatch),
        },
    }
}

/// Sign `auth_data || client_data_hash` as `alg` signs, and return the
/// signature in the encoding WebAuthn requires for `alg`:
///
/// * **ES256**: ECDSA over P-256 with SHA-256, as an ASN.1 DER
///   `Ecdsa-Sig-Value`.
/// * **ML-DSA-44/65/87**: the raw FIPS 204 signature bytes.
///
/// Returns [`CryptoError::KeyTypeMismatch`] when `alg` signs with another
/// type of key, and [`CryptoError::MlDsa`] / [`CryptoError::SigningFailed`]
/// when the underlying signature operation fails.  None of these abort.
pub fn try_sign_challenge(
    alg: CoseAlg,
    sk: &CredentialSecretKey,
    auth_data: &[u8],
    client_data_hash: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut msg = Vec::with_capacity(auth_data.len() + client_data_hash.len());
    msg.extend_from_slice(auth_data);
    msg.extend_from_slice(client_data_hash);
    match sk {
        CredentialSecretKey::P256(key) => match alg.scheme() {
            Scheme::EcdsaP256Sha256 => ecdsa_p256::sign(key, &msg),
            Scheme::MlDsa(_) => Err(CryptoError::KeyTypeMismatch),
        },
        CredentialSecretKey::MlDsa(seed) => match alg.scheme() {
            Scheme::MlDsa(param_set) => mldsa::sign(param_set, seed, &msg),
            Scheme::EcdsaP256Sha256 => Err(CryptoError::KeyTypeMismatch),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::verify::{VerificationError, verify_signature};
    use crate::store::{CredentialRecord, PrivateKeyMaterial};
    use ciborium::{de::from_reader, ser::into_writer, value::Integer, value::Value};
    use p256::ecdsa::Signature as P256EcdsaSignature;
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use pqkey_mldsa::{SEED_LEN, verify};
    use sha2::{Digest, Sha256};

    /// A new credential's COSE public key and signing key, made as the
    /// engine makes them: fresh key material, then the key pair.
    fn generated(alg: CoseAlg) -> (Vec<u8>, CredentialSecretKey) {
        let record = CredentialRecord {
            credential_id: vec![0x01; 33],
            rp_id: "example.com".into(),
            user_id: vec![0x02; 16],
            user_name: None,
            user_display_name: None,
            alg,
            private_key: PrivateKeyMaterial::try_generate(alg).expect("generate key material"),
            cred_random_with_uv: [0; 32],
            cred_random_without_uv: [0; 32],
            cred_protect: 1,
            sign_count: 0,
            created_at: 0,
        };
        let (secret_key, public_key) = record.keypair().expect("materialise key pair");
        (public_key, secret_key)
    }

    #[test]
    fn mldsa_roundtrip_signatures() {
        for alg in [CoseAlg::MLDSA44, CoseAlg::MLDSA65, CoseAlg::MLDSA87] {
            let (public_key_cbor, secret_key) = generated(alg);
            assert!(!public_key_cbor.is_empty());
            let auth_data = b"auth_data";
            let client_hash = b"client_data_hash";
            let signature = try_sign_challenge(alg, &secret_key, auth_data, client_hash)
                .expect("ML-DSA signature");
            let message: Vec<u8> = auth_data.iter().chain(client_hash).cloned().collect();
            verify_signature(alg, &public_key_cbor, &message, &signature)
                .expect("the signature verifies");
        }
    }

    /// An ML-DSA key held as its seed signs, serializes to the seed, reads back
    /// from it, and never prints it.
    #[test]
    fn mldsa_seed_key_signs_and_round_trips() {
        for alg in [CoseAlg::MLDSA44, CoseAlg::MLDSA65, CoseAlg::MLDSA87] {
            let Scheme::MlDsa(ps) = alg.scheme() else {
                panic!("{alg:?} is not ML-DSA");
            };
            let seed = [0x3c; SEED_LEN];
            let (pk, _) = pqkey_mldsa::try_keypair_from_seed(ps, &seed).expect("keygen");

            let key = CredentialSecretKey::MlDsa(MlDsaSeed::new(seed));
            assert_eq!(key.secret_bytes().as_slice(), &seed[..]);
            let rendered = format!("{key:?}");
            assert!(
                rendered.contains("redacted") && !rendered.contains("60"),
                "{rendered}"
            );

            let reloaded = try_credential_secret_from_bytes(alg, &key.secret_bytes()).unwrap();
            let CredentialSecretKey::MlDsa(_) = reloaded else {
                panic!("{alg:?}: the seed reads back as {reloaded:?}");
            };
            for key in [&key, &reloaded] {
                let signature = try_sign_challenge(alg, key, b"auth", b"hash").expect("sign");
                assert!(verify(ps, &pk, b"authhash", &signature));
            }
            assert!(matches!(
                try_sign_challenge(CoseAlg::ES256, &key, b"auth", b"hash"),
                Err(CryptoError::KeyTypeMismatch)
            ));
        }
    }

    #[test]
    fn es256_credential_roundtrip() {
        let (cose_key, secret_key) = generated(CoseAlg::ES256);
        assert_eq!(secret_key.secret_bytes().len(), 32);

        let value: Value = from_reader(cose_key.as_slice()).expect("decode ES256 COSE key");
        let Value::Map(entries) = value else {
            panic!("COSE key must be a map");
        };

        let mut kty = None;
        let mut alg = None;
        let mut crv = None;
        let mut x_bytes = None;
        let mut y_bytes = None;

        for (key, val) in entries {
            if let Value::Integer(label) = key {
                let label_value: i128 = label.into();
                match label_value {
                    1 => kty = Some(val),
                    3 => alg = Some(val),
                    -1 => crv = Some(val),
                    -2 => {
                        if let Value::Bytes(bytes) = val {
                            x_bytes = Some(bytes);
                        }
                    }
                    -3 => {
                        if let Value::Bytes(bytes) = val {
                            y_bytes = Some(bytes);
                        }
                    }
                    _ => {}
                }
            }
        }

        assert_eq!(kty, Some(Value::Integer(Integer::from(2))), "kty present");
        assert_eq!(
            alg,
            Some(Value::Integer(Integer::from(CoseAlg::ES256.identifier()))),
            "alg present"
        );
        assert_eq!(crv, Some(Value::Integer(Integer::from(1))), "crv present");

        let x_bytes = x_bytes.expect("x coordinate present");
        assert_eq!(x_bytes.len(), 32);
        let y_bytes = y_bytes.expect("y coordinate present");
        assert_eq!(y_bytes.len(), 32);

        let reconstructed =
            try_credential_secret_from_bytes(CoseAlg::ES256, &secret_key.secret_bytes())
                .expect("reconstruct P-256 secret");
        let CredentialSecretKey::P256(_) = reconstructed else {
            panic!("unexpected key variant");
        };
    }

    // ---------------------------------------------------------------------
    // Fallible APIs return errors rather than panicking
    // ---------------------------------------------------------------------

    #[test]
    fn try_sign_challenge_rejects_mismatched_key_variant() {
        let (_, ml_dsa_key) = generated(CoseAlg::MLDSA44);
        let (_, es256_key) = generated(CoseAlg::ES256);

        // Stored `alg` says ES256 but the key on disk is ML-DSA.
        assert_eq!(
            try_sign_challenge(CoseAlg::ES256, &ml_dsa_key, b"auth", b"hash"),
            Err(CryptoError::KeyTypeMismatch)
        );
        // Stored `alg` says ML-DSA but the key on disk is P-256.
        for alg in [CoseAlg::MLDSA44, CoseAlg::MLDSA65, CoseAlg::MLDSA87] {
            assert_eq!(
                try_sign_challenge(alg, &es256_key, b"auth", b"hash"),
                Err(CryptoError::KeyTypeMismatch)
            );
        }
    }

    /// A stored ML-DSA key is its 32-byte seed. Anything else, a truncated
    /// or corrupted record or an expanded secret key, is not a key.
    #[test]
    fn try_credential_secret_from_bytes_accepts_only_ml_dsa_seeds() {
        for alg in [CoseAlg::MLDSA44, CoseAlg::MLDSA65, CoseAlg::MLDSA87] {
            for len in [0, 7, SEED_LEN - 1, SEED_LEN + 1, 2560] {
                assert_eq!(
                    try_credential_secret_from_bytes(alg, &vec![0x42; len]).err(),
                    Some(CryptoError::InvalidKey),
                    "{alg:?}, {len} bytes"
                );
            }
        }
    }

    #[test]
    fn try_credential_secret_from_bytes_rejects_malformed_p256_scalar() {
        // `CredentialSecretKey` deliberately has no `PartialEq` (secret keys
        // must not be compared with `==`), so inspect the error side only.
        let err = |bytes: &[u8]| {
            try_credential_secret_from_bytes(CoseAlg::ES256, bytes).expect_err("must be rejected")
        };
        // Wrong length, including the 24 to 31 bytes that elliptic-curve's
        // `from_slice` would pad into a valid scalar.
        for len in [5, 24, 31, 33] {
            assert_eq!(
                err(&vec![0x11; len]),
                CryptoError::InvalidKey,
                "{len} bytes"
            );
        }
        // Correct length but not a valid scalar: zero is rejected.
        assert_eq!(err(&[0x00; 32]), CryptoError::InvalidKey);
        // Correct length but above the group order.
        assert_eq!(err(&[0xFF; 32]), CryptoError::InvalidKey);
    }

    // ---------------------------------------------------------------------
    // ES256 signature format (WebAuthn)
    // ---------------------------------------------------------------------

    /// WebAuthn requires an ES256 assertion signature to be ECDSA-P256-SHA256
    /// over `authData || clientDataHash`, encoded as an ASN.1 DER
    /// `Ecdsa-Sig-Value`.  Verifying the returned bytes as DER against the
    /// explicitly-computed SHA-256 prehash of that exact message pins all three
    /// properties at once.
    #[test]
    fn es256_signature_is_der_over_sha256_of_auth_data_and_client_data_hash() {
        let (_, secret_key) = generated(CoseAlg::ES256);
        let CredentialSecretKey::P256(sk) = &secret_key else {
            panic!("expected a P-256 key");
        };
        let verifying_key = *sk.verifying_key();

        let auth_data = [0x11u8; 37];
        let client_data_hash = [0x22u8; 32];
        let der = try_sign_challenge(CoseAlg::ES256, &secret_key, &auth_data, &client_data_hash)
            .expect("ES256 signature");

        // Must parse as DER (SEQUENCE of two INTEGERs), not as a fixed-width
        // r || s pair.
        assert_eq!(der[0], 0x30, "DER SEQUENCE tag");
        assert_ne!(der.len(), 64, "must not be the raw 64-byte encoding");
        let signature = P256EcdsaSignature::from_der(&der).expect("valid DER Ecdsa-Sig-Value");

        let mut message = auth_data.to_vec();
        message.extend_from_slice(&client_data_hash);
        let prehash = Sha256::digest(&message);
        verifying_key
            .verify_prehash(&prehash, &signature)
            .expect("signature verifies over SHA-256(authData || clientDataHash)");

        // A different message must not verify.
        let other = Sha256::digest(b"something else");
        assert!(verifying_key.verify_prehash(&other, &signature).is_err());
    }

    // ---------------------------------------------------------------------
    // The test verifier
    // ---------------------------------------------------------------------

    /// `cose_key` with its entries changed by `edit`.
    fn edited(cose_key: &[u8], edit: impl FnOnce(&mut Vec<(Value, Value)>)) -> Vec<u8> {
        let Value::Map(mut entries) = from_reader(cose_key).expect("a COSE_Key") else {
            panic!("a COSE_Key is a map");
        };
        edit(&mut entries);
        let mut out = Vec::new();
        into_writer(&Value::Map(entries), &mut out).expect("encode");
        out
    }

    /// `cose_key` with label `label` set to `value`.
    fn with_label(cose_key: &[u8], label: i64, value: Value) -> Vec<u8> {
        edited(cose_key, |entries| {
            let label = Value::Integer(Integer::from(label));
            entries.retain(|(found, _)| *found != label);
            entries.push((label, value));
        })
    }

    /// The verifier accepts a signature under the key that made it, and
    /// nothing else: not over another message, not under another key, and
    /// not as another algorithm's.
    #[test]
    fn the_verifier_accepts_only_a_signature_under_its_key() {
        for alg in CoseAlg::ALL {
            let (cose_key, secret_key) = generated(alg);
            let signature = try_sign_challenge(alg, &secret_key, b"auth", b"hash").expect("sign");
            assert_eq!(
                verify_signature(alg, &cose_key, b"authhash", &signature),
                Ok(()),
                "{alg:?}"
            );
            assert_eq!(
                verify_signature(alg, &cose_key, b"authhasH", &signature),
                Err(VerificationError::BadSignature),
                "{alg:?}: another message"
            );
            let (other_key, _) = generated(alg);
            assert_eq!(
                verify_signature(alg, &other_key, b"authhash", &signature),
                Err(VerificationError::BadSignature),
                "{alg:?}: another key"
            );
            for other in CoseAlg::ALL.into_iter().filter(|other| *other != alg) {
                assert!(
                    matches!(
                        verify_signature(other, &cose_key, b"authhash", &signature),
                        Err(VerificationError::MalformedKey(_))
                    ),
                    "{alg:?} as {other:?}"
                );
            }
        }
    }

    /// A key that is not of its algorithm's shape is malformed, whatever the
    /// signature.
    #[test]
    fn the_verifier_rejects_keys_of_another_shape() {
        let int = |value: i64| Value::Integer(Integer::from(value));
        let (es256, _) = generated(CoseAlg::ES256);
        let (mldsa65, _) = generated(CoseAlg::MLDSA65);
        let mut not_a_map = Vec::new();
        into_writer(&Value::Array(Vec::new()), &mut not_a_map).expect("encode");
        for (alg, name, cose_key) in [
            (CoseAlg::ES256, "kty OKP", with_label(&es256, 1, int(1))),
            (CoseAlg::ES256, "crv P-384", with_label(&es256, -1, int(2))),
            (
                CoseAlg::ES256,
                "the compressed point form",
                with_label(&es256, -3, Value::Bool(true)),
            ),
            (
                CoseAlg::ES256,
                "a 31-byte x",
                with_label(&es256, -2, Value::Bytes(vec![0x11; 31])),
            ),
            (
                CoseAlg::ES256,
                "a point off the curve",
                with_label(&es256, -3, Value::Bytes(vec![0; 32])),
            ),
            (
                CoseAlg::ES256,
                "a private key",
                with_label(&es256, -4, Value::Bytes(vec![0x11; 32])),
            ),
            (
                CoseAlg::ES256,
                "no crv",
                edited(&es256, |entries| {
                    entries.retain(|(label, _)| *label != int(-1))
                }),
            ),
            (
                CoseAlg::ES256,
                "a trailing byte",
                [es256.clone(), vec![0]].concat(),
            ),
            (CoseAlg::ES256, "not a map", not_a_map),
            (CoseAlg::MLDSA65, "kty EC2", with_label(&mldsa65, 1, int(2))),
            (
                CoseAlg::MLDSA65,
                "an ML-DSA-44 sized pub",
                with_label(&mldsa65, -1, Value::Bytes(vec![0x11; 1312])),
            ),
        ] {
            assert!(
                matches!(
                    verify_signature(alg, &cose_key, b"message", b"signature"),
                    Err(VerificationError::MalformedKey(_))
                ),
                "{name}"
            );
        }
    }
}
