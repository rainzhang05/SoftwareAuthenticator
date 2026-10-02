//! Credential keys: generating them, by the kind of key material, and reading
//! them back, deriving their public key and signing with them, each
//! dispatched on the algorithm's [`Scheme`] to the family that implements it.

use core::fmt;
use p256::ecdsa::SigningKey as P256SigningKey;
use rand_core::TryCryptoRng;
use zeroize::{Zeroize, Zeroizing};

use super::CryptoError;
use super::alg::{CoseAlg, KeyKind, Scheme};
use super::ecdsa::Curve;
use super::{ecdsa_p256, ecdsa_p384, ecdsa_p521, ecdsa_secp256k1, mldsa};

/// A credential's signing key, named by its key type: algorithms that share
/// a key type share a variant.
#[derive(Debug)]
pub enum CredentialSecretKey {
    /// An ML-DSA key held as its 32-byte FIPS 204 seed `ξ`, the form stored
    /// credentials use.  Signing expands the seed directly, so no expanded
    /// secret key encoding is produced or decoded.
    MlDsa(Seed),
    /// A P-256 private key, for ECDSA: ES256 and ESP256.
    P256(P256SigningKey),
    /// An ECDSA key on P-384 held as the seed its scalar is derived from, the
    /// form stored credentials use: ES384 and ESP384.  Each use derives the
    /// scalar anew.
    P384(Seed),
    /// An ECDSA key on P-521 held as the seed its scalar is derived from, the
    /// form stored credentials use: ES512 and ESP512.  Each use derives the
    /// scalar anew.
    P521(Seed),
    /// An ECDSA key on secp256k1 held as the seed its scalar is derived
    /// from, the form stored credentials use: ES256K.  Each use derives the
    /// scalar anew.
    Secp256k1(Seed),
}

impl CredentialSecretKey {
    /// Serialize the secret key into a byte buffer suitable for storage.
    ///
    /// The returned buffer is wrapped in [`Zeroizing`], so the copy is wiped
    /// when the caller drops it.  A key held as a seed serializes to its 32
    /// bytes, which [`try_credential_secret_from_bytes`] accepts back.
    pub fn secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        match self {
            CredentialSecretKey::MlDsa(seed)
            | CredentialSecretKey::P384(seed)
            | CredentialSecretKey::P521(seed)
            | CredentialSecretKey::Secp256k1(seed) => Zeroizing::new(seed.as_bytes().to_vec()),
            CredentialSecretKey::P256(sk) => {
                let mut scalar = sk.to_bytes();
                let out = Zeroizing::new(scalar.to_vec());
                scalar.zeroize();
                out
            }
        }
    }
}

/// The 32-byte seed a credential key is kept as ([`KeyKind::Seed`]), from
/// which its algorithm derives the key: for ML-DSA, the FIPS 204
/// key-generation seed `ξ`, and for ECDSA, the seed its scalar is derived
/// from.
///
/// Zeroized on drop; its `Debug` output is redacted.
pub struct Seed(Zeroizing<[u8; 32]>);

impl Seed {
    /// Wrap a seed.  The caller remains responsible for zeroizing `seed`'s
    /// own copy.
    pub fn new(seed: [u8; 32]) -> Self {
        Seed(Zeroizing::new(seed))
    }

    /// Borrow the seed bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Seed(<redacted>)")
    }
}

/// The seed whose bytes are `bytes`.  Stored keys of [`KeyKind::Seed`] are
/// seeds; an expanded secret key is never stored, so it is not accepted
/// either.
///
/// Returns [`CryptoError::InvalidKey`] unless `bytes` is exactly 32 bytes.
fn seed(bytes: &[u8]) -> Result<Seed, CryptoError> {
    <[u8; 32]>::try_from(bytes)
        .map(Seed::new)
        .map_err(|_| CryptoError::InvalidKey)
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
/// order) or a 32-byte seed.
pub fn try_credential_secret_from_bytes(
    alg: CoseAlg,
    bytes: &[u8],
) -> Result<CredentialSecretKey, CryptoError> {
    match alg.scheme() {
        Scheme::Ecdsa(Curve::P256) => ecdsa_p256::signing_key(bytes).map(CredentialSecretKey::P256),
        Scheme::Ecdsa(Curve::P384) => seed(bytes).map(CredentialSecretKey::P384),
        Scheme::Ecdsa(Curve::P521) => seed(bytes).map(CredentialSecretKey::P521),
        Scheme::Ecdsa(Curve::Secp256k1) => seed(bytes).map(CredentialSecretKey::Secp256k1),
        Scheme::MlDsa(_) => seed(bytes).map(CredentialSecretKey::MlDsa),
    }
}

/// The CBOR COSE_Key of `sk`'s public key, labelled with `alg`.
///
/// Returns [`CryptoError::KeyTypeMismatch`] when `alg` signs with another
/// type of key, [`CryptoError::MlDsa`] when an ML-DSA seed cannot be
/// expanded, and [`CryptoError::CborEncoding`] when the key cannot be
/// encoded.  None of these abort.
pub fn try_cose_public_key(alg: CoseAlg, sk: &CredentialSecretKey) -> Result<Vec<u8>, CryptoError> {
    match (sk, alg.scheme()) {
        (CredentialSecretKey::P256(key), Scheme::Ecdsa(Curve::P256)) => {
            ecdsa_p256::cose_public_key(alg, key)
        }
        (CredentialSecretKey::P384(seed), Scheme::Ecdsa(Curve::P384)) => {
            ecdsa_p384::cose_public_key(alg, seed)
        }
        (CredentialSecretKey::P521(seed), Scheme::Ecdsa(Curve::P521)) => {
            ecdsa_p521::cose_public_key(alg, seed)
        }
        (CredentialSecretKey::Secp256k1(seed), Scheme::Ecdsa(Curve::Secp256k1)) => {
            ecdsa_secp256k1::cose_public_key(alg, seed)
        }
        (CredentialSecretKey::MlDsa(seed), Scheme::MlDsa(param_set)) => {
            mldsa::cose_public_key(alg, param_set, seed)
        }
        // `alg` signs with another type of key.
        (
            CredentialSecretKey::P256(_)
            | CredentialSecretKey::P384(_)
            | CredentialSecretKey::P521(_)
            | CredentialSecretKey::Secp256k1(_)
            | CredentialSecretKey::MlDsa(_),
            Scheme::Ecdsa(_) | Scheme::MlDsa(_),
        ) => Err(CryptoError::KeyTypeMismatch),
    }
}

/// Sign `auth_data || client_data_hash` as `alg` signs, and return the
/// signature in the encoding WebAuthn requires for `alg`:
///
/// * **ES256**, **ESP256**, **ES384**, **ESP384**, **ES512**, **ESP512** and
///   **ES256K**: ECDSA over the algorithm's curve with its hash, P-256 with
///   SHA-256, P-384 with SHA-384, P-521 with SHA-512 or secp256k1 with
///   SHA-256, and an RFC 6979 nonce, as an ASN.1 DER `Ecdsa-Sig-Value`
///   (WebAuthn Level 3 §6.5.5).
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
    match (sk, alg.scheme()) {
        (CredentialSecretKey::P256(key), Scheme::Ecdsa(Curve::P256)) => ecdsa_p256::sign(key, &msg),
        (CredentialSecretKey::P384(seed), Scheme::Ecdsa(Curve::P384)) => {
            ecdsa_p384::sign(seed, &msg)
        }
        (CredentialSecretKey::P521(seed), Scheme::Ecdsa(Curve::P521)) => {
            ecdsa_p521::sign(seed, &msg)
        }
        (CredentialSecretKey::Secp256k1(seed), Scheme::Ecdsa(Curve::Secp256k1)) => {
            ecdsa_secp256k1::sign(seed, &msg)
        }
        (CredentialSecretKey::MlDsa(seed), Scheme::MlDsa(param_set)) => {
            mldsa::sign(param_set, seed, &msg)
        }
        // `alg` signs with another type of key.
        (
            CredentialSecretKey::P256(_)
            | CredentialSecretKey::P384(_)
            | CredentialSecretKey::P521(_)
            | CredentialSecretKey::Secp256k1(_)
            | CredentialSecretKey::MlDsa(_),
            Scheme::Ecdsa(_) | Scheme::MlDsa(_),
        ) => Err(CryptoError::KeyTypeMismatch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::verify::{VerificationError, verify_signature};
    use crate::store::{CredentialRecord, PrivateKeyMaterial};
    use ciborium::{de::from_reader, ser::into_writer, value::Integer, value::Value};
    use core::mem;
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

    /// Every algorithm's new key has the shape of its algorithm's public
    /// keys, and its signature verifies over the message it signed and no
    /// other.
    #[test]
    fn every_algorithm_signs_and_its_signatures_verify() {
        for alg in CoseAlg::ALL {
            let (public_key_cbor, secret_key) = generated(alg);
            assert!(!public_key_cbor.is_empty());
            let auth_data = b"auth_data";
            let client_hash = b"client_data_hash";
            let signature =
                try_sign_challenge(alg, &secret_key, auth_data, client_hash).expect("signature");
            let message: Vec<u8> = auth_data.iter().chain(client_hash).cloned().collect();
            verify_signature(alg, &public_key_cbor, &message, &signature)
                .unwrap_or_else(|err| panic!("{alg:?}: {err}"));
            let mut changed = message.clone();
            changed[0] ^= 1;
            assert_eq!(
                verify_signature(alg, &public_key_cbor, &changed, &signature),
                Err(VerificationError::BadSignature),
                "{alg:?}: a changed message"
            );
        }
    }

    /// An ML-DSA key held as its seed signs, serializes to the seed, reads back
    /// from it, and never prints it.
    #[test]
    fn mldsa_seed_key_signs_and_round_trips() {
        for alg in CoseAlg::ALL {
            let ps = match alg.scheme() {
                Scheme::MlDsa(ps) => ps,
                Scheme::Ecdsa(_) => continue,
            };
            let seed = [0x3c; SEED_LEN];
            let (pk, _) = pqkey_mldsa::try_keypair_from_seed(ps, &seed).expect("keygen");

            let key = CredentialSecretKey::MlDsa(Seed::new(seed));
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

    /// Every ECDSA public key is an EC2 COSE_Key with exactly kty, alg, crv,
    /// x and y: the curve's crv, and coordinates as long as the curve's field
    /// elements (RFC 9053 §7.1; WebAuthn Level 3 §5.8.5).  The key reads back
    /// from what it serializes to.
    #[test]
    fn every_ecdsa_key_is_an_ec2_key_on_its_curve() {
        let int = |value: i64| Value::Integer(Integer::from(value));
        let curves = [
            (CoseAlg::ES256, 1, 32),
            (CoseAlg::ESP256, 1, 32),
            (CoseAlg::ES384, 2, 48),
            (CoseAlg::ESP384, 2, 48),
            (CoseAlg::ES512, 3, 66),
            (CoseAlg::ESP512, 3, 66),
            (CoseAlg::ES256K, 8, 32),
        ];
        let ecdsa: Vec<CoseAlg> = CoseAlg::ALL
            .into_iter()
            .filter(|alg| matches!(alg.scheme(), Scheme::Ecdsa(_)))
            .collect();
        assert_eq!(curves.map(|(alg, ..)| alg).as_slice(), ecdsa.as_slice());
        for (alg, crv, length) in curves {
            let (cose_key, secret_key) = generated(alg);
            let Value::Map(entries) = from_reader(cose_key.as_slice()).expect("a COSE_Key") else {
                panic!("{alg:?}: a COSE_Key is a map");
            };
            let labels: Vec<&Value> = entries.iter().map(|(label, _)| label).collect();
            assert_eq!(labels, [&int(1), &int(3), &int(-1), &int(-2), &int(-3)]);
            assert_eq!(entries[0].1, int(2), "{alg:?}: kty EC2");
            assert_eq!(entries[1].1, int(alg.identifier().into()), "{alg:?}");
            assert_eq!(entries[2].1, int(crv), "{alg:?}: crv");
            for (_, coordinate) in &entries[3..] {
                assert_eq!(coordinate.as_bytes().map(Vec::len), Some(length), "{alg:?}");
            }
            assert_eq!(secret_key.secret_bytes().len(), 32, "{alg:?}");
            let reread =
                try_credential_secret_from_bytes(alg, &secret_key.secret_bytes()).expect("reread");
            assert_eq!(try_cose_public_key(alg, &reread), Ok(cose_key), "{alg:?}");
        }
    }

    /// A fully specified identifier names its curve's algorithm under
    /// another identifier: the same key, an ESP256 scalar or an ESP384 or
    /// ESP512 seed, gives the same COSE_Key as under ES256, ES384 or ES512 but
    /// for its alg.  The key a seed derives belongs to the curve.
    #[test]
    fn a_fully_specified_algorithm_has_its_curves_keys_but_for_its_alg() {
        for (alg, fully_specified) in [
            (CoseAlg::ES256, CoseAlg::ESP256),
            (CoseAlg::ES384, CoseAlg::ESP384),
            (CoseAlg::ES512, CoseAlg::ESP512),
        ] {
            let key = [0x42; 32];
            let cose_key = |alg| {
                let secret = try_credential_secret_from_bytes(alg, &key).expect("a key");
                try_cose_public_key(alg, &secret).expect("a COSE_Key")
            };
            let relabelled = edited(&cose_key(alg), |entries| {
                for (label, value) in entries.iter_mut() {
                    if *label == Value::Integer(Integer::from(3)) {
                        *value = Value::Integer(Integer::from(fully_specified.identifier()));
                    }
                }
            });
            assert_ne!(cose_key(alg), cose_key(fully_specified), "{alg:?}");
            assert_eq!(relabelled, cose_key(fully_specified), "{alg:?}");
        }
    }

    // ---------------------------------------------------------------------
    // Fallible APIs return errors rather than panicking
    // ---------------------------------------------------------------------

    #[test]
    fn try_sign_challenge_rejects_mismatched_key_variant() {
        // A stored `alg` that names another type of key than the one on disk,
        // such as ES256 with an ML-DSA seed, ML-DSA with a P-256 scalar, or
        // ES384 with an ML-DSA seed, which is a seed all the same.
        let keys: Vec<(CoseAlg, CredentialSecretKey)> = CoseAlg::ALL
            .into_iter()
            .map(|alg| (alg, generated(alg).1))
            .collect();
        for (alg, key) in &keys {
            for (other, other_key) in &keys {
                if mem::discriminant(key) == mem::discriminant(other_key) {
                    continue;
                }
                assert_eq!(
                    try_sign_challenge(*other, key, b"auth", b"hash"),
                    Err(CryptoError::KeyTypeMismatch),
                    "{alg:?} key, {other:?}"
                );
                assert_eq!(
                    try_cose_public_key(*other, key),
                    Err(CryptoError::KeyTypeMismatch),
                    "{alg:?} key, {other:?}"
                );
            }
        }
    }

    /// A stored key kept as a seed is its 32 bytes.  Anything else, a
    /// truncated or corrupted record or an expanded ML-DSA secret key, is not
    /// a key.
    #[test]
    fn try_credential_secret_from_bytes_accepts_only_32_byte_seeds() {
        for alg in CoseAlg::ALL {
            match alg.key_kind() {
                KeyKind::Seed => {}
                KeyKind::P256Scalar => continue,
            }
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

    /// ECDSA does not ask for low-S signatures, though `k256` makes and
    /// accepts only those: the verifier takes an ES256K signature with either
    /// s.
    #[test]
    fn the_verifier_accepts_es256k_signatures_with_a_high_s() {
        let (cose_key, secret_key) = generated(CoseAlg::ES256K);
        let signature =
            try_sign_challenge(CoseAlg::ES256K, &secret_key, b"auth", b"hash").expect("sign");
        let low = k256::ecdsa::Signature::from_der(&signature).expect("DER");
        let (r, s) = low.split_scalars();
        let high = k256::ecdsa::Signature::from_scalars(r, -s).expect("a signature");
        assert_ne!(high, low);
        assert_eq!(high.normalize_s(), low);
        for signature in [low, high] {
            assert_eq!(
                verify_signature(
                    CoseAlg::ES256K,
                    &cose_key,
                    b"authhash",
                    signature.to_der().as_bytes()
                ),
                Ok(())
            );
        }
    }

    /// A key that is not of its algorithm's shape is malformed, whatever the
    /// signature.
    #[test]
    fn the_verifier_rejects_keys_of_another_shape() {
        let int = |value: i64| Value::Integer(Integer::from(value));
        let (es256, _) = generated(CoseAlg::ES256);
        let (esp256, _) = generated(CoseAlg::ESP256);
        let (es384, _) = generated(CoseAlg::ES384);
        let (es512, _) = generated(CoseAlg::ES512);
        let (es256k, _) = generated(CoseAlg::ES256K);
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
            (
                CoseAlg::ESP256,
                "crv P-384",
                with_label(&esp256, -1, int(2)),
            ),
            (CoseAlg::ES384, "crv P-256", with_label(&es384, -1, int(1))),
            (
                CoseAlg::ES384,
                "a 47-byte x",
                with_label(&es384, -2, Value::Bytes(vec![0x11; 47])),
            ),
            (
                CoseAlg::ES384,
                "a point off the curve",
                with_label(&es384, -3, Value::Bytes(vec![0; 48])),
            ),
            (CoseAlg::ES512, "crv P-384", with_label(&es512, -1, int(2))),
            (
                CoseAlg::ES512,
                "a 65-byte x",
                with_label(&es512, -2, Value::Bytes(vec![0x01; 65])),
            ),
            (
                CoseAlg::ES256K,
                "crv P-256",
                with_label(&es256k, -1, int(1)),
            ),
            (
                CoseAlg::ES256K,
                "a point off the curve",
                with_label(&es256k, -3, Value::Bytes(vec![0; 32])),
            ),
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
