//! Credential keys: generating them, reading them back and signing with them.

use getrandom::SysRng;
use p256::ecdsa::{
    Signature as P256EcdsaSignature, SigningKey as P256SigningKey, signature::Signer,
};
use p256::elliptic_curve::Generate;
use pqkey_mldsa::{SEED_LEN, try_public_key_from_seed, try_sign_from_seed};
use rand_core::TryRng;
use zeroize::{Zeroize, Zeroizing};

use super::CryptoError;
use super::alg::CoseAlg;
use super::mldsa::{MlDsaSeed, mldsa_paramset_from_alg};
use super::scrub::with_scrubbed_stack;
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
    match alg {
        CoseAlg::ES256 => {
            // Exactly 32 bytes: `SigningKey::from_slice` would left-pad a
            // slice of 24 to 31 bytes, reading a truncated key as some other
            // key.  `from_bytes` performs the full range check (non-zero and
            // below the group order), and borrowing the bytes in place needs
            // no intermediate copy of the scalar.
            let scalar =
                <&p256::FieldBytes>::try_from(bytes).map_err(|_| CryptoError::InvalidKey)?;
            let signing_key =
                P256SigningKey::from_bytes(scalar).map_err(|_| CryptoError::InvalidKey)?;
            Ok(CredentialSecretKey::P256(signing_key))
        }
        // Stored ML-DSA keys are seeds; an expanded secret key is never
        // stored, so it is not accepted either.
        CoseAlg::MLDSA44 | CoseAlg::MLDSA65 | CoseAlg::MLDSA87 => <[u8; SEED_LEN]>::try_from(bytes)
            .map(|seed| CredentialSecretKey::MlDsa(MlDsaSeed::new(seed)))
            .map_err(|_| CryptoError::InvalidKey),
    }
}

/// Generate a new credential.
///
/// Returns the CBOR COSE_Key for the new public key plus the secret key
/// wrapper, for ML-DSA the seed.  Errors instead of panicking when `alg` names
/// no supported algorithm ([`CryptoError::UnsupportedAlgorithm`]), when the
/// operating system's random number generator fails
/// ([`CryptoError::Randomness`]), when ML-DSA key generation fails
/// ([`CryptoError::MlDsa`]), or when the generated P-256 point cannot be
/// encoded ([`CryptoError::InvalidPublicKey`]).
pub fn try_create_credential(alg: CoseAlg) -> Result<(Vec<u8>, CredentialSecretKey), CryptoError> {
    match alg {
        CoseAlg::ES256 => {
            let signing_key =
                with_scrubbed_stack(|| P256SigningKey::try_generate_from_rng(&mut SysRng))
                    .map_err(|_| CryptoError::Randomness)?;
            let public_key = signing_key.verifying_key().to_sec1_point(false);
            let cose = ecdsa_p256::try_cose_key(alg, &public_key)?;
            Ok((cose, CredentialSecretKey::P256(signing_key)))
        }
        _ => {
            let ps = mldsa_paramset_from_alg(alg).ok_or(CryptoError::UnsupportedAlgorithm)?;
            let mut seed = [0u8; SEED_LEN];
            SysRng
                .try_fill_bytes(&mut seed)
                .map_err(|_| CryptoError::Randomness)?;
            let key = MlDsaSeed::new(seed);
            seed.zeroize();
            let pk = try_public_key_from_seed(ps, key.as_bytes())?;
            let cose = mldsa::try_cose_key(alg, &pk)?;
            Ok((cose, CredentialSecretKey::MlDsa(key)))
        }
    }
}

/// Sign `auth_data || client_data_hash` and returns the encoded signature:
///
/// * **ES256**: ECDSA over P-256 with SHA-256 (the message is hashed
///   internally), returned as an ASN.1 DER `Ecdsa-Sig-Value`, which is the
///   encoding WebAuthn requires for COSE algorithm -7.
/// * **ML-DSA-44/65/87**: the raw FIPS 204 signature bytes.
///
/// Note: RustCrypto's `p256` does not normalize `s` to the lower half of the
/// group order (unlike `k256`, it does not override `SignPrimitive`), so roughly
/// half of the emitted signatures are "high-S".  That is valid ECDSA and is
/// accepted by WebAuthn verifiers; neither WebAuthn nor CTAP 2.1 requires low-S
/// for ES256.  Call `Signature::normalize_s` before encoding if a low-S
/// signature is ever required.
///
/// Returns [`CryptoError::KeyTypeMismatch`] when `alg` and the key variant
/// disagree, [`CryptoError::UnsupportedAlgorithm`] for an algorithm with no
/// ML-DSA parameter set, and [`CryptoError::MlDsa`] / [`CryptoError::SigningFailed`]
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
    match (alg, sk) {
        (CoseAlg::ES256, CredentialSecretKey::P256(sk)) => {
            let signature: P256EcdsaSignature = with_scrubbed_stack(|| sk.try_sign(&msg))
                .map_err(|_| CryptoError::SigningFailed)?;
            Ok(signature.to_der().as_bytes().to_vec())
        }
        (CoseAlg::ES256, _) => Err(CryptoError::KeyTypeMismatch),
        (_, CredentialSecretKey::MlDsa(seed)) => {
            let ps = mldsa_paramset_from_alg(alg).ok_or(CryptoError::UnsupportedAlgorithm)?;
            Ok(try_sign_from_seed(ps, seed.as_bytes(), &msg)?)
        }
        (_, _) => Err(CryptoError::KeyTypeMismatch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cose::LABEL_AKP_PUB;
    use ciborium::{de::from_reader, value::Integer, value::Value};
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use pqkey_mldsa::{PublicKey, verify};
    use sha2::{Digest, Sha256};

    #[test]
    fn mldsa_roundtrip_signatures() {
        for alg in [CoseAlg::MLDSA44, CoseAlg::MLDSA65, CoseAlg::MLDSA87] {
            let (public_key_cbor, secret_key) =
                try_create_credential(alg).expect("create ML-DSA credential");
            assert!(!public_key_cbor.is_empty());
            let auth_data = b"auth_data";
            let client_hash = b"client_data_hash";
            let signature = try_sign_challenge(alg, &secret_key, auth_data, client_hash)
                .expect("ML-DSA signature");
            let ps = mldsa_paramset_from_alg(alg).expect("ML-DSA param set");
            let message: Vec<u8> = auth_data.iter().chain(client_hash).cloned().collect();
            let pk = PublicKey(public_key_from_cose(&public_key_cbor));
            assert!(verify(ps, &pk, &message, &signature));
        }
    }

    /// An ML-DSA key held as its seed signs, serializes to the seed, reads back
    /// from it, and never prints it.
    #[test]
    fn mldsa_seed_key_signs_and_round_trips() {
        for alg in [CoseAlg::MLDSA44, CoseAlg::MLDSA65, CoseAlg::MLDSA87] {
            let ps = mldsa_paramset_from_alg(alg).expect("ML-DSA param set");
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
            assert!(matches!(reloaded, CredentialSecretKey::MlDsa(_)));
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
        let (cose_key, secret_key) =
            try_create_credential(CoseAlg::ES256).expect("create ES256 credential");
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
        match reconstructed {
            CredentialSecretKey::P256(_) => {}
            _ => panic!("unexpected key variant"),
        }
    }

    fn public_key_from_cose(cbor: &[u8]) -> Vec<u8> {
        let value: Value = from_reader(cbor).expect("valid CBOR");
        if let Value::Map(map) = value {
            for (k, v) in map {
                if k == Value::Integer(Integer::from(LABEL_AKP_PUB))
                    && let Value::Bytes(bytes) = v
                {
                    return bytes;
                }
            }
        }
        panic!("COSE key missing public key bytes");
    }

    // ---------------------------------------------------------------------
    // Fallible APIs return errors rather than panicking
    // ---------------------------------------------------------------------

    #[test]
    fn try_sign_challenge_rejects_mismatched_key_variant() {
        let (_, ml_dsa_key) = try_create_credential(CoseAlg::MLDSA44).unwrap();
        let (_, es256_key) = try_create_credential(CoseAlg::ES256).unwrap();

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
        let (_, secret_key) = try_create_credential(CoseAlg::ES256).unwrap();
        let verifying_key = match &secret_key {
            CredentialSecretKey::P256(sk) => *sk.verifying_key(),
            _ => panic!("expected a P-256 key"),
        };

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
}
