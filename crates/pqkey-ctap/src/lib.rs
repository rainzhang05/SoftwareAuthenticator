//! The CTAP2 authenticator: the protocol engine in [`ctap`], the encrypted
//! credential store in [`store`], and the cryptography they share: COSE keys
//! and ES256 and ML-DSA signing here, and the PIN/UV auth protocols' key
//! derivation and encryption, re-exported from a module of their own.

// Everything here is safe Rust; the one place that needs `unsafe` (the uhid
// device) lives in the pqkey crate.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use ciborium::ser::into_writer;
use ciborium::value::{Integer, Value};
use core::fmt;
use getrandom::SysRng;
use p256::Sec1Point;
use p256::ecdsa::{
    Signature as P256EcdsaSignature, SigningKey as P256SigningKey, signature::Signer,
};
use p256::elliptic_curve::Generate;
use pqkey_mldsa::{ParamSet, PublicKey, SEED_LEN, try_public_key_from_seed, try_sign_from_seed};
use rand_core::TryRng;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::scrub::with_scrubbed_stack;

mod crypto;
pub mod ctap;
pub mod platform;
pub mod store;

pub use crypto::CryptoError;
pub use crypto::pin_uv::{
    ClassicPinProtocol, PinUvSessionKeys, decrypt_classic_pin_block,
    derive_classic_pin_uv_session_keys, encrypt_classic_pin_block,
    try_derive_classic_pin_uv_session_keys,
};

/// COSE key type value assigned to Algorithm Key Pairs (AKP).
pub const COSE_KEY_TYPE_AKP: i32 = 7;

/// COSE_Key label 1, the key type (RFC 9052 §7.1).
pub const COSE_KEY_LABEL_KTY: i32 = 1;
/// COSE_Key label 3, the algorithm (RFC 9052 §7.1).
pub const COSE_KEY_LABEL_ALG: i32 = 3;
/// COSE_Key label -1 of an Algorithm Key Pair: the public key bytes.
pub const COSE_KEY_PARAM_AKP_KEY: i32 = -1;

/// The COSE algorithm identifiers this authenticator signs with: ES256 (-7)
/// and the three ML-DSA parameter sets, which RFC 9964 §8.1 registered in the
/// IANA "COSE Algorithms" registry as -48, -49 and -50.
///
/// * -7 -> ES256
/// * -48 -> ML-DSA-44
/// * -49 -> ML-DSA-65
/// * -50 -> ML-DSA-87
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CoseAlg {
    /// ECDSA with P-256 and SHA-256.
    ES256 = -7,
    /// ML-DSA-44.
    MLDSA44 = -48,
    /// ML-DSA-65.
    MLDSA65 = -49,
    /// ML-DSA-87.
    MLDSA87 = -50,
}

/// A COSE algorithm identifier that is not one of the [`CoseAlg`] values; it
/// carries the identifier.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct UnsupportedCoseAlg(pub i32);

impl fmt::Display for UnsupportedCoseAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unsupported COSE algorithm {}", self.0)
    }
}

impl std::error::Error for UnsupportedCoseAlg {}

impl TryFrom<i32> for CoseAlg {
    type Error = UnsupportedCoseAlg;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            -7 => Ok(CoseAlg::ES256),
            -48 => Ok(CoseAlg::MLDSA44),
            -49 => Ok(CoseAlg::MLDSA65),
            -50 => Ok(CoseAlg::MLDSA87),
            _ => Err(UnsupportedCoseAlg(value)),
        }
    }
}

/// Map a COSE algorithm identifier to the corresponding ML-DSA parameter set.
pub fn mldsa_paramset_from_alg(alg: CoseAlg) -> Option<ParamSet> {
    match alg {
        CoseAlg::MLDSA44 => Some(ParamSet::MLDSA44),
        CoseAlg::MLDSA65 => Some(ParamSet::MLDSA65),
        CoseAlg::MLDSA87 => Some(ParamSet::MLDSA87),
        _ => None,
    }
}

/// Build a COSE_Key map for an AKP public key using canonical ordering.
pub(crate) fn cose_akp_key_map(alg_id: i32, public_key: &[u8]) -> Value {
    Value::Map(vec![
        (
            Value::Integer(Integer::from(COSE_KEY_LABEL_KTY)),
            Value::Integer(Integer::from(COSE_KEY_TYPE_AKP)),
        ),
        (
            Value::Integer(Integer::from(COSE_KEY_LABEL_ALG)),
            Value::Integer(Integer::from(alg_id)),
        ),
        (
            Value::Integer(Integer::from(COSE_KEY_PARAM_AKP_KEY)),
            Value::Bytes(public_key.to_vec()),
        ),
    ])
}

/// Build the CBOR COSE_Key for an ML-DSA public key: the Algorithm Key Pair
/// structure with 1 (kty) = 7 (AKP), 3 (alg) = -48/-49/-50, and -1 = the raw
/// public key bytes.  Returns [`CryptoError::CborEncoding`] if serialization
/// fails.
pub fn try_cose_public_key(ps: ParamSet, pk: &PublicKey) -> Result<Vec<u8>, CryptoError> {
    let alg_id = match ps {
        ParamSet::MLDSA44 => CoseAlg::MLDSA44 as i32,
        ParamSet::MLDSA65 => CoseAlg::MLDSA65 as i32,
        ParamSet::MLDSA87 => CoseAlg::MLDSA87 as i32,
    };
    let mut out = Vec::new();
    let map = cose_akp_key_map(alg_id, &pk.0);
    into_writer(&map, &mut out).map_err(|_| CryptoError::CborEncoding)?;
    Ok(out)
}

/// Build the CBOR COSE_Key for an ES256 (P-256) public key.
///
/// Returns [`CryptoError::InvalidPublicKey`] if `point` is the point at
/// infinity or is a compressed/short encoding without both affine coordinates,
/// and [`CryptoError::CborEncoding`] if serialization fails.  `point` is
/// attacker-influenced in some code paths, so neither case may panic.
pub fn try_cose_es256_public_key(point: &Sec1Point) -> Result<Vec<u8>, CryptoError> {
    if point.is_identity() {
        return Err(CryptoError::InvalidPublicKey);
    }
    let x = point.x().ok_or(CryptoError::InvalidPublicKey)?.to_vec();
    let y = point.y().ok_or(CryptoError::InvalidPublicKey)?.to_vec();
    let map = Value::Map(vec![
        (
            Value::Integer(Integer::from(COSE_KEY_LABEL_KTY)),
            Value::Integer(Integer::from(2)),
        ),
        (
            Value::Integer(Integer::from(COSE_KEY_LABEL_ALG)),
            Value::Integer(Integer::from(CoseAlg::ES256 as i32)),
        ),
        (
            Value::Integer(Integer::from(-1)),
            Value::Integer(Integer::from(1)),
        ),
        (Value::Integer(Integer::from(-2)), Value::Bytes(x)),
        (Value::Integer(Integer::from(-3)), Value::Bytes(y)),
    ]);
    let mut out = Vec::new();
    into_writer(&map, &mut out).map_err(|_| CryptoError::CborEncoding)?;
    Ok(out)
}

/// Credential secret key variants supported by the authenticator.
#[derive(Debug)]
pub enum CredentialSecretKey {
    /// An ML-DSA key held as its 32-byte FIPS 204 seed `ξ`, the form stored
    /// credentials use.  Signing expands the seed directly, so no expanded
    /// secret key encoding is produced or decoded.
    MlDsaSeed(MlDsaSeed),
    /// A P-256 private key, for ES256.
    Es256(P256SigningKey),
}

/// The 32-byte FIPS 204 key-generation seed `ξ` of an ML-DSA key.
///
/// Zeroized on drop; its `Debug` output is redacted.
pub struct MlDsaSeed(Zeroizing<[u8; SEED_LEN]>);

impl MlDsaSeed {
    /// Wrap a seed.  The caller remains responsible for zeroizing `seed`'s
    /// own copy.
    pub fn new(seed: [u8; SEED_LEN]) -> Self {
        MlDsaSeed(Zeroizing::new(seed))
    }

    /// Borrow the seed bytes.
    pub fn as_bytes(&self) -> &[u8; SEED_LEN] {
        &self.0
    }
}

impl fmt::Debug for MlDsaSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MlDsaSeed(<redacted>)")
    }
}

impl CredentialSecretKey {
    /// Serialize the secret key into a byte buffer suitable for storage.
    ///
    /// The returned buffer is wrapped in [`Zeroizing`], so the copy is wiped
    /// when the caller drops it.  An ML-DSA key serializes to its 32-byte
    /// seed, which [`try_credential_secret_from_bytes`] accepts back.
    pub fn secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        match self {
            CredentialSecretKey::MlDsaSeed(seed) => Zeroizing::new(seed.as_bytes().to_vec()),
            CredentialSecretKey::Es256(sk) => {
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
            Ok(CredentialSecretKey::Es256(signing_key))
        }
        // Stored ML-DSA keys are seeds; an expanded secret key is never
        // stored, so it is not accepted either.
        CoseAlg::MLDSA44 | CoseAlg::MLDSA65 | CoseAlg::MLDSA87 => <[u8; SEED_LEN]>::try_from(bytes)
            .map(|seed| CredentialSecretKey::MlDsaSeed(MlDsaSeed::new(seed)))
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
            let cose = try_cose_es256_public_key(&public_key)?;
            Ok((cose, CredentialSecretKey::Es256(signing_key)))
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
            let cose = try_cose_public_key(ps, &pk)?;
            Ok((cose, CredentialSecretKey::MlDsaSeed(key)))
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
        (CoseAlg::ES256, CredentialSecretKey::Es256(sk)) => {
            let signature: P256EcdsaSignature = with_scrubbed_stack(|| sk.try_sign(&msg))
                .map_err(|_| CryptoError::SigningFailed)?;
            Ok(signature.to_der().as_bytes().to_vec())
        }
        (CoseAlg::ES256, _) => Err(CryptoError::KeyTypeMismatch),
        (_, CredentialSecretKey::MlDsaSeed(seed)) => {
            let ps = mldsa_paramset_from_alg(alg).ok_or(CryptoError::UnsupportedAlgorithm)?;
            Ok(try_sign_from_seed(ps, seed.as_bytes(), &msg)?)
        }
        (_, _) => Err(CryptoError::KeyTypeMismatch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::os_rng;
    use ciborium::{de::from_reader, value::Integer};
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use pqkey_mldsa::verify;
    use sha2::{Digest, Sha256};

    #[test]
    fn cose_public_key_canonical_encoding_matches_fixture() {
        let pk_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let pk = PublicKey(pk_bytes.clone());
        let cose = try_cose_public_key(ParamSet::MLDSA44, &pk).expect("encode COSE key");
        let expected = vec![
            0xA3, 0x01, 0x07, 0x03, 0x38, 0x2F, 0x20, 0x44, 0xDE, 0xAD, 0xBE, 0xEF,
        ];
        assert_eq!(cose, expected);
        let decoded: Value = from_reader(cose.as_slice()).expect("valid COSE public key");
        assert_eq!(
            decoded,
            cose_akp_key_map(CoseAlg::MLDSA44 as i32, &pk_bytes)
        );
    }

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

            let key = CredentialSecretKey::MlDsaSeed(MlDsaSeed::new(seed));
            assert_eq!(key.secret_bytes().as_slice(), &seed[..]);
            let rendered = format!("{key:?}");
            assert!(
                rendered.contains("redacted") && !rendered.contains("60"),
                "{rendered}"
            );

            let reloaded = try_credential_secret_from_bytes(alg, &key.secret_bytes()).unwrap();
            assert!(matches!(reloaded, CredentialSecretKey::MlDsaSeed(_)));
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
            Some(Value::Integer(Integer::from(CoseAlg::ES256 as i32))),
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
            CredentialSecretKey::Es256(_) => {}
            _ => panic!("unexpected key variant"),
        }
    }

    fn public_key_from_cose(cbor: &[u8]) -> Vec<u8> {
        let value: Value = from_reader(cbor).expect("valid CBOR");
        if let Value::Map(map) = value {
            for (k, v) in map {
                if k == Value::Integer(Integer::from(COSE_KEY_PARAM_AKP_KEY))
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

    #[test]
    fn try_cose_es256_public_key_rejects_identity_point() {
        let identity = Sec1Point::identity();
        assert!(identity.is_identity());
        assert_eq!(
            try_cose_es256_public_key(&identity),
            Err(CryptoError::InvalidPublicKey)
        );
    }

    #[test]
    fn try_cose_es256_public_key_rejects_point_without_y_coordinate() {
        let signing_key = P256SigningKey::generate_from_rng(&mut os_rng());
        // A compressed SEC1 encoding carries X but no Y.
        let compressed = signing_key.verifying_key().to_sec1_point(true);
        assert!(!compressed.is_identity());
        assert!(compressed.y().is_none());
        assert_eq!(
            try_cose_es256_public_key(&compressed),
            Err(CryptoError::InvalidPublicKey)
        );
    }

    #[test]
    fn try_create_credential_rejects_unsupported_algorithm() {
        // `CoseAlg` only carries supported identifiers, so exercise the parse
        // boundary that feeds it as well.
        assert_eq!(CoseAlg::try_from(-257), Err(UnsupportedCoseAlg(-257)));
        assert_eq!(CoseAlg::try_from(-8), Err(UnsupportedCoseAlg(-8)));
        assert_eq!(CoseAlg::try_from(-7), Ok(CoseAlg::ES256));
        assert_eq!(CoseAlg::try_from(-48), Ok(CoseAlg::MLDSA44));
        assert_eq!(CoseAlg::try_from(-49), Ok(CoseAlg::MLDSA65));
        assert_eq!(CoseAlg::try_from(-50), Ok(CoseAlg::MLDSA87));
        assert_eq!(
            UnsupportedCoseAlg(-257).to_string(),
            "unsupported COSE algorithm -257"
        );
        // ES256 has no ML-DSA parameter set.
        assert!(mldsa_paramset_from_alg(CoseAlg::ES256).is_none());
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
            CredentialSecretKey::Es256(sk) => *sk.verifying_key(),
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
