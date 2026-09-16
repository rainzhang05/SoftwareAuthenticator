use aes::Aes256;
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::{Decryptor, Encryptor};
use ciborium::ser::into_writer;
use ciborium::value::{Integer, Value};
use core::fmt;
use hkdf::Hkdf;
use p256::ecdsa::{
    signature::Signer, Signature as P256EcdsaSignature, SigningKey as P256SigningKey,
};
use p256::EncodedPoint;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use trussed_mldsa::{try_keypair, try_sign, MlDsaError, ParamSet, PublicKey, SecretKey};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// TEMPORARY: `ctap` still calls the deprecated infallible wrappers below
// (`create_credential`, `sign_challenge`, `cose_public_key`,
// `CredentialSecretKey::to_bytes`).  Suppressing the lint for that module only
// keeps the build quiet without hiding the deprecation from this module, from
// the new tests, or from downstream crates.  Remove this attribute once
// `ctap.rs` has been migrated to the `try_*` API.
#[allow(deprecated)]
pub mod ctap;
pub mod store;

type Aes256CbcEncryptor = Encryptor<Aes256>;
type Aes256CbcDecryptor = Decryptor<Aes256>;

/// COSE key type value assigned to Algorithm Key Pairs (AKP).
pub const COSE_KEY_TYPE_AKP: i32 = 7;

/// Standard COSE key map labels used by AKP keys.
pub const COSE_KEY_LABEL_KTY: i32 = 1;
pub const COSE_KEY_LABEL_ALG: i32 = 3;
pub const COSE_KEY_PARAM_AKP_KEY: i32 = -1;

/// Errors returned by the fallible (`try_*`) credential and COSE helpers.
///
/// Every variant corresponds to input an attacker can influence (a malformed
/// COSE key from the platform, a corrupted secret key read back from disk, an
/// `alg` field that disagrees with the stored key material).  None of them
/// should ever abort the process: this crate runs inside a long-lived daemon
/// that parses data originating from a web browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// The COSE algorithm identifier does not name a supported algorithm for
    /// the requested operation (e.g. an ES256 identifier where an ML-DSA
    /// parameter set was required).
    UnsupportedAlgorithm,
    /// The stored secret key variant does not match the requested algorithm.
    KeyTypeMismatch,
    /// The key bytes could not be parsed as a key for the requested algorithm.
    InvalidKey,
    /// A P-256 public key is the point at infinity, or otherwise carries no
    /// usable affine coordinates.
    InvalidPublicKey,
    /// The COSE_Key structure could not be serialized to CBOR.
    CborEncoding,
    /// Key derivation (HKDF) failed.
    KeyDerivation,
    /// Signature generation failed.
    SigningFailed,
    /// The underlying ML-DSA implementation reported an error.
    MlDsa(MlDsaError),
}

impl From<MlDsaError> for CryptoError {
    fn from(err: MlDsaError) -> Self {
        CryptoError::MlDsa(err)
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::UnsupportedAlgorithm => f.write_str("unsupported COSE algorithm"),
            CryptoError::KeyTypeMismatch => {
                f.write_str("secret key type does not match the requested algorithm")
            }
            CryptoError::InvalidKey => f.write_str("malformed secret key bytes"),
            CryptoError::InvalidPublicKey => f.write_str("malformed or identity public key"),
            CryptoError::CborEncoding => f.write_str("COSE_Key CBOR encoding failed"),
            CryptoError::KeyDerivation => f.write_str("key derivation failed"),
            CryptoError::SigningFailed => f.write_str("signature generation failed"),
            CryptoError::MlDsa(err) => write!(f, "ML-DSA error: {err:?}"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Session keys derived from a PIN/UV key-agreement shared secret.
///
/// Both halves are secret: `encryption_key` is the AES-256-CBC key and
/// `auth_key` is the HMAC-SHA-256 key.  The struct zeroizes itself on drop and
/// its `Debug` output is redacted so the keys cannot leak into logs.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PinUvSessionKeys {
    pub encryption_key: [u8; 32],
    pub auth_key: [u8; 32],
}

impl fmt::Debug for PinUvSessionKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinUvSessionKeys")
            .field("encryption_key", &"<redacted>")
            .field("auth_key", &"<redacted>")
            .finish()
    }
}

/// Supported classic PIN/UV protocol variants.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ClassicPinProtocol {
    V1,
    V2,
}

impl ClassicPinProtocol {
    /// Return the CTAP2 identifier associated with this protocol variant.
    pub fn identifier(self) -> i32 {
        match self {
            ClassicPinProtocol::V1 => 1,
            ClassicPinProtocol::V2 => 2,
        }
    }
}

/// Derive the AES/HMAC keys for the classic PIN/UV protocols from the raw
/// ECDH shared secret `Z` (the 32-byte big-endian x-coordinate of the shared
/// point).
///
/// The two protocols use different key derivation functions.  Per CTAP 2.1
/// §6.5.6 (PIN/UV Auth Protocol One):
///
/// ```text
/// kdf(Z) -> sharedSecret
///     Return SHA-256(Z)
/// ```
///
/// and per CTAP 2.1 §6.5.7 (PIN/UV Auth Protocol Two):
///
/// ```text
/// kdf(Z) -> sharedSecret
///     Return HKDF-SHA-256(salt = 32 zero bytes, IKM = Z, L = 32, info = "CTAP2 HMAC key") ||
///            HKDF-SHA-256(salt = 32 zero bytes, IKM = Z, L = 32, info = "CTAP2 AES key")
/// ```
///
/// Note in particular that protocol two derives from `Z` **directly**; it does
/// *not* pre-hash `Z` with SHA-256 the way protocol one does.  Feeding
/// `SHA-256(Z)` to HKDF produces keys that no conforming platform (Chrome,
/// libfido2, ...) will agree with.
///
/// `Hkdf::new(None, ikm)` uses an all-zero salt of the hash output length,
/// which for SHA-256 is exactly the 32 zero bytes the specification requires.
///
/// This function cannot fail; it is kept infallible because HKDF-Expand is only
/// defined to fail when `L > 255 * HashLen`, and both outputs here are a fixed
/// 32 bytes (`32 <= 255 * 32`).  See [`try_derive_classic_pin_uv_session_keys`]
/// for a `Result`-returning wrapper.
pub fn derive_classic_pin_uv_session_keys(
    protocol: ClassicPinProtocol,
    shared_secret: &[u8],
) -> PinUvSessionKeys {
    // UNREACHABLE: see the doc comment - the only documented failure mode of
    // HKDF-Expand is an output length above 255 * HashLen, and both requested
    // lengths are the constant 32.
    try_derive_classic_pin_uv_session_keys(protocol, shared_secret)
        .expect("HKDF expand cannot fail for a fixed 32-byte output")
}

/// Fallible form of [`derive_classic_pin_uv_session_keys`].
///
/// Prefer this in new code.  It returns [`CryptoError::KeyDerivation`] instead
/// of panicking, although with the fixed 32-byte outputs used here the error
/// path is not reachable in practice.
pub fn try_derive_classic_pin_uv_session_keys(
    protocol: ClassicPinProtocol,
    shared_secret: &[u8],
) -> Result<PinUvSessionKeys, CryptoError> {
    let mut encryption_key = [0u8; 32];
    let mut auth_key = [0u8; 32];
    match protocol {
        ClassicPinProtocol::V1 => {
            // kdf(Z) = SHA-256(Z); both keys are that same 32-byte value.
            let mut hash = Sha256::digest(shared_secret);
            encryption_key.copy_from_slice(&hash);
            auth_key.copy_from_slice(&hash);
            hash.zeroize();
        }
        ClassicPinProtocol::V2 => {
            // IKM is Z itself, NOT SHA-256(Z).  `None` salt == 32 zero bytes.
            let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
            hkdf.expand(b"CTAP2 AES key", &mut encryption_key)
                .map_err(|_| CryptoError::KeyDerivation)?;
            hkdf.expand(b"CTAP2 HMAC key", &mut auth_key)
                .map_err(|_| CryptoError::KeyDerivation)?;
        }
    }
    Ok(PinUvSessionKeys {
        encryption_key,
        auth_key,
    })
}

/// Encrypt a classic PIN block using AES-256-CBC.  Protocol 1 uses an all-zero
/// IV, while protocol 2 prepends the random IV to the ciphertext.
pub fn encrypt_classic_pin_block(
    protocol: ClassicPinProtocol,
    keys: &PinUvSessionKeys,
    iv: Option<&[u8; 16]>,
    plaintext: &[u8],
) -> Result<Vec<u8>, ()> {
    match protocol {
        ClassicPinProtocol::V1 => {
            if plaintext.len() % 16 != 0 {
                return Err(());
            }
            let iv = [0u8; 16];
            let cipher =
                Aes256CbcEncryptor::new_from_slices(&keys.encryption_key, &iv).map_err(|_| ())?;
            Ok(cipher.encrypt_padded_vec_mut::<NoPadding>(plaintext))
        }
        ClassicPinProtocol::V2 => {
            let iv = iv.ok_or(())?;
            if plaintext.len() % 16 != 0 {
                return Err(());
            }
            let cipher =
                Aes256CbcEncryptor::new_from_slices(&keys.encryption_key, iv).map_err(|_| ())?;
            let mut ciphertext = cipher.encrypt_padded_vec_mut::<NoPadding>(plaintext);
            let mut out = Vec::with_capacity(16 + ciphertext.len());
            out.extend_from_slice(iv);
            out.append(&mut ciphertext);
            Ok(out)
        }
    }
}

/// Decrypt a classic PIN block using AES-256-CBC.
pub fn decrypt_classic_pin_block(
    protocol: ClassicPinProtocol,
    keys: &PinUvSessionKeys,
    ciphertext: &[u8],
) -> Result<Vec<u8>, ()> {
    match protocol {
        ClassicPinProtocol::V1 => {
            let iv = [0u8; 16];
            let cipher =
                Aes256CbcDecryptor::new_from_slices(&keys.encryption_key, &iv).map_err(|_| ())?;
            if ciphertext.len() % 16 != 0 {
                return Err(());
            }
            cipher
                .decrypt_padded_vec_mut::<NoPadding>(ciphertext)
                .map_err(|_| ())
        }
        ClassicPinProtocol::V2 => {
            if ciphertext.len() < 16 {
                return Err(());
            }
            let (iv, body) = ciphertext.split_at(16);
            let cipher =
                Aes256CbcDecryptor::new_from_slices(&keys.encryption_key, iv).map_err(|_| ())?;
            if body.len() % 16 != 0 {
                return Err(());
            }
            cipher
                .decrypt_padded_vec_mut::<NoPadding>(body)
                .map_err(|_| ())
        }
    }
}

/// Enumeration of COSE algorithm identifiers for ML-DSA.  These values
/// follow the draft COSE registration; they are negative because COSE
/// reserves negative numbers for signature algorithms.
///
/// * -48 -> ML-DSA-44
/// * -49 -> ML-DSA-65
/// * -50 -> ML-DSA-87
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CoseAlg {
    ES256 = -7,
    MLDSA44 = -48,
    MLDSA65 = -49,
    MLDSA87 = -50,
}

impl TryFrom<i32> for CoseAlg {
    type Error = ();
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            -7 => Ok(CoseAlg::ES256),
            -48 => Ok(CoseAlg::MLDSA44),
            -49 => Ok(CoseAlg::MLDSA65),
            -50 => Ok(CoseAlg::MLDSA87),
            _ => Err(()),
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

/// Generate a COSE_Key for a given public key and parameter set.
///
/// The returned vector contains the CBOR encoding of the standard AKP
/// structure:
///
/// * **1 (kty)**: the Algorithm Key Pair key type (7).
/// * **3 (alg)**: the COSE algorithm identifier (-48/-49/-50).
/// * **-1**: the raw public key bytes.
///
/// # Deprecated
///
/// This function panics if CBOR serialization fails.  Use
/// [`try_cose_public_key`] instead.
#[deprecated(
    since = "0.1.0",
    note = "panics on CBOR encoding failure; use `try_cose_public_key` instead"
)]
pub fn cose_public_key(ps: ParamSet, pk: &PublicKey) -> Vec<u8> {
    try_cose_public_key(ps, pk).expect("CBOR encoding failed")
}

/// Fallible form of [`cose_public_key`]: build the CBOR COSE_Key for an ML-DSA
/// public key, returning [`CryptoError::CborEncoding`] rather than panicking.
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
pub fn try_cose_es256_public_key(point: &EncodedPoint) -> Result<Vec<u8>, CryptoError> {
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
    MlDsa(SecretKey),
    Es256(P256SigningKey),
}

impl CredentialSecretKey {
    /// Serialize the secret key into a byte buffer suitable for storage.
    ///
    /// The returned buffer is wrapped in [`Zeroizing`], so the copy is wiped
    /// when the caller drops it.  Prefer this over [`Self::to_bytes`].
    pub fn secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        match self {
            CredentialSecretKey::MlDsa(sk) => Zeroizing::new(sk.0.clone()),
            CredentialSecretKey::Es256(sk) => {
                let mut scalar = sk.to_bytes();
                let out = Zeroizing::new(scalar.to_vec());
                scalar.zeroize();
                out
            }
        }
    }

    /// Serialize the secret key into a plain byte vector.
    ///
    /// # Deprecated
    ///
    /// The returned `Vec<u8>` is a bare copy of private key material that is
    /// **not** wiped when it is dropped, so it can linger in freed heap memory.
    /// Use [`Self::secret_bytes`] instead, which returns a [`Zeroizing`] buffer.
    #[deprecated(
        since = "0.1.0",
        note = "returns un-zeroized private key material; use `secret_bytes` instead"
    )]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.secret_bytes().to_vec()
    }
}

/// Reconstruct a credential secret key from stored bytes.
///
/// `bytes` comes from persistent storage and is therefore not trusted: a
/// corrupted or truncated record must produce an error, never a panic.
pub fn credential_secret_from_bytes(alg: CoseAlg, bytes: &[u8]) -> Result<CredentialSecretKey, ()> {
    try_credential_secret_from_bytes(alg, bytes).map_err(|_| ())
}

/// Fallible form of [`credential_secret_from_bytes`] that reports a typed
/// [`CryptoError`] instead of `()`.
///
/// Returns [`CryptoError::InvalidKey`] when the bytes are not a valid scalar
/// for the requested algorithm (wrong length, zero, or >= the group order for
/// P-256).
pub fn try_credential_secret_from_bytes(
    alg: CoseAlg,
    bytes: &[u8],
) -> Result<CredentialSecretKey, CryptoError> {
    match alg {
        CoseAlg::ES256 => {
            // `SigningKey::from_slice` performs the full range check (non-zero
            // and below the group order) and rejects wrong lengths, so no
            // intermediate `SecretKey` copy of the scalar is needed.
            let signing_key =
                P256SigningKey::from_slice(bytes).map_err(|_| CryptoError::InvalidKey)?;
            Ok(CredentialSecretKey::Es256(signing_key))
        }
        CoseAlg::MLDSA44 | CoseAlg::MLDSA65 | CoseAlg::MLDSA87 => {
            // `SecretKey` zeroizes its buffer on drop.  Length validation
            // happens in `try_sign`, which rejects a wrong-sized key with
            // `MlDsaError::InvalidKeyLength`.
            Ok(CredentialSecretKey::MlDsa(SecretKey(bytes.to_vec())))
        }
    }
}

/// Generate a new credential.  Returns the COSE_Key and a secret key wrapper.
/// In a real authenticator you would store the secret key in secure
/// persistent storage and return only the credential ID and public key to the
/// client.
///
/// # Deprecated
///
/// This function panics when `alg` is not a supported algorithm and when key
/// generation fails.  Use [`try_create_credential`] instead.
#[deprecated(
    since = "0.1.0",
    note = "panics on unsupported algorithms and keygen failure; use `try_create_credential` instead"
)]
pub fn create_credential(alg: CoseAlg) -> (Vec<u8>, CredentialSecretKey) {
    try_create_credential(alg).expect("credential generation failed")
}

/// Fallible form of [`create_credential`].
///
/// Returns the CBOR COSE_Key for the new public key plus the secret key
/// wrapper.  Errors instead of panicking when `alg` names no supported
/// algorithm ([`CryptoError::UnsupportedAlgorithm`]), when ML-DSA key
/// generation fails ([`CryptoError::MlDsa`]), or when the generated P-256
/// point cannot be encoded ([`CryptoError::InvalidPublicKey`]).
pub fn try_create_credential(alg: CoseAlg) -> Result<(Vec<u8>, CredentialSecretKey), CryptoError> {
    match alg {
        CoseAlg::ES256 => {
            let signing_key = P256SigningKey::random(&mut OsRng);
            let public_key = signing_key.verifying_key().to_encoded_point(false);
            let cose = try_cose_es256_public_key(&public_key)?;
            Ok((cose, CredentialSecretKey::Es256(signing_key)))
        }
        _ => {
            let ps = mldsa_paramset_from_alg(alg).ok_or(CryptoError::UnsupportedAlgorithm)?;
            let (pk, sk) = try_keypair(ps)?;
            let cose = try_cose_public_key(ps, &pk)?;
            Ok((cose, CredentialSecretKey::MlDsa(sk)))
        }
    }
}

/// Produce a signature over `auth_data || client_data_hash` using the provided
/// secret key.
///
/// # Deprecated
///
/// This function panics when `alg` and the secret key variant disagree - a
/// condition driven by the `alg` field read back from persistent storage, so it
/// is reachable with a corrupted or tampered credential record.  It is also
/// unable to report a malformed stored key: it silently returns an **empty**
/// signature, which callers then happily encode into an assertion response.
/// Use [`try_sign_challenge`] instead.
#[deprecated(
    since = "0.1.0",
    note = "panics when the stored `alg` and key variant disagree, and returns an empty signature for a malformed key; use `try_sign_challenge` instead"
)]
pub fn sign_challenge(
    alg: CoseAlg,
    sk: &CredentialSecretKey,
    auth_data: &[u8],
    client_data_hash: &[u8],
) -> Vec<u8> {
    match try_sign_challenge(alg, sk, auth_data, client_data_hash) {
        Ok(signature) => signature,
        // Preserve the historical behaviour of `trussed_mldsa::sign`, which
        // logs and returns an empty signature rather than aborting when the
        // stored secret key is malformed.  Existing callers depend on it.
        // `try_sign_challenge` reports the real error instead.
        Err(CryptoError::MlDsa(err)) => {
            log::warn!("ML-DSA signing failed, returning an empty signature: {err:?}");
            Vec::new()
        }
        Err(err) => panic!("sign_challenge: {err}"),
    }
}

/// Fallible form of [`sign_challenge`].
///
/// Signs `auth_data || client_data_hash` and returns the encoded signature:
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
            let signature: P256EcdsaSignature =
                sk.try_sign(&msg).map_err(|_| CryptoError::SigningFailed)?;
            Ok(signature.to_der().as_bytes().to_vec())
        }
        (CoseAlg::ES256, _) => Err(CryptoError::KeyTypeMismatch),
        (_, CredentialSecretKey::MlDsa(sk)) => {
            let ps = mldsa_paramset_from_alg(alg).ok_or(CryptoError::UnsupportedAlgorithm)?;
            Ok(try_sign(ps, sk, &msg)?)
        }
        (_, _) => Err(CryptoError::KeyTypeMismatch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::{de::from_reader, value::Integer};
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use trussed_mldsa::verify;

    #[test]
    fn cose_public_key_canonical_encoding_matches_fixture() {
        let pk_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let pk = PublicKey(pk_bytes.clone());
        let cose = try_cose_public_key(ParamSet::MLDSA44, &pk).expect("encode COSE key");
        let expected = vec![
            0xA3, 0x01, 0x07, 0x03, 0x38, 0x2F, 0x20, 0x44, 0xDE, 0xAD, 0xBE, 0xEF,
        ];
        assert_eq!(cose, expected);
        let decoded: ciborium::value::Value =
            from_reader(cose.as_slice()).expect("valid COSE public key");
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

    #[test]
    fn es256_credential_roundtrip() {
        let (cose_key, secret_key) =
            try_create_credential(CoseAlg::ES256).expect("create ES256 credential");
        assert_eq!(secret_key.secret_bytes().len(), 32);

        let value: ciborium::value::Value =
            from_reader(cose_key.as_slice()).expect("decode ES256 COSE key");
        let ciborium::value::Value::Map(entries) = value else {
            panic!("COSE key must be a map");
        };

        let mut kty = None;
        let mut alg = None;
        let mut crv = None;
        let mut x_bytes = None;
        let mut y_bytes = None;

        for (key, val) in entries {
            if let ciborium::value::Value::Integer(label) = key {
                let label_value: i128 = label.into();
                match label_value {
                    1 => kty = Some(val),
                    3 => alg = Some(val),
                    -1 => crv = Some(val),
                    -2 => {
                        if let ciborium::value::Value::Bytes(bytes) = val {
                            x_bytes = Some(bytes);
                        }
                    }
                    -3 => {
                        if let ciborium::value::Value::Bytes(bytes) = val {
                            y_bytes = Some(bytes);
                        }
                    }
                    _ => {}
                }
            }
        }

        assert_eq!(
            kty,
            Some(ciborium::value::Value::Integer(Integer::from(2))),
            "kty present"
        );
        assert_eq!(
            alg,
            Some(ciborium::value::Value::Integer(Integer::from(
                CoseAlg::ES256 as i32
            ))),
            "alg present"
        );
        assert_eq!(
            crv,
            Some(ciborium::value::Value::Integer(Integer::from(1))),
            "crv present"
        );

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
        let value: ciborium::value::Value = ciborium::de::from_reader(cbor).expect("valid CBOR");
        if let ciborium::value::Value::Map(map) = value {
            for (k, v) in map {
                if k == ciborium::value::Value::Integer(Integer::from(COSE_KEY_PARAM_AKP_KEY)) {
                    if let ciborium::value::Value::Bytes(bytes) = v {
                        return bytes;
                    }
                }
            }
        }
        panic!("COSE key missing public key bytes");
    }

    // ---------------------------------------------------------------------
    // PIN/UV auth protocol key derivation
    // ---------------------------------------------------------------------

    /// A fixed ECDH shared secret Z (the 32-byte big-endian x-coordinate of the
    /// shared point) used by the KDF test vectors below.
    const TEST_Z: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    /// Regression test for PIN/UV auth protocol two's `kdf(Z)`.
    ///
    /// CTAP 2.1 §6.5.7 defines protocol two's KDF as:
    ///
    /// ```text
    /// kdf(Z) -> sharedSecret
    ///     Return HKDF-SHA-256(salt = 32 zero bytes, IKM = Z, L = 32, info = "CTAP2 HMAC key") ||
    ///            HKDF-SHA-256(salt = 32 zero bytes, IKM = Z, L = 32, info = "CTAP2 AES key")
    /// ```
    ///
    /// The expected values below were **not** produced by this crate.  They were
    /// computed outside the Rust build by three independent HKDF
    /// implementations, all of which agree:
    ///
    /// 1. A hand-written HKDF-SHA-256 transcribed directly from RFC 5869
    ///    §2.2/§2.3 in Python, first validated against RFC 5869's own published
    ///    SHA-256 test vectors (appendix A, test cases 1, 2 and 3).
    /// 2. `pyca/cryptography`'s `HKDF` (OpenSSL-backed).
    /// 3. The OpenSSL CLI:
    ///
    /// ```text
    /// openssl kdf -keylen 32 -kdfopt digest:SHA2-256 \
    ///   -kdfopt hexkey:0102...1f20 \
    ///   -kdfopt hexsalt:0000000000000000000000000000000000000000000000000000000000000000 \
    ///   -kdfopt info:"CTAP2 HMAC key" HKDF
    /// ```
    ///
    /// Because the expected keys are externally sourced, this test fails for the
    /// historical bug where `SHA-256(Z)` was fed to HKDF as the IKM instead of
    /// `Z`.  A round-trip / self-consistency test would not have caught that.
    #[test]
    fn pin_protocol_two_kdf_matches_external_test_vector() {
        const EXPECTED_HMAC_KEY: [u8; 32] = [
            0x9e, 0xb6, 0x85, 0xea, 0x1b, 0xd7, 0x95, 0xe0, 0x5c, 0xbf, 0xbe, 0x28, 0xf0, 0xef,
            0x46, 0xf1, 0xb8, 0x9a, 0xe3, 0xa7, 0x31, 0x61, 0xc4, 0xd6, 0x4d, 0x11, 0x81, 0x08,
            0x2e, 0x82, 0xdb, 0x67,
        ];
        const EXPECTED_AES_KEY: [u8; 32] = [
            0xe5, 0x6b, 0x82, 0x39, 0x8c, 0xbb, 0x09, 0xe2, 0xa1, 0xb5, 0x46, 0x80, 0x8a, 0x71,
            0x6b, 0xef, 0xa7, 0x90, 0x7d, 0x17, 0x97, 0x6b, 0x72, 0x19, 0x3c, 0x6f, 0x90, 0x94,
            0x13, 0xc7, 0x31, 0x84,
        ];

        let keys = try_derive_classic_pin_uv_session_keys(ClassicPinProtocol::V2, &TEST_Z)
            .expect("protocol two KDF");
        assert_eq!(
            keys.auth_key, EXPECTED_HMAC_KEY,
            "protocol two HMAC key must be HKDF-SHA-256(salt=0^32, IKM=Z, info=\"CTAP2 HMAC key\")"
        );
        assert_eq!(
            keys.encryption_key, EXPECTED_AES_KEY,
            "protocol two AES key must be HKDF-SHA-256(salt=0^32, IKM=Z, info=\"CTAP2 AES key\")"
        );
    }

    /// Guards specifically against reintroducing the `IKM = SHA-256(Z)` bug.
    #[test]
    fn pin_protocol_two_kdf_does_not_pre_hash_z() {
        let keys = try_derive_classic_pin_uv_session_keys(ClassicPinProtocol::V2, &TEST_Z)
            .expect("protocol two KDF");

        // What the buggy implementation produced: HKDF with IKM = SHA-256(Z).
        let hashed_z = Sha256::digest(TEST_Z);
        let wrong = Hkdf::<Sha256>::new(None, &hashed_z);
        let mut wrong_aes = [0u8; 32];
        let mut wrong_hmac = [0u8; 32];
        wrong.expand(b"CTAP2 AES key", &mut wrong_aes).unwrap();
        wrong.expand(b"CTAP2 HMAC key", &mut wrong_hmac).unwrap();

        assert_ne!(
            keys.encryption_key, wrong_aes,
            "protocol two must derive from Z, not SHA-256(Z)"
        );
        assert_ne!(
            keys.auth_key, wrong_hmac,
            "protocol two must derive from Z, not SHA-256(Z)"
        );
    }

    /// CTAP 2.1 §6.5.6: protocol one's `kdf(Z)` is simply `SHA-256(Z)`, and both
    /// the AES and HMAC keys are that same value.
    #[test]
    fn pin_protocol_one_kdf_is_sha256_of_z() {
        let keys = try_derive_classic_pin_uv_session_keys(ClassicPinProtocol::V1, &TEST_Z)
            .expect("protocol one KDF");
        let expected = Sha256::digest(TEST_Z);
        assert_eq!(keys.encryption_key.as_slice(), expected.as_slice());
        assert_eq!(keys.auth_key.as_slice(), expected.as_slice());
        assert_eq!(keys.encryption_key, keys.auth_key);
    }

    #[test]
    fn pin_protocols_derive_different_keys() {
        let v1 = try_derive_classic_pin_uv_session_keys(ClassicPinProtocol::V1, &TEST_Z).unwrap();
        let v2 = try_derive_classic_pin_uv_session_keys(ClassicPinProtocol::V2, &TEST_Z).unwrap();
        assert_ne!(v1.encryption_key, v2.encryption_key);
        assert_ne!(v1.auth_key, v2.auth_key);
        // Protocol two's two halves must be distinct keys.
        assert_ne!(v2.encryption_key, v2.auth_key);
    }

    #[test]
    fn protocol_identifiers_match_spec() {
        assert_eq!(ClassicPinProtocol::V1.identifier(), 1);
        assert_eq!(ClassicPinProtocol::V2.identifier(), 2);
    }

    #[test]
    fn pin_uv_session_keys_debug_is_redacted() {
        let keys = try_derive_classic_pin_uv_session_keys(ClassicPinProtocol::V2, &TEST_Z).unwrap();
        let rendered = format!("{keys:?}");
        assert!(rendered.contains("<redacted>"));
        // No byte of either key should appear in the debug output.
        assert!(!rendered.contains(&format!("{}", keys.auth_key[0])));
    }

    // ---------------------------------------------------------------------
    // PIN block encryption
    // ---------------------------------------------------------------------

    fn test_keys(protocol: ClassicPinProtocol) -> PinUvSessionKeys {
        try_derive_classic_pin_uv_session_keys(protocol, &TEST_Z).expect("derive session keys")
    }

    #[test]
    fn pin_block_roundtrip_protocol_one_has_no_iv_prefix() {
        let keys = test_keys(ClassicPinProtocol::V1);
        let plaintext = [0xA5u8; 64];
        let ciphertext =
            encrypt_classic_pin_block(ClassicPinProtocol::V1, &keys, None, &plaintext).unwrap();
        // Protocol one uses an all-zero IV and does NOT prepend it.
        assert_eq!(ciphertext.len(), plaintext.len());
        let decrypted =
            decrypt_classic_pin_block(ClassicPinProtocol::V1, &keys, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn pin_block_roundtrip_protocol_two_prepends_iv() {
        let keys = test_keys(ClassicPinProtocol::V2);
        let iv = [0x5Au8; 16];
        let plaintext = [0xA5u8; 64];
        let ciphertext =
            encrypt_classic_pin_block(ClassicPinProtocol::V2, &keys, Some(&iv), &plaintext)
                .unwrap();
        // Protocol two returns iv || ct.
        assert_eq!(ciphertext.len(), 16 + plaintext.len());
        assert_eq!(&ciphertext[..16], &iv[..]);
        let decrypted =
            decrypt_classic_pin_block(ClassicPinProtocol::V2, &keys, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn pin_block_protocol_two_requires_an_iv() {
        let keys = test_keys(ClassicPinProtocol::V2);
        assert!(
            encrypt_classic_pin_block(ClassicPinProtocol::V2, &keys, None, &[0u8; 32]).is_err()
        );
    }

    #[test]
    fn pin_block_rejects_non_block_aligned_input() {
        let unaligned = [0u8; 17];
        for protocol in [ClassicPinProtocol::V1, ClassicPinProtocol::V2] {
            let keys = test_keys(protocol);
            let iv = [0u8; 16];
            assert!(
                encrypt_classic_pin_block(protocol, &keys, Some(&iv), &unaligned).is_err(),
                "{protocol:?} must reject unaligned plaintext"
            );
        }

        let v1_keys = test_keys(ClassicPinProtocol::V1);
        assert!(decrypt_classic_pin_block(ClassicPinProtocol::V1, &v1_keys, &unaligned).is_err());

        let v2_keys = test_keys(ClassicPinProtocol::V2);
        // 16-byte IV plus a 17-byte body is still unaligned.
        let mut bad = vec![0u8; 16];
        bad.extend_from_slice(&unaligned);
        assert!(decrypt_classic_pin_block(ClassicPinProtocol::V2, &v2_keys, &bad).is_err());
        // Anything shorter than the IV is rejected outright.
        assert!(decrypt_classic_pin_block(ClassicPinProtocol::V2, &v2_keys, &[0u8; 15]).is_err());
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

    #[test]
    fn try_sign_challenge_rejects_malformed_ml_dsa_key_bytes() {
        // A truncated / corrupted ML-DSA secret key record read back from disk.
        let junk = try_credential_secret_from_bytes(CoseAlg::MLDSA65, &[0x42; 7]).unwrap();
        let result = try_sign_challenge(CoseAlg::MLDSA65, &junk, b"auth", b"hash");
        assert!(
            matches!(result, Err(CryptoError::MlDsa(_))),
            "expected an ML-DSA error, got {result:?}"
        );
    }

    #[test]
    fn try_credential_secret_from_bytes_rejects_malformed_p256_scalar() {
        // `CredentialSecretKey` deliberately has no `PartialEq` (secret keys
        // must not be compared with `==`), so inspect the error side only.
        let err = |bytes: &[u8]| {
            try_credential_secret_from_bytes(CoseAlg::ES256, bytes).expect_err("must be rejected")
        };
        // Wrong length.
        assert_eq!(err(&[0x11; 5]), CryptoError::InvalidKey);
        // Correct length but not a valid scalar: zero is rejected.
        assert_eq!(err(&[0x00; 32]), CryptoError::InvalidKey);
        // Correct length but above the group order.
        assert_eq!(err(&[0xFF; 32]), CryptoError::InvalidKey);
        // The `()`-returning wrapper must agree.
        assert!(credential_secret_from_bytes(CoseAlg::ES256, &[0x11; 5]).is_err());
    }

    #[test]
    fn try_cose_es256_public_key_rejects_identity_point() {
        let identity = EncodedPoint::identity();
        assert!(identity.is_identity());
        assert_eq!(
            try_cose_es256_public_key(&identity),
            Err(CryptoError::InvalidPublicKey)
        );
    }

    #[test]
    fn try_cose_es256_public_key_rejects_point_without_y_coordinate() {
        let signing_key = P256SigningKey::random(&mut OsRng);
        // A compressed SEC1 encoding carries X but no Y.
        let compressed = signing_key.verifying_key().to_encoded_point(true);
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
        assert!(CoseAlg::try_from(-257).is_err());
        assert!(CoseAlg::try_from(-8).is_err());
        assert_eq!(CoseAlg::try_from(-7), Ok(CoseAlg::ES256));
        assert_eq!(CoseAlg::try_from(-48), Ok(CoseAlg::MLDSA44));
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

    #[test]
    fn deprecated_wrappers_still_agree_with_fallible_versions() {
        #[allow(deprecated)]
        {
            let pk = PublicKey(vec![0x01, 0x02, 0x03]);
            assert_eq!(
                cose_public_key(ParamSet::MLDSA44, &pk),
                try_cose_public_key(ParamSet::MLDSA44, &pk).unwrap()
            );

            let (_, secret_key) = try_create_credential(CoseAlg::ES256).unwrap();
            assert_eq!(
                secret_key.to_bytes().as_slice(),
                secret_key.secret_bytes().as_slice()
            );
        }
    }
}
