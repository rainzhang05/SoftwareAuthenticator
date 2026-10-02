//! The PIN/UV auth protocols' cryptography: the key derivation from the
//! ECDH shared secret (CTAP 2.3 §6.5.6, §6.5.7) and AES-256-CBC.

use aes::Aes256;
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::NoPadding};
use cbc::{Decryptor, Encryptor};
use core::fmt;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::CryptoError;
use super::hkdf::hkdf_sha256;

type Aes256CbcEncryptor = Encryptor<Aes256>;
type Aes256CbcDecryptor = Decryptor<Aes256>;

/// Session keys derived from a PIN/UV key-agreement shared secret.
///
/// Both halves are secret: `encryption_key` is the AES-256-CBC key and
/// `auth_key` is the HMAC-SHA-256 key.  The struct zeroizes itself on drop and
/// its `Debug` output is redacted so the keys cannot leak into logs.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PinUvSessionKeys {
    /// The AES-256-CBC key of `encrypt` and `decrypt`.
    pub encryption_key: [u8; 32],
    /// The HMAC-SHA-256 key of `authenticate` and `verify`.
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
    /// PIN/UV auth protocol one (CTAP 2.3 §6.5.6).
    V1,
    /// PIN/UV auth protocol two (CTAP 2.3 §6.5.7).
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
/// `hkdf_sha256` uses an all-zero salt of the hash output length, which for
/// SHA-256 is exactly the 32 zero bytes the specification requires.
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
    // Derived in place, so no copy of either key outlives the struct that
    // zeroizes them.
    let mut keys = PinUvSessionKeys {
        encryption_key: [0u8; 32],
        auth_key: [0u8; 32],
    };
    match protocol {
        ClassicPinProtocol::V1 => {
            // kdf(Z) = SHA-256(Z); both keys are that same 32-byte value.
            let hash = Zeroizing::new(Sha256::digest(shared_secret));
            keys.encryption_key.copy_from_slice(&hash);
            keys.auth_key.copy_from_slice(&hash);
        }
        ClassicPinProtocol::V2 => {
            // IKM is Z itself, NOT SHA-256(Z), and the salt 32 zero bytes.
            hkdf_sha256(shared_secret, b"CTAP2 AES key", &mut keys.encryption_key)
                .map_err(|_| CryptoError::KeyDerivation)?;
            hkdf_sha256(shared_secret, b"CTAP2 HMAC key", &mut keys.auth_key)
                .map_err(|_| CryptoError::KeyDerivation)?;
        }
    }
    Ok(keys)
}

/// Encrypt a classic PIN block using AES-256-CBC.  Protocol 1 uses an all-zero
/// IV, while protocol 2 prepends the random IV to the ciphertext.
pub fn encrypt_classic_pin_block(
    protocol: ClassicPinProtocol,
    keys: &PinUvSessionKeys,
    iv: Option<&[u8; 16]>,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    match protocol {
        ClassicPinProtocol::V1 => {
            if !plaintext.len().is_multiple_of(16) {
                return Err(CryptoError::InvalidPinBlock);
            }
            let iv = [0u8; 16];
            let cipher = Aes256CbcEncryptor::new_from_slices(&keys.encryption_key, &iv)
                .map_err(|_| CryptoError::InvalidKey)?;
            Ok(cipher.encrypt_padded_vec::<NoPadding>(plaintext))
        }
        ClassicPinProtocol::V2 => {
            let iv = iv.ok_or(CryptoError::InvalidPinBlock)?;
            if !plaintext.len().is_multiple_of(16) {
                return Err(CryptoError::InvalidPinBlock);
            }
            let cipher = Aes256CbcEncryptor::new_from_slices(&keys.encryption_key, iv)
                .map_err(|_| CryptoError::InvalidKey)?;
            let mut ciphertext = cipher.encrypt_padded_vec::<NoPadding>(plaintext);
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
) -> Result<Vec<u8>, CryptoError> {
    match protocol {
        ClassicPinProtocol::V1 => {
            let iv = [0u8; 16];
            let cipher = Aes256CbcDecryptor::new_from_slices(&keys.encryption_key, &iv)
                .map_err(|_| CryptoError::InvalidKey)?;
            if !ciphertext.len().is_multiple_of(16) {
                return Err(CryptoError::InvalidPinBlock);
            }
            cipher
                .decrypt_padded_vec::<NoPadding>(ciphertext)
                .map_err(|_| CryptoError::InvalidPinBlock)
        }
        ClassicPinProtocol::V2 => {
            if ciphertext.len() < 16 {
                return Err(CryptoError::InvalidPinBlock);
            }
            let (iv, body) = ciphertext.split_at(16);
            let cipher = Aes256CbcDecryptor::new_from_slices(&keys.encryption_key, iv)
                .map_err(|_| CryptoError::InvalidKey)?;
            if !body.len().is_multiple_of(16) {
                return Err(CryptoError::InvalidPinBlock);
            }
            cipher
                .decrypt_padded_vec::<NoPadding>(body)
                .map_err(|_| CryptoError::InvalidPinBlock)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let mut wrong_aes = [0u8; 32];
        let mut wrong_hmac = [0u8; 32];
        hkdf_sha256(&hashed_z, b"CTAP2 AES key", &mut wrong_aes).unwrap();
        hkdf_sha256(&hashed_z, b"CTAP2 HMAC key", &mut wrong_hmac).unwrap();

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
}
