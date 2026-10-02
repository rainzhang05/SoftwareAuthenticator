//! The cryptography the CTAP engine and the credential store share: the
//! signature algorithms, COSE keys, credential keys and signing, the PIN/UV
//! auth protocols' key derivation and encryption, HKDF, and the stack
//! scrubbing around secret-dependent arithmetic.

use core::fmt;
use getrandom::SysRng;
use pqkey_mldsa::MlDsaError;
use rand_core::UnwrapErr;

pub(crate) mod alg;
pub(crate) mod cose;
pub(crate) mod credential_key;
pub(crate) mod ecdsa_p256;
pub(crate) mod hkdf;
pub(crate) mod mldsa;
pub(crate) mod pin_uv;
pub(crate) mod scrub;

/// The operating system's random number generator, for the infallible
/// `rand_core::Rng` interface.  Like `rand_core` 0.6's `OsRng`, it panics if the
/// operating system cannot provide randomness; use [`SysRng`] directly with
/// `TryRng` where that failure should be reported instead.
pub(crate) fn os_rng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}

/// Errors returned by the fallible (`try_*`) credential and COSE helpers.
///
/// Every variant corresponds to input an attacker can influence (a malformed
/// COSE key from the platform, a corrupted secret key read back from disk, an
/// `alg` field that disagrees with the stored key material).  None of them
/// should ever abort the process: this crate runs inside a long-lived daemon
/// that parses data originating from a web browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
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
    /// A PIN/UV auth protocol block is not a whole number of AES blocks, or
    /// protocol two was asked to encrypt without an IV.
    InvalidPinBlock,
    /// The underlying ML-DSA implementation reported an error.
    MlDsa(MlDsaError),
    /// The operating system's random number generator failed.
    Randomness,
}

impl From<MlDsaError> for CryptoError {
    fn from(err: MlDsaError) -> Self {
        CryptoError::MlDsa(err)
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::KeyTypeMismatch => {
                f.write_str("secret key type does not match the requested algorithm")
            }
            CryptoError::InvalidKey => f.write_str("malformed secret key bytes"),
            CryptoError::InvalidPublicKey => f.write_str("malformed or identity public key"),
            CryptoError::CborEncoding => f.write_str("COSE_Key CBOR encoding failed"),
            CryptoError::KeyDerivation => f.write_str("key derivation failed"),
            CryptoError::SigningFailed => f.write_str("signature generation failed"),
            CryptoError::InvalidPinBlock => f.write_str("malformed PIN/UV auth protocol block"),
            CryptoError::MlDsa(err) => write!(f, "ML-DSA error: {err:?}"),
            CryptoError::Randomness => f.write_str("the random number generator failed"),
        }
    }
}

impl std::error::Error for CryptoError {}
