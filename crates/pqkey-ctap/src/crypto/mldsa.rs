//! The ML-DSA family (FIPS 204,
//! [`Scheme::MlDsa`](super::alg::Scheme::MlDsa)): keys kept as their 32-byte
//! seed `ξ`, which the parameter set expands.

use core::fmt;
use pqkey_mldsa::{ParamSet, PublicKey, SEED_LEN, try_public_key_from_seed, try_sign_from_seed};
use zeroize::Zeroizing;

use super::CryptoError;
use super::alg::CoseAlg;
use super::cose::try_akp_key;

/// The key whose seed is `bytes`.  Stored ML-DSA keys are seeds; an expanded
/// secret key is never stored, so it is not accepted either.
///
/// Returns [`CryptoError::InvalidKey`] unless `bytes` is exactly [`SEED_LEN`]
/// bytes.
pub(super) fn seed(bytes: &[u8]) -> Result<MlDsaSeed, CryptoError> {
    <[u8; SEED_LEN]>::try_from(bytes)
        .map(MlDsaSeed::new)
        .map_err(|_| CryptoError::InvalidKey)
}

/// The CBOR COSE_Key of the public key that `seed` expands to under
/// `param_set`, for `alg`.
pub(super) fn cose_public_key(
    alg: CoseAlg,
    param_set: ParamSet,
    seed: &MlDsaSeed,
) -> Result<Vec<u8>, CryptoError> {
    let public_key = try_public_key_from_seed(param_set, seed.as_bytes())?;
    try_cose_key(alg, &public_key)
}

/// Sign `message` with the key that `seed` expands to under `param_set`:
/// hedged ML-DSA with an empty context, returned as the raw FIPS 204
/// signature bytes.
pub(super) fn sign(
    param_set: ParamSet,
    seed: &MlDsaSeed,
    message: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    Ok(try_sign_from_seed(param_set, seed.as_bytes(), message)?)
}

/// The CBOR COSE_Key of the ML-DSA public key `public_key`, for `alg`: an
/// Algorithm Key Pair whose `pub` is the raw FIPS 204 public key.  Returns
/// [`CryptoError::CborEncoding`] if serialization fails.
pub(crate) fn try_cose_key(alg: CoseAlg, public_key: &PublicKey) -> Result<Vec<u8>, CryptoError> {
    try_akp_key(alg, public_key.as_bytes())
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
