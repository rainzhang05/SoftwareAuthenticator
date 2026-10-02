//! The ML-DSA family (FIPS 204,
//! [`Scheme::MlDsa`](super::alg::Scheme::MlDsa)): keys kept as their 32-byte
//! seed `ξ`, which the parameter set expands.

use pqkey_mldsa::{ParamSet, PublicKey, try_public_key_from_seed, try_sign_from_seed};

use super::CryptoError;
use super::alg::CoseAlg;
use super::cose::try_akp_key;
use super::credential_key::Seed;

/// The CBOR COSE_Key of the public key that `seed` expands to under
/// `param_set`, for `alg`.
pub(super) fn cose_public_key(
    alg: CoseAlg,
    param_set: ParamSet,
    seed: &Seed,
) -> Result<Vec<u8>, CryptoError> {
    let public_key = try_public_key_from_seed(param_set, seed.as_bytes())?;
    try_cose_key(alg, &public_key)
}

/// Sign `message` with the key that `seed` expands to under `param_set`:
/// hedged ML-DSA with an empty context, returned as the raw FIPS 204
/// signature bytes.
pub(super) fn sign(
    param_set: ParamSet,
    seed: &Seed,
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
