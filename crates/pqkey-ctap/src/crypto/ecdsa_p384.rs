//! ECDSA on P-384 ([`Curve::P384`]) with SHA-384, the scheme of ES384: keys
//! kept as a seed the scalar is derived from ([`derive_scalar`]).

use p384::NistP384;
use p384::ecdsa::{DerSignature, SigningKey, signature::Signer};

use super::CryptoError;
use super::alg::CoseAlg;
use super::credential_key::Seed;
use super::ecdsa::{Curve, derive_scalar, try_cose_key};
use super::scrub::with_scrubbed_stack;

/// The curve's name in the derivation's input.
const NAME: &[u8] = b"P-384";

/// The signing key `seed` derives.  It computes the scalar and the public
/// key, so it runs on a scrubbed stack.
pub(super) fn signing_key(seed: &Seed) -> Result<SigningKey, CryptoError> {
    derive_scalar::<NistP384, _>(NAME, seed).map(SigningKey::from)
}

/// The CBOR COSE_Key of the public key `seed` derives, for `alg`.
pub(super) fn cose_public_key(alg: CoseAlg, seed: &Seed) -> Result<Vec<u8>, CryptoError> {
    let point = with_scrubbed_stack(|| {
        signing_key(seed).map(|key| key.verifying_key().to_sec1_point(false))
    })?;
    try_cose_key(alg, Curve::P384, point.coordinates())
}

/// Sign `message` with ECDSA over P-384 and SHA-384 (the message is hashed
/// internally) with the key `seed` derives, returned as an ASN.1 DER
/// `Ecdsa-Sig-Value`.
///
/// Returns [`CryptoError::SigningFailed`] if signing fails.
pub(super) fn sign(seed: &Seed, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let signature: DerSignature = with_scrubbed_stack(|| {
        signing_key(seed)?
            .try_sign(message)
            .map_err(|_| CryptoError::SigningFailed)
    })?;
    Ok(signature.as_bytes().to_vec())
}
