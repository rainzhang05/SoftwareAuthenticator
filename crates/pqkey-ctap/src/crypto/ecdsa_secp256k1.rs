//! ECDSA on secp256k1 ([`Curve::Secp256k1`]) with SHA-256, the scheme of
//! ES256K: keys kept as a seed the scalar is derived from ([`derive_scalar`]).

use k256::Secp256k1;
use k256::ecdsa::{DerSignature, SigningKey, signature::Signer};

use super::CryptoError;
use super::alg::CoseAlg;
use super::credential_key::Seed;
use super::ecdsa::{Curve, derive_scalar, try_cose_key};
use super::scrub::with_scrubbed_stack;

/// The curve's name in the derivation's input.
const NAME: &[u8] = b"secp256k1";

/// The signing key `seed` derives.  It computes the scalar and the public
/// key, so it runs on a scrubbed stack.
pub(super) fn signing_key(seed: &Seed) -> Result<SigningKey, CryptoError> {
    derive_scalar::<Secp256k1, _>(NAME, seed).map(SigningKey::from)
}

/// The CBOR COSE_Key of the public key `seed` derives, for `alg`.
pub(super) fn cose_public_key(alg: CoseAlg, seed: &Seed) -> Result<Vec<u8>, CryptoError> {
    let point = with_scrubbed_stack(|| {
        signing_key(seed).map(|key| key.verifying_key().to_sec1_point(false))
    })?;
    try_cose_key(alg, Curve::Secp256k1, point.coordinates())
}

/// Sign `message` with ECDSA over secp256k1 and SHA-256 (the message is
/// hashed internally) with the key `seed` derives, returned as an ASN.1 DER
/// `Ecdsa-Sig-Value`.
///
/// RustCrypto's `k256` normalizes `s` to the lower half of the group order
/// (its `EcdsaCurve::NORMALIZE_S` is true), so its signatures are "low-S".
/// That is valid ECDSA, as high-S signatures are too, and RFC 8812 asks for
/// neither.
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
