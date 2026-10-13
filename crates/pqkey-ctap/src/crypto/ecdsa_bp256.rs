//! ECDSA on brainpoolP256r1 with SHA-256 (ESB256, RFC 9864 §2.1).
//! The stored seed derives a scalar through the existing extra-random-bits KDF.

use bp256::BrainpoolP256r1;
use bp256::r1::ecdsa::DerSignature;
use ecdsa::signature::Signer;

use super::CryptoError;
use super::alg::CoseAlg;
use super::credential_key::Seed;
use super::ecdsa::{Curve, derive_scalar, try_cose_key};
use super::scrub::with_scrubbed_stack;

type SigningKey = ecdsa::SigningKey<BrainpoolP256r1>;

/// The signing key the seed derives; called only inside a scrubbed frame.
pub(super) fn signing_key(seed: &Seed) -> Result<SigningKey, CryptoError> {
    derive_scalar::<BrainpoolP256r1, _>(b"brainpoolP256r1", seed).map(SigningKey::from)
}

/// The uncompressed EC2 COSE public key, with both fixed-width coordinates.
pub(super) fn cose_public_key(alg: CoseAlg, seed: &Seed) -> Result<Vec<u8>, CryptoError> {
    let point = with_scrubbed_stack(|| {
        signing_key(seed).map(|key| key.verifying_key().to_sec1_point(false))
    })?;
    try_cose_key(alg, Curve::BrainpoolP256r1, point.coordinates())
}

/// Hash and sign the message with RFC 6979, returning ASN.1 DER ECDSA.
pub(super) fn sign(seed: &Seed, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let signature: DerSignature = with_scrubbed_stack(|| {
        signing_key(seed)?
            .try_sign(message)
            .map_err(|_| CryptoError::SigningFailed)
    })?;
    Ok(signature.as_bytes().to_vec())
}
