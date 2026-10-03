//! EdDSA on Ed25519 ([`EdwardsCurve::Ed25519`], RFC 8032 §5.1), the scheme of
//! EdDSA and Ed25519: keys kept as their 32-byte private key, the seed
//! itself.

use ed25519_dalek::{Signer, SigningKey};

use super::CryptoError;
use super::alg::CoseAlg;
use super::credential_key::Seed;
use super::eddsa::{EdwardsCurve, try_cose_key};
use super::scrub::with_scrubbed_stack;

/// The signing key whose RFC 8032 private key is `seed`.  It hashes the
/// private key into the secret scalar and prefix, and computes the public
/// key, so it runs on a scrubbed stack.
fn signing_key(seed: &Seed) -> SigningKey {
    SigningKey::from_bytes(seed.as_bytes())
}

/// The CBOR COSE_Key of the public key of `seed`, for `alg`.
pub(super) fn cose_public_key(alg: CoseAlg, seed: &Seed) -> Result<Vec<u8>, CryptoError> {
    let x = with_scrubbed_stack(|| signing_key(seed).verifying_key().to_bytes());
    try_cose_key(alg, EdwardsCurve::Ed25519, &x)
}

/// Sign `message` with pure Ed25519 under `seed`, returned as the 64-byte
/// signature R ‖ S that RFC 8032 §5.1.6 encodes.  Signing hashes the private
/// key again and draws the nonce r from its prefix and the message.
///
/// Returns [`CryptoError::SigningFailed`] if signing fails.
pub(super) fn sign(seed: &Seed, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let signature = with_scrubbed_stack(|| signing_key(seed).try_sign(message))
        .map_err(|_| CryptoError::SigningFailed)?;
    Ok(signature.to_bytes().to_vec())
}
