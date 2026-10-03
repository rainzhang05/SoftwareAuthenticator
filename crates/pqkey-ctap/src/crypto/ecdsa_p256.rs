//! ECDSA on P-256 ([`Curve::P256`]) with SHA-256, the scheme of ES256 and
//! ESP256: keys kept as their scalar.

use p256::SecretKey;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use p256::elliptic_curve::Generate;
use rand_core::TryCryptoRng;
use zeroize::Zeroize;

use super::CryptoError;
use super::alg::CoseAlg;
use super::ecdsa::{Curve, try_cose_key};
use super::scrub::with_scrubbed_stack;

/// Write a fresh scalar from `rng` into `scalar`, big-endian.  `SecretKey`
/// generation only yields scalars in [1, n), so it is valid by construction.
pub(super) fn generate_scalar<R: TryCryptoRng + ?Sized>(
    rng: &mut R,
    scalar: &mut [u8; 32],
) -> Result<(), R::Error> {
    let secret = SecretKey::try_generate_from_rng(rng)?;
    let mut encoded = secret.to_bytes();
    scalar.copy_from_slice(&encoded);
    encoded.as_mut_slice().zeroize();
    Ok(())
}

/// The signing key whose big-endian scalar is `bytes`.  It multiplies the
/// base point by the scalar, so it runs on a scrubbed stack.
///
/// Returns [`CryptoError::InvalidKey`] unless `bytes` is exactly 32 bytes and
/// a scalar that is non-zero and below the group order.
pub(super) fn signing_key(bytes: &[u8]) -> Result<SigningKey, CryptoError> {
    // Exactly 32 bytes: `SigningKey::from_slice` would left-pad a slice of
    // 24 to 31 bytes, reading a truncated key as some other key.
    // `from_bytes` performs the full range check (non-zero and below the
    // group order), and borrowing the bytes in place needs no intermediate
    // copy of the scalar.
    let scalar = <&p256::FieldBytes>::try_from(bytes).map_err(|_| CryptoError::InvalidKey)?;
    SigningKey::from_bytes(scalar).map_err(|_| CryptoError::InvalidKey)
}

/// The CBOR COSE_Key of `key`'s public key, for `alg`.
pub(super) fn cose_public_key(alg: CoseAlg, key: &SigningKey) -> Result<Vec<u8>, CryptoError> {
    try_cose_key(
        alg,
        Curve::P256,
        key.verifying_key().to_sec1_point(false).coordinates(),
    )
}

/// Sign `message` with ECDSA over P-256 and SHA-256 (the message is hashed
/// internally), returned as an ASN.1 DER `Ecdsa-Sig-Value`, the encoding
/// WebAuthn requires for ES256 and ESP256.
///
/// Note: RustCrypto's `p256` does not normalize `s` to the lower half of the
/// group order (unlike `k256`, its `EcdsaCurve::NORMALIZE_S` is false), so
/// roughly half of the emitted signatures are "high-S".  That is valid ECDSA
/// and is accepted by WebAuthn verifiers; neither WebAuthn nor CTAP 2.1
/// requires low-S for ES256 or ESP256.  Call `Signature::normalize_s` before
/// encoding if a low-S signature is ever required.
///
/// Returns [`CryptoError::SigningFailed`] if signing fails.
pub(super) fn sign(key: &SigningKey, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let signature: Signature =
        with_scrubbed_stack(|| key.try_sign(message)).map_err(|_| CryptoError::SigningFailed)?;
    Ok(signature.to_der().as_bytes().to_vec())
}
