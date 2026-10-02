//! The P-256 family: keys kept as their scalar, and ECDSA with SHA-256
//! ([`Scheme::EcdsaP256Sha256`](super::alg::Scheme::EcdsaP256Sha256)), the
//! scheme of ES256.

use p256::Sec1Point;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};

use super::CryptoError;
use super::alg::CoseAlg;
use super::cose::{CRV_P256, try_ec2_key};
use super::scrub::with_scrubbed_stack;

/// The signing key whose big-endian scalar is `bytes`.
///
/// Returns [`CryptoError::InvalidKey`] unless `bytes` is exactly 32 bytes and
/// a scalar that is non-zero and below the group order.
pub(super) fn signing_key(bytes: &[u8]) -> Result<SigningKey, CryptoError> {
    // Exactly 32 bytes: `SigningKey::from_slice` would left-pad a slice of
    // 24 to 31 bytes, reading a truncated key as some other key.
    // `from_bytes` performs the full range check (non-zero and below the
    // group order), and borrowing the bytes in place needs no intermediate
    // copy of the scalar.  It multiplies the base point by the scalar, so it
    // runs on a scrubbed stack.
    let scalar = <&p256::FieldBytes>::try_from(bytes).map_err(|_| CryptoError::InvalidKey)?;
    with_scrubbed_stack(|| SigningKey::from_bytes(scalar)).map_err(|_| CryptoError::InvalidKey)
}

/// The CBOR COSE_Key of `key`'s public key, for `alg`.
pub(super) fn cose_public_key(alg: CoseAlg, key: &SigningKey) -> Result<Vec<u8>, CryptoError> {
    try_cose_key(alg, &key.verifying_key().to_sec1_point(false))
}

/// Sign `message` with ECDSA over P-256 and SHA-256 (the message is hashed
/// internally), returned as an ASN.1 DER `Ecdsa-Sig-Value`, the encoding
/// WebAuthn requires for ES256.
///
/// Note: RustCrypto's `p256` does not normalize `s` to the lower half of the
/// group order (unlike `k256`, it does not override `SignPrimitive`), so
/// roughly half of the emitted signatures are "high-S".  That is valid ECDSA
/// and is accepted by WebAuthn verifiers; neither WebAuthn nor CTAP 2.1
/// requires low-S for ES256.  Call `Signature::normalize_s` before encoding
/// if a low-S signature is ever required.
///
/// Returns [`CryptoError::SigningFailed`] if signing fails.
pub(super) fn sign(key: &SigningKey, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let signature: Signature =
        with_scrubbed_stack(|| key.try_sign(message)).map_err(|_| CryptoError::SigningFailed)?;
    Ok(signature.to_der().as_bytes().to_vec())
}

/// The CBOR COSE_Key of the P-256 public key `point`, for `alg`: an EC2 key
/// on curve P-256.
///
/// Returns [`CryptoError::InvalidPublicKey`] if `point` is the point at
/// infinity or is a compressed/short encoding without both affine coordinates,
/// and [`CryptoError::CborEncoding`] if serialization fails.  `point` is
/// attacker-influenced in some code paths, so neither case may panic.
pub(crate) fn try_cose_key(alg: CoseAlg, point: &Sec1Point) -> Result<Vec<u8>, CryptoError> {
    if point.is_identity() {
        return Err(CryptoError::InvalidPublicKey);
    }
    let x = point.x().ok_or(CryptoError::InvalidPublicKey)?;
    let y = point.y().ok_or(CryptoError::InvalidPublicKey)?;
    try_ec2_key(alg, CRV_P256, x, y)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::os_rng;
    use p256::elliptic_curve::Generate;

    #[test]
    fn try_cose_key_rejects_identity_point() {
        let identity = Sec1Point::identity();
        assert!(identity.is_identity());
        assert_eq!(
            try_cose_key(CoseAlg::ES256, &identity),
            Err(CryptoError::InvalidPublicKey)
        );
    }

    #[test]
    fn try_cose_key_rejects_point_without_y_coordinate() {
        let signing_key = SigningKey::generate_from_rng(&mut os_rng());
        // A compressed SEC1 encoding carries X but no Y.
        let compressed = signing_key.verifying_key().to_sec1_point(true);
        assert!(!compressed.is_identity());
        assert!(compressed.y().is_none());
        assert_eq!(
            try_cose_key(CoseAlg::ES256, &compressed),
            Err(CryptoError::InvalidPublicKey)
        );
    }
}
