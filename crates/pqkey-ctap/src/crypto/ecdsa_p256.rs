//! ES256 keys: ECDSA over P-256.

use p256::Sec1Point;

use super::CryptoError;
use super::alg::CoseAlg;
use super::cose::{CRV_P256, try_ec2_key};

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
    use p256::ecdsa::SigningKey as P256SigningKey;
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
        let signing_key = P256SigningKey::generate_from_rng(&mut os_rng());
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
