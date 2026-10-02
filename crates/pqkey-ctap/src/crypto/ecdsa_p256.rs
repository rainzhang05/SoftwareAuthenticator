//! ES256 keys: ECDSA over P-256.

use ciborium::ser::into_writer;
use ciborium::value::{Integer, Value};
use p256::Sec1Point;

use super::CryptoError;
use super::alg::CoseAlg;
use super::cose::{COSE_KEY_LABEL_ALG, COSE_KEY_LABEL_KTY};

/// Build the CBOR COSE_Key for an ES256 (P-256) public key.
///
/// Returns [`CryptoError::InvalidPublicKey`] if `point` is the point at
/// infinity or is a compressed/short encoding without both affine coordinates,
/// and [`CryptoError::CborEncoding`] if serialization fails.  `point` is
/// attacker-influenced in some code paths, so neither case may panic.
pub fn try_cose_es256_public_key(point: &Sec1Point) -> Result<Vec<u8>, CryptoError> {
    if point.is_identity() {
        return Err(CryptoError::InvalidPublicKey);
    }
    let x = point.x().ok_or(CryptoError::InvalidPublicKey)?.to_vec();
    let y = point.y().ok_or(CryptoError::InvalidPublicKey)?.to_vec();
    let map = Value::Map(vec![
        (
            Value::Integer(Integer::from(COSE_KEY_LABEL_KTY)),
            Value::Integer(Integer::from(2)),
        ),
        (
            Value::Integer(Integer::from(COSE_KEY_LABEL_ALG)),
            Value::Integer(Integer::from(CoseAlg::ES256.identifier())),
        ),
        (
            Value::Integer(Integer::from(-1)),
            Value::Integer(Integer::from(1)),
        ),
        (Value::Integer(Integer::from(-2)), Value::Bytes(x)),
        (Value::Integer(Integer::from(-3)), Value::Bytes(y)),
    ]);
    let mut out = Vec::new();
    into_writer(&map, &mut out).map_err(|_| CryptoError::CborEncoding)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::os_rng;
    use p256::ecdsa::SigningKey as P256SigningKey;
    use p256::elliptic_curve::Generate;

    #[test]
    fn try_cose_es256_public_key_rejects_identity_point() {
        let identity = Sec1Point::identity();
        assert!(identity.is_identity());
        assert_eq!(
            try_cose_es256_public_key(&identity),
            Err(CryptoError::InvalidPublicKey)
        );
    }

    #[test]
    fn try_cose_es256_public_key_rejects_point_without_y_coordinate() {
        let signing_key = P256SigningKey::generate_from_rng(&mut os_rng());
        // A compressed SEC1 encoding carries X but no Y.
        let compressed = signing_key.verifying_key().to_sec1_point(true);
        assert!(!compressed.is_identity());
        assert!(compressed.y().is_none());
        assert_eq!(
            try_cose_es256_public_key(&compressed),
            Err(CryptoError::InvalidPublicKey)
        );
    }
}
