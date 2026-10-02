//! COSE_Key encoding (RFC 9052 §7) of the two key types the authenticator's
//! public keys take: EC2 and AKP.  The algorithm, and for EC2 the curve, are
//! inputs, so no encoder states an algorithm of its own.

use ciborium::ser::into_writer;
use ciborium::value::{Integer, Value};

use super::CryptoError;
use super::alg::CoseAlg;

/// COSE_Key label 1, the key type (RFC 9052 §7.1).
const LABEL_KTY: i32 = 1;
/// COSE_Key label 3, the algorithm (RFC 9052 §7.1).
const LABEL_ALG: i32 = 3;

/// Key type 2, EC2: an elliptic curve point with both coordinates (RFC 9053
/// §7.1.1).
const KTY_EC2: i32 = 2;
/// EC2 label -1, the curve (RFC 9053 §7.1.1).
const LABEL_EC2_CRV: i32 = -1;
/// EC2 label -2, the x coordinate (RFC 9053 §7.1.1).
const LABEL_EC2_X: i32 = -2;
/// EC2 label -3, the y coordinate (RFC 9053 §7.1.1).
const LABEL_EC2_Y: i32 = -3;
/// Curve 1, P-256 (RFC 9053 §7.1).
pub(crate) const CRV_P256: i32 = 1;
/// Curve 2, P-384 (RFC 9053 §7.1).
pub(crate) const CRV_P384: i32 = 2;

/// Key type 7, AKP: an Algorithm Key Pair, whose algorithm determines its
/// format (RFC 9964).
const KTY_AKP: i32 = 7;
/// AKP label -1, `pub`: the public key bytes (RFC 9964).
const LABEL_AKP_PUB: i32 = -1;

/// The COSE_Key map of the EC2 public key (`x`, `y`) on curve `crv` for
/// `alg`, in canonical order.
fn ec2_key_map(alg: CoseAlg, crv: i32, x: &[u8], y: &[u8]) -> Value {
    Value::Map(vec![
        (int(LABEL_KTY), int(KTY_EC2)),
        (int(LABEL_ALG), int(alg.identifier())),
        (int(LABEL_EC2_CRV), int(crv)),
        (int(LABEL_EC2_X), Value::Bytes(x.to_vec())),
        (int(LABEL_EC2_Y), Value::Bytes(y.to_vec())),
    ])
}

/// The COSE_Key map of the AKP public key `public_key` for `alg`, in
/// canonical order.
fn akp_key_map(alg: CoseAlg, public_key: &[u8]) -> Value {
    Value::Map(vec![
        (int(LABEL_KTY), int(KTY_AKP)),
        (int(LABEL_ALG), int(alg.identifier())),
        (int(LABEL_AKP_PUB), Value::Bytes(public_key.to_vec())),
    ])
}

/// [`ec2_key_map`], encoded.  Returns [`CryptoError::CborEncoding`] if
/// serialization fails.
pub(crate) fn try_ec2_key(
    alg: CoseAlg,
    crv: i32,
    x: &[u8],
    y: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    encode(&ec2_key_map(alg, crv, x, y))
}

/// [`akp_key_map`], encoded.  Returns [`CryptoError::CborEncoding`] if
/// serialization fails.
pub(crate) fn try_akp_key(alg: CoseAlg, public_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    encode(&akp_key_map(alg, public_key))
}

fn encode(map: &Value) -> Result<Vec<u8>, CryptoError> {
    let mut out = Vec::new();
    into_writer(map, &mut out).map_err(|_| CryptoError::CborEncoding)?;
    Ok(out)
}

fn int(value: i32) -> Value {
    Value::Integer(Integer::from(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::de::from_reader;

    #[test]
    fn cose_public_key_canonical_encoding_matches_fixture() {
        let pk_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let cose = try_akp_key(CoseAlg::MLDSA44, &pk_bytes).expect("encode COSE key");
        let expected = vec![
            0xA3, 0x01, 0x07, 0x03, 0x38, 0x2F, 0x20, 0x44, 0xDE, 0xAD, 0xBE, 0xEF,
        ];
        assert_eq!(cose, expected);
        let decoded: Value = from_reader(cose.as_slice()).expect("valid COSE public key");
        assert_eq!(decoded, akp_key_map(CoseAlg::MLDSA44, &pk_bytes));
    }
}
