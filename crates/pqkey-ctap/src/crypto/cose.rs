//! COSE_Key encoding (RFC 9052 §7) of the four key types the authenticator's
//! public keys take: EC2, OKP, AKP and RSA.  The algorithm, and for EC2 and OKP
//! the curve, are inputs, so no encoder states an algorithm of its own.

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
/// Curve 3, P-521 (RFC 9053 §7.1).
pub(crate) const CRV_P521: i32 = 3;
/// Curve 8, secp256k1 (RFC 8812 §3.1).
pub(crate) const CRV_SECP256K1: i32 = 8;

/// Key type 1, OKP: an Octet Key Pair, whose public key is one byte string
/// (RFC 9053 §7.2).
const KTY_OKP: i32 = 1;
/// OKP label -1, the curve (RFC 9053 §7.2).
const LABEL_OKP_CRV: i32 = -1;
/// OKP label -2, x: "the public key as defined by the algorithm" (RFC 9053
/// §7.2).
const LABEL_OKP_X: i32 = -2;
/// Curve 6, Ed25519, "for use w/ EdDSA only" (RFC 9053 §7.1).
pub(crate) const CRV_ED25519: i32 = 6;
/// Curve 7, Ed448, "for use w/ EdDSA only" (RFC 9053 §7.1).
pub(crate) const CRV_ED448: i32 = 7;

/// Key type 7, AKP: an Algorithm Key Pair, whose algorithm determines its
/// format (RFC 9964).
const KTY_AKP: i32 = 7;
/// AKP label -1, `pub`: the public key bytes (RFC 9964).
const LABEL_AKP_PUB: i32 = -1;

/// Key type 3, RSA: a modulus and a public exponent, each an unsigned
/// big-endian byte string in the fewest bytes (RFC 8230 §4).
const KTY_RSA: i32 = 3;
/// RSA label -1, n: the modulus (RFC 8230 §4).
const LABEL_RSA_N: i32 = -1;
/// RSA label -2, e: the public exponent (RFC 8230 §4).
const LABEL_RSA_E: i32 = -2;
/// The public exponent of every RSA key the authenticator makes, 65537.
const RSA_E: [u8; 3] = [0x01, 0x00, 0x01];

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

/// The COSE_Key map of the OKP public key `x` on curve `crv` for `alg`, in
/// canonical order.
fn okp_key_map(alg: CoseAlg, crv: i32, x: &[u8]) -> Value {
    Value::Map(vec![
        (int(LABEL_KTY), int(KTY_OKP)),
        (int(LABEL_ALG), int(alg.identifier())),
        (int(LABEL_OKP_CRV), int(crv)),
        (int(LABEL_OKP_X), Value::Bytes(x.to_vec())),
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

/// The COSE_Key map of the RSA public key with modulus `n` and exponent
/// 65537 for `alg`, in canonical order.
fn rsa_key_map(alg: CoseAlg, n: &[u8]) -> Value {
    Value::Map(vec![
        (int(LABEL_KTY), int(KTY_RSA)),
        (int(LABEL_ALG), int(alg.identifier())),
        (int(LABEL_RSA_N), Value::Bytes(n.to_vec())),
        (int(LABEL_RSA_E), Value::Bytes(RSA_E.to_vec())),
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

/// [`okp_key_map`], encoded.  Returns [`CryptoError::CborEncoding`] if
/// serialization fails.
pub(crate) fn try_okp_key(alg: CoseAlg, crv: i32, x: &[u8]) -> Result<Vec<u8>, CryptoError> {
    encode(&okp_key_map(alg, crv, x))
}

/// [`akp_key_map`], encoded.  Returns [`CryptoError::CborEncoding`] if
/// serialization fails.
pub(crate) fn try_akp_key(alg: CoseAlg, public_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    encode(&akp_key_map(alg, public_key))
}

/// [`rsa_key_map`], encoded.  Returns [`CryptoError::CborEncoding`] if
/// serialization fails.
pub(crate) fn try_rsa_key(alg: CoseAlg, n: &[u8]) -> Result<Vec<u8>, CryptoError> {
    encode(&rsa_key_map(alg, n))
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

    /// An OKP key is a map of kty 1, alg, crv and x, in that order, each label
    /// and integer in one byte.
    #[test]
    fn okp_public_key_canonical_encoding_matches_fixture() {
        let x = [0xAB; 32];
        let cose = try_okp_key(CoseAlg::EdDSA, CRV_ED25519, &x).expect("encode COSE key");
        let expected = [
            [0xA4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20].as_slice(),
            &x,
        ]
        .concat();
        assert_eq!(cose, expected);
        let decoded: Value = from_reader(cose.as_slice()).expect("valid COSE public key");
        assert_eq!(decoded, okp_key_map(CoseAlg::EdDSA, CRV_ED25519, &x));
    }
}
