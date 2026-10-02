//! COSE_Key encoding (RFC 9052 §7).

use ciborium::value::{Integer, Value};

/// COSE key type value assigned to Algorithm Key Pairs (AKP).
pub const COSE_KEY_TYPE_AKP: i32 = 7;

/// COSE_Key label 1, the key type (RFC 9052 §7.1).
pub const COSE_KEY_LABEL_KTY: i32 = 1;
/// COSE_Key label 3, the algorithm (RFC 9052 §7.1).
pub const COSE_KEY_LABEL_ALG: i32 = 3;
/// COSE_Key label -1 of an Algorithm Key Pair: the public key bytes.
pub const COSE_KEY_PARAM_AKP_KEY: i32 = -1;

/// Build a COSE_Key map for an AKP public key using canonical ordering.
pub(crate) fn cose_akp_key_map(alg_id: i32, public_key: &[u8]) -> Value {
    Value::Map(vec![
        (
            Value::Integer(Integer::from(COSE_KEY_LABEL_KTY)),
            Value::Integer(Integer::from(COSE_KEY_TYPE_AKP)),
        ),
        (
            Value::Integer(Integer::from(COSE_KEY_LABEL_ALG)),
            Value::Integer(Integer::from(alg_id)),
        ),
        (
            Value::Integer(Integer::from(COSE_KEY_PARAM_AKP_KEY)),
            Value::Bytes(public_key.to_vec()),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::alg::CoseAlg;
    use crate::crypto::mldsa::try_cose_public_key;
    use ciborium::de::from_reader;
    use pqkey_mldsa::{ParamSet, PublicKey};

    #[test]
    fn cose_public_key_canonical_encoding_matches_fixture() {
        let pk_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let pk = PublicKey(pk_bytes.clone());
        let cose = try_cose_public_key(ParamSet::MLDSA44, &pk).expect("encode COSE key");
        let expected = vec![
            0xA3, 0x01, 0x07, 0x03, 0x38, 0x2F, 0x20, 0x44, 0xDE, 0xAD, 0xBE, 0xEF,
        ];
        assert_eq!(cose, expected);
        let decoded: Value = from_reader(cose.as_slice()).expect("valid COSE public key");
        assert_eq!(
            decoded,
            cose_akp_key_map(CoseAlg::MLDSA44 as i32, &pk_bytes)
        );
    }
}
