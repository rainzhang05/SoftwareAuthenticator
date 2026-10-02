//! A signature verifier for tests: is a COSE_Key the public key an algorithm
//! should have, and does a signature verify under it?
//!
//! It is the oracle the algorithm table is checked against, so it states what
//! it expects of each algorithm itself, from the specifications, instead of
//! reading the table or using the encoders.  It names nothing but the crate's
//! public API, through `crate::CoseAlg`, because pqkey-ctap's integration tests
//! compile this file too; the library builds it only for its own unit tests
//! and with the `test-support` feature, so the daemon leaves it out.

use core::fmt;

use ciborium::value::Value;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use pqkey_mldsa::{ParamSet, PublicKey};

use crate::CoseAlg;

/// Why [`verify_signature`] rejected a signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    /// The COSE_Key is not a public key of the algorithm; the text says how.
    MalformedKey(String),
    /// The signature does not verify under the key.
    BadSignature,
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerificationError::MalformedKey(reason) => write!(f, "malformed COSE_Key: {reason}"),
            VerificationError::BadSignature => f.write_str("the signature does not verify"),
        }
    }
}

impl std::error::Error for VerificationError {}

/// The public key and signatures of an algorithm.
enum Expected {
    /// An EC2 key (kty 2) on P-256 (crv 1) with 32-byte x and y coordinates,
    /// and ECDSA signatures with SHA-256, DER-encoded.
    EcdsaP256,
    /// An AKP key (kty 7) whose `pub` is an ML-DSA public key of `length`
    /// bytes, and ML-DSA signatures with `param_set` and an empty context.
    MlDsa { param_set: ParamSet, length: usize },
}

/// The COSE identifier of `alg` and what its keys and signatures are.  The
/// identifiers are IANA's (RFC 9964 §8.1 for ML-DSA), the ML-DSA public key
/// lengths FIPS 204's, Table 2.
fn expected(alg: CoseAlg) -> (i64, Expected) {
    match alg {
        CoseAlg::ES256 => (-7, Expected::EcdsaP256),
        CoseAlg::MLDSA44 => (
            -48,
            Expected::MlDsa {
                param_set: ParamSet::MLDSA44,
                length: 1312,
            },
        ),
        CoseAlg::MLDSA65 => (
            -49,
            Expected::MlDsa {
                param_set: ParamSet::MLDSA65,
                length: 1952,
            },
        ),
        CoseAlg::MLDSA87 => (
            -50,
            Expected::MlDsa {
                param_set: ParamSet::MLDSA87,
                length: 2592,
            },
        ),
    }
}

/// Check that `cose_key`, one CBOR COSE_Key, is a public key of `alg`, and
/// that `signature` is `alg`'s signature over `message` under it.
///
/// The key must have the labels its key type requires and no others: "The
/// COSE_Key-encoded credential public key MUST contain the "alg" parameter
/// and MUST NOT contain any other OPTIONAL parameters." (WebAuthn Level 3
/// §6.5.1)  For ES256, "Keys with algorithm -7 (ES256) MUST specify 1
/// (P-256) as the crv parameter and MUST NOT use the compressed point form."
/// (§5.8.5): x and y are 32 bytes each and form a point on the curve.  For
/// ML-DSA, `pub` has the length of the parameter set's public key.
pub fn verify_signature(
    alg: CoseAlg,
    cose_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerificationError> {
    let (identifier, expected) = expected(alg);
    let key = Labels::decode(cose_key)?;
    match expected {
        Expected::EcdsaP256 => {
            key.exactly(&[1, 3, -1, -2, -3])?;
            key.integer(1, 2)?;
            key.integer(3, identifier)?;
            key.integer(-1, 1)?;
            let mut point = vec![0x04];
            point.extend_from_slice(key.bytes(-2, 32)?);
            point.extend_from_slice(key.bytes(-3, 32)?);
            let verifying_key = VerifyingKey::from_sec1_bytes(&point)
                .map_err(|_| malformed("x and y are not a point on P-256".into()))?;
            let signature =
                Signature::from_der(signature).map_err(|_| VerificationError::BadSignature)?;
            verifying_key
                .verify(message, &signature)
                .map_err(|_| VerificationError::BadSignature)
        }
        Expected::MlDsa { param_set, length } => {
            key.exactly(&[1, 3, -1])?;
            key.integer(1, 7)?;
            key.integer(3, identifier)?;
            let public_key = PublicKey::new(key.bytes(-1, length)?.to_vec());
            if pqkey_mldsa::verify(param_set, &public_key, message, signature) {
                Ok(())
            } else {
                Err(VerificationError::BadSignature)
            }
        }
    }
}

fn malformed(reason: String) -> VerificationError {
    VerificationError::MalformedKey(reason)
}

/// The entries of a COSE_Key, by integer label.
struct Labels(Vec<(i128, Value)>);

impl Labels {
    /// `cose_key` as one CBOR map with integer labels and nothing after it.
    fn decode(cose_key: &[u8]) -> Result<Self, VerificationError> {
        let mut rest = cose_key;
        let value: Value =
            ciborium::de::from_reader(&mut rest).map_err(|_| malformed("not CBOR".into()))?;
        if !rest.is_empty() {
            return Err(malformed(format!("{} bytes after the map", rest.len())));
        }
        let Value::Map(entries) = value else {
            return Err(malformed("not a map".into()));
        };
        let mut labels = Vec::with_capacity(entries.len());
        for (label, value) in entries {
            let Value::Integer(label) = label else {
                return Err(malformed(format!("label {label:?} is not an integer")));
            };
            labels.push((i128::from(label), value));
        }
        Ok(Labels(labels))
    }

    /// The labels are `wanted`, each once, and no others.
    fn exactly(&self, wanted: &[i128]) -> Result<(), VerificationError> {
        let mut found: Vec<i128> = self.0.iter().map(|(label, _)| *label).collect();
        found.sort_unstable();
        let mut wanted = wanted.to_vec();
        wanted.sort_unstable();
        if found == wanted {
            Ok(())
        } else {
            Err(malformed(format!("labels {found:?}, not {wanted:?}")))
        }
    }

    fn get(&self, label: i128) -> Option<&Value> {
        self.0
            .iter()
            .find(|(found, _)| *found == label)
            .map(|(_, value)| value)
    }

    /// Label `label` is the integer `wanted`.
    fn integer(&self, label: i128, wanted: i64) -> Result<(), VerificationError> {
        match self.get(label) {
            Some(Value::Integer(value)) if i128::from(*value) == i128::from(wanted) => Ok(()),
            other => Err(malformed(format!(
                "label {label} is {other:?}, not {wanted}"
            ))),
        }
    }

    /// Label `label` is a byte string of `length` bytes.
    fn bytes(&self, label: i128, length: usize) -> Result<&[u8], VerificationError> {
        match self.get(label) {
            Some(Value::Bytes(bytes)) if bytes.len() == length => Ok(bytes),
            Some(Value::Bytes(bytes)) => Err(malformed(format!(
                "label {label} is {} bytes, not {length}",
                bytes.len()
            ))),
            other => Err(malformed(format!(
                "label {label} is {other:?}, not a byte string"
            ))),
        }
    }
}
