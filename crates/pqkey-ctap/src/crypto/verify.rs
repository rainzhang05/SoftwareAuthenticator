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
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use pqkey_mldsa::{ParamSet, PublicKey};
use sha2::{Digest, Sha256, Sha384, Sha512};

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
    /// An EC2 key (kty 2) on curve `crv`, whose x and y coordinates are
    /// `length` bytes each, and ECDSA signatures over the message's `hash`,
    /// DER-encoded, which `curve` checks.
    Ecdsa {
        crv: i64,
        length: usize,
        curve: EcCurve,
        hash: Hash,
    },
    /// An OKP key (kty 1) on curve `crv`, whose x is `length` bytes, and pure
    /// EdDSA signatures as RFC 8032 encodes them, which `curve` checks.
    EdDsa {
        crv: i64,
        length: usize,
        curve: EdCurve,
    },
    /// An AKP key (kty 7) whose `pub` is an ML-DSA public key of `length`
    /// bytes, and ML-DSA signatures with `param_set` and an empty context.
    MlDsa { param_set: ParamSet, length: usize },
}

/// The elliptic curves of the ECDSA algorithms.
enum EcCurve {
    P256,
    P384,
    P521,
    Secp256k1,
}

/// The curves of the EdDSA algorithms.
enum EdCurve {
    Ed25519,
    Ed448,
}

/// The hashes ECDSA signs a message's digest of.
enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

/// The COSE identifier of `alg` and what its keys and signatures are.  The
/// identifiers are IANA's (RFC 9053 §2.1 for ES256, ES384 and ES512, RFC 9864
/// §2.1 for ESP256, ESP384 and ESP512, RFC 8812 §3.2 for ES256K, RFC 9053 §2.2
/// for EdDSA, RFC 9864 §2.2 for Ed25519 and Ed448, RFC 9964 §8.1 for ML-DSA),
/// and so are the curves (RFC 9053 §7.1, RFC 8812 §3.1 for secp256k1).  An
/// ECDSA coordinate is as long as the curve's field elements, an EdDSA public
/// key as RFC 8032 encodes it (32 bytes for Ed25519, §5.1.5, and 57 for Ed448,
/// §5.2.5), an ML-DSA public key as FIPS 204's Table 2 says.
fn expected(alg: CoseAlg) -> (i64, Expected) {
    let p256_sha256 = Expected::Ecdsa {
        crv: 1,
        length: 32,
        curve: EcCurve::P256,
        hash: Hash::Sha256,
    };
    let p384_sha384 = Expected::Ecdsa {
        crv: 2,
        length: 48,
        curve: EcCurve::P384,
        hash: Hash::Sha384,
    };
    let p521_sha512 = Expected::Ecdsa {
        crv: 3,
        length: 66,
        curve: EcCurve::P521,
        hash: Hash::Sha512,
    };
    let ed25519 = Expected::EdDsa {
        crv: 6,
        length: 32,
        curve: EdCurve::Ed25519,
    };
    match alg {
        CoseAlg::ES256 => (-7, p256_sha256),
        CoseAlg::ESP256 => (-9, p256_sha256),
        CoseAlg::ES384 => (-35, p384_sha384),
        CoseAlg::ESP384 => (-51, p384_sha384),
        CoseAlg::ES512 => (-36, p521_sha512),
        CoseAlg::ESP512 => (-52, p521_sha512),
        CoseAlg::ES256K => (
            -47,
            Expected::Ecdsa {
                crv: 8,
                length: 32,
                curve: EcCurve::Secp256k1,
                hash: Hash::Sha256,
            },
        ),
        CoseAlg::EdDSA => (-8, ed25519),
        CoseAlg::Ed25519 => (-19, ed25519),
        CoseAlg::Ed448 => (
            -53,
            Expected::EdDsa {
                crv: 7,
                length: 57,
                curve: EdCurve::Ed448,
            },
        ),
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
/// §6.5.1)  For ECDSA, "Keys with algorithm -7 (ES256) MUST specify 1
/// (P-256) as the crv parameter and MUST NOT use the compressed point form.
/// Keys with algorithm -9 (ESP256) MUST NOT use the compressed point form.
/// Keys with algorithm -35 (ES384) MUST specify 2 (P-384) as the crv
/// parameter and MUST NOT use the compressed point form.  Keys with algorithm
/// -51 (ESP384) MUST NOT use the compressed point form.  Keys with algorithm
/// -36 (ES512) MUST specify 3 (P-521) as the crv parameter and MUST NOT use
/// the compressed point form.  Keys with algorithm -52 (ESP512) MUST NOT use
/// the compressed point form." (§5.8.5)  ESP256 is "ECDSA using P-256 curve
/// and SHA-256", and ESP384 and ESP512 the same with P-384 and SHA-384 and
/// with P-521 and SHA-512 (RFC 9864 §2.1).  ES256K is ECDSA using secp256k1
/// and SHA-256, and "Implementations need to check that the key type is
/// "EC" for JOSE or "EC2" (2) for COSE and that the curve of the key is
/// secp256k1 when creating or verifying a signature." (RFC 8812 §3.2)
/// So x and y are as long as the curve's field elements and form a point on
/// it, and "the sig value MUST be encoded as an ASN.1 DER Ecdsa-Sig-Value"
/// (§6.5.5) over the message's digest with the algorithm's hash, which this
/// verifier computes itself.  For EdDSA, "The "kty" field MUST be present, and
/// it MUST be "OKP" (Octet Key Pair).  The "crv" field MUST be present, and it
/// MUST be a curve defined for this signature algorithm." (RFC 9053 §2.2), and
/// "Keys with algorithm -8 (EdDSA) MUST specify 6 (Ed25519) as the crv
/// parameter." (WebAuthn Level 3 §5.8.5)  Ed25519 is "EdDSA using the Ed25519
/// parameter set" (RFC 9864 §2.2), so its keys are on Ed25519 too: "Within
/// WebAuthn, the values [...] -19 (Ed25519) represent the same thing
/// respectively as [...] -8 (EdDSA)" (WebAuthn Level 3 §5.4).  Ed448 is "EdDSA
/// using the Ed448 parameter set" (RFC 9864 §2.2), with an empty context, as
/// COSE gives none.  An OKP key's "x" "contains the public key as defined by
/// the algorithm" (RFC 9053 §7.2), so it is as long as RFC 8032 encodes the
/// curve's public keys and decodes to a point on it, and "\[RFC8032\] describes
/// the method of encoding the signature value." (RFC 9053 §2.2): the signature
/// is RFC 8032's R ‖ S, never DER.  For ML-DSA, `pub` has the length of the
/// parameter set's public key.
pub fn verify_signature(
    alg: CoseAlg,
    cose_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerificationError> {
    let (identifier, expected) = expected(alg);
    let key = Labels::decode(cose_key)?;
    match expected {
        Expected::Ecdsa {
            crv,
            length,
            curve,
            hash,
        } => {
            key.exactly(&[1, 3, -1, -2, -3])?;
            key.integer(1, 2)?;
            key.integer(3, identifier)?;
            key.integer(-1, crv)?;
            let mut point = vec![0x04];
            point.extend_from_slice(key.bytes(-2, length)?);
            point.extend_from_slice(key.bytes(-3, length)?);
            let digest = match hash {
                Hash::Sha256 => Sha256::digest(message).to_vec(),
                Hash::Sha384 => Sha384::digest(message).to_vec(),
                Hash::Sha512 => Sha512::digest(message).to_vec(),
            };
            verify_ecdsa(curve, &point, &digest, signature)
        }
        Expected::EdDsa { crv, length, curve } => {
            key.exactly(&[1, 3, -1, -2])?;
            key.integer(1, 1)?;
            key.integer(3, identifier)?;
            key.integer(-1, crv)?;
            verify_eddsa(curve, key.bytes(-2, length)?, message, signature)
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

/// Check the DER `signature` over `digest` under the SEC1 `point` on
/// `curve`.  A point off the curve is a malformed key.
fn verify_ecdsa(
    curve: EcCurve,
    point: &[u8],
    digest: &[u8],
    signature: &[u8],
) -> Result<(), VerificationError> {
    let verified = match curve {
        EcCurve::P256 => {
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
                .map_err(|_| malformed("x and y are not a point on P-256".into()))?;
            p256::ecdsa::Signature::from_der(signature)
                .is_ok_and(|signature| key.verify_prehash(digest, &signature).is_ok())
        }
        EcCurve::P384 => {
            let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(point)
                .map_err(|_| malformed("x and y are not a point on P-384".into()))?;
            p384::ecdsa::Signature::from_der(signature)
                .is_ok_and(|signature| key.verify_prehash(digest, &signature).is_ok())
        }
        EcCurve::P521 => {
            let key = p521::ecdsa::VerifyingKey::from_sec1_bytes(point)
                .map_err(|_| malformed("x and y are not a point on P-521".into()))?;
            p521::ecdsa::Signature::from_der(signature)
                .is_ok_and(|signature| key.verify_prehash(digest, &signature).is_ok())
        }
        // `k256` accepts only signatures whose s is in the lower half of the
        // group order, a rule of Bitcoin's that ECDSA does not have, so s is
        // normalized first.
        EcCurve::Secp256k1 => {
            let key = k256::ecdsa::VerifyingKey::from_sec1_bytes(point)
                .map_err(|_| malformed("x and y are not a point on secp256k1".into()))?;
            k256::ecdsa::Signature::from_der(signature)
                .is_ok_and(|signature| key.verify_prehash(digest, &signature.normalize_s()).is_ok())
        }
    };
    if verified {
        Ok(())
    } else {
        Err(VerificationError::BadSignature)
    }
}

/// Check the pure EdDSA `signature` over `message` under the public key on
/// `curve` whose RFC 8032 encoding is `x`.  An `x` that decodes to no point
/// on the curve is a malformed key.
fn verify_eddsa(
    curve: EdCurve,
    x: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerificationError> {
    let verified = match curve {
        // Strict verification also rejects a small-order public key or R,
        // which RFC 8032 §5.1.7 accepts; the authenticator makes neither.
        EdCurve::Ed25519 => {
            let key = <&[u8; 32]>::try_from(x)
                .ok()
                .and_then(|x| ed25519_dalek::VerifyingKey::from_bytes(x).ok())
                .ok_or_else(|| malformed("x is not a point on Ed25519".into()))?;
            ed25519_dalek::Signature::from_slice(signature)
                .is_ok_and(|signature| key.verify_strict(message, &signature).is_ok())
        }
        EdCurve::Ed448 => {
            let key = <&[u8; 57]>::try_from(x)
                .ok()
                .and_then(|x| ed448_goldilocks::VerifyingKey::from_bytes(x).ok())
                .ok_or_else(|| malformed("x is not a point on Ed448".into()))?;
            ed448_goldilocks::Signature::try_from(signature)
                .is_ok_and(|signature| key.verify_ctx(&signature, &[], message).is_ok())
        }
    };
    if verified {
        Ok(())
    } else {
        Err(VerificationError::BadSignature)
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
