//! The COSE algorithms the authenticator signs with, and what it knows about
//! each of them: one table, [`CoseAlg::properties`], with a row per
//! algorithm, and [`CoseAlg::ALL`], the order getInfo lists them in.

use core::fmt;
use pqkey_mldsa::ParamSet;

use super::ecdsa::Curve;

/// The COSE algorithm identifiers this authenticator signs with: ES256 (-7,
/// RFC 9053 §2.1); the three ML-DSA parameter sets, which RFC 9964 §8.1
/// registered in the IANA "COSE Algorithms" registry as -48, -49 and -50;
/// ES384 (-35) and ES512 (-36, RFC 9053 §2.1); and ESP256 (-9), ESP384 (-51)
/// and ESP512 (-52), the fully specified identifiers of ECDSA using P-256 and
/// SHA-256, P-384 and SHA-384, and P-521 and SHA-512 (RFC 9864 §2.1); and
/// ES256K (-47), ECDSA using secp256k1 and SHA-256 (RFC 8812 §3.2).
///
/// Each variant's discriminant is its identifier, which
/// [`CoseAlg::identifier`] returns; [`CoseAlg::ALL`] lists every variant.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CoseAlg {
    /// ECDSA with P-256 and SHA-256.
    ES256 = -7,
    /// ML-DSA-44.
    MLDSA44 = -48,
    /// ML-DSA-65.
    MLDSA65 = -49,
    /// ML-DSA-87.
    MLDSA87 = -50,
    /// ECDSA with P-256 and SHA-256, as ES256, under its fully specified
    /// identifier.
    ESP256 = -9,
    /// ECDSA with P-384 and SHA-384.
    ES384 = -35,
    /// ECDSA with P-384 and SHA-384, as ES384, under its fully specified
    /// identifier.
    ESP384 = -51,
    /// ECDSA with P-521 and SHA-512.
    ES512 = -36,
    /// ECDSA with P-521 and SHA-512, as ES512, under its fully specified
    /// identifier.
    ESP512 = -52,
    /// ECDSA with secp256k1 and SHA-256.
    ES256K = -47,
}

/// The kind of private key material a credential keeps.  Each algorithm
/// keeps one kind, [`CoseAlg::key_kind`]; algorithms with the same signature
/// scheme keep the same kind.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum KeyKind {
    /// A P-256 private scalar, the key of ES256 and ESP256: 32 bytes,
    /// big-endian, non-zero and below the group order.
    P256Scalar,
    /// A 32-byte seed from which the credential's algorithm derives its key:
    /// for ML-DSA, the FIPS 204 key-generation seed `ξ`, and for ECDSA on
    /// P-384, P-521 and secp256k1, the seed its scalar is derived from by
    /// FIPS 186-5 Appendix A.2.1, with SHAKE256 in place of the random bit
    /// generator.
    Seed,
}

/// The signature scheme behind an algorithm.  It picks the family that reads
/// the key, derives the public key and signs: [`super::ecdsa`] or
/// [`super::mldsa`].  Algorithms that differ only in their identifier share a
/// scheme.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum Scheme {
    /// ECDSA over this curve with the curve's hash, the signature
    /// DER-encoded.
    Ecdsa(Curve),
    /// ML-DSA with this parameter set (FIPS 204).
    MlDsa(ParamSet),
}

impl Scheme {
    /// The kind of key material the scheme's keys are kept as.
    const fn key_kind(self) -> KeyKind {
        match self {
            Scheme::Ecdsa(Curve::P256) => KeyKind::P256Scalar,
            Scheme::Ecdsa(Curve::P384 | Curve::P521 | Curve::Secp256k1) | Scheme::MlDsa(_) => {
                KeyKind::Seed
            }
        }
    }
}

/// What the authenticator knows about an algorithm: its row in the table.
struct Properties {
    /// The algorithm's name, as `pqkey passkeys` prints it.
    name: &'static str,
    /// How the algorithm signs.
    scheme: Scheme,
}

impl CoseAlg {
    /// Every algorithm, in the order authenticatorGetInfo lists them (CTAP 2.3
    /// §6.4, `algorithms`).
    pub const ALL: [CoseAlg; 10] = [
        CoseAlg::ES256,
        CoseAlg::MLDSA44,
        CoseAlg::MLDSA65,
        CoseAlg::MLDSA87,
        CoseAlg::ESP256,
        CoseAlg::ES384,
        CoseAlg::ESP384,
        CoseAlg::ES512,
        CoseAlg::ESP512,
        CoseAlg::ES256K,
    ];

    /// The table: what the authenticator knows about each algorithm.
    const fn properties(self) -> Properties {
        match self {
            CoseAlg::ES256 => Properties {
                name: "ES256",
                scheme: Scheme::Ecdsa(Curve::P256),
            },
            CoseAlg::MLDSA44 => Properties {
                name: "ML-DSA-44",
                scheme: Scheme::MlDsa(ParamSet::MLDSA44),
            },
            CoseAlg::MLDSA65 => Properties {
                name: "ML-DSA-65",
                scheme: Scheme::MlDsa(ParamSet::MLDSA65),
            },
            CoseAlg::MLDSA87 => Properties {
                name: "ML-DSA-87",
                scheme: Scheme::MlDsa(ParamSet::MLDSA87),
            },
            CoseAlg::ESP256 => Properties {
                name: "ESP256",
                scheme: Scheme::Ecdsa(Curve::P256),
            },
            CoseAlg::ES384 => Properties {
                name: "ES384",
                scheme: Scheme::Ecdsa(Curve::P384),
            },
            CoseAlg::ESP384 => Properties {
                name: "ESP384",
                scheme: Scheme::Ecdsa(Curve::P384),
            },
            CoseAlg::ES512 => Properties {
                name: "ES512",
                scheme: Scheme::Ecdsa(Curve::P521),
            },
            CoseAlg::ESP512 => Properties {
                name: "ESP512",
                scheme: Scheme::Ecdsa(Curve::P521),
            },
            CoseAlg::ES256K => Properties {
                name: "ES256K",
                scheme: Scheme::Ecdsa(Curve::Secp256k1),
            },
        }
    }

    /// The algorithm's COSE identifier.
    pub const fn identifier(self) -> i32 {
        self as i32
    }

    /// The algorithm's name, such as "ML-DSA-65".
    pub const fn name(self) -> &'static str {
        self.properties().name
    }

    /// How the algorithm signs.
    pub(crate) const fn scheme(self) -> Scheme {
        self.properties().scheme
    }

    /// The kind of private key material the algorithm's credentials keep.
    pub const fn key_kind(self) -> KeyKind {
        self.scheme().key_kind()
    }
}

/// A COSE algorithm identifier that is not one of the [`CoseAlg`] values; it
/// carries the identifier.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct UnsupportedCoseAlg(pub i32);

impl fmt::Display for UnsupportedCoseAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unsupported COSE algorithm {}", self.0)
    }
}

impl std::error::Error for UnsupportedCoseAlg {}

impl TryFrom<i32> for CoseAlg {
    type Error = UnsupportedCoseAlg;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        CoseAlg::ALL
            .into_iter()
            .find(|alg| alg.identifier() == value)
            .ok_or(UnsupportedCoseAlg(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The identifiers are IANA's and the names are what `pqkey passkeys`
    /// prints, so both are spelled out here rather than read from the table.
    #[test]
    fn the_table_holds_the_registered_identifiers_and_the_printed_names() {
        let table: Vec<(i32, &str)> = CoseAlg::ALL
            .into_iter()
            .map(|alg| (alg.identifier(), alg.name()))
            .collect();
        assert_eq!(
            table,
            [
                (-7, "ES256"),
                (-48, "ML-DSA-44"),
                (-49, "ML-DSA-65"),
                (-50, "ML-DSA-87"),
                (-9, "ESP256"),
                (-35, "ES384"),
                (-51, "ESP384"),
                (-36, "ES512"),
                (-52, "ESP512"),
                (-47, "ES256K"),
            ]
        );
    }

    /// ES256 and ESP256 are ECDSA over P-256 with SHA-256, ES384 and ESP384
    /// over P-384 with SHA-384, and ES512 and ESP512 over P-521 with SHA-512
    /// (RFC 9053 §2.1, RFC 9864 §2.1), ES256K over secp256k1 with SHA-256
    /// (RFC 8812 §3.2), and each ML-DSA identifier names its own parameter
    /// set (RFC 9964 §8.1).
    #[test]
    fn each_algorithm_signs_with_its_scheme() {
        let schemes: Vec<Scheme> = CoseAlg::ALL.into_iter().map(CoseAlg::scheme).collect();
        assert_eq!(
            schemes,
            [
                Scheme::Ecdsa(Curve::P256),
                Scheme::MlDsa(ParamSet::MLDSA44),
                Scheme::MlDsa(ParamSet::MLDSA65),
                Scheme::MlDsa(ParamSet::MLDSA87),
                Scheme::Ecdsa(Curve::P256),
                Scheme::Ecdsa(Curve::P384),
                Scheme::Ecdsa(Curve::P384),
                Scheme::Ecdsa(Curve::P521),
                Scheme::Ecdsa(Curve::P521),
                Scheme::Ecdsa(Curve::Secp256k1),
            ]
        );
    }

    /// ES256 and ESP256 keep the P-256 scalar, ML-DSA the seed `ξ`, and ES384,
    /// ESP384, ES512, ESP512 and ES256K the seed their scalar is derived from:
    /// what the store and sealed credential IDs hold.
    #[test]
    fn each_algorithm_keeps_its_kind_of_key() {
        let kinds: Vec<KeyKind> = CoseAlg::ALL.into_iter().map(CoseAlg::key_kind).collect();
        assert_eq!(
            kinds,
            [
                KeyKind::P256Scalar,
                KeyKind::Seed,
                KeyKind::Seed,
                KeyKind::Seed,
                KeyKind::P256Scalar,
                KeyKind::Seed,
                KeyKind::Seed,
                KeyKind::Seed,
                KeyKind::Seed,
                KeyKind::Seed,
            ]
        );
    }

    /// Exactly the identifiers of the table parse.  `CoseAlg` only carries
    /// supported identifiers, so this is the boundary that keeps others out.
    #[test]
    fn only_the_identifiers_of_the_table_parse() {
        for alg in CoseAlg::ALL {
            assert_eq!(CoseAlg::try_from(alg.identifier()), Ok(alg));
        }
        assert_eq!(CoseAlg::try_from(-257), Err(UnsupportedCoseAlg(-257)));
        assert_eq!(CoseAlg::try_from(-8), Err(UnsupportedCoseAlg(-8)));
        assert_eq!(CoseAlg::try_from(-7), Ok(CoseAlg::ES256));
        assert_eq!(CoseAlg::try_from(-48), Ok(CoseAlg::MLDSA44));
        assert_eq!(CoseAlg::try_from(-49), Ok(CoseAlg::MLDSA65));
        assert_eq!(CoseAlg::try_from(-50), Ok(CoseAlg::MLDSA87));
        assert_eq!(CoseAlg::try_from(-9), Ok(CoseAlg::ESP256));
        assert_eq!(CoseAlg::try_from(-35), Ok(CoseAlg::ES384));
        assert_eq!(CoseAlg::try_from(-51), Ok(CoseAlg::ESP384));
        assert_eq!(CoseAlg::try_from(-36), Ok(CoseAlg::ES512));
        assert_eq!(CoseAlg::try_from(-52), Ok(CoseAlg::ESP512));
        assert_eq!(CoseAlg::try_from(-47), Ok(CoseAlg::ES256K));
        assert_eq!(
            UnsupportedCoseAlg(-257).to_string(),
            "unsupported COSE algorithm -257"
        );
    }
}
