//! The COSE algorithms the authenticator signs with, and what it knows about
//! each of them: one table, [`CoseAlg::properties`], with a row per
//! algorithm, and [`CoseAlg::ALL`], the order getInfo lists them in.

use core::fmt;
use pqkey_mldsa::ParamSet;

use super::ecdsa::Curve;

/// The COSE algorithm identifiers this authenticator signs with: ES256 (-7)
/// and the three ML-DSA parameter sets, which RFC 9964 §8.1 registered in the
/// IANA "COSE Algorithms" registry as -48, -49 and -50.
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
}

/// The kind of private key material a credential keeps.  Each algorithm
/// keeps one kind, [`CoseAlg::key_kind`]; algorithms with the same signature
/// scheme keep the same kind.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum KeyKind {
    /// A P-256 private scalar: 32 bytes, big-endian, non-zero and below the
    /// group order.
    P256Scalar,
    /// A 32-byte seed from which the credential's algorithm derives its key:
    /// for ML-DSA, the FIPS 204 key-generation seed `ξ`.
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
            Scheme::MlDsa(_) => KeyKind::Seed,
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
    pub const ALL: [CoseAlg; 4] = [
        CoseAlg::ES256,
        CoseAlg::MLDSA44,
        CoseAlg::MLDSA65,
        CoseAlg::MLDSA87,
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
            ]
        );
    }

    /// ES256 is ECDSA over P-256 with SHA-256, and each ML-DSA identifier
    /// names its own parameter set (RFC 9964 §8.1).
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
            ]
        );
    }

    /// ES256 keeps the P-256 scalar and ML-DSA the seed `ξ`: what the store
    /// and sealed credential IDs hold.
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
        assert_eq!(
            UnsupportedCoseAlg(-257).to_string(),
            "unsupported COSE algorithm -257"
        );
    }
}
