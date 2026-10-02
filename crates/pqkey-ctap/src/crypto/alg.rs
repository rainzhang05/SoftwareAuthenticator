//! The COSE algorithms the authenticator signs with.

use core::fmt;

/// The COSE algorithm identifiers this authenticator signs with: ES256 (-7)
/// and the three ML-DSA parameter sets, which RFC 9964 §8.1 registered in the
/// IANA "COSE Algorithms" registry as -48, -49 and -50.
///
/// * -7 -> ES256
/// * -48 -> ML-DSA-44
/// * -49 -> ML-DSA-65
/// * -50 -> ML-DSA-87
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
        match value {
            -7 => Ok(CoseAlg::ES256),
            -48 => Ok(CoseAlg::MLDSA44),
            -49 => Ok(CoseAlg::MLDSA65),
            -50 => Ok(CoseAlg::MLDSA87),
            _ => Err(UnsupportedCoseAlg(value)),
        }
    }
}
