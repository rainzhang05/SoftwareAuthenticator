//! The ECDSA family ([`Scheme::Ecdsa`](super::alg::Scheme::Ecdsa)): ECDSA
//! over each [`Curve`] with the curve's hash, the signature an ASN.1 DER
//! `Ecdsa-Sig-Value`.  "For COSEAlgorithmIdentifier -7 (ES256), and other
//! ECDSA-based algorithms, the sig value MUST be encoded as an ASN.1 DER
//! Ecdsa-Sig-Value" (WebAuthn Level 3 §6.5.5).
//!
//! Each curve's own types live in a module of its own,
//! [`super::ecdsa_p256`]; this one holds what the curves share.

use p256::elliptic_curve::sec1::{Coordinates, ModulusSize};

use super::CryptoError;
use super::alg::CoseAlg;
use super::cose::{CRV_P256, try_ec2_key};

/// The curves the authenticator signs ECDSA over.  Each is used with one
/// hash only: "SHA-256 be used only with curve P-256" (RFC 9053 §2.1).
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum Curve {
    /// P-256 with SHA-256: ES256 and ESP256.  Keys are kept as their scalar.
    P256,
}

impl Curve {
    /// The curve's identifier in the COSE "Elliptic Curves" registry, an EC2
    /// key's `crv`.
    const fn crv(self) -> i32 {
        match self {
            Curve::P256 => CRV_P256,
        }
    }
}

/// The CBOR COSE_Key of the public key on `curve` whose SEC1 coordinates are
/// `point`, for `alg`: an EC2 key with both coordinates, as WebAuthn requires
/// ("MUST NOT use the compressed point form", WebAuthn Level 3 §5.8.5).
///
/// Returns [`CryptoError::InvalidPublicKey`] for the point at infinity and
/// for a compressed or compact point, which carry no y coordinate, and
/// [`CryptoError::CborEncoding`] if serialization fails.  Neither case may
/// panic.
pub(crate) fn try_cose_key<Size: ModulusSize>(
    alg: CoseAlg,
    curve: Curve,
    point: Coordinates<'_, Size>,
) -> Result<Vec<u8>, CryptoError> {
    match point {
        Coordinates::Uncompressed { x, y } => try_ec2_key(alg, curve.crv(), x, y),
        Coordinates::Identity | Coordinates::Compact { .. } | Coordinates::Compressed { .. } => {
            Err(CryptoError::InvalidPublicKey)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::os_rng;
    use p256::Sec1Point;
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::Generate;

    #[test]
    fn try_cose_key_rejects_identity_point() {
        let identity = Sec1Point::identity();
        assert!(identity.is_identity());
        assert_eq!(
            try_cose_key(CoseAlg::ES256, Curve::P256, identity.coordinates()),
            Err(CryptoError::InvalidPublicKey)
        );
    }

    #[test]
    fn try_cose_key_rejects_point_without_y_coordinate() {
        let signing_key = SigningKey::generate_from_rng(&mut os_rng());
        // A compressed SEC1 encoding carries X but no Y.
        let compressed = signing_key.verifying_key().to_sec1_point(true);
        assert!(!compressed.is_identity());
        assert!(compressed.y().is_none());
        assert_eq!(
            try_cose_key(CoseAlg::ES256, Curve::P256, compressed.coordinates()),
            Err(CryptoError::InvalidPublicKey)
        );
    }
}
