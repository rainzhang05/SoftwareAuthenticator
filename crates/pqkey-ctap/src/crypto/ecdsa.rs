//! The ECDSA family ([`Scheme::Ecdsa`](super::alg::Scheme::Ecdsa)): ECDSA
//! over each [`Curve`] with the curve's hash, the signature an ASN.1 DER
//! `Ecdsa-Sig-Value`.  "For COSEAlgorithmIdentifier -7 (ES256), and other
//! ECDSA-based algorithms, the sig value MUST be encoded as an ASN.1 DER
//! Ecdsa-Sig-Value" (WebAuthn Level 3 §6.5.5).
//!
//! Each curve's own types live in a module of its own,
//! [`super::ecdsa_p256`], [`super::ecdsa_p384`], [`super::ecdsa_p521`] and
//! [`super::ecdsa_secp256k1`]; this one holds what the curves share.

use p256::elliptic_curve::bigint::{NonZero, U640, Uint};
use p256::elliptic_curve::sec1::{Coordinates, ModulusSize};
use p256::elliptic_curve::{CurveArithmetic, NonZeroScalar};
use shake::{ExtendableOutput, Shake256, Update, XofReader};
use zeroize::Zeroizing;

use super::CryptoError;
use super::alg::CoseAlg;
use super::cose::{CRV_P256, CRV_P384, CRV_P521, CRV_SECP256K1, try_ec2_key};
use super::credential_key::Seed;

/// The curves the authenticator signs ECDSA over.  Each is used with one
/// hash only: "SHA-256 be used only with curve P-256, SHA-384 be used only
/// with curve P-384, and SHA-512 be used only with curve P-521" (RFC 9053
/// §2.1), and secp256k1 with SHA-256, as ES256K (RFC 8812 §3.2).
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum Curve {
    /// P-256 with SHA-256: ES256 and ESP256.  Keys are kept as their scalar.
    P256,
    /// P-384 with SHA-384: ES384 and ESP384.  Keys are kept as a seed the
    /// scalar is derived from ([`derive_scalar`]).
    P384,
    /// P-521 with SHA-512: ES512 and ESP512.  Keys are kept as a seed the
    /// scalar is derived from ([`derive_scalar`]).
    P521,
    /// secp256k1 with SHA-256: ES256K.  Keys are kept as a seed the scalar is
    /// derived from ([`derive_scalar`]).
    Secp256k1,
}

impl Curve {
    /// The curve's identifier in the COSE "Elliptic Curves" registry, an EC2
    /// key's `crv`.
    const fn crv(self) -> i32 {
        match self {
            Curve::P256 => CRV_P256,
            Curve::P384 => CRV_P384,
            Curve::P521 => CRV_P521,
            Curve::Secp256k1 => CRV_SECP256K1,
        }
    }
}

/// What the derivation's input starts with, before the curve's name and the
/// seed.
const DERIVATION_CONTEXT: &[u8] = b"pqkey/v1/ecdsa-key/";

/// The private scalar d of the key on curve `C`, named `curve_name`, that
/// `seed` derives: FIPS 186-5 Appendix A.2.1, "ECDSA Key Pair Generation
/// using Extra Random Bits", with SHAKE256 in place of the random bit
/// generator.
///
/// * returned_bits are the first L = ⌈(N + 64) / 8⌉ bytes of
///   SHAKE256("pqkey/v1/ecdsa-key/" ‖ `curve_name` ‖ `seed`), where N is the
///   bit length of the group order n: 56 bytes for P-384, 74 for P-521 and
///   40 for secp256k1.
///   The standard asks for N + 64 bits, which whole bytes round up to: P-521
///   takes 592 bits, 7 more than its 585, which only bring d closer still to
///   uniform.
/// * c is returned_bits read as a big-endian integer, and
///   d = (c mod (n − 1)) + 1, in [1, n − 1].
///
/// The input names the curve and not the algorithm, so the algorithms of a
/// curve derive the same key from a seed.  The arithmetic is crypto-bigint's,
/// constant-time, and every value this function holds is zeroized.  The
/// copies crypto-bigint makes in frames of its own are not, so callers run
/// this on a scrubbed stack, as they run what they do with the key.
///
/// Returns [`CryptoError::KeyDerivation`] if n is too long for the
/// derivation, or d is not a scalar of the curve, neither of which happens
/// for the curves here.
pub(super) fn derive_scalar<C, const LIMBS: usize>(
    curve_name: &[u8],
    seed: &Seed,
) -> Result<NonZeroScalar<C>, CryptoError>
where
    C: CurveArithmetic<Uint = Uint<LIMBS>>,
{
    let n = C::ORDER.as_ref();
    let n_minus_one = NonZero::new(n.wrapping_sub(&Uint::ONE))
        .into_option()
        .ok_or(CryptoError::KeyDerivation)?;
    let length = (n.bits() as usize + 64).div_ceil(8);
    let start = U640::BYTES
        .checked_sub(length)
        .ok_or(CryptoError::KeyDerivation)?;
    let mut returned_bits = Zeroizing::new([0u8; U640::BYTES]);
    let mut shake = Shake256::default();
    shake.update(DERIVATION_CONTEXT);
    shake.update(curve_name);
    shake.update(seed.as_bytes());
    shake.finalize_xof().read(&mut returned_bits[start..]);
    let c = Zeroizing::new(U640::from_be_slice(&returned_bits[..]));
    let remainder = Zeroizing::new(c.rem(&n_minus_one));
    let d = Zeroizing::new(remainder.wrapping_add(&Uint::ONE));
    NonZeroScalar::from_uint(*d)
        .into_option()
        .ok_or(CryptoError::KeyDerivation)
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
    use crate::crypto::{ecdsa_p384, ecdsa_p521, ecdsa_secp256k1};
    use crate::{try_cose_public_key, try_credential_secret_from_bytes};
    use ciborium::value::{Integer, Value};
    use p256::Sec1Point;
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::Generate;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// Known answers for keys kept as a seed: d, and the public key's x and
    /// y, for two seeds on each curve.  They come from an independent
    /// computation, Python's hashlib and integers for d and
    /// pyca/cryptography for the public key:
    ///
    /// ```python
    /// import hashlib
    /// from cryptography.hazmat.primitives.asymmetric import ec
    ///
    /// CURVES = {  # name: (curve, group order n)
    ///     "P-384": (ec.SECP384R1(), int(
    ///         "ffffffffffffffffffffffffffffffffffffffffffffffff"
    ///         "c7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16)),
    ///     "P-521": (ec.SECP521R1(), int(
    ///         "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    ///         "fa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
    ///         16)),
    ///     "secp256k1": (ec.SECP256K1(), int(
    ///         "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)),
    /// }
    /// for name, (curve, n) in CURVES.items():
    ///     for seed in (bytes(range(32)), b"\xff" * 32):
    ///         length = (n.bit_length() + 64 + 7) // 8
    ///         returned_bits = hashlib.shake_256(
    ///             b"pqkey/v1/ecdsa-key/" + name.encode() + seed).digest(length)
    ///         d = int.from_bytes(returned_bits, "big") % (n - 1) + 1
    ///         public = ec.derive_private_key(d, curve).public_key().public_numbers()
    ///         size = (curve.key_size + 7) // 8
    ///         print(name, seed.hex(),
    ///               *(v.to_bytes(size, "big").hex() for v in (d, public.x, public.y)))
    /// ```
    #[test]
    fn keys_kept_as_a_seed_derive_the_known_answers() {
        type Scalar = fn(&Seed) -> Vec<u8>;
        let p384: Scalar = |seed| {
            let key = ecdsa_p384::signing_key(seed).expect("a key");
            key.to_bytes().to_vec()
        };
        let p521: Scalar = |seed| {
            let key = ecdsa_p521::signing_key(seed).expect("a key");
            key.to_bytes().to_vec()
        };
        let secp256k1: Scalar = |seed| {
            let key = ecdsa_secp256k1::signing_key(seed).expect("a key");
            key.to_bytes().to_vec()
        };
        let low: [u8; 32] = core::array::from_fn(|i| i as u8);
        for (alg, scalar, seed, d, x, y) in [
            (
                CoseAlg::ES384,
                p384,
                low,
                "89792dd6913a82c9f55346379e96e99594465ce4e3413a9cfca41b43b281a64a1da7030054be7dc306a723bd3e9eff31",
                "40827d02766591783cda299dbf8e9096c289ceadf4df73a2d9fb32e31538665af9ea117a5e2da9dcf22da5b903266cdb",
                "bb9ac1ff16e14fa9377aaeb7f6ef83a38c317eba19c1339a0ec4a866ade97e5f1640b1d843168213d6a6457234376399",
            ),
            (
                CoseAlg::ES384,
                p384,
                [0xff; 32],
                "5d8908fe4cd1f1da41bbe1f57db2e9d7c60a9ad99a255fa7d4c381b3657c9ba759467e1c24ff2e6d239e39cf9e68d79d",
                "01f1d2ac06ad1ada4c0c7ada3aabd97024788bfe201fcd55d1aa2306429e74931d361fcf74eb35f8bac0ca755cdb360c",
                "520d0174e69456b122a3bd1f7c7c161e4e75e9cabd485c540b4df99ea6d01bb70a65550cde8dfa736be190c7836c1de7",
            ),
            (
                CoseAlg::ES512,
                p521,
                low,
                "008f8a33dbb56284e3e075d4baa674917cc2c6dee4d4e2329f81b24286dd94f30432e17b4ad53b752b4a56b0996a0651239d6ffb0c73281e0bfb99db063e630884eb",
                "018a7d1cd43e7eebcef6a12a4bb5e0cfc439be421790748fd5bbc0dff94752db1df0e41622480c26dfdba3c142bc747b204125d4933a6ea79040d9bc845084a611f8",
                "00bd6d7007d1df6d42f9c759500eaf55182675a38e344ce723905ca9a81fec8aaa0296b14247d40b74063d5654e533e2a6648aca5b4b326fc15a077cbf93144075dc",
            ),
            (
                CoseAlg::ES512,
                p521,
                [0xff; 32],
                "0101686d78af55fa464edd47c619b8e9ed430a1d0dd8c0d98625b0fcedbedd4882316da2f8875fe1906afbedbb67867b7ce5b98baf048643edb01fbd972976f6a152",
                "01d7dfd079e91f3e73eba8a44bcc240c9c756d3d91aadc1f87a760550687334ffc9cf788f004a2a81e153137b551032c388f9879b0f74ed6d7cd24491fca83a51ee3",
                "003ed01a131b47f3ca6ba624861973892a1fa5ef7654d0575583dd04002b8b37262e9b35f36d8307ee0aedd5727208b33aafdd75618acfcd66c9787b2e2f612b902b",
            ),
            (
                CoseAlg::ES256K,
                secp256k1,
                low,
                "63169330aa84589e10b9ccfeaa26d0fae51697298616efe973071c83dfeda532",
                "a66e3920ca909e2bf2f76f36aee686c0f140102f556acc3f464ec1495c3c116e",
                "74544c936f37312d66f018f8de67a6232183635c805bd8df059f5de3ae9811c1",
            ),
            (
                CoseAlg::ES256K,
                secp256k1,
                [0xff; 32],
                "41ff7944657b55e7e24f373a1a85019b745088c3f38c9f12ab1664ad61289d22",
                "1cb22ad377e2960d66996c81247f0d1a4f6c83d1ad7ecbedfda3c825fc6f6374",
                "3bbb57e604dd56538844c7085660af3f15ed2eb6212d6d7240ec791610ce9f16",
            ),
        ] {
            assert_eq!(hex(&scalar(&Seed::new(seed))), d, "{alg:?}: d");
            let key = try_credential_secret_from_bytes(alg, &seed).expect("a key");
            let cose_key = try_cose_public_key(alg, &key).expect("a COSE_Key");
            let Value::Map(entries) =
                ciborium::de::from_reader(cose_key.as_slice()).expect("a COSE_Key")
            else {
                panic!("a COSE_Key is a map");
            };
            let coordinate = |label: i64| {
                let label = Value::Integer(Integer::from(label));
                let (_, value) = entries
                    .iter()
                    .find(|(found, _)| *found == label)
                    .expect("a coordinate");
                hex(value.as_bytes().expect("bytes"))
            };
            assert_eq!(coordinate(-2), x, "{alg:?}: x");
            assert_eq!(coordinate(-3), y, "{alg:?}: y");
        }
    }

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
