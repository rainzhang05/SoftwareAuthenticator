//! RSA-2048 signatures with exponent 65537: RSASSA-PKCS1-v1_5 and
//! RSASSA-PSS (RFC 8017 §8). PSS uses the same hash for MGF1 and a salt as
//! long as the hash output (RFC 8230 §2). Signatures are raw 256-byte values,
//! never ASN.1 wrapped (WebAuthn Level 3 §6.5.5).

use core::{convert::Infallible, fmt};
use p256::elliptic_curve::bigint::ConcatenatingMul;
use rand_core::{TryCryptoRng, TryRng};
use rsa::{
    BoxedUint, RsaPrivateKey,
    signature::{RandomizedSigner, SignatureEncoding},
    traits::{PrivateKeyParts, PublicKeyParts},
};
use sha2::{Sha256, Sha384, Sha512};
use shake::{ExtendableOutput, Shake256, Shake256Reader, Update, XofReader};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{CryptoError, alg::CoseAlg, cose::try_rsa_key, scrub::with_scrubbed_stack};

/// The two RFC 8017 signature paddings.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum Padding {
    /// EMSA-PKCS1-v1_5 with DigestInfo (RFC 8017 §9.2).
    Pkcs1v15,
    /// EMSA-PSS (RFC 8017 §9.1).
    Pss,
}

/// The hash of both the message and, for PSS, MGF1.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum Hash {
    /// SHA-256, and a 32-byte PSS salt.
    Sha256,
    /// SHA-384, and a 48-byte PSS salt.
    Sha384,
    /// SHA-512, and a 64-byte PSS salt.
    Sha512,
}

/// An infallible cryptographic stream expanded from 32 bytes of OS entropy.
/// The sponge and reader zeroize on drop through shake's zeroize feature.
struct ShakeRng(Shake256Reader);

impl fmt::Debug for ShakeRng {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ShakeRng(<redacted>)")
    }
}

impl TryRng for ShakeRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut bytes = Zeroizing::new([0; 4]);
        self.0.read(&mut bytes[..]);
        Ok(u32::from_le_bytes(*bytes))
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut bytes = Zeroizing::new([0; 8]);
        self.0.read(&mut bytes[..]);
        Ok(u64::from_le_bytes(*bytes))
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Infallible> {
        self.0.read(bytes);
        Ok(())
    }
}
impl TryCryptoRng for ShakeRng {}

/// Generate p || q on the scrubbed stack. RSA needs an infallible generator,
/// so only the initial 32-byte draw can fail for lack of randomness.
pub(crate) fn generate<R: TryCryptoRng + ?Sized>(
    rng: &mut R,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    with_scrubbed_stack(|| {
        let mut seed = Zeroizing::new([0; 32]);
        rng.try_fill_bytes(&mut seed[..])
            .map_err(|_| CryptoError::Randomness)?;
        let mut shake = Shake256::default();
        shake.update(b"pqkey/v1/rsa-key/");
        shake.update(&seed[..]);
        let key = RsaPrivateKey::new(&mut ShakeRng(shake.finalize_xof()), 2048)
            .map_err(|_| CryptoError::KeyDerivation)?;
        Ok(secret_bytes(&key))
    })
}

/// Reconstruct only two distinct, odd 1024-bit primes with a 2048-bit product.
/// Store bytes are untrusted; reject them before the crate's reconstruction
/// and validation, which also computes d mod lcm(p-1, q-1) and CRT values.
pub(crate) fn signing_key(bytes: &[u8]) -> Result<RsaPrivateKey, CryptoError> {
    if bytes.len() != 256 {
        return Err(CryptoError::InvalidKey);
    }
    let (p, q) = bytes.split_at(128);
    if p[0] & 0x80 == 0
        || q[0] & 0x80 == 0
        || p[127] & 1 == 0
        || q[127] & 1 == 0
        || bool::from(p.ct_eq(q))
    {
        return Err(CryptoError::InvalidKey);
    }
    let p = Zeroizing::new(BoxedUint::from_be_slice(p, 1024).map_err(|_| CryptoError::InvalidKey)?);
    let q = Zeroizing::new(BoxedUint::from_be_slice(q, 1024).map_err(|_| CryptoError::InvalidKey)?);
    let n = Zeroizing::new(p.concatenating_mul(&q));
    if n.bits() != 2048 {
        return Err(CryptoError::InvalidKey);
    }
    RsaPrivateKey::from_p_q((*p).clone(), (*q).clone(), 65537u64.into())
        .map_err(|_| CryptoError::InvalidKey)
}

/// Serialize only the primes, never d or the CRT values. Secret copies of
/// the crate's heap integers and their byte encodings are zeroized on drop.
pub(crate) fn secret_bytes(key: &RsaPrivateKey) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(256));
    for prime in key.primes() {
        let encoded = Zeroizing::new(prime.to_be_bytes());
        bytes.extend_from_slice(&encoded);
    }
    bytes
}

/// The RFC 8230 §4 public key, built on the scrubbed stack.
pub(crate) fn cose_public_key(alg: CoseAlg, key: &RsaPrivateKey) -> Result<Vec<u8>, CryptoError> {
    with_scrubbed_stack(|| try_rsa_key(alg, &key.n().to_be_bytes()))
}

/// Blind every private operation using the fallible operating-system RNG.
pub(crate) fn sign(
    key: &RsaPrivateKey,
    padding: Padding,
    hash: Hash,
    message: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    sign_with_rng(key, padding, hash, message, &mut getrandom::SysRng)
}

/// The signing entry point with an injectable fallible RNG for failure tests.
fn sign_with_rng<R: TryCryptoRng + ?Sized>(
    key: &RsaPrivateKey,
    padding: Padding,
    hash: Hash,
    message: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, CryptoError> {
    with_scrubbed_stack(|| {
        // Explicit dispatch keeps each algorithm's padding, hash and salt
        // visible. The ordinary PSS SigningKey does not blind the operation.
        let signature = match (padding, hash) {
            (Padding::Pkcs1v15, Hash::Sha256) => {
                rsa::pkcs1v15::SigningKey::<Sha256>::new(key.clone())
                    .try_sign_with_rng(rng, message)
                    .map(|s| s.to_vec())
            }
            (Padding::Pkcs1v15, Hash::Sha384) => {
                rsa::pkcs1v15::SigningKey::<Sha384>::new(key.clone())
                    .try_sign_with_rng(rng, message)
                    .map(|s| s.to_vec())
            }
            (Padding::Pkcs1v15, Hash::Sha512) => {
                rsa::pkcs1v15::SigningKey::<Sha512>::new(key.clone())
                    .try_sign_with_rng(rng, message)
                    .map(|s| s.to_vec())
            }
            (Padding::Pss, Hash::Sha256) => {
                rsa::pss::BlindedSigningKey::<Sha256>::new_with_salt_len(key.clone(), 32)
                    .try_sign_with_rng(rng, message)
                    .map(|s| s.to_vec())
            }
            (Padding::Pss, Hash::Sha384) => {
                rsa::pss::BlindedSigningKey::<Sha384>::new_with_salt_len(key.clone(), 48)
                    .try_sign_with_rng(rng, message)
                    .map(|s| s.to_vec())
            }
            (Padding::Pss, Hash::Sha512) => {
                rsa::pss::BlindedSigningKey::<Sha512>::new_with_salt_len(key.clone(), 64)
                    .try_sign_with_rng(rng, message)
                    .map(|s| s.to_vec())
            }
        };
        signature.map_err(|_| CryptoError::SigningFailed)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::verify::{VerificationError, verify_signature};
    use crate::rsa_fixture::{MESSAGE, MODULUS, PRIMES, SIGNATURES};
    use ciborium::value::Value;

    const ALGORITHMS: [(CoseAlg, Padding, Hash); 6] = [
        (CoseAlg::RS256, Padding::Pkcs1v15, Hash::Sha256),
        (CoseAlg::RS384, Padding::Pkcs1v15, Hash::Sha384),
        (CoseAlg::RS512, Padding::Pkcs1v15, Hash::Sha512),
        (CoseAlg::PS256, Padding::Pss, Hash::Sha256),
        (CoseAlg::PS384, Padding::Pss, Hash::Sha384),
        (CoseAlg::PS512, Padding::Pss, Hash::Sha512),
    ];

    #[test]
    fn fixed_primes_and_pkcs1_signatures_match_cryptography() {
        let key = signing_key(&PRIMES).expect("fixed key");
        assert_eq!(key.n().to_be_bytes().as_ref(), MODULUS);
        assert_eq!(secret_bytes(&key).as_slice(), PRIMES);
        for (i, (alg, padding, hash)) in ALGORITHMS.into_iter().enumerate() {
            let public = cose_public_key(alg, &key).expect("COSE");
            let Value::Map(entries) = ciborium::de::from_reader(public.as_slice()).expect("map")
            else {
                panic!("map");
            };
            let labels: Vec<i128> = entries
                .iter()
                .map(|(label, _)| i128::from(label.as_integer().expect("integer")))
                .collect();
            assert_eq!(labels, [1, 3, -1, -2]);
            assert_eq!(entries[0].1.as_integer().map(i128::from), Some(3));
            assert_eq!(entries[2].1.as_bytes().expect("n"), &MODULUS);
            assert_eq!(entries[3].1.as_bytes().expect("e"), &[1, 0, 1]);
            let signature = sign(&key, padding, hash, &MESSAGE).expect("sign");
            assert_eq!(signature.len(), 256);
            if i < 3 {
                assert_eq!(signature, SIGNATURES[i]);
            }
            assert_eq!(verify_signature(alg, &public, &MESSAGE, &signature), Ok(()));
            assert_eq!(
                verify_signature(alg, &public, b"another message", &signature),
                Err(VerificationError::BadSignature)
            );
            for (other, _, _) in ALGORITHMS.into_iter().filter(|(other, _, _)| *other != alg) {
                let public = cose_public_key(other, &key).expect("other alg");
                assert_eq!(
                    verify_signature(other, &public, &MESSAGE, &signature),
                    Err(VerificationError::BadSignature),
                    "{alg:?} as {other:?}"
                );
            }
        }
    }

    #[test]
    fn verifier_rejects_malformed_rsa_cose_keys() {
        let key = signing_key(&PRIMES).expect("fixed key");
        let public = cose_public_key(CoseAlg::RS256, &key).expect("COSE");
        let Value::Map(entries) = ciborium::de::from_reader(public.as_slice()).expect("map") else {
            panic!("map");
        };
        let mut cases = Vec::new();
        let mut missing = entries.clone();
        missing.pop();
        cases.push(missing);
        let mut extra = entries.clone();
        extra.push((Value::Integer(4.into()), Value::Bytes(vec![])));
        cases.push(extra);
        let mut duplicate = entries.clone();
        duplicate.push(entries[0].clone());
        cases.push(duplicate);
        let mut short_n = MODULUS.to_vec();
        short_n.remove(0);
        let mut short_bits = MODULUS.to_vec();
        short_bits[0] &= 0x7f;
        for (index, value) in [
            (0, Value::Integer(2.into())),
            (1, Value::Integer((-258).into())),
            (2, Value::Bytes(short_n)),
            (2, Value::Bytes(short_bits)),
            (3, Value::Bytes(vec![0, 1, 0, 1])),
            (3, Value::Bytes(vec![1, 0, 3])),
        ] {
            let mut changed = entries.clone();
            changed[index].1 = value;
            cases.push(changed);
        }
        for entries in cases {
            let mut encoded = Vec::new();
            ciborium::ser::into_writer(&Value::Map(entries), &mut encoded).expect("CBOR");
            assert!(matches!(
                verify_signature(CoseAlg::RS256, &encoded, &MESSAGE, &SIGNATURES[0]),
                Err(VerificationError::MalformedKey(_))
            ));
        }
    }

    #[test]
    fn malformed_primes_are_rejected() {
        for length in [0, 32, 128, 255, 257, 512] {
            assert_eq!(
                signing_key(&vec![0xff; length]).err(),
                Some(CryptoError::InvalidKey)
            );
        }
        for offset in [0, 128] {
            let mut short = Zeroizing::new(PRIMES);
            short[offset] &= 0x7f;
            assert_eq!(signing_key(&short[..]).err(), Some(CryptoError::InvalidKey));
            let mut even = Zeroizing::new(PRIMES);
            even[offset + 127] &= 0xfe;
            assert_eq!(signing_key(&even[..]).err(), Some(CryptoError::InvalidKey));
        }
        let mut equal = Zeroizing::new(PRIMES);
        equal.copy_within(..128, 128);
        assert_eq!(signing_key(&equal[..]).err(), Some(CryptoError::InvalidKey));
        let mut small_n = Zeroizing::new([0; 256]);
        small_n[0] = 0x80;
        small_n[128] = 0x80;
        small_n[127] = 3;
        small_n[255] = 5;
        assert_eq!(
            signing_key(&small_n[..]).err(),
            Some(CryptoError::InvalidKey)
        );
        // 65537 divides p-1, so no private exponent exists. This reaches
        // the RSA crate's checks after the byte and modulus checks.
        let mut invalid = Zeroizing::new([0xff; 256]);
        invalid[125] = 0xfe;
        assert_eq!(
            signing_key(&invalid[..]).err(),
            Some(CryptoError::InvalidKey)
        );
    }

    struct FailingRng;
    impl TryRng for FailingRng {
        type Error = CryptoError;
        fn try_next_u32(&mut self) -> Result<u32, CryptoError> {
            Err(CryptoError::Randomness)
        }
        fn try_next_u64(&mut self) -> Result<u64, CryptoError> {
            Err(CryptoError::Randomness)
        }
        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), CryptoError> {
            Err(CryptoError::Randomness)
        }
    }
    impl TryCryptoRng for FailingRng {}

    #[test]
    fn failing_randomness_fails_generation_and_every_signature() {
        assert_eq!(
            generate(&mut FailingRng).err(),
            Some(CryptoError::Randomness)
        );
        let key = signing_key(&PRIMES).expect("fixed key");
        for (_, padding, hash) in ALGORITHMS {
            assert_eq!(
                sign_with_rng(&key, padding, hash, &MESSAGE, &mut FailingRng),
                Err(CryptoError::SigningFailed)
            );
        }
    }

    #[test]
    fn verifier_rejects_signature_lengths_ranges_and_wrong_pss_salt() {
        let key = signing_key(&PRIMES).expect("fixed key");
        for (alg, _, _) in ALGORITHMS {
            let public = cose_public_key(alg, &key).expect("COSE");
            for signature in [
                vec![0; 255],
                vec![0; 257],
                vec![0xff; 256],
                MODULUS.to_vec(),
            ] {
                assert_eq!(
                    verify_signature(alg, &public, &MESSAGE, &signature),
                    Err(VerificationError::BadSignature)
                );
            }
        }
        for (alg, signature) in [
            (
                CoseAlg::PS256,
                rsa::pss::BlindedSigningKey::<Sha256>::new_with_salt_len(key.clone(), 0)
                    .try_sign_with_rng(&mut getrandom::SysRng, &MESSAGE)
                    .expect("sign")
                    .to_vec(),
            ),
            (
                CoseAlg::PS384,
                rsa::pss::BlindedSigningKey::<Sha384>::new_with_salt_len(key.clone(), 32)
                    .try_sign_with_rng(&mut getrandom::SysRng, &MESSAGE)
                    .expect("sign")
                    .to_vec(),
            ),
            (
                CoseAlg::PS512,
                rsa::pss::BlindedSigningKey::<Sha512>::new_with_salt_len(key, 48)
                    .try_sign_with_rng(&mut getrandom::SysRng, &MESSAGE)
                    .expect("sign")
                    .to_vec(),
            ),
        ] {
            let public = try_rsa_key(alg, &MODULUS).expect("COSE");
            assert_eq!(
                verify_signature(alg, &public, &MESSAGE, &signature),
                Err(VerificationError::BadSignature)
            );
        }
    }
}
