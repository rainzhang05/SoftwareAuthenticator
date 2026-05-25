//! Safe Rust wrapper around pure-Rust ML-DSA implementations from `fips204`.
//!
//! This crate exposes a small, stable surface (`keypair`, `sign`, `verify`)
//! for the three ML-DSA parameter sets defined in FIPS 204 (ML-DSA-44/65/87).
//! The implementation is provided by the `fips204` crate, which has no C
//! dependencies, contains no `unsafe` code, and operates in constant-time.
//!
//! Secret keys are zeroized on drop.

use fips204::traits::{SerDes, Signer, Verifier};
use zeroize::Zeroize;

/// ML-DSA parameter sets supported by this wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamSet {
    MLDSA44,
    MLDSA65,
    MLDSA87,
}

/// Public key wrapper. The inner bytes are the canonical FIPS 204 encoding.
#[derive(Debug, Clone)]
pub struct PublicKey(pub Vec<u8>);

/// Secret key wrapper. The inner bytes are the canonical FIPS 204 encoding;
/// they are zeroized on drop.
#[derive(Debug)]
pub struct SecretKey(pub Vec<u8>);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Returned by FIPS 204 calls that fail at runtime (invalid lengths,
/// keygen failure, signing failure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaError {
    InvalidParameterSet,
    InvalidKeyLength,
    InvalidSignatureLength,
    KeyGenFailed,
    SigningFailed,
}

/// Return the (public-key, secret-key, signature) byte lengths for a
/// parameter set.  Useful for storage / buffer sizing.
pub fn lengths(ps: ParamSet) -> (usize, usize, usize) {
    match ps {
        #[cfg(feature = "mldsa44")]
        ParamSet::MLDSA44 => (
            fips204::ml_dsa_44::PK_LEN,
            fips204::ml_dsa_44::SK_LEN,
            fips204::ml_dsa_44::SIG_LEN,
        ),
        #[cfg(feature = "mldsa65")]
        ParamSet::MLDSA65 => (
            fips204::ml_dsa_65::PK_LEN,
            fips204::ml_dsa_65::SK_LEN,
            fips204::ml_dsa_65::SIG_LEN,
        ),
        #[cfg(feature = "mldsa87")]
        ParamSet::MLDSA87 => (
            fips204::ml_dsa_87::PK_LEN,
            fips204::ml_dsa_87::SK_LEN,
            fips204::ml_dsa_87::SIG_LEN,
        ),
        #[cfg(not(feature = "mldsa44"))]
        ParamSet::MLDSA44 => panic!("feature mldsa44 is not enabled"),
        #[cfg(not(feature = "mldsa65"))]
        ParamSet::MLDSA65 => panic!("feature mldsa65 is not enabled"),
        #[cfg(not(feature = "mldsa87"))]
        ParamSet::MLDSA87 => panic!("feature mldsa87 is not enabled"),
    }
}

/// Generate an ML-DSA keypair.
///
/// Panics if the parameter-set feature is not enabled.  Returns an error if
/// the underlying FIPS 204 keygen call fails (extremely rare; surfaces RNG
/// problems).
pub fn try_keypair(ps: ParamSet) -> Result<(PublicKey, SecretKey), MlDsaError> {
    match ps {
        #[cfg(feature = "mldsa44")]
        ParamSet::MLDSA44 => {
            let (pk, sk) =
                fips204::ml_dsa_44::try_keygen().map_err(|_| MlDsaError::KeyGenFailed)?;
            Ok((
                PublicKey(pk.into_bytes().to_vec()),
                SecretKey(sk.into_bytes().to_vec()),
            ))
        }
        #[cfg(feature = "mldsa65")]
        ParamSet::MLDSA65 => {
            let (pk, sk) =
                fips204::ml_dsa_65::try_keygen().map_err(|_| MlDsaError::KeyGenFailed)?;
            Ok((
                PublicKey(pk.into_bytes().to_vec()),
                SecretKey(sk.into_bytes().to_vec()),
            ))
        }
        #[cfg(feature = "mldsa87")]
        ParamSet::MLDSA87 => {
            let (pk, sk) =
                fips204::ml_dsa_87::try_keygen().map_err(|_| MlDsaError::KeyGenFailed)?;
            Ok((
                PublicKey(pk.into_bytes().to_vec()),
                SecretKey(sk.into_bytes().to_vec()),
            ))
        }
        #[cfg(not(feature = "mldsa44"))]
        ParamSet::MLDSA44 => Err(MlDsaError::InvalidParameterSet),
        #[cfg(not(feature = "mldsa65"))]
        ParamSet::MLDSA65 => Err(MlDsaError::InvalidParameterSet),
        #[cfg(not(feature = "mldsa87"))]
        ParamSet::MLDSA87 => Err(MlDsaError::InvalidParameterSet),
    }
}

/// Generate an ML-DSA keypair, panicking on failure.  Kept for API
/// compatibility with the previous liboqs-based wrapper.
pub fn keypair(ps: ParamSet) -> (PublicKey, SecretKey) {
    try_keypair(ps).expect("ML-DSA keypair generation failed")
}

/// Try to sign `message` with the supplied secret key.  Returns the raw
/// FIPS 204 signature bytes.  The context value is always empty per the
/// CTAP2 / WebAuthn profile that uses this wrapper.
pub fn try_sign(ps: ParamSet, sk: &SecretKey, message: &[u8]) -> Result<Vec<u8>, MlDsaError> {
    let (_pk_len, sk_len, _sig_len) = lengths(ps);
    if sk.0.len() != sk_len {
        return Err(MlDsaError::InvalidKeyLength);
    }
    match ps {
        #[cfg(feature = "mldsa44")]
        ParamSet::MLDSA44 => {
            let bytes: [u8; fips204::ml_dsa_44::SK_LEN] =
                sk.0.as_slice()
                    .try_into()
                    .map_err(|_| MlDsaError::InvalidKeyLength)?;
            let sk = fips204::ml_dsa_44::PrivateKey::try_from_bytes(bytes)
                .map_err(|_| MlDsaError::InvalidKeyLength)?;
            let sig = sk
                .try_sign(message, &[])
                .map_err(|_| MlDsaError::SigningFailed)?;
            Ok(sig.to_vec())
        }
        #[cfg(feature = "mldsa65")]
        ParamSet::MLDSA65 => {
            let bytes: [u8; fips204::ml_dsa_65::SK_LEN] =
                sk.0.as_slice()
                    .try_into()
                    .map_err(|_| MlDsaError::InvalidKeyLength)?;
            let sk = fips204::ml_dsa_65::PrivateKey::try_from_bytes(bytes)
                .map_err(|_| MlDsaError::InvalidKeyLength)?;
            let sig = sk
                .try_sign(message, &[])
                .map_err(|_| MlDsaError::SigningFailed)?;
            Ok(sig.to_vec())
        }
        #[cfg(feature = "mldsa87")]
        ParamSet::MLDSA87 => {
            let bytes: [u8; fips204::ml_dsa_87::SK_LEN] =
                sk.0.as_slice()
                    .try_into()
                    .map_err(|_| MlDsaError::InvalidKeyLength)?;
            let sk = fips204::ml_dsa_87::PrivateKey::try_from_bytes(bytes)
                .map_err(|_| MlDsaError::InvalidKeyLength)?;
            let sig = sk
                .try_sign(message, &[])
                .map_err(|_| MlDsaError::SigningFailed)?;
            Ok(sig.to_vec())
        }
        #[cfg(not(feature = "mldsa44"))]
        ParamSet::MLDSA44 => Err(MlDsaError::InvalidParameterSet),
        #[cfg(not(feature = "mldsa65"))]
        ParamSet::MLDSA65 => Err(MlDsaError::InvalidParameterSet),
        #[cfg(not(feature = "mldsa87"))]
        ParamSet::MLDSA87 => Err(MlDsaError::InvalidParameterSet),
    }
}

/// Sign a message.  Kept for API compatibility with the previous
/// liboqs-based wrapper; returns an empty `Vec` (and logs a warning via
/// `eprintln!`-equivalent) on key-length / signing errors rather than
/// aborting the process, since the daemon must not crash on a malformed
/// stored credential.
pub fn sign(ps: ParamSet, sk: &SecretKey, message: &[u8]) -> Vec<u8> {
    match try_sign(ps, sk, message) {
        Ok(sig) => sig,
        Err(err) => {
            #[cfg(feature = "log")]
            log::warn!("ML-DSA signing failed: {err:?}");
            let _ = err;
            Vec::new()
        }
    }
}

/// Verify a signature.  Returns `false` on length mismatch or invalid
/// signature.
pub fn verify(ps: ParamSet, pk: &PublicKey, message: &[u8], signature: &[u8]) -> bool {
    let (pk_len, _sk_len, sig_len) = lengths(ps);
    if pk.0.len() != pk_len || signature.len() != sig_len {
        return false;
    }
    match ps {
        #[cfg(feature = "mldsa44")]
        ParamSet::MLDSA44 => {
            let pk_bytes: [u8; fips204::ml_dsa_44::PK_LEN] = match pk.0.as_slice().try_into() {
                Ok(bytes) => bytes,
                Err(_) => return false,
            };
            let sig_bytes: [u8; fips204::ml_dsa_44::SIG_LEN] = match signature.try_into() {
                Ok(bytes) => bytes,
                Err(_) => return false,
            };
            match fips204::ml_dsa_44::PublicKey::try_from_bytes(pk_bytes) {
                Ok(pk) => pk.verify(message, &sig_bytes, &[]),
                Err(_) => false,
            }
        }
        #[cfg(feature = "mldsa65")]
        ParamSet::MLDSA65 => {
            let pk_bytes: [u8; fips204::ml_dsa_65::PK_LEN] = match pk.0.as_slice().try_into() {
                Ok(bytes) => bytes,
                Err(_) => return false,
            };
            let sig_bytes: [u8; fips204::ml_dsa_65::SIG_LEN] = match signature.try_into() {
                Ok(bytes) => bytes,
                Err(_) => return false,
            };
            match fips204::ml_dsa_65::PublicKey::try_from_bytes(pk_bytes) {
                Ok(pk) => pk.verify(message, &sig_bytes, &[]),
                Err(_) => false,
            }
        }
        #[cfg(feature = "mldsa87")]
        ParamSet::MLDSA87 => {
            let pk_bytes: [u8; fips204::ml_dsa_87::PK_LEN] = match pk.0.as_slice().try_into() {
                Ok(bytes) => bytes,
                Err(_) => return false,
            };
            let sig_bytes: [u8; fips204::ml_dsa_87::SIG_LEN] = match signature.try_into() {
                Ok(bytes) => bytes,
                Err(_) => return false,
            };
            match fips204::ml_dsa_87::PublicKey::try_from_bytes(pk_bytes) {
                Ok(pk) => pk.verify(message, &sig_bytes, &[]),
                Err(_) => false,
            }
        }
        #[cfg(not(feature = "mldsa44"))]
        ParamSet::MLDSA44 => false,
        #[cfg(not(feature = "mldsa65"))]
        ParamSet::MLDSA65 => false,
        #[cfg(not(feature = "mldsa87"))]
        ParamSet::MLDSA87 => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(ps: ParamSet) {
        let (pk, sk) = keypair(ps);
        let (pk_len, sk_len, _sig_len) = lengths(ps);
        assert_eq!(pk.0.len(), pk_len, "public key length");
        assert_eq!(sk.0.len(), sk_len, "secret key length");

        let message = b"post-quantum authentication";
        let signature = sign(ps, &sk, message);
        assert!(
            verify(ps, &pk, message, &signature),
            "verification failed for {:?}",
            ps
        );

        let mut tampered = signature.clone();
        tampered[0] ^= 0x01;
        assert!(
            !verify(ps, &pk, message, &tampered),
            "tampered signature must not verify ({:?})",
            ps
        );

        let mut other_message = message.to_vec();
        other_message.push(0xFF);
        assert!(
            !verify(ps, &pk, &other_message, &signature),
            "signature must not verify for different message ({:?})",
            ps
        );
    }

    #[test]
    fn mldsa44_roundtrip() {
        roundtrip(ParamSet::MLDSA44);
    }

    #[test]
    fn mldsa65_roundtrip() {
        roundtrip(ParamSet::MLDSA65);
    }

    #[test]
    fn mldsa87_roundtrip() {
        roundtrip(ParamSet::MLDSA87);
    }

    #[test]
    fn rejects_wrong_length_signature() {
        let (pk, _sk) = keypair(ParamSet::MLDSA44);
        assert!(!verify(ParamSet::MLDSA44, &pk, b"hello", &[0u8; 16]));
    }

    #[test]
    fn rejects_wrong_length_pubkey() {
        let (_pk, sk) = keypair(ParamSet::MLDSA44);
        let sig = sign(ParamSet::MLDSA44, &sk, b"hello");
        let pk = PublicKey(vec![0u8; 32]);
        assert!(!verify(ParamSet::MLDSA44, &pk, b"hello", &sig));
    }
}
