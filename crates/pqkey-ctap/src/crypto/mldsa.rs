//! ML-DSA keys (FIPS 204), held as their seed.

use ciborium::ser::into_writer;
use core::fmt;
use pqkey_mldsa::{ParamSet, PublicKey, SEED_LEN};
use zeroize::Zeroizing;

use super::CryptoError;
use super::alg::CoseAlg;
use super::cose::cose_akp_key_map;

/// Map a COSE algorithm identifier to the corresponding ML-DSA parameter set.
pub fn mldsa_paramset_from_alg(alg: CoseAlg) -> Option<ParamSet> {
    match alg {
        CoseAlg::MLDSA44 => Some(ParamSet::MLDSA44),
        CoseAlg::MLDSA65 => Some(ParamSet::MLDSA65),
        CoseAlg::MLDSA87 => Some(ParamSet::MLDSA87),
        _ => None,
    }
}

/// Build the CBOR COSE_Key for an ML-DSA public key: the Algorithm Key Pair
/// structure with 1 (kty) = 7 (AKP), 3 (alg) = -48/-49/-50, and -1 = the raw
/// public key bytes.  Returns [`CryptoError::CborEncoding`] if serialization
/// fails.
pub fn try_cose_public_key(ps: ParamSet, pk: &PublicKey) -> Result<Vec<u8>, CryptoError> {
    let alg_id = match ps {
        ParamSet::MLDSA44 => CoseAlg::MLDSA44.identifier(),
        ParamSet::MLDSA65 => CoseAlg::MLDSA65.identifier(),
        ParamSet::MLDSA87 => CoseAlg::MLDSA87.identifier(),
    };
    let mut out = Vec::new();
    let map = cose_akp_key_map(alg_id, &pk.0);
    into_writer(&map, &mut out).map_err(|_| CryptoError::CborEncoding)?;
    Ok(out)
}

/// The 32-byte FIPS 204 key-generation seed `ξ` of an ML-DSA key.
///
/// Zeroized on drop; its `Debug` output is redacted.
pub struct MlDsaSeed(Zeroizing<[u8; SEED_LEN]>);

impl MlDsaSeed {
    /// Wrap a seed.  The caller remains responsible for zeroizing `seed`'s
    /// own copy.
    pub fn new(seed: [u8; SEED_LEN]) -> Self {
        MlDsaSeed(Zeroizing::new(seed))
    }

    /// Borrow the seed bytes.
    pub fn as_bytes(&self) -> &[u8; SEED_LEN] {
        &self.0
    }
}

impl fmt::Debug for MlDsaSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MlDsaSeed(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn es256_has_no_ml_dsa_parameter_set() {
        assert!(mldsa_paramset_from_alg(CoseAlg::ES256).is_none());
    }
}
