//! ML-DSA keys (FIPS 204), held as their seed.

use core::fmt;
use pqkey_mldsa::{ParamSet, PublicKey, SEED_LEN};
use zeroize::Zeroizing;

use super::CryptoError;
use super::alg::CoseAlg;
use super::cose::try_akp_key;

/// Map a COSE algorithm identifier to the corresponding ML-DSA parameter set.
pub fn mldsa_paramset_from_alg(alg: CoseAlg) -> Option<ParamSet> {
    match alg {
        CoseAlg::MLDSA44 => Some(ParamSet::MLDSA44),
        CoseAlg::MLDSA65 => Some(ParamSet::MLDSA65),
        CoseAlg::MLDSA87 => Some(ParamSet::MLDSA87),
        _ => None,
    }
}

/// The CBOR COSE_Key of the ML-DSA public key `public_key`, for `alg`: an
/// Algorithm Key Pair whose `pub` is the raw FIPS 204 public key.  Returns
/// [`CryptoError::CborEncoding`] if serialization fails.
pub(crate) fn try_cose_key(alg: CoseAlg, public_key: &PublicKey) -> Result<Vec<u8>, CryptoError> {
    try_akp_key(alg, public_key.as_bytes())
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
