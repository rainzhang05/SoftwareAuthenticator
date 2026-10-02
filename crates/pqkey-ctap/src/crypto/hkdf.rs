//! HKDF-SHA-256 (RFC 5869), in the one form the crate uses.

use hmac::{Hmac, KeyInit, Mac, digest::InvalidLength};
use sha2::Sha256;
use zeroize::Zeroizing;

/// HKDF-SHA-256 (RFC 5869) with no salt and a single 32-byte output block,
/// the only form this crate uses: `HMAC(HMAC(0³², ikm), info || 0x01)`.
///
/// Written out rather than taken from the `hkdf` crate, which drops the
/// pseudorandom key it extracts, as secret as `ikm`, without wiping it.  Here
/// that key and the output block are wiped, and the HMAC states wipe
/// themselves.
pub(crate) fn hkdf_sha256(
    ikm: &[u8],
    info: &[u8],
    okm: &mut [u8; 32],
) -> Result<(), InvalidLength> {
    // RFC 5869 §2.2: a missing salt is HashLen zero bytes.
    let mut extract = <Hmac<Sha256> as KeyInit>::new_from_slice(&[0u8; 32])?;
    extract.update(ikm);
    let prk = Zeroizing::new(extract.finalize().into_bytes());
    let mut expand = <Hmac<Sha256> as KeyInit>::new_from_slice(&prk)?;
    expand.update(info);
    expand.update(&[1]);
    let block = Zeroizing::new(expand.finalize().into_bytes());
    okm.copy_from_slice(&block);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5869 test case 3 (A.3), SHA-256 with no salt and no info: the
    /// first 32 bytes of its output keying material.
    #[test]
    fn hkdf_matches_rfc_5869() {
        let mut okm = [0u8; 32];
        hkdf_sha256(&[0x0b; 22], b"", &mut okm).unwrap();
        let hex: String = okm.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            hex,
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        );
    }
}
