//! The serialized large-blob array's capacity, initial value and integrity.

use sha2::{Digest, Sha256};

use super::StoreError;

/// The largest serialized large-blob array this store accepts, in bytes.
pub const MAX_SERIALIZED_LARGE_BLOB_ARRAY: usize = 16_384;

/// The empty serialized large-blob array and its trailing truncated SHA-256
/// digest (CTAP 2.3 §6.10.1), restored after a reset.
pub const INITIAL_LARGE_BLOB_ARRAY: [u8; 17] = [
    0x80, 0x76, 0xbe, 0x8b, 0x52, 0x8d, 0x00, 0x75, 0xf7, 0xaa, 0xe9, 0x8d, 0x6f, 0xa5, 0x7a, 0x6d,
    0x3c,
];

/// Check only the array's length and trailing hash. Platforms own the
/// contents; the authenticator must not interpret them (CTAP 2.3 §6.10.2).
pub(crate) fn validate_large_blob_array(array: &[u8]) -> Result<(), StoreError> {
    if !(17..=MAX_SERIALIZED_LARGE_BLOB_ARRAY).contains(&array.len()) {
        return Err(StoreError::InvalidRecord(
            "serialized large-blob array length out of range",
        ));
    }
    let (contents, hash) = array.split_at(array.len() - 16);
    if Sha256::digest(contents)[..16] != *hash {
        return Err(StoreError::InvalidRecord(
            "serialized large-blob array hash is invalid",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_array_matches_the_specification() {
        assert_eq!(
            INITIAL_LARGE_BLOB_ARRAY,
            [
                0x80, 0x76, 0xbe, 0x8b, 0x52, 0x8d, 0x00, 0x75, 0xf7, 0xaa, 0xe9, 0x8d, 0x6f, 0xa5,
                0x7a, 0x6d, 0x3c
            ],
        );
        assert!(validate_large_blob_array(&INITIAL_LARGE_BLOB_ARRAY).is_ok());
    }

    #[test]
    fn only_length_and_hash_are_validated() {
        for length in [17, MAX_SERIALIZED_LARGE_BLOB_ARRAY] {
            // Intentionally not a CBOR array: contents remain opaque.
            let mut array = vec![0xff; length - 16];
            array.extend_from_slice(&Sha256::digest(&array)[..16]);
            assert!(validate_large_blob_array(&array).is_ok());
            array[length - 1] ^= 1;
            assert!(validate_large_blob_array(&array).is_err());
        }
        for length in [0, 1, 16, MAX_SERIALIZED_LARGE_BLOB_ARRAY + 1] {
            assert!(validate_large_blob_array(&vec![0; length]).is_err());
        }
    }
}
