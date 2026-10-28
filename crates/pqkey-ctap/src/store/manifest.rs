//! Authenticated membership, independent of physical credential cleanup.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use super::envelope::{MAX_ENVELOPE_LEN, OVERHEAD};
use super::keys::is_credential_file_name;
use super::{Corruption, StoreError};

pub(super) const MANAGED_DIR: &str = "credential-set";
pub(super) const RECORDS_DIR: &str = "records";
pub(super) const ACTIVE_FILE: &str = "active";
pub(super) const FORMAT_FILE: &str = "credential-format";
pub(super) const FORMAT: &[u8] = b"pqkey/credential-set/v1";
const MAGIC: &[u8; 4] = b"PQC1";

/// Legacy records retain their original authenticated logical name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Location {
    Legacy,
    Managed,
}

pub(super) type Manifest = BTreeMap<String, Location>;

pub(super) fn encode(manifest: &Manifest) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let length = manifest
        .len()
        .checked_mul(33)
        .and_then(|n| n.checked_add(8))
        .filter(|&n| n <= MAX_ENVELOPE_LEN - OVERHEAD)
        .ok_or(StoreError::InvalidRecord(
            "credential-set metadata is too large",
        ))?;
    let count = u32::try_from(manifest.len())
        .map_err(|_| StoreError::InvalidRecord("too many credential-set entries"))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(length));
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&count.to_be_bytes());
    for (name, location) in manifest {
        if !is_credential_file_name(name) {
            return Err(StoreError::InvalidRecord("invalid credential-set filename"));
        }
        bytes.push(match location {
            Location::Legacy => 0,
            Location::Managed => 1,
        });
        for pair in name.as_bytes().as_chunks::<2>().0 {
            let digit = |byte: u8| {
                if byte <= b'9' {
                    byte - b'0'
                } else {
                    byte - b'a' + 10
                }
            };
            bytes.push(digit(pair[0]) << 4 | digit(pair[1]));
        }
    }
    Ok(bytes)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Manifest, Corruption> {
    if bytes.len() < 8 || &bytes[..4] != MAGIC {
        return Err(Corruption::Encoding);
    }
    let count =
        u32::from_be_bytes(bytes[4..8].try_into().map_err(|_| Corruption::Encoding)?) as usize;
    if count.checked_mul(33).and_then(|n| n.checked_add(8)) != Some(bytes.len()) {
        return Err(Corruption::Encoding);
    }
    let mut manifest = Manifest::new();
    let mut previous: Option<String> = None;
    for entry in bytes[8..].as_chunks::<33>().0 {
        let location = match entry[0] {
            0 => Location::Legacy,
            1 => Location::Managed,
            _ => return Err(Corruption::Encoding),
        };
        let name = super::fsio::hex(&entry[1..]);
        if previous.as_ref().is_some_and(|previous| previous >= &name) {
            return Err(Corruption::Encoding);
        }
        previous = Some(name.clone());
        manifest.insert(name, location);
    }
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::envelope::{self, RecordType};
    use crate::store::keys::{CredentialKeys, RootKey};

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn strict_manifest_round_trip() {
        let manifest = [
            ("01".repeat(32), Location::Legacy),
            ("ab".repeat(32), Location::Managed),
        ]
        .into_iter()
        .collect();
        let encoded = encode(&manifest).unwrap();
        assert_eq!(decode(&encoded).unwrap(), manifest);
        for length in 0..encoded.len() {
            assert!(decode(&encoded[..length]).is_err());
        }
        let mut invalid = encoded.to_vec();
        invalid[8] = 2;
        assert!(decode(&invalid).is_err());
        let mut duplicate = encoded.to_vec();
        duplicate[42..74].copy_from_slice(&encoded[9..41]);
        assert!(decode(&duplicate).is_err());
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(decode(&trailing).is_err());
    }

    /// The membership encoding documented on `FileStore`, written out by hand
    /// for one legacy and one managed entry: `PQC1`, the entry count as a
    /// big-endian u32, then per entry in name order a location byte (0 legacy,
    /// 1 managed) and the 32-byte file name.
    const TWO_ENTRY_MANIFEST: &str = concat!(
        "50514331", // "PQC1"
        "00000002", // two entries
        "01",       // managed, first in name order
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "00", // legacy
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
    );

    /// Pins the encoding above. An upgraded store must still read after an
    /// update: a decoder that misplaced entries would hide their records, and
    /// cleanup would delete them at the next membership change.
    #[test]
    fn manifest_encoding_matches_the_documented_format() {
        let manifest: Manifest = [
            (
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff".to_owned(),
                Location::Legacy,
            ),
            (
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".to_owned(),
                Location::Managed,
            ),
        ]
        .into_iter()
        .collect();
        let expected = unhex(TWO_ENTRY_MANIFEST);
        assert_eq!(encode(&manifest).unwrap().as_slice(), expected);
        assert_eq!(decode(&expected).unwrap(), manifest);

        // The empty set, which a reset publishes.
        assert_eq!(
            encode(&Manifest::new()).unwrap().as_slice(),
            b"PQC1\0\0\0\0"
        );
        assert_eq!(decode(b"PQC1\0\0\0\0").unwrap(), Manifest::new());
    }

    /// Pins the format marker's envelope to the independent implementation
    /// that `envelope_matches_independent_implementation` in the envelope
    /// tests describes, cross-checked with PyCryptodome's XChaCha20-Poly1305:
    ///
    /// ```text
    /// key       = credential record subkey of root key bytes(range(32))
    /// nonce     = bytes(range(0x40, 0x58))
    /// name      = "credential-format", record type 7
    /// plaintext = b"pqkey/credential-set/v1"
    /// aad       = b"FTSA" + b"\x01\x07" + (17).to_bytes(2, "big") + b"credential-format"
    /// envelope  = b"FTSA\x01\x07" + nonce + ciphertext + tag
    /// ```
    ///
    /// An upgraded store whose marker does not open to exactly this plaintext
    /// refuses to read its credentials.
    #[test]
    fn format_marker_matches_independent_implementation() {
        let key = CredentialKeys::derive(&RootKey::from_bytes(core::array::from_fn(|i| i as u8)))
            .unwrap()
            .record;
        let nonce = core::array::from_fn(|i| 0x40 + i as u8);
        let expected = unhex(concat!(
            "465453410107404142434445464748494a4b4c4d4e4f5051525354555657",
            "ae879f23043dd89c611c51066d1cab2cf62b48ab4f101e",
            "56917e0fa0d24aec69ba8b0968b23a6c",
        ));
        assert_eq!(
            envelope::seal_with_nonce(
                &key,
                RecordType::CredentialFormat,
                FORMAT_FILE,
                &nonce,
                FORMAT
            )
            .unwrap(),
            expected,
        );
        assert_eq!(
            envelope::open(&key, RecordType::CredentialFormat, FORMAT_FILE, &expected)
                .unwrap()
                .as_slice(),
            FORMAT,
        );
    }

    /// Pins the membership envelope, `credential-set/active`, to the
    /// independent implementation and cross-check described for the format
    /// marker above, with
    ///
    /// ```text
    /// key       = credential record subkey of root key bytes(range(32))
    /// nonce     = bytes(range(0x40, 0x58))
    /// name      = "credential-set/active", record type 6
    /// plaintext = the two-entry encoding above
    /// aad       = b"FTSA" + b"\x01\x06" + (21).to_bytes(2, "big") + b"credential-set/active"
    /// envelope  = b"FTSA\x01\x06" + nonce + ciphertext + tag
    /// ```
    ///
    /// An upgraded store whose membership does not open under this record type
    /// and name refuses to read its credentials.
    #[test]
    fn manifest_envelope_matches_independent_implementation() {
        let key = CredentialKeys::derive(&RootKey::from_bytes(core::array::from_fn(|i| i as u8)))
            .unwrap()
            .record;
        let nonce = core::array::from_fn(|i| 0x40 + i as u8);
        let name = format!("{MANAGED_DIR}/{ACTIVE_FILE}");
        let plaintext = unhex(TWO_ENTRY_MANIFEST);
        let expected = unhex(concat!(
            "465453410106404142434445464748494a4b4c4d4e4f5051525354555657",
            "8ea7b7777d12bbec0578356a1a71cf46dc5024d56b6a22ce1333c5684f669d00db694c2bbc",
            "a22fb30779eb47946315cb16f196d8958ebef8ab182c256a0743230f0f0df71718404c6430",
            "b1cb9616d902a55a33d9249cf1833453",
        ));
        assert_eq!(
            envelope::seal_with_nonce(&key, RecordType::CredentialSet, &name, &nonce, &plaintext)
                .unwrap(),
            expected,
        );
        assert_eq!(
            envelope::open(&key, RecordType::CredentialSet, &name, &expected)
                .unwrap()
                .as_slice(),
            plaintext,
        );
    }
}
