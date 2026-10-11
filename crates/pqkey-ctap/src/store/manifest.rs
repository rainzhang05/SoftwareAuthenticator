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
}
