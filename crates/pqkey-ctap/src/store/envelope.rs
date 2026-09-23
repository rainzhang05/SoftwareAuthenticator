//! The authenticated encryption envelope around every stored object.
//!
//! ```text
//! offset  length  field
//!      0       4  magic, the ASCII bytes "FTSA"
//!      4       1  format version, 1
//!      5       1  record type: 1 credential, 2 PIN state, 3 attestation
//!      6      24  XChaCha20-Poly1305 nonce, freshly random for every write
//!     30       n  XChaCha20-Poly1305 ciphertext of the n-byte encoded record
//!   30+n      16  Poly1305 tag
//! ```
//!
//! The associated data binds the object to its type and location:
//!
//! ```text
//! magic (4) || version (1) || record type (1) || len(name) as u16 big-endian (2) || name
//! ```
//!
//! where `name` is the object's logical name in UTF-8: `pin-state`,
//! `attestation`, or `credentials/` followed by the 64-hex-digit file name.
//! Copying one object over another therefore fails authentication even when
//! both are encrypted under the same key.
//!
//! # Sealed credential IDs
//!
//! A credential ID that carries a credential, instead of naming a stored one,
//! is sealed without the header, since the CTAP engine frames the ID itself:
//!
//! ```text
//! offset  length  field
//!      0      24  XChaCha20-Poly1305 nonce, freshly random for every seal
//!     24       n  ciphertext of the n-byte plaintext
//!   24+n      16  Poly1305 tag
//! ```
//!
//! under the credential ID key and with the associated data the caller binds
//! it to.

use chacha20poly1305::{AeadInOut, Key, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use getrandom::SysRng;
use rand_core::TryRng;
use zeroize::{Zeroize, Zeroizing};

use super::keys::SubKey;
use super::{Corruption, StoreError};

/// The first four bytes of every stored object.
pub(crate) const MAGIC: [u8; 4] = *b"FTSA";
/// The current format version.
pub(crate) const VERSION: u8 = 1;
/// Length of the XChaCha20-Poly1305 nonce.
pub(crate) const NONCE_LEN: usize = 24;
/// Length of the Poly1305 tag.
pub(crate) const TAG_LEN: usize = 16;
/// Length of everything before the ciphertext.
pub(crate) const HEADER_LEN: usize = MAGIC.len() + 2 + NONCE_LEN;
/// Bytes an envelope adds to its plaintext.
pub(crate) const OVERHEAD: usize = HEADER_LEN + TAG_LEN;
/// The largest envelope the store writes or reads, 1 MiB.  Real records are a
/// few hundred bytes to a few kilobytes; the bound keeps a junk file from
/// exhausting memory.
pub(crate) const MAX_ENVELOPE_LEN: usize = 1 << 20;

/// Bytes a sealed credential ID adds to its plaintext: the nonce and the tag.
pub const SEALED_ID_OVERHEAD: usize = NONCE_LEN + TAG_LEN;

/// The record type byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum RecordType {
    Credential = 1,
    PinState = 2,
    Attestation = 3,
}

/// Encrypt `plaintext` into a new envelope under a fresh random nonce.
pub(crate) fn seal(
    key: &SubKey,
    record_type: RecordType,
    name: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, StoreError> {
    let mut nonce = [0u8; NONCE_LEN];
    SysRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| StoreError::Random)?;
    seal_with_nonce(key, record_type, name, &nonce, plaintext)
}

fn seal_with_nonce(
    key: &SubKey,
    record_type: RecordType,
    name: &str,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, StoreError> {
    if plaintext.len() > MAX_ENVELOPE_LEN - OVERHEAD {
        return Err(StoreError::InvalidRecord(
            "record is larger than the store accepts",
        ));
    }
    // Sized exactly, so the plaintext copied in below is encrypted in place
    // and never left behind in a reallocated buffer.
    let mut envelope = Vec::with_capacity(OVERHEAD + plaintext.len());
    envelope.extend_from_slice(&MAGIC);
    envelope.push(VERSION);
    envelope.push(record_type as u8);
    envelope.extend_from_slice(nonce);
    envelope.extend_from_slice(plaintext);
    let cipher = XChaCha20Poly1305::new(<&Key>::from(key.expose()));
    let aad = associated_data(record_type, name);
    match cipher.encrypt_inout_detached(
        <&XNonce>::from(nonce),
        &aad,
        (&mut envelope[HEADER_LEN..]).into(),
    ) {
        Ok(tag) => {
            envelope.extend_from_slice(&tag);
            Ok(envelope)
        }
        Err(_) => {
            envelope.zeroize();
            Err(StoreError::InvalidRecord("record could not be encrypted"))
        }
    }
}

/// Authenticate and decrypt an envelope that must hold a `record_type` object
/// named `name`.
pub(crate) fn open(
    key: &SubKey,
    record_type: RecordType,
    name: &str,
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Corruption> {
    if envelope.len() < OVERHEAD || envelope.len() > MAX_ENVELOPE_LEN {
        return Err(Corruption::Length);
    }
    let (header, body) = envelope.split_at(HEADER_LEN);
    if header[..MAGIC.len()] != MAGIC
        || header[MAGIC.len()] != VERSION
        || header[MAGIC.len() + 1] != record_type as u8
    {
        return Err(Corruption::Header);
    }
    // Both conversions are infallible: the lengths were checked above.
    let nonce = <&XNonce>::try_from(&header[MAGIC.len() + 2..]).map_err(|_| Corruption::Length)?;
    let (ciphertext, tag) = body.split_at(body.len() - TAG_LEN);
    let tag = <&Tag>::try_from(tag).map_err(|_| Corruption::Length)?;
    let mut buffer = Zeroizing::new(ciphertext.to_vec());
    let cipher = XChaCha20Poly1305::new(<&Key>::from(key.expose()));
    cipher
        .decrypt_inout_detached(
            nonce,
            &associated_data(record_type, name),
            buffer.as_mut_slice().into(),
            tag,
        )
        .map_err(|_| Corruption::Authentication)?;
    Ok(buffer)
}

/// Seal `plaintext` into a credential ID's contents under a fresh random
/// nonce, bound to `associated_data`.
pub(crate) fn seal_credential_id(
    key: &SubKey,
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, StoreError> {
    let mut nonce = [0u8; NONCE_LEN];
    SysRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| StoreError::Random)?;
    seal_credential_id_with_nonce(key, &nonce, plaintext, associated_data)
}

fn seal_credential_id_with_nonce(
    key: &SubKey,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, StoreError> {
    // Sized exactly, so the plaintext is encrypted in place and never left
    // behind in a reallocated buffer.
    let mut sealed = Vec::with_capacity(SEALED_ID_OVERHEAD + plaintext.len());
    sealed.extend_from_slice(nonce);
    sealed.extend_from_slice(plaintext);
    let cipher = XChaCha20Poly1305::new(<&Key>::from(key.expose()));
    match cipher.encrypt_inout_detached(
        <&XNonce>::from(nonce),
        associated_data,
        (&mut sealed[NONCE_LEN..]).into(),
    ) {
        Ok(tag) => {
            sealed.extend_from_slice(&tag);
            Ok(sealed)
        }
        Err(_) => {
            sealed.zeroize();
            Err(StoreError::InvalidRecord(
                "credential ID could not be encrypted",
            ))
        }
    }
}

/// The plaintext of a sealed credential ID, or `None` unless `sealed` was
/// sealed under `key` with `associated_data`.
pub(crate) fn open_credential_id(
    key: &SubKey,
    sealed: &[u8],
    associated_data: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    if sealed.len() < SEALED_ID_OVERHEAD {
        return None;
    }
    let (nonce, rest) = sealed.split_at(NONCE_LEN);
    let (ciphertext, tag) = rest.split_at(rest.len() - TAG_LEN);
    let nonce = <&XNonce>::try_from(nonce).ok()?;
    let tag = <&Tag>::try_from(tag).ok()?;
    let mut buffer = Zeroizing::new(ciphertext.to_vec());
    XChaCha20Poly1305::new(<&Key>::from(key.expose()))
        .decrypt_inout_detached(nonce, associated_data, buffer.as_mut_slice().into(), tag)
        .ok()?;
    Some(buffer)
}

fn associated_data(record_type: RecordType, name: &str) -> Vec<u8> {
    let name = name.as_bytes();
    // Logical names are at most 76 bytes, so the length always fits.
    let name_len = u16::try_from(name.len()).unwrap_or(u16::MAX);
    let mut aad = Vec::with_capacity(MAGIC.len() + 4 + name.len());
    aad.extend_from_slice(&MAGIC);
    aad.push(VERSION);
    aad.push(record_type as u8);
    aad.extend_from_slice(&name_len.to_be_bytes());
    aad.extend_from_slice(name);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::keys::{CredentialKeys, DeviceKeys, RootKey};

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn key() -> SubKey {
        CredentialKeys::derive(&RootKey::generate().unwrap())
            .unwrap()
            .record
    }

    /// Pins the envelope format, including the associated data, to an
    /// independent implementation.
    ///
    /// The expected envelope was produced outside this crate in Python: the
    /// XChaCha20-Poly1305 construction of draft-irtf-cfrg-xchacha-03 built from
    /// a hand-written HChaCha20 and `pyca/cryptography`'s `ChaCha20Poly1305`,
    /// which reproduces the draft's HChaCha20 (§2.2.1) and AEAD (§A.3.1) test
    /// vectors, with
    ///
    /// ```text
    /// key       = credential record subkey of root key bytes(range(32))
    /// nonce     = bytes(range(0x40, 0x58))
    /// name      = "pin-state", record type 2
    /// plaintext = the PIN state record encoding pinned in the codec tests
    /// aad       = b"FTSA" + b"\x01\x02" + (9).to_bytes(2, "big") + b"pin-state"
    /// envelope  = b"FTSA\x01\x02" + nonce + ciphertext + tag
    /// ```
    #[test]
    fn envelope_matches_independent_implementation() {
        let mut root = [0u8; 32];
        for (i, byte) in root.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let key = CredentialKeys::derive(&RootKey::from_bytes(root))
            .unwrap()
            .record;
        let mut nonce = [0u8; NONCE_LEN];
        for (i, byte) in nonce.iter_mut().enumerate() {
            *byte = 0x40 + i as u8;
        }
        let plaintext = unhex("a4015000112233445566778899aabbccddeeff0205030204f5");
        let expected = unhex(concat!(
            "46545341",
            "0102",
            "404142434445464748494a4b4c4d4e4f5051525354555657",
            "7af7a4466c3088aa511e43e080df718c06b6d2dd65652dc4e9",
            "783961ecb6e9bcc93e2c28da48763344"
        ));

        let sealed =
            seal_with_nonce(&key, RecordType::PinState, "pin-state", &nonce, &plaintext).unwrap();
        assert_eq!(sealed, expected);
        let opened = open(&key, RecordType::PinState, "pin-state", &expected).unwrap();
        assert_eq!(opened.as_slice(), plaintext.as_slice());
    }

    /// Pins the sealed credential ID format to the independent implementation
    /// described for `envelope_matches_independent_implementation`, with
    ///
    /// ```text
    /// key       = credential ID subkey of root key bytes(range(32))
    /// nonce     = bytes(range(0x40, 0x58))
    /// plaintext = bytes([0xf9, 0x02]) + bytes(range(0x80, 0xa0))
    /// aad       = b"credential id aad"
    /// sealed    = nonce + ciphertext + tag
    /// ```
    #[test]
    fn sealed_credential_id_matches_independent_implementation() {
        let mut root = [0u8; 32];
        for (i, byte) in root.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let key = CredentialKeys::derive(&RootKey::from_bytes(root))
            .unwrap()
            .id;
        let mut nonce = [0u8; NONCE_LEN];
        for (i, byte) in nonce.iter_mut().enumerate() {
            *byte = 0x40 + i as u8;
        }
        let mut plaintext = vec![0xf9, 0x02];
        plaintext.extend(0x80..0xa0u8);
        let aad = b"credential id aad";
        let expected = unhex(concat!(
            "404142434445464748494a4b4c4d4e4f5051525354555657",
            "9a26acd2ef80a957ad3a1553876e5bc822b9c5cfa96e70ac9a461fb1cdbeaf1bd454",
            "39c3e4c82d5cae2d2caabc8942b05c8c"
        ));

        let sealed = seal_credential_id_with_nonce(&key, &nonce, &plaintext, aad).unwrap();
        assert_eq!(sealed, expected);
        let opened = open_credential_id(&key, &expected, aad).unwrap();
        assert_eq!(opened.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn sealed_credential_ids_open_only_unchanged_with_their_key_and_data() {
        let key = CredentialKeys::derive(&RootKey::generate().unwrap())
            .unwrap()
            .id;
        let plaintext = [0xa5; 34];
        let sealed = seal_credential_id(&key, &plaintext, b"rp one").unwrap();
        assert_eq!(sealed.len(), SEALED_ID_OVERHEAD + plaintext.len());
        assert!(!sealed.windows(8).any(|window| window == &plaintext[..8]));
        assert_eq!(
            open_credential_id(&key, &sealed, b"rp one")
                .unwrap()
                .as_slice(),
            plaintext
        );
        assert_ne!(
            sealed,
            seal_credential_id(&key, &plaintext, b"rp one").unwrap(),
            "a fresh nonce every time"
        );

        assert!(open_credential_id(&key, &sealed, b"rp two").is_none());
        let other = CredentialKeys::derive(&RootKey::generate().unwrap())
            .unwrap()
            .id;
        assert!(open_credential_id(&other, &sealed, b"rp one").is_none());
        for index in 0..sealed.len() {
            let mut tampered = sealed.clone();
            tampered[index] ^= 0x01;
            assert!(
                open_credential_id(&key, &tampered, b"rp one").is_none(),
                "byte {index}"
            );
        }
        for length in 0..sealed.len() {
            assert!(open_credential_id(&key, &sealed[..length], b"rp one").is_none());
        }
    }

    #[test]
    fn round_trip_and_layout() {
        let key = key();
        for plaintext in [&b""[..], b"x", &[0xa5; 5000]] {
            let sealed = seal(&key, RecordType::Credential, "credentials/ab", plaintext).unwrap();
            assert_eq!(sealed.len(), OVERHEAD + plaintext.len());
            assert_eq!(&sealed[..4], b"FTSA");
            assert_eq!(sealed[4], VERSION);
            assert_eq!(sealed[5], RecordType::Credential as u8);
            if plaintext.len() >= 8 {
                assert!(
                    !sealed
                        .windows(plaintext.len())
                        .any(|window| window == plaintext)
                );
            }
            let opened = open(&key, RecordType::Credential, "credentials/ab", &sealed).unwrap();
            assert_eq!(opened.as_slice(), plaintext);
        }
    }

    #[test]
    fn every_seal_uses_a_fresh_nonce() {
        let key = key();
        let a = seal(&key, RecordType::PinState, "pin-state", b"same").unwrap();
        let b = seal(&key, RecordType::PinState, "pin-state", b"same").unwrap();
        assert_ne!(a[6..HEADER_LEN], b[6..HEADER_LEN]);
        assert_ne!(a[HEADER_LEN..], b[HEADER_LEN..]);
    }

    #[test]
    fn rejects_wrong_key_name_or_type() {
        let key = key();
        let sealed = seal(&key, RecordType::Credential, "credentials/aa", b"record").unwrap();
        assert_eq!(
            open(
                &self::key(),
                RecordType::Credential,
                "credentials/aa",
                &sealed
            )
            .err(),
            Some(Corruption::Authentication)
        );
        assert_eq!(
            open(&key, RecordType::Credential, "credentials/ab", &sealed).err(),
            Some(Corruption::Authentication)
        );
        assert_eq!(
            open(&key, RecordType::PinState, "credentials/aa", &sealed).err(),
            Some(Corruption::Header)
        );
        // Rewriting the type byte as well does not help: it is authenticated.
        let mut retyped = sealed.clone();
        retyped[5] = RecordType::PinState as u8;
        assert_eq!(
            open(&key, RecordType::PinState, "credentials/aa", &retyped).err(),
            Some(Corruption::Authentication)
        );
        let device = DeviceKeys::derive(&RootKey::generate().unwrap()).unwrap();
        assert_eq!(
            open(
                &device.record,
                RecordType::Credential,
                "credentials/aa",
                &sealed
            )
            .err(),
            Some(Corruption::Authentication)
        );
    }

    #[test]
    fn rejects_any_modification() {
        let key = key();
        let sealed = seal(&key, RecordType::Attestation, "attestation", b"attestation").unwrap();
        for index in 0..sealed.len() {
            let mut tampered = sealed.clone();
            tampered[index] ^= 0x01;
            let expected = if index < 6 {
                Corruption::Header
            } else {
                Corruption::Authentication
            };
            assert_eq!(
                open(&key, RecordType::Attestation, "attestation", &tampered).err(),
                Some(expected),
                "byte {index}"
            );
        }
    }

    #[test]
    fn rejects_truncation_and_extension() {
        let key = key();
        let sealed = seal(&key, RecordType::PinState, "pin-state", b"state").unwrap();
        for len in 0..sealed.len() {
            let expected = if len < OVERHEAD {
                Corruption::Length
            } else {
                Corruption::Authentication
            };
            assert_eq!(
                open(&key, RecordType::PinState, "pin-state", &sealed[..len]).err(),
                Some(expected),
                "length {len}"
            );
        }
        let mut extended = sealed.clone();
        extended.push(0);
        assert_eq!(
            open(&key, RecordType::PinState, "pin-state", &extended).err(),
            Some(Corruption::Authentication)
        );
    }

    #[test]
    fn size_limit_applies_to_both_directions() {
        let key = key();
        let largest = vec![0u8; MAX_ENVELOPE_LEN - OVERHEAD];
        let sealed = seal(&key, RecordType::Attestation, "attestation", &largest).unwrap();
        assert_eq!(sealed.len(), MAX_ENVELOPE_LEN);
        assert!(open(&key, RecordType::Attestation, "attestation", &sealed).is_ok());

        let too_large = vec![0u8; MAX_ENVELOPE_LEN - OVERHEAD + 1];
        assert!(matches!(
            seal(&key, RecordType::Attestation, "attestation", &too_large),
            Err(StoreError::InvalidRecord(_))
        ));
        let oversized = vec![0u8; MAX_ENVELOPE_LEN + 1];
        assert_eq!(
            open(&key, RecordType::Attestation, "attestation", &oversized).err(),
            Some(Corruption::Length)
        );
    }
}
