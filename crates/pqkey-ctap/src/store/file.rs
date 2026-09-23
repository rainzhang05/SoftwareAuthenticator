//! The file-backed [`CredentialStore`].

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use super::codec;
use super::envelope::{self, MAX_ENVELOPE_LEN, RecordType};
use super::fsio;
use super::keys::{
    CredentialKeys, DeviceKeys, FileKeySource, KeyDomain, KeySource, RootKey, SubKey,
    is_credential_file_name,
};
use super::{
    AttestationRecord, Corruption, CredentialRecord, CredentialStore, DEFAULT_MAX_CREDENTIALS,
    PinStateRecord, StoreError, next_created_at, sort_newest_first, validate_attestation,
    validate_credential,
};

const CREDENTIALS_DIR: &str = "credentials";
const KEYS_DIR: &str = "keys";
const PIN_STATE_FILE: &str = "pin-state";
const ATTESTATION_FILE: &str = "attestation";

/// The production [`CredentialStore`]: authenticated, encrypted files in a
/// private state directory.
///
/// Read the [threat model](super#threat-model) before relying on the
/// encryption.
///
/// Every operation reads the directory afresh; nothing is cached between
/// calls except the configuration.  An object that fails authentication or
/// decoding is reported (by [`get`](CredentialStore::get),
/// [`pin_state`](CredentialStore::pin_state), and
/// [`attestation`](CredentialStore::attestation)) or skipped with a warning
/// (by [`list`](CredentialStore::list) and [`count`](CredentialStore::count)),
/// and never deleted except by [`delete`](CredentialStore::delete) or
/// [`clear`](CredentialStore::clear).
///
/// # Layout
///
/// ```text
/// <state dir>/                0700
/// ├── keys/                   0700  root keys (FileKeySource only)
/// │   ├── device.key          0600  32 random bytes
/// │   └── credential.key      0600  32 random bytes, replaced by clear()
/// ├── credentials/            0700
/// │   └── <64 hex digits>     0600  one envelope per credential, record type 1
/// ├── pin-state               0600  envelope, record type 2
/// └── attestation             0600  envelope, record type 3
/// ```
///
/// Writes briefly create `.tmp-<16 hex digits>` files next to their target.
///
/// A credential's file name is the lowercase hex encoding of
/// HMAC-SHA-256(credential index key, credential ID), so a directory listing
/// reveals neither credential IDs nor anything about relying parties.
///
/// # Keys
///
/// Two independent 32-byte root keys come from the [`KeySource`]:
///
/// * the **device** key protects the attestation record and survives
///   [`clear`](CredentialStore::clear);
/// * the **credential** key protects credential records, credential file
///   names, the PIN state, and sealed credential IDs, and is replaced by
///   [`clear`](CredentialStore::clear).
///
/// Root keys are never used directly.  Subkeys are HKDF-SHA-256 (RFC 5869)
/// with no salt, the root key as input keying material, a 32-byte output, and
/// these ASCII info strings:
///
/// ```text
/// root key    info string                                 subkey
/// device      ftsa-store/v1/device/record-encryption      encrypts the attestation record
/// credential  ftsa-store/v1/credential/record-encryption  encrypts credentials and PIN state
/// credential  ftsa-store/v1/credential/index-hmac         keys the credential file names
/// credential  ftsa-store/v1/credential/id-encryption      seals credential IDs
/// ```
///
/// A root key that is missing while data encrypted under it exists, or that
/// exists but is malformed, is never regenerated: operations that need it
/// fail with [`StoreError::KeyUnavailable`].  Only
/// [`clear`](CredentialStore::clear) replaces the credential key, which also
/// makes it the way to recover from a lost one.
///
/// # Envelope
///
/// ```text
/// offset  length  field
///      0       4  magic, ASCII "FTSA"
///      4       1  format version, 1
///      5       1  record type: 1 credential, 2 PIN state, 3 attestation
///      6      24  XChaCha20-Poly1305 nonce, freshly random for every write
///     30       n  ciphertext of the n-byte record encoding
///   30+n      16  Poly1305 tag
/// ```
///
/// The associated data is
///
/// ```text
/// "FTSA" || version || record type || u16 big-endian length of name || name
/// ```
///
/// where `name` is the object's path relative to the state directory:
/// `pin-state`, `attestation`, or `credentials/<64 hex digits>`.  Copying one
/// file over another therefore fails authentication even under the same key.
/// Envelopes are at most 1 MiB.
///
/// # Records
///
/// The plaintext is a CBOR map with unsigned integer keys, written in
/// ascending key order with shortest-form integers and lengths.  Optional
/// fields are omitted when absent.  Decoding accepts the keys in any order and
/// longer encodings than needed, but nothing else: unknown, duplicate or
/// missing keys and wrong types make the record corrupt.
///
/// ```text
/// credential record (type 1)
///    1  credential_id           byte string
///    2  rp_id                   text string
///    3  user_id                 byte string
///    4  user_name               text string, optional
///    5  user_display_name       text string, optional
///    6  alg                     integer, COSE algorithm identifier (-7, -48, -49, -50)
///    7  private key type        unsigned: 1 = P-256 scalar, 2 = ML-DSA seed
///    8  private key             byte string, 32 bytes
///    9  cred_random_with_uv     byte string, 32 bytes
///   10  cred_random_without_uv  byte string, 32 bytes
///   11  cred_protect            unsigned, 1-3
///   12  sign_count              unsigned, 32 bits
///   13  created_at              unsigned, 64 bits
///
/// PIN state record (type 2)
///    1  pin_hash                byte string, 16 bytes, optional
///    2  pin_retries             unsigned, 8 bits
///    3  consecutive_failures    unsigned, 8 bits
///    4  pin_auth_blocked        boolean
///
/// attestation record (type 3)
///    1  private_key             byte string, 32 bytes
///    2  certificate_chain       array of byte strings, at least one, none empty
/// ```
///
/// # Durability
///
/// Files are created with their final mode and never modified in place: a
/// write goes to a temporary file that is flushed, renamed over its target,
/// and followed by a flush of the directory.  See
/// [`put`](CredentialStore::put) and [`clear`](CredentialStore::clear) in
/// the source for the crash analysis.
#[derive(Debug)]
pub struct FileStore<K = FileKeySource> {
    root: PathBuf,
    credentials_dir: PathBuf,
    keys: K,
    max_credentials: usize,
}

impl FileStore<FileKeySource> {
    /// Open the store in `state_dir`, keeping root keys in `state_dir/keys`.
    ///
    /// Creates the state directory (and its parents), the credential
    /// directory, and any root key that does not exist yet.  See
    /// [`Self::open_with_key_source`].
    pub fn open(state_dir: impl AsRef<Path>) -> Result<Self, StoreError> {
        let state_dir = state_dir.as_ref();
        Self::open_with_key_source(state_dir, FileKeySource::new(state_dir.join(KEYS_DIR)))
    }
}

impl<K: KeySource> FileStore<K> {
    /// Open the store in `state_dir` with root keys from `keys`.
    ///
    /// Missing root keys are created unless data encrypted under them already
    /// exists.  A root key that is unusable does not make opening fail: it is
    /// logged here and reported by each operation that needs it, so that the
    /// device key and [`clear`](CredentialStore::clear) stay usable.
    pub fn open_with_key_source(state_dir: impl AsRef<Path>, keys: K) -> Result<Self, StoreError> {
        let root = state_dir.as_ref().to_path_buf();
        if let Some(parent) = root
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(|err| fsio::io_error(parent, err))?;
        }
        fsio::ensure_private_dir(&root)?;
        let store = Self {
            credentials_dir: root.join(CREDENTIALS_DIR),
            root,
            keys,
            max_credentials: DEFAULT_MAX_CREDENTIALS,
        };
        fsio::ensure_private_dir(&store.credentials_dir)?;
        for domain in KeyDomain::ALL {
            match store.root_key_for_write(domain) {
                Ok(_) => {}
                Err(err @ StoreError::KeyUnavailable { .. }) => {
                    log::warn!("credential store: {err}");
                }
                Err(err) => return Err(err),
            }
        }
        Ok(store)
    }

    /// Set the credential limit.
    #[must_use]
    pub fn with_max_credentials(mut self, max_credentials: usize) -> Self {
        self.max_credentials = max_credentials;
        self
    }

    /// The state directory.
    #[must_use]
    pub fn state_dir(&self) -> &Path {
        &self.root
    }

    /// The key source.
    #[must_use]
    pub fn key_source(&self) -> &K {
        &self.keys
    }

    /// The root key for a read, or `None` if neither the key nor any data
    /// encrypted under it exists.
    fn root_key_for_read(&self, domain: KeyDomain) -> Result<Option<RootKey>, StoreError> {
        match self.keys.load(domain)? {
            Some(key) => Ok(Some(key)),
            None if self.has_data(domain)? => Err(missing_key(domain)),
            None => Ok(None),
        }
    }

    /// The root key for a write, created if neither it nor any data encrypted
    /// under it exists.
    fn root_key_for_write(&self, domain: KeyDomain) -> Result<RootKey, StoreError> {
        match self.keys.load(domain)? {
            Some(key) => Ok(key),
            None if self.has_data(domain)? => Err(missing_key(domain)),
            None => self.keys.create(domain),
        }
    }

    /// Whether any object encrypted under `domain`'s key exists.
    fn has_data(&self, domain: KeyDomain) -> Result<bool, StoreError> {
        match domain {
            KeyDomain::Device => exists(&self.root.join(ATTESTATION_FILE)),
            KeyDomain::Credential => Ok(exists(&self.root.join(PIN_STATE_FILE))?
                || !self.credential_file_names()?.is_empty()),
        }
    }

    fn credential_keys(&self) -> Result<Option<CredentialKeys>, StoreError> {
        self.root_key_for_read(KeyDomain::Credential)?
            .map(|root| CredentialKeys::derive(&root))
            .transpose()
    }

    /// Names of the files in `credentials/` that look like credential records.
    fn credential_file_names(&self) -> Result<Vec<String>, StoreError> {
        let dir = &self.credentials_dir;
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(fsio::io_error(dir, err)),
        };
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|err| fsio::io_error(dir, err))?;
            if let Some(name) = entry.file_name().to_str()
                && is_credential_file_name(name)
            {
                names.push(name.to_owned());
            }
        }
        Ok(names)
    }

    /// Read `credentials/<name>`, or `None` if it does not exist.
    fn read_credential(
        &self,
        keys: &CredentialKeys,
        name: &str,
    ) -> Result<Option<CredentialRecord>, StoreError> {
        let object = format!("{CREDENTIALS_DIR}/{name}");
        let Some(sealed) = fsio::read_file(&self.credentials_dir.join(name), max_envelope_len())?
        else {
            return Ok(None);
        };
        let plaintext = envelope::open(&keys.record, RecordType::Credential, &object, &sealed)
            .map_err(|reason| corrupt(&object, reason))?;
        let record =
            codec::decode_credential(&plaintext).map_err(|reason| corrupt(&object, reason))?;
        // Authentication already ties the contents to this name; this catches
        // a record written under the wrong name by a buggy writer.
        if keys.file_name(&record.credential_id)? != name {
            return Err(corrupt(&object, Corruption::Inconsistent));
        }
        Ok(Some(record))
    }

    /// Every readable credential, in directory order.  Unreadable credentials
    /// are logged and skipped.
    fn scan(&self, keys: &CredentialKeys) -> Result<Vec<CredentialRecord>, StoreError> {
        let names = self.credential_file_names()?;
        // Sized up front so that growing the vector never leaves copies of
        // records in freed memory.
        let mut records = Vec::with_capacity(names.len());
        for name in names {
            match self.read_credential(keys, &name) {
                Ok(Some(record)) => records.push(record),
                // Deleted since the directory was listed.
                Ok(None) => {}
                Err(err) => log::warn!("credential store: skipping credential: {err}"),
            }
        }
        Ok(records)
    }

    fn read_object<T>(
        &self,
        key: &SubKey,
        record_type: RecordType,
        name: &str,
        decode: fn(&[u8]) -> Result<T, Corruption>,
    ) -> Result<Option<T>, StoreError> {
        let Some(sealed) = fsio::read_file(&self.root.join(name), max_envelope_len())? else {
            return Ok(None);
        };
        let plaintext = envelope::open(key, record_type, name, &sealed)
            .map_err(|reason| corrupt(name, reason))?;
        decode(&plaintext)
            .map(Some)
            .map_err(|reason| corrupt(name, reason))
    }

    fn write_object(
        &self,
        key: &SubKey,
        record_type: RecordType,
        name: &str,
        plaintext: &[u8],
    ) -> Result<(), StoreError> {
        let sealed = envelope::seal(key, record_type, name, plaintext)?;
        fsio::replace_file(&self.root, name, &sealed)
    }

    fn write_pin_state(
        &self,
        keys: &CredentialKeys,
        state: &PinStateRecord,
    ) -> Result<(), StoreError> {
        let plaintext = codec::encode_pin_state(state)?;
        self.write_object(
            &keys.record,
            RecordType::PinState,
            PIN_STATE_FILE,
            &plaintext,
        )
    }
}

impl<K: KeySource> CredentialStore for FileStore<K> {
    fn get(&self, credential_id: &[u8]) -> Result<Option<CredentialRecord>, StoreError> {
        let Some(keys) = self.credential_keys()? else {
            return Ok(None);
        };
        let name = keys.file_name(credential_id)?;
        match self.read_credential(&keys, &name)? {
            Some(record) if record.credential_id != credential_id => Err(corrupt(
                &format!("{CREDENTIALS_DIR}/{name}"),
                Corruption::Inconsistent,
            )),
            record => Ok(record),
        }
    }

    fn put(&mut self, record: &CredentialRecord) -> Result<(), StoreError> {
        // Crash safety: the only file this changes is `credentials/<name>`
        // (plus, on first use, the credential key, which is created atomically
        // before anything is encrypted under it).  `replace_file` writes the
        // envelope to a flushed temporary file, renames it into place, and
        // flushes the directory, so a crash leaves either the previous file
        // (or none) or the complete new one, never a torn record.  A leftover
        // temporary file does not have a credential name, so it is ignored
        // until `clear` removes it.  There is no index or counter to fall out
        // of step: the limit and the creation order are recomputed from the
        // records on every insert.
        validate_credential(record)?;
        let keys = CredentialKeys::derive(&self.root_key_for_write(KeyDomain::Credential)?)?;
        let name = keys.file_name(&record.credential_id)?;
        let existing = match self.read_credential(&keys, &name) {
            Ok(existing) => existing,
            // An unreadable record under this name is replaced like an absent
            // one; it did not count towards the limit either.
            Err(StoreError::Corrupt { .. }) => None,
            Err(err) => return Err(err),
        };
        let created_at = match existing {
            Some(existing) => existing.created_at,
            None => {
                let current = self.scan(&keys)?;
                if current.len() >= self.max_credentials {
                    return Err(StoreError::Full {
                        max: self.max_credentials,
                    });
                }
                next_created_at(&current)
            }
        };
        let object = format!("{CREDENTIALS_DIR}/{name}");
        let plaintext = codec::encode_credential(record, created_at)?;
        let sealed = envelope::seal(&keys.record, RecordType::Credential, &object, &plaintext)?;
        fsio::ensure_private_dir(&self.credentials_dir)?;
        fsio::replace_file(&self.credentials_dir, &name, &sealed)
    }

    fn delete(&mut self, credential_id: &[u8]) -> Result<bool, StoreError> {
        let Some(keys) = self.credential_keys()? else {
            return Ok(false);
        };
        let name = keys.file_name(credential_id)?;
        let removed = fsio::remove_file_if_present(&self.credentials_dir.join(name))?;
        if removed {
            fsio::sync_dir(&self.credentials_dir)?;
        }
        Ok(removed)
    }

    fn list(&self) -> Result<Vec<CredentialRecord>, StoreError> {
        let Some(keys) = self.credential_keys()? else {
            return Ok(Vec::new());
        };
        let mut records = self.scan(&keys)?;
        sort_newest_first(&mut records);
        Ok(records)
    }

    fn count(&self) -> Result<usize, StoreError> {
        let Some(keys) = self.credential_keys()? else {
            return Ok(0);
        };
        Ok(self.scan(&keys)?.len())
    }

    fn max_credentials(&self) -> usize {
        self.max_credentials
    }

    fn clear(&mut self) -> Result<(), StoreError> {
        // Crash safety.  The steps run in this order; a crash after any prefix
        // leaves a state that is safe to use and that a repeated `clear`
        // completes.
        //
        // 1. Delete every file in `credentials/`, then flush the directory.  A
        //    crash part-way leaves some credentials, still guarded by the
        //    unchanged PIN state.  Nothing is exposed.
        // 2. Delete `pin-state`, then flush the state directory.  This happens
        //    only once no credential file is left, so a PIN is never removed
        //    while it still guards a credential.  A crash here leaves an empty
        //    store without a PIN, which is what a reset produces, except that
        //    the old key is still current, so old copies are not yet shredded.
        // 3. Rotate the credential key: the new key is written to a flushed
        //    temporary file and renamed over the old one, the directory is
        //    flushed, and the old key's contents are then overwritten.  Before
        //    the rename is durable the old key is in effect, afterwards the new
        //    one; either way no file is left for it to decrypt.  From here on
        //    every copy of the old files is undecryptable.
        // 4. Write the default PIN state under the new key, atomically.  A crash
        //    before it completes leaves no `pin-state`, which reads as `None`,
        //    the same as a fresh store.
        //
        // Deleting the PIN state in step 2 instead of only overwriting it in
        // step 4 is what keeps a crash between 3 and 4 from leaving a
        // `pin-state` sealed under a key that no longer exists, which would
        // make `pin_state` fail until the next reset.  No step needs the old
        // key, so `clear` also recovers a store whose credential key is lost
        // or malformed.
        fsio::remove_all_files(&self.credentials_dir)?;
        fsio::ensure_private_dir(&self.credentials_dir)?;
        if fsio::remove_file_if_present(&self.root.join(PIN_STATE_FILE))? {
            fsio::sync_dir(&self.root)?;
        }
        let root_key = self.keys.rotate(KeyDomain::Credential)?;
        let keys = CredentialKeys::derive(&root_key)?;
        self.write_pin_state(&keys, &PinStateRecord::default())
    }

    fn pin_state(&self) -> Result<Option<PinStateRecord>, StoreError> {
        let Some(keys) = self.credential_keys()? else {
            return Ok(None);
        };
        self.read_object(
            &keys.record,
            RecordType::PinState,
            PIN_STATE_FILE,
            codec::decode_pin_state,
        )
    }

    fn set_pin_state(&mut self, state: &PinStateRecord) -> Result<(), StoreError> {
        let keys = CredentialKeys::derive(&self.root_key_for_write(KeyDomain::Credential)?)?;
        self.write_pin_state(&keys, state)
    }

    fn attestation(&self) -> Result<Option<AttestationRecord>, StoreError> {
        let Some(root) = self.root_key_for_read(KeyDomain::Device)? else {
            return Ok(None);
        };
        let keys = DeviceKeys::derive(&root)?;
        self.read_object(
            &keys.record,
            RecordType::Attestation,
            ATTESTATION_FILE,
            codec::decode_attestation,
        )
    }

    fn set_attestation(&mut self, record: &AttestationRecord) -> Result<(), StoreError> {
        validate_attestation(record)?;
        let keys = DeviceKeys::derive(&self.root_key_for_write(KeyDomain::Device)?)?;
        let plaintext = codec::encode_attestation(record)?;
        self.write_object(
            &keys.record,
            RecordType::Attestation,
            ATTESTATION_FILE,
            &plaintext,
        )
    }

    fn seal_credential_id(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, StoreError> {
        let root = self.root_key_for_write(KeyDomain::Credential)?;
        let keys = CredentialKeys::derive(&root)?;
        envelope::seal_credential_id(&keys.id, plaintext, associated_data)
    }

    fn open_credential_id(
        &self,
        sealed: &[u8],
        associated_data: &[u8],
    ) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError> {
        let Some(keys) = self.credential_keys()? else {
            return Ok(None);
        };
        Ok(envelope::open_credential_id(
            &keys.id,
            sealed,
            associated_data,
        ))
    }
}

fn max_envelope_len() -> u64 {
    MAX_ENVELOPE_LEN as u64
}

fn corrupt(object: &str, reason: Corruption) -> StoreError {
    StoreError::Corrupt {
        object: object.to_owned(),
        reason,
    }
}

fn missing_key(domain: KeyDomain) -> StoreError {
    StoreError::KeyUnavailable {
        domain,
        detail: "the key is missing but data encrypted under it exists; \
                 restore the key or reset the store"
            .into(),
    }
}

fn exists(path: &Path) -> Result<bool, StoreError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
        Err(err) => Err(fsio::io_error(path, err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CoseAlg;
    use crate::store::PrivateKeyMaterial;
    use crate::store::test_support::TempDir;

    fn record(credential_id: &[u8]) -> CredentialRecord {
        CredentialRecord {
            credential_id: credential_id.to_vec(),
            rp_id: "example.com".into(),
            user_id: vec![1],
            user_name: None,
            user_display_name: None,
            alg: CoseAlg::MLDSA65,
            private_key: PrivateKeyMaterial::generate(CoseAlg::MLDSA65),
            cred_random_with_uv: [1; 32],
            cred_random_without_uv: [2; 32],
            cred_protect: 1,
            sign_count: 0,
            created_at: 0,
        }
    }

    fn credential_keys(store: &FileStore) -> CredentialKeys {
        CredentialKeys::derive(&store.root_key_for_write(KeyDomain::Credential).unwrap()).unwrap()
    }

    /// Seal `plaintext` with the store's real key under `credentials/<name>`,
    /// bypassing every check `put` performs.
    fn forge(store: &FileStore, name: &str, plaintext: &[u8]) {
        let keys = credential_keys(store);
        let object = format!("{CREDENTIALS_DIR}/{name}");
        let sealed =
            envelope::seal(&keys.record, RecordType::Credential, &object, plaintext).unwrap();
        fs::write(store.credentials_dir.join(name), sealed).unwrap();
    }

    /// A correctly encrypted record whose contents belong to a different
    /// credential ID than its file name.
    #[test]
    fn record_under_the_wrong_name_is_inconsistent() {
        let scratch = TempDir::new();
        let mut store = FileStore::open(scratch.path().join("state")).unwrap();
        store.put(&record(b"bystander")).unwrap();
        let keys = credential_keys(&store);
        let victim_name = keys.file_name(b"victim").unwrap();
        let plaintext = codec::encode_credential(&record(b"impostor"), 1).unwrap();
        forge(&store, &victim_name, &plaintext);

        assert!(matches!(
            store.get(b"victim"),
            Err(StoreError::Corrupt {
                reason: Corruption::Inconsistent,
                ..
            })
        ));
        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].credential_id, b"bystander");
    }

    /// A correctly encrypted record whose `alg` disagrees with its key
    /// material is treated as corruption on load.
    #[test]
    fn algorithm_and_key_mismatch_is_inconsistent() {
        let scratch = TempDir::new();
        let mut store = FileStore::open(scratch.path().join("state")).unwrap();
        store.put(&record(b"bystander")).unwrap();
        let mut mismatched = record(b"mismatched");
        mismatched.alg = CoseAlg::ES256;
        let plaintext = codec::encode_credential(&mismatched, 7).unwrap();
        let name = credential_keys(&store).file_name(b"mismatched").unwrap();
        forge(&store, &name, &plaintext);

        assert!(matches!(
            store.get(b"mismatched"),
            Err(StoreError::Corrupt {
                reason: Corruption::Inconsistent,
                ..
            })
        ));
        assert_eq!(store.count().unwrap(), 1);
        assert_eq!(store.list().unwrap()[0].credential_id, b"bystander");
    }

    #[test]
    fn undecodable_plaintext_is_an_encoding_error() {
        let scratch = TempDir::new();
        let store = FileStore::open(scratch.path().join("state")).unwrap();
        let name = credential_keys(&store).file_name(b"garbage").unwrap();
        forge(&store, &name, b"\xff not cbor");
        assert!(matches!(
            store.get(b"garbage"),
            Err(StoreError::Corrupt {
                reason: Corruption::Encoding,
                ..
            })
        ));
        assert_eq!(store.list().unwrap(), []);
    }
}
