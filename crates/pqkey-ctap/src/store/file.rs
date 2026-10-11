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
use super::manifest::{
    self, ACTIVE_FILE, FORMAT, FORMAT_FILE, Location, MANAGED_DIR, Manifest, RECORDS_DIR,
};
use super::{
    AttestationRecord, CommitDurability, Corruption, CredentialCommit, CredentialRecord,
    CredentialStore, DEFAULT_MAX_CREDENTIALS, INITIAL_LARGE_BLOB_ARRAY, PinStateRecord, StoreError,
    next_created_at, sort_newest_first, validate_attestation, validate_credential,
};

const CREDENTIALS_DIR: &str = "credentials";
const KEYS_DIR: &str = "keys";
const PIN_STATE_FILE: &str = "pin-state";
const SIGNATURE_COUNTER_FILE: &str = "signature-counter";
const LARGE_BLOBS_FILE: &str = "large-blobs";
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
/// [`pin_state`](CredentialStore::pin_state),
/// [`large_blob_array`](CredentialStore::large_blob_array), and
/// [`attestation`](CredentialStore::attestation)) or skipped with a warning
/// (by [`list`](CredentialStore::list) and [`count`](CredentialStore::count)),
/// and never deleted as a corruption repair. Unreferenced ciphertext in the
/// managed namespace may be reclaimed by transaction cleanup.
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
/// ├── signature-counter       0600  envelope, record type 4
/// ├── large-blobs             0600  envelope, record type 5
/// └── attestation             0600  envelope, record type 3
/// ```
///
/// Writes briefly create `.tmp-<16 hex digits>` files next to their target.
/// This is the legacy layout, retained until the first atomic discoverable
/// registration. The managed layout is described below.
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
///   names, membership metadata, the PIN state, signature counter, large-blob array and sealed
///   credential IDs, and is replaced by [`clear`](CredentialStore::clear).
///
/// Root keys are never used directly.  Subkeys are HKDF-SHA-256 (RFC 5869)
/// with no salt, the root key as input keying material, a 32-byte output, and
/// these ASCII info strings:
///
/// ```text
/// root key    info string                                 subkey
/// device      ftsa-store/v1/device/record-encryption      encrypts the attestation record
/// credential  ftsa-store/v1/credential/record-encryption  encrypts credentials, PIN state, counters and blobs
/// credential  ftsa-store/v1/credential/index-hmac         keys the credential file names
/// credential  ftsa-store/v1/credential/id-encryption      seals credential IDs
/// ```
///
/// A root key that is missing while data encrypted under it exists, or that
/// exists but is malformed, is never regenerated: operations that need it
/// fail with [`StoreError::KeyUnavailable`].  Sealing a credential ID writes
/// the default PIN state if there is none, so that sealed credentials, which
/// only relying parties hold, count as such data.  Only
/// [`clear`](CredentialStore::clear) replaces the credential key, which also
/// makes it the way to recover from a lost one.
///
/// # Envelope
///
/// ```text
/// offset  length  field
///      0       4  magic, ASCII "FTSA"
///      4       1  format version, 1
///      5       1  record type: 1 credential, 2 PIN state, 3 attestation,
///                             4 signature counter, 5 large-blob array
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
/// `pin-state`, `attestation`, `signature-counter`, `large-blobs`, or
/// `credentials/<64 hex digits>`. Copying one file over another therefore
/// fails authentication even under the same key.
/// Envelopes are at most 1 MiB.
///
/// # Records
///
/// Types 1–5 have a plaintext CBOR map with unsigned integer keys, written in
/// ascending key order with shortest-form integers and lengths.  Optional
/// fields are omitted when absent.  Decoding accepts the keys in any order and
/// longer encodings than needed, but nothing else: unknown, duplicate or
/// missing keys and wrong types make the record corrupt. Transaction
/// metadata types 6–7 have the separate encodings specified below.
///
/// ```text
/// credential record (type 1)
///    1  credential_id           byte string
///    2  rp_id                   text string
///    3  user_id                 byte string
///    4  user_name               text string, optional
///    5  user_display_name       text string, optional
///    6  alg                     integer, COSE algorithm identifier, one of CoseAlg's
///    7  private key type        unsigned: 1 = P-256 scalar, 2 = seed (ML-DSA's ξ, an
///                               ECDSA key's seed on P-384, P-521 or secp256k1, an
///                               Ed25519 private key, or an Ed448 key's seed)
///    8  private key             byte string, 32 bytes
///    9  cred_random_with_uv     byte string, 32 bytes
///   10  cred_random_without_uv  byte string, 32 bytes
///   11  cred_protect            unsigned, 1-3
///   12  sign_count              unsigned, 32 bits
///   13  created_at              unsigned, 64 bits
///   14  cred_blob               byte string, at most 32 bytes, optional
///   15  large_blob_key          byte string, 32 bytes, optional
///
/// PIN state record (type 2)
///    1  pin_hash                byte string, 16 bytes, optional
///    2  pin_retries             unsigned, 8 bits
///    3  consecutive_failures    unsigned, 8 bits
///    4  pin_auth_blocked        boolean
///    5  min_pin_length          unsigned integer, 4-63, default 4
///    6  min_pin_length_rp_ids   array of text strings, at most 8,
///                               each at most 253 bytes, default empty
///    7  force_pin_change        boolean, default false
///    8  pin_code_point_length   unsigned integer, 4-63, default 4
///    9  always_uv               boolean, default false
///
/// attestation record (type 3)
///    1  private_key             byte string, 32 bytes
///    2  certificate_chain       array of byte strings, at least one, none empty
///
/// signature counter record (type 4)
///    1  signature_counter       unsigned integer, 32 bits
///
/// large-blob array record (type 5)
///    1  serialized_array        byte string, 17–16,384 bytes, trailing hash
/// ```
///
/// # Credential-set transactions
///
/// [`insert_or_replace_discoverable`](CredentialStore::insert_or_replace_discoverable)
/// validates every active record before staging: an unreadable record could
/// match the account and become usable again if ignored. Ordinary listing
/// still skips corrupt individual records. The new ID must be unoccupied,
/// including by corrupt, retired or abandoned staged files. Replacement
/// retires every readable discoverable record with the exact RP ID and user
/// handle, receives a fresh creation order, and needs no extra logical slot.
/// Physical space for staging and metadata is still required.
///
/// ```text
/// <state dir>/credential-format       0600  encrypted format marker, type 7
/// <state dir>/credential-set/         0700  managed namespace
/// ├── active                         0600  encrypted membership, type 6
/// ├── <64 hex digits>                 0600  retained legacy records
/// └── records/                       0700
///     └── <64 hex digits>             0600  new records, named by ID HMAC
/// ```
///
/// Both metadata objects use the unchanged credential record-encryption key
/// and version-1 envelope, with their own record type and logical path in the
/// associated data. The marker's plaintext is `pqkey/credential-set/v1`.
/// Membership is a strictly encoded binary value: ASCII `PQC1`, a four-byte
/// big-endian entry count, then sorted unique entries of one location byte
/// (0 legacy, 1 managed) and the 32-byte filename HMAC. Length, location,
/// ordering, duplicates and trailing bytes are checked. The existing 1 MiB
/// envelope limit also bounds metadata; an oversized set fails before commit.
/// Credential CBOR, existing HKDF domains and sealed IDs do not change.
/// Moved legacy ciphertext retains the logical name `credentials/<hash>`;
/// new ciphertext uses `credential-set/records/<hash>`.
///
/// Migration writes the format marker, stages the new record in the legacy
/// directory's ignored `records/` subdirectory, and prepares `active` there.
/// Files and preparation directories are flushed before atomically renaming
/// `credentials/` to `credential-set/`. That rename is the first commit.
/// Before it, legacy records remain usable and the candidate is invisible.
/// Afterwards, only membership in `active` permits lookup or enumeration.
/// Later inserts, replacements and deletes commit by renaming a flushed
/// manifest over `active`. Same-ID record updates retain creation order.
///
/// A pre-commit error preserves the preceding usable set. After commit, the
/// atomic API always returns [`CredentialCommit`], even if flushing fails.
/// [`CommitDurability::Unconfirmed`] means the new set is visible on process
/// restart, but publication might roll back after power loss. Cleanup waits
/// for successful flushes of both publication and namespace directories;
/// otherwise all preceding records are retained. Cleanup errors set
/// `cleanup_pending` and are logged. Retired and abandoned records are
/// excluded permanently by membership, even if removal fails, files reappear,
/// the store is reopened, or the replacement is subsequently replaced or
/// deleted. A later committed membership change retries cleanup.
///
/// Managed-mode `put` inserts and `delete` similarly return success after
/// publication, logging unconfirmed durability or pending cleanup. Active
/// same-ID updates retain their existing per-record write/error semantics.
/// Missing or corrupt authority returns
/// [`StoreError::CredentialSetUnavailable`], not an empty listing or an
/// individual-record error. Neither opening nor reads reconstruct authority
/// from files. The format marker distinguishes a missing managed namespace
/// from a legacy store; a failed migration still has its usable legacy
/// directory. Explicit reset rotates the key and establishes empty authority.
///
/// Upgrade is forward-only: old binaries do not understand this namespace.
/// Back up the whole store before upgrading; do not run an old binary on an
/// upgraded state directory. There is no multiwriter coordination or trusted
/// anti-rollback counter. Removing all format evidence or restoring a prior
/// whole-store snapshot is outside the integrity guarantee.
///
/// # Durability
///
/// Files are created with their final mode and never modified in place: a
/// write goes to a temporary file that is flushed, renamed over its target,
/// and followed by a flush of the directory.  See
/// [`put`](CredentialStore::put) and [`clear`](CredentialStore::clear) in
/// the source for the crash analysis. A large-blob array write commits when
/// renamed: a later directory-flush failure is logged and returns success,
/// although a power failure may then restore the preceding file. Other
/// writers report that failure even though the replacement is visible.
/// Credential-set membership follows the explicit commit rules above.
/// `Flushed` relies on the filesystem and hardware honoring flushes; it is
/// not protection against snapshot rollback. Unsupported directory flushing
/// aborts transaction preparation or gives `Unconfirmed` after publication.
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
        if !exists(&store.root.join(MANAGED_DIR))? && !exists(&store.root.join(FORMAT_FILE))? {
            fsio::ensure_private_dir(&store.credentials_dir)?;
        }
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
                || exists(&self.root.join(SIGNATURE_COUNTER_FILE))?
                || exists(&self.root.join(LARGE_BLOBS_FILE))?
                || exists(&self.root.join(FORMAT_FILE))?
                || exists(&self.root.join(MANAGED_DIR))?
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
        self.read_credential_in(keys, name, &self.credentials_dir, Location::Legacy)
    }

    fn read_credential_in(
        &self,
        keys: &CredentialKeys,
        name: &str,
        dir: &Path,
        location: Location,
    ) -> Result<Option<CredentialRecord>, StoreError> {
        let object = credential_object(name, location);
        let Some(sealed) = fsio::read_file(&dir.join(name), max_envelope_len())? else {
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
        if let Some(manifest) = self.active_manifest(keys)? {
            let mut records = Vec::with_capacity(manifest.len());
            for (name, location) in manifest {
                match self.read_credential_in(keys, &name, &self.record_dir(location), location) {
                    Ok(Some(record)) => records.push(record),
                    Ok(None) => {}
                    Err(err) => log::warn!("credential store: skipping credential: {err}"),
                }
            }
            return Ok(records);
        }
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

    fn record_dir(&self, location: Location) -> PathBuf {
        let dir = self.root.join(MANAGED_DIR);
        match location {
            Location::Legacy => dir,
            Location::Managed => dir.join(RECORDS_DIR),
        }
    }

    /// Listing may skip a bad record. Replacement cannot: an unreadable
    /// active record might belong to the account being replaced, and must
    /// not become a second usable credential if its read error clears.
    fn replacement_records(
        &self,
        keys: &CredentialKeys,
        manifest: Option<&Manifest>,
    ) -> Result<Vec<CredentialRecord>, StoreError> {
        let entries: Vec<_> = match manifest {
            Some(manifest) => manifest
                .iter()
                .map(|(name, location)| (name.clone(), *location))
                .collect(),
            None => self
                .credential_file_names()?
                .into_iter()
                .map(|name| (name, Location::Legacy))
                .collect(),
        };
        let mut records = Vec::with_capacity(entries.len());
        for (name, location) in entries {
            let dir = if manifest.is_some() {
                self.record_dir(location)
            } else {
                self.credentials_dir.clone()
            };
            let record = self
                .read_credential_in(keys, &name, &dir, location)?
                .ok_or_else(|| {
                    metadata_error(&name, "active credential is missing during replacement")
                })?;
            records.push(record);
        }
        Ok(records)
    }

    /// A missing manifest never restores directory scanning. The namespace
    /// switch and the persistent format marker distinguish legacy stores
    /// from damaged upgraded stores, including an empty upgraded store.
    fn active_manifest(&self, keys: &CredentialKeys) -> Result<Option<Manifest>, StoreError> {
        if !exists(&self.root.join(MANAGED_DIR))? {
            if exists(&self.credentials_dir)? {
                return Ok(None);
            }
            return Err(metadata_error(
                MANAGED_DIR,
                "credential namespace is missing",
            ));
        }
        let marker = self
            .read_object(
                &keys.record,
                RecordType::CredentialFormat,
                FORMAT_FILE,
                |bytes| {
                    if bytes == FORMAT {
                        Ok(())
                    } else {
                        Err(Corruption::Encoding)
                    }
                },
            )
            .map_err(|err| metadata_error(FORMAT_FILE, &err.to_string()))?;
        if marker.is_none() {
            return Err(metadata_error(FORMAT_FILE, "format marker is missing"));
        }
        let name = format!("{MANAGED_DIR}/{ACTIVE_FILE}");
        self.read_object(
            &keys.record,
            RecordType::CredentialSet,
            &name,
            manifest::decode,
        )
        .map_err(|err| metadata_error(&name, &err.to_string()))?
        .map(Some)
        .ok_or_else(|| metadata_error(&name, "manifest is missing"))
    }

    fn write_candidate(
        &self,
        keys: &CredentialKeys,
        record: &CredentialRecord,
        created_at: u64,
        namespace: &Path,
    ) -> Result<(), StoreError> {
        let dir = namespace.join(RECORDS_DIR);
        fsio::ensure_private_dir(&dir)?;
        let name = keys.file_name(&record.credential_id)?;
        let plaintext = codec::encode_credential(record, created_at)?;
        let sealed = envelope::seal(
            &keys.record,
            RecordType::Credential,
            &credential_object(&name, Location::Managed),
            &plaintext,
        )?;
        let temp = fsio::write_temp_file(&dir, &sealed)?;
        let target = dir.join(name);
        if let Err(err) = fsio::checkpoint("rename", &target)
            .and_then(|()| fs::rename(&temp, &target).map_err(|err| fsio::io_error(&target, err)))
        {
            let _ = fs::remove_file(temp);
            return Err(err);
        }
        fsio::checkpoint("renamed", &target)?;
        fsio::sync_dir_strict(&dir)
    }

    fn prepare_manifest(
        &self,
        keys: &CredentialKeys,
        manifest: &Manifest,
        dir: &Path,
    ) -> Result<PathBuf, StoreError> {
        let plaintext = manifest::encode(manifest)?;
        let sealed = envelope::seal(
            &keys.record,
            RecordType::CredentialSet,
            &format!("{MANAGED_DIR}/{ACTIVE_FILE}"),
            &plaintext,
        )?;
        fsio::write_temp_file(dir, &sealed)
    }

    fn publish_manifest(
        &self,
        keys: &CredentialKeys,
        manifest: &Manifest,
    ) -> Result<CredentialCommit, StoreError> {
        let dir = self.root.join(MANAGED_DIR);
        let temp = self.prepare_manifest(keys, manifest, &dir)?;
        let target = dir.join(ACTIVE_FILE);
        if let Err(err) = fsio::checkpoint("publication", &target)
            .and_then(|()| fs::rename(&temp, &target).map_err(|err| fsio::io_error(&target, err)))
        {
            let _ = fs::remove_file(temp);
            return Err(err);
        }
        Ok(self.finish_commit(manifest, &dir))
    }

    fn finish_commit(&self, manifest: &Manifest, publication_dir: &Path) -> CredentialCommit {
        // Nothing after publication is returned as a failed transaction.
        let published = self.root.join(MANAGED_DIR).join(ACTIVE_FILE);
        if let Err(err) = fsio::checkpoint("published", &published)
            .and_then(|()| fsio::sync_dir_strict(publication_dir))
            .and_then(|()| {
                if publication_dir != self.root {
                    // A preceding migration may have returned Unconfirmed.
                    // Flush its namespace before reclaiming any preceding data.
                    fsio::sync_dir_strict(&self.root)
                } else {
                    Ok(())
                }
            })
        {
            log::warn!("credential set committed with unconfirmed durability: {err}");
            return CredentialCommit {
                durability: CommitDurability::Unconfirmed,
                cleanup_pending: true,
            };
        }
        let cleanup_pending = self.cleanup_retired(manifest);
        CredentialCommit {
            durability: CommitDurability::Flushed,
            cleanup_pending,
        }
    }

    fn cleanup_retired(&self, manifest: &Manifest) -> bool {
        let mut pending = false;
        for location in [Location::Legacy, Location::Managed] {
            let dir = self.record_dir(location);
            let cleanup = (|| {
                fsio::checkpoint("cleanup", &dir)?;
                let entries = fs::read_dir(&dir).map_err(|err| fsio::io_error(&dir, err))?;
                for entry in entries {
                    let entry = entry.map_err(|err| fsio::io_error(&dir, err))?;
                    let name = entry.file_name();
                    let Some(name) = name.to_str().filter(|name| is_credential_file_name(name))
                    else {
                        continue;
                    };
                    if manifest.get(name) != Some(&location) {
                        fsio::remove_file_if_present(&entry.path())?;
                    }
                }
                fsio::sync_dir_strict(&dir)
            })();
            if let Err(err) = cleanup {
                log::warn!("credential set committed; retired-record cleanup pending: {err}");
                pending = true;
            }
        }
        pending
    }

    fn collision(&self, name: &str) -> Result<bool, StoreError> {
        for dir in [&self.credentials_dir, &self.root.join(MANAGED_DIR)] {
            if exists(&dir.join(name))? || exists(&dir.join(RECORDS_DIR).join(name))? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn put_managed(
        &self,
        keys: &CredentialKeys,
        mut manifest: Manifest,
        record: &CredentialRecord,
    ) -> Result<(), StoreError> {
        let name = keys.file_name(&record.credential_id)?;
        if let Some(&location) = manifest.get(&name) {
            let existing =
                match self.read_credential_in(keys, &name, &self.record_dir(location), location) {
                    Ok(existing) => existing,
                    Err(StoreError::Corrupt { .. }) => None,
                    Err(err) => return Err(err),
                };
            let order = match existing {
                Some(existing) => existing.created_at,
                None => {
                    let current = self.scan(keys)?;
                    if current.len() >= self.max_credentials {
                        return Err(StoreError::Full {
                            max: self.max_credentials,
                        });
                    }
                    next_created_at(&current)
                }
            };
            let plaintext = codec::encode_credential(record, order)?;
            let sealed = envelope::seal(
                &keys.record,
                RecordType::Credential,
                &credential_object(&name, location),
                &plaintext,
            )?;
            return fsio::replace_file(&self.record_dir(location), &name, &sealed);
        }
        // An orphan is not an existing active credential and cannot be
        // resurrected accidentally by a same-ID update.
        if self.collision(&name)? {
            return Err(StoreError::InvalidRecord("credential ID is occupied"));
        }
        let current = self.scan(keys)?;
        if current.len() >= self.max_credentials {
            return Err(StoreError::Full {
                max: self.max_credentials,
            });
        }
        manifest.insert(name, Location::Managed);
        // Metadata size/encoding errors must precede any record mutation.
        let _ = manifest::encode(&manifest)?;
        self.write_candidate(
            keys,
            record,
            next_created_at(&current),
            &self.root.join(MANAGED_DIR),
        )?;
        let _committed = self.publish_manifest(keys, &manifest)?;
        Ok(())
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
        let record = match self.active_manifest(&keys)? {
            Some(manifest) => {
                let Some(&location) = manifest.get(&name) else {
                    return Ok(None);
                };
                self.read_credential_in(&keys, &name, &self.record_dir(location), location)?
            }
            None => self.read_credential(&keys, &name)?,
        };
        match record {
            Some(record) if record.credential_id != credential_id => Err(corrupt(
                &format!("{CREDENTIALS_DIR}/{name}"),
                Corruption::Inconsistent,
            )),
            record => Ok(record),
        }
    }

    fn put(&mut self, record: &CredentialRecord) -> Result<(), StoreError> {
        // The managed path uses authoritative membership; same-ID updates
        // keep their per-record semantics. The legacy path below changes
        // only `credentials/<name>`
        // (plus, on first use, the credential key, which is created atomically
        // before anything is encrypted under it).  `replace_file` writes the
        // envelope to a flushed temporary file, renames it into place, and
        // flushes the directory, so a crash leaves either the previous file
        // (or none) or the complete new one, never a torn record.  A leftover
        // temporary file does not have a credential name, so it is ignored
        // until `clear` removes it. In legacy mode there is no index to fall out
        // of step: the limit and the creation order are recomputed from the
        // records on every insert.
        validate_credential(record)?;
        let keys = CredentialKeys::derive(&self.root_key_for_write(KeyDomain::Credential)?)?;
        if let Some(manifest) = self.active_manifest(&keys)? {
            return self.put_managed(&keys, manifest, record);
        }
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

    fn insert_or_replace_discoverable(
        &mut self,
        record: &CredentialRecord,
    ) -> Result<CredentialCommit, StoreError> {
        validate_credential(record)?;
        if !crate::credential_id::is_discoverable(&record.credential_id) {
            return Err(StoreError::InvalidRecord(
                "replacement requires a discoverable credential",
            ));
        }
        let keys = CredentialKeys::derive(&self.root_key_for_write(KeyDomain::Credential)?)?;
        let name = keys.file_name(&record.credential_id)?;
        if self.collision(&name)? {
            return Err(StoreError::InvalidRecord("credential ID is occupied"));
        }
        let preceding = self.active_manifest(&keys)?;
        let current = self.replacement_records(&keys, preceding.as_ref())?;
        let matching: Vec<_> = current
            .iter()
            .filter(|existing| {
                crate::credential_id::is_discoverable(&existing.credential_id)
                    && existing.rp_id == record.rp_id
                    && existing.user_id == record.user_id
            })
            .map(|existing| keys.file_name(&existing.credential_id))
            .collect::<Result<_, _>>()?;
        if matching.is_empty() && current.len() >= self.max_credentials {
            return Err(StoreError::Full {
                max: self.max_credentials,
            });
        }
        let migrating = preceding.is_none();
        let mut manifest = match preceding {
            Some(manifest) => manifest,
            None => self
                .credential_file_names()?
                .into_iter()
                .map(|name| (name, Location::Legacy))
                .collect(),
        };
        for name in matching {
            manifest.remove(&name);
        }
        manifest.insert(name, Location::Managed);
        let _ = manifest::encode(&manifest)?;
        let namespace = if migrating {
            self.credentials_dir.clone()
        } else {
            self.root.join(MANAGED_DIR)
        };
        if migrating {
            let sealed = envelope::seal(
                &keys.record,
                RecordType::CredentialFormat,
                FORMAT_FILE,
                FORMAT,
            )?;
            // This marker does not change membership. An interrupted prepare
            // still has the legacy namespace and all its preceding records.
            fsio::replace_file(&self.root, FORMAT_FILE, &sealed)?;
            fsio::sync_dir_strict(&self.root)?;
        }
        self.write_candidate(&keys, record, next_created_at(&current), &namespace)?;
        if !migrating {
            return self.publish_manifest(&keys, &manifest);
        }
        let temp = self.prepare_manifest(&keys, &manifest, &namespace)?;
        let active = namespace.join(ACTIVE_FILE);
        if let Err(err) = fsio::checkpoint("rename", &active)
            .and_then(|()| fs::rename(&temp, &active).map_err(|err| fsio::io_error(&active, err)))
        {
            let _ = fs::remove_file(temp);
            return Err(err);
        }
        fsio::checkpoint("renamed", &active)?;
        fsio::sync_dir_strict(&namespace)?;
        let managed = self.root.join(MANAGED_DIR);
        fsio::checkpoint("publication", &managed)?;
        fs::rename(&namespace, &managed).map_err(|err| fsio::io_error(&managed, err))?;
        Ok(self.finish_commit(&manifest, &self.root))
    }

    fn delete(&mut self, credential_id: &[u8]) -> Result<bool, StoreError> {
        let Some(keys) = self.credential_keys()? else {
            return Ok(false);
        };
        let name = keys.file_name(credential_id)?;
        if let Some(mut manifest) = self.active_manifest(&keys)? {
            if manifest.remove(&name).is_none() {
                return Ok(false);
            }
            let _committed = self.publish_manifest(&keys, &manifest)?;
            return Ok(true);
        }
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
        // Rotate before discarding any state protected by the credential key.
        // A failure before publication leaves credentials, their counters and
        // PIN/UV policy intact. Rotation can also fail AFTER publishing the
        // new key (for example on directory flush): leave all old records in
        // place on any rotation error. They fail authentication under the new
        // key, or remain consistent if power loss restores the old key.
        // Never infer which key is active from an error or reset its counter.
        //
        // Only a successful, durable rotation permits purging credentials,
        // counters and blobs, establishing empty managed membership, and
        // finally writing default PIN state. Until that last write, old PIN
        // state reads as corrupt and the restarted engine fails closed. No
        // step needs the old key or readable records, so an explicit retry
        // can recover an interrupted reset or a lost/malformed key.
        let managed =
            exists(&self.root.join(MANAGED_DIR))? || exists(&self.root.join(FORMAT_FILE))?;
        let root_key = self.keys.rotate(KeyDomain::Credential)?;
        let keys = CredentialKeys::derive(&root_key)?;
        if managed {
            let dir = self.root.join(MANAGED_DIR);
            fsio::ensure_private_dir(&dir)?;
            fsio::remove_all_files(&dir.join(RECORDS_DIR))?;
            fsio::remove_all_files(&dir)?;
            // A failed migration can also have a legacy namespace.
            fsio::remove_all_files(&self.credentials_dir.join(RECORDS_DIR))?;
            fsio::remove_all_files(&self.credentials_dir)?;
            if exists(&self.credentials_dir)? {
                // Leave unknown directories alone, as the legacy reset does.
                let _ = fs::remove_dir(&self.credentials_dir);
            }
        } else {
            fsio::remove_all_files(&self.credentials_dir)?;
            fsio::ensure_private_dir(&self.credentials_dir)?;
        }
        let counter_removed =
            fsio::remove_file_if_present(&self.root.join(SIGNATURE_COUNTER_FILE))?;
        let array_removed = fsio::remove_file_if_present(&self.root.join(LARGE_BLOBS_FILE))?;
        if counter_removed || array_removed {
            fsio::sync_dir(&self.root)?;
        }
        if managed {
            let sealed = envelope::seal(
                &keys.record,
                RecordType::CredentialFormat,
                FORMAT_FILE,
                FORMAT,
            )?;
            fsio::replace_file(&self.root, FORMAT_FILE, &sealed)?;
            let _committed = self.publish_manifest(&keys, &Manifest::new())?;
        }
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

    fn signature_counter(&self) -> Result<u32, StoreError> {
        let Some(keys) = self.credential_keys()? else {
            return Ok(0);
        };
        Ok(self
            .read_object(
                &keys.record,
                RecordType::SignatureCounter,
                SIGNATURE_COUNTER_FILE,
                codec::decode_signature_counter,
            )?
            .unwrap_or(0))
    }

    fn set_signature_counter(&mut self, value: u32) -> Result<(), StoreError> {
        let keys = CredentialKeys::derive(&self.root_key_for_write(KeyDomain::Credential)?)?;
        let plaintext = codec::encode_signature_counter(value)?;
        self.write_object(
            &keys.record,
            RecordType::SignatureCounter,
            SIGNATURE_COUNTER_FILE,
            &plaintext,
        )
    }

    fn large_blob_array(&self) -> Result<Vec<u8>, StoreError> {
        if !exists(&self.root.join(LARGE_BLOBS_FILE))? {
            return Ok(INITIAL_LARGE_BLOB_ARRAY.to_vec());
        }
        let Some(keys) = self.credential_keys()? else {
            return Ok(INITIAL_LARGE_BLOB_ARRAY.to_vec());
        };
        Ok(self
            .read_object(
                &keys.record,
                RecordType::LargeBlobArray,
                LARGE_BLOBS_FILE,
                codec::decode_large_blob_array,
            )?
            .unwrap_or_else(|| INITIAL_LARGE_BLOB_ARRAY.to_vec()))
    }

    fn set_large_blob_array(&mut self, array: &[u8]) -> Result<(), StoreError> {
        let plaintext = codec::encode_large_blob_array(array)?;
        let keys = CredentialKeys::derive(&self.root_key_for_write(KeyDomain::Credential)?)?;
        let sealed = envelope::seal(
            &keys.record,
            RecordType::LargeBlobArray,
            LARGE_BLOBS_FILE,
            &plaintext,
        )?;
        fsio::replace_file_committed(&self.root, LARGE_BLOBS_FILE, &sealed)
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
        // Sealed IDs live at relying parties, where `has_data` cannot see
        // them.  A PIN state, the default one if there is none yet, marks that
        // something depends on the credential key, so a lost key is reported
        // rather than replaced as if nothing did.
        if !exists(&self.root.join(PIN_STATE_FILE))? {
            self.write_pin_state(&keys, &PinStateRecord::default())?;
        }
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

fn credential_object(name: &str, location: Location) -> String {
    match location {
        Location::Legacy => format!("{CREDENTIALS_DIR}/{name}"),
        Location::Managed => format!("{MANAGED_DIR}/{RECORDS_DIR}/{name}"),
    }
}

fn metadata_error(object: &str, detail: &str) -> StoreError {
    StoreError::CredentialSetUnavailable {
        object: object.to_owned(),
        detail: detail.to_owned(),
    }
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
#[path = "replacement_tests.rs"]
mod replacement_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CoseAlg;
    use crate::store::PrivateKeyMaterial;
    use crate::store::test_support::TempDir;

    #[test]
    fn authenticated_invalid_arrays_are_reported_and_replaceable() {
        let scratch = TempDir::new();
        let mut store = FileStore::open(scratch.path().join("state")).unwrap();
        let keys = store.credential_keys().unwrap().unwrap();
        for plaintext in [
            vec![0xa1, 0x01, 0xf5],
            vec![0xa1, 0x01, 0x40],
            [vec![0xa1, 0x01, 0x51], vec![0; 17]].concat(),
            [vec![0xa1, 0x01, 0x59, 0x40, 0x01], vec![0; 16_385]].concat(),
        ] {
            let sealed = envelope::seal(
                &keys.record,
                RecordType::LargeBlobArray,
                LARGE_BLOBS_FILE,
                &plaintext,
            )
            .unwrap();
            fs::write(store.root.join(LARGE_BLOBS_FILE), &sealed).unwrap();
            assert!(matches!(
                store.large_blob_array(),
                Err(StoreError::Corrupt { .. })
            ));
            assert_eq!(fs::read(store.root.join(LARGE_BLOBS_FILE)).unwrap(), sealed);
            store
                .set_large_blob_array(&INITIAL_LARGE_BLOB_ARRAY)
                .unwrap();
            assert_eq!(store.large_blob_array().unwrap(), INITIAL_LARGE_BLOB_ARRAY);
        }
    }

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
            cred_blob: None,
            large_blob_key: None,
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
    fn overlong_credential_blob_is_inconsistent() {
        let scratch = TempDir::new();
        let mut store = FileStore::open(scratch.path().join("state")).unwrap();
        store.put(&record(b"bystander")).unwrap();
        let mut invalid = record(b"overlong");
        invalid.cred_blob = Some(vec![0x55; 33]);
        assert!(matches!(
            store.put(&invalid),
            Err(StoreError::InvalidRecord(_))
        ));
        let plaintext = codec::encode_credential(&invalid, 7).unwrap();
        let name = credential_keys(&store).file_name(b"overlong").unwrap();
        forge(&store, &name, &plaintext);
        assert!(matches!(
            store.get(b"overlong"),
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
