//! Root keys, where they come from, and the subkeys derived from them.
//!
//! ```text
//! device root key (32 random bytes)
//! └── HKDF-SHA-256 "ftsa-store/v1/device/record-encryption"      -> attestation record key
//!
//! credential root key (32 random bytes, replaced by clear())
//! ├── HKDF-SHA-256 "ftsa-store/v1/credential/record-encryption"  -> credential + PIN state key
//! └── HKDF-SHA-256 "ftsa-store/v1/credential/index-hmac"         -> credential file name key
//! ```
//!
//! HKDF uses no salt (RFC 5869's default of 32 zero bytes) and a 32-byte
//! output, with the root key as input keying material.  Root keys are never
//! used directly, and the domain is part of every info string, so even a key
//! source that returned the same key for both domains would not make their
//! subkeys collide.

use core::fmt;
use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::fsio;
use super::StoreError;

/// Length of every root key and subkey.
pub(crate) const KEY_LEN: usize = 32;

/// HKDF info string for the attestation record encryption key.
pub(crate) const INFO_DEVICE_RECORD: &[u8] = b"ftsa-store/v1/device/record-encryption";
/// HKDF info string for the credential and PIN state encryption key.
pub(crate) const INFO_CREDENTIAL_RECORD: &[u8] = b"ftsa-store/v1/credential/record-encryption";
/// HKDF info string for the key that names credential files.
pub(crate) const INFO_CREDENTIAL_INDEX: &[u8] = b"ftsa-store/v1/credential/index-hmac";

/// How often [`FileKeySource::create`] re-reads after losing a creation race
/// before giving up.
const CREATE_ATTEMPTS: usize = 4;

/// The two independent key domains of a store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyDomain {
    /// Protects the attestation record.  Survives
    /// [`clear`](super::CredentialStore::clear).
    Device,
    /// Protects credential records, the names of credential files, and the
    /// PIN state.  Replaced by [`clear`](super::CredentialStore::clear).
    Credential,
}

impl KeyDomain {
    /// Both domains.
    pub const ALL: [KeyDomain; 2] = [KeyDomain::Device, KeyDomain::Credential];

    /// A short lowercase name: `device` or `credential`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            KeyDomain::Device => "device",
            KeyDomain::Credential => "credential",
        }
    }
}

impl fmt::Display for KeyDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A 32-byte root key.  Zeroized on drop, redacted from `Debug`, and compared
/// in constant time.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RootKey([u8; KEY_LEN]);

impl RootKey {
    /// Length of a root key in bytes.
    pub const LEN: usize = KEY_LEN;

    /// Wrap existing key bytes.  The caller remains responsible for zeroizing
    /// its own copy.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Generate a key from the operating system's random number generator.
    pub fn generate() -> Result<Self, StoreError> {
        let mut key = Self([0; KEY_LEN]);
        OsRng
            .try_fill_bytes(&mut key.0)
            .map_err(|_| StoreError::Random)?;
        Ok(key)
    }

    pub(crate) fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl PartialEq for RootKey {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0[..].ct_eq(&other.0[..]))
    }
}

impl Eq for RootKey {}

impl fmt::Debug for RootKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RootKey(<redacted>)")
    }
}

/// Where a [`FileStore`](super::FileStore) gets its root keys.
///
/// The store calls [`load`](Self::load) at the start of every operation instead
/// of caching keys, so that a reset performed through another store instance
/// or process takes effect immediately.  An implementation backed by something
/// slow, such as a TPM, should cache internally.
///
/// Implementations must never replace an existing key except in
/// [`rotate`](Self::rotate): a regenerated key orphans every record encrypted
/// under the old one.
pub trait KeySource {
    /// The current root key for `domain`, or `Ok(None)` if it has never been
    /// created.
    ///
    /// A key that exists but is unusable (for example a key file of the wrong
    /// length) must be reported as [`StoreError::KeyUnavailable`], not as
    /// `Ok(None)`.
    fn load(&self, domain: KeyDomain) -> Result<Option<RootKey>, StoreError>;

    /// Create a fresh root key for `domain` unless one exists, and return the
    /// key in effect afterwards.
    ///
    /// Must be safe against concurrent callers in other processes: if another
    /// caller creates the key first, return that key rather than replacing it.
    fn create(&self, domain: KeyDomain) -> Result<RootKey, StoreError>;

    /// Replace the root key for `domain` with a fresh random key, whether or
    /// not the current one is usable, and destroy the old key as thoroughly as
    /// the backend allows.  Returns the new key once it is durable.
    fn rotate(&self, domain: KeyDomain) -> Result<RootKey, StoreError>;
}

/// The default [`KeySource`]: each root key is a raw 32-byte file in a private
/// directory, `device.key` and `credential.key`.
///
/// * The directory is created `0700` and key files `0600`.
/// * A key file is created race-free: the key is written to a temporary file,
///   flushed, and hard-linked to its final name, which fails if another
///   process got there first; the loser then reads the winner's key.  No
///   process can observe a partially written key file.
/// * A key file whose length is not exactly 32 bytes, or that holds only
///   zeros, is a hard error ([`StoreError::KeyUnavailable`]); it is never
///   regenerated.
/// * [`rotate`](KeySource::rotate) atomically renames a new key file over the
///   old one, then overwrites the old file's contents with zeros through a
///   handle opened beforehand, as a best effort against recovery from the
///   disk.
#[derive(Debug, Clone)]
pub struct FileKeySource {
    dir: PathBuf,
}

impl FileKeySource {
    /// A key source keeping its key files in `dir`, which is created on first
    /// use.
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The directory holding the key files.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The file holding the root key for `domain`.
    #[must_use]
    pub fn key_path(&self, domain: KeyDomain) -> PathBuf {
        self.dir.join(Self::file_name(domain))
    }

    fn file_name(domain: KeyDomain) -> &'static str {
        match domain {
            KeyDomain::Device => "device.key",
            KeyDomain::Credential => "credential.key",
        }
    }
}

impl KeySource for FileKeySource {
    fn load(&self, domain: KeyDomain) -> Result<Option<RootKey>, StoreError> {
        let path = self.key_path(domain);
        let Some(contents) = fsio::read_file(&path, KEY_LEN as u64)? else {
            return Ok(None);
        };
        let contents = Zeroizing::new(contents);
        match <[u8; KEY_LEN]>::try_from(contents.as_slice()) {
            // All zeros is what `rotate` leaves in a replaced key file, so a
            // process that opened the file just before a concurrent rotation
            // can read it.  A generated key is never all zeros; refuse to use
            // one rather than encrypt under a publicly known key.
            Ok(bytes) if bytes.iter().all(|&byte| byte == 0) => Err(StoreError::KeyUnavailable {
                domain,
                detail: format!(
                    "{} is all zeros, as left behind by a key rotation",
                    path.display()
                ),
            }),
            Ok(mut bytes) => {
                let key = RootKey::from_bytes(bytes);
                bytes.zeroize();
                Ok(Some(key))
            }
            Err(_) => {
                let actual = std::fs::metadata(&path)
                    .map(|metadata| metadata.len().to_string())
                    .unwrap_or_else(|_| "an unknown number of".into());
                Err(StoreError::KeyUnavailable {
                    domain,
                    detail: format!(
                        "{} holds {actual} bytes instead of {KEY_LEN}; refusing to replace it",
                        path.display()
                    ),
                })
            }
        }
    }

    fn create(&self, domain: KeyDomain) -> Result<RootKey, StoreError> {
        fsio::ensure_private_dir(&self.dir)?;
        for _ in 0..CREATE_ATTEMPTS {
            if let Some(existing) = self.load(domain)? {
                return Ok(existing);
            }
            let key = RootKey::generate()?;
            if fsio::create_file_exclusive(&self.dir, Self::file_name(domain), key.expose())? {
                return Ok(key);
            }
            // Another process created the key between our load and our link.
            // Loop to read its key; never overwrite it.
        }
        Err(StoreError::KeyUnavailable {
            domain,
            detail: format!(
                "{} kept appearing and disappearing while it was being created",
                self.key_path(domain).display()
            ),
        })
    }

    fn rotate(&self, domain: KeyDomain) -> Result<RootKey, StoreError> {
        fsio::ensure_private_dir(&self.dir)?;
        let path = self.key_path(domain);
        // Open the old key first: once the new file is renamed over it this
        // handle is the only way left to reach its contents.
        let previous = match OpenOptions::new().write(true).open(&path) {
            Ok(file) => Some(file),
            Err(err) if err.kind() == ErrorKind::NotFound => None,
            Err(err) => {
                log::warn!(
                    "credential store: cannot open {} to overwrite it: {err}",
                    path.display()
                );
                None
            }
        };
        let key = RootKey::generate()?;
        fsio::replace_file(&self.dir, Self::file_name(domain), key.expose())?;
        if let Some(previous) = previous {
            if let Err(err) = fsio::overwrite_with_zeros(&previous) {
                log::warn!("credential store: could not overwrite the old {domain} key: {err}");
            }
        }
        // A crash during an earlier creation or rotation can leave a temporary
        // file holding a key; do not let one outlive a rotation.
        fsio::remove_temp_files(&self.dir);
        Ok(key)
    }
}

/// A 32-byte key derived from a root key for a single purpose.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct SubKey([u8; KEY_LEN]);

impl SubKey {
    fn derive(root: &RootKey, domain: KeyDomain, info: &[u8]) -> Result<Self, StoreError> {
        let mut subkey = Self([0; KEY_LEN]);
        Hkdf::<Sha256>::new(None, root.expose())
            .expand(info, &mut subkey.0)
            .map_err(|_| StoreError::KeyUnavailable {
                domain,
                detail: "HKDF key derivation failed".into(),
            })?;
        Ok(subkey)
    }

    pub(crate) fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// Subkeys of the device domain.
pub(crate) struct DeviceKeys {
    /// Encrypts the attestation record.
    pub(crate) record: SubKey,
}

impl DeviceKeys {
    pub(crate) fn derive(root: &RootKey) -> Result<Self, StoreError> {
        Ok(Self {
            record: SubKey::derive(root, KeyDomain::Device, INFO_DEVICE_RECORD)?,
        })
    }
}

/// Subkeys of the credential domain.
pub(crate) struct CredentialKeys {
    /// Encrypts credential records and the PIN state.
    pub(crate) record: SubKey,
    /// Keys the HMAC that names credential files.
    index: SubKey,
}

impl CredentialKeys {
    pub(crate) fn derive(root: &RootKey) -> Result<Self, StoreError> {
        Ok(Self {
            record: SubKey::derive(root, KeyDomain::Credential, INFO_CREDENTIAL_RECORD)?,
            index: SubKey::derive(root, KeyDomain::Credential, INFO_CREDENTIAL_INDEX)?,
        })
    }

    /// The file name of a credential: lowercase hex of
    /// HMAC-SHA-256(index key, credential ID).  It reveals nothing about the
    /// credential ID or relying party without the key.
    pub(crate) fn file_name(&self, credential_id: &[u8]) -> Result<String, StoreError> {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(self.index.expose()).map_err(|_| {
            StoreError::KeyUnavailable {
                domain: KeyDomain::Credential,
                detail: "HMAC key setup failed".into(),
            }
        })?;
        mac.update(credential_id);
        Ok(fsio::hex(&mac.finalize().into_bytes()))
    }
}

/// Whether `name` has the shape of a credential file name.
pub(crate) fn is_credential_file_name(name: &str) -> bool {
    name.len() == 2 * KEY_LEN && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::test_support::TempDir;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Barrier};

    fn unhex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn fixed_root() -> RootKey {
        let mut bytes = [0u8; KEY_LEN];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = i as u8;
        }
        RootKey::from_bytes(bytes)
    }

    /// Pins the key hierarchy to an independent implementation.
    ///
    /// The expected values were computed outside this crate with Python's
    /// standard library, implementing RFC 5869 directly on `hmac`/`hashlib`:
    ///
    /// ```text
    /// prk    = hmac.new(b"\0" * 32, root, sha256).digest()
    /// subkey = hmac.new(prk, info + b"\x01", sha256).digest()
    /// name   = hmac.new(index_subkey, credential_id, sha256).hexdigest()
    /// ```
    ///
    /// with `root = bytes(range(32))` and
    /// `credential_id = bytes(range(0xa0, 0xb0))`, and cross-checked against
    /// the `HKDF` class of `pyca/cryptography`.  A change to an info string,
    /// the salt, or the naming scheme makes every existing store unreadable,
    /// so it must show up here.
    #[test]
    fn key_hierarchy_matches_independent_implementation() {
        let root = fixed_root();
        let device = DeviceKeys::derive(&root).unwrap();
        let credential = CredentialKeys::derive(&root).unwrap();
        assert_eq!(
            device.record.expose().as_slice(),
            unhex("44551201ddb1bd229931a7d77274fc2f9a76ed10bc8e254e4c5b3497bc13d9d5")
        );
        assert_eq!(
            credential.record.expose().as_slice(),
            unhex("51172de714c0ce276f34019208c078a11d4dfd9f97f229b1f145c63962f1bc56")
        );
        assert_eq!(
            credential.index.expose().as_slice(),
            unhex("1d634187fbd84715e4989c36021d72028133ce89e7cdd79d7694a9cbe6ac3b6f")
        );
        let credential_id: Vec<u8> = (0xa0..0xb0).collect();
        assert_eq!(
            credential.file_name(&credential_id).unwrap(),
            "e149de70f7e7fda0653f378cac5c6c1da5eef20d294378099da36f93e2c45727"
        );
    }

    #[test]
    fn subkeys_are_distinct_per_purpose_and_domain() {
        let root = fixed_root();
        let device = DeviceKeys::derive(&root).unwrap();
        let credential = CredentialKeys::derive(&root).unwrap();
        let keys = [
            root.expose(),
            device.record.expose(),
            credential.record.expose(),
            credential.index.expose(),
        ];
        for (i, a) in keys.iter().enumerate() {
            for b in &keys[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn credential_file_names_are_deterministic_and_keyed() {
        let keys = CredentialKeys::derive(&fixed_root()).unwrap();
        let other = CredentialKeys::derive(&RootKey::generate().unwrap()).unwrap();
        let name = keys.file_name(b"credential").unwrap();
        assert!(is_credential_file_name(&name));
        assert_eq!(name, keys.file_name(b"credential").unwrap());
        assert_ne!(name, keys.file_name(b"credentiaL").unwrap());
        assert_ne!(name, other.file_name(b"credential").unwrap());
        assert!(!name.contains(&fsio::hex(b"credential")));
    }

    #[test]
    fn credential_file_name_shape() {
        assert!(is_credential_file_name(&"0".repeat(64)));
        assert!(is_credential_file_name(&"af".repeat(32)));
        assert!(!is_credential_file_name(&"0".repeat(63)));
        assert!(!is_credential_file_name(&"A".repeat(64)));
        assert!(!is_credential_file_name(&format!("{}g", "0".repeat(63))));
        assert!(!is_credential_file_name(".tmp-0123456789abcdef"));
    }

    #[test]
    fn root_key_debug_is_redacted_and_generation_is_random() {
        let key = RootKey::from_bytes([0xc7; KEY_LEN]);
        let rendered = format!("{key:?}");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("199") && !rendered.contains("c7"));
        assert_ne!(RootKey::generate().unwrap(), RootKey::generate().unwrap());
    }

    #[test]
    fn file_key_source_creates_private_keys_once() {
        let scratch = TempDir::new();
        let source = FileKeySource::new(scratch.path().join("keys"));
        for domain in KeyDomain::ALL {
            assert_eq!(source.load(domain).unwrap(), None);
        }
        let device = source.create(KeyDomain::Device).unwrap();
        let credential = source.create(KeyDomain::Credential).unwrap();
        assert_ne!(device, credential);
        assert_eq!(
            source.load(KeyDomain::Device).unwrap(),
            Some(device.clone())
        );
        assert_eq!(source.create(KeyDomain::Device).unwrap(), device);
        assert_eq!(source.create(KeyDomain::Credential).unwrap(), credential);

        let dir_mode = fs::metadata(source.dir()).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        for domain in KeyDomain::ALL {
            let path = source.key_path(domain);
            assert_eq!(fs::metadata(&path).unwrap().len(), 32);
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(fs::read_dir(source.dir()).unwrap().count(), 2);
    }

    #[test]
    fn malformed_key_file_is_a_hard_error() {
        let scratch = TempDir::new();
        let source = FileKeySource::new(scratch.path());
        let wrong_lengths = [0usize, 1, 31, 33, 64, 4096].map(|len| vec![0x5a; len]);
        let all_zeros = vec![0u8; KEY_LEN];
        for contents in wrong_lengths.iter().chain([&all_zeros]) {
            for domain in KeyDomain::ALL {
                fs::write(source.key_path(domain), contents).unwrap();
                assert!(matches!(
                    source.load(domain),
                    Err(StoreError::KeyUnavailable { domain: d, .. }) if d == domain
                ));
                assert!(matches!(
                    source.create(domain),
                    Err(StoreError::KeyUnavailable { .. })
                ));
                assert_eq!(&fs::read(source.key_path(domain)).unwrap(), contents);
            }
        }
    }

    #[test]
    fn concurrent_creation_converges_on_one_key() {
        let scratch = TempDir::new();
        let dir = scratch.path().join("keys");
        let threads = 16;
        let barrier = Arc::new(Barrier::new(threads));
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                let source = FileKeySource::new(&dir);
                std::thread::spawn(move || {
                    barrier.wait();
                    source.create(KeyDomain::Credential).unwrap()
                })
            })
            .collect();
        let keys: Vec<RootKey> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let on_disk = FileKeySource::new(&dir)
            .load(KeyDomain::Credential)
            .unwrap()
            .unwrap();
        assert!(keys.iter().all(|key| *key == on_disk));
        let names: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["credential.key"], "no temporary files may remain");
    }

    #[test]
    fn rotation_replaces_the_key_and_leaves_no_copy_behind() {
        let scratch = TempDir::new();
        let source = FileKeySource::new(scratch.path().join("keys"));
        let device = source.create(KeyDomain::Device).unwrap();
        let old = source.create(KeyDomain::Credential).unwrap();
        // A stale temporary file that happens to hold the old key.
        fs::write(source.dir().join(".tmp-stale"), old.expose()).unwrap();

        let new = source.rotate(KeyDomain::Credential).unwrap();
        assert_ne!(new, old);
        assert_eq!(source.load(KeyDomain::Credential).unwrap(), Some(new));
        assert_eq!(source.load(KeyDomain::Device).unwrap(), Some(device));
        for entry in fs::read_dir(source.dir()).unwrap() {
            let contents = fs::read(entry.unwrap().path()).unwrap();
            assert_ne!(contents.as_slice(), old.expose().as_slice());
        }
        assert_eq!(fs::read_dir(source.dir()).unwrap().count(), 2);
    }

    /// Rotation overwrites the old key's contents, which also reaches any other
    /// name or open handle for the same file.  Whoever reads it through one of
    /// those afterwards gets zeros, which must be refused rather than used.
    #[test]
    fn rotation_zeroes_the_old_key_and_zeros_are_never_used() {
        let scratch = TempDir::new();
        let source = FileKeySource::new(scratch.path().join("keys"));
        let old = source.create(KeyDomain::Credential).unwrap();
        let stale = FileKeySource::new(scratch.path().join("stale"));
        fs::create_dir(stale.dir()).unwrap();
        fs::hard_link(
            source.key_path(KeyDomain::Credential),
            stale.key_path(KeyDomain::Credential),
        )
        .unwrap();
        assert_eq!(stale.load(KeyDomain::Credential).unwrap(), Some(old));

        source.rotate(KeyDomain::Credential).unwrap();
        assert_eq!(
            fs::read(stale.key_path(KeyDomain::Credential)).unwrap(),
            vec![0; KEY_LEN]
        );
        assert!(matches!(
            stale.load(KeyDomain::Credential),
            Err(StoreError::KeyUnavailable { .. })
        ));
    }

    #[test]
    fn rotation_recovers_from_a_malformed_key_file() {
        let scratch = TempDir::new();
        let source = FileKeySource::new(scratch.path());
        fs::write(source.key_path(KeyDomain::Credential), b"short").unwrap();
        assert!(source.load(KeyDomain::Credential).is_err());
        let new = source.rotate(KeyDomain::Credential).unwrap();
        assert_eq!(source.load(KeyDomain::Credential).unwrap(), Some(new));
    }
}
